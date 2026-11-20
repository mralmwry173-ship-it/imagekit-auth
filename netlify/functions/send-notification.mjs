import { createRemoteJWKSet, jwtVerify } from 'jose';
import { createSign } from 'node:crypto';

const PROJECT_ID = 'matjar-yemen';
const FIREBASE_ISSUER = 'https://securetoken.google.com/' + PROJECT_ID;
const FIREBASE_JWKS = createRemoteJWKSet(
  new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'),
);

const STATUS_LABELS = {
  pending: 'قيد الانتظار',
  payment_pending: 'بانتظار تأكيد الدفع',
  awaiting_payment_confirmation: 'بيانات الدفع بانتظار المراجعة',
  payment_rejected: 'تم رفض الدفع',
  paid: 'تم تأكيد الدفع',
  confirmed: 'تم تأكيد الطلب',
  preparing: 'جارٍ تجهيز الطلب',
  processing: 'جارٍ تجهيز الطلب',
  shipped: 'تم شحن الطلب',
  ready_for_pickup: 'الطلب جاهز للاستلام',
  delivery_searching: 'جارٍ البحث عن مندوب توصيل',
  assigned_to_agent: 'تم تعيين مندوب للطلب',
  picked_up: 'استلم المندوب الطلب',
  on_the_way: 'الطلب في الطريق إليك',
  delivering: 'الطلب في الطريق إليك',
  delivered: 'تم تسليم الطلب',
  completed: 'اكتمل الطلب',
  cancelled: 'تم إلغاء الطلب',
  rejected: 'تم رفض الطلب',
  failed_delivery: 'تعذّر توصيل الطلب',
  returned: 'تم إرجاع الطلب',
};

const MERCHANT_STATUSES = new Set([
  'paid',
  'confirmed',
  'preparing',
  'processing',
  'shipped',
  'ready_for_pickup',
  'delivery_searching',
  'rejected',
]);
const AGENT_STATUSES = new Set([
  'assigned_to_agent',
  'picked_up',
  'on_the_way',
  'delivering',
  'delivered',
  'failed_delivery',
]);
const CUSTOMER_STATUSES = new Set([
  'pending',
  'payment_pending',
  'awaiting_payment_confirmation',
]);
const PARTICIPANT_STATUSES = new Set([
  'cancelled',
  'completed',
  'returned',
]);
const ADMIN_ROLES = new Set(['super_admin', 'admin_staff']);
const SUPPORT_ROLES = new Set(['super_admin', 'admin_staff', 'support']);

let serviceAccountCache;
let accessTokenCache;

function response(statusCode, payload, headers = {}) {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...headers,
    },
    body: payload === '' ? '' : JSON.stringify(payload),
  };
}

function corsHeaders(event) {
  const origin = event.headers?.origin || event.headers?.Origin || '';
  const allowedOrigin = process.env.ALLOWED_ORIGIN || '';

  // Native Android/iOS requests normally have no Origin header.
  if (!origin) return {};
  if (!allowedOrigin || origin !== allowedOrigin) return null;

  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    Vary: 'Origin',
  };
}

function decodeFirestoreValue(value) {
  if (!value || typeof value !== 'object') return null;
  if (Object.hasOwn(value, 'stringValue')) return value.stringValue;
  if (Object.hasOwn(value, 'integerValue')) return Number(value.integerValue);
  if (Object.hasOwn(value, 'doubleValue')) return Number(value.doubleValue);
  if (Object.hasOwn(value, 'booleanValue')) return value.booleanValue;
  if (Object.hasOwn(value, 'timestampValue')) return value.timestampValue;
  if (Object.hasOwn(value, 'nullValue')) return null;
  if (value.arrayValue) {
    return (value.arrayValue.values || []).map(decodeFirestoreValue);
  }
  if (value.mapValue) {
    return decodeFirestoreFields(value.mapValue.fields || {});
  }
  return null;
}

function decodeFirestoreFields(fields = {}) {
  return Object.fromEntries(
    Object.entries(fields).map(([key, value]) => [key, decodeFirestoreValue(value)]),
  );
}

function encodeFirestoreValue(value, depth = 0) {
  if (depth > 12) return { stringValue: '[maximum depth]' };
  if (value === null || value === undefined) return { nullValue: 'NULL_VALUE' };
  if (value instanceof Date) return { timestampValue: value.toISOString() };
  if (typeof value === 'string') return { stringValue: value.slice(0, 4000) };
  if (typeof value === 'boolean') return { booleanValue: value };
  if (typeof value === 'number') {
    return Number.isInteger(value)
      ? { integerValue: String(value) }
      : { doubleValue: value };
  }
  if (Array.isArray(value)) {
    return {
      arrayValue: {
        values: value.slice(0, 100).map((item) => encodeFirestoreValue(item, depth + 1)),
      },
    };
  }
  if (typeof value === 'object') {
    return {
      mapValue: {
        fields: Object.fromEntries(
          Object.entries(value)
            .filter(([key]) => key.length > 0 && key.length <= 150)
            .slice(0, 100)
            .map(([key, item]) => [key, encodeFirestoreValue(item, depth + 1)]),
        ),
      },
    };
  }
  return { stringValue: String(value).slice(0, 4000) };
}

function encodeFirestoreFields(fields) {
  return Object.fromEntries(
    Object.entries(fields).map(([key, value]) => [key, encodeFirestoreValue(value)]),
  );
}

function readServiceAccount() {
  if (serviceAccountCache) return serviceAccountCache;

  const configured = process.env.FIREBASE_SERVICE_ACCOUNT_BASE64;
  if (!configured) throw new Error('Missing FIREBASE_SERVICE_ACCOUNT_BASE64');

  let json;
  try {
    json = configured.trim().startsWith('{')
      ? configured
      : Buffer.from(configured, 'base64').toString('utf8');
    serviceAccountCache = JSON.parse(json);
  } catch {
    throw new Error('FIREBASE_SERVICE_ACCOUNT_BASE64 is not valid service-account JSON');
  }

  const account = serviceAccountCache;
  if (
    account.project_id !== PROJECT_ID ||
    typeof account.client_email !== 'string' ||
    typeof account.private_key !== 'string'
  ) {
    serviceAccountCache = undefined;
    throw new Error('Service account does not match the Matjar Yemen Firebase project');
  }

  return account;
}

function base64url(value) {
  return Buffer.from(value).toString('base64url');
}

async function getGoogleAccessToken() {
  if (accessTokenCache && accessTokenCache.expiresAt > Date.now() + 60_000) {
    return accessTokenCache.token;
  }

  const account = readServiceAccount();
  const tokenUri = account.token_uri || 'https://oauth2.googleapis.com/token';
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = base64url(JSON.stringify({
    iss: account.client_email,
    scope: 'https://www.googleapis.com/auth/datastore https://www.googleapis.com/auth/firebase.messaging',
    aud: tokenUri,
    iat: now,
    exp: now + 3600,
  }));
  const unsigned = header + '.' + claims;
  const signer = createSign('RSA-SHA256');
  signer.update(unsigned);
  signer.end();
  const assertion = unsigned + '.' + signer.sign(account.private_key).toString('base64url');

  const tokenResponse = await fetch(tokenUri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }),
  });

  const tokenJson = await tokenResponse.json().catch(() => ({}));
  if (!tokenResponse.ok || typeof tokenJson.access_token !== 'string') {
    throw new Error('Google OAuth token request failed (' + tokenResponse.status + ')');
  }

  accessTokenCache = {
    token: tokenJson.access_token,
    expiresAt: Date.now() + Number(tokenJson.expires_in || 3600) * 1000,
  };
  return accessTokenCache.token;
}

async function getFirestoreDocument(path) {
  const token = await getGoogleAccessToken();
  const url = 'https://firestore.googleapis.com/v1/projects/' + PROJECT_ID +
    '/databases/(default)/documents/' + path;
  const result = await fetch(url, {
    headers: { Authorization: 'Bearer ' + token },
  });

  if (result.status === 404) return null;
  if (!result.ok) throw new Error('Firestore read failed (' + result.status + ')');

  const document = await result.json();
  return decodeFirestoreFields(document.fields || {});
}

async function createNotificationDocument(notificationId, fields) {
  const accessToken = await getGoogleAccessToken();
  const url = 'https://firestore.googleapis.com/v1/projects/' + PROJECT_ID +
    '/databases/(default)/documents/notifications?documentId=' +
    encodeURIComponent(notificationId);

  const result = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: 'Bearer ' + accessToken,
      'Content-Type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({ fields: encodeFirestoreFields(fields) }),
  });

  if (result.status === 409) return { created: false, duplicate: true };
  if (!result.ok) {
    throw new Error('Firestore notification write failed (' + result.status + ')');
  }
  return { created: true, duplicate: false };
}

function extractFcmTokens(user) {
  if (!user) return [];
  const raw = user.fcmTokens ?? user.fcmToken;
  let tokens = [];

  if (Array.isArray(raw)) {
    tokens = raw;
  } else if (typeof raw === 'string') {
    tokens = [raw];
  } else if (raw && typeof raw === 'object') {
    tokens = Object.entries(raw)
      .filter(([, enabled]) => enabled === true || enabled === 1)
      .map(([token]) => token);
  }

  return [...new Set(tokens.filter(
    (token) => typeof token === 'string' && token.length > 20,
  ))].slice(0, 20);
}

async function removeUnregisteredFcmTokens(recipientUid, staleTokens, recipientUser) {
  const uniqueTokens = [...new Set(staleTokens.filter(
    (token) => typeof token === 'string' && token.length > 20,
  ))];
  if (uniqueTokens.length === 0) return 0;

  const documentName = 'projects/' + PROJECT_ID +
    '/databases/(default)/documents/users/' + encodeURIComponent(recipientUid);
  const transforms = [];
  const matchedTokens = new Set();

  for (const fieldPath of ['fcmTokens', 'fcmToken']) {
    const storedValue = recipientUser?.[fieldPath];
    if (!Array.isArray(storedValue)) continue;
    const valuesToRemove = uniqueTokens.filter((token) => storedValue.includes(token));
    if (valuesToRemove.length === 0) continue;

    valuesToRemove.forEach((token) => matchedTokens.add(token));
    transforms.push({
      fieldPath,
      removeAllFromArray: {
        values: valuesToRemove.map((token) => ({ stringValue: token })),
      },
    });
  }

  if (transforms.length > 0) {
    const accessToken = await getGoogleAccessToken();
    const result = await fetch(
      'https://firestore.googleapis.com/v1/projects/' + PROJECT_ID +
        '/databases/(default)/documents:commit',
      {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + accessToken,
          'Content-Type': 'application/json; charset=utf-8',
        },
        body: JSON.stringify({
          writes: [{
            transform: {
              document: documentName,
              fieldTransforms: transforms,
            },
          }],
        }),
      },
    );
    if (!result.ok) {
      throw new Error('Firestore stale-token array cleanup failed (' + result.status + ')');
    }
  }

  // Older app versions may have stored a single token in fcmToken.
  if (
    typeof recipientUser?.fcmToken === 'string' &&
    uniqueTokens.includes(recipientUser.fcmToken)
  ) {
    const accessToken = await getGoogleAccessToken();
    const url = 'https://firestore.googleapis.com/v1/' + documentName +
      '?updateMask.fieldPaths=fcmToken';
    const result = await fetch(url, {
      method: 'PATCH',
      headers: {
        Authorization: 'Bearer ' + accessToken,
        'Content-Type': 'application/json; charset=utf-8',
      },
      body: JSON.stringify({
        name: documentName,
        fields: { fcmToken: { nullValue: 'NULL_VALUE' } },
      }),
    });
    if (!result.ok) {
      throw new Error('Firestore legacy-token cleanup failed (' + result.status + ')');
    }
    matchedTokens.add(recipientUser.fcmToken);
  }

  return matchedTokens.size;
}

function toFcmData(data, notificationId, orderId, status) {
  const result = {
    notificationId,
    type: 'order_status',
    orderId,
    status,
    route: typeof data.route === 'string' && data.route.startsWith('/')
      ? data.route
      : '/notifications',
  };

  for (const [key, value] of Object.entries(data)) {
    if (
      /^[A-Za-z0-9_-]{1,40}$/.test(key) &&
      value !== null &&
      value !== undefined &&
      ['string', 'number', 'boolean'].includes(typeof value)
    ) {
      result[key] = String(value).slice(0, 500);
    }
  }

  // Keep these trusted routing/status values authoritative.
  result.notificationId = notificationId;
  result.type = 'order_status';
  result.orderId = orderId;
  result.status = status;
  return result;
}

async function sendToFcm(token, title, body, data) {
  const accessToken = await getGoogleAccessToken();
  const result = await fetch(
    'https://fcm.googleapis.com/v1/projects/' + PROJECT_ID + '/messages:send',
    {
      method: 'POST',
      headers: {
        Authorization: 'Bearer ' + accessToken,
        'Content-Type': 'application/json; charset=utf-8',
      },
      body: JSON.stringify({
        message: {
          token,
          notification: { title, body },
          data,
          android: {
            priority: 'HIGH',
            notification: { channel_id: 'matjar_default_channel' },
          },
        },
      }),
    },
  );

  if (!result.ok) {
    const errorBody = await result.text().catch(() => '');
    let payload = {};
    try {
      payload = JSON.parse(errorBody);
    } catch {
      // Some upstream failures may not return JSON.
    }

    const apiError = payload?.error ?? {};
    const details = Array.isArray(apiError.details) ? apiError.details : [];
    const fcmDetail = details.find((item) =>
      typeof item?.errorCode === 'string' ||
      (typeof item?.['@type'] === 'string' &&
        item['@type'].includes('google.firebase.fcm.v1.FcmError')),
    );

    return {
      ok: false,
      status: result.status,
      errorStatus: typeof apiError.status === 'string'
        ? apiError.status.slice(0, 80)
        : 'UNKNOWN',
      errorCode: typeof fcmDetail?.errorCode === 'string'
        ? fcmDetail.errorCode.slice(0, 80)
        : '',
      errorMessage: typeof apiError.message === 'string'
        ? apiError.message.replace(/\s+/g, ' ').slice(0, 180)
        : 'FCM request rejected',
    };
  }
  return { ok: true };
}

async function sendComplaintNotification({
  notificationId,
  recipientUid,
  recipientUser,
  senderUid,
  title,
  body,
  complaintId,
  event,
  route,
}) {
  const notificationData = {
    complaintId,
    event,
    route: typeof route === 'string' && route.startsWith('/')
      ? route
      : '/notifications',
  };

  const writeResult = await createNotificationDocument(notificationId, {
    recipientUid,
    senderUid,
    title,
    body,
    type: 'complaint',
    data: notificationData,
    isRead: false,
    createdAt: new Date(),
  });

  if (writeResult.duplicate) {
    return {
      success: true,
      duplicate: true,
      stored: true,
      sent: 0,
      failed: 0,
    };
  }

  const tokens = extractFcmTokens(recipientUser);
  if (tokens.length === 0) {
    return {
      success: true,
      stored: true,
      sent: 0,
      failed: 0,
      reason: 'No registered FCM tokens for recipient',
    };
  }

  const fcmData = {
    notificationId,
    type: 'complaint',
    complaintId,
    event,
    route: notificationData.route,
  };
  const results = await Promise.all(
    tokens.map(async (token, index) => {
      try {
        return {
          ...(await sendToFcm(token, title, body, fcmData)),
          tokenIndex: index + 1,
        };
      } catch (error) {
        return {
          ok: false,
          status: 0,
          errorStatus: 'NETWORK_ERROR',
          errorCode: error instanceof Error ? error.name.slice(0, 80) : 'FETCH_ERROR',
          errorMessage: 'The request to the FCM API could not be completed',
          tokenIndex: index + 1,
        };
      }
    }),
  );

  const sent = results.filter((item) => item.ok).length;
  const failed = results.length - sent;
  const unregisteredTokens = results
    .filter((item) => !item.ok && item.errorCode === 'UNREGISTERED')
    .map((item) => tokens[item.tokenIndex - 1])
    .filter(Boolean);

  let staleTokensRemoved = 0;
  if (unregisteredTokens.length > 0) {
    try {
      staleTokensRemoved = await removeUnregisteredFcmTokens(
        recipientUid,
        unregisteredTokens,
        recipientUser,
      );
      console.info('[FCM] removed unregistered device tokens:', staleTokensRemoved);
    } catch (cleanupError) {
      console.error(
        '[FCM] stale-token cleanup failed:',
        cleanupError instanceof Error ? cleanupError.message : 'unknown error',
      );
    }
  }

  if (failed > 0) {
    const failures = results
      .filter((item) => !item.ok)
      .map((item) => ({
        tokenIndex: item.tokenIndex,
        httpStatus: item.status,
        fcmStatus: item.errorStatus || 'UNKNOWN',
        fcmErrorCode: item.errorCode || '',
        message: item.errorMessage || 'Unknown FCM error',
      }));
    console.error('[FCM] complaint send failures:', JSON.stringify({
      failed,
      total: results.length,
      staleTokensRemoved,
      failures,
    }));
  }

  return {
    success: true,
    stored: true,
    sent,
    failed,
    staleTokensRemoved,
  };
}

function safeId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,150}$/.test(value);
}

function safeText(value, maxLength) {
  return typeof value === 'string' ? value.trim().slice(0, maxLength) : '';
}

export const handler = async (event) => {
  const cors = corsHeaders(event);
  const commonHeaders = {
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    ...((cors && cors.Vary) ? { Vary: cors.Vary } : {}),
  };

  if (event.httpMethod === 'OPTIONS') {
    if (cors === null) return response(403, { error: 'Origin not allowed' });
    return { statusCode: 204, headers: { ...commonHeaders, ...(cors || {}) }, body: '' };
  }
  if (event.httpMethod !== 'POST') {
    return response(405, { error: 'Method not allowed' }, commonHeaders);
  }
  if (cors === null) {
    return response(403, { error: 'Origin not allowed' }, commonHeaders);
  }

  const headers = { ...commonHeaders, ...(cors || {}) };
  const authorization = event.headers?.authorization || event.headers?.Authorization || '';
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) return response(401, { error: 'Authentication required' }, headers);

  try {
    let requestBody;
    try {
      const rawBody = event.isBase64Encoded
        ? Buffer.from(event.body || '', 'base64').toString('utf8')
        : (event.body || '');
      requestBody = JSON.parse(rawBody);
    } catch {
      return response(400, { error: 'Invalid JSON body' }, headers);
    }

    const notificationId = requestBody?.notificationId;
    const recipientUid = requestBody?.recipientUid;
    const title = safeText(requestBody?.title, 120);
    const body = safeText(requestBody?.body, 400);
    const type = safeText(requestBody?.type || 'system', 40);
    const data = requestBody?.data && typeof requestBody.data === 'object' &&
      !Array.isArray(requestBody.data)
      ? requestBody.data
      : {};

    // The Flutter NotificationService sends notificationId/recipientUid/title/body/type/data.
    // Order context must be inside data; the target is never trusted without checking Firestore.
    const orderId = data.orderId || data.order_id;
    const newStatus = data.newStatus || data.new_status || data.status || data.toStatus || data.to_status;

    if (!safeId(notificationId) || !safeId(recipientUid) || !title || !body) {
      return response(400, { error: 'notificationId, recipientUid, title and body are required' }, headers);
    }
    if (type === 'complaint') {
      if (
        !safeId(data.complaintId) ||
        !['created', 'resolved'].includes(safeText(data.event, 32))
      ) {
        return response(400, {
          error: 'Complaint notifications require data.complaintId and event created or resolved',
        }, headers);
      }
    } else if (
      type !== 'order' && type !== 'payment'
    ) {
      return response(400, { error: 'Unsupported notification type' }, headers);
    } else if (
      !safeId(orderId) ||
      typeof newStatus !== 'string' ||
      !Object.hasOwn(STATUS_LABELS, newStatus)
    ) {
      return response(400, {
        error: 'Order notifications require data.orderId and a supported data.status',
      }, headers);
    }

    const { payload: identity } = await jwtVerify(match[1], FIREBASE_JWKS, {
      issuer: FIREBASE_ISSUER,
      audience: PROJECT_ID,
      algorithms: ['RS256'],
    });

    const senderUid = identity.sub;
    if (!safeId(senderUid)) {
      return response(401, { error: 'Invalid authentication token' }, headers);
    }

    if (type === 'complaint') {
      const complaintId = data.complaintId;
      const complaintEvent = safeText(data.event, 32);
      const [complaint, sender] = await Promise.all([
        getFirestoreDocument('complaints/' + encodeURIComponent(complaintId)),
        getFirestoreDocument('users/' + encodeURIComponent(senderUid)),
      ]);

      if (!complaint) return response(404, { error: 'Complaint not found' }, headers);
      if (!sender) return response(403, { error: 'User account not found' }, headers);

      const senderAccountStatus = safeText(sender.status, 32).toLowerCase();
      if (['disabled', 'suspended', 'blocked', 'deleted'].includes(senderAccountStatus)) {
        return response(403, { error: 'User account is not active' }, headers);
      }
      const senderRole = safeText(sender.role || identity.role || '', 64).toLowerCase();
      const complainantUid = safeText(complaint.complainantUid, 128);
      let allowed = false;

      if (complaintEvent === 'created') {
        allowed = senderUid === complainantUid && senderRole !== '';
        if (allowed) {
          const recipient = await getFirestoreDocument(
            'users/' + encodeURIComponent(recipientUid),
          );
          if (!recipient || !ADMIN_ROLES.has(
            safeText(recipient.role, 64).toLowerCase(),
          )) {
            return response(403, {
              error: 'New complaint notifications may only target an administrator',
            }, headers);
          }
        }
      } else if (complaintEvent === 'resolved') {
        allowed = SUPPORT_ROLES.has(senderRole) &&
          complaint.status === 'resolved' &&
          recipientUid === complainantUid;
      }

      if (!allowed) {
        return response(403, {
          error: 'Sender or recipient is not authorized for this complaint event',
        }, headers);
      }

      if (recipientUid === senderUid) {
        return response(200, {
          success: true,
          skipped: true,
          reason: 'Sender does not receive their own notification',
        }, headers);
      }

      const recipientUser = await getFirestoreDocument(
        'users/' + encodeURIComponent(recipientUid),
      );
      if (!recipientUser) {
        return response(404, { error: 'Recipient account not found' }, headers);
      }
      const pushResult = await sendComplaintNotification({
        notificationId: safeText(requestBody.notificationId, 150),
        recipientUid,
        recipientUser,
        senderUid,
        title,
        body,
        complaintId,
        event: complaintEvent,
        route: data.route,
      });
      return response(200, pushResult, headers);
    }

    const [order, sender] = await Promise.all([
      getFirestoreDocument('orders/' + encodeURIComponent(orderId)),
      getFirestoreDocument('users/' + encodeURIComponent(senderUid)),
    ]);

    if (!order) return response(404, { error: 'Order not found' }, headers);
    if (!sender) return response(403, { error: 'User account not found' }, headers);

    const accountStatus = String(sender.status || '').toLowerCase();
    if (['disabled', 'suspended', 'blocked', 'deleted'].includes(accountStatus)) {
      return response(403, { error: 'User account is not active' }, headers);
    }
    if (order.status !== newStatus) {
      return response(409, { error: 'The order status does not match this notification' }, headers);
    }

    const customerUid = order.customerUid;
    const assignedAgentUid = order.assignedAgentUid;
    const storeId = order.storeId;
    let storeOwnerUid = order.merchantUid || order.storeOwnerUid || order.ownerUid || null;

    if (!storeOwnerUid && safeId(storeId)) {
      const store = await getFirestoreDocument('stores/' + encodeURIComponent(storeId));
      storeOwnerUid = store?.ownerUid || store?.merchantUid || store?.userId || null;
    }

    const participants = [...new Set(
      [customerUid, assignedAgentUid, storeOwnerUid].filter((uid) => safeId(uid)),
    )];
    const role = String(sender.role || identity.role || '').toLowerCase();
    const isAdmin = ['admin_staff', 'super_admin'].includes(role);
    const isCustomer = senderUid === customerUid;
    const isMerchant = senderUid === storeOwnerUid;
    const isAgent = senderUid === assignedAgentUid;

    if (newStatus === 'awaiting_payment_confirmation' &&
        (!isCustomer || recipientUid !== storeOwnerUid)) {
      return response(403, {
        error: 'Payment-submission notifications may only be sent by the customer to the store owner',
      }, headers);
    }
    if (newStatus === 'payment_rejected' && !isAdmin) {
      return response(403, {
        error: 'Only an administrator may send payment-rejection notifications',
      }, headers);
    }
    if (!isAdmin && !participants.includes(senderUid)) {
      return response(403, { error: 'You are not a participant in this order' }, headers);
    }
    if (!isAdmin && MERCHANT_STATUSES.has(newStatus) && !isMerchant) {
      return response(403, { error: 'Only the store owner or an administrator can notify this status' }, headers);
    }
    const isMerchantLegacyDeliveryCompletion =
      newStatus === 'delivered' && isMerchant;
    if (!isAdmin && AGENT_STATUSES.has(newStatus) &&
        !isAgent && !isMerchantLegacyDeliveryCompletion) {
      return response(403, { error: 'Only the assigned delivery agent or an administrator can notify this status' }, headers);
    }
    if (!isAdmin && CUSTOMER_STATUSES.has(newStatus) && !isCustomer) {
      return response(403, { error: 'Only the customer or an administrator can notify this status' }, headers);
    }
    if (
      !isAdmin &&
      PARTICIPANT_STATUSES.has(newStatus) &&
      !(isCustomer || isMerchant || isAgent)
    ) {
      return response(403, { error: 'An order participant or administrator is required for this status' }, headers);
    }

    // OrderNotifier intentionally targets the current user for some events
    // (for example: the customer notification for their own pending order).
    // Accept that request as a no-op instead of creating a duplicate fallback.
    if (recipientUid === senderUid) {
      return response(200, { success: true, skipped: true, reason: 'Sender does not receive their own notification' }, headers);
    }

    const isAvailableAgentBroadcast =
      data.for === 'agent' && newStatus === 'ready_for_pickup';

    let isEligibleBroadcastAgent = false;
    if (!participants.includes(recipientUid) && isAvailableAgentBroadcast) {
      const agentProfile = await getFirestoreDocument(
        'delivery_agents/' + encodeURIComponent(recipientUid),
      );
      if (
        !agentProfile ||
        agentProfile.isAvailable !== true ||
        agentProfile.approvalStatus !== 'approved' ||
        agentProfile.isActive === false
      ) {
        return response(403, { error: 'Recipient is not an approved, available delivery agent' }, headers);
      }
      isEligibleBroadcastAgent = true;
    }

    if (!participants.includes(recipientUid) && !isEligibleBroadcastAgent) {
      return response(403, { error: 'Recipient is not an order participant or eligible available agent' }, headers);
    }

    const recipientUser = await getFirestoreDocument(
      'users/' + encodeURIComponent(recipientUid),
    );
    if (!recipientUser) {
      return response(404, { error: 'Recipient account not found' }, headers);
    }
    if (
      isEligibleBroadcastAgent &&
      String(recipientUser.role || '').toLowerCase() !== 'delivery_agent'
    ) {
      return response(403, { error: 'Broadcast recipient is not a delivery-agent account' }, headers);
    }

    const notificationData = {
      ...data,
      orderId,
      status: newStatus,
      route: typeof data.route === 'string' && data.route.startsWith('/')
        ? data.route
        : '/notifications',
    };

    // Store the in-app notification first; the Flutter screen reads this collection.
    const writeResult = await createNotificationDocument(notificationId, {
      recipientUid,
      senderUid,
      title,
      body,
      type,
      data: notificationData,
      isRead: false,
      createdAt: new Date(),
    });

    if (writeResult.duplicate) {
      return response(200, { success: true, duplicate: true, sent: 0 }, headers);
    }

    const tokens = extractFcmTokens(recipientUser);
    if (tokens.length === 0) {
      return response(200, {
        success: true,
        stored: true,
        sent: 0,
        reason: 'No registered FCM tokens for recipient',
      }, headers);
    }

    const fcmData = toFcmData(notificationData, notificationId, orderId, newStatus);
    const results = await Promise.all(
      tokens.map(async (token, index) => {
        try {
          return {
            ...(await sendToFcm(token, title, body, fcmData)),
            tokenIndex: index + 1,
          };
        } catch (error) {
          // Never log the registration token or request credentials.
          return {
            ok: false,
            status: 0,
            errorStatus: 'NETWORK_ERROR',
            errorCode: error instanceof Error ? error.name.slice(0, 80) : 'FETCH_ERROR',
            errorMessage: 'The request to the FCM API could not be completed',
            tokenIndex: index + 1,
          };
        }
      }),
    );
    const sent = results.filter((item) => item.ok).length;
    const failed = results.length - sent;

    const unregisteredTokens = results
      .filter((item) => !item.ok && item.errorCode === 'UNREGISTERED')
      .map((item) => tokens[item.tokenIndex - 1])
      .filter(Boolean);

    let staleTokensRemoved = 0;
    if (unregisteredTokens.length > 0) {
      try {
        staleTokensRemoved = await removeUnregisteredFcmTokens(
          recipientUid,
          unregisteredTokens,
          recipientUser,
        );
        console.info('[FCM] removed unregistered device tokens:', staleTokensRemoved);
      } catch (cleanupError) {
        console.error(
          '[FCM] stale-token cleanup failed:',
          cleanupError instanceof Error ? cleanupError.message : 'unknown error',
        );
      }
    }

    if (failed > 0) {
      const failures = results
        .filter((item) => !item.ok)
        .map((item) => ({
          tokenIndex: item.tokenIndex,
          httpStatus: item.status,
          fcmStatus: item.errorStatus || 'UNKNOWN',
          fcmErrorCode: item.errorCode || '',
          message: item.errorMessage || 'Unknown FCM error',
        }));
      console.error('[FCM] individual send failures:', JSON.stringify({
        failed,
        total: results.length,
        staleTokensRemoved,
        failures,
      }));
    }

    // The in-app notification is already stored; return success to avoid the
    // mobile client writing a duplicate fallback record.
    return response(200, {
      success: true,
      stored: true,
      sent,
      failed,
    }, headers);
  } catch (error) {
    // Do not log secrets, service-account keys, ID tokens, or request bodies.
    console.error(
      'Notification function failed:',
      error instanceof Error ? error.message : 'unknown error',
    );
    return response(500, { error: 'Notification service temporarily unavailable' }, headers);
  }
};
