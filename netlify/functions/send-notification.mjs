import { createRemoteJWKSet, jwtVerify } from 'jose';
import { createSign } from 'node:crypto';

const PROJECT_ID = 'matjar-yemen';
const FIREBASE_ISSUER = 'https://securetoken.google.com/' + PROJECT_ID;
const FIREBASE_JWKS = createRemoteJWKSet(
  new URL('https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com'),
);

const ORDER_STATUS_LABELS = {
  pending: 'قيد الانتظار',
  payment_pending: 'بانتظار تأكيد الدفع',
  paid: 'تم تأكيد الدفع',
  confirmed: 'تم تأكيد الطلب',
  preparing: 'جارٍ تجهيز الطلب',
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
};

const MERCHANT_STATUSES = new Set([
  'paid', 'confirmed', 'preparing', 'ready_for_pickup', 'delivery_searching', 'rejected',
]);
const AGENT_STATUSES = new Set([
  'assigned_to_agent', 'picked_up', 'on_the_way', 'delivering', 'delivered',
]);
const PARTICIPANT_STATUSES = new Set([
  'pending', 'payment_pending', 'completed', 'cancelled',
]);

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
  const url = 'https://firestore.googleapis.com/v1/projects/' + PROJECT_ID + '/databases/(default)/documents/' + path;
  const result = await fetch(url, {
    headers: { Authorization: 'Bearer ' + token },
  });

  if (result.status === 404) return null;
  if (!result.ok) throw new Error('Firestore read failed (' + result.status + ')');

  const document = await result.json();
  return decodeFirestoreFields(document.fields || {});
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

  return [...new Set(tokens.filter((token) => typeof token === 'string' && token.length > 20))]
    .slice(0, 20);
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
          android: { priority: 'HIGH' },
        },
      }),
    },
  );

  if (!result.ok) {
    const errorBody = await result.text().catch(() => '');
    return { ok: false, status: result.status, error: errorBody.slice(0, 500) };
  }
  return { ok: true };
}

function safeId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,150}$/.test(value);
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

    const payload = requestBody?.event && typeof requestBody.event === 'object'
      ? requestBody.event
      : requestBody?.data && typeof requestBody.data === 'object'
        ? requestBody.data
        : requestBody;

    const orderId = payload?.orderId;
    const newStatus = payload?.newStatus || payload?.new_status || payload?.status;
    if (!safeId(orderId) || typeof newStatus !== 'string' || !Object.hasOwn(ORDER_STATUS_LABELS, newStatus)) {
      return response(400, { error: 'An orderId and a supported newStatus are required' }, headers);
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
      [customerUid, assignedAgentUid, storeOwnerUid]
        .filter((uid) => safeId(uid)),
    )];
    const role = String(sender.role || identity.role || '').toLowerCase();
    const isAdmin = ['admin_staff', 'super_admin'].includes(role);
    const isCustomer = senderUid === customerUid;
    const isMerchant = senderUid === storeOwnerUid;
    const isAgent = senderUid === assignedAgentUid;

    if (!isAdmin && !participants.includes(senderUid)) {
      return response(403, { error: 'You are not a participant in this order' }, headers);
    }
    if (!isAdmin && MERCHANT_STATUSES.has(newStatus) && !isMerchant) {
      return response(403, { error: 'Only the store owner or an administrator can notify this status' }, headers);
    }
    if (!isAdmin && AGENT_STATUSES.has(newStatus) && !isAgent) {
      return response(403, { error: 'Only the assigned delivery agent or an administrator can notify this status' }, headers);
    }
    if (!isAdmin && PARTICIPANT_STATUSES.has(newStatus) && !(isCustomer || isMerchant || isAgent)) {
      return response(403, { error: 'Order participant required' }, headers);
    }

    let recipientUids = participants.filter((uid) => uid !== senderUid);
    const requestedRecipient = payload.recipientUid || payload.targetUid || requestBody?.recipientUid || requestBody?.targetUid;
    if (requestedRecipient !== undefined) {
      if (!safeId(requestedRecipient) || !recipientUids.includes(requestedRecipient)) {
        return response(403, { error: 'Recipient is not a participant in this order' }, headers);
      }
      recipientUids = [requestedRecipient];
    }
    const requestedUids = payload.recipientUids || requestBody?.recipientUids;
    if (Array.isArray(requestedUids)) {
      const requested = [...new Set(requestedUids)];
      if (
        requested.length === 0 ||
        requested.some((uid) => !safeId(uid) || !recipientUids.includes(uid))
      ) {
        return response(403, { error: 'One or more recipients are not participants in this order' }, headers);
      }
      recipientUids = requested;
    }

    if (recipientUids.length === 0) {
      return response(200, { success: true, sent: 0, reason: 'No other order participants' }, headers);
    }

    const recipientUsers = await Promise.all(
      recipientUids.map(async (uid) => ({ uid, user: await getFirestoreDocument('users/' + encodeURIComponent(uid)) })),
    );
    const tokenTargets = recipientUsers.flatMap(({ uid, user }) =>
      extractFcmTokens(user).map((token) => ({ uid, token })),
    );

    if (tokenTargets.length === 0) {
      return response(200, { success: true, sent: 0, reason: 'No registered notification tokens' }, headers);
    }

    const title = 'تحديث الطلب ' + orderId;
    const body = 'حالة طلبك الآن: ' + ORDER_STATUS_LABELS[newStatus];
    const data = {
      type: 'order_status',
      orderId,
      status: newStatus,
      route: '/notifications',
    };

    const results = await Promise.all(
      tokenTargets.map(({ token }) => sendToFcm(token, title, body, data)),
    );
    const sent = results.filter((result) => result.ok).length;
    const failed = results.length - sent;

    if (sent === 0 && failed > 0) {
      console.error('FCM send failed for all targeted device tokens.');
      return response(502, { success: false, sent, failed }, headers);
    }

    return response(200, {
      success: true,
      sent,
      failed,
      recipientCount: recipientUids.length,
    }, headers);
  } catch (error) {
    // Avoid logging credentials, tokens, request bodies, or private-key material.
    console.error('Notification function failed:', error instanceof Error ? error.message : 'unknown error');
    return response(500, { error: 'Notification service temporarily unavailable' }, headers);
  }
};
