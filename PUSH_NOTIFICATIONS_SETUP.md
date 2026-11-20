# Push Notifications – Matjar Yemen

This branch contains an authenticated Netlify Function for Firebase Cloud Messaging HTTP v1. It stores in-app notifications in Firestore and sends push notifications to registered devices.

## Existing services kept unchanged

- `netlify/functions/imagekit-auth.js` is not modified.
- `netlify.toml` is not modified.
- `package.json` and `package-lock.json` are not modified.
- Existing ImageKit environment variables must remain unchanged.
- No Firebase Functions deployment or Blaze upgrade is required for this Netlify endpoint.

## Request contract

Flutter sends:

```json
{
  "notificationId": "<Firestore notification document id>",
  "recipientUid": "<recipient user uid>",
  "title": "<notification title>",
  "body": "<notification body>",
  "type": "order",
  "data": {
    "orderId": "<orders document id>",
    "status": "confirmed",
    "route": "/notifications"
  }
}
```

The endpoint requires a Firebase ID token in the Authorization header. It never accepts device tokens or Firebase service-account credentials from the mobile app.

## Supported order events

The function validates the current Firestore order status and verifies that the sender and recipient are associated with the order.

Order status names currently supported include:

- Customer/order intake: `pending`, `payment_pending`, `paid`, `confirmed`.
- Merchant workflow: `preparing`, `processing`, `ready_for_pickup`, `delivery_searching`, `shipped`, `rejected`.
- Delivery workflow: `assigned_to_agent`, `picked_up`, `on_the_way`, `delivering`, `delivered`, `failed_delivery`.
- Order closure: `completed`, `cancelled`, `returned`.

Legacy `processing` and `shipped` values are accepted because they are still used by the current merchant orders screen. The sender's role and relationship to the order are checked before a notification is stored or sent. Available-agent broadcasts for `ready_for_pickup` additionally require an approved, active, available delivery-agent profile.

## Supported complaint events

Only two complaint events are accepted:

- `created`: the authenticated sender must be the complaint's `complainantUid`; the recipient must have role `super_admin` or `admin_staff`.
- `resolved`: the authenticated sender must have role `super_admin`, `admin_staff`, or `support`; the complaint must already have status `resolved`; the recipient must equal `complainantUid`.

The complaint document uses `complainantUid` and `status` fields, as written by the current Flutter complaint screens. Other complaint events are not accepted.

## Firestore data

The function reads:

- `orders/{orderId}`: `customerUid`, `storeId`, `assignedAgentUid`, `status`, and merchant-owner fallback fields when present.
- `stores/{storeId}`: `ownerUid` (or supported owner aliases).
- `complaints/{complaintId}`: `complainantUid` and `status`.
- `delivery_agents/{uid}`: approval, active, and availability fields for ready-for-pickup broadcasts.
- `users/{uid}`: role, account status, and registered FCM tokens.
- `notifications/{notificationId}`: server-created in-app notification records.

The server writes the in-app notification before attempting FCM. A device-send failure therefore does not discard the in-app notification.

## FCM token lifecycle

Tokens are read from `users/{uid}.fcmTokens` (array) or the legacy `fcmToken` field. When FCM explicitly returns `UNREGISTERED`, the function removes only the affected token from that user's stored token list. Other registered tokens are preserved. Device tokens are never written to logs.

Per-device errors are logged using the response status, FCM error code, and token index only. Never log or share actual FCM tokens, Firebase ID tokens, the service-account JSON, or its base64 value.

## Netlify environment variable

Set `FIREBASE_SERVICE_ACCOUNT_BASE64` in the Netlify environment variables to the base64-encoded service-account JSON for project `matjar-yemen`.

The service account must be able to read and write the relevant Firestore documents and send FCM messages. Keep the value only in Netlify's secure environment settings. Never commit it or paste it into chat, GitHub, issues, or logs.

Keep `IMAGEKIT_PRIVATE_KEY`, `FIREBASE_WEB_API_KEY`, and existing ImageKit settings unchanged. Preserve `ALLOWED_ORIGIN`; native mobile requests normally have no Origin header.

## Flutter integration checks

- `NotificationService.send()` must send the Firebase ID token, notification ID, recipient UID, title, body, type, and data.
- `FcmService` must save the current user's FCM token after sign-in and listen for token refresh.
- The app must expose the root route `/notifications` for all roles, and notification taps must navigate through the app router.
- Foreground notifications use the local notification plugin; background notifications are displayed by FCM/Android using the notification payload.
- Test the customer, merchant, and delivery-agent flows with test orders and accounts before production.

## Current test status and deliberate limits

- A merchant-acceptance push was received on a second Android phone using Deploy Preview.
- The function has logged and removed obsolete `UNREGISTERED` FCM tokens.
- Complaint create/resolve server authorization has been added but still requires a live end-to-end test.
- Delivery-agent status changes still require verification of the actual Flutter write path and a live end-to-end test.
- Foreground, background, and terminated-state behavior must be tested separately on real Android devices.
- Do not merge the draft pull request or deploy the production branch until those checks pass.
