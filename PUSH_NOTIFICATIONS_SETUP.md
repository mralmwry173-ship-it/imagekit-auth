# Push Notifications – Matjar Yemen

This branch adds an independent Netlify Function for Firebase Cloud Messaging HTTP v1 order-status notifications.

## What is kept unchanged
- Existing `netlify/functions/imagekit-auth.js` remains unchanged.
- Existing `netlify.toml` remains unchanged.
- Existing `package.json` and `package-lock.json` remain unchanged; the function uses the already-installed `jose` package and Node.js built-ins.
- Existing ImageKit environment variables must remain unchanged.
- No Firebase Functions deployment or Blaze upgrade is needed for this Netlify endpoint.

## Flutter request contract
The current Flutter `NotificationService.send()` posts this shape:

```json
{
  "notificationId": "<new Firestore document id>",
  "recipientUid": "<other order participant uid>",
  "title": "<notification title>",
  "body": "<notification text>",
  "type": "order_status",
  "data": {
    "orderId": "<orders document id>",
    "newStatus": "assigned_to_agent",
    "route": "/notifications"
  }
}
```

The endpoint accepts the status in `data.newStatus`, `data.new_status`, `data.status`, or `data.toStatus`. The order context must remain inside the `data` map because that is what the current Flutter service sends.

## Firestore fields verified against the Flutter models
- `orders/{orderId}`: `customerUid`, `storeId`, `assignedAgentUid`, and `status`.
- `stores/{storeId}`: `ownerUid`.
- `users/{uid}`: `role`, optional `status`, and `fcmTokens` (the FCM service writes this as an array using `FieldValue.arrayUnion`).
- `notifications/{notificationId}`: written by the server with `recipientUid`, `senderUid`, `title`, `body`, `type`, `data`, `isRead`, and a Firestore timestamp `createdAt`.

The server verifies the Firebase ID token, loads the order and sender from Firestore, confirms the order has the requested current status, verifies that the sender is allowed to report that status, and confirms the requested recipient is another participant in the same order. It never accepts an FCM token from the client.

Supported order statuses are enumerated in the function. Merchant statuses require the store owner (or an administrator); delivery statuses require the assigned agent (or an administrator); customer statuses require the customer (or an administrator).

## Netlify environment variable
Set `FIREBASE_SERVICE_ACCOUNT_BASE64` in the Netlify site's environment variables to the base64-encoded Firebase service-account JSON for project `matjar-yemen`.

The service account must have permission to read/write the Firestore database and send Firebase Cloud Messaging messages. Add it only in Netlify's secure environment-variable settings. Never commit the service-account JSON or paste its base64 value into GitHub, chat, issues, or logs.

Keep `IMAGEKIT_PRIVATE_KEY`, `FIREBASE_WEB_API_KEY`, and any existing ImageKit-related variables exactly as they are. Do not replace or remove `ALLOWED_ORIGIN`; native mobile requests normally have no Origin header, while web requests are checked against the configured origin.

## Deliberate limits
- This first version handles order-status notifications only. Complaint notification authorization is not implemented because the complaint schema and participant rules have not yet been verified.
- If `data.orderId` or a supported status is missing, the endpoint rejects the request. The current Flutter service then attempts its existing Firestore fallback.
- The function stores the in-app notification before attempting FCM, so notification history remains available even when a device has no registered token or FCM is temporarily unavailable.
- Stale-token cleanup and delivery analytics are not included in this first version.

## Deploy Preview and test
1. Configure `FIREBASE_SERVICE_ACCOUNT_BASE64` in Netlify without sharing the value.
2. Confirm the current Android app has registered a token under `users/{uid}.fcmTokens`.
3. Use a test order, not a real customer order.
4. Call the endpoint through the app after the order status update.
5. Verify the `notifications/{notificationId}` document is created and the recipient receives the notification.
6. Test foreground, background, and terminated app states.
7. Do not merge this draft PR until the exact `OrderNotifier` payload is verified and the tests pass.
