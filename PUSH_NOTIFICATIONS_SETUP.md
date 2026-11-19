# Push Notifications – Matjar Yemen

This branch adds an independent Netlify Function for authenticated order-status push notifications using Firebase Cloud Messaging HTTP v1.

## Safety and compatibility
- Existing `netlify/functions/imagekit-auth.js` is unchanged.
- Existing `netlify.toml` is unchanged.
- Existing `package.json` and `package-lock.json` are unchanged; the function uses the already-installed `jose` dependency and Node.js built-ins.
- No Firebase Blaze upgrade is required by this endpoint.
- The endpoint verifies Firebase ID tokens, reads the order and its participants from Firestore, checks the sender's role/participation and only sends to other order participants' FCM tokens.
- The endpoint does not write Firestore notification documents; the app's existing Firestore notification flow remains responsible for the in-app notification history.

## Netlify environment variable
Set `FIREBASE_SERVICE_ACCOUNT_BASE64` in Netlify to the base64-encoded Firebase service-account JSON for project `matjar-yemen`. Do not commit the JSON file or paste the value into GitHub, issues, chat, or logs.

The service account must be authorized to read Firestore documents and send FCM messages. Keep existing ImageKit environment variables unchanged.

## Firestore schema expected by this function
- `orders/{orderId}`: `status`, `customerUid`, `assignedAgentUid`, `storeId`, and optionally `merchantUid`, `storeOwnerUid`, or `ownerUid`.
- `stores/{storeId}`: `ownerUid` (fallbacks: `merchantUid`, `userId`).
- `users/{uid}`: `role`, `status`, and `fcmTokens` (array, token string, or token-to-boolean map) or `fcmToken`.

These field names must be compared against the actual application schema before production use. The function currently supports order status changes only; complaint notifications are deliberately out of scope until complaint ownership and schema are reviewed.

## Request
POST `/.netlify/functions/send-notification` with:
- Header: `Authorization: Bearer <Firebase ID token>`
- JSON: `{"orderId":"<order document id>","newStatus":"ready_for_pickup"}`

Optional `recipientUid` or `recipientUids` values are accepted only if they match actual participants in that order.

## Deployment and test
1. Add the environment variable in Netlify.
2. Run a Netlify Deploy Preview for this branch.
3. Verify a logged-in Android app has a current token in `users/{uid}.fcmTokens`.
4. Test a real status change in a test order from the authorized merchant/assigned agent/admin.
5. Test foreground, background, and terminated app states.
6. Do not merge to `main` until the app's actual Firestore field names and request body are confirmed and tests pass.
