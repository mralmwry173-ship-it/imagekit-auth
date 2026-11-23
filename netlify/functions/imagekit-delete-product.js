const PROJECT_ID = "matjar-yemen";
const FIRESTORE_ROOT = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents`;
let firebaseJwks;

function jsonResponse(statusCode, headers, payload) {
  return {
    statusCode,
    headers,
    body: JSON.stringify(payload),
  };
}

function stringField(document, fieldName) {
  const value = document?.fields?.[fieldName]?.stringValue;
  return typeof value === "string" ? value : "";
}

async function readFirestoreDocument(relativePath, idToken) {
  const url = `${FIRESTORE_ROOT}/${relativePath}`;
  const response = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${idToken}`,
      Accept: "application/json",
    },
    signal: AbortSignal.timeout(8000),
  });

  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`Firestore read failed (${response.status})`);
  }
  return response.json();
}

exports.handler = async (event) => {
  const origin = event.headers?.origin || event.headers?.Origin || "";
  const allowedOrigin = process.env.ALLOWED_ORIGIN || "";
  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    Vary: "Origin",
  };

  if (origin) {
    if (!allowedOrigin || origin !== allowedOrigin) {
      return jsonResponse(403, headers, { error: "Origin not allowed" });
    }
    headers["Access-Control-Allow-Origin"] = origin;
  }

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers, body: "" };
  }
  if (event.httpMethod !== "POST") {
    return jsonResponse(405, headers, { error: "Method not allowed" });
  }

  const firebaseApiKey = process.env.FIREBASE_WEB_API_KEY;
  const imageKitPrivateKey = process.env.IMAGEKIT_PRIVATE_KEY;
  if (!firebaseApiKey || !imageKitPrivateKey) {
    return jsonResponse(500, headers, { error: "Server configuration is incomplete" });
  }

  const authorization =
    event.headers?.authorization || event.headers?.Authorization || "";
  const bearerMatch = authorization.match(/^Bearer\s+(.+)$/i);
  if (!bearerMatch) {
    return jsonResponse(401, headers, { error: "Authentication required" });
  }

  let body;
  try {
    const rawBody = event.isBase64Encoded
      ? Buffer.from(event.body || "", "base64").toString("utf8")
      : (event.body || "{}");
    body = JSON.parse(rawBody);
  } catch {
    return jsonResponse(400, headers, { error: "Invalid request body" });
  }

  const productId = body?.productId;
  if (typeof productId !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(productId)) {
    return jsonResponse(400, headers, { error: "Invalid product ID" });
  }

  const idToken = bearerMatch[1];
  let uid;
  let role;

  try {
    const { createRemoteJWKSet, jwtVerify } = await import("jose");
    if (!firebaseJwks) {
      firebaseJwks = createRemoteJWKSet(
        new URL("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"),
      );
    }

    const { payload } = await jwtVerify(idToken, firebaseJwks, {
      issuer: `https://securetoken.google.com/${PROJECT_ID}`,
      audience: PROJECT_ID,
      algorithms: ["RS256"],
    });

    uid = payload.sub;
    role = payload.role;
    if (
      typeof uid !== "string" || !uid ||
      typeof payload.auth_time !== "number" ||
      !["merchant", "grocery_owner"].includes(role)
    ) {
      return jsonResponse(403, headers, { error: "Account is not allowed to delete products" });
    }

    // Confirm the Firebase account is still enabled and its login session valid.
    const verification = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(firebaseApiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idToken }),
        signal: AbortSignal.timeout(8000),
      },
    );
    if (!verification.ok) {
      return jsonResponse(401, headers, { error: "Invalid or expired login" });
    }

    const accountData = await verification.json();
    const firebaseUser = accountData.users?.[0];
    if (
      !firebaseUser ||
      firebaseUser.localId !== uid ||
      firebaseUser.disabled === true
    ) {
      return jsonResponse(401, headers, { error: "Account is unavailable" });
    }
    if (firebaseUser.validSince) {
      const validSince = Number(firebaseUser.validSince);
      if (Number.isFinite(validSince) && validSince > 0 && payload.auth_time < validSince) {
        return jsonResponse(401, headers, { error: "Login session has expired" });
      }
    }

    // The user's own profile is readable under the existing Firestore rules.
    const userDocument = await readFirestoreDocument(`users/${encodeURIComponent(uid)}`, idToken);
    if (
      !userDocument ||
      stringField(userDocument, "role") !== role ||
      stringField(userDocument, "status").toLowerCase() !== "active"
    ) {
      return jsonResponse(403, headers, { error: "Active merchant account required" });
    }

    // Product and store reads are public in the current Firestore rules;
    // ownership is then checked here and again by Firestore on final deletion.
    const productDocument = await readFirestoreDocument(`products/${encodeURIComponent(productId)}`, idToken);
    if (!productDocument) {
      return jsonResponse(404, headers, { error: "Product not found" });
    }

    const storeId = stringField(productDocument, "storeId");
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(storeId)) {
      return jsonResponse(409, headers, { error: "Product store data is invalid" });
    }

    const storeDocument = await readFirestoreDocument(`stores/${encodeURIComponent(storeId)}`, idToken);
    if (!storeDocument || stringField(storeDocument, "ownerUid") !== uid) {
      return jsonResponse(403, headers, { error: "You do not own this product's store" });
    }

    // ImageKit list API: list at most 26 images so unusually large folders
    // fail closed instead of deleting an unbounded number of files.
    const imageKitAuth = `Basic ${Buffer.from(`${imageKitPrivateKey}:`).toString("base64")}`;
    const listUrl = new URL("https://api.imagekit.io/v1/files");
    listUrl.searchParams.set("type", "file");
    listUrl.searchParams.set("fileType", "image");
    listUrl.searchParams.set("path", `/products/${productId}/`);
    listUrl.searchParams.set("limit", "26");
    listUrl.searchParams.set("skip", "0");

    const listResponse = await fetch(listUrl, {
      method: "GET",
      headers: { Authorization: imageKitAuth, Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });
    if (!listResponse.ok) {
      return jsonResponse(502, headers, { error: "Could not list this product's ImageKit files" });
    }

    const assets = await listResponse.json();
    if (!Array.isArray(assets)) {
      return jsonResponse(502, headers, { error: "Unexpected ImageKit file-list response" });
    }
    if (assets.length > 25) {
      return jsonResponse(409, headers, { error: "Too many files in this product folder; manual review is required" });
    }

    const allowedPrefix = `/products/${productId}/`;
    const fileIds = [];
    for (const asset of assets) {
      const filePath = typeof asset.filePath === "string"
        ? (asset.filePath.startsWith("/") ? asset.filePath : `/${asset.filePath}`)
        : "";
      if (!filePath.startsWith(allowedPrefix) || typeof asset.fileId !== "string" || !asset.fileId) {
        return jsonResponse(409, headers, { error: "ImageKit returned a file outside the expected product folder" });
      }
      fileIds.push(asset.fileId);
    }

    // Delete product images first. Keep the Firestore document
    // intact whenever any ImageKit deletion fails.
    let deletedImages = 0;
    let imageCleanupComplete = true;

    for (let offset = 0; offset < fileIds.length; offset += 5) {
      const batch = fileIds.slice(offset, offset + 5);

      const results = await Promise.allSettled(batch.map(async (fileId) => {
        const deleteResponse = await fetch(
          `https://api.imagekit.io/v1/files/${encodeURIComponent(fileId)}`,
          {
            method: "DELETE",
            headers: {
              Authorization: imageKitAuth,
              Accept: "application/json",
            },
            signal: AbortSignal.timeout(8000),
          },
        );

        if (!deleteResponse.ok && deleteResponse.status !== 404) {
          throw new Error(`ImageKit delete failed (${deleteResponse.status})`);
        }

        return true;
      }));

      deletedImages += results.filter(
        (result) => result.status === "fulfilled",
      ).length;

      if (results.some((result) => result.status === "rejected")) {
        imageCleanupComplete = false;
      }
    }

    // Do not delete the product document when even one image remains.
    // A retry will find and remove only the remaining files.
    if (!imageCleanupComplete) {
      return jsonResponse(502, headers, {
        success: false,
        productDeleted: false,
        deletedImages,
        imageCleanupComplete: false,
        error: "Some images could not be deleted. The product remains; retry deletion.",
      });
    }

    // Image cleanup succeeded. Firestore rules remain the final
    // authorization gate for deleting the product document.
    const firestoreDelete = await fetch(
      `${FIRESTORE_ROOT}/products/${encodeURIComponent(productId)}`,
      {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${idToken}`,
        },
        signal: AbortSignal.timeout(8000),
      },
    );

    if (!firestoreDelete.ok && firestoreDelete.status !== 404) {
      return jsonResponse(403, headers, {
        success: false,
        productDeleted: false,
        deletedImages,
        imageCleanupComplete: true,
        error: "Images were removed, but Firestore did not authorize product deletion. The product remains; retry after checking access.",
      });
    }

    return jsonResponse(200, headers, {
      success: true,
      productDeleted: true,
      deletedImages,
      imageCleanupComplete: true,
    });  } catch (error) {
    // Do not return internal error details, Firebase tokens, or private keys.
    console.error("[imagekit-delete-product] request failed:", error?.message || "unknown error");
    return jsonResponse(500, headers, { error: "Product and image deletion failed safely. Please retry." });
  }
};