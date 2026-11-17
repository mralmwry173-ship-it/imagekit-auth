const crypto = require("node:crypto");

let firebaseJwks;

exports.handler = async (event) => {
  const origin = event.headers?.origin || event.headers?.Origin || "";
  const allowedOrigin = process.env.ALLOWED_ORIGIN || "";

  const headers = {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin"
  };

  if (origin) {
    if (!allowedOrigin || origin !== allowedOrigin) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ error: "Origin not allowed" })
      };
    }

    headers["Access-Control-Allow-Origin"] = origin;
  }

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers, body: "" };
  }

  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ error: "Method not allowed" })
    };
  }

  const apiKey = process.env.FIREBASE_WEB_API_KEY;
  const privateKey = process.env.IMAGEKIT_PRIVATE_KEY;

  if (!apiKey || !privateKey) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: "Server configuration is incomplete" })
    };
  }

  const authHeader =
    event.headers?.authorization ||
    event.headers?.Authorization ||
    "";

  const match = authHeader.match(/^Bearer\s+(.+)$/i);

  if (!match) {
    return {
      statusCode: 401,
      headers,
      body: JSON.stringify({ error: "Authentication required" })
    };
  }

  try {
    const { createRemoteJWKSet, jwtVerify } = await import("jose");

    if (!firebaseJwks) {
      firebaseJwks = createRemoteJWKSet(
        new URL(
          "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"
        )
      );
    }

    // التحقق من توقيع رمز Firebase وبياناته الأساسية
    const { payload } = await jwtVerify(
      match[1],
      firebaseJwks,
      {
        issuer: "https://securetoken.google.com/matjar-yemen",
        audience: "matjar-yemen",
        algorithms: ["RS256"]
      }
    );

    if (
      typeof payload.sub !== "string" ||
      !payload.sub ||
      typeof payload.auth_time !== "number"
    ) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: "Invalid login token" })
      };
    }

    // السماح بأدوار محددة فقط
    const allowedRoles = [
      "merchant",
      "grocery_owner",
      "admin_staff",
      "super_admin"
    ];

    if (!allowedRoles.includes(payload.role)) {
      return {
        statusCode: 403,
        headers,
        body: JSON.stringify({ error: "You are not allowed to upload product images" })
      };
    }

    // التأكد من أن حساب Firebase موجود وغير معطّل
    const verification = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${encodeURIComponent(apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idToken: match[1] })
      }
    );

    if (!verification.ok) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: "Invalid or expired login" })
      };
    }

    const userData = await verification.json();
    const firebaseUser = userData.users?.[0];

    if (
      !firebaseUser ||
      firebaseUser.localId !== payload.sub ||
      firebaseUser.disabled === true
    ) {
      return {
        statusCode: 401,
        headers,
        body: JSON.stringify({ error: "Account is unavailable" })
      };
    }

    // رفض الرمز إذا كان أقدم من وقت إبطال الجلسات في Firebase
    if (firebaseUser.validSince) {
      const validSince = Number(firebaseUser.validSince);

      if (
        Number.isFinite(validSince) &&
        validSince > 0 &&
        payload.auth_time < validSince
      ) {
        return {
          statusCode: 401,
          headers,
          body: JSON.stringify({ error: "Login session has expired" })
        };
      }
    }

    // إصدار بيانات توقيع ImageKit بعد اجتياز التحقق
    const token = crypto.randomUUID();
    const expire = Math.floor(Date.now() / 1000) + 600;

    const signature = crypto
      .createHmac("sha1", privateKey)
      .update(token + expire)
      .digest("hex");

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        token,
        expire,
        signature
      })
    };
  } catch (error) {
    // لا نعرض تفاصيل الأخطاء الداخلية أو الأسرار للمستخدم
    return {
      statusCode: 401,
      headers,
      body: JSON.stringify({ error: "Authentication failed" })
    };
  }
};
