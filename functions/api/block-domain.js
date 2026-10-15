
const PROTECTED_DOMAINS = [
  "gmail.com",
  "hotmail.com",
  "highlightmotor.com",
  "cloudflare.com",
  "missiveapp.com",
  "microsoft.com",
  "google.com"
];

function jsonResponse(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store"
    }
  });
}

function decodeBase64Url(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded = base64.padEnd(
    Math.ceil(base64.length / 4) * 4,
    "="
  );

  return Uint8Array.from(
    atob(padded),
    character => character.charCodeAt(0)
  );
}

async function verifyAccess(request, env) {
  const token = request.headers.get(
    "Cf-Access-Jwt-Assertion"
  );

  if (
    !token ||
    !env.ACCESS_AUD ||
    !env.ACCESS_TEAM_DOMAIN
  ) {
    return {
      authorized: false,
      status: 401,
      message: "Authentication required"
    };
  }

  try {
    const teamDomain = String(env.ACCESS_TEAM_DOMAIN)
      .replace(/^https?:\/\//, "")
      .replace(/\/+$/, "");

    const certsResponse = await fetch(
      `https://${teamDomain}/cdn-cgi/access/certs`
    );

    if (!certsResponse.ok) {
      throw new Error("Cannot retrieve Access keys");
    }

    const { keys } = await certsResponse.json();

    const parts = token.split(".");

    if (parts.length !== 3) {
      throw new Error("Malformed Access token");
    }

    const [headerPart, payloadPart, signaturePart] =
      parts;

    const decoder = new TextDecoder();

    const header = JSON.parse(
      decoder.decode(decodeBase64Url(headerPart))
    );

    const payload = JSON.parse(
      decoder.decode(decodeBase64Url(payloadPart))
    );

    if (header.alg !== "RS256") {
      throw new Error("Unsupported signing algorithm");
    }

    const signingKey = keys.find(
      key => key.kid === header.kid
    );

    if (!signingKey) {
      throw new Error("Unknown signing key");
    }

    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      signingKey,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );

    const signatureValid =
      await crypto.subtle.verify(
        "RSASSA-PKCS1-v1_5",
        cryptoKey,
        decodeBase64Url(signaturePart),
        new TextEncoder().encode(
          `${headerPart}.${payloadPart}`
        )
      );

    const now = Math.floor(Date.now() / 1000);
    const expectedIssuer = `https://${teamDomain}`;

    const audienceValid = []
      .concat(payload.aud || [])
      .includes(env.ACCESS_AUD);

    const tokenValid =
      signatureValid &&
      payload.iss === expectedIssuer &&
      audienceValid &&
      typeof payload.exp === "number" &&
      payload.exp > now &&
      typeof payload.iat === "number" &&
      payload.iat <= now &&
      (
        typeof payload.nbf !== "number" ||
        payload.nbf <= now
      );

    if (!tokenValid) {
      throw new Error("Invalid Access token");
    }

    const email = String(payload.email || "")
      .trim()
      .toLowerCase();

    const allowedEmails = String(
      env.ALLOWED_EMAILS || ""
    )
      .split(",")
      .map(value => value.trim().toLowerCase())
      .filter(Boolean);

    if (!email || !allowedEmails.includes(email)) {
      return {
        authorized: false,
        status: 403,
        message: "Not authorized to block domains"
      };
    }

    return {
      authorized: true,
      email
    };

  } catch {
    return {
      authorized: false,
      status: 401,
      message: "Access verification failed"
    };
  }
}

function validateDomain(domain) {
  return (
    domain.length <= 253 &&
    /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)
  );
}

function isProtectedDomain(domain) {
  return PROTECTED_DOMAINS.some(
    protectedDomain =>
      domain === protectedDomain ||
      domain.endsWith("." + protectedDomain)
  );
}

export async function onRequestPost(context) {
  const { request, env } = context;

  // 1. Authenticate through Cloudflare Access.
  const access = await verifyAccess(request, env);

  if (!access.authorized) {
    return jsonResponse({
      success: false,
      blocked: false,
      message: access.message
    }, access.status);
  }

  // 2. Verify server-side n8n configuration.
  if (
    !env.N8N_WEBHOOK_URL ||
    !env.N8N_AUTH_HEADER_NAME ||
    !env.N8N_AUTH_HEADER_VALUE
  ) {
    return jsonResponse({
      success: false,
      blocked: false,
      message: "Server configuration incomplete"
    }, 503);
  }

  // 3. Read submitted JSON.
  let body;

  try {
    body = await request.json();

    if (
      !body ||
      typeof body !== "object" ||
      Array.isArray(body)
    ) {
      throw new Error("Invalid request body");
    }
  } catch {
    return jsonResponse({
      success: false,
      blocked: false,
      message: "Invalid JSON request"
    }, 400);
  }

  const domain = String(body.domain ?? "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");

  const reason = String(body.reason ?? "").trim();

  // 4. Validate domain.
  if (!validateDomain(domain)) {
    return jsonResponse({
      success: false,
      blocked: false,
      domain,
      message: "Invalid domain"
    }, 400);
  }

  // 5. Validate manually entered reason.
  if (
    reason.length < 5 ||
    reason.length > 500
  ) {
    return jsonResponse({
      success: false,
      blocked: false,
      domain,
      message: "Reason must contain between 5 and 500 characters"
    }, 400);
  }

  // 6. Reject protected domains and subdomains.
  if (isProtectedDomain(domain)) {
    return jsonResponse({
      success: false,
      blocked: false,
      domain,
      message: "Protected domain - blocking prohibited"
    }, 403);
  }

  // 7. Forward approved request to n8n.
  try {
    const upstream = await fetch(
      env.N8N_WEBHOOK_URL,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          [env.N8N_AUTH_HEADER_NAME]:
            env.N8N_AUTH_HEADER_VALUE
        },
        body: JSON.stringify({
          domain,
          reason,
          source: "missive",
          requestedBy: access.email
        }),
        signal: AbortSignal.timeout(20000)
      }
    );

    // 8. Read and validate n8n response.
    let result;

    try {
      result = await upstream.json();
    } catch {
      return jsonResponse({
        success: false,
        blocked: false,
        domain,
        message: "Invalid response from n8n"
      }, 502);
    }

    // 9. Successful block or existing entry.
    if (
      upstream.ok &&
      result.success === true &&
      result.blocked === true &&
      result.domain === domain
    ) {
      return jsonResponse({
        success: true,
        blocked: true,
        domain,
        alreadyBlocked: result.alreadyBlocked === true,
        message: result.alreadyBlocked === true
          ? "Domain is already in the Cloudflare block list"
          : "Domain successfully added to Cloudflare Zero Trust"
      }, 200);
    }

    // 10. Preserve explicit rejection from n8n.
    if (
      upstream.status === 400 ||
      upstream.status === 403
    ) {
      return jsonResponse({
        success: false,
        blocked: false,
        domain,
        message: typeof result.message === "string"
          ? result.message
          : "Domain blocking request rejected"
      }, upstream.status);
    }

    // 11. Handle other upstream failures.
    return jsonResponse({
      success: false,
      blocked: false,
      domain,
      message: "Cloudflare blocking could not be confirmed"
    }, 502);

  } catch {
    return jsonResponse({
      success: false,
      blocked: false,
      domain,
      message: "Unable to contact n8n"
    }, 502);
  }
}
