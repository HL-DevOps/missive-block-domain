
const PROTECTED_DOMAINS = [
  "gmail.com",
  "hotmail.com",
  "highlightmotor.com",
  "cloudflare.com",
  "missiveapp.com",
  "microsoft.com",
  "google.com"
];

const ALLOWED_REASONS = new Set([
  "False positive",
  "Approved by InfoSec",
  "No longer a threat",
  "Other"
]);

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
        message: "Not authorized to unblock domains"
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

  // 1. Authenticate user through Cloudflare Access.
  const access = await verifyAccess(request, env);

  if (!access.authorized) {
    return jsonResponse({
      success: false,
      unblocked: false,
      message: access.message
    }, access.status);
  }

  // 2. Verify n8n configuration.
  if (
    !env.N8N_UNBLOCK_WEBHOOK_URL ||
    !env.N8N_AUTH_HEADER_NAME ||
    !env.N8N_AUTH_HEADER_VALUE
  ) {
    return jsonResponse({
      success: false,
      unblocked: false,
      message: "Server configuration incomplete"
    }, 503);
  }

  // 3. Read submitted JSON payload.
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
      unblocked: false,
      message: "Invalid JSON request"
    }, 400);
  }

  const domain = String(body.domain ?? "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");

  const reason = String(body.reason ?? "").trim();

  // 4. Validate domain and reason.
  if (!validateDomain(domain)) {
    return jsonResponse({
      success: false,
      unblocked: false,
      domain,
      message: "Invalid domain"
    }, 400);
  }

  if (!ALLOWED_REASONS.has(reason)) {
    return jsonResponse({
      success: false,
      unblocked: false,
      domain,
      message: "Invalid unblock reason"
    }, 400);
  }

  // 5. Preserve existing protected-domain safeguards.
  if (isProtectedDomain(domain)) {
    return jsonResponse({
      success: false,
      unblocked: false,
      domain,
      message: "Protected domain - operation prohibited"
    }, 403);
  }

  // 6. Forward approved unblock request to n8n.
  try {
    const upstream = await fetch(
      env.N8N_UNBLOCK_WEBHOOK_URL,
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
          action: "unblock",

          // Verified Cloudflare Access user.
          requestedBy: access.email
        }),
        signal: AbortSignal.timeout(20000)
      }
    );

    // 7. Read and validate the n8n response.
    let result;

    try {
      result = await upstream.json();
    } catch {
      return jsonResponse({
        success: false,
        unblocked: false,
        domain,
        message: "Invalid response from n8n"
      }, 502);
    }

    // 8. Successful removal or already-unblocked entry.
    if (
      upstream.ok &&
      result.success === true &&
      result.unblocked === true &&
      result.domain === domain
    ) {
      return jsonResponse({
        success: true,
        unblocked: true,
        domain,
        alreadyUnblocked:
          result.alreadyUnblocked === true,
        message: result.alreadyUnblocked === true
          ? "Domain is not present in the automation block list"
          : "Domain successfully removed from Cloudflare Zero Trust"
      }, 200);
    }

    // 9. Preserve explicit n8n rejection.
    if (
      upstream.status === 400 ||
      upstream.status === 403
    ) {
      return jsonResponse({
        success: false,
        unblocked: false,
        domain,
        message: typeof result.message === "string"
          ? result.message
          : "Domain unblocking request rejected"
      }, upstream.status);
    }

    // 10. Handle all other upstream failures.
    return jsonResponse({
      success: false,
      unblocked: false,
      domain,
      message: "Cloudflare unblocking could not be confirmed"
    }, 502);

  } catch {
    return jsonResponse({
      success: false,
      unblocked: false,
      domain,
      message: "Unable to contact n8n"
    }, 502);
  }
}
