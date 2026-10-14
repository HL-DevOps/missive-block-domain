
export async function onRequestPost(context) {
  const { request, env } = context;

  const json = (data, status = 200) =>
    Response.json(data, {
      status,
      headers: { "Cache-Control": "no-store" }
    });

  // Require Cloudflare Access authentication.
  const accessJwt = request.headers.get("Cf-Access-Jwt-Assertion");

  if (!accessJwt || !env.ACCESS_AUD) {
    return json({
      success: false,
      message: "Authentication required"
    }, 401);
  }

  // Validate the Access JWT cryptographically.
  // Never trust an unverified identity header.
  try {
    const teamDomain = env.ACCESS_TEAM_DOMAIN;
    if (!teamDomain) throw new Error("Missing team domain");

    const certsResponse = await fetch(
      `https://${teamDomain}/cdn-cgi/access/certs`
    );
    if (!certsResponse.ok) throw new Error("Cannot fetch Access keys");

    const { keys } = await certsResponse.json();
    const [headerPart, payloadPart, signaturePart] =
      accessJwt.split(".");

    if (!headerPart || !payloadPart || !signaturePart) {
      throw new Error("Malformed token");
    }

    const decode = part => {
      const base64 = part.replace(/-/g, "+").replace(/_/g, "/");
      const bytes = Uint8Array.from(
        atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "=")),
        c => c.charCodeAt(0)
      );
      return bytes;
    };

    const header = JSON.parse(
      new TextDecoder().decode(decode(headerPart))
    );
    const payload = JSON.parse(
      new TextDecoder().decode(decode(payloadPart))
    );

    if (header.alg !== "RS256") throw new Error("Invalid algorithm");

    const keyData = keys.find(k => k.kid === header.kid);
    if (!keyData) throw new Error("Unknown signing key");

    const cryptoKey = await crypto.subtle.importKey(
      "jwk",
      keyData,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );

    const validSignature = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      cryptoKey,
      decode(signaturePart),
      new TextEncoder().encode(
        `${headerPart}.${payloadPart}`
      )
    );

    const now = Math.floor(Date.now() / 1000);
    const expectedIssuer =
      `https://${teamDomain.replace(/\/$/, "")}`;

    if (
      !validSignature ||
      payload.iss !== expectedIssuer ||
      ![].concat(payload.aud || []).includes(env.ACCESS_AUD) ||
      typeof payload.exp !== "number" ||
      payload.exp <= now ||
      typeof payload.nbf === "number" && payload.nbf > now
    ) {
      throw new Error("Invalid Access token");
    }

    const email = String(payload.email || "").toLowerCase();
    const allowed = String(env.ALLOWED_EMAILS || "")
      .split(",")
      .map(x => x.trim().toLowerCase())
      .filter(Boolean);

    if (!email || !allowed.includes(email)) {
      return json({
        success: false,
        message: "Not authorized to block domains"
      }, 403);
    }
  } catch {
    return json({
      success: false,
      message: "Access verification failed"
    }, 401);
  }

  if (!env.N8N_WEBHOOK_URL ||
      !env.N8N_AUTH_HEADER_NAME ||
      !env.N8N_AUTH_HEADER_VALUE) {
    return json({
      success: false,
      message: "Server configuration incomplete"
    }, 503);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({
      success: false,
      message: "Invalid JSON"
    }, 400);
  }

  const domain = String(body.domain || "")
    .trim().toLowerCase().replace(/\.$/, "");

  const validDomain =
    domain.length <= 253 &&
    /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain);

  const reasons = new Set([
    "Phishing", "Malware", "Spam",
    "Company policy", "Other"
  ]);

  if (!validDomain || !reasons.has(body.reason)) {
    return json({
      success: false,
      message: "Invalid domain or reason"
    }, 400);
  }

  // Prevent accidentally blocking critical infrastructure.
  const protectedDomains = new Set([
    "cloudflare.com",
    "missiveapp.com",
    "microsoft.com",
    "google.com"
  ]);

  if (protectedDomains.has(domain)) {
    return json({
      success: false,
      message: "Domain requires administrator review"
    }, 403);
  }

  try {
    const upstream = await fetch(env.N8N_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [env.N8N_AUTH_HEADER_NAME]: env.N8N_AUTH_HEADER_VALUE
      },
      body: JSON.stringify({
        domain,
        reason: body.reason,
        source: "missive"
      })
    });

    const result = await upstream.json();

    if (!upstream.ok || result.success !== true) {
      return json({
        success: false,
        message: "n8n did not confirm the request"
      }, 502);
    }

    return json({
      success: true,
      status: result.status || "accepted"
    });
  } catch {
    return json({
      success: false,
      message: "Unable to contact n8n"
    }, 502);
  }
}
