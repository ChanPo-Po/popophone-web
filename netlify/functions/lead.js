const ALLOWED_ORIGINS = new Set([
  "https://popophone.vn",
  "https://www.popophone.vn"
]);

const ipHits = new Map();
const WINDOW_MS = 60 * 1000;
const MAX_POSTS_PER_MINUTE = 12;

function json(statusCode, body, origin) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": origin || "https://popophone.vn",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Cache-Control": "no-store"
    },
    body: JSON.stringify(body)
  };
}

function isRateLimited(ip) {
  const now = Date.now();
  const history = (ipHits.get(ip) || []).filter(t => now - t < WINDOW_MS);
  history.push(now);
  ipHits.set(ip, history);
  return history.length > MAX_POSTS_PER_MINUTE;
}

exports.handler = async function(event) {
  const origin = event.headers.origin || event.headers.Origin || "";

  if (event.httpMethod === "OPTIONS") {
    return json(200, { ok: true }, ALLOWED_ORIGINS.has(origin) ? origin : "https://popophone.vn");
  }

  if (event.httpMethod !== "POST") {
    return json(405, { ok: false, error: "Method not allowed" }, origin);
  }

  if (!ALLOWED_ORIGINS.has(origin)) {
    return json(403, { ok: false, error: "Origin blocked" }, "https://popophone.vn");
  }

  const ip = event.headers["x-nf-client-connection-ip"] || event.headers["client-ip"] || event.headers["x-forwarded-for"] || "unknown";
  if (isRateLimited(ip)) {
    return json(429, { ok: false, error: "Too many requests" }, origin);
  }

  if ((event.body || "").length > 30000) {
    return json(413, { ok: false, error: "Payload too large" }, origin);
  }

  let payload;
  try {
    payload = JSON.parse(event.body || "{}");
  } catch (error) {
    return json(400, { ok: false, error: "Invalid JSON" }, origin);
  }

  // Honeypot field from HTML form. Human users never fill this.
  if (payload.company_website) {
    return json(200, { ok: true, blocked: true }, origin);
  }

  const phone = String(payload.phone || payload.sdt || payload.so_dien_thoai || "").replace(/\D/g, "");
  if (phone && (phone.length < 9 || phone.length > 12)) {
    return json(400, { ok: false, error: "Invalid phone" }, origin);
  }

  const googleScriptUrl = process.env.GOOGLE_SCRIPT_URL;
  if (!googleScriptUrl) {
    return json(500, { ok: false, error: "Missing GOOGLE_SCRIPT_URL env" }, origin);
  }

  const forwardPayload = {
    ...payload,
    server_received_at: new Date().toISOString(),
    client_ip_hint: String(ip).split(",")[0]
  };

  try {
    const res = await fetch(googleScriptUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(forwardPayload)
    });

    return json(200, { ok: true, forwarded: res.ok }, origin);
  } catch (error) {
    return json(502, { ok: false, error: "Forward failed" }, origin);
  }
};
