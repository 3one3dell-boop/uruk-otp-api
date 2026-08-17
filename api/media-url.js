const { getAdmin, applyCors, readJson, rateLimit, clientIp } = require("./_lib");
const { parseMediaRef, isPathAllowed, signedGet } = require("./_media");

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });
  const limited = rateLimit("media-url:" + clientIp(req), 240, 15 * 60 * 1000);
  if (!limited.ok) return res.status(429).json({ error: "rate_limited", retryAfter: limited.retryAfter });

  try {
    const body = await readJson(req);
    const { idToken, mediaRef, filename } = body;
    if (!idToken || !mediaRef) return res.status(400).json({ error: "missing_fields" });
    const admin = getAdmin();
    const decoded = await admin.auth().verifyIdToken(idToken);
    const { provider, key } = parseMediaRef(mediaRef);
    if (!isPathAllowed(key, decoded.uid, "read")) return res.status(403).json({ error: "forbidden_media" });
    const url = await signedGet(provider, key, filename || "");
    return res.status(200).json({ ok: true, url, expiresIn: 900 });
  } catch (e) {
    console.error("media-url:", e);
    const code = e.message === "forbidden_media" ? 403 : 400;
    return res.status(code).json({ error: e.message || "media_url_error" });
  }
};
