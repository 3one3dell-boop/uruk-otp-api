const { getAdmin, applyCors, readJson, rateLimit, clientIp } = require("./_lib");
const {
  MAX_MEDIA_BYTES,
  providerForPath,
  cleanPath,
  isPathAllowed,
  mediaRef,
  signedPut,
  signedGet,
  providerConfig,
} = require("./_media");

function allowedContentType(type) {
  return /^(image|audio|video)\//i.test(type || "") || /^(application|text)\//i.test(type || "");
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });
  const limited = rateLimit("media-presign:" + clientIp(req), 120, 15 * 60 * 1000);
  if (!limited.ok) return res.status(429).json({ error: "rate_limited", retryAfter: limited.retryAfter });

  try {
    const body = await readJson(req);
    const { idToken, pathname, contentType, size } = body;
    if (!idToken || !pathname) return res.status(400).json({ error: "missing_fields" });
    const key = cleanPath(pathname);
    const byteSize = Number(size || 0);
    if (!Number.isFinite(byteSize) || byteSize < 1 || byteSize > MAX_MEDIA_BYTES) {
      return res.status(413).json({ error: "file_too_large", maxBytes: MAX_MEDIA_BYTES });
    }
    if (!allowedContentType(contentType)) return res.status(415).json({ error: "unsupported_content_type" });

    const admin = getAdmin();
    const decoded = await admin.auth().verifyIdToken(idToken);
    const uid = decoded.uid;
    if (!isPathAllowed(key, uid, "write")) return res.status(403).json({ error: "forbidden_path" });

    const provider = providerForPath(key);
    const cfg = providerConfig(provider);
    const putUrl = await signedPut(provider, key, contentType || "application/octet-stream");
    const url = await signedGet(provider, key);
    return res.status(200).json({
      ok: true,
      provider,
      bucket: cfg.bucket,
      key,
      mediaRef: mediaRef(provider, key),
      putUrl,
      url,
      expiresIn: 900,
    });
  } catch (e) {
    console.error("media-presign:", e);
    const code = e.message === "forbidden_path" ? 403 : e.message === "unsupported_media_path" ? 400 : 400;
    return res.status(code).json({ error: e.message || "presign_error" });
  }
};
