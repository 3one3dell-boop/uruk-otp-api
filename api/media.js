const { getAdmin, applyCors, readJson, rateLimit, clientIp } = require("./_lib");
const {
  MAX_MEDIA_BYTES, providerForPath, cleanPath, isPathAllowed, mediaRef,
  parseMediaRef, signedPut, signedGet, providerConfig, listObjects, deleteObjects,
} = require("./_media");

function allowedContentType(type) {
  return /^(image|audio|video)\//i.test(type || "") || /^(application|text)\//i.test(type || "");
}
async function requireAdmin(admin, idToken) {
  const decoded = await admin.auth().verifyIdToken(idToken);
  const cfg = await admin.firestore().collection("siteConfig").doc("main").get();
  const adminUid = cfg.exists ? cfg.data().adminUid : null;
  if (!adminUid || decoded.uid !== adminUid) { const e = new Error("caller_not_admin"); e.httpCode = 403; throw e; }
  return decoded.uid;
}
async function collectReferencedRefs(db) {
  const refs = new Set();
  const users = await db.collection("users").get();
  users.forEach((d) => { const u = d.data() || {}; if (u.photoRef) refs.add(String(u.photoRef)); });
  const chats = await db.collection("chats").get();
  for (const chat of chats.docs) {
    const messages = await chat.ref.collection("messages").get();
    messages.forEach((d) => { const m = d.data() || {}; if (m.mediaRef) refs.add(String(m.mediaRef)); });
  }
  const statusUsers = await db.collection("status").get();
  for (const user of statusUsers.docs) {
    const items = await user.ref.collection("items").get();
    items.forEach((d) => { const item = d.data() || {}; if (item.mediaRef) refs.add(String(item.mediaRef)); });
  }
  return refs;
}
async function usageFor(provider) {
  const data = await listObjects(provider, 5000);
  const usedBytes = data.objects.reduce((n, o) => n + o.size, 0);
  return { provider, bucket: data.bucket, objectCount: data.objects.length, usedBytes, quotaBytes: data.quotaBytes, remainingBytes: Math.max(0, data.quotaBytes - usedBytes), scannedAll: !data.truncated, truncated: data.truncated };
}
function cleanupPreview(objects, refs, graceHours) {
  const cutoff = Date.now() - graceHours * 3600 * 1000;
  const candidates = objects.filter((o) => (!o.lastModified || new Date(o.lastModified).getTime() < cutoff) && !refs.has(o.ref));
  return { count: candidates.length, bytes: candidates.reduce((n, o) => n + o.size, 0), truncated: objects.length >= 5000, objects: candidates.slice(0, 100).map((o) => ({ key: o.key, ref: o.ref, size: o.size, lastModified: o.lastModified })) };
}
async function handlePresign(body, res, admin) {
  const { idToken, pathname, contentType, size } = body;
  if (!idToken || !pathname) return res.status(400).json({ error: "missing_fields" });
  const key = cleanPath(pathname); const byteSize = Number(size || 0);
  if (!Number.isFinite(byteSize) || byteSize < 1 || byteSize > MAX_MEDIA_BYTES) return res.status(413).json({ error: "file_too_large", maxBytes: MAX_MEDIA_BYTES });
  if (!allowedContentType(contentType)) return res.status(415).json({ error: "unsupported_content_type" });
  const decoded = await admin.auth().verifyIdToken(idToken);
  if (!isPathAllowed(key, decoded.uid, "write")) return res.status(403).json({ error: "forbidden_path" });
  const provider = providerForPath(key); const cfg = providerConfig(provider);
  return res.status(200).json({ ok: true, provider, bucket: cfg.bucket, key, mediaRef: mediaRef(provider, key), putUrl: await signedPut(provider, key, contentType || "application/octet-stream"), url: await signedGet(provider, key), expiresIn: 900 });
}
async function handleUrl(body, res, admin) {
  const { idToken, mediaRef: ref, filename } = body;
  if (!idToken || !ref) return res.status(400).json({ error: "missing_fields" });
  const decoded = await admin.auth().verifyIdToken(idToken); const parsed = parseMediaRef(ref);
  if (!isPathAllowed(parsed.key, decoded.uid, "read")) return res.status(403).json({ error: "forbidden_media" });
  return res.status(200).json({ ok: true, url: await signedGet(parsed.provider, parsed.key, filename || ""), expiresIn: 900 });
}
async function handleSeenCleanup(body, res, admin) {
  const { idToken, chatId, messageId, mediaRef: ref } = body;
  if (!idToken || !chatId || !messageId || !ref) return res.status(400).json({ error: "missing_fields" });
  const decoded = await admin.auth().verifyIdToken(idToken);
  if (!chatId.split("_").includes(decoded.uid)) return res.status(403).json({ error: "forbidden" });
  const db = admin.firestore(); const msgRef = db.collection("chats").doc(chatId).collection("messages").doc(messageId); const snap = await msgRef.get();
  if (!snap.exists) return res.status(404).json({ error: "not_found" });
  const m = snap.data() || {};
  if (m.status !== "read" && m.status !== "delivered") return res.status(409).json({ error: "not_seen_yet" });
  if (m.mediaCleaned) return res.status(200).json({ ok: true, alreadyClean: true });
  if (m.mediaRef !== ref) return res.status(409).json({ error: "media_ref_mismatch" });
  const parsed = parseMediaRef(ref); const result = await deleteObjects(parsed.provider, [parsed.key]);
  await msgRef.update({ mediaUrl: "", mediaCleaned: true });
  return res.status(200).json({ ok: true, provider: parsed.provider, deleted: result.deleted || [] });
}
async function handleAdmin(body, res, admin) {
  await requireAdmin(admin, body.idToken); const db = admin.firestore(); const action = body.action || "usage"; const provider = body.provider;
  if (action === "usage") {
    const providers = provider ? [provider] : ["r2", "b2"];
    return res.status(200).json({ ok: true, providers: await Promise.all(providers.map(usageFor)), generatedAt: new Date().toISOString() });
  }
  if (!["r2", "b2"].includes(provider)) return res.status(400).json({ error: "invalid_provider" });
  const data = await listObjects(provider, 5000); const refs = await collectReferencedRefs(db); const graceHours = Math.min(24 * 30, Math.max(24, Number(body.graceHours || 24 * 7))); const preview = cleanupPreview(data.objects, refs, graceHours);
  if (action === "preview_cleanup") return res.status(200).json({ ok: true, provider, graceHours, ...preview, generatedAt: new Date().toISOString() });
  if (action === "cleanup") {
    if (body.confirm !== "URUK-CLEANUP") return res.status(400).json({ error: "confirmation_required" });
    const allowed = new Set(preview.objects.map((o) => o.key)); const requested = Array.isArray(body.keys) && body.keys.length ? body.keys.map(String) : [...allowed]; const keys = requested.filter((key) => allowed.has(key)).slice(0, 1000); const result = await deleteObjects(provider, keys);
    await db.collection("admin_logs").add({ action: "media_cleanup", provider, deletedCount: result.deleted.length, deletedBytes: preview.objects.filter((o) => result.deleted.includes(o.key)).reduce((n, o) => n + o.size, 0), at: admin.firestore.FieldValue.serverTimestamp() }).catch(() => {});
    return res.status(200).json({ ok: true, provider, deleted: result.deleted, errors: result.errors || [], remainingCandidates: Math.max(0, preview.count - result.deleted.length) });
  }
  return res.status(400).json({ error: "unknown_action" });
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });
  const limited = rateLimit("media:" + clientIp(req), 240, 15 * 60 * 1000);
  if (!limited.ok) return res.status(429).json({ error: "rate_limited", retryAfter: limited.retryAfter });
  try {
    const body = await readJson(req); const admin = getAdmin();
    switch (body.action) {
      case "presign": return await handlePresign(body, res, admin);
      case "url": return await handleUrl(body, res, admin);
      case "seen_cleanup": return await handleSeenCleanup(body, res, admin);
      case "usage": case "preview_cleanup": case "cleanup": return await handleAdmin(body, res, admin);
      default: return res.status(400).json({ error: "unknown_action" });
    }
  } catch (e) {
    console.error("media:", e);
    return res.status(e.httpCode || (e.message === "caller_not_admin" ? 403 : 400)).json({ error: e.message || "media_error" });
  }
};
