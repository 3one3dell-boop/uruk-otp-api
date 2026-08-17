const { getAdmin, applyCors, readJson, rateLimit, clientIp } = require("./_lib");
const { parseMediaRef, deleteObjects } = require("./_media");

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });
  const limited = rateLimit("media-cleanup:" + clientIp(req), 60, 15 * 60 * 1000);
  if (!limited.ok) return res.status(429).json({ error: "rate_limited", retryAfter: limited.retryAfter });
  try {
    const { idToken, chatId, messageId, mediaRef } = await readJson(req);
    if (!idToken || !chatId || !messageId || !mediaRef) return res.status(400).json({ error: "missing_fields" });
    const admin = getAdmin();
    const decoded = await admin.auth().verifyIdToken(idToken);
    if (!chatId.split("_").includes(decoded.uid)) return res.status(403).json({ error: "forbidden" });
    const db = admin.firestore();
    const msgRef = db.collection("chats").doc(chatId).collection("messages").doc(messageId);
    const snap = await msgRef.get();
    if (!snap.exists) return res.status(404).json({ error: "not_found" });
    const m = snap.data() || {};
    if (m.status !== "read" && m.status !== "delivered") return res.status(409).json({ error: "not_seen_yet" });
    if (m.mediaCleaned) return res.status(200).json({ ok: true, alreadyClean: true });
    if (m.mediaRef !== mediaRef) return res.status(409).json({ error: "media_ref_mismatch" });
    const { provider, key } = parseMediaRef(mediaRef);
    const result = await deleteObjects(provider, [key]);
    await msgRef.update({ mediaUrl: "", mediaCleaned: true });
    return res.status(200).json({ ok: true, provider, deleted: result.deleted || [] });
  } catch (e) {
    console.error("media-cleanup:", e);
    return res.status(e.message === "forbidden" ? 403 : 400).json({ error: e.message || "cleanup_error" });
  }
};
