// ============================================================
// POST /api/blob-cleanup — يحذف الملف الأصلي عالي الجودة من Vercel Blob
// بعد ما يشوفه طرفا المحادثة الفردية كلاهم (توفير تخزين + خصوصية).
// الفقاعة والصورة المصغّرة (thumbUrl) يضلوا موجودين بالمحادثة دايماً —
// نحذف بس الملف الأصلي (mediaUrl) من التخزين، ونصفّر الحقل بفايرستور.
//
// أمان: نتحقق من توكن فايربيس الحقيقي + إن صاحبه طرف بهذي المحادثة +
// نعيد التحقق من حالة الرسالة فعلياً بفايرستور (status === read/delivered)
// قبل الحذف — ما نثق بادعاء العميل وحده.
// ============================================================
const { del } = require("@vercel/blob");
const { getAdmin, applyCors, readJson } = require("./_lib");

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  try {
    const { idToken, chatId, messageId } = await readJson(req);
    if (!idToken || !chatId || !messageId) return res.status(400).json({ error: "missing_fields" });

    const admin = getAdmin();
    const decoded = await admin.auth().verifyIdToken(idToken);
    const uid = decoded.uid;

    // صاحب التوكن لازم يكون طرف بهذي المحادثة (نفس منطق صلاحيات blob-upload)
    if (!chatId.split("_").includes(uid)) {
      return res.status(403).json({ error: "forbidden" });
    }

    const db = admin.firestore();
    const msgRef = db.collection("chats").doc(chatId).collection("messages").doc(messageId);
    const snap = await msgRef.get();
    if (!snap.exists) return res.status(404).json({ error: "not_found" });
    const m = snap.data();

    // إعادة تحقق فعلية: الرسالة لازم تكون "شافها" الطرف الآخر فعلاً
    // (status صار read أو delivered، مو بس ادّعاء الطلب)
    if (m.status !== "read" && m.status !== "delivered") {
      return res.status(409).json({ error: "not_seen_yet" });
    }
    if (!m.mediaUrl) {
      return res.status(200).json({ ok: true, alreadyClean: true }); // اتنظّفت أصلاً
    }
    if (!["image", "video"].includes(m.type)) {
      return res.status(400).json({ error: "unsupported_type" });
    }

    try { await del(m.mediaUrl); } catch (e) { console.warn("blob del (قد يكون محذوف أصلاً):", e.message); }
    await msgRef.update({ mediaUrl: "", mediaCleaned: true });

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("blob-cleanup:", e);
    return res.status(400).json({ error: "cleanup_error", detail: e.message || String(e) });
  }
};
