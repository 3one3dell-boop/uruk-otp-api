// ============================================================
// POST /api/send-message-push — إشعار "رسالة جديدة" فوري عبر FCM،
// نفس آلية send-call-push بالضبط (بدون Cloud Functions، بدون خطة مدفوعة).
// الجسم: { "toUid", "fromUid", "fromName", "chatId", "preview" }
// ============================================================
const { getAdmin, applyCors, readJson, rateLimit, clientIp } = require("./_lib");

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  try {
    const { toUid, fromUid, fromName, chatId, preview } = await readJson(req);
    if (!toUid || !fromUid || !chatId) {
      return res.status(400).json({ error: "missing_fields" });
    }

    const ip = clientIp(req);
    const rl = rateLimit("msg-push:" + fromUid, 60, 60 * 1000); // أعلى من المكالمات، الرسائل أكثر تكراراً
    if (!rl.ok) return res.status(429).json({ error: "too_many_requests" });

    const admin = getAdmin();
    const db = admin.firestore();

    const toUserSnap = await db.collection("users").doc(toUid).get();
    const fcmToken = toUserSnap.exists ? toUserSnap.data().fcmToken : null;
    if (!fcmToken) return res.status(200).json({ ok: true, delivered: false, reason: "no_token" });

    // إشعار عرض عادي (notification, مو data-only) — أندرويد/المتصفح يعرضونه
    // تلقائياً من النظام حتى لو التطبيق مغلق، بدون حاجة لمعالجة إضافية بالتطبيق
    await admin.messaging().send({
      token: fcmToken,
      notification: {
        title: String(fromName || "رسالة جديدة"),
        body: String(preview || "").slice(0, 100),
      },
      data: { type: "new_message", chatId: String(chatId), fromUid: String(fromUid) },
      android: { priority: "high", notification: { channelId: "uruk_messages" } },
    });

    return res.status(200).json({ ok: true, delivered: true });
  } catch (e) {
    console.error("send-message-push:", e);
    return res.status(500).json({ error: "internal_error", detail: e.message || String(e) });
  }
};
