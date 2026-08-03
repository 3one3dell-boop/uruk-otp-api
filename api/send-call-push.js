// ============================================================
// POST /api/send-call-push — يرسل إشعار "مكالمة واردة" فوري عبر
// Firebase Cloud Messaging مباشرة (بدون Cloud Functions، بدون خطة
// مدفوعة — يستخدم نفس بيانات اعتماد Admin SDK الموجودة أصلاً).
// الجسم: { "toUid", "fromUid", "fromName", "callId", "isVideo" }
// ============================================================
const { getAdmin, applyCors, readJson, rateLimit, clientIp } = require("./_lib");

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  try {
    const { toUid, fromUid, fromName, callId, isVideo } = await readJson(req);
    if (!toUid || !fromUid || !callId) {
      return res.status(400).json({ error: "missing_fields" });
    }

    // حد إرسال بسيط لمنع إغراق مستخدم بإشعارات وهمية
    const ip = clientIp(req);
    const rl = rateLimit("call-push:" + fromUid, 20, 60 * 1000);
    if (!rl.ok) return res.status(429).json({ error: "too_many_requests" });

    const admin = getAdmin();
    const db = admin.firestore();

    const toUserSnap = await db.collection("users").doc(toUid).get();
    const fcmToken = toUserSnap.exists ? toUserSnap.data().fcmToken : null;
    if (!fcmToken) {
      // المستقبل ما عنده جهاز مسجّل لإشعارات فورية (مثلاً يستخدم متصفح بدون تفعيل) —
      // مو خطأ فعلي، الاستماع اللحظي بالتطبيق (onSnapshot) هو المسار الاحتياطي دايماً
      return res.status(200).json({ ok: true, delivered: false, reason: "no_token" });
    }

    // رسالة بيانات خام (data-only) — تعطينا تحكماً كاملاً بواجهة "مكالمة واردة"
    // الأصلية بالتطبيق بدل إشعار نظام عادي، وتوصل حتى لو التطبيق مغلق تماماً
    await admin.messaging().send({
      token: fcmToken,
      android: { priority: "high" },
      data: {
        type: "incoming_call",
        callId: String(callId),
        fromUid: String(fromUid),
        fromName: String(fromName || "مجهول"),
        isVideo: isVideo ? "1" : "0",
      },
    });

    return res.status(200).json({ ok: true, delivered: true });
  } catch (e) {
    console.error("send-call-push:", e);
    return res.status(500).json({ error: "internal_error", detail: e.message || String(e) });
  }
};
