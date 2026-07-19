// ============================================================
// POST /api/link-approve — الجهاز الجديد يطلب توكن بعد موافقة الجهاز المسجّل
// الجسم: { "code": "123456" }
// نتحقق أن link_requests/{code} موافَق عليه (approved:true + uid)، ونصدر توكن.
// ============================================================
const { getAdmin, applyCors, rateLimit, readJson, clientIp } = require("./_lib");

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });
  try {
    const { code } = await readJson(req);
    if (!/^\d{6}$/.test(String(code || ""))) return res.status(400).json({ error: "invalid_code" });

    const ip = clientIp(req);
    const rl = rateLimit("linkapprove:" + ip, 15, 15 * 60 * 1000);
    if (!rl.ok) return res.status(429).json({ error: "too_many_requests", retryAfter: rl.retryAfter });

    const admin = getAdmin();
    const db = admin.firestore();
    const ref = db.collection("link_requests").doc(String(code));
    const snap = await ref.get();
    if (!snap.exists) return res.status(400).json({ error: "no_request", message: "طلب غير موجود" });
    const rec = snap.data();

    const exp = rec.expiresAt && rec.expiresAt.toMillis ? rec.expiresAt.toMillis() : 0;
    if (Date.now() > exp) { await ref.delete().catch(function(){}); return res.status(400).json({ error: "expired", message: "انتهت صلاحية الطلب" }); }
    if (!rec.approved || !rec.uid) return res.status(400).json({ error: "not_approved", message: "لم تتم الموافقة بعد" });

    await ref.delete().catch(function(){}); // يُستخدم مرة واحدة
    const customToken = await admin.auth().createCustomToken(rec.uid, { linkedDevice: true });
    return res.status(200).json({ ok: true, customToken: customToken, uid: rec.uid });
  } catch (e) {
    console.error("link-approve:", e);
    // تفاصيل الخطأ الدقيقة مؤقتاً بالرد نفسه — يساعدنا نشخّص بسرعة، نشيلها بعد ما تنحل المشكلة
    return res.status(500).json({ error: "internal_error", detail: e.message || String(e), code: e.code || null });
  }
};
