// ============================================================
// POST /api/link-device — ربط جهاز جديد عبر كود ظاهر على جهاز مسجّل
// الجسم: { "code": "123456" }
// نتحقق من الكود في link_codes، ونصدر Custom Token لنفس حساب المستخدم.
// ============================================================
const { getAdmin, applyCors, rateLimit, readJson, clientIp } = require("./_lib");

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  try {
    const { code } = await readJson(req);
    if (!/^\d{6}$/.test(String(code || ""))) {
      return res.status(400).json({ error: "invalid_code", message: "الكود غير صحيح" });
    }

    const ip = clientIp(req);
    const rl = rateLimit("link:" + ip, 10, 15 * 60 * 1000);
    if (!rl.ok) return res.status(429).json({ error: "too_many_requests", retryAfter: rl.retryAfter });

    const admin = getAdmin();
    const db = admin.firestore();
    const ref = db.collection("link_codes").doc(String(code));
    const snap = await ref.get();

    if (!snap.exists) return res.status(400).json({ error: "no_code", message: "كود غير موجود أو منتهٍ" });
    const rec = snap.data();

    const exp = rec.expiresAt && rec.expiresAt.toMillis ? rec.expiresAt.toMillis() : 0;
    if (rec.used || Date.now() > exp) {
      await ref.delete().catch(function () {});
      return res.status(400).json({ error: "expired", message: "انتهت صلاحية الكود، اطلب كوداً جديداً" });
    }

    // الكود صحيح — نستهلكه ونصدر توكن لنفس الحساب
    await ref.update({ used: true }).catch(function () {});
    const uid = rec.uid;
    if (!uid) return res.status(400).json({ error: "invalid_code" });

    const customToken = await admin.auth().createCustomToken(uid, { linkedDevice: true });
    return res.status(200).json({ ok: true, customToken: customToken, uid: uid });
  } catch (e) {
    console.error("link-device:", e);
    return res.status(500).json({ error: "internal_error" });
  }
};
