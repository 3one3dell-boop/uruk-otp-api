// ============================================================
// POST /api/verify-otp — التحقق من الكود (المقارنة مع Firestore) ثم
// إصدار Firebase Custom Token لتسجيل الدخول.
// الجسم: { "phone": "+9647701234567", "code": "123456" }
// ============================================================
const crypto = require("crypto");
const { getAdmin, applyCors, validE164, rateLimit, readJson, clientIp } = require("./_lib");

function toDigits(e164) { return e164.replace(/[^\d]/g, ""); }
function hashCode(phone, code) {
  const salt = process.env.OTP_HASH_SALT || "uruk-default-salt";
  return crypto.createHash("sha256").update(salt + ":" + phone + ":" + code).digest("hex");
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  try {
    const { phone, code } = await readJson(req);
    if (!validE164(phone)) return res.status(400).json({ error: "invalid_phone" });
    if (!/^\d{4,8}$/.test(String(code || ""))) {
      return res.status(400).json({ error: "invalid_code", message: "الكود غير صحيح" });
    }

    // تحديد المعدّل على التحقق
    const ip = clientIp(req);
    const rl = rateLimit("verify:" + phone, 8, 15 * 60 * 1000);
    if (!rl.ok) return res.status(429).json({ error: "too_many_requests", retryAfter: rl.retryAfter });

    const admin = getAdmin();
    const db = admin.firestore();
    const docId = "otp_" + toDigits(phone);
    const ref = db.collection("otp_codes").doc(docId);
    const snap = await ref.get();

    if (!snap.exists) {
      return res.status(400).json({ error: "no_code", message: "لا يوجد كود لهذا الرقم، اطلب كوداً جديداً" });
    }
    const rec = snap.data();

    // انتهاء الصلاحية
    const exp = rec.expiresAt && rec.expiresAt.toMillis ? rec.expiresAt.toMillis() : 0;
    if (Date.now() > exp) {
      await ref.delete().catch(function () {});
      return res.status(400).json({ error: "expired", message: "انتهت صلاحية الكود، اطلب كوداً جديداً" });
    }

    // حد محاولات التحقق (5 محاولات للكود الواحد)
    if ((rec.attempts || 0) >= 5) {
      await ref.delete().catch(function () {});
      return res.status(429).json({ error: "too_many_attempts", message: "محاولات كثيرة، اطلب كوداً جديداً" });
    }

    // المقارنة الآمنة للـ hash
    const expected = Buffer.from(rec.hash || "", "hex");
    const actual = Buffer.from(hashCode(phone, String(code)), "hex");
    const match = expected.length === actual.length && crypto.timingSafeEqual(expected, actual);

    if (!match) {
      await ref.update({ attempts: (rec.attempts || 0) + 1 }).catch(function () {});
      return res.status(401).json({ error: "wrong_code", message: "الكود غير صحيح" });
    }

    // نجح — نحذف الكود (يُستخدم مرة واحدة)
    await ref.delete().catch(function () {});

    // نُنشئ/نجلب المستخدم في Firebase
    const uid = "phone_" + toDigits(phone);
    let isNew = false;
    try {
      await admin.auth().getUser(uid);
    } catch (e) {
      if (e.code === "auth/user-not-found") {
        await admin.auth().createUser({ uid: uid, phoneNumber: phone });
        isNew = true;
      } else { throw e; }
    }

    const customToken = await admin.auth().createCustomToken(uid, { phone: phone });
    return res.status(200).json({ ok: true, customToken: customToken, uid: uid, phone: phone, isNew: isNew });
  } catch (e) {
    console.error("verify-otp:", e);
    return res.status(500).json({ error: "internal_error" });
  }
};
