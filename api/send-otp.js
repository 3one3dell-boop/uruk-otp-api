// ============================================================
// POST /api/send-otp — إرسال كود عبر OTPIQ (SMS/WhatsApp) للعراق
// الجسم: { "phone": "+9647701234567" }
// آلية العمل: نولّد الكود، نخزّن نسخته المُجزّأة (hash) في Firestore
// مؤقتاً (10 دقائق)، ونرسله عبر OTPIQ. التحقق لاحقاً بمقارنة الـ hash.
// كل المفاتيح تبقى في متغيّرات البيئة على الخادم فقط.
// ============================================================
const crypto = require("crypto");
const { getAdmin, applyCors, validE164, rateLimit, readJson, clientIp } = require("./_lib");

// OTPIQ يتوقع الرقم بصيغة أرقام فقط تبدأ برمز الدولة (بدون +)
function toOtpiqPhone(e164) { return e164.replace(/[^\d]/g, ""); }
function hashCode(phone, code) {
  const salt = process.env.OTP_HASH_SALT || "uruk-default-salt";
  return crypto.createHash("sha256").update(salt + ":" + phone + ":" + code).digest("hex");
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  try {
    const { phone } = await readJson(req);
    if (!validE164(phone)) {
      return res.status(400).json({ error: "invalid_phone", message: "صيغة الرقم غير صحيحة (مثال: +9647701234567)" });
    }

    // تحديد المعدّل: 3 إرسالات/رقم و10/IP كل 15 دقيقة
    const ip = clientIp(req);
    const perPhone = rateLimit("send:" + phone, 3, 15 * 60 * 1000);
    if (!perPhone.ok) return res.status(429).json({ error: "too_many_requests", retryAfter: perPhone.retryAfter, message: "محاولات كثيرة، جرّب لاحقاً" });
    const perIp = rateLimit("send-ip:" + ip, 10, 15 * 60 * 1000);
    if (!perIp.ok) return res.status(429).json({ error: "too_many_requests", retryAfter: perIp.retryAfter });

    const apiKey = process.env.OTPIQ_API_KEY;
    if (!apiKey) return res.status(500).json({ error: "server_misconfigured" });

    // نولّد كوداً من 6 أرقام
    const code = String(crypto.randomInt(100000, 1000000));

    // نخزّن الـ hash في Firestore (مؤقت، مع عدّاد محاولات)
    const admin = getAdmin();
    const db = admin.firestore();
    const docId = "otp_" + toOtpiqPhone(phone);
    await db.collection("otp_codes").doc(docId).set({
      hash: hashCode(phone, code),
      phone: phone,
      attempts: 0,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + 10 * 60 * 1000),
    });

    // نرسل عبر OTPIQ (نعطيه الكود ليوصله؛ smart routing: واتساب ثم SMS)
    const otpRes = await fetch("https://api.otpiq.com/api/sms", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        phoneNumber: toOtpiqPhone(phone),
        smsType: "verification",
        provider: "whatsapp-telegram-sms",
        verificationCode: code,
      }),
    });

    const data = await otpRes.json().catch(() => ({}));
    if (!otpRes.ok) {
      console.error("otpiq send error:", data);
      const msg = (data && (data.message || data.error)) || "تعذّر إرسال الكود، حاول لاحقاً";
      const friendly = /credit|balance|insufficient/i.test(JSON.stringify(data))
        ? "لا يوجد رصيد كافٍ في حساب OTPIQ — اشحن رصيداً" : msg;
      return res.status(502).json({ error: "send_failed", message: friendly });
    }

    return res.status(200).json({ ok: true, status: "pending", smsId: data.smsId || null });
  } catch (e) {
    console.error("send-otp:", e);
    return res.status(500).json({ error: "internal_error" });
  }
};
