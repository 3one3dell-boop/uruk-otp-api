// ============================================================
// POST /api/phone-status — يتحقق هل رقم الهاتف مسجّل وله كلمة سر
// الجسم: { "phone": "+9647701234567" }
// يُستخدم في شاشة الدخول لتقرير: نطلب كلمة سر مباشرة، أو نبدأ تحقق OTP.
// لا يكشف أي بيانات حساسة — فقط وجود الحساب وبريد الدخول الداخلي (مش سري).
// ============================================================
const { getAdmin, applyCors, validE164, rateLimit, readJson, clientIp } = require("./_lib");

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  try {
    const { phone } = await readJson(req);
    if (!validE164(phone)) return res.status(400).json({ error: "invalid_phone" });

    const ip = clientIp(req);
    const rl = rateLimit("phonestatus:" + ip, 25, 15 * 60 * 1000);
    if (!rl.ok) return res.status(429).json({ error: "too_many_requests", retryAfter: rl.retryAfter });

    const admin = getAdmin();
    const uid = "phone_" + phone.replace(/[^\d]/g, "");
    try {
      const user = await admin.auth().getUser(uid);
      const hasPassword = (user.providerData || []).some((p) => p.providerId === "password");
      return res.status(200).json({
        exists: true,
        hasPassword,
        authEmail: hasPassword ? user.email : null,
      });
    } catch (e) {
      if (e.code === "auth/user-not-found") {
        return res.status(200).json({ exists: false, hasPassword: false, authEmail: null });
      }
      throw e;
    }
  } catch (e) {
    console.error("phone-status:", e);
    return res.status(500).json({ error: "internal_error" });
  }
};
