// ============================================================
// POST /api/admin — نقطة موحّدة لإجراءات الإدارة الحساسة اللي تحتاج
// صلاحيات Admin SDK (ماكو طريقة تسويها من طرف العميل بأمان). نفس نمط
// totp.js: الإجراء يُحدَّد عبر حقل "action" — يبقينا تحت حد الـ١٢ دالة.
//
//   action: "delete_user_auth" → حذف حساب Firebase Auth فعلياً (بعد
//     حذف مستند Firestore من طرف العميل). بدون هذا، حذف "نهائي" من
//     العميل يمسح البيانات بس يترك حساب الدخول موجود تقنياً — فلو
//     نفس الرقم/البريد يرجع يسجّل، يرتبط بنفس الـuid القديم بدل حساب
//     جديد فعلاً (سلوك "الحساب الشبح" اللي وصفه المستخدم).
//
// كل الإجراءات هنا تتطلب توكن أدمن صحيح (تحقّق ضد adminUid المسجّل
// بـsiteConfig/main) — صفر استثناء.
// ============================================================
const { getAdmin, applyCors, rateLimit, clientIp } = require("./_lib");

async function readJsonBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  return await new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { resolve({}); } });
  });
}

async function requireAdmin(admin, idToken) {
  const decoded = await admin.auth().verifyIdToken(idToken);
  const db = admin.firestore();
  const cfg = await db.collection("siteConfig").doc("main").get();
  const adminUid = cfg.exists ? cfg.data().adminUid : null;
  if (!adminUid || decoded.uid !== adminUid) {
    const err = new Error("caller_not_admin"); err.httpCode = 403; throw err;
  }
  return decoded.uid;
}

async function handleDeleteUserAuth(body, res, admin) {
  const { idToken, targetUid } = body;
  if (!idToken || !targetUid) return res.status(400).json({ error: "missing_fields" });
  await requireAdmin(admin, idToken);

  // نحذف حساب Firebase Auth فعلياً — يخلّي رجوع نفس الرقم/البريد
  // يُنشئ حساب Auth جديد كلياً بدل ما يرتبط بنفس الـuid القديم
  try {
    await admin.auth().deleteUser(targetUid);
  } catch (e) {
    // لو أصلاً محذوف أو غير موجود بـAuth (مثلاً حساب اتحذف بمكان ثاني)، نعتبرها نجاح
    if (e.code !== "auth/user-not-found") throw e;
  }
  return res.status(200).json({ ok: true });
}

async function handleDeleteOwnAccount(body, res, admin) {
  const { idToken } = body;
  if (!idToken) return res.status(400).json({ error: "missing_fields" });
  // صلاحية مختلفة عن delete_user_auth: ماكو شرط isAdmin هنا — أي مستخدم
  // يقدر يحذف حسابه هو بس (verifyIdToken يضمن التوكن أصلي وحقيقي، والـuid
  // المستهدف هو نفسه صاحب التوكن دايماً — ما نقبل targetUid من العميل هنا
  // أصلاً، حتى ما يصير فيه أي احتمال حذف حساب غيرك بالغلط أو قصداً)
  const decoded = await admin.auth().verifyIdToken(idToken);
  try {
    await admin.auth().deleteUser(decoded.uid);
  } catch (e) {
    if (e.code !== "auth/user-not-found") throw e;
  }
  return res.status(200).json({ ok: true });
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  const limited = rateLimit("admin:" + clientIp(req), 30, 15 * 60 * 1000);
  if (!limited.ok) return res.status(429).json({ error: "rate_limited", retryAfter: limited.retryAfter });

  try {
    const body = await readJsonBody(req);
    const admin = getAdmin();
    switch (body.action) {
      case "delete_user_auth": return await handleDeleteUserAuth(body, res, admin);
      case "delete_own_account": return await handleDeleteOwnAccount(body, res, admin);
      default: return res.status(400).json({ error: "unknown_action" });
    }
  } catch (e) {
    console.error("admin:", e);
    const code = e.httpCode || 400;
    return res.status(code).json({ error: e.message === "caller_not_admin" ? "forbidden" : "admin_error", detail: e.message || String(e) });
  }
};
