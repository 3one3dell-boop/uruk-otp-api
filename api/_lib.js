// ============================================================
// أدوات مشتركة للخادم (Vercel Serverless) — أوروك OTP عبر Twilio Verify
// كل المفاتيح السرية تُقرأ من متغيّرات البيئة، ولا تظهر أبداً في الواجهة.
// ============================================================
const admin = require("firebase-admin");

// --- تهيئة Firebase Admin مرة واحدة (لإصدار Custom Tokens) ---
function getAdmin() {
  if (!admin.apps.length) {
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    // المفتاح الخاص يُخزَّن كسطر واحد مع \n مُرمّزة؛ نعيدها لأسطر حقيقية
    const privateKey = (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n");
    if (!projectId || !clientEmail || !privateKey) {
      throw new Error("missing_firebase_admin_env");
    }
    admin.initializeApp({
      credential: admin.credential.cert({ projectId, clientEmail, privateKey }),
    });
  }
  return admin;
}

// --- CORS: نسمح فقط لنطاق التطبيق (يُضبط في ALLOWED_ORIGIN) ---
function applyCors(req, res) {
  const allowed = process.env.ALLOWED_ORIGIN || "*";
  res.setHeader("Access-Control-Allow-Origin", allowed);
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "86400");
  if (req.method === "OPTIONS") { res.status(204).end(); return true; }
  return false;
}

// --- تحقّق من صيغة الرقم E.164 (مثال: +9647701234567) ---
function validE164(phone) {
  return typeof phone === "string" && /^\+[1-9]\d{7,14}$/.test(phone.trim());
}

// --- تحديد المعدّل: ذاكرة داخل نفس نسخة الدالة (حماية أساسية) ---
// ملاحظة: serverless قد يُنشئ نسخاً متعددة؛ هذا حاجز أول، والحاجز الأقوى
// هو حدود Twilio Verify نفسها (5 محاولات، 3 إعادات) المضبوطة في الخدمة.
const _hits = new Map(); // key -> [timestamps]
function rateLimit(key, maxPerWindow, windowMs) {
  const now = Date.now();
  const arr = (_hits.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= maxPerWindow) {
    const retryMs = windowMs - (now - arr[0]);
    return { ok: false, retryAfter: Math.ceil(retryMs / 1000) };
  }
  arr.push(now); _hits.set(key, arr);
  return { ok: true };
}

// --- قراءة جسم الطلب JSON بأمان ---
async function readJson(req) {
  if (req.body && typeof req.body === "object") return req.body;
  return await new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { resolve({}); } });
  });
}

function clientIp(req) {
  return (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
}

module.exports = { getAdmin, applyCors, validE164, rateLimit, readJson, clientIp };
