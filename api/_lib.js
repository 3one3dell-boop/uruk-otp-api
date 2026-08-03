// ============================================================
// أدوات مشتركة للخادم (Vercel Serverless) — أوروك OTP عبر Twilio Verify
// كل المفاتيح السرية تُقرأ من متغيّرات البيئة، ولا تظهر أبداً في الواجهة.
// ============================================================
const admin = require("firebase-admin");

// --- بصمة آمنة لبيانات الاعتماد (بدون كشف القيم السرّية نفسها) —
// تساعد نكتشف أخطاء نسخ/لصق شائعة: طول غير متوقع، بداية/نهاية ناقصة، مسافات زائدة
function credFingerprint() {
  const projectId = process.env.FIREBASE_PROJECT_ID || "";
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL || "";
  const rawKey = process.env.FIREBASE_PRIVATE_KEY || "";
  const key = rawKey.replace(/\\n/g, "\n");
  return {
    projectId: projectId,
    projectIdLen: projectId.length,
    clientEmail: clientEmail,
    clientEmailLen: clientEmail.length,
    keyRawLen: rawKey.length,
    keyAfterNewlineFixLen: key.length,
    keyStartsCorrectly: key.startsWith("-----BEGIN PRIVATE KEY-----"),
    keyEndsCorrectly: key.trim().endsWith("-----END PRIVATE KEY-----"),
    keyLineCount: key.split("\n").length, // مفتاح سليم عادة حوله 28 سطراً
    keyFirst15: key.slice(0, 15),
    keyLast15: key.slice(-15),
  };
}

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

// --- CORS: نسمح للدومينات الموثوقة فقط (القديم + الجديد معاً، حتى
// ما ينكسر أي طلب أثناء الانتقال بين الدومينات). كل دومين إضافي يُضاف
// بمتغيّر ALLOWED_ORIGINS (مفصول بفواصل) بدون حاجة لتعديل الكود مرة ثانية.
const DEFAULT_ALLOWED_ORIGINS = [
  "https://sada-chat-iq.web.app",
  "https://www.urukapp.store",
  "https://urukapp.store",
];
function applyCors(req, res) {
  const extra = (process.env.ALLOWED_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
  const allowedList = extra.length ? extra : DEFAULT_ALLOWED_ORIGINS;
  const origin = req.headers.origin || "";
  const matched = allowedList.includes(origin) ? origin : allowedList[0];
  res.setHeader("Access-Control-Allow-Origin", matched);
  res.setHeader("Vary", "Origin"); // يمنع أي وسيط تخزين مؤقت يخلط بين الدومينات
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Max-Age", "30");
  // يمنع أي تخزين مؤقت (متصفح، وسيط شبكة، أو Vercel Edge نفسه) من
  // الاحتفاظ بأي رد قديم — كل طلب يوصل السيرفر فعلياً، صفر كاش بأي طبقة
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Pragma", "no-cache");
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

// ============================================================
// TOTP (RFC 6238) — التحقق بخطوتين عبر تطبيقات Authenticator
// (Google Authenticator / Microsoft Authenticator / Authy...).
// تطبيق كامل بدون أي مكتبة خارجية — crypto المدمجة بـNode كافية
// لـHMAC-SHA1، ونطبّق ترميز Base32 يدوياً (خوارزمية قياسية بسيطة).
// ============================================================
const crypto = require("crypto");

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(buf) {
  let bits = "", out = "";
  for (const byte of buf) bits += byte.toString(2).padStart(8, "0");
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, "0");
    out += B32_ALPHABET[parseInt(chunk, 2)];
  }
  return out;
}
function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const ch of clean) bits += B32_ALPHABET.indexOf(ch).toString(2).padStart(5, "0");
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}
function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20)); // 160-bit، معيار Authenticator القياسي
}
function totpAt(secretB32, timeStep) {
  const key = base32Decode(secretB32);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(timeStep));
  const hmac = crypto.createHmac("sha1", key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, "0");
}
// نقبل الرمز الحالي + خطوة قبل/بعد (هامش انزلاق ساعة ±30 ثانية — شائع ومقبول)
function verifyTotp(secretB32, code, window = 1) {
  if (!/^\d{6}$/.test(String(code || ""))) return false;
  const step = Math.floor(Date.now() / 1000 / 30);
  for (let w = -window; w <= window; w++) {
    if (totpAt(secretB32, step + w) === String(code)) return true;
  }
  return false;
}
function otpauthUrl(secretB32, accountLabel, issuer = "Uruk") {
  const label = encodeURIComponent(`${issuer}:${accountLabel}`);
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
// رموز استرداد: نولّد نص عادي (يُعرض مرة وحدة)، نخزّن hash فقط (نفس نمط send-otp.js)
function generateRecoveryCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(5).toString("hex").toUpperCase(); // 10 محارف
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5)}`);
  }
  return codes;
}
function hashRecoveryCode(code) {
  const salt = process.env.OTP_HASH_SALT || "uruk-salt";
  return crypto.createHash("sha256").update(salt + ":" + code.toUpperCase()).digest("hex");
}

// ============================================================
// reCAPTCHA Enterprise — يتحقق من التوكن المُرسل من العميل عبر واجهة
// Google Cloud Assessment API. يحتاج GOOGLE_CLOUD_API_KEY بمتغيّرات
// البيئة (مفتاح API عادي بمشروع Google Cloud، صلاحية reCAPTCHA
// Enterprise). الحد الأدنى للنتيجة (score) قابل للتعديل حسب الحالة.
// ============================================================
async function verifyRecaptcha(token, expectedAction, minScore = 0.5) {
  const apiKey = process.env.GOOGLE_CLOUD_API_KEY;
  const projectId = process.env.RECAPTCHA_PROJECT_ID || "sada-chat-iq";
  const siteKey = process.env.RECAPTCHA_SITE_KEY;
  if (!apiKey || !siteKey) {
    // ماكو إعداد — نرفض بأمان بدل ما نسمح للجميع (فشل آمن)
    return { pass: false, reason: "recaptcha_not_configured" };
  }
  if (!token) return { pass: false, reason: "missing_token" };
  try {
    const url = `https://recaptchaenterprise.googleapis.com/v1/projects/${projectId}/assessments?key=${apiKey}`;
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event: { token, expectedAction, siteKey } }),
    });
    const data = await r.json();
    if (!r.ok || !data.tokenProperties || !data.tokenProperties.valid) {
      return { pass: false, reason: "invalid_token", detail: data };
    }
    if (expectedAction && data.tokenProperties.action !== expectedAction) {
      return { pass: false, reason: "action_mismatch" };
    }
    const score = data.riskAnalysis ? data.riskAnalysis.score : 0;
    return { pass: score >= minScore, score, reason: score >= minScore ? "ok" : "low_score" };
  } catch (e) {
    console.error("verifyRecaptcha:", e);
    return { pass: false, reason: "verify_error" };
  }
}

module.exports = {
  getAdmin, applyCors, validE164, rateLimit, readJson, clientIp, credFingerprint,
  generateTotpSecret, verifyTotp, otpauthUrl, generateRecoveryCodes, hashRecoveryCode,
  verifyRecaptcha,
};
