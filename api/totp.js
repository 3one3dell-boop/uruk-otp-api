// ============================================================
// POST /api/totp — نقطة موحّدة لكل عمليات TOTP (بدل ٤ ملفات منفصلة).
// السبب: خطة Vercel المجانية تسمح بحد أقصى ١٢ دالة Serverless لكل
// نشرة — دمج الملفات هنا يقلّل العدد بدل ما يزيده مع نمو المشروع.
//
// يحدَّد الإجراء المطلوب عبر حقل "action" بجسم الطلب:
//   action: "setup"   → توليد مفتاح جديد (بانتظار التأكيد)
//   action: "confirm" → تأكيد أول رمز + تفعيل + توليد رموز استرداد
//   action: "verify"  → التحقق أثناء تسجيل الدخول
//   action: "disable" → تعطيل الحماية (يتطلب رمز صحيح)
//
// كل دالة أدناه هي بالضبط نفس منطق الملف الأصلي المقابل لها،
// بدون أي تغيير بالسلوك أو الأمان — فقط إعادة تنظيم بملف واحد.
// جسم الطلب يُقرأ مرة وحدة بالمستوى الأعلى (module.exports) ويُمرَّر
// جاهزاً (مُحلَّلاً) لكل دالة فرعية — لا تعيد أي دالة قراءته من جديد.
// ============================================================
const {
  getAdmin, applyCors, rateLimit, clientIp,
  generateTotpSecret, verifyTotp, otpauthUrl,
  generateRecoveryCodes, hashRecoveryCode,
} = require("./_lib");

async function handleSetup(body, res, admin, req) {
  const limited = rateLimit("totp-setup:" + clientIp(req), 10, 15 * 60 * 1000);
  if (!limited.ok) return res.status(429).json({ error: "rate_limited", retryAfter: limited.retryAfter });

  const { idToken } = body;
  if (!idToken) return res.status(400).json({ error: "missing_token" });
  const decoded = await admin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;

  const db = admin.firestore();
  const userDoc = await db.collection("users").doc(uid).get();
  const userData = userDoc.exists ? userDoc.data() : {};
  if (userData.totpEnabled) return res.status(409).json({ error: "already_enabled" });

  const secret = generateTotpSecret();
  const label = userData.username || userData.phone || uid.slice(0, 8);
  const url = otpauthUrl(secret, label);
  // السرّ يُخزَّن بمجموعة totpSecrets المحمية بالكامل (allow read,write: if
  // false بقواعد Firestore) — صفر عميل يقدر يقرأه، حتى صاحب الحساب نفسه.
  // كل التحقق يصير هنا بالخادم فقط عبر Admin SDK.
  await db.collection("totpSecrets").doc(uid).set({ pendingSecret: secret }, { merge: true });
  return res.status(200).json({ ok: true, secret, otpauthUrl: url });
}

async function handleConfirm(body, res, admin) {
  const { idToken, code } = body;
  if (!idToken || !code) return res.status(400).json({ error: "missing_fields" });
  const decoded = await admin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;

  const db = admin.firestore();
  const secretRef = db.collection("totpSecrets").doc(uid);
  const snap = await secretRef.get();
  const secret = snap.exists ? snap.data().pendingSecret : null;
  if (!secret) return res.status(400).json({ error: "no_pending_setup" });
  if (!verifyTotp(secret, code)) return res.status(400).json({ error: "invalid_code" });

  const recoveryCodes = generateRecoveryCodes(10);
  const hashed = recoveryCodes.map((c) => ({ hash: hashRecoveryCode(c), used: false }));
  await secretRef.set({
    secret, pendingSecret: admin.firestore.FieldValue.delete(), recoveryCodes: hashed,
  }, { merge: true });
  // الأعلام العامة بس تبقى بمستند users (العميل يحتاجها يعرف "هل مفعّل؟")
  await db.collection("users").doc(uid).set({ totpEnabled: true, twoFactor: true }, { merge: true });
  return res.status(200).json({ ok: true, recoveryCodes });
}

async function handleVerify(body, res, admin, req) {
  const { idToken, code } = body;
  if (!idToken || !code) return res.status(400).json({ error: "missing_fields" });
  const decoded = await admin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;

  const limUid = rateLimit("totp-verify:uid:" + uid, 5, 15 * 60 * 1000);
  const limIp = rateLimit("totp-verify:ip:" + clientIp(req), 15, 15 * 60 * 1000);
  if (!limUid.ok || !limIp.ok) {
    return res.status(429).json({ error: "rate_limited", retryAfter: Math.max(limUid.retryAfter || 0, limIp.retryAfter || 0) });
  }

  const db = admin.firestore();
  const userSnap = await db.collection("users").doc(uid).get();
  if (!userSnap.exists || !userSnap.data().totpEnabled) return res.status(400).json({ error: "totp_not_enabled" });
  const secretSnap = await db.collection("totpSecrets").doc(uid).get();
  const data = secretSnap.exists ? secretSnap.data() : {};

  if (/^\d{6}$/.test(String(code))) {
    if (verifyTotp(data.secret, code)) return res.status(200).json({ ok: true, method: "totp" });
    return res.status(400).json({ error: "invalid_code" });
  }
  const hash = hashRecoveryCode(code);
  const codes = Array.isArray(data.recoveryCodes) ? data.recoveryCodes : [];
  const idx = codes.findIndex((c) => c.hash === hash && !c.used);
  if (idx === -1) return res.status(400).json({ error: "invalid_code" });
  codes[idx].used = true; codes[idx].usedAt = Date.now();
  await db.collection("totpSecrets").doc(uid).update({ recoveryCodes: codes });
  const remaining = codes.filter((c) => !c.used).length;
  return res.status(200).json({ ok: true, method: "recovery", remainingCodes: remaining });
}

async function handleDisable(body, res, admin, req) {
  const limited = rateLimit("totp-disable:" + clientIp(req), 10, 15 * 60 * 1000);
  if (!limited.ok) return res.status(429).json({ error: "rate_limited", retryAfter: limited.retryAfter });

  const { idToken, code } = body;
  if (!idToken || !code) return res.status(400).json({ error: "missing_fields" });
  const decoded = await admin.auth().verifyIdToken(idToken);
  const uid = decoded.uid;

  const db = admin.firestore();
  const userRef = db.collection("users").doc(uid);
  const userSnap = await userRef.get();
  if (!userSnap.exists || !userSnap.data().totpEnabled) return res.status(400).json({ error: "totp_not_enabled" });
  const secretRef = db.collection("totpSecrets").doc(uid);
  const secretSnap = await secretRef.get();
  const data = secretSnap.exists ? secretSnap.data() : {};

  let valid = false;
  if (/^\d{6}$/.test(String(code))) {
    valid = verifyTotp(data.secret, code);
  } else {
    const hash = hashRecoveryCode(code);
    valid = (data.recoveryCodes || []).some((c) => c.hash === hash && !c.used);
  }
  if (!valid) return res.status(400).json({ error: "invalid_code" });

  await secretRef.delete();
  await userRef.update({ totpEnabled: false, twoFactor: false });
  return res.status(200).json({ ok: true });
}

async function handleAdminRemove(body, res, admin) {
  // إزالة إدارية — تتطلب صلاحية أدمن حقيقية، تستخدم لمن الإدمن يوافق
  // على طلب استرداد بعد التحقق من الهوية (بدون حاجة لرمز المستخدم نفسه)
  const { idToken, targetUid } = body;
  if (!idToken || !targetUid) return res.status(400).json({ error: "missing_fields" });
  const decoded = await admin.auth().verifyIdToken(idToken);
  const db = admin.firestore();
  const cfg = await db.collection("siteConfig").doc("main").get();
  const adminUid = cfg.exists ? cfg.data().adminUid : null;
  if (!adminUid || decoded.uid !== adminUid) return res.status(403).json({ error: "forbidden" });

  await db.collection("totpSecrets").doc(targetUid).delete();
  await db.collection("users").doc(targetUid).update({ totpEnabled: false, twoFactor: false });
  return res.status(200).json({ ok: true });
}

async function readJsonBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  return await new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => { try { resolve(JSON.parse(data || "{}")); } catch { resolve({}); } });
  });
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  try {
    const body = await readJsonBody(req); // يُقرأ مرة وحدة هنا فقط
    const admin = getAdmin();
    switch (body.action) {
      case "setup": return await handleSetup(body, res, admin, req);
      case "confirm": return await handleConfirm(body, res, admin);
      case "verify": return await handleVerify(body, res, admin, req);
      case "disable": return await handleDisable(body, res, admin, req);
      case "admin_remove": return await handleAdminRemove(body, res, admin);
      default: return res.status(400).json({ error: "unknown_action" });
    }
  } catch (e) {
    console.error("totp:", e);
    return res.status(400).json({ error: "totp_error", detail: e.message || String(e) });
  }
};
