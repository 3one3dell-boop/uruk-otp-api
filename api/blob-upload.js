// ============================================================
// POST /api/blob-upload — يُصدر توكن رفع آمن لـ Vercel Blob بعد التحقق
// من هوية المستخدم (Firebase ID Token) وصلاحية المسار المطلوب.
// الرفع الفعلي للملف يصير من المتصفح مباشرة لخوادم Vercel Blob
// (ما يمر عبر هالدالة — أسرع وما يصطدم بحد حجم دوال Vercel).
//
// آلية العمل (بروتوكول @vercel/blob/client الرسمي):
// 1) المتصفح يستدعي هالنقطة بجسم فيه pathname المطلوب + clientPayload
//    (يحتوي Firebase ID Token).
// 2) هنا نتحقق التوكن صحيح (verifyIdToken) ونتأكد صاحبه مصرّح له
//    يكتب بهذا المسار بالضبط (نفس منطق storage.rules تماماً).
// 3) نرجع توكن رفع مؤقت (صالح لدقائق) يستخدمه المتصفح للرفع المباشر.
// ============================================================
const { handleUpload } = require("@vercel/blob/client");
const { getAdmin, applyCors, readJson } = require("./_lib");

// نفس منطق الصلاحيات الموجود بـ storage.rules بالضبط — أي تعديل هناك
// لازم ينعكس هنا كمان حتى يضلوا متطابقين
function isPathAllowed(pathname, uid) {
  if (pathname.startsWith(`avatars/${uid}.jpg`) || pathname.startsWith(`avatars/${uid}`)) return true;
  if (pathname.startsWith(`status/${uid}/`)) return true;
  const m = pathname.match(/^(images|files|voice)\/([^/]+)\//);
  if (m) {
    const chatId = m[2];
    return chatId.split("_").includes(uid);
  }
  return false;
}
// الصورة الشخصية مسارها ثابت بقصد (avatars/{uid}.jpg) — كل تبديل يحل محل
// القديمة بنفس المكان. باقي الأنواع (صور محادثات/ملفات/صوت/حالات) مسارها
// فريد كل مرة أصلاً (فيه وقت الإرسال بالاسم) فما تحتاج استبدال إطلاقاً.
function needsOverwrite(pathname, uid) {
  return pathname.startsWith(`avatars/${uid}`);
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });

  try {
    const body = await readJson(req);
    const jsonResponse = await handleUpload({
      body,
      request: req,
      onBeforeGenerateToken: async (pathname, clientPayload) => {
        let idToken = null;
        try { idToken = JSON.parse(clientPayload || "{}").idToken; } catch (e) {}
        if (!idToken) throw new Error("missing_auth_token");

        const admin = getAdmin();
        const decoded = await admin.auth().verifyIdToken(idToken); // يرمي استثناء لو التوكن غير صالح/منتهي
        const uid = decoded.uid;

        if (!isPathAllowed(pathname, uid)) {
          throw new Error("forbidden_path");
        }

        return {
          allowedContentTypes: ["image/*", "audio/*", "video/*", "application/pdf", "application/octet-stream", "application/zip", "application/msword", "application/vnd.*", "text/plain"],
          maximumSizeInBytes: 20 * 1024 * 1024, // 20MB — يطابق MAX_FILE_BYTES بالواجهة
          addRandomSuffix: false, // نتحكم بالاسم كامل من الواجهة (زمن + معرف)
          allowOverwrite: needsOverwrite(pathname, uid), // فقط للصورة الشخصية (مسار ثابت بقصد)
          tokenPayload: JSON.stringify({ uid }),
        };
      },
      onUploadCompleted: async () => {
        // ما نحتاج إجراء إضافي هنا — التطبيق يكتب مرجع الرسالة بفايرستور بنفسه بعد اكتمال الرفع
      },
    });
    return res.status(200).json(jsonResponse);
  } catch (e) {
    console.error("blob-upload:", e);
    const msg = e.message === "forbidden_path" ? "ماكو صلاحية للرفع بهذا المسار"
      : e.message === "missing_auth_token" ? "الجلسة غير صالحة، سجّل الدخول من جديد"
      : "تعذّر تجهيز الرفع";
    // تفاصيل الخطأ الدقيقة مؤقتاً للتشخيص (نفس نمط send-otp.js) — نشيلها بعد ما تنحل المشكلة
    return res.status(400).json({ error: "upload_error", message: msg, detail: e.message || String(e), hasBlobToken: !!process.env.BLOB_READ_WRITE_TOKEN });
  }
};
