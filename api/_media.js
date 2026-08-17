const {
  S3Client,
  ListObjectsV2Command,
  GetObjectCommand,
  PutObjectCommand,
  DeleteObjectsCommand,
} = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const MAX_MEDIA_BYTES = 60 * 1024 * 1024;
const DEFAULT_QUOTA_BYTES = 10 * 1024 * 1024 * 1024;

function providerConfig(provider) {
  if (provider === "r2") {
    return {
      provider: "r2",
      bucket: process.env.R2_BUCKET || "uruk-media-private",
      endpoint: process.env.R2_ENDPOINT || "",
      region: "auto",
      accessKeyId: process.env.R2_ACCESS_KEY_ID || "",
      secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || "",
      quotaBytes: Number(process.env.R2_QUOTA_BYTES || DEFAULT_QUOTA_BYTES),
    };
  }
  if (provider === "b2") {
    return {
      provider: "b2",
      bucket: process.env.B2_BUCKET || "uruk-media-b2",
      endpoint: process.env.B2_ENDPOINT || "",
      region: process.env.B2_REGION || "us-east-005",
      accessKeyId: process.env.B2_KEY_ID || "",
      secretAccessKey: process.env.B2_APPLICATION_KEY || "",
      quotaBytes: Number(process.env.B2_QUOTA_BYTES || DEFAULT_QUOTA_BYTES),
    };
  }
  throw new Error("unknown_provider");
}

function assertProviderReady(provider) {
  const cfg = providerConfig(provider);
  if (!cfg.endpoint || !cfg.bucket || !cfg.accessKeyId || !cfg.secretAccessKey) {
    throw new Error(`${provider}_storage_not_configured`);
  }
  return cfg;
}

function clientFor(provider) {
  const cfg = assertProviderReady(provider);
  return {
    cfg,
    client: new S3Client({
      region: cfg.region,
      endpoint: cfg.endpoint,
      forcePathStyle: false,
      credentials: { accessKeyId: cfg.accessKeyId, secretAccessKey: cfg.secretAccessKey },
    }),
  };
}

// التوزيع يحافظ على استخدام المزودين معًا: صور الحساب/الحالات/الصور في R2،
// والملفات/الصوت/الفيديو في B2. لا تُرسل أسرار المزود إلى المتصفح.
function providerForPath(pathname) {
  const p = String(pathname || "").replace(/^\/+/, "");
  if (p.startsWith("avatars/") || p.startsWith("status/") || p.startsWith("images/")) return "r2";
  if (p.startsWith("files/") || p.startsWith("voice/") || p.startsWith("videos/")) return "b2";
  throw new Error("unsupported_media_path");
}

function cleanPath(pathname) {
  const p = String(pathname || "").replace(/^\/+/, "");
  if (!p || p.length > 512 || p.includes("..") || /[\\\u0000\r\n]/.test(p)) throw new Error("invalid_media_path");
  return p;
}

function isPathAllowed(pathname, uid, mode = "write") {
  const p = cleanPath(pathname);
  const avatar = p.startsWith("avatars/");
  const ownAvatar = p.startsWith(`avatars/${uid}`);
  const ownStatus = p.startsWith(`status/${uid}/`);
  const status = p.startsWith("status/");
  const match = p.match(/^(images|files|voice|videos)\/([^/]+)\//);
  const chat = !!(match && String(match[2]).split("_").includes(uid));
  if (mode === "write") return ownAvatar || ownStatus || chat;
  // مثل قواعد Firebase القديمة: الصور الشخصية والحالات قابلة للقراءة للمستخدم الموثق،
  // بينما وسائط المحادثة لا تُقرأ إلا من طرفي chatId.
  return avatar || status || chat;
}

function mediaRef(provider, key) {
  return `${provider}:${key}`;
}

function parseMediaRef(ref) {
  const s = String(ref || "");
  const i = s.indexOf(":");
  if (i < 1) throw new Error("invalid_media_ref");
  const provider = s.slice(0, i);
  const key = cleanPath(s.slice(i + 1));
  if (!['r2', 'b2'].includes(provider)) throw new Error("invalid_media_provider");
  return { provider, key };
}

async function signedPut(provider, key, contentType) {
  const { cfg, client } = clientFor(provider);
  const command = new PutObjectCommand({
    Bucket: cfg.bucket,
    Key: key,
    ContentType: contentType || "application/octet-stream",
    CacheControl: "private, max-age=3600",
  });
  return getSignedUrl(client, command, { expiresIn: 15 * 60 });
}

async function signedGet(provider, key, filename = "") {
  const { cfg, client } = clientFor(provider);
  const command = new GetObjectCommand({
    Bucket: cfg.bucket,
    Key: key,
    ...(filename ? { ResponseContentDisposition: `attachment; filename*=UTF-8''${encodeURIComponent(filename)}` } : {}),
  });
  return getSignedUrl(client, command, { expiresIn: 15 * 60 });
}

async function listObjects(provider, maxObjects = 5000) {
  const { cfg, client } = clientFor(provider);
  const objects = [];
  let ContinuationToken;
  let truncated = false;
  do {
    const data = await client.send(new ListObjectsV2Command({
      Bucket: cfg.bucket,
      ContinuationToken,
      MaxKeys: Math.min(1000, Math.max(1, maxObjects - objects.length)),
    }));
    for (const o of (data.Contents || [])) {
      objects.push({
        provider,
        bucket: cfg.bucket,
        key: o.Key,
        ref: mediaRef(provider, o.Key),
        size: Number(o.Size || 0),
        lastModified: o.LastModified ? new Date(o.LastModified).toISOString() : null,
      });
    }
    truncated = !!data.IsTruncated;
    ContinuationToken = data.NextContinuationToken;
  } while (truncated && ContinuationToken && objects.length < maxObjects);
  return { provider, bucket: cfg.bucket, quotaBytes: cfg.quotaBytes, objects, truncated };
}

async function deleteObjects(provider, keys) {
  if (!keys.length) return { deleted: [] };
  const { cfg, client } = clientFor(provider);
  const result = await client.send(new DeleteObjectsCommand({
    Bucket: cfg.bucket,
    Delete: { Objects: keys.slice(0, 1000).map((Key) => ({ Key })), Quiet: true },
  }));
  return { deleted: (result.Deleted || []).map((x) => x.Key).filter(Boolean), errors: result.Errors || [] };
}

module.exports = {
  MAX_MEDIA_BYTES,
  DEFAULT_QUOTA_BYTES,
  providerConfig,
  assertProviderReady,
  clientFor,
  providerForPath,
  cleanPath,
  isPathAllowed,
  mediaRef,
  parseMediaRef,
  signedPut,
  signedGet,
  listObjects,
  deleteObjects,
};
