const { getAdmin, applyCors, readJson, rateLimit, clientIp } = require("./_lib");
const { listObjects, deleteObjects } = require("./_media");

async function requireAdmin(admin, idToken) {
  const decoded = await admin.auth().verifyIdToken(idToken);
  const cfg = await admin.firestore().collection("siteConfig").doc("main").get();
  const adminUid = cfg.exists ? cfg.data().adminUid : null;
  if (!adminUid || decoded.uid !== adminUid) {
    const err = new Error("caller_not_admin"); err.httpCode = 403; throw err;
  }
  return decoded.uid;
}

async function collectReferencedRefs(db) {
  const refs = new Set();
  const users = await db.collection("users").get();
  users.forEach((d) => {
    const u = d.data() || {};
    if (u.photoRef) refs.add(String(u.photoRef));
  });

  const chats = await db.collection("chats").get();
  for (const chat of chats.docs) {
    const messages = await chat.ref.collection("messages").get();
    messages.forEach((d) => {
      const m = d.data() || {};
      if (m.mediaRef) refs.add(String(m.mediaRef));
    });
  }

  const statusUsers = await db.collection("status").get();
  for (const user of statusUsers.docs) {
    const items = await user.ref.collection("items").get();
    items.forEach((d) => {
      const item = d.data() || {};
      if (item.mediaRef) refs.add(String(item.mediaRef));
    });
  }
  return refs;
}

async function usageFor(provider) {
  const data = await listObjects(provider, 5000);
  const usedBytes = data.objects.reduce((n, o) => n + o.size, 0);
  return {
    provider,
    bucket: data.bucket,
    objectCount: data.objects.length,
    usedBytes,
    quotaBytes: data.quotaBytes,
    remainingBytes: Math.max(0, data.quotaBytes - usedBytes),
    scannedAll: !data.truncated,
    truncated: data.truncated,
  };
}

function candidateView(objects, refs, graceHours) {
  const cutoff = Date.now() - graceHours * 3600 * 1000;
  const candidates = objects.filter((o) => {
    const oldEnough = !o.lastModified || new Date(o.lastModified).getTime() < cutoff;
    return oldEnough && !refs.has(o.ref);
  });
  return {
    count: candidates.length,
    bytes: candidates.reduce((n, o) => n + o.size, 0),
    truncated: objects.length >= 5000,
    objects: candidates.slice(0, 100).map((o) => ({ key: o.key, ref: o.ref, size: o.size, lastModified: o.lastModified })),
  };
}

module.exports = async (req, res) => {
  if (applyCors(req, res)) return;
  if (req.method !== "POST") return res.status(405).json({ error: "method_not_allowed" });
  const limited = rateLimit("media-admin:" + clientIp(req), 30, 15 * 60 * 1000);
  if (!limited.ok) return res.status(429).json({ error: "rate_limited", retryAfter: limited.retryAfter });

  try {
    const body = await readJson(req);
    const admin = getAdmin();
    await requireAdmin(admin, body.idToken);
    const db = admin.firestore();
    const action = body.action || "usage";
    const provider = body.provider;

    if (action === "usage") {
      const providers = provider ? [provider] : ["r2", "b2"];
      const results = await Promise.all(providers.map(usageFor));
      return res.status(200).json({ ok: true, providers: results, generatedAt: new Date().toISOString() });
    }

    if (!["r2", "b2"].includes(provider)) return res.status(400).json({ error: "invalid_provider" });
    const data = await listObjects(provider, 5000);
    const refs = await collectReferencedRefs(db);
    const graceHours = Math.min(24 * 30, Math.max(24, Number(body.graceHours || 24 * 7)));
    const preview = candidateView(data.objects, refs, graceHours);

    if (action === "preview_cleanup") {
      return res.status(200).json({ ok: true, provider, graceHours, ...preview, generatedAt: new Date().toISOString() });
    }

    if (action === "cleanup") {
      if (body.confirm !== "URUK-CLEANUP") return res.status(400).json({ error: "confirmation_required" });
      const allowedKeys = new Set(preview.objects.map((o) => o.key));
      const requested = Array.isArray(body.keys) && body.keys.length ? body.keys.map(String) : [...allowedKeys];
      const keys = requested.filter((key) => allowedKeys.has(key)).slice(0, 1000);
      const result = await deleteObjects(provider, keys);
      await db.collection("admin_logs").add({
        action: "media_cleanup", provider, deletedCount: result.deleted.length,
        deletedBytes: preview.objects.filter((o) => result.deleted.includes(o.key)).reduce((n, o) => n + o.size, 0),
        at: admin.firestore.FieldValue.serverTimestamp(),
      }).catch(() => {});
      return res.status(200).json({ ok: true, provider, deleted: result.deleted, errors: result.errors || [], remainingCandidates: Math.max(0, preview.count - result.deleted.length) });
    }
    return res.status(400).json({ error: "unknown_action" });
  } catch (e) {
    console.error("media-admin:", e);
    return res.status(e.httpCode || 400).json({ error: e.message === "caller_not_admin" ? "forbidden" : "media_admin_error", detail: e.message || String(e) });
  }
};
