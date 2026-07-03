require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: false,
  })
);

app.use(cors());
app.use(express.json({ limit: "32kb" }));

const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const LOOTLABS_BASE_URL = process.env.LOOTLABS_BASE_URL;
const POSTBACK_SECRET = process.env.POSTBACK_SECRET;
const KEY_PEPPER = process.env.KEY_PEPPER;

const KEY_TTL_HOURS = Number(process.env.KEY_TTL_HOURS || 24);
const SESSION_TTL_MINUTES = Number(process.env.SESSION_TTL_MINUTES || 60);

const ADMIN_SECRET = process.env.ADMIN_SECRET || "";

function requireEnv(name, value) {
  if (!value || String(value).trim() === "") {
    console.error("Missing env:", name);
    process.exit(1);
  }
}

requireEnv("SUPABASE_URL", SUPABASE_URL);
requireEnv("SUPABASE_SERVICE_ROLE_KEY", SUPABASE_SERVICE_ROLE_KEY);
requireEnv("LOOTLABS_BASE_URL", LOOTLABS_BASE_URL);
requireEnv("POSTBACK_SECRET", POSTBACK_SECRET);
requireEnv("KEY_PEPPER", KEY_PEPPER);

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
  },
});

function now() {
  return new Date();
}

function addMinutes(date, minutes) {
  return new Date(date.getTime() + minutes * 60 * 1000);
}

function addHours(date, hours) {
  return new Date(date.getTime() + hours * 60 * 60 * 1000);
}

function sha256(text) {
  return crypto.createHash("sha256").update(String(text)).digest("hex");
}

function hashKey(key) {
  return sha256(`${KEY_PEPPER}:${key}`);
}

function normalizeUid(uid) {
  uid = String(uid || "").trim();

  if (!/^\d{1,20}$/.test(uid)) {
    return null;
  }

  return uid;
}

function normalizeSid(sid) {
  sid = String(sid || "").trim().toLowerCase();

  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
      sid
    )
  ) {
    return null;
  }

  return sid;
}

function normalizeKey(key) {
  key = String(key || "").trim().toUpperCase();

  if (!/^NL-[A-Z0-9]{4}(-[A-Z0-9]{4}){5}$/.test(key)) {
    return null;
  }

  return key;
}

function firstQueryValue(value) {
  if (Array.isArray(value)) {
    return value[0];
  }

  return value;
}

function randomChars(length) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.randomBytes(length);

  let out = "";

  for (let i = 0; i < length; i++) {
    out += alphabet[bytes[i] % alphabet.length];
  }

  return out;
}

function makeKey() {
  const raw = randomChars(24);
  return "NL-" + raw.match(/.{1,4}/g).join("-");
}

function makeLootlabsUrl(sid) {
  const base = String(LOOTLABS_BASE_URL).trim();

  if (base.includes("puid=")) {
    throw new Error("LOOTLABS_BASE_URL must not contain puid=");
  }

  const joiner = base.includes("?") ? "&" : "?";

  return `${base}${joiner}puid=${encodeURIComponent(sid)}`;
}

function clientIp(req) {
  return (
    req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.ip ||
    ""
  );
}

function jsonError(res, status, message, extra = {}) {
  return res.status(status).json({
    ok: false,
    message,
    ...extra,
  });
}

function parseCookies(req) {
  const header = req.headers.cookie || "";
  const cookies = {};

  header.split(";").forEach((part) => {
    const index = part.indexOf("=");

    if (index === -1) return;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    try {
      cookies[key] = decodeURIComponent(value);
    } catch {
      cookies[key] = value;
    }
  });

  return cookies;
}

function setKeyCookies(res, sid, uid) {
  const maxAge = SESSION_TTL_MINUTES * 60;

  res.setHeader("Set-Cookie", [
    `ks_sid=${encodeURIComponent(
      sid
    )}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`,
    `ks_uid=${encodeURIComponent(
      uid
    )}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`,
  ]);
}

const publicLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 90,
  standardHeaders: true,
  legacyHeaders: false,
});

const strictLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(publicLimiter);

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "roblox-lootlabs-supabase-keysystem",
    endpoints: [
      "/get-key",
      "/complete",
      "/site-claim",
      "/verify",
      "/session-debug",
      "/lootlabs/postback/:secret",
    ],
  });
});

app.get("/get-key", strictLimiter, async (req, res) => {
  try {
    const uid = normalizeUid(req.query.uid);

    if (!uid) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(400).end("Bad uid");
    }

    const createdAt = now();
    const expiresAt = addMinutes(createdAt, SESSION_TTL_MINUTES);
    const sid = crypto.randomUUID();

    const lootlabsUrl = makeLootlabsUrl(sid);

    console.log("GET_KEY CREATED");
    console.log("UID:", uid);
    console.log("SID:", sid);
    console.log("LOOTLABS URL:", lootlabsUrl);

    const { error } = await supabase.from("key_sessions").insert({
      sid,
      uid,
      completed: false,
      claimed: false,
      created_at: createdAt.toISOString(),
      expires_at: expiresAt.toISOString(),
      start_ip: clientIp(req),
      start_user_agent: String(req.headers["user-agent"] || "").slice(0, 300),
    });

    if (error) {
      console.error("GET_KEY_INSERT_ERROR", error);
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(500).end("Database error");
    }

    setKeyCookies(res, sid, uid);

    return res.redirect(lootlabsUrl);
  } catch (err) {
    console.error("GET_KEY_ERROR", err);
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.status(500).end("Server error");
  }
});

app.get("/complete", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");

  res.end(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Your Key</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: radial-gradient(circle at top, #171722, #07070b 60%);
      color: white;
      font-family: Arial, sans-serif;
    }

    .box {
      width: min(92vw, 560px);
      padding: 28px;
      border-radius: 22px;
      background: rgba(17, 17, 24, 0.95);
      border: 1px solid #292938;
      box-shadow: 0 25px 80px rgba(0, 0, 0, .55);
      text-align: center;
    }

    h1 {
      margin: 0 0 12px;
      font-size: 28px;
    }

    p {
      margin: 0;
      color: #b8b8c6;
      line-height: 1.5;
      font-size: 15px;
    }

    .key {
      margin-top: 18px;
      padding: 16px;
      border-radius: 15px;
      background: #1d1d27;
      border: 1px solid #343448;
      font-size: 18px;
      line-height: 1.45;
      word-break: break-all;
      user-select: all;
      display: none;
    }

    button {
      margin-top: 20px;
      width: 100%;
      height: 48px;
      border: 0;
      border-radius: 15px;
      background: #ffffff;
      color: #050508;
      font-weight: 800;
      font-size: 15px;
      cursor: pointer;
    }

    button:disabled {
      opacity: .55;
      cursor: not-allowed;
    }

    .status {
      margin-top: 14px;
      color: #b8b8c6;
      font-size: 14px;
      line-height: 1.4;
      min-height: 20px;
    }

    .small {
      margin-top: 16px;
      color: #77778a;
      font-size: 12px;
    }
  </style>
</head>

<body>
  <div class="box">
    <h1>LootLabs completed</h1>

    <p>
      Нажми кнопку ниже, чтобы получить ключ.
      Потом скопируй его и вставь в Roblox.
    </p>

    <button id="btn">Show Key</button>

    <div id="key" class="key"></div>
    <div id="status" class="status">Waiting...</div>

    <div class="small">
      Если ключ не появился сразу, подожди 5 секунд и нажми Try Again.
    </div>
  </div>

  <script>
    const btn = document.getElementById("btn");
    const keyBox = document.getElementById("key");
    const statusBox = document.getElementById("status");

    let currentKey = "";

    async function copyKey() {
      if (!currentKey) return;

      try {
        await navigator.clipboard.writeText(currentKey);
        statusBox.textContent = "Copied. Paste it in Roblox.";
      } catch (e) {
        statusBox.textContent = "Copy manually.";
      }
    }

    async function claim() {
      btn.disabled = true;
      btn.textContent = "Loading...";
      statusBox.textContent = "Checking LootLabs completion...";

      try {
        const res = await fetch("/site-claim", {
          method: "GET",
          credentials: "include"
        });

        const data = await res.json();

        if (data.ok && data.key) {
          currentKey = data.key;

          keyBox.style.display = "block";
          keyBox.textContent = data.key;

          statusBox.textContent = "Key ready. Paste it in Roblox.";

          try {
            await navigator.clipboard.writeText(data.key);
            statusBox.textContent = "Key copied. Paste it in Roblox.";
          } catch (e) {}

          btn.textContent = "Copy Key";
          btn.disabled = false;
          btn.onclick = copyKey;

          return;
        }

        if (data.pending) {
          statusBox.textContent =
            "LootLabs postback has not arrived yet. Wait 5 seconds and press again.";

          btn.textContent = "Try Again";
          btn.disabled = false;
          btn.onclick = claim;

          return;
        }

        statusBox.textContent = data.message || "Failed to get key.";
        btn.textContent = "Try Again";
        btn.disabled = false;
        btn.onclick = claim;
      } catch (err) {
        statusBox.textContent = "Request failed. Try again.";
        btn.textContent = "Try Again";
        btn.disabled = false;
        btn.onclick = claim;
      }
    }

    btn.onclick = claim;

    setTimeout(claim, 800);
  </script>
</body>
</html>`);
});

app.get("/site-claim", strictLimiter, async (req, res) => {
  try {
    const cookies = parseCookies(req);

    const sid = normalizeSid(cookies.ks_sid);
    const uid = normalizeUid(cookies.ks_uid);

    console.log("SITE_CLAIM");
    console.log("COOKIE SID:", sid);
    console.log("COOKIE UID:", uid);

    if (!sid || !uid) {
      return res.json({
        ok: false,
        message: "Session not found. Open Get Key from Roblox again.",
      });
    }

    const { data: session, error: sessionError } = await supabase
      .from("key_sessions")
      .select("*")
      .eq("sid", sid)
      .eq("uid", uid)
      .maybeSingle();

    if (sessionError) {
      console.error("SITE_CLAIM_SESSION_ERROR", sessionError);
      return jsonError(res, 500, "Database error");
    }

    if (!session) {
      return res.json({
        ok: false,
        message: "Session not found. Open Get Key from Roblox again.",
      });
    }

    console.log("SITE_CLAIM SESSION:", {
      sid: session.sid,
      uid: session.uid,
      completed: session.completed,
      claimed: session.claimed,
      expires_at: session.expires_at,
      lootlabs_unique_id: session.lootlabs_unique_id,
    });

    if (new Date(session.expires_at) <= now()) {
      return res.json({
        ok: false,
        message: "Session expired. Open Get Key from Roblox again.",
      });
    }

    if (!session.completed) {
      return res.json({
        ok: false,
        pending: true,
        message: "Complete LootLabs first",
      });
    }

    if (session.claimed && session.display_key) {
      return res.json({
        ok: true,
        key: session.display_key,
        expiresAt: session.key_expires_at,
      });
    }

    if (session.claimed && !session.display_key) {
      return res.json({
        ok: false,
        message: "Key already claimed. Open Get Key from Roblox again.",
      });
    }

    const key = makeKey();
    const keyHash = hashKey(key);
    const keyCreatedAt = now();
    const keyExpiresAt = addHours(keyCreatedAt, KEY_TTL_HOURS);

    const { error: keyInsertError } = await supabase.from("keys").insert({
      key_hash: keyHash,
      uid,
      sid,
      active: true,
      created_at: keyCreatedAt.toISOString(),
      expires_at: keyExpiresAt.toISOString(),
      used_count: 0,
    });

    if (keyInsertError) {
      console.error("SITE_CLAIM_KEY_INSERT_ERROR", keyInsertError);
      return jsonError(res, 500, "Failed to create key");
    }

    const { error: updateError } = await supabase
      .from("key_sessions")
      .update({
        claimed: true,
        claimed_at: keyCreatedAt.toISOString(),
        key_hash: keyHash,
        key_created_at: keyCreatedAt.toISOString(),
        key_expires_at: keyExpiresAt.toISOString(),
        display_key: key,
      })
      .eq("sid", sid)
      .eq("uid", uid);

    if (updateError) {
      console.error("SITE_CLAIM_UPDATE_ERROR", updateError);
      return jsonError(res, 500, "Failed to save key");
    }

    console.log("KEY CREATED:", {
      sid,
      uid,
      expiresAt: keyExpiresAt.toISOString(),
    });

    return res.json({
      ok: true,
      key,
      expiresInHours: KEY_TTL_HOURS,
      expiresAt: keyExpiresAt.toISOString(),
    });
  } catch (err) {
    console.error("SITE_CLAIM_ERROR", err);
    return jsonError(res, 500, "Server error");
  }
});

app.get("/lootlabs/postback/:secret", async (req, res) => {
  console.log("POSTBACK HIT");
  console.log("POSTBACK SECRET:", req.params.secret);
  console.log("POSTBACK URL:", req.originalUrl);
  console.log("POSTBACK QUERY:", req.query);

  try {
    if (req.params.secret !== POSTBACK_SECRET) {
      console.log("POSTBACK FORBIDDEN: bad secret");

      return jsonError(res, 403, "Forbidden");
    }

    const rawSid =
      firstQueryValue(req.query.click_id) ||
      firstQueryValue(req.query.puid) ||
      firstQueryValue(req.query.sid);

    const rawUniqueId =
      firstQueryValue(req.query.unique_id) ||
      firstQueryValue(req.query.uniqueid) ||
      "";

    const rawIp = firstQueryValue(req.query.ip) || "";

    const sid = normalizeSid(rawSid);
    const uniqueId = String(rawUniqueId).trim();
    const lootlabsIp = String(rawIp).trim();

    console.log("POSTBACK PARSED:", {
      rawSid,
      sid,
      uniqueId,
      lootlabsIp,
    });

    if (!sid) {
      console.log("POSTBACK ERROR: missing or bad click_id");

      return jsonError(res, 400, "Missing or bad click_id", {
        rawSid,
        query: req.query,
      });
    }

    if (!uniqueId || uniqueId.length > 200) {
      console.log("POSTBACK ERROR: missing unique_id");

      return jsonError(res, 400, "Missing unique_id", {
        query: req.query,
      });
    }

    const { data: duplicate, error: duplicateError } = await supabase
      .from("postbacks")
      .select("id, sid, unique_id")
      .eq("unique_id", uniqueId)
      .maybeSingle();

    if (duplicateError) {
      console.error("SUPABASE_DUPLICATE_CHECK_ERROR", duplicateError);
      return jsonError(res, 500, "Database error");
    }

    if (duplicate) {
      console.log("POSTBACK DUPLICATE:", duplicate);

      return res.json({
        ok: true,
        duplicate: true,
      });
    }

    const { data: session, error: sessionError } = await supabase
      .from("key_sessions")
      .select("*")
      .eq("sid", sid)
      .maybeSingle();

    if (sessionError) {
      console.error("SUPABASE_SESSION_READ_ERROR", sessionError);
      return jsonError(res, 500, "Database error");
    }

    if (!session) {
      console.log("POSTBACK ERROR: session not found", sid);

      return jsonError(res, 404, "Session not found", {
        sid,
      });
    }

    if (new Date(session.expires_at) <= now()) {
      console.log("POSTBACK ERROR: session expired", {
        sid,
        expires_at: session.expires_at,
      });

      return jsonError(res, 410, "Session expired", {
        sid,
        expires_at: session.expires_at,
      });
    }

    const createdAt = now();

    const { error: postbackInsertError } = await supabase
      .from("postbacks")
      .insert({
        unique_id: uniqueId,
        sid,
        uid: session.uid,
        lootlabs_ip: lootlabsIp,
        request_ip: clientIp(req),
        query: req.query,
        created_at: createdAt.toISOString(),
      });

    if (postbackInsertError) {
      if (postbackInsertError.code === "23505") {
        console.log("POSTBACK DUPLICATE INSERT");

        return res.json({
          ok: true,
          duplicate: true,
        });
      }

      console.error("SUPABASE_POSTBACK_INSERT_ERROR", postbackInsertError);
      return jsonError(res, 500, "Database error");
    }

    const { error: updateError } = await supabase
      .from("key_sessions")
      .update({
        completed: true,
        completed_at: createdAt.toISOString(),
        lootlabs_ip: lootlabsIp,
        lootlabs_unique_id: uniqueId,
      })
      .eq("sid", sid);

    if (updateError) {
      console.error("SUPABASE_SESSION_UPDATE_ERROR", updateError);
      return jsonError(res, 500, "Database error");
    }

    console.log("POSTBACK SUCCESS:", {
      sid,
      uid: session.uid,
      uniqueId,
    });

    return res.json({
      ok: true,
    });
  } catch (err) {
    console.error("POSTBACK_ERROR", err);
    return jsonError(res, 500, "Server error");
  }
});

app.get("/verify", strictLimiter, async (req, res) => {
  try {
    const uid = normalizeUid(req.query.uid);
    const key = normalizeKey(req.query.key);

    if (!uid || !key) {
      return jsonError(res, 400, "Bad uid or key");
    }

    const keyHash = hashKey(key);

    const { data: keyDoc, error } = await supabase
      .from("keys")
      .select("*")
      .eq("key_hash", keyHash)
      .maybeSingle();

    if (error) {
      console.error("SUPABASE_VERIFY_READ_ERROR", error);
      return jsonError(res, 500, "Database error");
    }

    if (!keyDoc || !keyDoc.active) {
      return res.json({
        ok: false,
        message: "Invalid key",
      });
    }

    if (keyDoc.uid !== uid) {
      return res.json({
        ok: false,
        message: "This key is linked to another Roblox account",
      });
    }

    const currentTime = now();
    const expiresAt = new Date(keyDoc.expires_at);

    if (expiresAt <= currentTime) {
      return res.json({
        ok: false,
        message: "Key expired",
      });
    }

    await supabase
      .from("keys")
      .update({
        used_count: Number(keyDoc.used_count || 0) + 1,
        last_used_at: currentTime.toISOString(),
        last_ip: clientIp(req),
      })
      .eq("key_hash", keyHash);

    return res.json({
      ok: true,
      message: "Valid key",
      expiresAt: expiresAt.toISOString(),
      secondsLeft: Math.max(
        0,
        Math.floor((expiresAt.getTime() - currentTime.getTime()) / 1000)
      ),
    });
  } catch (err) {
    console.error("VERIFY_ERROR", err);
    return jsonError(res, 500, "Server error");
  }
});

app.get("/session-debug", async (req, res) => {
  try {
    const cookies = parseCookies(req);

    const sid = normalizeSid(cookies.ks_sid);
    const uid = normalizeUid(cookies.ks_uid);

    if (!sid || !uid) {
      return res.json({
        ok: false,
        message: "No session cookies",
        cookiesFound: Object.keys(cookies),
        rawCookieHeader: req.headers.cookie || null,
      });
    }

    const { data: session, error } = await supabase
      .from("key_sessions")
      .select(
        "sid, uid, completed, claimed, created_at, completed_at, expires_at, lootlabs_unique_id, display_key, key_expires_at"
      )
      .eq("sid", sid)
      .eq("uid", uid)
      .maybeSingle();

    if (error) {
      return res.json({
        ok: false,
        message: "Database error",
        error,
      });
    }

    return res.json({
      ok: true,
      cookieSid: sid,
      cookieUid: uid,
      session,
    });
  } catch (err) {
    return res.json({
      ok: false,
      message: "Server error",
      error: String(err),
    });
  }
});

app.get("/admin/stats", async (req, res) => {
  try {
    if (!ADMIN_SECRET || req.query.secret !== ADMIN_SECRET) {
      return jsonError(res, 403, "Forbidden");
    }

    const [
      sessionsResult,
      completedResult,
      keysResult,
      activeKeysResult,
      postbacksResult,
    ] = await Promise.all([
      supabase.from("key_sessions").select("*", { count: "exact", head: true }),
      supabase
        .from("key_sessions")
        .select("*", { count: "exact", head: true })
        .eq("completed", true),
      supabase.from("keys").select("*", { count: "exact", head: true }),
      supabase
        .from("keys")
        .select("*", { count: "exact", head: true })
        .eq("active", true)
        .gt("expires_at", now().toISOString()),
      supabase.from("postbacks").select("*", { count: "exact", head: true }),
    ]);

    return res.json({
      ok: true,
      sessions: sessionsResult.count || 0,
      completed: completedResult.count || 0,
      keys: keysResult.count || 0,
      activeKeys: activeKeysResult.count || 0,
      postbacks: postbacksResult.count || 0,
    });
  } catch (err) {
    console.error("ADMIN_STATS_ERROR", err);
    return jsonError(res, 500, "Server error");
  }
});

app.listen(PORT, () => {
  console.log(`Key system running on port ${PORT}`);
});
