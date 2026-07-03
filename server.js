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

  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(sid)) {
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
    `ks_sid=${encodeURIComponent(sid)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`,
    `ks_uid=${encodeURIComponent(uid)}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`,
  ]);
}

async function getSessionByCookies(req) {
  const cookies = parseCookies(req);

  const sid = normalizeSid(cookies.ks_sid);
  const uid = normalizeUid(cookies.ks_uid);

  if (!sid || !uid) {
    return {
      sid: null,
      uid: null,
      session: null,
      error: "No session",
    };
  }

  const { data, error } = await supabase
    .from("key_sessions")
    .select("*")
    .eq("sid", sid)
    .eq("uid", uid)
    .maybeSingle();

  if (error) {
    return {
      sid,
      uid,
      session: null,
      error: "Database error",
    };
  }

  return {
    sid,
    uid,
    session: data,
    error: null,
  };
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
    service: "key-system",
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

app.get("/continue", strictLimiter, async (req, res) => {
  try {
    const result = await getSessionByCookies(req);

    if (!result.sid || !result.uid || !result.session) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(400).end("Open Get Key from Roblox first.");
    }

    if (new Date(result.session.expires_at) <= now()) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.status(410).end("Session expired. Open Get Key from Roblox again.");
    }

    return res.redirect(makeLootlabsUrl(result.sid));
  } catch (err) {
    console.error("CONTINUE_ERROR", err);
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
  <title>Key System</title>
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
      background: #09090d;
      color: #ffffff;
      font-family: Arial, sans-serif;
    }

    .box {
      width: min(92vw, 480px);
      padding: 24px;
      border-radius: 16px;
      background: #14141b;
      border: 1px solid #2a2a36;
      text-align: center;
    }

    h1 {
      margin: 0 0 10px;
      font-size: 24px;
    }

    p {
      margin: 0;
      color: #b7b7c4;
      line-height: 1.45;
      font-size: 14px;
    }

    .key {
      display: none;
      margin-top: 18px;
      padding: 14px;
      border-radius: 12px;
      background: #20202a;
      border: 1px solid #353545;
      font-size: 16px;
      line-height: 1.45;
      word-break: break-all;
      user-select: all;
    }

    button {
      margin-top: 18px;
      width: 100%;
      height: 44px;
      border: 0;
      border-radius: 12px;
      background: #ffffff;
      color: #09090d;
      font-weight: 700;
      font-size: 14px;
      cursor: pointer;
    }

    button:disabled {
      opacity: .55;
      cursor: not-allowed;
    }

    .status {
      margin-top: 12px;
      color: #b7b7c4;
      font-size: 13px;
      min-height: 18px;
      line-height: 1.35;
    }
  </style>
</head>
<body>
  <div class="box">
    <h1>Your Key</h1>
    <p>Complete LootLabs, then copy your key and paste it in Roblox.</p>

    <button id="btn">Checking...</button>

    <div id="key" class="key"></div>
    <div id="status" class="status">Please wait...</div>
  </div>

  <script>
    const btn = document.getElementById("btn");
    const keyBox = document.getElementById("key");
    const statusBox = document.getElementById("status");

    let currentKey = "";
    let attempts = 0;
    const maxAttempts = 8;

    async function copyKey() {
      if (!currentKey) return;

      try {
        await navigator.clipboard.writeText(currentKey);
        statusBox.textContent = "Copied. Paste it in Roblox.";
      } catch (e) {
        statusBox.textContent = "Copy manually.";
      }
    }

    async function check() {
      attempts += 1;
      btn.disabled = true;
      btn.textContent = "Checking...";
      statusBox.textContent = "Waiting for confirmation...";

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

          try {
            await navigator.clipboard.writeText(data.key);
            statusBox.textContent = "Key copied. Paste it in Roblox.";
          } catch (e) {
            statusBox.textContent = "Key ready. Copy it manually.";
          }

          btn.textContent = "Copy Key";
          btn.disabled = false;
          btn.onclick = copyKey;
          return;
        }

        if (data.pending) {
          if (attempts < maxAttempts) {
            statusBox.textContent = "Waiting for LootLabs postback...";
            setTimeout(check, 2000);
            return;
          }

          statusBox.textContent = "Confirmation not found. Redirecting to LootLabs...";
          setTimeout(function () {
            window.location.href = "/continue";
          }, 1200);
          return;
        }

        statusBox.textContent = data.message || "Failed to get key.";
        btn.textContent = "Try Again";
        btn.disabled = false;
        btn.onclick = check;
      } catch (e) {
        statusBox.textContent = "Request failed.";
        btn.textContent = "Try Again";
        btn.disabled = false;
        btn.onclick = check;
      }
    }

    btn.onclick = check;
    setTimeout(check, 500);
  </script>
</body>
</html>`);
});

app.get("/site-claim", strictLimiter, async (req, res) => {
  try {
    const result = await getSessionByCookies(req);

    const sid = result.sid;
    const uid = result.uid;
    const session = result.session;

    if (!sid || !uid || !session) {
      return res.json({
        ok: false,
        message: "Open Get Key from Roblox first.",
      });
    }

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
        message: "Waiting for LootLabs confirmation.",
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
  try {
    if (req.params.secret !== POSTBACK_SECRET) {
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

    if (!sid) {
      return jsonError(res, 400, "Missing or bad click_id");
    }

    if (!uniqueId || uniqueId.length > 200) {
      return jsonError(res, 400, "Missing unique_id");
    }

    const { data: duplicate, error: duplicateError } = await supabase
      .from("postbacks")
      .select("id")
      .eq("unique_id", uniqueId)
      .maybeSingle();

    if (duplicateError) {
      console.error("DUPLICATE_CHECK_ERROR", duplicateError);
      return jsonError(res, 500, "Database error");
    }

    if (duplicate) {
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
      console.error("SESSION_READ_ERROR", sessionError);
      return jsonError(res, 500, "Database error");
    }

    if (!session) {
      return jsonError(res, 404, "Session not found");
    }

    if (new Date(session.expires_at) <= now()) {
      return jsonError(res, 410, "Session expired");
    }

    const createdAt = now();

    const { error: postbackInsertError } = await supabase.from("postbacks").insert({
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
        return res.json({
          ok: true,
          duplicate: true,
        });
      }

      console.error("POSTBACK_INSERT_ERROR", postbackInsertError);
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
      console.error("SESSION_UPDATE_ERROR", updateError);
      return jsonError(res, 500, "Database error");
    }

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
      console.error("VERIFY_READ_ERROR", error);
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
    const result = await getSessionByCookies(req);

    if (!result.sid || !result.uid) {
      return res.json({
        ok: false,
        message: "No session cookies",
        rawCookieHeader: req.headers.cookie || null,
      });
    }

    return res.json({
      ok: true,
      cookieSid: result.sid,
      cookieUid: result.uid,
      session: result.session,
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
