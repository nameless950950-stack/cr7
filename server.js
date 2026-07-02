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
    endpoints: ["/start", "/claim", "/verify", "/complete"],
  });
});

app.get("/complete", (req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");

  res.end(`<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Completed</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #08080c;
      color: white;
      font-family: Arial, sans-serif;
    }

    .box {
      width: min(92vw, 520px);
      padding: 28px;
      border-radius: 20px;
      background: #111118;
      border: 1px solid #252532;
      box-shadow: 0 20px 70px rgba(0, 0, 0, .45);
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
    }

    code {
      background: #1e1e29;
      padding: 4px 8px;
      border-radius: 8px;
      color: white;
    }
  </style>
</head>
<body>
  <div class="box">
    <h1>Completed</h1>
    <p>Вернись в Roblox и нажми <code>Claim Key</code>.</p>
  </div>
</body>
</html>`);
});

app.get("/start", strictLimiter, async (req, res) => {
  try {
    const uid = normalizeUid(req.query.uid);

    if (!uid) {
      return jsonError(res, 400, "Bad uid");
    }

    const createdAt = now();
    const expiresAt = addMinutes(createdAt, SESSION_TTL_MINUTES);
    const sid = crypto.randomUUID();

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
      console.error("SUPABASE_START_ERROR", error);
      return jsonError(res, 500, "Database error");
    }

    return res.json({
      ok: true,
      sid,
      lootlabsUrl: makeLootlabsUrl(sid),
      expiresInMinutes: SESSION_TTL_MINUTES,
    });
  } catch (err) {
    console.error("START_ERROR", err);
    return jsonError(res, 500, "Server error");
  }
});

app.get("/lootlabs/postback/:secret", async (req, res) => {
  try {
    if (req.params.secret !== POSTBACK_SECRET) {
      return jsonError(res, 403, "Forbidden");
    }

    const sid = normalizeSid(req.query.click_id || req.query.puid || req.query.sid);
    const uniqueId = String(req.query.unique_id || req.query.uniqueid || "").trim();
    const lootlabsIp = String(req.query.ip || "").trim();

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
      console.error("SUPABASE_DUPLICATE_CHECK_ERROR", duplicateError);
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
      console.error("SUPABASE_SESSION_READ_ERROR", sessionError);
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

    return res.json({
      ok: true,
    });
  } catch (err) {
    console.error("POSTBACK_ERROR", err);
    return jsonError(res, 500, "Server error");
  }
});

app.get("/claim", strictLimiter, async (req, res) => {
  try {
    const sid = normalizeSid(req.query.sid);
    const uid = normalizeUid(req.query.uid);

    if (!sid || !uid) {
      return jsonError(res, 400, "Bad request");
    }

    const claimTime = now();

    const { data: updatedSessions, error: updateError } = await supabase
      .from("key_sessions")
      .update({
        claimed: true,
        claimed_at: claimTime.toISOString(),
      })
      .eq("sid", sid)
      .eq("uid", uid)
      .eq("completed", true)
      .eq("claimed", false)
      .gt("expires_at", claimTime.toISOString())
      .select("*");

    if (updateError) {
      console.error("SUPABASE_CLAIM_UPDATE_ERROR", updateError);
      return jsonError(res, 500, "Database error");
    }

    const session = updatedSessions && updatedSessions[0];

    if (!session) {
      const { data: existing, error: existingError } = await supabase
        .from("key_sessions")
        .select("*")
        .eq("sid", sid)
        .eq("uid", uid)
        .maybeSingle();

      if (existingError) {
        console.error("SUPABASE_CLAIM_EXISTING_ERROR", existingError);
        return jsonError(res, 500, "Database error");
      }

      if (!existing) {
        return jsonError(res, 404, "Session not found");
      }

      if (new Date(existing.expires_at) <= now()) {
        return jsonError(res, 410, "Session expired. Press Get Key again.");
      }

      if (!existing.completed) {
        return res.json({
          ok: false,
          pending: true,
          message: "Complete LootLabs first",
        });
      }

      if (existing.claimed) {
        return jsonError(
          res,
          409,
          "Key already claimed. Press Get Key again for a new key."
        );
      }

      return jsonError(res, 400, "Cannot claim key");
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
      console.error("SUPABASE_KEY_INSERT_ERROR", keyInsertError);

      await supabase
        .from("key_sessions")
        .update({
          claimed: false,
          claimed_at: null,
        })
        .eq("sid", sid)
        .eq("uid", uid);

      return jsonError(res, 500, "Failed to create key");
    }

    const { error: sessionKeyUpdateError } = await supabase
      .from("key_sessions")
      .update({
        key_hash: keyHash,
        key_created_at: keyCreatedAt.toISOString(),
        key_expires_at: keyExpiresAt.toISOString(),
      })
      .eq("sid", sid)
      .eq("uid", uid);

    if (sessionKeyUpdateError) {
      console.error("SUPABASE_SESSION_KEY_UPDATE_ERROR", sessionKeyUpdateError);
    }

    return res.json({
      ok: true,
      key,
      expiresInHours: KEY_TTL_HOURS,
      expiresAt: keyExpiresAt.toISOString(),
    });
  } catch (err) {
    console.error("CLAIM_ERROR", err);
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
