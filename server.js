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

const KEY_TTL_HOURS = Number(process.env.KEY_TTL_HOURS || 6);
const SESSION_TTL_MINUTES = Number(
  process.env.SESSION_TTL_MINUTES || 60
);
const PUBLIC_ORIGIN = String(
  process.env.PUBLIC_ORIGIN || "https://nhhub.top"
).replace(/\/+$/, "");

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

const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  }
);

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
  return crypto
    .createHash("sha256")
    .update(String(text))
    .digest("hex");
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
  return Array.isArray(value) ? value[0] : value;
}

function randomChars(length) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.randomBytes(length);

  let output = "";

  for (let i = 0; i < length; i++) {
    output += alphabet[bytes[i] % alphabet.length];
  }

  return output;
}

function makeKey() {
  const raw = randomChars(24);
  return "NL-" + raw.match(/.{1,4}/g).join("-");
}

function makeLootlabsUrl(sid) {
  const base = String(LOOTLABS_BASE_URL).trim();

  if (base.includes("puid=")) {
    throw new Error(
      "LOOTLABS_BASE_URL must not contain puid="
    );
  }

  const joiner = base.includes("?") ? "&" : "?";

  return (
    base +
    joiner +
    "puid=" +
    encodeURIComponent(sid)
  );
}

function clientIp(req) {
  return (
    req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"]
      ?.split(",")[0]
      ?.trim() ||
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

    if (index === -1) {
      return;
    }

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
  const maxAge = Math.max(
    SESSION_TTL_MINUTES * 60,
    Math.ceil(KEY_TTL_HOURS * 60 * 60)
  );

  res.setHeader("Set-Cookie", [
    `ks_sid=${encodeURIComponent(
      sid
    )}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`,
    `ks_uid=${encodeURIComponent(
      uid
    )}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`,
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

const siteCss = `
:root {
  color-scheme: dark;
  --bg: #050506;
  --card: rgba(17, 17, 20, .82);
  --soft: rgba(255, 255, 255, .045);
  --line: rgba(255, 255, 255, .1);
  --text: #f8f8fa;
  --muted: #9696a1;
  --green: #91efb5;
  --red: #ff9da8;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  min-height: 100svh;
  color: var(--text);
  background:
    radial-gradient(
      circle at 16% 8%,
      rgba(255, 255, 255, .08),
      transparent 28rem
    ),
    radial-gradient(
      circle at 86% 90%,
      rgba(110, 110, 130, .1),
      transparent 30rem
    ),
    var(--bg);
  font-family:
    Inter,
    ui-sans-serif,
    -apple-system,
    BlinkMacSystemFont,
    "Segoe UI",
    sans-serif;
  -webkit-font-smoothing: antialiased;
}

body::before {
  content: "";
  position: fixed;
  inset: 0;
  pointer-events: none;
  opacity: .28;
  background-image:
    linear-gradient(
      rgba(255, 255, 255, .018) 1px,
      transparent 1px
    ),
    linear-gradient(
      90deg,
      rgba(255, 255, 255, .018) 1px,
      transparent 1px
    );
  background-size: 42px 42px;
  mask-image: linear-gradient(#000, transparent 86%);
}

.page {
  position: relative;
  z-index: 1;
  width: min(100%, 620px);
  min-height: 100vh;
  min-height: 100svh;
  margin: auto;
  padding: 28px 20px 22px;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.brand {
  display: flex;
  align-items: center;
  gap: 11px;
  margin-bottom: 44px;
}

.logo {
  width: 38px;
  height: 38px;
  display: grid;
  place-items: center;
  border: 1px solid rgba(255, 255, 255, .15);
  border-radius: 12px;
  background: rgba(255, 255, 255, .055);
  font-size: 13px;
  font-weight: 800;
}

.brand-copy {
  display: grid;
  gap: 2px;
}

.brand-copy strong {
  font-size: 14px;
}

.brand-copy span {
  color: var(--muted);
  font-size: 11px;
}

.online {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 7px;
  color: #bdbdc5;
  font-size: 11px;
  font-weight: 650;
}

.online::before {
  content: "";
  width: 6px;
  height: 6px;
  border-radius: 99px;
  background: var(--green);
  box-shadow: 0 0 0 4px rgba(145, 239, 181, .08);
}

.eyebrow {
  margin-bottom: 14px;
  color: #b7b7c0;
  font-size: 11px;
  font-weight: 750;
  letter-spacing: .13em;
  text-transform: uppercase;
}

.eyebrow span {
  margin-right: 8px;
  color: #696972;
}

h1 {
  margin: 0;
  max-width: 540px;
  font-size: clamp(34px, 8vw, 56px);
  font-weight: 760;
  line-height: .99;
  letter-spacing: -.052em;
}

.lead {
  max-width: 510px;
  margin: 18px 0 0;
  color: var(--muted);
  font-size: 15px;
  line-height: 1.65;
}

.card {
  margin-top: 30px;
  padding: 20px;
  border: 1px solid var(--line);
  border-radius: 24px;
  background: var(--card);
  box-shadow:
    0 28px 80px rgba(0, 0, 0, .36),
    inset 0 1px 0 rgba(255, 255, 255, .04);
  backdrop-filter: blur(22px);
}

.account {
  padding: 15px 16px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  border: 1px solid var(--line);
  border-radius: 16px;
  background: var(--soft);
}

.account span,
.label {
  color: var(--muted);
  font-size: 11px;
}

.account strong,
.key,
.timer {
  font-family: "SFMono-Regular", Consolas, monospace;
}

.account strong {
  font-size: 12px;
}

.method-title {
  margin: 20px 2px 10px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  color: var(--muted);
  font-size: 11px;
}

.method-title span:last-child {
  color: #666670;
}

.method {
  position: relative;
  padding: 14px;
  display: grid;
  grid-template-columns: 42px 1fr 20px;
  align-items: center;
  gap: 12px;
  border: 1px solid rgba(255, 255, 255, .16);
  border-radius: 16px;
  background: rgba(255, 255, 255, .055);
  cursor: pointer;
  transition:
    border-color .16s ease,
    background .16s ease,
    transform .16s ease;
}

.method:hover {
  transform: translateY(-1px);
  border-color: rgba(255, 255, 255, .24);
  background: rgba(255, 255, 255, .07);
}

.method-input {
  position: absolute;
  opacity: 0;
  pointer-events: none;
}

.method-icon {
  width: 42px;
  height: 42px;
  display: grid;
  place-items: center;
  border-radius: 12px;
  background: #f4f4f5;
  color: #0a0a0b;
  font-size: 10px;
  font-weight: 850;
}

.method-copy {
  display: grid;
  gap: 4px;
}

.method-copy strong {
  font-size: 13px;
}

.method-copy span {
  color: var(--muted);
  font-size: 11px;
}

.method-check {
  width: 19px;
  height: 19px;
  display: grid;
  place-items: center;
  border: 1px solid rgba(255, 255, 255, .35);
  border-radius: 99px;
}

.method-check::after {
  content: "";
  width: 9px;
  height: 9px;
  border-radius: 99px;
  background: #fff;
  box-shadow: 0 0 0 3px rgba(255, 255, 255, .06);
}

.method + .button,
.method ~ .button {
  margin-top: 16px;
}

.steps {
  margin: 20px 0;
  display: grid;
  gap: 12px;
}

.step {
  display: grid;
  grid-template-columns: 28px 1fr;
  align-items: center;
  gap: 11px;
  color: #d0d0d5;
  font-size: 13px;
}

.step i {
  width: 28px;
  height: 28px;
  display: grid;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 9px;
  background: rgba(255, 255, 255, .025);
  color: var(--muted);
  font-style: normal;
  font-size: 10px;
  font-weight: 800;
}

.button {
  width: 100%;
  min-height: 52px;
  border: 1px solid #fff;
  border-radius: 15px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 9px;
  background: #fff;
  color: #09090a;
  font: inherit;
  font-size: 13px;
  font-weight: 760;
  text-decoration: none;
  cursor: pointer;
  transition:
    transform .16s ease,
    background .16s ease,
    opacity .16s ease;
}

.button:hover {
  transform: translateY(-1px);
  background: #ececef;
}

.button:active {
  transform: scale(.99);
}

.button:disabled {
  opacity: .48;
  cursor: not-allowed;
  transform: none;
}

.button.secondary {
  margin-top: 10px;
  border-color: var(--line);
  background: var(--soft);
  color: #dddde2;
}

.micro,
.status {
  margin: 12px 0 0;
  color: #70707a;
  text-align: center;
  font-size: 11px;
  line-height: 1.5;
}

.status.good {
  color: var(--green);
}

.status.bad {
  color: var(--red);
}

.loader-wrap {
  min-height: 168px;
  display: grid;
  place-items: center;
  text-align: center;
}

.loader {
  width: 34px;
  height: 34px;
  margin: 0 auto 17px;
  border: 2px solid rgba(255, 255, 255, .1);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin .85s linear infinite;
}

.loader-wrap strong {
  display: block;
  margin-bottom: 7px;
  font-size: 14px;
}

.loader-wrap p {
  margin: 0;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.55;
}

.key {
  margin-top: 10px;
  padding: 17px 14px;
  border: 1px solid var(--line);
  border-radius: 15px;
  background: #09090b;
  color: #fff;
  text-align: center;
  font-size: clamp(12px, 3.6vw, 15px);
  font-weight: 700;
  line-height: 1.5;
  word-break: break-all;
  user-select: all;
}

.timer-row {
  margin-top: 20px;
  display: flex;
  align-items: end;
  justify-content: space-between;
}

.timer {
  font-size: 20px;
  font-weight: 720;
}

.progress {
  height: 5px;
  margin: 11px 0 20px;
  overflow: hidden;
  border-radius: 99px;
  background: rgba(255, 255, 255, .07);
}

.progress span {
  display: block;
  width: 100%;
  height: 100%;
  border-radius: inherit;
  background: #fff;
  transition: width 1s linear;
}

.hidden {
  display: none !important;
}

footer {
  margin-top: 28px;
  color: #5f5f68;
  text-align: center;
  font-size: 10px;
  letter-spacing: .08em;
  text-transform: uppercase;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 520px) {
  .page {
    padding: 20px 16px 18px;
  }

  .brand {
    margin-bottom: 34px;
  }

  .card {
    padding: 16px;
    border-radius: 21px;
  }
}
`;

function brand() {
  return `
    <header class="brand">
      <div class="logo">NH</div>

      <div class="brand-copy">
        <strong>Nameless Hub</strong>
        <span>Secure key delivery</span>
      </div>

      <div class="online">Online</div>
    </header>
  `;
}

function page(title, description, content, script = "") {
  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta
          name="viewport"
          content="width=device-width,initial-scale=1,viewport-fit=cover"
        >
        <meta name="theme-color" content="#050506">
        <meta name="description" content="${description}">
        <meta property="og:title" content="${title}">
        <meta
          property="og:url"
          content="${PUBLIC_ORIGIN}/get-key"
        >

        <title>${title}</title>

        <style>${siteCss}</style>
      </head>

      <body>
        ${content}
        ${script ? `<script>${script}</script>` : ""}
      </body>
    </html>
  `;
}

function getKeyPage(uid) {
  const safeUid = normalizeUid(uid);

  const body = safeUid
    ? `
      <main class="page">
        ${brand()}

        <div class="eyebrow">
          <span>01</span>
          Key access
        </div>

        <h1>Get Key</h1>

        <p class="lead">
          Choose a method below. Your generated key will be
          linked to your Roblox account and remain active for
          ${KEY_TTL_HOURS} hours.
        </p>

        <section class="card">
          <div class="account">
            <span>Roblox account</span>
            <strong>ID ${safeUid}</strong>
          </div>

          <form action="/start" method="get">
            <input
              type="hidden"
              name="uid"
              value="${safeUid}"
            >

            <div class="method-title">
              <span>Available methods</span>
              <span>1 available</span>
            </div>

            <label class="method">
              <input
                class="method-input"
                type="radio"
                name="method"
                value="lootlabs"
                checked
              >

              <span class="method-icon">LL</span>

              <span class="method-copy">
                <strong>LootLabs</strong>
                <span>
                  Complete a short checkpoint · ~2 min
                </span>
              </span>

              <span class="method-check"></span>
            </label>

            <button class="button" type="submit">
              Continue with LootLabs
              <span>→</span>
            </button>
          </form>

          <p class="micro">
            After completion, you will return here to receive
            your key.
          </p>
        </section>

        <footer>
          nhhub.top · protected access
        </footer>
      </main>
    `
    : `
      <main class="page">
        ${brand()}

        <div class="eyebrow">
          <span>01</span>
          Access request
        </div>

        <h1>Open this page from Nameless Hub.</h1>

        <p class="lead">
          Press Get Key inside the script. It creates a secure
          link connected to your Roblox account.
        </p>

        <section class="card">
          <div class="account">
            <span>Account link</span>
            <strong>Not detected</strong>
          </div>

          <div class="steps">
            <div class="step">
              <i>01</i>
              <span>
                Return to the Nameless Hub key screen
              </span>
            </div>

            <div class="step">
              <i>02</i>
              <span>
                Press Get Key and open the copied link
              </span>
            </div>
          </div>

          <button class="button" disabled>
            Waiting for account link
          </button>
        </section>

        <footer>
          nhhub.top · protected access
        </footer>
      </main>
    `;

  return page(
    "Get Key · Nameless Hub",
    "Secure Nameless Hub key delivery.",
    body
  );
}

function errorPage(title, message, uid) {
  const safeUid = normalizeUid(uid);

  const href = safeUid
    ? `/get-key?uid=${encodeURIComponent(safeUid)}`
    : "/get-key";

  return page(
    `${title} · Nameless Hub`,
    message,
    `
      <main class="page">
        ${brand()}

        <div class="eyebrow">
          <span>!</span>
          Request stopped
        </div>

        <h1>${title}</h1>
        <p class="lead">${message}</p>

        <section class="card">
          <a class="button" href="${href}">
            Try again
            <span>→</span>
          </a>
        </section>
      </main>
    `
  );
}

function isOldRenderHost(req) {
  const host = String(
    req.hostname ||
    req.headers.host ||
    ""
  )
    .split(":")[0]
    .trim()
    .toLowerCase();

  return host.endsWith(".onrender.com");
}

function redirectToPublicOrigin(req, res) {
  let path = String(
    req.originalUrl ||
    req.url ||
    "/"
  );

  if (!path.startsWith("/")) {
    path = "/";
  }

  return res.redirect(
    302,
    `${PUBLIC_ORIGIN}${path}`
  );
}

app.get("/", (req, res) => {
  const originalUrl = String(
    req.originalUrl ||
    req.url ||
    "/"
  );

  const queryIndex = originalUrl.indexOf("?");

  const getKeyPath =
    "/get-key" +
    (
      queryIndex >= 0
        ? originalUrl.slice(queryIndex)
        : ""
    );

  if (isOldRenderHost(req)) {
    return res.redirect(
      302,
      `${PUBLIC_ORIGIN}${getKeyPath}`
    );
  }

  return res.redirect(302, getKeyPath);
});

app.get("/ping", (req, res) => {
  return res.status(200).json({
    ok: true,
    status: "alive",
    time: new Date().toISOString(),
  });
});

app.get("/health", (req, res) => {
  return res.status(200).send("OK");
});

function wantsLegacyKeyFlow(req) {
  const mode = String(
    req.query.mode || ""
  )
    .trim()
    .toLowerCase();

  const direct = String(
    req.query.direct || ""
  )
    .trim()
    .toLowerCase();

  const legacy = String(
    req.query.legacy || ""
  )
    .trim()
    .toLowerCase();

  return (
    mode === "legacy" ||
    mode === "direct" ||
    direct === "1" ||
    direct === "true" ||
    legacy === "1" ||
    legacy === "true"
  );
}

app.get(
  "/get-key",
  strictLimiter,
  (req, res) => {
    if (isOldRenderHost(req)) {
      return redirectToPublicOrigin(req, res);
    }

    if (wantsLegacyKeyFlow(req)) {
      return startKeyFlow(req, res);
    }

    res.setHeader("Cache-Control", "no-store");

    return res
      .type("html")
      .send(getKeyPage(req.query.uid));
  }
);

async function startKeyFlow(req, res) {
  try {
    const uid = normalizeUid(req.query.uid);

    const method = String(
      req.query.method || "lootlabs"
    )
      .trim()
      .toLowerCase();

    if (!uid) {
      return res
        .status(400)
        .type("html")
        .send(
          errorPage(
            "Account link is missing.",
            "Open the Get Key link from Nameless Hub."
          )
        );
    }

    if (method !== "lootlabs") {
      return res
        .status(400)
        .type("html")
        .send(
          errorPage(
            "Method is unavailable.",
            "Choose LootLabs on the Get Key page.",
            uid
          )
        );
    }

    const createdAt = now();

    const expiresAt = addMinutes(
      createdAt,
      SESSION_TTL_MINUTES
    );

    const sid = crypto.randomUUID();
    const lootlabsUrl = makeLootlabsUrl(sid);

    const { error } = await supabase
      .from("key_sessions")
      .insert({
        sid,
        uid,
        completed: false,
        claimed: false,
        created_at: createdAt.toISOString(),
        expires_at: expiresAt.toISOString(),
        start_ip: clientIp(req),
        start_user_agent: String(
          req.headers["user-agent"] || ""
        ).slice(0, 300),
      });

    if (error) {
      console.error(
        "GET_KEY_INSERT_ERROR",
        error
      );

      return res
        .status(500)
        .type("html")
        .send(
          errorPage(
            "Request could not start.",
            "The key service is temporarily unavailable.",
            uid
          )
        );
    }

    setKeyCookies(res, sid, uid);

    return res.redirect(lootlabsUrl);
  } catch (error) {
    console.error("GET_KEY_ERROR", error);

    return res
      .status(500)
      .type("html")
      .send(
        errorPage(
          "Request could not start.",
          "The key service is temporarily unavailable.",
          req.query.uid
        )
      );
  }
}

app.get(
  "/start",
  strictLimiter,
  startKeyFlow
);

app.get(
  "/get-key-direct",
  strictLimiter,
  startKeyFlow
);

app.get(
  "/legacy/get-key",
  strictLimiter,
  startKeyFlow
);

app.get(
  "/continue",
  strictLimiter,
  async (req, res) => {
    try {
      if (isOldRenderHost(req)) {
        return redirectToPublicOrigin(req, res);
      }

      const result =
        await getSessionByCookies(req);

      if (
        !result.sid ||
        !result.uid ||
        !result.session
      ) {
        return res
          .status(400)
          .type("html")
          .send(
            errorPage(
              "Session not found.",
              "Create a fresh key request from Nameless Hub."
            )
          );
      }

      if (
        result.session.claimed &&
        result.session.display_key &&
        result.session.key_expires_at &&
        new Date(
          result.session.key_expires_at
        ) > now()
      ) {
        return res.redirect("/complete");
      }

      if (
        new Date(
          result.session.expires_at
        ) <= now()
      ) {
        return res
          .status(410)
          .type("html")
          .send(
            errorPage(
              "Session expired.",
              "Create a fresh key request from Nameless Hub.",
              result.uid
            )
          );
      }

      if (result.session.completed) {
        return res.redirect("/complete");
      }

      return res.redirect(
        makeLootlabsUrl(result.sid)
      );
    } catch (error) {
      console.error(
        "CONTINUE_ERROR",
        error
      );

      return res
        .status(500)
        .type("html")
        .send(
          errorPage(
            "Request could not continue.",
            "The key service is temporarily unavailable."
          )
        );
    }
  }
);

app.get("/complete", (req, res) => {
  if (isOldRenderHost(req)) {
    return redirectToPublicOrigin(req, res);
  }

  const cookies = parseCookies(req);

  const uid =
    normalizeUid(cookies.ks_uid) || "";

  const fallbackSeconds = Math.max(
    1,
    Math.round(KEY_TTL_HOURS * 3600)
  );

  const content = `
    <main class="page">
      ${brand()}

      <div class="eyebrow">
        <span>02</span>
        Key delivery
      </div>

      <h1 id="title">
        Your key is almost ready.
      </h1>

      <p id="lead" class="lead">
        Keep this page open while the confirmation
        is processed.
      </p>

      <section id="loading" class="card">
        <div class="loader-wrap">
          <div>
            <div class="loader"></div>

            <strong>
              Confirming completion
            </strong>

            <p>
              This normally takes only a few seconds.
            </p>
          </div>
        </div>
      </section>

      <section
        id="result"
        class="card hidden"
      >
        <div class="label">
          Your access key
        </div>

        <div id="key" class="key"></div>

        <div class="timer-row">
          <span class="label">
            Time remaining
          </span>

          <strong id="timer" class="timer">
            --:--:--
          </strong>
        </div>

        <div class="progress">
          <span id="bar"></span>
        </div>

        <button
          id="copy"
          class="button"
          type="button"
        >
          Copy key
        </button>

        <div
          id="status"
          class="status"
        ></div>
      </section>

      <section
        id="error"
        class="card hidden"
      >
        <div class="loader-wrap">
          <div>
            <strong>Key not ready</strong>
            <p id="errorText"></p>
          </div>
        </div>

        <a
          id="retry"
          class="button"
          href="/continue"
        >
          Try again
        </a>
      </section>

      <footer>
        nhhub.top · protected access
      </footer>
    </main>
  `;

  const script = `
    const loading =
      document.getElementById("loading");

    const result =
      document.getElementById("result");

    const errorBox =
      document.getElementById("error");

    const title =
      document.getElementById("title");

    const lead =
      document.getElementById("lead");

    const keyBox =
      document.getElementById("key");

    const timer =
      document.getElementById("timer");

    const bar =
      document.getElementById("bar");

    const copy =
      document.getElementById("copy");

    const status =
      document.getElementById("status");

    const errorText =
      document.getElementById("errorText");

    const retry =
      document.getElementById("retry");

    const uid = ${JSON.stringify(uid)};
    const fallback = ${fallbackSeconds};

    let currentKey = "";
    let expiresAt = 0;
    let total = fallback;
    let attempts = 0;
    let timerHandle = null;

    function format(value) {
      value = Math.max(
        0,
        Math.floor(value)
      );

      const hours =
        Math.floor(value / 3600);

      const minutes =
        Math.floor((value % 3600) / 60);

      const seconds =
        value % 60;

      return [
        hours,
        minutes,
        seconds
      ]
        .map(function (part) {
          return String(part).padStart(2, "0");
        })
        .join(":");
    }

    function setStatus(text, state) {
      status.textContent = text || "";

      status.className =
        "status" +
        (state ? " " + state : "");
    }

    function fail(message, canContinue) {
      loading.classList.add("hidden");
      result.classList.add("hidden");
      errorBox.classList.remove("hidden");

      title.textContent =
        "Key delivery paused.";

      lead.textContent =
        "Use the action below to finish or restart your request.";

      errorText.textContent =
        message ||
        "Unable to deliver the key.";

      retry.href = canContinue
        ? "/continue"
        : uid
          ? "/get-key?uid=" +
            encodeURIComponent(uid)
          : "/get-key";

      retry.textContent = canContinue
        ? "Return to checkpoint"
        : "Create a new request";
    }

    function tick() {
      const left = Math.max(
        0,
        Math.ceil(
          (expiresAt - Date.now()) / 1000
        )
      );

      timer.textContent = format(left);

      bar.style.width =
        Math.max(
          0,
          Math.min(
            100,
            (left / total) * 100
          )
        ) + "%";

      if (left <= 0) {
        clearInterval(timerHandle);

        copy.disabled = true;
        copy.textContent = "Key expired";

        setStatus(
          "Create a new key to continue.",
          "bad"
        );
      }
    }

    function ready(data) {
      currentKey = String(data.key || "");
      expiresAt = Date.parse(
        data.expiresAt || ""
      );

      if (
        !currentKey ||
        !Number.isFinite(expiresAt)
      ) {
        fail(
          "The server returned an incomplete key.",
          false
        );

        return;
      }

      const hours =
        Number(data.expiresInHours);

      total =
        Number.isFinite(hours) &&
        hours > 0
          ? Math.max(
              1,
              Math.round(hours * 3600)
            )
          : Math.max(
              1,
              Math.ceil(
                (expiresAt - Date.now()) / 1000
              )
            );

      keyBox.textContent = currentKey;

      loading.classList.add("hidden");
      errorBox.classList.add("hidden");
      result.classList.remove("hidden");

      title.textContent =
        "Your key is ready.";

      lead.textContent =
        "Copy it below and paste it into Nameless Hub.";

      setStatus(
        "Key ready. Copy it and return to Roblox.",
        "good"
      );

      tick();

      timerHandle =
        setInterval(tick, 1000);
    }

    async function copyKey() {
      if (!currentKey) {
        return;
      }

      try {
        if (
          navigator.clipboard &&
          window.isSecureContext
        ) {
          await navigator.clipboard.writeText(
            currentKey
          );
        } else {
          const field =
            document.createElement("textarea");

          field.value = currentKey;
          field.style.position = "fixed";
          field.style.opacity = "0";

          document.body.appendChild(field);

          field.select();
          document.execCommand("copy");
          field.remove();
        }

        copy.textContent = "Copied";

        setStatus(
          "Copied. Paste the key in Nameless Hub.",
          "good"
        );

        setTimeout(function () {
          if (!copy.disabled) {
            copy.textContent = "Copy key";
          }
        }, 1500);
      } catch {
        setStatus(
          "Select the key and copy it manually.",
          "bad"
        );
      }
    }

    async function claim() {
      attempts += 1;

      try {
        const response = await fetch(
          "/site-claim",
          {
            credentials: "include",
            cache: "no-store"
          }
        );

        const data =
          await response.json();

        if (data.ok && data.key) {
          ready(data);
          return;
        }

        if (
          data.pending &&
          attempts < 16
        ) {
          setTimeout(claim, 1500);
          return;
        }

        if (data.pending) {
          fail(
            "Confirmation is taking longer than expected.",
            true
          );

          return;
        }

        fail(
          data.message ||
          "Unable to deliver the key.",
          false
        );
      } catch {
        if (attempts < 4) {
          setTimeout(claim, 1800);
          return;
        }

        fail(
          "The server could not be reached.",
          false
        );
      }
    }

    copy.addEventListener(
      "click",
      copyKey
    );

    setTimeout(claim, 450);
  `;

  res.setHeader(
    "Cache-Control",
    "no-store"
  );

  return res
    .type("html")
    .send(
      page(
        "Your Key · Nameless Hub",
        "Your generated Nameless Hub access key.",
        content,
        script
      )
    );
});

app.get(
  "/site-claim",
  strictLimiter,
  async (req, res) => {
    try {
      res.setHeader(
        "Cache-Control",
        "no-store"
      );

      const result =
        await getSessionByCookies(req);

      const sid = result.sid;
      const uid = result.uid;
      const session = result.session;

      if (!sid || !uid || !session) {
        return res.json({
          ok: false,
          message:
            "Open Get Key from Roblox first.",
        });
      }

      if (
        session.claimed &&
        session.display_key
      ) {
        const keyExpiresAt =
          new Date(session.key_expires_at);

        if (
          !session.key_expires_at ||
          keyExpiresAt <= now()
        ) {
          return res.json({
            ok: false,
            message:
              "Key expired. Create a new request.",
          });
        }

        return res.json({
          ok: true,
          key: session.display_key,
          issuedAt:
            session.key_created_at,
          expiresAt:
            session.key_expires_at,
          expiresInHours:
            KEY_TTL_HOURS,
        });
      }

      if (
        session.claimed &&
        !session.display_key
      ) {
        return res.json({
          ok: false,
          message:
            "Key already claimed. Create a new request.",
        });
      }

      if (
        new Date(session.expires_at) <=
        now()
      ) {
        return res.json({
          ok: false,
          message:
            "Session expired. Create a new request.",
        });
      }

      if (!session.completed) {
        return res.json({
          ok: false,
          pending: true,
          message:
            "Waiting for checkpoint confirmation.",
        });
      }

      const key = makeKey();
      const keyHash = hashKey(key);
      const keyCreatedAt = now();

      const keyExpiresAt = addHours(
        keyCreatedAt,
        KEY_TTL_HOURS
      );

      const {
        error: keyInsertError,
      } = await supabase
        .from("keys")
        .insert({
          key_hash: keyHash,
          uid,
          sid,
          active: true,
          created_at:
            keyCreatedAt.toISOString(),
          expires_at:
            keyExpiresAt.toISOString(),
          used_count: 0,
        });

      if (keyInsertError) {
        console.error(
          "SITE_CLAIM_KEY_INSERT_ERROR",
          keyInsertError
        );

        return jsonError(
          res,
          500,
          "Failed to create key"
        );
      }

      const {
        error: updateError,
      } = await supabase
        .from("key_sessions")
        .update({
          claimed: true,
          claimed_at:
            keyCreatedAt.toISOString(),
          key_hash: keyHash,
          key_created_at:
            keyCreatedAt.toISOString(),
          key_expires_at:
            keyExpiresAt.toISOString(),
          display_key: key,
        })
        .eq("sid", sid)
        .eq("uid", uid);

      if (updateError) {
        console.error(
          "SITE_CLAIM_UPDATE_ERROR",
          updateError
        );

        return jsonError(
          res,
          500,
          "Failed to save key"
        );
      }

      return res.json({
        ok: true,
        key,
        issuedAt:
          keyCreatedAt.toISOString(),
        expiresInHours:
          KEY_TTL_HOURS,
        expiresAt:
          keyExpiresAt.toISOString(),
      });
    } catch (error) {
      console.error(
        "SITE_CLAIM_ERROR",
        error
      );

      return jsonError(
        res,
        500,
        "Server error"
      );
    }
  }
);

app.get(
  "/lootlabs/postback/:secret",
  async (req, res) => {
    try {
      if (
        req.params.secret !==
        POSTBACK_SECRET
      ) {
        return jsonError(
          res,
          403,
          "Forbidden"
        );
      }

      const rawSid =
        firstQueryValue(
          req.query.click_id
        ) ||
        firstQueryValue(
          req.query.puid
        ) ||
        firstQueryValue(
          req.query.sid
        );

      const rawUniqueId =
        firstQueryValue(
          req.query.unique_id
        ) ||
        firstQueryValue(
          req.query.uniqueid
        ) ||
        "";

      const rawIp =
        firstQueryValue(req.query.ip) ||
        "";

      const sid = normalizeSid(rawSid);

      const uniqueId =
        String(rawUniqueId).trim();

      const lootlabsIp =
        String(rawIp).trim();

      if (!sid) {
        return jsonError(
          res,
          400,
          "Missing or bad click_id"
        );
      }

      if (
        !uniqueId ||
        uniqueId.length > 200
      ) {
        return jsonError(
          res,
          400,
          "Missing unique_id"
        );
      }

      const {
        data: duplicate,
        error: duplicateError,
      } = await supabase
        .from("postbacks")
        .select("id")
        .eq("unique_id", uniqueId)
        .maybeSingle();

      if (duplicateError) {
        console.error(
          "DUPLICATE_CHECK_ERROR",
          duplicateError
        );

        return jsonError(
          res,
          500,
          "Database error"
        );
      }

      if (duplicate) {
        return res.json({
          ok: true,
          duplicate: true,
        });
      }

      const {
        data: session,
        error: sessionError,
      } = await supabase
        .from("key_sessions")
        .select("*")
        .eq("sid", sid)
        .maybeSingle();

      if (sessionError) {
        console.error(
          "SESSION_READ_ERROR",
          sessionError
        );

        return jsonError(
          res,
          500,
          "Database error"
        );
      }

      if (!session) {
        return jsonError(
          res,
          404,
          "Session not found"
        );
      }

      if (
        new Date(session.expires_at) <=
        now()
      ) {
        return jsonError(
          res,
          410,
          "Session expired"
        );
      }

      const createdAt = now();

      const {
        error: postbackInsertError,
      } = await supabase
        .from("postbacks")
        .insert({
          unique_id: uniqueId,
          sid,
          uid: session.uid,
          lootlabs_ip: lootlabsIp,
          request_ip: clientIp(req),
          query: req.query,
          created_at:
            createdAt.toISOString(),
        });

      if (postbackInsertError) {
        if (
          postbackInsertError.code ===
          "23505"
        ) {
          return res.json({
            ok: true,
            duplicate: true,
          });
        }

        console.error(
          "POSTBACK_INSERT_ERROR",
          postbackInsertError
        );

        return jsonError(
          res,
          500,
          "Database error"
        );
      }

      const {
        error: updateError,
      } = await supabase
        .from("key_sessions")
        .update({
          completed: true,
          completed_at:
            createdAt.toISOString(),
          lootlabs_ip: lootlabsIp,
          lootlabs_unique_id:
            uniqueId,
        })
        .eq("sid", sid);

      if (updateError) {
        console.error(
          "SESSION_UPDATE_ERROR",
          updateError
        );

        return jsonError(
          res,
          500,
          "Database error"
        );
      }

      return res.json({
        ok: true,
      });
    } catch (error) {
      console.error(
        "POSTBACK_ERROR",
        error
      );

      return jsonError(
        res,
        500,
        "Server error"
      );
    }
  }
);

app.get(
  "/verify",
  strictLimiter,
  async (req, res) => {
    try {
      const uid =
        normalizeUid(req.query.uid);

      const key =
        normalizeKey(req.query.key);

      if (!uid || !key) {
        return jsonError(
          res,
          400,
          "Bad uid or key"
        );
      }

      const keyHash = hashKey(key);

      const {
        data: keyDoc,
        error,
      } = await supabase
        .from("keys")
        .select("*")
        .eq("key_hash", keyHash)
        .maybeSingle();

      if (error) {
        console.error(
          "VERIFY_READ_ERROR",
          error
        );

        return jsonError(
          res,
          500,
          "Database error"
        );
      }

      if (
        !keyDoc ||
        !keyDoc.active
      ) {
        return res.json({
          ok: false,
          message: "Invalid key",
        });
      }

      if (keyDoc.uid !== uid) {
        return res.json({
          ok: false,
          message:
            "This key is linked to another Roblox account",
        });
      }

      const currentTime = now();

      const expiresAt =
        new Date(keyDoc.expires_at);

      if (expiresAt <= currentTime) {
        return res.json({
          ok: false,
          message: "Key expired",
        });
      }

      await supabase
        .from("keys")
        .update({
          used_count:
            Number(
              keyDoc.used_count || 0
            ) + 1,
          last_used_at:
            currentTime.toISOString(),
          last_ip: clientIp(req),
        })
        .eq("key_hash", keyHash);

      return res.json({
        ok: true,
        message: "Valid key",
        expiresAt:
          expiresAt.toISOString(),
        secondsLeft: Math.max(
          0,
          Math.floor(
            (
              expiresAt.getTime() -
              currentTime.getTime()
            ) / 1000
          )
        ),
      });
    } catch (error) {
      console.error(
        "VERIFY_ERROR",
        error
      );

      return jsonError(
        res,
        500,
        "Server error"
      );
    }
  }
);

app.get(
  "/session-debug",
  async (req, res) => {
    try {
      const result =
        await getSessionByCookies(req);

      if (!result.sid || !result.uid) {
        return res.json({
          ok: false,
          message: "No session cookies",
          rawCookieHeader:
            req.headers.cookie || null,
        });
      }

      return res.json({
        ok: true,
        cookieSid: result.sid,
        cookieUid: result.uid,
        session: result.session,
      });
    } catch (error) {
      return res.json({
        ok: false,
        message: "Server error",
        error: String(error),
      });
    }
  }
);

app.get(
  "/admin/stats",
  async (req, res) => {
    try {
      if (
        !ADMIN_SECRET ||
        req.query.secret !== ADMIN_SECRET
      ) {
        return jsonError(
          res,
          403,
          "Forbidden"
        );
      }

      const [
        sessionsResult,
        completedResult,
        keysResult,
        activeKeysResult,
        postbacksResult,
      ] = await Promise.all([
        supabase
          .from("key_sessions")
          .select("*", {
            count: "exact",
            head: true,
          }),

        supabase
          .from("key_sessions")
          .select("*", {
            count: "exact",
            head: true,
          })
          .eq("completed", true),

        supabase
          .from("keys")
          .select("*", {
            count: "exact",
            head: true,
          }),

        supabase
          .from("keys")
          .select("*", {
            count: "exact",
            head: true,
          })
          .eq("active", true)
          .gt(
            "expires_at",
            now().toISOString()
          ),

        supabase
          .from("postbacks")
          .select("*", {
            count: "exact",
            head: true,
          }),
      ]);

      return res.json({
        ok: true,
        sessions:
          sessionsResult.count || 0,
        completed:
          completedResult.count || 0,
        keys:
          keysResult.count || 0,
        activeKeys:
          activeKeysResult.count || 0,
        postbacks:
          postbacksResult.count || 0,
      });
    } catch (error) {
      console.error(
        "ADMIN_STATS_ERROR",
        error
      );

      return jsonError(
        res,
        500,
        "Server error"
      );
    }
  }
);

app.listen(PORT, () => {
  console.log(
    `Key system running on port ${PORT}`
  );
});
