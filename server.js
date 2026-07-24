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
  --card: #0b0b0d;
  --soft: #121214;
  --line: rgba(255, 255, 255, .12);
  --line-strong: rgba(255, 255, 255, .32);
  --text: #f5f5f7;
  --muted: #85858f;
  --green: #8fe3ae;
  --red: #ff929e;
  --blob-a: rgba(255, 255, 255, .5);
  --blob-b: rgba(255, 60, 75, .4);
  --blob-c: rgba(255, 146, 158, .38);
  --blob-d: rgba(255, 255, 255, .32);
}

* {
  box-sizing: border-box;
}

html {
  background: var(--bg);
}

body {
  position: relative;
  margin: 0;
  min-height: 100vh;
  min-height: 100svh;
  overflow-x: hidden;
  color: var(--text);
  background: var(--bg);
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
  z-index: 1;
  opacity: .05;
  mix-blend-mode: overlay;
  pointer-events: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='140' height='140'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='2' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
}

.lava-bg {
  position: fixed;
  inset: 0;
  z-index: 0;
  overflow: hidden;
  pointer-events: none;
}

.lava-bg span {
  position: absolute;
  border-radius: 50%;
  filter: blur(70px);
  will-change: transform;
}

.lava-bg .b1 {
  left: 8%;
  top: 8%;
  width: 46vmax;
  height: 46vmax;
  background: var(--blob-a);
  animation: drift-1 10s ease-in-out infinite alternate;
}

.lava-bg .b2 {
  right: 4%;
  top: 32%;
  width: 34vmax;
  height: 34vmax;
  background: var(--blob-b);
  animation: drift-2 13s ease-in-out infinite alternate;
}

.lava-bg .b3 {
  left: 18%;
  bottom: 4%;
  width: 38vmax;
  height: 38vmax;
  background: var(--blob-c);
  animation: drift-3 9s ease-in-out infinite alternate;
}

.lava-bg .b4 {
  right: 18%;
  bottom: -10%;
  width: 30vmax;
  height: 30vmax;
  background: var(--blob-d);
  animation: drift-4 15s ease-in-out infinite alternate;
}

.lava-bg::after {
  content: "";
  position: absolute;
  inset: 0;
  background: radial-gradient(
    circle at 50% 40%,
    transparent 0%,
    var(--bg) 88%
  );
}

@keyframes drift-1 {
  0% { transform: translate3d(0, 0, 0) scale(1); }
  100% { transform: translate3d(10vmax, 14vmax, 0) scale(1.15); }
}

@keyframes drift-2 {
  0% { transform: translate3d(0, 0, 0) scale(1); }
  100% { transform: translate3d(-12vmax, 10vmax, 0) scale(.9); }
}

@keyframes drift-3 {
  0% { transform: translate3d(0, 0, 0) scale(1); }
  100% { transform: translate3d(9vmax, -12vmax, 0) scale(1.1); }
}

@keyframes drift-4 {
  0% { transform: translate3d(0, 0, 0) scale(1); }
  100% { transform: translate3d(-8vmax, -9vmax, 0) scale(1.2); }
}

@media (prefers-reduced-motion: reduce) {
  .lava-bg span {
    animation: none !important;
  }
}

button,
a {
  -webkit-tap-highlight-color: transparent;
}

.page {
  position: relative;
  z-index: 1;
  width: min(100%, 500px);
  min-height: 100vh;
  min-height: 100svh;
  margin: auto;
  padding: 28px 18px;
  display: flex;
  flex-direction: column;
  justify-content: center;
}

.brand {
  margin-bottom: 42px;
  display: flex;
  align-items: center;
  gap: 10px;
}

.brand-mark {
  width: 11px;
  height: 11px;
  border: 2px solid #fff;
  border-radius: 3px;
  transform: rotate(45deg);
  filter: drop-shadow(0 0 8px rgba(255, 70, 85, .6));
  animation: mark-pulse 3.2s ease-in-out infinite;
}

@keyframes mark-pulse {
  0%, 100% {
    filter: drop-shadow(0 0 6px rgba(255, 70, 85, .45));
    transform: rotate(45deg) scale(1);
  }
  50% {
    filter: drop-shadow(0 0 13px rgba(255, 70, 85, .85));
    transform: rotate(45deg) scale(1.12);
  }
}

.brand strong {
  font-size: 12px;
  font-weight: 700;
  letter-spacing: .14em;
  text-transform: uppercase;
}

h1 {
  margin: 0;
  background: linear-gradient(135deg, #ffffff 45%, #ff8a95 120%);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
  font-size: clamp(32px, 8.5vw, 44px);
  font-weight: 760;
  line-height: 1;
  letter-spacing: -.04em;
}

.lead {
  margin: 14px 0 0;
  color: var(--muted);
  font-size: 14px;
  line-height: 1.55;
}

.card {
  position: relative;
  overflow: hidden;
  margin-top: 26px;
  padding: 18px;
  border: 1px solid rgba(255, 255, 255, .1);
  border-radius: 22px;
  background: rgba(16, 16, 19, .55);
  backdrop-filter: blur(28px) saturate(160%);
  -webkit-backdrop-filter: blur(28px) saturate(160%);
  box-shadow:
    0 24px 60px -24px rgba(0, 0, 0, .65),
    inset 0 1px 0 rgba(255, 255, 255, .06);
}

.spot::after {
  content: "";
  position: absolute;
  inset: 0;
  z-index: 0;
  border-radius: inherit;
  background: radial-gradient(
    240px circle at var(--mx, 50%) var(--my, 50%),
    rgba(255, 110, 120, .16),
    transparent 72%
  );
  opacity: 0;
  transition: opacity .4s ease;
  pointer-events: none;
}

.spot:hover::after {
  opacity: 1;
}

.card > *,
.method > * {
  position: relative;
  z-index: 1;
}

.account {
  padding: 12px 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  border: 1px solid rgba(255, 255, 255, .08);
  border-radius: 14px;
  background: rgba(255, 255, 255, .04);
}

.account span,
.label {
  color: var(--muted);
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .1em;
  text-transform: uppercase;
}

.account strong,
.key,
.timer {
  font-family: "SFMono-Regular", Consolas, monospace;
}

.account strong {
  font-size: 12px;
  font-weight: 650;
}

.method {
  position: relative;
  overflow: hidden;
  margin-top: 14px;
  padding: 12px;
  display: grid;
  grid-template-columns: 44px 1fr 18px;
  align-items: center;
  gap: 12px;
  border: 1px solid rgba(255, 255, 255, .1);
  border-radius: 16px;
  background: rgba(255, 255, 255, .03);
  cursor: pointer;
  transition:
    border-color .25s cubic-bezier(.16, 1, .3, 1),
    background .25s cubic-bezier(.16, 1, .3, 1),
    transform .25s cubic-bezier(.16, 1, .3, 1),
    box-shadow .25s cubic-bezier(.16, 1, .3, 1);
}

.method:hover {
  border-color: rgba(255, 255, 255, .22);
  background: rgba(255, 255, 255, .06);
  transform: translateY(-2px);
  box-shadow: 0 16px 34px -18px rgba(255, 60, 75, .45);
}

.method-input {
  position: absolute;
  opacity: 0;
  pointer-events: none;
}

.method-icon {
  width: 44px;
  height: 44px;
  overflow: hidden;
  display: grid;
  place-items: center;
  border-radius: 12px;
  background: #fff;
}

.method-icon img {
  width: 100%;
  height: 100%;
  display: block;
  object-fit: cover;
}

.method-fallback {
  width: 100%;
  height: 100%;
  display: none;
  place-items: center;
  color: #111;
  font-size: 10px;
  font-weight: 850;
}

.method-copy {
  min-width: 0;
  display: grid;
  gap: 3px;
}

.method-copy strong {
  font-size: 13px;
  font-weight: 680;
}

.method-copy span {
  color: var(--muted);
  font-size: 11px;
}

.method-arrow {
  color: #777781;
  font-size: 20px;
  line-height: 1;
}

.button {
  position: relative;
  overflow: hidden;
  width: 100%;
  min-height: 50px;
  margin-top: 14px;
  border: 1px solid rgba(255, 255, 255, .9);
  border-radius: 15px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(180deg, #ffffff, #efeff2);
  color: #09090a;
  font: inherit;
  font-size: 12px;
  font-weight: 720;
  letter-spacing: .06em;
  text-transform: uppercase;
  text-decoration: none;
  cursor: pointer;
  box-shadow: 0 14px 30px -14px rgba(255, 255, 255, .3);
  transition:
    transform .25s cubic-bezier(.16, 1, .3, 1),
    box-shadow .25s cubic-bezier(.16, 1, .3, 1),
    background .25s ease;
}

.button::after {
  content: "";
  position: absolute;
  top: 0;
  bottom: 0;
  left: -40%;
  width: 30%;
  background: linear-gradient(
    115deg,
    transparent,
    rgba(255, 90, 105, .55),
    transparent
  );
  transform: skewX(-18deg);
  opacity: 0;
}

.button:hover::after {
  opacity: 1;
  animation: sheen 1s ease forwards;
}

@keyframes sheen {
  0% { left: -40%; }
  100% { left: 130%; }
}

.button:hover {
  background: #ffffff;
  transform: translateY(-2px);
  box-shadow: 0 18px 38px -14px rgba(255, 70, 85, .45);
}

.button:active {
  transform: translateY(0);
  opacity: .9;
}

.button:disabled {
  opacity: .42;
  cursor: not-allowed;
  transform: none;
}

.status {
  min-height: 17px;
  margin: 10px 0 0;
  color: var(--muted);
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
  min-height: 144px;
  display: grid;
  place-items: center;
  text-align: center;
}

.loader {
  width: 30px;
  height: 30px;
  margin: 0 auto 15px;
  border: 2px solid rgba(255, 255, 255, .1);
  border-top-color: #fff;
  border-radius: 50%;
  animation: spin .8s linear infinite;
}

.loader-wrap strong {
  display: block;
  font-size: 13px;
  font-weight: 650;
}

.loader-wrap p {
  margin: 7px 0 0;
  color: var(--muted);
  font-size: 11px;
  line-height: 1.5;
}

.key {
  margin-top: 9px;
  padding: 16px 12px;
  border: 1px solid rgba(255, 255, 255, .12);
  border-radius: 15px;
  background: rgba(0, 0, 0, .35);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  color: #fff;
  text-align: center;
  font-size: clamp(12px, 3.6vw, 14px);
  font-weight: 700;
  letter-spacing: .02em;
  line-height: 1.5;
  word-break: break-all;
  user-select: all;
}

.timer-row {
  margin-top: 17px;
  display: flex;
  align-items: end;
  justify-content: space-between;
}

.timer {
  font-size: 18px;
  font-weight: 700;
}

.progress {
  height: 4px;
  margin: 10px 0 4px;
  overflow: hidden;
  border-radius: 99px;
  background: rgba(255, 255, 255, .08);
}

.progress span {
  display: block;
  width: 100%;
  height: 100%;
  border-radius: inherit;
  background: linear-gradient(90deg, #ff929e, #ffffff);
  transition: width 1s linear;
}

.confetti-piece {
  position: fixed;
  z-index: 9999;
  top: -14px;
  width: 6px;
  height: 10px;
  pointer-events: none;
  opacity: 0;
  animation:
    confetti-fall
    var(--duration)
    cubic-bezier(.2, .65, .25, 1)
    forwards;
}

.hidden {
  display: none !important;
}

@keyframes spin {
  to {
    transform: rotate(360deg);
  }
}

@keyframes confetti-fall {
  0% {
    opacity: 0;
    transform:
      translate3d(0, -12px, 0)
      rotate(0deg);
  }

  12% {
    opacity: 1;
  }

  100% {
    opacity: 0;
    transform:
      translate3d(var(--drift), 52vh, 0)
      rotate(var(--rotation));
  }
}

@media (max-width: 520px) {
  .page {
    padding: 22px 15px;
  }

  .brand {
    margin-bottom: 34px;
  }

  .card {
    padding: 15px;
    border-radius: 18px;
  }
}
`;

function brand() {
  return `
    <header class="brand">
      <span class="brand-mark"></span>
      <strong>Nameless Hub</strong>
    </header>
  `;
}

const spotlightScript = `
  (function () {
    var els = document.querySelectorAll(".spot");

    els.forEach(function (el) {
      el.addEventListener("pointermove", function (e) {
        var rect = el.getBoundingClientRect();
        el.style.setProperty("--mx", (e.clientX - rect.left) + "px");
        el.style.setProperty("--my", (e.clientY - rect.top) + "px");
      });
    });
  })();
`;

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

        <meta
          name="theme-color"
          content="#050506"
        >

        <meta
          name="description"
          content="${description}"
        >

        <meta
          property="og:title"
          content="${title}"
        >

        <meta
          property="og:url"
          content="${PUBLIC_ORIGIN}/get-key"
        >

        <title>${title}</title>

        <style>${siteCss}</style>
      </head>

      <body>
        <div class="lava-bg" aria-hidden="true">
          <span class="b1"></span>
          <span class="b2"></span>
          <span class="b3"></span>
          <span class="b4"></span>
        </div>

        ${content}
        <script>${spotlightScript}</script>
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

        <h1>Get Key</h1>

        <p class="lead">
          Choose a method to continue.
        </p>

        <section class="card spot">
          <div class="account">
            <span>Roblox ID</span>
            <strong>${safeUid}</strong>
          </div>

          <form action="/start" method="get">
            <input
              type="hidden"
              name="uid"
              value="${safeUid}"
            >

            <label class="method spot">
              <input
                class="method-input"
                type="radio"
                name="method"
                value="lootlabs"
                checked
              >

              <span class="method-icon">
                <img
                  src="https://media.licdn.com/dms/image/v2/D4D0BAQFC2ErrY3XtXw/company-logo_200_200/company-logo_200_200/0/1684408131437/lootlabsgg_logo?e=2147483647&amp;v=beta&amp;t=kO3BbH2OnfQqlSm8hd1K1IhD4cJlEQgCWWDjM4DwLpE"
                  alt="LootLabs"
                  referrerpolicy="no-referrer"
                  onerror="this.style.display='none';this.nextElementSibling.style.display='grid'"
                >

                <span class="method-fallback">
                  LL
                </span>
              </span>

              <span class="method-copy">
                <strong>LootLabs</strong>
                <span>About 2 minutes</span>
              </span>

              <span class="method-arrow">›</span>
            </label>

            <button class="button" type="submit">
              Continue
            </button>
          </form>
        </section>
      </main>
    `
    : `
      <main class="page">
        ${brand()}

        <h1>Open from the script</h1>

        <p class="lead">
          Use Get Key inside Nameless Hub to create a linked request.
        </p>

        <section class="card spot">
          <button class="button" disabled>
            Account not linked
          </button>
        </section>
      </main>
    `;

  return page(
    "Get Key · Nameless Hub",
    "Nameless Hub key delivery.",
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

        <h1>${title}</h1>
        <p class="lead">${message}</p>

        <section class="card spot">
          <a class="button" href="${href}">
            Try again
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

      <h1 id="title">Checking key</h1>

      <p id="lead" class="lead">
        Confirming your LootLabs completion.
      </p>

      <section id="loading" class="card spot">
        <div class="loader-wrap">
          <div>
            <div class="loader"></div>
            <strong>Checking completion</strong>
          </div>
        </div>
      </section>

      <section
        id="result"
        class="card spot hidden"
      >
        <div class="label">Key</div>

        <div id="key" class="key"></div>

        <div class="timer-row">
          <span class="label">Expires in</span>

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
        class="card spot hidden"
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

    function celebrate() {
      const colors = [
        "#ffffff",
        "#f7d154",
        "#7dd3fc",
        "#c4b5fd",
        "#f9a8d4"
      ];

      for (
        let index = 0;
        index < 28;
        index += 1
      ) {
        const piece =
          document.createElement("span");

        piece.className =
          "confetti-piece";

        piece.style.left =
          Math.random() * 100 + "vw";

        piece.style.background =
          colors[index % colors.length];

        piece.style.borderRadius =
          Math.random() > .55
            ? "99px"
            : "2px";

        piece.style.setProperty(
          "--drift",
          (Math.random() * 150 - 75) + "px"
        );

        piece.style.setProperty(
          "--rotation",
          (Math.random() * 720 - 360) + "deg"
        );

        piece.style.setProperty(
          "--duration",
          (1.25 + Math.random() * .65) + "s"
        );

        piece.style.animationDelay =
          Math.random() * .18 + "s";

        document.body.appendChild(piece);

        piece.addEventListener(
          "animationend",
          function () {
            piece.remove();
          }
        );
      }
    }

    function celebrateOnce() {
      const token =
        "nh-confetti:" + currentKey;

      let shown = false;

      try {
        shown =
          sessionStorage.getItem(token) === "1";

        if (!shown) {
          sessionStorage.setItem(token, "1");
        }
      } catch {
        shown = false;
      }

      if (!shown) {
        celebrate();
      }
    }

    function fail(message, canContinue) {
      loading.classList.add("hidden");
      result.classList.add("hidden");
      errorBox.classList.remove("hidden");

      title.textContent =
        "Key unavailable";

      lead.textContent =
        "Finish the checkpoint or create a new request.";

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
        ? "Continue"
        : "New request";
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
          "Create a new key.",
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

      title.textContent = "Key ready";

      lead.textContent =
        "Copy it and paste it into Nameless Hub.";

      setStatus("", "");
      celebrateOnce();
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
        setStatus("Copied", "good");

        setTimeout(function () {
          if (!copy.disabled) {
            copy.textContent = "Copy key";
            setStatus("", "");
          }
        }, 1400);
      } catch {
        setStatus(
          "Select and copy the key manually.",
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
