'use strict';

/**
 * GuardFi — environment configuration (Phase 1, extended in Phase 2)
 *
 * Responsibilities:
 *  1. Load `.env` exactly once, before any other module reads process.env.
 *  2. Validate the environment with zod and FAIL FAST with a readable report.
 *  3. Expose a single frozen `config` object so no other file touches process.env.
 *
 * Compliance note on the master spec's "validate every required key" rule:
 * keys for phases that do not exist yet (Twilio, Firebase, Gemini, Cloudinary)
 * are reported as DEFERRED warnings instead of hard failures — otherwise the
 * Phase 1 API could not boot at all. Set STRICT_ENV=true (the default in
 * production) to turn every declared key into a hard requirement; that is what
 * the Phase 10 deployment checklist expects.
 */

const fs = require('node:fs');
const path = require('node:path');
const dotenv = require('dotenv');
const { z } = require('zod');

const envFilePath = path.resolve(process.cwd(), '.env');

// Real environment variables always win over .env, which lets CI and the
// verification harness inject overrides without editing any file.
// `quiet` silences dotenv's own banner so application logs stay parseable.
const dotenvResult = dotenv.config({ path: envFilePath, quiet: true });

/**
 * Snapshot of .env's own contents, so a validation failure can say WHERE a bad
 * value came from. Without this, "PORT: Too small" is baffling when .env says
 * PORT=3000 and some shell or IDE quietly exported PORT=0.
 */
let envFileValues = {};
try {
  envFileValues = dotenv.parse(fs.readFileSync(envFilePath, 'utf8'));
} catch {
  envFileValues = {};
}

const logger = require('../utils/logger');

if (dotenvResult.error && dotenvResult.error.code !== 'ENOENT') {
  logger.warn(`[env] .env could not be read (${dotenvResult.error.code}); using the process environment only.`);
}

/**
 * Drop variables that are present but blank ("PORT="), so they fall back to
 * their schema default instead of being coerced into 0 and failing a range
 * check with a confusing message.
 */
function sanitizeEnv(source) {
  const cleaned = { ...source };

  for (const key of Object.keys(cleaned)) {
    if (typeof cleaned[key] === 'string' && cleaned[key].trim() === '') delete cleaned[key];
  }

  return cleaned;
}

// Presence of the Phase 1 secrets is checked before schema parsing so the
// developer gets a plain instruction instead of a zod message. These two are
// also the keys dotenv cannot default, so they must be real.
const missingRequiredKeys = [
  {
    key: 'MONGO_URI',
    hint: 'needs your MongoDB Atlas connection string, e.g. mongodb+srv://USER:PASS@cluster.mongodb.net/guardfi',
  },
  {
    key: 'JWT_SECRET',
    hint: 'needs at least 32 random characters — generate one with: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"',
  },
].filter((entry) => isBlank(process.env[entry.key]));

if (missingRequiredKeys.length > 0) {
  failFast(missingRequiredKeys.map((entry) => `${entry.key} is not set — ${entry.hint}`));
}

/** Values that look like a secret but are not one. */
const PLACEHOLDER_SECRETS = new Set([
  'change_me',
  'changeme',
  'your_secret_here',
  'your-secret-here',
  'jwt_secret',
  'secret',
  'placeholder',
  'test',
  'todo',
]);

const coreSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('debug'),

  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  TRUST_PROXY: z.string().trim().default(''),
  STRICT_ENV: z.string().trim().default(''),

  // --- MongoDB -------------------------------------------------------------
  MONGO_URI: z
    .string()
    .trim()
    .min(1, 'is required — set your MongoDB Atlas connection string')
    .refine(
      (value) => /^mongodb(\+srv)?:\/\//.test(value),
      'must start with mongodb:// or mongodb+srv://'
    ),
  // Used when MONGO_URI does not name a database. Without this, a URI such as
  // mongodb+srv://user:pass@cluster.mongodb.net/?retryWrites=true makes the
  // driver write to a database literally called "test" — silent data loss that
  // looks like the app working.
  MONGO_DB_NAME: z
    .string()
    .trim()
    .regex(/^[A-Za-z0-9_-]{1,63}$/, 'must be 1-63 characters of letters, digits, underscore or hyphen')
    .default('guardfi'),
  MONGO_MAX_POOL_SIZE: z.coerce.number().int().min(1).max(100).default(10),
  MONGO_MIN_POOL_SIZE: z.coerce.number().int().min(0).max(50).default(2),
  MONGO_CONNECT_RETRIES: z.coerce.number().int().min(0).max(20).default(3),
  MONGO_RETRY_BASE_DELAY_MS: z.coerce.number().int().min(0).max(60000).default(1000),
  MONGO_SERVER_SELECTION_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60000).default(8000),

  // --- Auth ----------------------------------------------------------------
  JWT_SECRET: z
    .string()
    .min(32, 'must be at least 32 characters — generate one with crypto.randomBytes(48).toString("hex")')
    .refine((value) => !PLACEHOLDER_SECRETS.has(value.trim().toLowerCase()), 'is still a placeholder value'),
  JWT_EXPIRES_IN: z.string().trim().min(1).default('7d'),

  // --- Phone identity (Phase 2) -------------------------------------------
  DEFAULT_PHONE_COUNTRY_CODE: z
    .string()
    .trim()
    .regex(/^[1-9]\d{0,2}$/, 'must be a country calling code without the + sign, e.g. 91')
    .default('91'),

  // --- Nominee / guardian cap (Phase 3) -----------------------------------
  // The master spec asks for "a sensible cap (e.g., max 5 nominees per user)".
  // Env-driven so a demo can raise it without a code change, and bounded so it
  // can never become an unbounded write surface.
  MAX_NOMINEES_PER_USER: z.coerce.number().int().min(1).max(50).default(5),

  // --- OTP / SMS (Phase 2) ------------------------------------------------
  OTP_DEV_MODE: z.string().trim().default(''),
  // Escape hatch for the guard below: without it, a production boot with
  // OTP_DEV_MODE=true refuses to start rather than serve live OTPs in HTTP
  // responses. Set it to true only for a deliberate, temporary demo.
  ALLOW_OTP_DEV_MODE_IN_PRODUCTION: z.string().trim().default(''),
  OTP_LENGTH: z.coerce.number().int().min(4).max(8).default(6),
  OTP_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(300),
  OTP_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(10).default(3),
  OTP_RESEND_COOLDOWN_SECONDS: z.coerce.number().int().min(0).max(600).default(30),
  // Per-PHONE cap on codes per window. The IP limiter is not enough on its own:
  // one attacker with a handful of proxies can hold a victim's number hostage and
  // burn real SMS credit, which the 30s cooldown alone only slows to 120/hour.
  // 0 disables the cap.
  OTP_MAX_SENDS_PER_WINDOW: z.coerce.number().int().min(0).max(100).default(10),
  OTP_SEND_WINDOW_SECONDS: z.coerce.number().int().min(60).max(86_400).default(3600),
  OTP_HASH_ROUNDS: z.coerce.number().int().min(4).max(12).default(8),
  BCRYPT_SALT_ROUNDS: z.coerce.number().int().min(4).max(15).default(10),
  SMS_PROVIDER: z.enum(['auto', 'twilio', 'fast2sms', 'none']).default('auto'),
  SMS_HTTP_TIMEOUT_MS: z.coerce.number().int().min(500).max(30_000).default(10_000),
  // 'otp' uses Fast2SMS's pre-approved OTP template (variables_values only);
  // 'q' sends a free-form quick message. 'dlt' is not implemented because it
  // needs a sender id + template id that this project does not have yet.
  FAST2SMS_ROUTE: z.enum(['otp', 'q']).default('otp'),
  TWILIO_ACCOUNT_SID: z.string().trim().default(''),
  TWILIO_AUTH_TOKEN: z.string().trim().default(''),
  TWILIO_PHONE_NUMBER: z.string().trim().default(''),
  FAST2SMS_API_KEY: z.string().trim().default(''),

  // --- SOS / live location (Phase 4) ---------------------------------------
  // How often a GPS stream is actually written to MongoDB. Everything faster is
  // broadcast over Socket.io from RAM and dropped from persistence: a phone
  // posting 10 updates/second must not become 10 database writes/second.
  SOS_LOCATION_PERSIST_INTERVAL_SECONDS: z.coerce.number().int().min(1).max(120).default(5),
  // Breadcrumbs kept per alert. Older points are sliced off in the same atomic
  // $push, so the document can never grow without bound.
  SOS_LOCATION_HISTORY_LIMIT: z.coerce.number().int().min(10).max(1000).default(200),
  // SMS is the fallback for guardians without a push token (or when push fails).
  // Costs real credit, so it can be switched off. Defaults on: an SOS that
  // silently reaches nobody is worse than an SMS bill.
  SOS_SMS_FALLBACK_ENABLED: z.string().trim().default(''),
  // Per-socket ceiling on location updates, in messages per second.
  SOS_MAX_LOCATION_UPDATES_PER_SECOND: z.coerce.number().int().min(1).max(100).default(5),
  // Optional deep link sent in the fallback SMS, e.g. https://app.guardfi.in/sos
  // (the room id is appended as ?room=…). Empty means the SMS carries the room
  // code only.
  SOS_TRACKING_BASE_URL: z
    .string()
    .trim()
    .default('')
    .refine((value) => value === '' || /^https?:\/\/\S+$/i.test(value), 'must be an http(s) URL or empty'),

  // --- Dashboard analytics (Phase 5) ---------------------------------------
  // Radius for the "alerts near me" aggregate. Bounded so one request can never
  // ask MongoDB to walk an unbounded slice of the planet.
  ANALYTICS_NEARBY_RADIUS_METERS: z.coerce.number().int().min(100).max(50_000).default(5_000),
  // "Recent" window for global SOS counts, in hours.
  ANALYTICS_RECENT_WINDOW_HOURS: z.coerce.number().int().min(1).max(168).default(24),

  // --- Shield Pay (Phase 6) ------------------------------------------------
  // Risk bands for the 0-100 score. Heuristics are capped below the danger
  // threshold on purpose (see shieldPayService): only a reported entity may
  // produce a "Fraud Alert". Cross-field checked below, so an inverted band
  // fails the boot instead of silently making every payee look safe.
  SHIELD_PAY_SUSPICIOUS_THRESHOLD: z.coerce.number().int().min(1).max(99).default(30),
  SHIELD_PAY_DANGER_THRESHOLD: z.coerce.number().int().min(2).max(100).default(70),
  // How long the server-side "you were warned" state survives. The window is the
  // user's chance to actually complete the payment; after it, the check is dead
  // and the payee must be re-checked (a stale warning is not informed consent).
  SHIELD_PAY_RISK_CHECK_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
  // Largest single Shield Pay amount, in rupees. A demo/hackathon cap that can
  // be raised for production without touching code.
  SHIELD_PAY_MAX_AMOUNT: z.coerce.number().int().min(1).max(10_000_000).default(200_000),

  // --- Scam Buster: Gemini + Cloudinary (Phase 7) ---------------------------
  // Google AI Studio key. Missing → scans are answered by the deterministic
  // offline heuristics (analysisSource=HEURISTIC) instead of failing; the boot
  // log says exactly that.
  GEMINI_API_KEY: z.string().trim().default(''),
  GEMINI_MODEL: z.string().trim().min(1).default('gemini-2.5-flash'),
  // Hard deadline for one generation. The endpoint must answer even when the
  // provider stalls, so this is enforced by the SDK AND by a race on top of it.
  GEMINI_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60_000).default(15_000),
  // All three or none: a partial Cloudinary config cannot authenticate.
  CLOUDINARY_CLOUD_NAME: z.string().trim().default(''),
  CLOUDINARY_API_KEY: z.string().trim().default(''),
  CLOUDINARY_API_SECRET: z.string().trim().default(''),
  CLOUDINARY_FOLDER: z.string().trim().default('guardfi/scam-scans'),
  CLOUDINARY_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60_000).default(20_000),
  // One screenshot is a phone screen, not a RAW photo. Bytes are paid for twice
  // (storage + AI input), so the cap is deliberately small and configurable.
  SCAM_BUSTER_MAX_IMAGE_BYTES: z.coerce.number().int().min(1024).max(25_000_000).default(5 * 1024 * 1024),
  SCAM_BUSTER_TEXT_MAX_CHARS: z.coerce.number().int().min(100).max(20_000).default(5_000),
  // Where screenshots are stored: 'auto' = Cloudinary when configured, else the
  // local directory below; pinned to 'cloudinary' or 'local' it fails loudly
  // instead of silently changing destination.
  SCAM_BUSTER_STORAGE_MODE: z.enum(['auto', 'cloudinary', 'local']).default('auto'),
  SCAM_BUSTER_LOCAL_STORAGE_DIR: z.string().trim().min(1).default('uploads/scam-scans'),
  // Largest screenshot that may be inlined as a data URI when the local write
  // itself fails (read-only FS). 1 MB keeps the MongoDB document well under the
  // 16 MB limit once base64 inflates it by ~33%.
  SCAM_BUSTER_INLINE_IMAGE_MAX_BYTES: z.coerce.number().int().min(1024).max(2_000_000).default(1_048_576),

  // --- Emergency biometric bypass (Phase 8) --------------------------------
  // Shared HMAC key provisioned in the Flutter build. The app signs
  //   guardfi-biometric-v1|<userId>|true|<verifiedAtEpochMs>|<nonce>
  // with HMAC-SHA256 and this server verifies it. Empty means the endpoint
  // answers 503: an unsigned `{"success": true}` from the wire is never trusted.
  // Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
  BIOMETRIC_SHARED_SECRET: z.string().trim().default(''),
  // How old a signed biometric result may be. Short on purpose: an assertion
  // captured yesterday is not proof of a finger on the sensor now.
  BIOMETRIC_MAX_ASSERTION_AGE_SECONDS: z.coerce.number().int().min(10).max(900).default(120),
  // Biometric attempts each write an audit row, so they need their own budget.
  RATE_LIMIT_EMERGENCY_MAX: z.coerce.number().int().min(1).max(100_000).default(10),

  // --- Dynamic global configuration (Phase 9) -------------------------------
  // How long GET /api/v1/config/global may be answered from node-cache before
  // MongoDB is read again. The admin PUT invalidates the entry immediately, so
  // this is a safety net for a missed invalidation, not the main mechanism.
  GLOBAL_CONFIG_CACHE_TTL_SECONDS: z.coerce.number().int().min(30).max(86_400).default(600),

  // --- Firebase Cloud Messaging (Phase 4) ----------------------------------
  // All three or none: a partial service account cannot authenticate, so the
  // app reports push as unconfigured and relies on the SMS fallback.
  FIREBASE_PROJECT_ID: z.string().trim().default(''),
  FIREBASE_CLIENT_EMAIL: z.string().trim().default(''),
  FIREBASE_PRIVATE_KEY: z.string().trim().default(''),

  // --- HTTP surface --------------------------------------------------------
  CORS_ORIGINS: z.string().trim().default('*'),
  JSON_BODY_LIMIT: z.string().trim().min(1).default('1mb'),
  RATE_LIMIT_WINDOW_MS: z.coerce.number().int().min(1000).max(86_400_000).default(15 * 60 * 1000),
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(100_000).default(300),
  AUTH_RATE_LIMIT_MAX: z.coerce.number().int().min(1).max(100_000).default(10),
  RATE_LIMIT_OTP_MAX: z.coerce.number().int().min(1).max(100_000).default(5),
  RATE_LIMIT_OTP_WINDOW_MS: z.coerce.number().int().min(1000).max(86_400_000).default(15 * 60 * 1000),
  // Shield Pay PIN attempts (Phase 6): a 4-6 digit PIN is a 10 000-guess space,
  // so the credential routes get their own small budget, like auth does.
  RATE_LIMIT_PIN_MAX: z.coerce.number().int().min(1).max(100_000).default(10),
  // Scam Buster scans (Phase 7): every scan spends Gemini tokens and, for a
  // screenshot, a Cloudinary upload — a budget of its own, not the global one.
  RATE_LIMIT_SCAM_BUSTER_MAX: z.coerce.number().int().min(1).max(100_000).default(20),
  // Limiters are skipped automatically under NODE_ENV=test so an automated
  // verification run is never throttled. The harness sets this to false when it
  // deliberately wants to prove a 429 is returned.
  RATE_LIMIT_SKIP_IN_TEST: z.string().trim().default(''),
  SHUTDOWN_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60_000).default(10_000),

  // --- Socket.io connection budget ----------------------------------------
  // Socket.io is mounted before Phase 4 adds handshake authentication, and even
  // once it does, every open socket costs memory and a file descriptor. Without
  // a cap, an unauthenticated client can open connections until the process or
  // the platform runs out. 0 disables that half of the guard.
  SOCKET_MAX_CONNECTIONS_PER_IP: z.coerce.number().int().min(0).max(100_000).default(25),
  SOCKET_MAX_CONNECTIONS: z.coerce.number().int().min(0).max(1_000_000).default(2000),
});

/**
 * Keys owned by later phases. Presence is checked so the foundation can warn
 * long before the phase that needs them is written.
 * @type {{ key: string, phase: number, purpose: string }[]}
 */
const DEFERRED_KEYS = [
  { key: 'TWILIO_ACCOUNT_SID', phase: 2, purpose: 'OTP SMS delivery (optional while OTP_DEV_MODE=true)' },
  { key: 'TWILIO_AUTH_TOKEN', phase: 2, purpose: 'OTP SMS delivery (optional while OTP_DEV_MODE=true)' },
  { key: 'TWILIO_PHONE_NUMBER', phase: 2, purpose: 'OTP SMS sender id (optional while OTP_DEV_MODE=true)' },
  { key: 'FAST2SMS_API_KEY', phase: 2, purpose: 'OTP SMS fallback provider (optional while OTP_DEV_MODE=true)' },
  { key: 'FIREBASE_PROJECT_ID', phase: 4, purpose: 'FCM push notifications' },
  { key: 'FIREBASE_CLIENT_EMAIL', phase: 4, purpose: 'FCM push notifications' },
  { key: 'FIREBASE_PRIVATE_KEY', phase: 4, purpose: 'FCM push notifications' },
  { key: 'GEMINI_API_KEY', phase: 7, purpose: 'Scam Buster AI analysis' },
  { key: 'CLOUDINARY_CLOUD_NAME', phase: 7, purpose: 'screenshot upload storage' },
  { key: 'CLOUDINARY_API_KEY', phase: 7, purpose: 'screenshot upload storage' },
  { key: 'CLOUDINARY_API_SECRET', phase: 7, purpose: 'screenshot upload storage' },
  { key: 'BIOMETRIC_SHARED_SECRET', phase: 8, purpose: 'verifying the app\'s signed biometric result' },
];

function isBlank(value) {
  return value === undefined || value === null || String(value).trim() === '';
}

/**
 * Where did this variable's effective value come from?
 * dotenv never overwrites an existing variable, so a value that differs from
 * .env's own text must have been inherited from the parent process.
 * @param {string} key
 * @returns {string}
 */
function originOf(key) {
  const fileValue = envFileValues[key];
  const processValue = process.env[key];

  if (fileValue === undefined) return 'the OS/shell environment (not .env)';
  if (processValue === undefined) return '.env';
  return processValue === fileValue ? '.env' : 'the OS/shell environment (it overrides .env)';
}

function resolveTrustProxy(raw, isProduction) {
  if (raw === '') return isProduction ? 1 : false;
  if (raw === 'true') return 1;
  if (raw === 'false') return false;
  const hops = Number(raw);
  return Number.isInteger(hops) && hops >= 0 ? hops : false;
}

function resolveStrictEnv(raw, isProduction) {
  if (raw === '') return isProduction;
  return String(raw).toLowerCase() === 'true';
}

/**
 * Work out which database the connection string targets.
 *
 * Accepts both shapes MongoDB itself accepts:
 *   mongodb+srv://USER:PASS@cluster.mongodb.net/guardfi?retryWrites=true
 *   mongodb+srv://USER:PASS@cluster.mongodb.net/?retryWrites=true   ← no db name
 * and also tolerates an accidental double slash ("…net//guardfi"), which is
 * easy to paste and used to send every write to a database named "/guardfi".
 *
 * @returns {{ name: string, explicit: boolean }}
 */
function resolveDatabaseName(uri, fallbackName) {
  const withoutScheme = uri.replace(/^mongodb(\+srv)?:\/\//, '');
  const lastAt = withoutScheme.lastIndexOf('@');
  const authority = lastAt === -1 ? withoutScheme : withoutScheme.slice(lastAt + 1);
  const queryIndex = authority.indexOf('?');
  const pathPart = queryIndex === -1 ? authority : authority.slice(0, queryIndex);
  const slashIndex = pathPart.indexOf('/');
  const rawName = slashIndex === -1 ? '' : pathPart.slice(slashIndex + 1);
  const name = rawName.replace(/^\/+/, '').trim();

  if (name === '') return { name: fallbackName, explicit: false };
  return { name, explicit: true };
}

/**
 * Read a boolean env var, falling back to `fallback` when it is blank.
 * Only the literal string "true" turns a flag on; anything else is false, so a
 * typo can never silently enable a dangerous mode.
 */
function parseBoolean(raw, fallback = false) {
  if (raw === undefined || raw === null || raw === '') return fallback;
  return String(raw).trim().toLowerCase() === 'true';
}

function parseOrigins(raw) {
  if (raw.trim() === '*') return ['*'];
  return raw
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
}

/** Print a fatal, readable report and stop the process. */
function failFast(messages) {
  const line = '─'.repeat(74);
  const body = messages.map((message) => `  • ${message}`).join('\n');
  // console (not logger) on purpose: this must be visible even if logging is
  // misconfigured, and it is the last thing the process ever prints.
  console.error(
    [
      line,
      '✖ GuardFi backend cannot start: environment configuration is invalid.',
      line,
      body,
      line,
      '  Fix .env  (copy the template:  cp .env.example .env)  and restart.',
      line,
    ].join('\n')
  );
  process.exit(1);
}

const parsed = coreSchema.safeParse(sanitizeEnv(process.env));

if (!parsed.success) {
  const issues = (parsed.error && parsed.error.issues) || [];
  const messages = issues.map((issue) => {
    const key = issue.path.join('.') || '(root)';
    // Only annotate real values; a missing key has no origin worth naming.
    const suffix = process.env[key] === undefined ? '' : `  [value came from ${originOf(key)}]`;
    return `${key}: ${issue.message}${suffix}`;
  });
  failFast(messages.length > 0 ? messages : ['Unknown validation failure while reading environment variables.']);
}

const raw = parsed.data;
const isProduction = raw.NODE_ENV === 'production';
const strictEnv = resolveStrictEnv(raw.STRICT_ENV, isProduction);

// Development convenience by default, never enabled in production unless the
// operator explicitly asks for it — and then they get shouted at below.
const otpDevMode = parseBoolean(raw.OTP_DEV_MODE, !isProduction);
const otpDevModeAllowedInProduction = parseBoolean(raw.ALLOW_OTP_DEV_MODE_IN_PRODUCTION, false);

// Leaking a live OTP in a response body is a full account-takeover primitive, so
// it must never be one stray env var away in production. Refuse the boot and
// say exactly how to resolve it.
if (otpDevMode && isProduction && !otpDevModeAllowedInProduction) {
  failFast([
    'OTP_DEV_MODE=true while NODE_ENV=production.',
    'That would return live OTPs inside /api/v1/auth/send-otp responses, letting anyone sign in as any user.',
    'Fix it by setting OTP_DEV_MODE=false (real SMS delivery), or — for a deliberate temporary demo — set',
    'ALLOW_OTP_DEV_MODE_IN_PRODUCTION=true and accept that OTPs are public while it stays on.',
  ]);
}

// Cross-field rule that a per-key schema cannot express: an inverted risk band
// would make the danger threshold unreachable, i.e. every scam payee reading as
// merely "suspicious". That is a silent safety regression, so refuse to boot.
if (parsed.data.SHIELD_PAY_DANGER_THRESHOLD <= parsed.data.SHIELD_PAY_SUSPICIOUS_THRESHOLD) {
  failFast([
    `SHIELD_PAY_DANGER_THRESHOLD (${parsed.data.SHIELD_PAY_DANGER_THRESHOLD}) must be greater than SHIELD_PAY_SUSPICIOUS_THRESHOLD (${parsed.data.SHIELD_PAY_SUSPICIOUS_THRESHOLD}).`,
    'With the bands inverted no payee could ever reach the DANGER level. Set e.g. 30 and 70.',
  ]);
}

// A pinned screenshot destination with no credentials would fail on the first
// scan, in production, at the worst moment. Refuse to boot instead — the same
// reasoning as pinning SMS_PROVIDER.
const cloudinaryCredsPresent = Boolean(
  parsed.data.CLOUDINARY_CLOUD_NAME && parsed.data.CLOUDINARY_API_KEY && parsed.data.CLOUDINARY_API_SECRET
);

if (parsed.data.SCAM_BUSTER_STORAGE_MODE === 'cloudinary' && !cloudinaryCredsPresent) {
  failFast([
    'SCAM_BUSTER_STORAGE_MODE=cloudinary but the Cloudinary credentials are incomplete.',
    'Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET, or use SCAM_BUSTER_STORAGE_MODE=auto.',
  ]);
}

// --- Deferred keys: warn in development, hard-fail when STRICT_ENV is on ----
const missingDeferred = DEFERRED_KEYS.filter((entry) => isBlank(process.env[entry.key]));

if (missingDeferred.length > 0) {
  const summary = missingDeferred
    .map((entry) => `${entry.key} (Phase ${entry.phase} — ${entry.purpose})`)
    .join(', ');

  if (strictEnv) {
    failFast([
      `STRICT_ENV is enabled, so every declared key is required. Missing ${missingDeferred.length}:`,
    ].concat(missingDeferred.map((entry) => `${entry.key} — Phase ${entry.phase} (${entry.purpose})`)));
  }

  logger.warn(`[env] ${missingDeferred.length} deferred key(s) not set yet: ${summary}`);
  logger.warn('[env] GuardFi will boot; these become required in the phases that use them.');
}

const databaseName = resolveDatabaseName(raw.MONGO_URI, raw.MONGO_DB_NAME);

if (!databaseName.explicit) {
  logger.warn(
    `[env] MONGO_URI names no database, so GuardFi will use "${databaseName.name}". Add "/${databaseName.name}" to MONGO_URI, or set MONGO_DB_NAME, if you want a different one.`
  );
}

// --- Proxy-trust warning ---------------------------------------------------
// `trust proxy` only decides whose IP Express believes. Get it wrong in the
// permissive direction and every per-IP rate limit (OTP sending, sign-in
// attempts, the global limiter) becomes advisory: an attacker sends a fresh
// X-Forwarded-For value per request and gets a new bucket every time.
// NOTE: resolved locally, not via `config` — the config object is built further
// down this file and reading it here would be a temporal-dead-zone crash.
const resolvedTrustProxy = resolveTrustProxy(raw.TRUST_PROXY, isProduction);

if (resolvedTrustProxy !== false) {
  const hops = resolvedTrustProxy === true ? 'permissive (true)' : `${resolvedTrustProxy} hop(s)`;

  if (isProduction) {
    logger.warn(
      `[env] TRUST_PROXY is set to ${hops}. Confirm the deployment really sits behind exactly that many proxies that OVERWRITE X-Forwarded-For, otherwise rate limits can be spoofed.`
    );
  } else {
    logger.warn(
      `[env] TRUST_PROXY is set to ${hops} in development. Directly reachable servers cannot validate X-Forwarded-For, so rate limits are bypassable — leave it false locally.`
    );
  }
}

const corsOrigins = parseOrigins(raw.CORS_ORIGINS);

if (corsOrigins.includes('*')) {
  if (isProduction) {
    logger.warn('[env] CORS_ORIGINS=* in production. Set a real allow-list before going live.');
  } else {
    // Credentialed cross-origin requests are switched off automatically for a
    // wildcard policy (see config/cors.js), so this is informational.
    logger.warn('[env] CORS_ORIGINS=* — any origin is accepted, with credentialed requests disabled (development only).');
  }
}

const config = Object.freeze({
  env: raw.NODE_ENV,
  isProduction,
  isDevelopment: raw.NODE_ENV === 'development',
  isTest: raw.NODE_ENV === 'test',
  strictEnv,
  logLevel: raw.LOG_LEVEL,

  port: raw.PORT,
  trustProxy: resolvedTrustProxy,
  shutdownTimeoutMs: raw.SHUTDOWN_TIMEOUT_MS,

  mongo: Object.freeze({
    uri: raw.MONGO_URI,
    // Always resolved, never left to the driver's "test" default.
    dbName: databaseName.name,
    dbNameFromUri: databaseName.explicit,
    maxPoolSize: raw.MONGO_MAX_POOL_SIZE,
    minPoolSize: Math.min(raw.MONGO_MIN_POOL_SIZE, raw.MONGO_MAX_POOL_SIZE),
    retries: raw.MONGO_CONNECT_RETRIES,
    retryBaseDelayMs: raw.MONGO_RETRY_BASE_DELAY_MS,
    serverSelectionTimeoutMs: raw.MONGO_SERVER_SELECTION_TIMEOUT_MS,
    // Build indexes automatically in development only; production relies on
    // deliberate index creation so a stray schema change cannot lock a collection.
    autoIndex: !isProduction,
  }),

  jwt: Object.freeze({
    secret: raw.JWT_SECRET,
    expiresIn: raw.JWT_EXPIRES_IN,
  }),

  http: Object.freeze({
    corsOrigins,
    allowAllOrigins: corsOrigins.includes('*'),
    jsonBodyLimit: raw.JSON_BODY_LIMIT,
  }),

  rateLimit: Object.freeze({
    windowMs: raw.RATE_LIMIT_WINDOW_MS,
    max: raw.RATE_LIMIT_MAX,
    authMax: raw.AUTH_RATE_LIMIT_MAX,
    otpMax: raw.RATE_LIMIT_OTP_MAX,
    otpWindowMs: raw.RATE_LIMIT_OTP_WINDOW_MS,
    pinMax: raw.RATE_LIMIT_PIN_MAX,
    scamBusterMax: raw.RATE_LIMIT_SCAM_BUSTER_MAX,
    emergencyMax: raw.RATE_LIMIT_EMERGENCY_MAX,
    skipInTest: parseBoolean(raw.RATE_LIMIT_SKIP_IN_TEST, true),
  }),

  phone: Object.freeze({
    defaultCountryCode: raw.DEFAULT_PHONE_COUNTRY_CODE,
  }),

  nominees: Object.freeze({
    maxPerUser: raw.MAX_NOMINEES_PER_USER,
  }),

  analytics: Object.freeze({
    nearbyRadiusMeters: raw.ANALYTICS_NEARBY_RADIUS_METERS,
    recentWindowHours: raw.ANALYTICS_RECENT_WINDOW_HOURS,
  }),

  shieldPay: Object.freeze({
    suspiciousThreshold: raw.SHIELD_PAY_SUSPICIOUS_THRESHOLD,
    dangerThreshold: raw.SHIELD_PAY_DANGER_THRESHOLD,
    checkTtlSeconds: raw.SHIELD_PAY_RISK_CHECK_TTL_SECONDS,
    maxAmount: raw.SHIELD_PAY_MAX_AMOUNT,
  }),

  scamBuster: Object.freeze({
    maxImageBytes: raw.SCAM_BUSTER_MAX_IMAGE_BYTES,
    textMaxChars: raw.SCAM_BUSTER_TEXT_MAX_CHARS,
    storageMode: raw.SCAM_BUSTER_STORAGE_MODE,
    localStorageDir: raw.SCAM_BUSTER_LOCAL_STORAGE_DIR,
    inlineImageMaxBytes: raw.SCAM_BUSTER_INLINE_IMAGE_MAX_BYTES,
  }),

  gemini: Object.freeze({
    apiKey: raw.GEMINI_API_KEY,
    model: raw.GEMINI_MODEL,
    timeoutMs: raw.GEMINI_TIMEOUT_MS,
    configured: raw.GEMINI_API_KEY !== '',
  }),

  appConfig: Object.freeze({
    cacheTtlSeconds: raw.GLOBAL_CONFIG_CACHE_TTL_SECONDS,
  }),

  biometric: Object.freeze({
    sharedSecret: raw.BIOMETRIC_SHARED_SECRET,
    maxAssertionAgeSeconds: raw.BIOMETRIC_MAX_ASSERTION_AGE_SECONDS,
    // A short key is worse than no key: it looks configured while being cheap to
    // brute-force. Treat anything under 32 characters as unconfigured.
    configured: raw.BIOMETRIC_SHARED_SECRET.length >= 32,
  }),

  cloudinary: Object.freeze({
    cloudName: raw.CLOUDINARY_CLOUD_NAME,
    apiKey: raw.CLOUDINARY_API_KEY,
    apiSecret: raw.CLOUDINARY_API_SECRET,
    folder: raw.CLOUDINARY_FOLDER,
    timeoutMs: raw.CLOUDINARY_TIMEOUT_MS,
    configured: Boolean(raw.CLOUDINARY_CLOUD_NAME && raw.CLOUDINARY_API_KEY && raw.CLOUDINARY_API_SECRET),
  }),

  sos: Object.freeze({
    persistIntervalSeconds: raw.SOS_LOCATION_PERSIST_INTERVAL_SECONDS,
    historyLimit: raw.SOS_LOCATION_HISTORY_LIMIT,
    smsFallbackEnabled: parseBoolean(raw.SOS_SMS_FALLBACK_ENABLED, true),
    maxLocationUpdatesPerSecond: raw.SOS_MAX_LOCATION_UPDATES_PER_SECOND,
    trackingBaseUrl: raw.SOS_TRACKING_BASE_URL,
  }),

  fcm: Object.freeze({
    projectId: raw.FIREBASE_PROJECT_ID,
    clientEmail: raw.FIREBASE_CLIENT_EMAIL,
    // Service-account keys are stored in .env with literal \n escapes; the SDK
    // needs real newlines.
    privateKey: raw.FIREBASE_PRIVATE_KEY ? raw.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : '',
    configured: Boolean(raw.FIREBASE_PROJECT_ID && raw.FIREBASE_CLIENT_EMAIL && raw.FIREBASE_PRIVATE_KEY),
  }),

  socket: Object.freeze({
    maxConnectionsPerIp: raw.SOCKET_MAX_CONNECTIONS_PER_IP,
    maxConnections: raw.SOCKET_MAX_CONNECTIONS,
  }),

  otp: Object.freeze({
    length: raw.OTP_LENGTH,
    ttlSeconds: raw.OTP_TTL_SECONDS,
    maxAttempts: raw.OTP_MAX_ATTEMPTS,
    resendCooldownSeconds: raw.OTP_RESEND_COOLDOWN_SECONDS,
    maxSendsPerWindow: raw.OTP_MAX_SENDS_PER_WINDOW,
    sendWindowSeconds: raw.OTP_SEND_WINDOW_SECONDS,
    hashRounds: raw.OTP_HASH_ROUNDS,
    devMode: otpDevMode,
  }),

  bcrypt: Object.freeze({
    saltRounds: raw.BCRYPT_SALT_ROUNDS,
  }),

  sms: Object.freeze({
    provider: raw.SMS_PROVIDER,
    timeoutMs: raw.SMS_HTTP_TIMEOUT_MS,
    twilio: Object.freeze({
      accountSid: raw.TWILIO_ACCOUNT_SID,
      authToken: raw.TWILIO_AUTH_TOKEN,
      phoneNumber: raw.TWILIO_PHONE_NUMBER,
    }),
    fast2sms: Object.freeze({
      apiKey: raw.FAST2SMS_API_KEY,
      route: raw.FAST2SMS_ROUTE,
    }),
  }),

  deferredKeys: Object.freeze({
    missing: missingDeferred.map((entry) => entry.key),
  }),
});

// --- Phase 2 operational warnings ------------------------------------------
if (otpDevMode) {
  if (isProduction) {
    logger.error(
      '[env] OTP_DEV_MODE=true in production AND ALLOW_OTP_DEV_MODE_IN_PRODUCTION=true: POST /api/v1/auth/send-otp returns live OTPs in the HTTP response. Turn both off before shipping.'
    );
  } else {
    logger.warn('[env] OTP_DEV_MODE=true — OTPs are returned in the API response instead of being texted (development only).');
  }
}

// --- Phase 1 operational warnings ------------------------------------------
if (config.socket.maxConnectionsPerIp === 0 && config.socket.maxConnections === 0) {
  logger.warn(
    '[env] Both Socket.io connection caps are disabled (SOCKET_MAX_CONNECTIONS_PER_IP=0, SOCKET_MAX_CONNECTIONS=0): any client may open unlimited sockets.'
  );
}

const hasTwilio = Boolean(config.sms.twilio.accountSid && config.sms.twilio.authToken && config.sms.twilio.phoneNumber);
const hasFast2Sms = Boolean(config.sms.fast2sms.apiKey);

if (!hasTwilio && !hasFast2Sms && !otpDevMode) {
  logger.error(
    '[env] No SMS provider credentials and OTP_DEV_MODE is off: /send-otp will answer 503 because neither Twilio nor Fast2SMS can deliver a code.'
  );
} else if (!hasTwilio && !hasFast2Sms) {
  logger.warn('[env] No Twilio/Fast2SMS credentials — SMS is simulated by OTP_DEV_MODE until they are added.');
}

// --- Phase 4 operational warnings ------------------------------------------
if (!config.fcm.configured) {
  logger.warn(
    '[env] FCM is not configured (FIREBASE_PROJECT_ID / CLIENT_EMAIL / PRIVATE_KEY): SOS push notifications will be skipped and every guardian reachable by SMS will get the fallback text instead.'
  );
}

if (!config.fcm.configured && !hasTwilio && !hasFast2Sms) {
  logger.warn(
    '[env] No push and no SMS transport: an SOS will still be recorded and streamed to connected guardians, but nobody who is offline will be alerted.'
  );
}

// --- Phase 7 operational warnings ------------------------------------------
if (!config.gemini.configured) {
  logger.warn(
    '[env] GEMINI_API_KEY is not set: scam scans will use the deterministic OFFLINE heuristic screen (analysisSource=HEURISTIC). Add the key for real AI analysis.'
  );
}

if (!config.cloudinary.configured) {
  logger.warn(
    `[env] Cloudinary credentials are incomplete: screenshots will be stored on local disk under "${config.scamBuster.localStorageDir}" (imageStorage=LOCAL). This is fine for development and ephemeral on most deployed hosts.`
  );
}

// --- Phase 8 operational warnings ------------------------------------------
if (!config.biometric.configured) {
  const reason =
    raw.BIOMETRIC_SHARED_SECRET === ''
      ? 'is not set'
      : `is only ${raw.BIOMETRIC_SHARED_SECRET.length} characters (needs at least 32)`;
  logger.warn(
    `[env] BIOMETRIC_SHARED_SECRET ${reason}: POST /api/v1/emergency/biometric-verify will answer 503, so emergency mode cannot be unlocked. Set it to the same value provisioned in the Flutter app.`
  );
}

module.exports = { config };
