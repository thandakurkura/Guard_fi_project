'use strict';

/**
 * GuardFi — Phase 2 verification harness
 *
 * Proves phone+OTP authentication end to end against a throwaway in-memory
 * MongoDB: real Express, real Mongoose, real bcrypt, real rate-limit middleware,
 * real index creation. Your .env, your Atlas cluster and your SMS credits are
 * never touched.
 *
 * It boots TWO servers on purpose:
 *   • Server A (OTP_DEV_MODE=true, limits skipped) — functional behaviour.
 *   • Server B (OTP_DEV_MODE=false, limits ON, tiny budgets) — that a code is
 *     never handed back when development mode is off, and that the limiters
 *     really do answer 429.
 * A third group of checks runs in-process, because provider transports are
 * injected there rather than reached over the network.
 *
 * Run:  npm run verify:phase2
 * Exit: 0 = every check passed, 1 = at least one failed, 2 = harness cannot run.
 */

// --- environment for THIS process (must precede every local require) --------
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = process.env.VERIFY_LOG_LEVEL || 'error';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'verify-phase2-secret-'.padEnd(48, '0');
process.env.CORS_ORIGINS = '*';
process.env.STRICT_ENV = 'false';
process.env.TRUST_PROXY = 'false';
delete process.env.PORT;

// Placeholder until the in-memory server is up, so dotenv can never make this
// run talk to the real Atlas cluster.
process.env.MONGO_URI = 'mongodb://127.0.0.1:27017/guardfi-phase2-placeholder';

// Deterministic "no SMS credentials" world: dotenv will not overwrite keys that
// already exist, so blanking them here disables every real transport.
process.env.OTP_DEV_MODE = 'true';
process.env.SMS_PROVIDER = 'auto';
process.env.TWILIO_ACCOUNT_SID = '';
process.env.TWILIO_AUTH_TOKEN = '';
process.env.TWILIO_PHONE_NUMBER = '';
process.env.FAST2SMS_API_KEY = '';
// Cooldown ON for the in-process checks; both spawned servers override it to 0.
process.env.OTP_RESEND_COOLDOWN_SECONDS = '30';

const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const SERVER_A_PORT = Number(process.env.VERIFY_APP_PORT || 4321);
const SERVER_B_PORT = Number(process.env.VERIFY_THROTTLE_PORT || 4323);
const BASE_A = `http://127.0.0.1:${SERVER_A_PORT}`;
const BASE_B = `http://127.0.0.1:${SERVER_B_PORT}`;

const TEST_PHONE = '+919876512345';
const SERVER_B_PHONE = '+919876499945';

let mongo = null;
/** @type {{ label: string, child: import('node:child_process').ChildProcess, output: string[] }[]} */
const servers = [];
const results = [];

function record(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => results.push({ name, ok: true }))
    .catch((error) => results.push({ name, ok: false, error: error.message }));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function call(base, pathname, { method = 'POST', body, headers = {} } = {}) {
  const init = { method, headers: { ...headers } };

  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const response = await fetch(`${base}${pathname}`, init);
  const text = await response.text();
  let parsed = null;

  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }

  return { status: response.status, body: parsed, text, headers: response.headers };
}

const post = (base, pathname, body) => call(base, pathname, { method: 'POST', body });
const get = (base, pathname) => call(base, pathname, { method: 'GET' });

async function waitForHealth(base, label, timeoutMs = 40_000) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no response';

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${base}/health`);
      const body = await response.json();
      if (response.status === 200 && body?.data?.database?.connected === true) return body;
      last = `status=${response.status} db=${body?.data?.database?.state}`;
    } catch (error) {
      last = error.message;
    }
    await sleep(400);
  }

  throw new Error(`${label} never became healthy within ${timeoutMs}ms (last: ${last})`);
}

function spawnServer({ label, port, env }) {
  const child = spawn(process.execPath, [path.join(PROJECT_ROOT, 'server.js')], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      LOG_LEVEL: 'error',
      PORT: String(port),
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const entry = { label, child, output: [] };
  child.stdout.on('data', (chunk) => entry.output.push(chunk.toString()));
  child.stderr.on('data', (chunk) => entry.output.push(chunk.toString()));
  servers.push(entry);

  return entry;
}

async function stopServers() {
  for (const entry of servers) {
    if (entry.child.exitCode === null) {
      entry.child.kill();
      await sleep(200);
    }
  }

  if (results.some((result) => !result.ok)) {
    for (const entry of servers) {
      if (entry.output.length === 0) continue;
      console.error(`\n--- ${entry.label} output ---`);
      console.error(entry.output.join('').split('\n').slice(-15).join('\n'));
    }
  }
}

// ===========================================================================
// Server A — functional behaviour (OTP_DEV_MODE=true, limiters skipped)
// ===========================================================================
async function runHttpChecks() {
  const User = require('../models/User');
  const Otp = require('../models/Otp');

  let issuedCode = null;
  let issuedPhone = null;

  await record('send-otp: 10-digit national number → 200, E.164 normalised, dev-mode code', async () => {
    const { status, body } = await post(BASE_A, '/api/v1/auth/send-otp', { phone: '9876500001' });

    assert.equal(status, 200);
    assert.equal(body.success, true);
    assert.equal(body.errors, null);
    assert.equal(body.data.phone, '+919876500001');
    assert.equal(body.data.devMode, true);
    assert.match(body.data.otp, /^\d{6}$/);
    assert.equal(body.data.attemptsAllowed, 3);
    assert.equal(body.data.delivery.delivered, false);
    assert.equal(body.data.delivery.provider, 'none');
    assert.ok(body.data.expiresInSeconds > 290 && body.data.expiresInSeconds <= 300, `expiresInSeconds=${body.data.expiresInSeconds}`);
  });

  await record('send-otp: stores only a bcrypt hash — the code is never persisted', async () => {
    const { body } = await post(BASE_A, '/api/v1/auth/send-otp', { phone: '9876500011' });
    issuedPhone = body.data.phone;
    issuedCode = body.data.otp;

    const raw = await Otp.findOne({ phone: issuedPhone }).select('+otpHash');
    assert.ok(raw, 'no Otp document was written');
    assert.notEqual(raw.otpHash, issuedCode);
    assert.match(raw.otpHash, /^\$2[aby]\$/, 'expected a bcrypt hash');
    assert.equal(await bcrypt.compare(issuedCode, raw.otpHash), true);
    assert.equal(raw.attempts, 0);
    assert.ok(!JSON.stringify(raw.toObject()).includes(issuedCode), 'the plaintext code is present in the document');

    const withoutExplicitSelect = await Otp.findOne({ phone: issuedPhone });
    assert.equal(withoutExplicitSelect.otpHash, undefined, 'otpHash must be select:false');
  });

  await record('send-otp: invalid phone → 400 envelope with a field error', async () => {
    const { status, body } = await post(BASE_A, '/api/v1/auth/send-otp', { phone: 'not-a-phone' });

    assert.equal(status, 400);
    assert.equal(body.success, false);
    assert.equal(body.data, null);
    assert.ok(Array.isArray(body.errors) && body.errors.length > 0);
    assert.equal(body.errors[0].field, 'phone');
    assert.match(body.errors[0].message, /valid phone number/i);
  });

  await record('send-otp: empty body → 400 "phone is required"', async () => {
    const { status, body } = await post(BASE_A, '/api/v1/auth/send-otp', {});

    assert.equal(status, 400);
    assert.match(JSON.stringify(body.errors), /phone is required/);
  });

  await record('send-otp: phone sent as a JSON number (Dart int) is accepted', async () => {
    const { status, body } = await post(BASE_A, '/api/v1/auth/send-otp', { phone: 9876500002 });

    assert.equal(status, 200);
    assert.equal(body.data.phone, '+919876500002');
  });

  await record('send-otp: every spelling of one number collapses to one identity', async () => {
    for (const variant of ['+91 98765 00003', '0091 9876500003', '09876500003', '9876500003']) {
      const { status, body } = await post(BASE_A, '/api/v1/auth/send-otp', { phone: variant });
      assert.equal(status, 200, `variant "${variant}" was rejected: ${JSON.stringify(body)}`);
      assert.equal(body.data.phone, '+919876500003', `variant "${variant}" normalised to ${body.data.phone}`);
    }
  });

  await record('verify-otp: correct code → 200, JWT, user upserted, secrets never returned', async () => {
    const issued = await post(BASE_A, '/api/v1/auth/send-otp', { phone: TEST_PHONE });
    const { status, body } = await post(BASE_A, '/api/v1/auth/verify-otp', {
      phone: TEST_PHONE,
      otp: issued.body.data.otp,
      name: 'Phase Two User',
      fcmToken: 'fcm-token-phase2',
    });

    assert.equal(status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.isNewUser, true);
    assert.equal(body.data.tokenType, 'Bearer');
    assert.equal(body.data.expiresIn, '7d');
    assert.equal(body.data.user.phone, TEST_PHONE);
    assert.equal(body.data.user.name, 'Phase Two User');
    assert.equal(body.data.user.role, 'user');
    assert.equal(body.data.user.isEmergencyMode, false);
    assert.equal(body.data.user.securityPinHash, undefined, 'securityPinHash leaked');
    assert.equal(body.data.user.fcmToken, undefined, 'fcmToken leaked');

    const decoded = jwt.verify(body.data.token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
    assert.equal(decoded.sub, String(body.data.user._id));
    assert.equal(decoded.phone, TEST_PHONE);
    assert.equal(decoded.role, 'user');
    assert.ok(decoded.jti, 'expected a jti claim');
    assert.equal(decoded.exp - decoded.iat, 604_800, 'expected a 7-day token');

    // The token response hides the token, but the database must have stored it.
    const stored = await User.findById(decoded.sub).select('+fcmToken +securityPinHash');
    assert.equal(stored.fcmToken, 'fcm-token-phase2');
    assert.equal(stored.securityPinHash, null);
    assert.ok(stored.lastLoginAt instanceof Date);
  });

  await record('verify-otp: the code is single-use', async () => {
    const issued = await post(BASE_A, '/api/v1/auth/send-otp', { phone: '+919876522001' });
    const code = issued.body.data.otp;

    const first = await post(BASE_A, '/api/v1/auth/verify-otp', { phone: '+919876522001', otp: code });
    assert.equal(first.status, 200);

    const replay = await post(BASE_A, '/api/v1/auth/verify-otp', { phone: '+919876522001', otp: code });
    assert.equal(replay.status, 400);
    assert.match(JSON.stringify(replay.body.errors), /OTP_NOT_REQUESTED/);
  });

  await record('verify-otp: second sign-in reuses the account and updates the profile', async () => {
    const first = await post(BASE_A, '/api/v1/auth/send-otp', { phone: TEST_PHONE });
    const login = await post(BASE_A, '/api/v1/auth/verify-otp', {
      phone: TEST_PHONE,
      otp: first.body.data.otp,
      name: 'Phase Two Renamed',
    });

    assert.equal(login.status, 200);
    assert.equal(login.body.data.isNewUser, false);
    assert.equal(login.body.data.user.name, 'Phase Two Renamed');
    assert.equal(await User.countDocuments({ phone: TEST_PHONE }), 1, 'a duplicate user was created');
  });

  await record('verify-otp: a differently spelled phone reaches the SAME account', async () => {
    const issued = await post(BASE_A, '/api/v1/auth/send-otp', { phone: '09876512345' });
    const login = await post(BASE_A, '/api/v1/auth/verify-otp', { phone: '+91 98765 12345', otp: issued.body.data.otp });

    assert.equal(login.status, 200);
    assert.equal(login.body.data.user.phone, TEST_PHONE);
    assert.equal(await User.countDocuments({ phone: TEST_PHONE }), 1);
  });

  await record('verify-otp: number with no pending code → 400 OTP_NOT_REQUESTED', async () => {
    const { status, body } = await post(BASE_A, '/api/v1/auth/verify-otp', { phone: '+919000000001', otp: '123456' });

    assert.equal(status, 400);
    assert.equal(body.errors[0].code, 'OTP_NOT_REQUESTED');
  });

  await record('verify-otp: wrong code burns an attempt and locks after OTP_MAX_ATTEMPTS', async () => {
    const phone = '+919876599991';
    const issued = await post(BASE_A, '/api/v1/auth/send-otp', { phone });
    const rightCode = issued.body.data.otp;
    const wrongCode = rightCode === '000000' ? '111111' : '000000';

    const first = await post(BASE_A, '/api/v1/auth/verify-otp', { phone, otp: wrongCode });
    assert.equal(first.status, 400);
    assert.equal(first.body.errors[0].code, 'OTP_INVALID');
    assert.equal(first.body.errors[0].remainingAttempts, 2);

    const second = await post(BASE_A, '/api/v1/auth/verify-otp', { phone, otp: wrongCode });
    assert.equal(second.status, 400);
    assert.equal(second.body.errors[0].remainingAttempts, 1);

    const third = await post(BASE_A, '/api/v1/auth/verify-otp', { phone, otp: wrongCode });
    assert.equal(third.status, 429);
    assert.equal(third.body.errors[0].code, 'OTP_LOCKED');

    const stored = await Otp.findOne({ phone });
    assert.equal(stored.attempts, 3, 'the attempt counter must stop at the cap');

    // The correct code must not sneak through a locked record.
    const withRightCode = await post(BASE_A, '/api/v1/auth/verify-otp', { phone, otp: rightCode });
    assert.equal(withRightCode.status, 429);
    assert.equal(withRightCode.body.errors[0].code, 'OTP_LOCKED');
  });

  await record('send-otp: requesting a new code unlocks the number and kills the old code', async () => {
    const phone = '+919876599991';
    const locked = await post(BASE_A, '/api/v1/auth/verify-otp', { phone, otp: '000000' });
    assert.equal(locked.status, 429, 'the number should still be locked at this point');

    const refreshed = await post(BASE_A, '/api/v1/auth/send-otp', { phone });
    const newCode = refreshed.body.data.otp;

    const stored = await Otp.findOne({ phone });
    assert.equal(stored.attempts, 0, 'a resend must reset the attempt counter');

    const login = await post(BASE_A, '/api/v1/auth/verify-otp', { phone, otp: newCode });
    assert.equal(login.status, 200, `expected the fresh code to work, got ${JSON.stringify(login.body)}`);
  });

  await record('verify-otp: an aged code is rejected as expired (TTL enforced in code, not just by the sweeper)', async () => {
    const phone = '+919876599992';
    const issued = await post(BASE_A, '/api/v1/auth/send-otp', { phone });
    const code = issued.body.data.otp;

    await Otp.updateOne({ phone }, { $set: { createdAt: new Date(Date.now() - 6 * 60 * 1000) } });

    const { status, body } = await post(BASE_A, '/api/v1/auth/verify-otp', { phone, otp: code });
    assert.equal(status, 400);
    assert.equal(body.errors[0].code, 'OTP_EXPIRED', `unexpected body ${JSON.stringify(body)}`);
    assert.equal(await Otp.countDocuments({ phone }), 0, 'an expired code must be deleted');
  });

  await record('verify-otp: malformed code → 400 from the validator, before any database work', async () => {
    const { status, body } = await post(BASE_A, '/api/v1/auth/verify-otp', { phone: TEST_PHONE, otp: 'abc' });

    assert.equal(status, 400);
    assert.equal(body.errors[0].field, 'otp');
  });

  await record('verify-otp: an 8-digit numeric code (Dart int, wrong length) → 400', async () => {
    const { status, body } = await post(BASE_A, '/api/v1/auth/verify-otp', { phone: TEST_PHONE, otp: 12_345_678 });

    assert.equal(status, 400);
    assert.equal(body.errors[0].field, 'otp');
  });

  await record('verify-otp: a JSON array body → 400, never a crash', async () => {
    const response = await fetch(`${BASE_A}/api/v1/auth/verify-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify([{ phone: TEST_PHONE }]),
    });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.equal(body.success, false);
    assert.equal(body.data, null);
  });

  await record('send-otp: phone as an array or an object → 400 with a field error', async () => {
    for (const phone of [['+919876500001'], { nested: true }, true]) {
      const { status, body } = await post(BASE_A, '/api/v1/auth/send-otp', { phone });

      assert.equal(status, 400, `phone ${JSON.stringify(phone)} was accepted`);
      assert.equal(body.errors[0].field, 'phone');
    }
  });

  await record('send-otp: a missing Content-Type is still validated, not a crash', async () => {
    // fetch labels a string body as text/plain, so express.json never parses it
    // and Express 5 leaves req.body undefined — the validator must cope.
    const response = await fetch(`${BASE_A}/api/v1/auth/send-otp`, { method: 'POST', body: '{"phone":"9876500004"}' });
    const body = await response.json();

    assert.equal(response.status, 400);
    assert.match(JSON.stringify(body.errors), /phone is required/);
  });

  await record('verify-otp: oversized name and fcmToken → 400 naming both fields', async () => {
    const phone = '+919876522003';
    const issued = await post(BASE_A, '/api/v1/auth/send-otp', { phone });
    const { status, body } = await post(BASE_A, '/api/v1/auth/verify-otp', {
      phone,
      otp: issued.body.data.otp,
      name: 'x'.repeat(81),
      fcmToken: 'y'.repeat(513),
    });

    assert.equal(status, 400);
    assert.deepEqual(
      body.errors.map((error) => error.field).sort(),
      ['fcmToken', 'name']
    );
  });

  await record('api/v1: reports the auth module as mounted', async () => {
    const { status, body } = await get(BASE_A, '/api/v1');

    assert.equal(status, 200);
    // Cumulative across phases: Phase 3 added /nominees alongside /auth.
    assert.ok(body.data.mountedModules.includes('auth'), JSON.stringify(body.data.mountedModules));
    assert.ok(body.data.mountedModules.includes('nominees'));
  });

  await record('api/v1/auth/send-otp: GET is not mounted → 404 envelope', async () => {
    const { status, body } = await get(BASE_A, '/api/v1/auth/send-otp');

    assert.equal(status, 404);
    assert.equal(body.success, false);
  });
}

// ===========================================================================
// Server B — no code leaks without DEV_MODE, and the limiters truly bite
// ===========================================================================
async function runThrottleChecks() {
  const Otp = require('../models/Otp');

  await record('send-otp: OTP_DEV_MODE=false + no SMS transport → 503, code never echoed', async () => {
    const { status, body, text } = await post(BASE_B, '/api/v1/auth/send-otp', { phone: SERVER_B_PHONE });

    assert.equal(status, 503);
    assert.equal(body.success, false);
    assert.equal(body.data, null);
    assert.match(body.message, /could not send a verification code/i);
    assert.ok(!/\b\d{6}\b/.test(text), `a 6-digit code leaked in the error response: ${text}`);
    assert.ok(!text.includes('otp"'), 'the word otp appeared in the payload');
  });

  await record('send-otp: an undeliverable code is deleted instead of left at rest', async () => {
    assert.equal(await Otp.countDocuments({ phone: SERVER_B_PHONE }), 0);
  });

  await record('send-otp: RATE_LIMIT_OTP_MAX is enforced with 429 + Retry-After', async () => {
    const second = await post(BASE_B, '/api/v1/auth/send-otp', { phone: SERVER_B_PHONE });
    assert.equal(second.status, 503, 'the second request should still be allowed through the limiter');

    const third = await post(BASE_B, '/api/v1/auth/send-otp', { phone: SERVER_B_PHONE });
    assert.equal(third.status, 429, `expected 429, got ${third.status}`);
    assert.equal(third.body.success, false);
    assert.equal(third.body.data, null);
    assert.match(third.body.message, /verification codes/i);
    assert.ok(third.headers.get('ratelimit') || third.headers.get('ratelimit-policy'), 'RateLimit headers missing');
    assert.ok(Number(third.headers.get('retry-after')) > 0, 'Retry-After header missing');
  });

  await record('verify-otp: AUTH_RATE_LIMIT_MAX is enforced with 429', async () => {
    const first = await post(BASE_B, '/api/v1/auth/verify-otp', { phone: SERVER_B_PHONE, otp: '000000' });
    assert.equal(first.status, 400, 'the first attempt should reach the handler');

    const second = await post(BASE_B, '/api/v1/auth/verify-otp', { phone: SERVER_B_PHONE, otp: '000000' });
    assert.equal(second.status, 400);

    const third = await post(BASE_B, '/api/v1/auth/verify-otp', { phone: SERVER_B_PHONE, otp: '000000' });
    assert.equal(third.status, 429);
    assert.match(third.body.message, /authentication attempts/i);
  });
}

// ===========================================================================
// Models — indexes, defaults and defence in depth
// ===========================================================================
async function runModelChecks() {
  const User = require('../models/User');
  const Otp = require('../models/Otp');

  await record('model: users.phone carries a unique index', async () => {
    await User.init();
    const indexes = await User.collection.indexes();
    const phoneIndex = indexes.find((index) => index.key && index.key.phone === 1);

    assert.ok(phoneIndex, `no phone index found (${JSON.stringify(indexes.map((i) => i.key))})`);
    assert.equal(phoneIndex.unique, true);
  });

  await record('model: users.lastKnownLocation carries a 2dsphere index', async () => {
    const indexes = await User.collection.indexes();
    const geoIndex = indexes.find((index) => index.key && index.key.lastKnownLocation === '2dsphere');

    assert.ok(geoIndex, `no 2dsphere index found (${JSON.stringify(indexes.map((i) => i.key))})`);
  });

  await record('model: otps.createdAt carries a TTL index of OTP_TTL_SECONDS', async () => {
    await Otp.init();
    const indexes = await Otp.collection.indexes();
    const ttlIndex = indexes.find((index) => index.key && index.key.createdAt === 1);

    assert.ok(ttlIndex, 'no createdAt index found');
    assert.equal(ttlIndex.expireAfterSeconds, 300);
  });

  await record('model: a duplicate phone number is rejected with E11000', async () => {
    await User.create({ phone: '+919876577001' });

    await assert.rejects(
      () => User.create({ phone: '+919876577001' }),
      (error) => error.code === 11_000
    );
  });

  await record('model: an invalid phone number is rejected by the schema', async () => {
    await assert.rejects(
      () => User.create({ phone: '98765' }),
      (error) => error.name === 'ValidationError'
    );
    await assert.rejects(
      () => User.create({ phone: '+91abcde' }),
      (error) => error.name === 'ValidationError'
    );
  });

  await record('model: securityPinHash and fcmToken never come back from a default query', async () => {
    const created = await User.create({
      phone: '+919876577002',
      securityPinHash: await bcrypt.hash('1234', 8),
      fcmToken: 'token-x',
    });

    const loaded = await User.findById(created._id);
    assert.equal(loaded.securityPinHash, undefined);
    assert.equal(loaded.fcmToken, undefined);

    const explicit = await User.findById(created._id).select('+securityPinHash +fcmToken');
    assert.match(explicit.securityPinHash, /^\$2[aby]\$/);
    assert.equal(await bcrypt.compare('1234', explicit.securityPinHash), true);
    assert.equal(explicit.fcmToken, 'token-x');

    const json = explicit.toJSON();
    assert.equal(json.securityPinHash, undefined, 'the JSON transform must strip the PIN hash');
    assert.equal(json.fcmToken, undefined, 'the JSON transform must strip the FCM token');
  });

  await record('model: defaults are role=user and isEmergencyMode=false', async () => {
    const user = await User.create({ phone: '+919876577003' });

    assert.equal(user.role, 'user');
    assert.equal(user.isEmergencyMode, false);
    assert.equal(user.name, null);
  });

  await record('model: GeoJSON lastKnownLocation round-trips and rejects bad points', async () => {
    const user = await User.create({
      phone: '+919876577004',
      lastKnownLocation: { type: 'Point', coordinates: [73.8567, 18.5204] },
    });

    const loaded = await User.findById(user._id);
    assert.equal(loaded.lastKnownLocation.type, 'Point');
    assert.deepEqual([...loaded.lastKnownLocation.coordinates], [73.8567, 18.5204]);

    await assert.rejects(
      () => User.create({ phone: '+919876577005', lastKnownLocation: { type: 'Point', coordinates: [200, 91] } }),
      (error) => error.name === 'ValidationError'
    );
    await assert.rejects(
      () => User.create({ phone: '+919876577006', lastKnownLocation: { type: 'Point', coordinates: [1, 2, 3] } }),
      (error) => error.name === 'ValidationError'
    );
  });

  await record('model: Otp.upsertForPhone replaces the code, resets attempts, keeps one document', async () => {
    const phone = '+919876577007';
    const first = await Otp.upsertForPhone(phone, 'hash-one');
    await Otp.registerFailedAttempt(first._id);
    await Otp.registerFailedAttempt(first._id);

    const second = await Otp.upsertForPhone(phone, 'hash-two');
    assert.equal(second.attempts, 0);

    const raw = await Otp.findOne({ phone }).select('+otpHash');
    assert.equal(raw.otpHash, 'hash-two');
    assert.equal(raw._id.toString(), first._id.toString(), 'the document should be replaced in place');
    assert.equal(await Otp.countDocuments({ phone }), 1);
  });

  await record('model: the attempt counter cannot exceed the cap, even in a burst', async () => {
    const doc = await Otp.upsertForPhone('+919876577009', 'hash');

    const outcomes = await Promise.all(Array.from({ length: 10 }, () => Otp.registerFailedAttempt(doc._id)));
    const stored = await Otp.findById(doc._id);

    assert.equal(stored.attempts, 3, `counter reached ${stored.attempts}`);
    // Exactly two calls may observe a counter below the cap (values 1 and 2);
    // every other call — including the one that lands on 3 — must report locked.
    assert.equal(outcomes.filter((outcome) => outcome.attempts < 3).length, 2, 'more than two increments were applied');
    assert.equal(outcomes.filter((outcome) => outcome.locked).length, 8, 'the final increment and the refusals must report locked');
  });

  await record('otp: the test server can accelerate its TTL monitor', async () => {
    const mongoose = require('mongoose');
    const result = await mongoose.connection.db.admin().command({ setParameter: 1, ttlMonitorSleepSecs: 1 });

    assert.equal(result.ok, 1);
  });

  await record('otp: MongoDB itself deletes an expired code (TTL sweeper observed)', async () => {
    const mongoose = require('mongoose');
    const Otp = require('../models/Otp');
    const phone = '+919876577011';

    await Otp.upsertForPhone(phone, 'ttl-sweeper-probe');
    // Age it past the 300s window without waiting five minutes.
    await Otp.updateOne({ phone }, { $set: { createdAt: new Date(Date.now() - 400_000) } });
    assert.equal(await Otp.countDocuments({ phone }), 1, 'the probe document should exist before the sweep');

    // The raw collection is checked so this is the server deleting the document,
    // not Mongoose filtering it out.
    const deadline = Date.now() + 75_000;
    let remaining = 1;

    while (Date.now() < deadline) {
      remaining = await mongoose.connection.db.collection('otps').countDocuments({ phone });
      if (remaining === 0) break;
      await sleep(500);
    }

    assert.equal(remaining, 0, 'the TTL monitor never removed the expired code');
  });

  await record('model: isExpired() enforces the TTL window in application code', async () => {
    const doc = await Otp.upsertForPhone('+919876577010', 'hash');
    assert.equal(doc.isExpired(), false);
    assert.ok(doc.secondsUntilExpiry() > 0);

    await Otp.updateOne({ _id: doc._id }, { $set: { createdAt: new Date(Date.now() - 301_000) } });
    const aged = await Otp.findById(doc._id);

    assert.equal(aged.isExpired(), true);
    assert.equal(aged.secondsUntilExpiry(), 0);
  });
}

// ===========================================================================
// SMS transports — injected, so no credentials and no network are needed
// ===========================================================================
async function runSmsChecks() {
  const sms = require('../services/smsService');

  const emptyTwilio = { accountSid: '', authToken: '', phoneNumber: '' };
  const fakeTwilio = { accountSid: 'AC-fake', authToken: 'token-fake', phoneNumber: '+15005550006' };
  const base = { provider: 'auto', timeoutMs: 400, twilio: emptyTwilio, fast2sms: { apiKey: '', route: 'otp' } };

  await record('sms: resolveProvider — auto prefers Twilio, then Fast2SMS, else none', async () => {
    assert.equal(sms.resolveProvider(base), 'none');
    assert.equal(sms.resolveProvider({ ...base, fast2sms: { apiKey: 'k', route: 'otp' } }), 'fast2sms');
    assert.equal(
      sms.resolveProvider({ ...base, twilio: fakeTwilio, fast2sms: { apiKey: 'k', route: 'otp' } }),
      'twilio'
    );
  });

  await record('sms: resolveProvider never silently substitutes a pinned provider', async () => {
    assert.equal(sms.resolveProvider({ ...base, provider: 'twilio', fast2sms: { apiKey: 'k', route: 'otp' } }), 'none');
    assert.equal(sms.resolveProvider({ ...base, provider: 'fast2sms' }), 'none');
    assert.equal(sms.resolveProvider({ ...base, provider: 'none', twilio: fakeTwilio }), 'none');
  });

  await record('sms: sendOtpSms reports not_configured instead of throwing', async () => {
    const result = await sms.sendOtpSms({ phone: '+919876588001', otp: '123456' });

    assert.equal(result.delivered, false);
    assert.equal(result.provider, 'none');
    assert.equal(result.reason, 'not_configured');
  });

  await record('sms: Fast2SMS success path — OTP route, national number, auth header', async () => {
    const fast2sms = { ...base, provider: 'fast2sms', fast2sms: { apiKey: 'fake-key', route: 'otp' } };
    let captured = null;
    const fetchImpl = async (url, init) => {
      captured = { url, headers: init.headers, payload: JSON.parse(init.body), hasSignal: Boolean(init.signal) };
      return { ok: true, status: 200, text: async () => JSON.stringify({ return: true, request_id: 'req-1' }) };
    };

    const result = await sms.sendViaFast2Sms({ phone: '+919876588002', otp: '654321', sms: fast2sms, fetchImpl });

    assert.equal(result.delivered, true);
    assert.equal(result.provider, 'fast2sms');
    assert.equal(result.messageId, 'req-1');
    assert.equal(captured.url, sms.FAST2SMS_ENDPOINT);
    assert.equal(captured.headers.authorization, 'fake-key');
    assert.equal(captured.payload.route, 'otp');
    assert.equal(captured.payload.variables_values, '654321');
    assert.equal(captured.payload.numbers, '9876588002');
    assert.equal(captured.hasSignal, true, 'the request must carry an abort signal');
  });

  await record("sms: Fast2SMS 'q' route sends the composed message instead of variables", async () => {
    const fast2sms = { ...base, provider: 'fast2sms', fast2sms: { apiKey: 'fake-key', route: 'q' } };
    let payload = null;
    const fetchImpl = async (url, init) => {
      payload = JSON.parse(init.body);
      return { ok: true, status: 200, text: async () => JSON.stringify({ return: true }) };
    };

    const result = await sms.sendViaFast2Sms({ phone: '+919876588002', otp: '654321', sms: fast2sms, fetchImpl });

    assert.equal(result.delivered, true);
    assert.equal(payload.route, 'q');
    assert.match(payload.message, /654321/);
    assert.equal(payload.numbers, '9876588002');
  });

  await record('sms: Fast2SMS HTTP failure → delivered false with the status', async () => {
    const fast2sms = { ...base, provider: 'fast2sms', fast2sms: { apiKey: 'bad', route: 'otp' } };
    const fetchImpl = async () => ({
      ok: false,
      status: 401,
      text: async () => JSON.stringify({ return: false, message: 'Invalid authorization' }),
    });

    const result = await sms.sendViaFast2Sms({ phone: '+919876588003', otp: '111111', sms: fast2sms, fetchImpl });

    assert.equal(result.delivered, false);
    assert.equal(result.reason, 'http_401');
    assert.match(result.detail, /Invalid authorization/);
  });

  await record('sms: Fast2SMS provider rejection → provider_rejected', async () => {
    const fast2sms = { ...base, provider: 'fast2sms', fast2sms: { apiKey: 'k', route: 'otp' } };
    const fetchImpl = async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ return: false, message: 'OTP route not activated' }),
    });

    const result = await sms.sendViaFast2Sms({ phone: '+919876588004', otp: '111111', sms: fast2sms, fetchImpl });

    assert.equal(result.delivered, false);
    assert.equal(result.reason, 'provider_rejected');
  });

  await record('sms: network error → network_error, never a throw', async () => {
    const fast2sms = { ...base, provider: 'fast2sms', fast2sms: { apiKey: 'k', route: 'otp' } };
    const fetchImpl = async () => {
      throw new Error('getaddrinfo ENOTFOUND www.fast2sms.com');
    };

    const result = await sms.sendViaFast2Sms({ phone: '+919876588005', otp: '111111', sms: fast2sms, fetchImpl });

    assert.equal(result.delivered, false);
    assert.equal(result.reason, 'network_error');
  });

  await record('sms: a hanging provider is aborted by SMS_HTTP_TIMEOUT_MS', async () => {
    const fast2sms = { ...base, provider: 'fast2sms', timeoutMs: 300, fast2sms: { apiKey: 'k', route: 'otp' } };
    const fetchImpl = (url, init) =>
      new Promise((resolve, reject) => {
        init.signal.addEventListener('abort', () =>
          reject(Object.assign(new Error('The operation was aborted'), { name: 'AbortError' }))
        );
      });

    const startedAt = Date.now();
    const result = await sms.sendViaFast2Sms({ phone: '+919876588006', otp: '111111', sms: fast2sms, fetchImpl });
    const elapsedMs = Date.now() - startedAt;

    assert.equal(result.delivered, false);
    assert.equal(result.reason, 'timeout');
    assert.ok(elapsedMs < 3_000, `expected an abort well under 3s, took ${elapsedMs}ms`);
  });

  await record('sms: the OTP message carries the code and the validity window', async () => {
    const message = sms.otpMessageTemplate('424242');

    assert.match(message, /424242/);
    assert.match(message, /5 minute/);
  });

  await record('sms: Twilio success path returns the message sid', async () => {
    let sent = null;
    const clientFactory = () => ({
      messages: {
        create: async (payload) => {
          sent = payload;
          return { sid: 'SM1234567890' };
        },
      },
    });

    const result = await sms.sendViaTwilio({
      phone: '+919876588007',
      otp: '123456',
      sms: { ...base, twilio: fakeTwilio },
      clientFactory,
    });

    assert.equal(result.delivered, true);
    assert.equal(result.provider, 'twilio');
    assert.equal(result.messageId, 'SM1234567890');
    assert.equal(sent.from, fakeTwilio.phoneNumber);
    assert.match(sent.body, /123456/);
  });

  await record('sms: Twilio failure → delivered false with the provider error code', async () => {
    const clientFactory = () => ({
      messages: {
        create: async () => {
          throw Object.assign(new Error('Authenticate'), { code: 20_003 });
        },
      },
    });

    const result = await sms.sendViaTwilio({
      phone: '+919876588008',
      otp: '123456',
      sms: { ...base, twilio: fakeTwilio },
      clientFactory,
    });

    assert.equal(result.delivered, false);
    assert.equal(result.reason, 'twilio_20003');
    assert.match(result.detail, /Authenticate/);
  });

  await record('sms: a Twilio client factory that throws is contained', async () => {
    const result = await sms.sendViaTwilio({
      phone: '+919876588009',
      otp: '123456',
      sms: { ...base, twilio: fakeTwilio },
      clientFactory: () => {
        throw new Error('twilio module unavailable');
      },
    });

    assert.equal(result.delivered, false);
    assert.equal(result.reason, 'twilio_error');
  });
}

// ===========================================================================
// Tokens and in-process service rules (cooldown, hashing)
// ===========================================================================
async function runTokenAndServiceChecks() {
  const { config } = require('../config/env');
  const { signAccessToken } = require('../services/tokenService');
  const { issueOtp, consumeOtpAttempt, verifyOtpAndLogin } = require('../services/otpService');
  const Otp = require('../models/Otp');
  const SendThrottle = require('../models/SendThrottle');

  await record('model: sendthrottles.expiresAt carries a TTL index, so a window cannot leak rows', async () => {
    await SendThrottle.init();
    const indexes = await SendThrottle.collection.indexes();
    const ttlIndex = indexes.find((index) => index.key && index.key.expiresAt === 1);

    assert.ok(ttlIndex, `no expiresAt index found (${JSON.stringify(indexes.map((i) => i.key))})`);
    assert.equal(ttlIndex.expireAfterSeconds, 0, 'the document must go when expiresAt passes');
  });

  await record('token: claims, HS256 header and 7-day expiry', async () => {
    const auth = signAccessToken({
      _id: '507f1f77bcf86cd799439011',
      phone: '+919876500001',
      name: 'Token Probe',
      role: 'admin',
      isEmergencyMode: true,
    });

    const decoded = jwt.decode(auth.token, { complete: true });
    const payload = jwt.verify(auth.token, process.env.JWT_SECRET, { algorithms: ['HS256'] });

    assert.equal(decoded.header.alg, 'HS256');
    assert.equal(payload.sub, '507f1f77bcf86cd799439011');
    assert.equal(payload.phone, '+919876500001');
    assert.equal(payload.role, 'admin');
    assert.equal(payload.isEmergencyMode, true);
    assert.ok(payload.jti);
    assert.equal(payload.exp - payload.iat, 604_800);
    assert.equal(auth.tokenType, 'Bearer');
    assert.equal(auth.expiresIn, '7d');
    assert.ok(auth.expiresAt && new Date(auth.expiresAt).getTime() > Date.now());
  });

  await record('service: resend cooldown rejects a second code for the same number', async () => {
    const phone = '+919876533001';
    const first = await issueOtp({ phone });

    assert.equal(first.devMode, true);
    assert.match(first.otp, /^\d{6}$/);
    assert.equal(first.delivery.delivered, false);

    await assert.rejects(
      () => issueOtp({ phone }),
      (error) => error.statusCode === 429 && error.errors?.[0]?.code === 'OTP_COOLDOWN_ACTIVE'
    );
  });

  await record('service: once the cooldown lapses a new code replaces the old one', async () => {
    const phone = '+919876533002';
    const first = await issueOtp({ phone });


    await Otp.updateOne({ phone }, { $set: { createdAt: new Date(Date.now() - 31_000) } });
    const second = await issueOtp({ phone });

    assert.notEqual(second.otp, first.otp);
    assert.equal(second.attemptsAllowed, 3);

    const stored = await Otp.findOne({ phone }).select('+otpHash');
    assert.equal(await bcrypt.compare(second.otp, stored.otpHash), true);
    assert.equal(await bcrypt.compare(first.otp, stored.otpHash), false, 'the previous code must be dead');
  });

  await record('service: an exhausted code is refused before its hash is compared', async () => {
    const phone = '+919876533003';
    const issued = await issueOtp({ phone });

    await Otp.updateOne({ phone }, { $set: { attempts: 3 } });

    await assert.rejects(
      () => consumeOtpAttempt({ phone, otp: issued.otp }),
      (error) => error.statusCode === 429 && error.errors[0].code === 'OTP_LOCKED'
    );
  });

  await record('service: a successful login deletes the code and returns the upserted user', async () => {
    const phone = '+919876533004';
    const issued = await issueOtp({ phone });
    const { user, created } = await verifyOtpAndLogin({ phone, otp: issued.otp, name: 'Service Probe' });

    assert.equal(created, true);
    assert.equal(user.phone, phone);
    assert.equal(await Otp.countDocuments({ phone }), 0);

    const again = await verifyOtpAndLogin({ phone, otp: issued.otp }).catch((error) => error);
    assert.ok(again instanceof Error, 'replaying a consumed code must fail');
    assert.equal(again.statusCode, 400);
  });

  await record('service: a wrong code reports the remaining attempts from the database', async () => {
    const phone = '+919876533005';
    const issued = await issueOtp({ phone });
    const wrongCode = issued.otp === '000000' ? '111111' : '000000';

    const error = await consumeOtpAttempt({ phone, otp: wrongCode }).catch((failure) => failure);

    assert.equal(error.statusCode, 400);
    assert.equal(error.errors[0].remainingAttempts, 2);
    assert.equal((await Otp.findOne({ phone })).attempts, 1);
  });

  /**
   * Age the stored document past the resend cooldown but NOT past the send
   * window, so the send budget can be counted the way an attacker rotating IPs
   * would experience it: no cooldown trouble, one number, many codes.
   */
  const agePastCooldown = (phone) =>
    Otp.updateOne({ phone }, { $set: { createdAt: new Date(Date.now() - (config.otp.resendCooldownSeconds + 1) * 1000) } });

  /** Milliseconds of the send window that must still be ahead of us. */
  const windowMsRemaining = () => config.otp.sendWindowSeconds * 1000 - 60_000;

  await record('otp: the per-phone send budget stops a number being text-bombed', async () => {
    const cap = config.otp.maxSendsPerWindow;
    if (cap <= 0) return; // deliberately disabled by configuration

    const phone = '+919876544010';
    let last = null;

    for (let send = 0; send < cap; send += 1) {
      await agePastCooldown(phone);
      last = await issueOtp({ phone, callerIp: '127.0.0.1' });
    }

    // The response tells the honest client how much budget is left (0 here).
    assert.equal(last.sendsRemainingInWindow, 0);
    assert.equal((await SendThrottle.findOne({ phone })).sendCount, cap);

    await agePastCooldown(phone);

    await assert.rejects(
      () => issueOtp({ phone, callerIp: '127.0.0.1' }),
      (error) =>
        error.statusCode === 429 &&
        error.errors?.[0]?.code === 'OTP_SEND_LIMIT_REACHED' &&
        typeof error.errors[0].retryAfterSeconds === 'number'
    );

    // The blocked request must NOT have minted a usable code.
    const stored = await Otp.findOne({ phone }).select('+otpHash');
    assert.equal(await bcrypt.compare(last.otp, stored.otpHash), true, 'the last delivered code is still the valid one');
  });

  await record('otp: a lapsed send window starts the budget again', async () => {
    const cap = config.otp.maxSendsPerWindow;
    if (cap <= 0) return;

    const phone = '+919876544010'; // same number, budget already exhausted above
    const windowMs = config.otp.sendWindowSeconds * 1000;

    await agePastCooldown(phone);
    await SendThrottle.updateOne(
      { phone },
      { $set: { windowStartedAt: new Date(Date.now() - windowMs - 1000), expiresAt: new Date(Date.now() - 1000) } }
    );

    const result = await issueOtp({ phone, callerIp: '127.0.0.1' });

    assert.ok(result.otp, 'a new window must allow a new code');
    assert.equal((await SendThrottle.findOne({ phone })).sendCount, 1, 'the counter must restart with the window');
    assert.equal(result.sendsRemainingInWindow, cap - 1);
  });

  await record('otp: the send budget outlives the code it protects', async () => {
    const cap = config.otp.maxSendsPerWindow;
    if (cap <= 0) return;

    const phone = '+919876544030';

    for (let send = 0; send < cap; send += 1) {
      await agePastCooldown(phone);
      await issueOtp({ phone, callerIp: '127.0.0.1' });
    }

    // This is the regression this check exists for: the OTP document has its own
    // 300-second TTL, so if the counter lived on that document, the budget would
    // silently reset five minutes after the attacker stopped — making
    // "10 per hour" behave as "10 per five minutes". Delete the code the way the
    // TTL sweeper would and prove the budget is still counting.
    await Otp.deleteMany({ phone });

    await assert.rejects(
      () => issueOtp({ phone, callerIp: '127.0.0.1' }),
      (error) => error.statusCode === 429 && error.errors?.[0]?.code === 'OTP_SEND_LIMIT_REACHED'
    );

    const stored = await SendThrottle.findOne({ phone }).lean();
    assert.equal(stored.sendCount, cap);
    assert.ok(
      stored.expiresAt.getTime() > Date.now() + windowMsRemaining(),
      'the counter document must live until its window ends, not until the code expires'
    );
  });

  await record('otp: dev mode warns in the response when the caller is not on a private address', async () => {
    const localPhone = '+919876544020';
    const local = await issueOtp({ phone: localPhone, callerIp: '127.0.0.1' });

    assert.ok(local.otp, 'dev mode returns the code for a local caller');
    assert.equal(local.securityNotice, undefined, 'a laptop caller gets no warning');

    const publicPhone = '+919876544021';
    const remote = await issueOtp({ phone: publicPhone, callerIp: '203.0.113.7' });

    assert.ok(remote.otp, 'the code is still returned — the notice is what makes it loud');
    assert.match(remote.securityNotice, /OTP_DEV_MODE is on/);
    assert.match(remote.securityNotice, /203\.0\.113\.7/);
  });
}

// ===========================================================================
async function main() {
  let MongoMemoryServer;

  try {
    ({ MongoMemoryServer } = require('mongodb-memory-server'));
  } catch {
    console.error('✖ mongodb-memory-server is not installed. Run: npm install');
    process.exit(2);
  }

  console.log('▶ Starting throwaway in-memory MongoDB...');
  mongo = await MongoMemoryServer.create({
    instance: {
      dbName: 'guardfi-phase2-verify',
      // The first run downloads a ~78 MB mongod binary and cold-starts it.
      launchTimeout: 90_000,
    },
  });

  const uri = mongo.getUri('guardfi-phase2-verify');
  process.env.MONGO_URI = uri;

  // The harness process needs its own connection for database-level assertions.
  const { connectDatabase } = require('../config/db');
  await connectDatabase();

  try {
    console.log(`▶ Booting functional server on port ${SERVER_A_PORT}...`);
    spawnServer({
      label: 'server A (dev mode)',
      port: SERVER_A_PORT,
      env: { MONGO_URI: uri, OTP_DEV_MODE: 'true', OTP_RESEND_COOLDOWN_SECONDS: '0' },
    });
    await waitForHealth(BASE_A, 'server A');
    console.log('▶ Server A healthy. Running functional checks...\n');
    await runHttpChecks();

    console.log(`▶ Booting throttled server on port ${SERVER_B_PORT}...`);
    spawnServer({
      label: 'server B (throttled)',
      port: SERVER_B_PORT,
      env: {
        MONGO_URI: uri,
        OTP_DEV_MODE: 'false',
        OTP_RESEND_COOLDOWN_SECONDS: '0',
        RATE_LIMIT_SKIP_IN_TEST: 'false',
        RATE_LIMIT_OTP_MAX: '2',
        RATE_LIMIT_OTP_WINDOW_MS: '60000',
        AUTH_RATE_LIMIT_MAX: '2',
        RATE_LIMIT_MAX: '1000',
      },
    });
    await waitForHealth(BASE_B, 'server B');
    console.log('▶ Server B healthy. Running leak/rate-limit checks...\n');
    await runThrottleChecks();
  } catch (error) {
    results.push({ name: 'harness: both servers became healthy', ok: false, error: error.message });
  } finally {
    await stopServers();
  }

  await runModelChecks();
  await runSmsChecks();
  await runTokenAndServiceChecks();

  const passed = results.filter((result) => result.ok).length;
  const failed = results.filter((result) => !result.ok);

  console.log('');
  for (const result of results) {
    console.log(`${result.ok ? '  PASS' : '  FAIL'}  ${result.name}${result.ok ? '' : `\n          ↳ ${result.error}`}`);
  }
  console.log(`\n${passed}/${results.length} checks passed.`);

  if (mongo) await mongo.stop();

  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch(async (error) => {
  console.error('✖ Harness crashed:', error);
  await stopServers();
  if (mongo) await mongo.stop().catch(() => {});
  process.exit(1);
});
