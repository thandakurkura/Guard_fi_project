'use strict';

/**
 * GuardFi — Phase 1 verification harness
 *
 * Boots the REAL server against a throwaway in-memory MongoDB and asserts real
 * HTTP behaviour. It never touches your .env values or your Atlas cluster.
 *
 * Phase 2 note: authMiddleware now hydrates req.user from MongoDB, so the auth
 * checks seed a real user and prove the database (not the token) is
 * authoritative for identity, role and isEmergencyMode.
 *
 * Run:  npm run verify:phase1
 * Exit: 0 = every check passed, 1 = at least one failed, 2 = harness cannot run.
 */

// Must be set before any local module is required: config/env.js validates
// process.env, and dotenv never overwrites variables that already exist.
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = process.env.VERIFY_LOG_LEVEL || 'error';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'verify-phase1-secret-'.padEnd(48, '0');
process.env.CORS_ORIGINS = '*';
process.env.STRICT_ENV = 'false';
process.env.TRUST_PROXY = 'false';
// Limiters are normally skipped under NODE_ENV=test. This harness verifies them
// on purpose, so it re-enables them — the checks below stay far under the
// 300-request global budget.
process.env.RATE_LIMIT_SKIP_IN_TEST = 'false';
// This harness process loads config/env too (for the middleware probe) but never
// listens on PORT itself, and some shells export PORT=0. Let the schema default win.
delete process.env.PORT;

const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');

const express = require('express');
const jwt = require('jsonwebtoken');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const APP_PORT = Number(process.env.VERIFY_APP_PORT || 4321);
const PROBE_PORT = Number(process.env.VERIFY_PROBE_PORT || 4322);
const TRUST_PROBE_PORT = Number(process.env.VERIFY_TRUST_PROBE_PORT || 4326);
const PRODUCTION_PORT = Number(process.env.VERIFY_PRODUCTION_PORT || 4331);
const SOCKET_BUDGET_PORT = Number(process.env.VERIFY_SOCKET_PORT || 4333);
const BASE = `http://127.0.0.1:${APP_PORT}`;
const PROBE = `http://127.0.0.1:${PROBE_PORT}`;
const JWT_SECRET = process.env.JWT_SECRET;

const results = [];
let child = null;
let mongo = null;

function record(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => results.push({ name, ok: true }))
    .catch((error) => results.push({ name, ok: false, error: error.message }));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForHealth(base = BASE, label = 'server', timeoutMs = 30_000) {
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

function signToken(payload, options = {}) {
  return jwt.sign(payload, options.secret || JWT_SECRET, {
    algorithm: 'HS256',
    expiresIn: options.expiresIn ?? '5m',
    ...options.extra,
  });
}

/** Small Express app that exercises the real middlewares over real HTTP. */
function buildProbeApp() {
  const authMiddleware = require('../middlewares/authMiddleware');
  const { requireEmergencyMode, requireRoles } = require('../middlewares/rbacMiddleware');
  const { notFoundHandler, errorMiddleware } = require('../middlewares/errorMiddleware');
  const { assertValidObjectId } = require('../utils/validateObjectId');
  const ApiError = require('../utils/ApiError');
  const asyncHandler = require('../utils/asyncHandler');

  const probe = express();
  probe.use(express.json());

  probe.get('/protected', authMiddleware, (req, res) =>
    res.json({ success: true, id: req.user._id, phone: req.user.phone, role: req.user.role })
  );
  probe.get('/emergency', authMiddleware, requireEmergencyMode, (req, res) => res.json({ success: true }));
  probe.get('/admin', authMiddleware, requireRoles('admin'), (req, res) => res.json({ success: true }));

  probe.get(
    '/object-id/:id',
    asyncHandler(async (req, res) => {
      const id = assertValidObjectId(req.params.id, 'id');
      res.json({ success: true, id });
    })
  );

  probe.get(
    '/boom',
    asyncHandler(async () => {
      throw ApiError.internal('simulated failure');
    })
  );

  probe.use(notFoundHandler);
  probe.use(errorMiddleware);

  return probe;
}

async function checkAuthAndMiddleware() {
  // Phase 2 changed this contract: authMiddleware now hydrates req.user from
  // MongoDB (so isEmergencyMode is never a stale token claim), which means the
  // probe needs a real account in the same throwaway database the spawned server
  // uses. This process connects to that instance directly.
  const { connectDatabase } = require('../config/db');
  await connectDatabase();

  const User = require('../models/User');
  const seeded = await User.create({ phone: '+919876500001', name: 'Phase One Probe' });
  const userId = String(seeded._id);

  const probe = buildProbeApp();
  const server = await new Promise((resolve) => {
    const instance = probe.listen(PROBE_PORT, () => resolve(instance));
  });
  const url = (p) => `${PROBE}${p}`;

  const call = async (path, init) => {
    const response = await fetch(url(path), init);
    let body = null;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    return { status: response.status, body };
  };

  const bearer = (token) => ({ headers: { Authorization: `Bearer ${token}` } });

  try {
    await record('auth: no Authorization header → 401 envelope', async () => {
      const { status, body } = await call('/protected');
      assert.equal(status, 401);
      assert.equal(body.success, false);
      assert.equal(body.data, null);
      assert.equal(body.errors, null);
    });

    await record('auth: wrong scheme → 401', async () => {
      const { status } = await call('/protected', { headers: { Authorization: `Token abc.def.ghi` } });
      assert.equal(status, 401);
    });

    await record('auth: malformed token → 401', async () => {
      const { status } = await call('/protected', bearer('not.a.jwt'));
      assert.equal(status, 401);
    });

    await record('auth: wrong signature → 401', async () => {
      const token = jwt.sign({ sub: userId }, 'a-completely-different-secret-value-000000', {
        algorithm: 'HS256',
        expiresIn: '5m',
      });
      const { status } = await call('/protected', bearer(token));
      assert.equal(status, 401);
    });

    await record('auth: expired token → 401 + expiry message', async () => {
      const token = signToken({ sub: userId }, { expiresIn: '-10s' });
      const { status, body } = await call('/protected', bearer(token));
      assert.equal(status, 401);
      assert.match(body.message, /expired/i);
    });

    await record('auth: not-yet-valid (nbf) token → 401', async () => {
      const token = jwt.sign({ sub: userId }, JWT_SECRET, {
        algorithm: 'HS256',
        notBefore: '10m',
        expiresIn: '20m',
      });
      const { status, body } = await call('/protected', bearer(token));
      assert.equal(status, 401);
      assert.match(body.message, /not active yet/i);
    });

    await record('auth: token without subject → 401', async () => {
      const token = signToken({ phone: '+910000000000' });
      const { status, body } = await call('/protected', bearer(token));
      assert.equal(status, 401);
      assert.match(body.message, /subject/i);
    });

    await record('auth: valid token → 200 with identity hydrated from the database', async () => {
      // The token deliberately claims a different phone number to prove the
      // database, not the token, is authoritative.
      const token = signToken({ sub: userId, phone: '+910000000000' });
      const { status, body } = await call('/protected', bearer(token));
      assert.equal(status, 200);
      assert.equal(body.id, userId);
      assert.equal(body.phone, '+919876500001');
      assert.equal(body.role, 'user');
    });

    await record('rbac: emergency route while the database flag is false → 403 (stale token claim ignored)', async () => {
      const token = signToken({ sub: userId, isEmergencyMode: true });
      const { status, body } = await call('/emergency', bearer(token));
      assert.equal(status, 403);
      assert.equal(body.success, false);
    });

    await record('rbac: emergency route once the database flag is true → 200 (no token claim needed)', async () => {
      await User.updateOne({ _id: userId }, { $set: { isEmergencyMode: true } });
      const token = signToken({ sub: userId });
      const { status } = await call('/emergency', bearer(token));
      await User.updateOne({ _id: userId }, { $set: { isEmergencyMode: false } });
      assert.equal(status, 200);
    });

    await record('rbac: role mismatch → 403', async () => {
      // The token claims a role the database does not have; the database wins.
      const token = signToken({ sub: userId, role: 'admin' });
      const { status } = await call('/admin', bearer(token));
      assert.equal(status, 403);
    });

    await record('objectId: invalid id → 400 (no CastError crash)', async () => {
      const { status, body } = await call('/object-id/not-an-object-id');
      assert.equal(status, 400);
      assert.equal(body.success, false);
    });

    await record('objectId: valid id → 200 normalised', async () => {
      const { status, body } = await call('/object-id/507F1F77BCF86CD799439011');
      assert.equal(status, 200);
      assert.equal(body.id, '507f1f77bcf86cd799439011');
    });

    await record('errors: unknown 5xx → generic message, no crash', async () => {
      const { status, body } = await call('/boom');
      assert.equal(status, 500);
      assert.equal(body.success, false);
      assert.ok(body.message.length > 0);
    });

    await record('auth: token subject that is not an ObjectId → 401', async () => {
      const token = signToken({ sub: 'user-1' });
      const { status, body } = await call('/protected', bearer(token));
      assert.equal(status, 401);
      assert.match(body.message, /not a valid user id/i);
    });

    await record('auth: token whose account was deleted → 401', async () => {
      const doomed = await User.create({ phone: '+919876500099', name: 'Doomed Probe' });
      const token = signToken({ sub: String(doomed._id) });
      await User.deleteOne({ _id: doomed._id });
      const { status } = await call('/protected', bearer(token));
      assert.equal(status, 401);
    });

    await record('errors: unmounted path → 404 envelope', async () => {
      const { status, body } = await call('/nope');
      assert.equal(status, 404);
      assert.equal(body.success, false);
    });
  } finally {
    await new Promise((resolve) => server.close(() => resolve()));
  }
}

async function checkDatabaseModule() {
  const { connectDatabase, disconnectDatabase, getDatabaseStatus, pingDatabase } = require('../config/db');
  const { config } = require('../config/env');

  await record('config: MONGO_URI without a database resolves to MONGO_DB_NAME', async () => {
    assert.equal(config.mongo.dbNameFromUri, false, 'the harness URI should have had no database name');
    assert.equal(config.mongo.dbName, 'guardfi', `resolved to "${config.mongo.dbName}"`);
  });

  await record('db: connectDatabase() connects and pools', async () => {
    await connectDatabase();
    const status = getDatabaseStatus();
    assert.equal(status.connected, true);
    assert.equal(status.readyState, 1);
    assert.ok(status.host, 'expected a connection host');
  });

  await record('db: pingDatabase() round-trips', async () => {
    const ping = await pingDatabase();
    assert.equal(ping.ok, true);
    assert.equal(typeof ping.latencyMs, 'number');
  });

  await record('db: disconnectDatabase() closes cleanly', async () => {
    await disconnectDatabase({ force: true });
    assert.equal(getDatabaseStatus().readyState, 0);
  });
}

async function checkHttpSurface() {
  await record('http: GET /health → 200 ok with db ping', async () => {
    const response = await fetch(`${BASE}/health`);
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.database.ping.ok, true);
  });

  await record('http: /health falls back to MONGO_DB_NAME when MONGO_URI names no database', async () => {
    const response = await fetch(`${BASE}/health`);
    const body = await response.json();

    assert.equal(body.data.database.database, 'guardfi', `connected to "${body.data.database.database}" instead`);
  });

  await record('http: GET /api/v1 → 200 versioned envelope', async () => {
    const response = await fetch(`${BASE}/api/v1`);
    const body = await response.json();
    assert.equal(response.status, 200);
    assert.equal(body.success, true);
    assert.equal(body.data.version, 'v1');
  });

  await record('http: GET unknown route → 404 envelope', async () => {
    const response = await fetch(`${BASE}/definitely-not-a-route`);
    const body = await response.json();
    assert.equal(response.status, 404);
    assert.equal(body.success, false);
    assert.equal(body.errors, null);
  });

  await record('http: malformed JSON body → 400 not a crash', async () => {
    const response = await fetch(`${BASE}/api/v1`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"broken":',
    });
    const body = await response.json();
    assert.equal(response.status, 400);
    assert.match(body.message, /valid JSON/i);
  });

  await record('http: oversized body → 413', async () => {
    const response = await fetch(`${BASE}/api/v1`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ padding: 'x'.repeat(1_500_000) }),
    });
    assert.equal(response.status, 413);
  });

  await record('http: helmet headers present, x-powered-by absent', async () => {
    const response = await fetch(`${BASE}/health`);
    assert.equal(response.headers.get('x-powered-by'), null);
    assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  });

  await record('http: CORS preflight is answered without credentialed access for a wildcard origin', async () => {
    const response = await fetch(`${BASE}/api/v1`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://app.guardfi.test', 'Access-Control-Request-Method': 'GET' },
    });

    assert.ok(response.status === 204 || response.status === 200);
    assert.equal(response.headers.get('access-control-allow-origin'), 'https://app.guardfi.test');
    // Bearer tokens do not need browser credentials, and advertising them for ANY
    // origin is how a site starts reading a signed-in user's responses.
    assert.equal(
      response.headers.get('access-control-allow-credentials'),
      null,
      'credentialed CORS must not be advertised while CORS_ORIGINS=*'
    );
  });

  await record('http: socket.io endpoint is mounted', async () => {
    const response = await fetch(`${BASE}/socket.io/?EIO=4&transport=polling`);
    assert.ok([200, 400].includes(response.status), `unexpected status ${response.status}`);
  });
}

/**
 * Run a snippet in a throwaway child process. config/env.js validates the
 * environment exactly once per process, so loading config with different
 * variables needs a fresh process.
 *
 * @param {{ env?: Record<string, string>, expression: string }} options
 * @returns {Promise<{ code: number, stdout: string, stderr: string }>}
 */
function runEnvChildProcess({ env = {}, expression }) {
  return new Promise((resolve) => {
    const probe = spawn(process.execPath, ['-e', expression], {
      cwd: PROJECT_ROOT,
      env: { ...process.env, LOG_LEVEL: 'error', ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    probe.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
    });
    probe.stderr.on('data', (chunk) => {
      stderr += chunk.toString();
    });
    probe.on('error', (error) => resolve({ code: -1, stdout, stderr: error.message }));
    probe.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

/**
 * @param {string} uri
 * @param {Record<string, string>} [extraEnv]
 * @returns {Promise<{ dbName: string, fromUri: boolean }>}
 */
async function resolveDbNameInChildProcess(uri, extraEnv = {}) {
  const result = await runEnvChildProcess({
    env: { MONGO_URI: uri, ...extraEnv },
    expression:
      "const { config } = require(process.cwd() + '/config/env'); process.stdout.write(JSON.stringify({ dbName: config.mongo.dbName, fromUri: config.mongo.dbNameFromUri }));",
  });

  assert.equal(result.code, 0, `env probe exited ${result.code}: ${result.stderr.split('\n').filter(Boolean).pop() || 'no output'}`);
  return JSON.parse(result.stdout);
}

async function checkDatabaseNameResolution() {
  await record('config: a URI with a database name uses it (and says so)', async () => {
    const resolved = await resolveDbNameInChildProcess('mongodb://127.0.0.1:27017/guardfi-verify');

    assert.equal(resolved.dbName, 'guardfi-verify');
    assert.equal(resolved.fromUri, true);
  });

  await record('config: a URI without a database name falls back to MONGO_DB_NAME', async () => {
    const resolved = await resolveDbNameInChildProcess('mongodb://127.0.0.1:27017');

    assert.equal(resolved.dbName, 'guardfi');
    assert.equal(resolved.fromUri, false);
  });

  await record('config: MONGO_DB_NAME overrides the fallback', async () => {
    const resolved = await resolveDbNameInChildProcess('mongodb://127.0.0.1:27017', { MONGO_DB_NAME: 'guardfi_dev' });

    assert.equal(resolved.dbName, 'guardfi_dev');
  });

  await record('config: a stray double slash cannot produce an invalid database name', async () => {
    const resolved = await resolveDbNameInChildProcess('mongodb://127.0.0.1:27017//guardfi');

    assert.equal(resolved.dbName, 'guardfi');
  });

  await record('config: an invalid MONGO_DB_NAME fails fast at boot', async () => {
    await assert.rejects(
      () => resolveDbNameInChildProcess('mongodb://127.0.0.1:27017', { MONGO_DB_NAME: 'bad/name' }),
      (error) => /exited 1/.test(error.message)
    );
  });

  await record('config: a bad value inherited from the shell is traced to the shell, not .env', async () => {
    const result = await runEnvChildProcess({
      // Exactly what an IDE or a stray `export PORT=0` does to a working .env.
      env: { PORT: '0' },
      expression: "require(process.cwd() + '/config/env'); process.stdout.write('booted');",
    });

    assert.equal(result.code, 1, 'the probe should have refused to boot');
    assert.match(result.stderr, /PORT: Too small/);
    assert.match(result.stderr, /OS\/shell environment/, 'the failure must name where the bad value came from');
  });

  await record('config: OTP_DEV_MODE=true in production refuses to boot', async () => {
    const result = await runEnvChildProcess({
      env: { NODE_ENV: 'production', OTP_DEV_MODE: 'true', STRICT_ENV: 'false' },
      expression: "require(process.cwd() + '/config/env'); process.stdout.write('booted');",
    });

    assert.equal(result.code, 1, 'a production deploy that leaks OTPs must not start');
    assert.match(result.stderr, /OTP_DEV_MODE=true while NODE_ENV=production/);
    assert.match(result.stderr, /ALLOW_OTP_DEV_MODE_IN_PRODUCTION/);
  });

  await record('config: the production OTP guard has a working explicit override', async () => {
    const result = await runEnvChildProcess({
      env: {
        NODE_ENV: 'production',
        OTP_DEV_MODE: 'true',
        ALLOW_OTP_DEV_MODE_IN_PRODUCTION: 'true',
        STRICT_ENV: 'false',
        CORS_ORIGINS: 'https://app.guardfi.test',
      },
      expression:
        "const { config } = require(process.cwd() + '/config/env'); process.stdout.write(JSON.stringify({ devMode: config.otp.devMode, production: config.isProduction }));",
    });

    assert.equal(result.code, 0, `probe exited ${result.code}: ${result.stderr.split('\n').filter(Boolean).pop() || 'no output'}`);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.devMode, true);
    assert.equal(parsed.production, true);
  });
}

/**
 * Repo hygiene: the real secrets in .env must not be copied into any file that
 * could be committed, screenshotted or shipped.
 */
async function checkSecretHygiene() {
  const fsSync = require('node:fs');

  await record('secrets: no .env secret value appears in any project file', async () => {
    const envText = fsSync.readFileSync(path.join(PROJECT_ROOT, '.env'), 'utf8');
    /** @type {string[]} */
    const secrets = [];

    const uriMatch = /^\s*MONGO_URI\s*=\s*(.+)$/m.exec(envText);
    if (uriMatch) {
      const uri = uriMatch[1].trim();
      secrets.push(uri);
      const credentials = /:\/\/[^:@/]+:([^@]+)@/.exec(uri);
      if (credentials) secrets.push(credentials[1]);
    }

    const jwtMatch = /^\s*JWT_SECRET\s*=\s*(.+)$/m.exec(envText);
    if (jwtMatch) secrets.push(jwtMatch[1].trim());

    const scannedExtensions = ['.js', '.json', '.md', '.yml', '.yaml', '.example', '.log', '.txt'];
    const skipDirectories = new Set(['node_modules', '.git', '.freebuff', 'coverage']);
    const offenders = [];

    const walk = (directory) => {
      for (const entry of fsSync.readdirSync(directory, { withFileTypes: true })) {
        if (skipDirectories.has(entry.name)) continue;
        const fullPath = path.join(directory, entry.name);
        if (entry.isDirectory()) {
          walk(fullPath);
          continue;
        }
        if (!scannedExtensions.includes(path.extname(entry.name))) continue;
        // .env itself is the one legitimate home for these values.
        if (/^\.env(\.|$)/.test(entry.name) && entry.name !== '.env.example') continue;

        const content = fsSync.readFileSync(fullPath, 'utf8');
        if (secrets.some((secret) => secret.length > 6 && content.includes(secret))) {
          offenders.push(path.relative(PROJECT_ROOT, fullPath));
        }
      }
    };

    walk(PROJECT_ROOT);

    assert.deepEqual(offenders, [], `secret found in: ${offenders.join(', ')}`);
  });
}

/**
 * Hardening checks. Each one covers a way the API could quietly stop protecting
 * itself, and each was verified rather than assumed.
 */
async function checkHardening() {
  const expressLib = require('express');
  const { config } = require('../config/env');
  const { authLimiter } = require('../middlewares/rateLimiter');
  const { errorMiddleware, notFoundHandler, redactUrl } = require('../middlewares/errorMiddleware');
  const asyncHandler = require('../utils/asyncHandler');
  const { initSocket, closeSocket } = require('../sockets');

  const authLimit = config.rateLimit.authMax;

  /** @returns {Promise<{ close: () => Promise<void> }>} */
  const startLimiterProbe = async (port, trustProxy) => {
    const probe = expressLib();
    probe.set('trust proxy', trustProxy);
    probe.use(authLimiter);
    probe.get('/limited', (req, res) => res.json({ success: true, ip: req.ip }));

    const server = await new Promise((resolve) => {
      const instance = probe.listen(port, () => resolve(instance));
    });

    return { close: () => new Promise((resolve) => server.close(() => resolve())) };
  };

  const probeStatus = async (port, spoofedIp) => {
    const response = await fetch(`http://127.0.0.1:${port}/limited`, {
      headers: { 'X-Forwarded-For': spoofedIp },
    });

    return response.status;
  };

  await record('config: TRUST_PROXY is off, so per-IP limits cannot be spoofed', async () => {
    assert.equal(config.trustProxy, false, `trustProxy is ${config.trustProxy}`);
  });

  await record('rate limit: a fresh X-Forwarded-For per request cannot buy extra attempts', async () => {
    const probe = await startLimiterProbe(TRUST_PROBE_PORT, false);

    try {
      const statuses = [];
      for (let i = 1; i <= authLimit + 1; i += 1) statuses.push(await probeStatus(TRUST_PROBE_PORT, `198.51.100.${i}`));

      assert.equal(statuses[authLimit], 429, `expected 429 on request ${authLimit + 1}, got: ${statuses.join(',')}`);
    } finally {
      await probe.close();
    }
  });

  await record('rate limit: TRUST_PROXY=1 would let that same header bypass the limiter entirely', async () => {
    const probe = await startLimiterProbe(TRUST_PROBE_PORT + 1, 1);

    try {
      const statuses = [];
      for (let i = 1; i <= authLimit + 5; i += 1) statuses.push(await probeStatus(TRUST_PROBE_PORT + 1, `203.0.113.${i}`));

      assert.ok(
        !statuses.includes(429),
        `the limiter should have been bypassed with trust proxy on, got: ${statuses.join(',')}`
      );
    } finally {
      await probe.close();
    }
  });

  await record('errors: an error claiming statusCode 200 cannot become HTTP 200 with success:false', async () => {
    const probe = expressLib();

    probe.get(
      '/bad-status',
      asyncHandler(async () => {
        throw Object.assign(new Error('a library lied about its status'), { statusCode: 200 });
      })
    );
    probe.use(notFoundHandler);
    probe.use(errorMiddleware);

    const server = await new Promise((resolve) => {
      const instance = probe.listen(TRUST_PROBE_PORT + 2, () => resolve(instance));
    });

    try {
      const response = await fetch(`http://127.0.0.1:${TRUST_PROBE_PORT + 2}/bad-status`);
      const body = await response.json();

      assert.equal(response.status, 500, `expected 500, got ${response.status}`);
      assert.equal(body.success, false);
    } finally {
      await new Promise((resolve) => server.close(() => resolve()));
    }
  });

  await record('privacy: sensitive query values are redacted before they reach a log line', async () => {
    const dirty = redactUrl('/api/v1/auth/send-otp?phone=%2B919876543210&otp=123456&page=2');

    assert.equal(dirty.includes('919876543210'), false, dirty);
    assert.equal(dirty.includes('123456'), false, dirty);
    assert.match(dirty, /page=2/, 'non-sensitive parameters must survive for debugging');
    assert.equal(redactUrl('/health?verbose=1'), '/health?verbose=1');
    assert.equal(redactUrl('/api/v1'), '/api/v1');
    assert.equal(redactUrl(''), '');
  });

  await record('socket: session recovery still runs middleware (no auth bypass when Phase 4 lands)', async () => {
    const http = require('node:http');
    const server = http.createServer();
    const io = initSocket(server);

    try {
      assert.equal(io.opts.connectionStateRecovery.skipMiddlewares, false);
    } finally {
      await closeSocket();
      await new Promise((resolve) => server.close(() => resolve()));
    }
  });
}

/**
 * Socket.io is mounted before Phase 4 adds handshake authentication, so without a
 * budget any client could open connections until the process runs out of memory.
 * This boots a server with a deliberately tiny budget and proves two things the
 * naive implementation gets wrong: the cap actually refuses the handshake, and
 * requests that belong to an ALREADY-counted session (they carry a sid) are not
 * charged against the budget.
 */
async function checkSocketConnectionBudget() {
  await record('socket: an unauthenticated client cannot open unlimited connections', async () => {
    const socketChild = spawn(process.execPath, [path.join(PROJECT_ROOT, 'server.js')], {
      cwd: PROJECT_ROOT,
      env: {
        ...process.env,
        NODE_ENV: 'test',
        PORT: String(SOCKET_BUDGET_PORT),
        MONGO_URI: process.env.MONGO_URI,
        SOCKET_MAX_CONNECTIONS_PER_IP: '2',
        LOG_LEVEL: 'error',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const output = [];
    socketChild.stdout.on('data', (chunk) => output.push(chunk.toString()));
    socketChild.stderr.on('data', (chunk) => output.push(chunk.toString()));

    const handshake = () =>
      fetch(`http://127.0.0.1:${SOCKET_BUDGET_PORT}/socket.io/?EIO=4&transport=polling`);

    try {
      await waitForHealth(`http://127.0.0.1:${SOCKET_BUDGET_PORT}`, 'socket budget server');

      const first = await handshake();
      const firstBody = await first.text();
      assert.equal(first.status, 200, `first handshake: ${first.status} ${firstBody.slice(0, 100)}`);

      const sid = JSON.parse(firstBody.slice(firstBody.indexOf('{'))).sid;
      assert.ok(sid, `the handshake must return a session id, got: ${firstBody.slice(0, 100)}`);

      const second = await handshake();
      assert.equal(second.status, 200, `second handshake: ${second.status}`);

      const third = await handshake();
      const thirdBody = await third.text();
      assert.equal(
        third.status,
        403,
        `the third concurrent handshake from one address must be refused, got ${third.status}: ${thirdBody.slice(0, 120)}`
      );

      // A request that carries a sid belongs to a session that was counted at its
      // handshake, so the cap must not apply a second time. A bogus sid therefore
      // fails on session lookup (400) — never on the connection budget (403).
      const existingSession = await fetch(
        `http://127.0.0.1:${SOCKET_BUDGET_PORT}/socket.io/?EIO=4&transport=polling&sid=000000000000000000000000`
      );
      assert.notEqual(existingSession.status, 403, 'a sid request must not be charged against the connection budget');
    } catch (error) {
      if (output.length > 0) {
        console.error('\n--- socket budget server output ---');
        console.error(output.join('').split('\n').slice(-15).join('\n'));
      }
      throw error;
    } finally {
      if (socketChild.exitCode === null) {
        socketChild.kill();
        await sleep(300);
      }
    }
  });
}

/**
 * Boots a real production-mode server to prove it starts with the safe defaults
 * AND stops volunteering infrastructure details on a public endpoint.
 */
async function checkProductionSurface() {
  await record('production: /health stays up but stops disclosing cluster details', async () => {
    const child = spawn(process.execPath, [path.join(PROJECT_ROOT, 'server.js')], {
      cwd: PROJECT_ROOT,
      env: {
        ...process.env,
        NODE_ENV: 'production',
        PORT: String(PRODUCTION_PORT),
        OTP_DEV_MODE: 'false',
        STRICT_ENV: 'false',
        CORS_ORIGINS: 'https://app.guardfi.test',
        LOG_LEVEL: 'error',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    const output = [];
    child.stdout.on('data', (chunk) => output.push(chunk.toString()));
    child.stderr.on('data', (chunk) => output.push(chunk.toString()));

    try {
      const body = await waitForHealth(`http://127.0.0.1:${PRODUCTION_PORT}`, 'production server');

      assert.equal(body.data.database.connected, true);
      assert.equal(body.data.database.ping.ok, true);
      assert.equal(body.data.database.host, undefined, `host disclosed: ${body.data.database.host}`);
      assert.equal(body.data.database.database, undefined, `database name disclosed: ${body.data.database.database}`);
      assert.equal(body.data.database.poolSize, undefined);
    } catch (error) {
      if (output.length > 0) {
        console.error('\n--- production server output ---');
        console.error(output.join('').split('\n').slice(-15).join('\n'));
      }
      throw error;
    } finally {
      if (child.exitCode === null) {
        child.kill();
        await sleep(300);
      }
    }
  });
}

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
      dbName: 'guardfi-verify',
      // The first run downloads a ~78 MB mongod binary and cold-starts it, which
      // comfortably exceeds the library's 10s default on Windows.
      launchTimeout: 90_000,
    },
  });
  const uri = mongo.getUri('guardfi-verify');

  // Deliberately strip the database name. A connection string pasted from Atlas
  // frequently looks like "…mongodb.net/?retryWrites=true", and the driver's own
  // default would then be a database called "test". Every check below therefore
  // also proves the MONGO_DB_NAME fallback works end to end.
  const uriWithoutDatabase = uri.replace(/\/[^/?]+$/, '');
  if (uriWithoutDatabase === uri) throw new Error('harness could not strip the database name from the in-memory URI');
  process.env.MONGO_URI = uriWithoutDatabase;

  console.log(`▶ Booting server.js on port ${APP_PORT} (MONGO_URI without a database name)...`);
  child = spawn(process.execPath, [path.join(PROJECT_ROOT, 'server.js')], {
    cwd: PROJECT_ROOT,
    env: { ...process.env, NODE_ENV: 'test', PORT: String(APP_PORT), MONGO_URI: uriWithoutDatabase, LOG_LEVEL: 'error' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const childOutput = [];
  child.stdout.on('data', (chunk) => childOutput.push(chunk.toString()));
  child.stderr.on('data', (chunk) => childOutput.push(chunk.toString()));

  try {
    await waitForHealth();
    console.log('▶ Server is healthy. Running checks...\n');

    await checkHttpSurface();
    await checkAuthAndMiddleware();
    await checkDatabaseModule();
    await checkDatabaseNameResolution();
    await checkSecretHygiene();
    await checkHardening();
    await checkSocketConnectionBudget();
    await checkProductionSurface();
  } catch (error) {
    results.push({ name: 'harness: server became healthy', ok: false, error: error.message });
    if (childOutput.length > 0) {
      console.error('\n--- server output ---');
      console.error(childOutput.join('').split('\n').slice(-25).join('\n'));
    }
  } finally {
    if (child && child.exitCode === null) {
      child.kill();
      await sleep(300);
    }
    if (mongo) await mongo.stop();
  }

  const passed = results.filter((r) => r.ok).length;
  const failed = results.filter((r) => !r.ok);

  console.log('');
  for (const result of results) {
    console.log(`${result.ok ? '  PASS' : '  FAIL'}  ${result.name}${result.ok ? '' : `\n          ↳ ${result.error}`}`);
  }
  console.log(`\n${passed}/${results.length} checks passed.`);

  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch(async (error) => {
  console.error('✖ Harness crashed:', error);
  if (child && child.exitCode === null) child.kill();
  if (mongo) await mongo.stop().catch(() => {});
  process.exit(1);
});
