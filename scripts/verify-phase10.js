'use strict';

/**
 * GuardFi — Phase 10 verification harness (production readiness)
 *
 * Covers the deliverables an in-memory API test cannot reach:
 *
 *   • the deployment files exist and say the right thing (Procfile, render.yaml);
 *   • `.gitignore` actually protects `.env`, uploads and service-account keys;
 *   • the Postman collection/environment parse as JSON, cover every module, and
 *     the verify-OTP request really captures {{jwt_token}};
 *   • production runs with `trust proxy = 1` (render.yaml sets it, and the config
 *     default is 1 when NODE_ENV=production), while development stays false;
 *   • rate limiting behind a reverse proxy keys buckets on the FORWARDED client
 *     address, not on the proxy — otherwise one user's burst throttles everyone;
 *   • Socket.io upgrades to a real WebSocket, enforces the per-IP connection
 *     budget, and RELEASES it on disconnect (the classic engine.io leak);
 *   • `seed:demo` populates the demo account, guardians, blocklist and config,
 *     is idempotent on a second run, and honours --dry-run;
 *   • the audit sweep: every model's live indexes exist (2dsphere, TTL, unique,
 *     partial) and no controller passes an unvalidated route param to Mongoose.
 *
 * Run:  npm run verify:phase10
 * Exit: 0 = every check passed, 1 = at least one failed, 2 = harness cannot run.
 */

process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = process.env.VERIFY_LOG_LEVEL || 'error';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'verify-phase10-secret-'.padEnd(48, '0');
process.env.CORS_ORIGINS = '*';
process.env.STRICT_ENV = 'false';
process.env.TRUST_PROXY = 'false';
delete process.env.PORT;

process.env.MONGO_URI = 'mongodb://127.0.0.1:27017/guardfi-phase10-placeholder';
process.env.OTP_DEV_MODE = 'true';
process.env.SMS_PROVIDER = 'none';
process.env.BIOMETRIC_SHARED_SECRET = 'phase10-verify-secret-'.padEnd(64, 'k');

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const MAIN_PORT = Number(process.env.VERIFY_PHASE10_PORT || 4346);
const PROXY_PORT = Number(process.env.VERIFY_PHASE10_PROXY_PORT || 4347);
const SOCKET_PORT = Number(process.env.VERIFY_PHASE10_SOCKET_PORT || 4348);
const MAIN_BASE = `http://127.0.0.1:${MAIN_PORT}`;
const PROXY_BASE = `http://127.0.0.1:${PROXY_PORT}`;
const SOCKET_BASE = `http://127.0.0.1:${SOCKET_PORT}`;

let mongo = null;
const servers = [];
const results = [];
let seeded = null;

function record(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => results.push({ name, ok: true }))
    .catch((error) => results.push({ name, ok: false, error: error.message }));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function readProjectFile(relativePath) {
  return fs.readFile(path.join(PROJECT_ROOT, relativePath), 'utf8');
}

async function call(base, pathname, { method = 'GET', token, body, headers = {} } = {}) {
  const init = { method, headers: { 'user-agent': 'GuardFi-Phase10-Verify/1.0', ...headers } };
  if (token) init.headers.Authorization = `Bearer ${token}`;
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

  return { status: response.status, body: parsed, text };
}

async function waitForHealth(base, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no response';

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${base}/health`);
      const body = await response.json();
      if (response.status === 200 && body?.data?.database?.connected === true) {
        return body;
      }
      last = `status=${response.status}`;
    } catch (error) {
      last = error.message;
    }
    await sleep(400);
  }

  throw new Error(`server at ${base} never became healthy within ${timeoutMs}ms (last: ${last})`);
}

function spawnServer({ port, env = {}, label, file = 'server.js' }) {
  const child = spawn(process.execPath, [path.join(PROJECT_ROOT, file)], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      LOG_LEVEL: 'error',
      PORT: String(port),
      MONGO_URI: process.env.MONGO_URI,
      RATE_LIMIT_SKIP_IN_TEST: 'true',
      FIREBASE_PROJECT_ID: '',
      FIREBASE_CLIENT_EMAIL: '',
      FIREBASE_PRIVATE_KEY: '',
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
      if (!entry.output.length) continue;
      console.error(`\n--- ${entry.label} output ---`);
      console.error(entry.output.join('').split('\n').slice(-20).join('\n'));
    }
  }
}

/** Run a tiny node script in a child process and return { code, stdout, stderr }. */
function runNodeScript(script, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, ['-e', script], {
      cwd: PROJECT_ROOT,
      env: { ...process.env, ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => (stdout += chunk.toString()));
    child.stderr.on('data', (chunk) => (stderr += chunk.toString()));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
}

// ===========================================================================
// Dataset
// ===========================================================================
async function seedDataset() {
  const User = require('../models/User');
  const { signAccessToken } = require('../services/tokenService');

  await User.init();

  const user = {
    _id: new mongoose.Types.ObjectId(),
    phone: '+919876580001',
    name: 'Phase 10 User',
    role: 'user',
    securityPinHash: null,
    isEmergencyMode: false,
    biometricEnabled: false,
    emergencyActivatedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  await User.collection.insertMany([user]);

  seeded = { user: { id: String(user._id), objectId: user._id, token: signAccessToken(user).token } };
  return seeded;
}

// ===========================================================================
// A. Deployment deliverables
// ===========================================================================
async function runDeliverableChecks() {
  await record('deploy: Procfile runs the real entry point', async () => {
    const procfile = (await readProjectFile('Procfile')).trim();
    assert.equal(procfile, 'web: node server.js');
  });

  await record('deploy: render.yaml pins production env, health check, trust proxy and start command', async () => {
    const yaml = await readProjectFile('render.yaml');

    assert.match(yaml, /startCommand: node server\.js/);
    assert.match(yaml, /buildCommand: npm ci --omit=dev/);
    assert.match(yaml, /healthCheckPath: \/health/);
    assert.match(yaml, /- key: NODE_ENV\n\s+value: production/);
    assert.match(yaml, /- key: TRUST_PROXY\n\s+value: "1"/);
    assert.match(yaml, /- key: MONGO_URI\n\s+sync: false/);
    assert.match(yaml, /- key: JWT_SECRET\n\s+generateValue: true/);
    assert.match(yaml, /- key: BIOMETRIC_SHARED_SECRET\n\s+sync: false/);
    assert.match(yaml, /- key: OTP_DEV_MODE\n\s+value: "false"/);
  });

  await record('gitignore: secrets, dependencies and uploads can never be committed', async () => {
    const gitignore = await readProjectFile('.gitignore');

    for (const pattern of ['node_modules/', '.env', 'uploads/', '*.log', '*.pem', '*.key', 'firebase-service-account*.json']) {
      assert.ok(gitignore.includes(pattern), `.gitignore is missing ${pattern}`);
    }

    assert.ok(gitignore.includes('!.env.example'), '.env.example must stay committed');
  });

  await record('postman: the collection and environment parse and cover every module', async () => {
    const collection = JSON.parse(await readProjectFile('docs/GuardFi.postman_collection.json'));
    const environment = JSON.parse(await readProjectFile('docs/GuardFi.postman_environment.json'));

    assert.equal(collection.info.schema, 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json');
    assert.equal(environment._postman_variable_scope, 'environment');

    const requests = [];
    const folderNames = [];

    for (const folder of collection.item) {
      folderNames.push(folder.name);
      for (const request of folder.item) {
        requests.push({ folder: folder.name, request });
      }
    }

    assert.ok(requests.length >= 25, `expected a complete collection, found ${requests.length} requests`);

    const urls = requests.map((entry) => entry.request.request.url.raw).join('\n');
    const required = [
      '/health',
      '/api/v1/auth/send-otp',
      '/api/v1/auth/verify-otp',
      '/api/v1/nominees/add',
      '/api/v1/nominees/list',
      '/api/v1/nominees/remove/',
      '/api/v1/sos/trigger',
      '/api/v1/sos/resolve',
      '/api/v1/sos/active',
      '/api/v1/analytics/dashboard',
      '/api/v1/shield-pay/check-upi',
      '/api/v1/shield-pay/proceed-transaction',
      '/api/v1/shield-pay/set-pin',
      '/api/v1/scam-buster/analyze',
      '/api/v1/scam-buster/history',
      '/api/v1/emergency/biometric-verify',
      '/api/v1/emergency/restricted-action',
      '/api/v1/emergency/lock',
      '/api/v1/config/global',
    ];

    for (const endpoint of required) {
      assert.ok(urls.includes(endpoint), `the collection is missing ${endpoint}`);
    }

    const serialized = JSON.stringify(collection);
    assert.ok(serialized.includes("pm.environment.set('jwt_token'"), 'verify-OTP never stores {{jwt_token}}');

    const keys = environment.values.map((entry) => entry.key);
    for (const key of ['base_url', 'demo_phone', 'demo_pin', 'jwt_token', 'biometric_secret', 'scam_upi']) {
      assert.ok(keys.includes(key), `the environment is missing ${key}`);
    }

    const withTests = requests.filter((entry) =>
      (entry.request.event || []).some((event) => event.listen === 'test')
    );
    assert.ok(
      withTests.length >= Math.floor(requests.length * 0.9),
      `only ${withTests.length}/${requests.length} requests carry assertions`
    );
  });
}

// ===========================================================================
// B. Production trust proxy
// ===========================================================================
const APP_TRUST_PROXY_PROBE = [
  "const app = require('./app');",
  "const { config } = require('./config/env');",
  'console.log(JSON.stringify({ trust: app.get("trust proxy"), env: config.env, trustProxy: config.trustProxy }));',
].join('\n');

async function runTrustProxyChecks() {
  const baseEnv = {
    STRICT_ENV: 'false',
    OTP_DEV_MODE: 'false',
    SMS_PROVIDER: 'none',
    MONGO_URI: 'mongodb://127.0.0.1:1/guardfi-trust-proxy-probe',
    JWT_SECRET: 'trust-proxy-probe-secret-'.padEnd(48, '0'),
    CORS_ORIGINS: '*',
    PORT: '',
    TRUST_PROXY: '',
  };

  await record('proxy: production defaults to trust proxy 1, development stays false', async () => {
    const production = await runNodeScript(APP_TRUST_PROXY_PROBE, { ...baseEnv, NODE_ENV: 'production' });
    assert.equal(production.code, 0, production.stderr);
    const productionResult = JSON.parse(production.stdout.trim().split('\n').pop());
    assert.equal(productionResult.env, 'production');
    assert.equal(productionResult.trust, 1, 'app.set("trust proxy") must be 1 in production');

    const development = await runNodeScript(APP_TRUST_PROXY_PROBE, { ...baseEnv, NODE_ENV: 'development' });
    assert.equal(development.code, 0, development.stderr);
    const developmentResult = JSON.parse(development.stdout.trim().split('\n').pop());
    assert.equal(developmentResult.trust, false, 'a directly reachable dev server must not trust X-Forwarded-For');
  });
}

// ===========================================================================
// C. Rate limiting behind the proxy
// ===========================================================================
async function runProxyRateLimitChecks() {
  await record('proxy: per-IP limiters key on the forwarded client address, not the proxy', async () => {
    const firstIp = '203.0.113.21';
    const secondIp = '203.0.113.22';

    const attempt = (ip) =>
      call(PROXY_BASE, '/api/v1/auth/verify-otp', {
        method: 'POST',
        body: { phone: '+919876580099', otp: '000000' },
        headers: { 'X-Forwarded-For': ip },
      });

    const first = await attempt(firstIp);
    assert.ok(
      [400, 401].includes(first.status),
      `the first attempt should reach the handler (400/401), got ${first.status}: ${first.text}`
    );

    const second = await attempt(firstIp);
    assert.equal(second.status, 429, `the same client should be limited after AUTH_RATE_LIMIT_MAX=1: ${second.text}`);

    const other = await attempt(secondIp);
    assert.ok(
      [400, 401].includes(other.status),
      `a different client must get a fresh bucket, got ${other.status}: ${other.text}`
    );

    const health = await fetch(`${PROXY_BASE}/health`);
    assert.equal(health.status, 200, 'the global limiter must not have been exhausted by these few calls');
  });
}

// ===========================================================================
// D. Socket.io upgrade + connection-budget leak test
// ===========================================================================
async function runSocketChecks() {
  const { io } = require('socket.io-client');

  /**
   * @param {string} base
   * @param {string} token
   * @param {number} timeoutMs
   */
  function connectSocket(base, token, timeoutMs = 6_000) {
    return new Promise((resolve) => {
      const socket = io(base, {
        auth: { token },
        transports: ['websocket'],
        reconnection: false,
        timeout: timeoutMs,
      });

      const finish = (ok, error) => {
        clearTimeout(timer);
        resolve({ ok, socket, error });
      };

      const timer = setTimeout(() => finish(false, new Error('timed out waiting for connect')), timeoutMs);

      socket.on('connect', () => finish(true, null));
      socket.on('connect_error', (error) => finish(false, error));
    });
  }

  await record('socket: the handshake upgrades to a real WebSocket', async () => {
    const { ok, socket, error } = await connectSocket(MAIN_BASE, seeded.user.token);

    try {
      assert.ok(ok, `socket did not connect: ${error?.message}`);
      assert.equal(socket.io.engine.transport.name, 'websocket');
      assert.equal(socket.connected, true);
    } finally {
      socket.close();
    }
  });

  await record('socket: the per-IP budget refuses a second concurrent connection', async () => {
    const first = await connectSocket(SOCKET_BASE, seeded.user.token);

    try {
      assert.ok(first.ok, `the first socket should connect: ${first.error?.message}`);

      const second = await connectSocket(SOCKET_BASE, seeded.user.token, 4_000);
      assert.equal(second.ok, false, 'a second concurrent connection must be refused by SOCKET_MAX_CONNECTIONS_PER_IP=1');
      second.socket.close();
    } finally {
      first.socket.close();
    }
  });

  await record('socket: the budget is released on disconnect (no engine.io leak)', async () => {
    // A leaking slot is NEVER available again; a released one just takes a moment
    // for engine.io to emit 'close'. So poll for a bounded window instead of
    // failing on one arbitrary delay — otherwise this check measures timing, not
    // correctness (it flaked once for exactly that reason).
    const connectWhenReleased = async (attempts = 8) => {
      let last = null;

      for (let attempt = 0; attempt < attempts; attempt += 1) {
        const result = await connectSocket(SOCKET_BASE, seeded.user.token, 3_000);
        if (result.ok) return result;
        last = result;
        await sleep(300);
      }

      return last;
    };

    for (let cycle = 0; cycle < 3; cycle += 1) {
      const result = await connectWhenReleased();
      assert.ok(result.ok, `cycle ${cycle + 1} could not connect — the budget leaked: ${result.error?.message}`);

      result.socket.close();
      await sleep(400);
    }

    const health = await fetch(`${SOCKET_BASE}/health`);
    assert.equal(health.status, 200);
  });
}

// ===========================================================================
// E. Demo seed
// ===========================================================================
async function runSeedChecks() {
  const User = require('../models/User');
  const Nominee = require('../models/Nominee');
  const FlaggedEntity = require('../models/FlaggedEntity');
  const AppConfig = require('../models/AppConfig');
  const bcrypt = require('bcryptjs');
  const { seedDemo, DEMO_USER, DEMO_NOMINEES } = require('./seedDemo');
  const { FLAGGED_ENTITIES } = require('./seedFlaggedUpi');

  const identifiers = FLAGGED_ENTITIES.map((entry) => entry.identifier);

  let demoUserId = null;

  await record('seed: the first run creates the demo account, guardians, blocklist and config', async () => {
    const summary = await seedDemo();

    assert.equal(summary.user.action, 'created');
    demoUserId = summary.user.id;

    const user = await User.findById(demoUserId).select('+securityPinHash phone name lastKnownLocation').lean();
    assert.equal(user.phone, DEMO_USER.phone);
    assert.equal(user.name, DEMO_USER.name);
    assert.equal(await bcrypt.compare(DEMO_USER.pin, user.securityPinHash), true, 'the demo PIN must actually work');
    assert.equal(user.lastKnownLocation.type, 'Point');
    assert.deepEqual(user.lastKnownLocation.coordinates, [DEMO_USER.location.longitude, DEMO_USER.location.latitude]);

    const nominees = await Nominee.find({ userId: demoUserId }).sort({ phone: 1 }).lean();
    assert.equal(nominees.length, DEMO_NOMINEES.length);
    assert.equal(nominees.filter((entry) => entry.isPrimary).length, 1, 'exactly one primary guardian');

    assert.equal(summary.flagged.total, FLAGGED_ENTITIES.length);
    assert.ok(summary.flagged.total >= 10, 'the demo needs at least 10 flagged entities');
    assert.equal(await FlaggedEntity.countDocuments({ identifier: { $in: identifiers } }), FLAGGED_ENTITIES.length);

    const config = await AppConfig.findOne({ key: 'GLOBAL_CONFIG' }).lean();
    assert.ok(config, 'the demo seed must leave an AppConfig document');
    assert.equal(config.globalWarningThresholds.upiRiskScoreThreshold, 70);
  });

  await record('seed: a second run is idempotent (updates, never duplicates)', async () => {
    const summary = await seedDemo();

    assert.equal(summary.user.action, 'updated');
    assert.equal(await User.countDocuments({ phone: DEMO_USER.phone }), 1);
    assert.equal(await Nominee.countDocuments({ userId: demoUserId }), DEMO_NOMINEES.length);
    assert.equal(await FlaggedEntity.countDocuments({ identifier: { $in: identifiers } }), FLAGGED_ENTITIES.length);
    assert.equal(await AppConfig.countDocuments({ key: 'GLOBAL_CONFIG' }), 1);
    assert.equal(summary.appConfig.action, 'existing-kept');
  });

  await record('seed: --dry-run writes nothing', async () => {
    const before = await User.countDocuments({ phone: DEMO_USER.phone });
    const summary = await seedDemo({ dryRun: true });

    assert.equal(summary.flagged.total, FLAGGED_ENTITIES.length);
    assert.equal(await User.countDocuments({ phone: DEMO_USER.phone }), before);
  });

  // Hand the seeded demo user to the cleanup step and remember the app-config
  // state so the probe never leaves the harness database dirty.
  return { demoUserId, identifiers };
}

// ===========================================================================
// F. Audit sweep: live indexes + static code checks
// ===========================================================================
async function runAuditSweep() {
  const User = require('../models/User');
  const Nominee = require('../models/Nominee');
  const Otp = require('../models/Otp');
  const SosAlert = require('../models/SosAlert');
  const SendThrottle = require('../models/SendThrottle');
  const FlaggedEntity = require('../models/FlaggedEntity');
  const TransactionAudit = require('../models/TransactionAudit');
  const ScamScan = require('../models/ScamScan');
  const AuditLog = require('../models/AuditLog');
  const AppConfig = require('../models/AppConfig');

  await record('audit: every required index really exists on the live collections', async () => {
    const models = [User, Nominee, Otp, SosAlert, SendThrottle, FlaggedEntity, TransactionAudit, ScamScan, AuditLog, AppConfig];
    await Promise.all(models.map((model) => model.init()));

    const indexKeys = async (model) => (await model.collection.indexes()).map((index) => index.key);

    const hasKey = async (model, predicate, label) => {
      const keys = await indexKeys(model);
      assert.ok(keys.some(predicate), `${label} is missing (found: ${JSON.stringify(keys)})`);
    };

    await hasKey(User, (key) => key.phone === 1, 'users.phone unique');
    await hasKey(User, (key) => key.lastKnownLocation === '2dsphere', 'users.lastKnownLocation 2dsphere');
    await hasKey(Nominee, (key) => key.userId === 1 && key.phone === 1, 'nominees {userId, phone} compound');
    await hasKey(Nominee, (key) => key.userId === 1, 'nominees one-primary partial index');
    await hasKey(Otp, (key) => Object.keys(key).length === 1, 'otps TTL key');
    await hasKey(SosAlert, (key) => key.initialLocation === '2dsphere', 'sosalerts.initialLocation 2dsphere');
    await hasKey(SosAlert, (key) => key.userId === 1 && key.status === 1, 'sosalerts {userId, status}');
    await hasKey(SendThrottle, (key) => key.expiresAt === 1, 'sendthrottles TTL');
    await hasKey(FlaggedEntity, (key) => key.identifier === 1, 'flaggedentities.identifier unique');
    await hasKey(TransactionAudit, (key) => key.userId === 1 && key.createdAt === -1, 'transactionaudits history');
    await hasKey(TransactionAudit, (key) => key.transactionHash === 1, 'transactionaudits hash unique');
    await hasKey(TransactionAudit, (key) => key.expiresAt === 1, 'transactionaudits TTL');
    await hasKey(ScamScan, (key) => key.userId === 1 && key.createdAt === -1, 'scamscans history');
    await hasKey(AuditLog, (key) => key.userId === 1 && key.assertionNonce === 1, 'auditlogs nonce guard');
    await hasKey(AppConfig, (key) => key.key === 1, 'appconfigs.key unique');

    const otpIndexes = await Otp.collection.indexes();
    assert.ok(
      otpIndexes.some((index) => index.expireAfterSeconds !== undefined),
      'otps has no TTL index'
    );

    const throttleIndexes = await SendThrottle.collection.indexes();
    assert.ok(
      throttleIndexes.some((index) => index.expireAfterSeconds !== undefined),
      'sendthrottles has no TTL index'
    );

    const auditIndexes = await AuditLog.collection.indexes();
    const nonceIndex = auditIndexes.find((index) => index.key.assertionNonce === 1);
    assert.equal(nonceIndex.unique, true);
    assert.ok(nonceIndex.partialFilterExpression, 'the nonce guard must stay partial');

    const nomineeIndexes = await Nominee.collection.indexes();
    const primaryIndex = nomineeIndexes.find((index) => index.name === 'one_primary_nominee_per_user');
    assert.equal(primaryIndex.unique, true);
    assert.deepEqual(primaryIndex.partialFilterExpression, { isPrimary: true });
  });

  await record('audit: no controller passes an unvalidated route param into a query', async () => {
    const dir = path.join(PROJECT_ROOT, 'controllers');
    const files = await fs.readdir(dir);
    const riskyPatterns = [/findById\(\s*req\.(params|query|body)/, /findOne\(\s*\{\s*_id:\s*req\.(params|query|body)/];

    for (const file of files) {
      const source = await fs.readFile(path.join(dir, file), 'utf8');

      assert.ok(
        source.includes("require('../utils/asyncHandler')"),
        `${file} does not wrap its handlers in asyncHandler`
      );

      for (const pattern of riskyPatterns) {
        assert.equal(pattern.test(source), false, `${file} passes a raw request value to Mongoose (${pattern})`);
      }
    }
  });

  await record('audit: the server has global rejection and exception handlers and no unref-less timers', async () => {
    const server = await readProjectFile('server.js');
    assert.match(server, /process\.on\('unhandledRejection'/);
    assert.match(server, /process\.on\('uncaughtException'/);

    const timerSources = [
      await readProjectFile('services/geminiService.js'),
      await readProjectFile('services/cloudinaryService.js'),
    ];

    for (const source of timerSources) {
      assert.match(source, /timer\.unref\(\)/, 'a provider timeout timer is not unref-ed');
      assert.match(source, /clearTimeout\(timer\)/, 'a provider timeout timer is not cleared');
    }
  });
}

// ===========================================================================
// Cleanup
// ===========================================================================
async function cleanupProbeData(seedState) {
  const User = require('../models/User');
  const Nominee = require('../models/Nominee');
  const FlaggedEntity = require('../models/FlaggedEntity');
  const AppConfig = require('../models/AppConfig');
  const AuditLog = require('../models/AuditLog');

  const report = { users: 0, nominees: 0, flagged: 0, config: 0, audits: 0 };

  if (seedState?.demoUserId) {
    report.nominees = (await Nominee.collection.deleteMany({ userId: seedState.demoUserId })).deletedCount || 0;
    report.users += (await User.collection.deleteMany({ _id: seedState.demoUserId })).deletedCount || 0;
    report.audits = (await AuditLog.collection.deleteMany({ userId: seedState.demoUserId })).deletedCount || 0;
  }

  report.flagged = (
    await FlaggedEntity.collection.deleteMany({ identifier: { $in: seedState?.identifiers || [] } })
  ).deletedCount || 0;

  report.config = (await AppConfig.collection.deleteMany({ key: 'GLOBAL_CONFIG' })).deletedCount || 0;

  if (seeded) {
    report.users += (await User.collection.deleteMany({ _id: seeded.user.objectId })).deletedCount || 0;
  }

  return {
    ...report,
    remainingDemoUsers: seedState?.demoUserId
      ? await User.collection.countDocuments({ _id: seedState.demoUserId })
      : 0,
    remainingFlagged: await FlaggedEntity.collection.countDocuments({
      identifier: { $in: seedState?.identifiers || [] },
    }),
    remainingConfig: await AppConfig.collection.countDocuments({ key: 'GLOBAL_CONFIG' }),
    remainingProbeUsers: seeded ? await User.collection.countDocuments({ _id: seeded.user.objectId }) : 0,
  };
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
    instance: { dbName: 'guardfi-phase10-verify', launchTimeout: 90_000 },
  });

  process.env.MONGO_URI = mongo.getUri('guardfi-phase10-verify');

  const { connectDatabase } = require('../config/db');
  await connectDatabase();

  let seedState = null;

  try {
    console.log('▶ Checking deployment deliverables...');
    await runDeliverableChecks();

    console.log('▶ Seeding a probe user and starting three servers...');
    await seedDataset();

    spawnServer({ port: MAIN_PORT, label: 'main server' });
    spawnServer({
      port: PROXY_PORT,
      label: 'proxy server',
      env: { TRUST_PROXY: '1', RATE_LIMIT_SKIP_IN_TEST: 'false', AUTH_RATE_LIMIT_MAX: '1' },
    });
    spawnServer({
      port: SOCKET_PORT,
      label: 'socket budget server',
      env: { SOCKET_MAX_CONNECTIONS_PER_IP: '1' },
    });

    await waitForHealth(MAIN_BASE);
    await waitForHealth(PROXY_BASE);
    await waitForHealth(SOCKET_BASE);

    console.log('▶ Running trust-proxy, rate-limit and socket checks...\n');
    await runTrustProxyChecks();
    await runProxyRateLimitChecks();
    await runSocketChecks();
  } catch (error) {
    results.push({ name: 'harness: servers became healthy', ok: false, error: error.message });
  } finally {
    await stopServers();
  }

  console.log('▶ Running demo-seed checks...');
  seedState = await runSeedChecks();

  console.log('▶ Running the audit sweep...');
  await runAuditSweep();

  await record('cleanup: seed, probe users and config are fully removed', async () => {
    const report = await cleanupProbeData(seedState);

    assert.ok(report.flagged >= 10, 'the cleanup expected the seeded blocklist');
    assert.equal(report.remainingDemoUsers, 0);
    assert.equal(report.remainingFlagged, 0);
    assert.equal(report.remainingConfig, 0);
    assert.equal(report.remainingProbeUsers, 0);
  });

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
