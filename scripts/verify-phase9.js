'use strict';

/**
 * GuardFi — Phase 9 verification harness (dynamic global configuration)
 *
 * Proves, against a real Express server and a throwaway MongoDB:
 *   • GET /api/v1/config/global is PUBLIC — no token, and a garbage token, both
 *     answer 200;
 *   • the first read auto-seeds the AppConfig singleton with the documented
 *     defaults and reports source: 'database'; the next reports 'cache';
 *   • a cache hit performs NO database work (proved by deleting the document
 *     from under the cache, and by counting model calls);
 *   • the cache entry carries the configured TTL;
 *   • PUT requires an admin: anonymous 401, plain user 403, malformed 400;
 *   • an accepted PUT updates MongoDB, invalidates the cache immediately (the
 *     very next GET reports 'database' with the new values), bumps the version
 *     and writes an immutable AuditLog row;
 *   • nested threshold updates are partial — they never wipe the keys the admin
 *     did not send;
 *   • the singleton stays a singleton, including under concurrent cold reads;
 *   • a cached read is measurably cheaper than a database read.
 *
 * Run:  npm run verify:phase9
 * Exit: 0 = every check passed, 1 = at least one failed, 2 = harness cannot run.
 */

process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = process.env.VERIFY_LOG_LEVEL || 'error';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'verify-phase9-secret-'.padEnd(48, '0');
process.env.CORS_ORIGINS = '*';
process.env.STRICT_ENV = 'false';
process.env.TRUST_PROXY = 'false';
delete process.env.PORT;

process.env.MONGO_URI = 'mongodb://127.0.0.1:27017/guardfi-phase9-placeholder';
process.env.OTP_DEV_MODE = 'true';
process.env.SMS_PROVIDER = 'none';
process.env.GLOBAL_CONFIG_CACHE_TTL_SECONDS = '600';
process.env.BIOMETRIC_SHARED_SECRET = 'phase9-verify-secret-'.padEnd(64, 'k');

const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const MAIN_PORT = Number(process.env.VERIFY_CONFIG_PORT || 4345);
const MAIN_BASE = `http://127.0.0.1:${MAIN_PORT}`;
const USER_AGENT = 'GuardFi-Phase9-Verify/1.0';
const CONFIG_PATH = '/api/v1/config/global';

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

async function call(pathname, { method = 'GET', token, body, headers = {} } = {}) {
  const init = { method, headers: { 'user-agent': USER_AGENT, ...headers } };
  if (token) init.headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const response = await fetch(`${MAIN_BASE}${pathname}`, init);
  const text = await response.text();
  let parsed = null;

  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }

  return { status: response.status, body: parsed, text, headers: response.headers };
}

function expectSuccess(response, status) {
  assert.equal(response.status, status, `expected ${status}, got ${response.status}: ${response.text}`);
  assert.equal(response.body?.success, true);
}

function expectErrorCode(response, status, code) {
  assert.equal(response.status, status, `expected ${status}, got ${response.status}: ${response.text}`);
  assert.equal(response.body?.success, false);
  const haystack = `${response.body?.message || ''} ${JSON.stringify(response.body?.errors || [])}`;
  assert.ok(haystack.includes(code), `expected code ${code} in ${response.text}`);
}

async function waitForHealth(timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no response';

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${MAIN_BASE}/health`);
      const body = await response.json();
      if (
        response.status === 200 &&
        body?.data?.database?.connected === true &&
        body?.data?.database?.indexesReady === true
      ) {
        return body;
      }
      last = `status=${response.status} db=${body?.data?.database?.state}`;
    } catch (error) {
      last = error.message;
    }
    await sleep(400);
  }

  throw new Error(`server never became healthy within ${timeoutMs}ms (last: ${last})`);
}

function spawnServer({ port, env = {}, label }) {
  const child = spawn(process.execPath, [path.join(PROJECT_ROOT, 'server.js')], {
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

// ===========================================================================
// Dataset
// ===========================================================================
async function seedDataset() {
  const User = require('../models/User');
  const { signAccessToken } = require('../services/tokenService');

  await User.init();

  const make = (phone, name, role) => ({
    _id: new mongoose.Types.ObjectId(),
    phone,
    name,
    role,
    securityPinHash: null,
    isEmergencyMode: false,
    biometricEnabled: false,
    emergencyActivatedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  const admin = make('+919876570001', 'Config Admin', 'admin');
  const user = make('+919876570002', 'Config User', 'user');

  await User.collection.insertMany([admin, user]);

  seeded = {
    admin: { id: String(admin._id), objectId: admin._id, token: signAccessToken(admin).token },
    user: { id: String(user._id), objectId: user._id, token: signAccessToken(user).token },
  };

  return seeded;
}

/** Median of a numeric list; used for the cache-vs-database comparison. */
function median(values) {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle];
}

/** Wrap AppConfig.findOneAndUpdate with a counter, so "cache hit does no DB work" is measured, not assumed. */
function instrumentConfigReads() {
  const AppConfig = require('../models/AppConfig');
  const original = AppConfig.findOneAndUpdate;
  const counter = { reads: 0 };

  AppConfig.findOneAndUpdate = function countedFindOneAndUpdate(...args) {
    counter.reads += 1;
    return original.apply(this, args);
  };

  return {
    counter,
    restore() {
      AppConfig.findOneAndUpdate = original;
    },
  };
}

// ===========================================================================
// HTTP checks
// ===========================================================================
async function runPublicReadChecks() {
  await record('public: GET /config/global works with no token and auto-seeds the defaults', async () => {
    const response = await call(CONFIG_PATH);

    expectSuccess(response, 200);
    const { source, config } = response.body.data;

    assert.equal(source, 'database', 'the first read must come from the database');
    assert.equal(config.key, 'GLOBAL_CONFIG');
    assert.equal(config.privacyPolicyUrl, '');
    assert.equal(config.termsUrl, '');
    assert.deepEqual(config.globalWarningThresholds, {
      upiRiskScoreThreshold: 70,
      sosRadiusMeters: 5000,
      maxNomineesPerUser: 5,
    });
    assert.equal(config.maintenanceMode, false);
    assert.equal(config.emergencyHelplines.length, 3);
    assert.deepEqual(
      config.emergencyHelplines.map((entry) => entry.number),
      ['112', '1930', '1091']
    );
    assert.ok(config.emergencyHelplines.every((entry) => entry.name_en && entry.name_hi));
    assert.equal(config.version, 1);
    assert.equal(response.headers.get('cache-control'), 'no-store');
  });

  await record('public: a garbage Authorization header is ignored, not rejected', async () => {
    const response = await call(CONFIG_PATH, { headers: { Authorization: 'Bearer not-a-real-token' } });
    expectSuccess(response, 200);
    assert.equal(response.body.data.source, 'cache');
  });

  await record('cache: the second read is served from the cache (no database pass)', async () => {
    const response = await call(CONFIG_PATH);

    expectSuccess(response, 200);
    assert.equal(response.body.data.source, 'cache');
  });
}

async function runUpdateChecks() {
  const { admin, user } = seeded;

  await record('auth: PUT /config/global refuses anonymous and non-admin callers', async () => {
    const anonymous = await call(CONFIG_PATH, { method: 'PUT', body: { maintenanceMode: true } });
    expectErrorCode(anonymous, 401, 'Authentication token is missing');

    const plainUser = await call(CONFIG_PATH, {
      method: 'PUT',
      token: user.token,
      body: { maintenanceMode: true },
    });
    assert.equal(plainUser.status, 403, plainUser.text);
    assert.equal(plainUser.body.success, false);
    assert.match(plainUser.body.message, /role/i);
  });

  await record('validation: malformed admin payloads are rejected before any write', async () => {
    const cases = [
      {},
      { privacyPolicyUrl: 'not-a-url' },
      { termsUrl: 'ftp://example.com/terms' },
      { maintenanceMode: 'true' },
      { globalWarningThresholds: {} },
      { globalWarningThresholds: { upiRiskScoreThreshold: 0 } },
      { globalWarningThresholds: { upiRiskScoreThreshold: 101 } },
      { globalWarningThresholds: { sosRadiusMeters: 50 } },
      { globalWarningThresholds: { maxNomineesPerUser: 51 } },
      { emergencyHelplines: [] },
      { emergencyHelplines: [{ name_en: 'Police', name_hi: 'पुलिस', number: 'abc' }] },
      { emergencyHelplines: [{ name_en: 'Police', name_hi: 'पुलिस' }] },
      { maintainanceMode: true },
    ];

    for (const body of cases) {
      const response = await call(CONFIG_PATH, { method: 'PUT', token: admin.token, body });
      assert.equal(response.status, 400, `expected 400 for ${JSON.stringify(body)}: ${response.text}`);
      assert.equal(response.body.success, false);
      assert.ok(Array.isArray(response.body.errors) && response.body.errors.length > 0, response.text);
    }

    const AuditLog = require('../models/AuditLog');
    assert.equal(await AuditLog.countDocuments({ action: 'CONFIG_UPDATED' }), 0, 'a rejected PUT was audited');
  });

  await record('update: an admin PUT changes MongoDB, bumps the version and audits the write', async () => {
    const response = await call(CONFIG_PATH, {
      method: 'PUT',
      token: admin.token,
      body: {
        maintenanceMode: true,
        globalWarningThresholds: { upiRiskScoreThreshold: 85 },
      },
    });

    expectSuccess(response, 200);
    const data = response.body.data;

    assert.equal(data.config.maintenanceMode, true);
    assert.equal(data.config.globalWarningThresholds.upiRiskScoreThreshold, 85);
    assert.equal(
      data.config.globalWarningThresholds.sosRadiusMeters,
      5000,
      'a partial threshold update must not wipe the keys the admin did not send'
    );
    assert.equal(data.version, 2);
    assert.equal(data.previousVersion, 1);
    assert.equal(data.cacheInvalidated, true);
    assert.deepEqual([...data.changedFields].sort(), ['globalWarningThresholds', 'maintenanceMode']);
    assert.equal(data.audit.action, 'CONFIG_UPDATED');

    const AuditLog = require('../models/AuditLog');
    const row = await AuditLog.findById(data.audit.id).lean();
    assert.equal(row.userId.toString(), admin.id);
    assert.equal(row.action, 'CONFIG_UPDATED');
    assert.equal(row.userAgent, USER_AGENT);
    assert.ok(row.ipAddress);
    assert.equal(row.details.requestedAction, 'UPDATE_GLOBAL_CONFIG');
    assert.match(row.details.note, /maintenanceMode/);
  });

  await record('update: the very next GET misses the cache and shows the new values', async () => {
    const response = await call(CONFIG_PATH);

    expectSuccess(response, 200);
    assert.equal(response.body.data.source, 'database', 'the PUT must have invalidated the cache');
    assert.equal(response.body.data.config.maintenanceMode, true);
    assert.equal(response.body.data.config.globalWarningThresholds.upiRiskScoreThreshold, 85);
    assert.equal(response.body.data.config.version, 2);

    const cached = await call(CONFIG_PATH);
    assert.equal(cached.body.data.source, 'cache');
  });

  await record('update: policy URLs and the helpline list are replaceable', async () => {
    const response = await call(CONFIG_PATH, {
      method: 'PUT',
      token: admin.token,
      body: {
        privacyPolicyUrl: 'https://guardfi.app/privacy',
        termsUrl: 'https://guardfi.app/terms',
        emergencyHelplines: [
          { name_en: 'Police', name_hi: 'पुलिस', number: '112' },
          { name_en: 'Cyber Crime Helpline', name_hi: 'साइबर अपराध हेल्पलाइन', number: '1930' },
          { name_en: 'Women Helpline', name_hi: 'महिला हेल्पलाइन', number: '1091' },
          { name_en: 'Child Helpline', name_hi: 'चाइल्ड हेल्पलाइन', number: '1098' },
        ],
      },
    });

    expectSuccess(response, 200);
    assert.equal(response.body.data.version, 3);

    const read = await call(CONFIG_PATH);
    assert.equal(read.body.data.config.privacyPolicyUrl, 'https://guardfi.app/privacy');
    assert.equal(read.body.data.config.termsUrl, 'https://guardfi.app/terms');
    assert.equal(read.body.data.config.emergencyHelplines.length, 4);
    assert.ok(read.body.data.config.emergencyHelplines.some((entry) => entry.number === '1098'));
  });

  await record('update: a nested threshold update is partial in both directions', async () => {
    const response = await call(CONFIG_PATH, {
      method: 'PUT',
      token: admin.token,
      body: { globalWarningThresholds: { maxNomineesPerUser: 9 } },
    });

    expectSuccess(response, 200);
    const thresholds = response.body.data.config.globalWarningThresholds;

    assert.equal(thresholds.maxNomineesPerUser, 9);
    assert.equal(thresholds.upiRiskScoreThreshold, 85, 'the other threshold was overwritten');
    assert.equal(thresholds.sosRadiusMeters, 5000);
    assert.equal(response.body.data.version, 4);
  });
}

// ===========================================================================
// Singleton + in-process service checks
// ===========================================================================
async function runModelAndServiceChecks() {
  const AppConfig = require('../models/AppConfig');
  const {
    getGlobalConfig,
    getCacheStats,
    getCacheTtlRemainingSeconds,
    invalidateGlobalConfigCache,
    updateGlobalConfig,
  } = require('../services/configService');

  await record('cache: a warmed entry carries the configured 600-second TTL', async () => {
    await getGlobalConfig(); // warm the harness process's own cache

    const remaining = getCacheTtlRemainingSeconds();
    assert.ok(remaining > 580 && remaining <= 600, `TTL remaining was ${remaining}s`);
    assert.equal(getCacheStats().keys, 1);
  });

  await record('cache: a cache hit performs no model call at all', async () => {
    const instrumentation = instrumentConfigReads();

    try {
      await getGlobalConfig();
      const result = await getGlobalConfig();

      assert.equal(result.source, 'cache');
      assert.equal(instrumentation.counter.reads, 0, 'a cache hit must not call the model');
      assert.ok(getCacheStats().hits > 0);
    } finally {
      instrumentation.restore();
    }
  });

  await record('cache: a warm cache keeps serving while the document is gone, then re-seeds on a miss', async () => {
    await AppConfig.collection.deleteMany({ key: 'GLOBAL_CONFIG' });
    assert.equal(await AppConfig.collection.countDocuments({ key: 'GLOBAL_CONFIG' }), 0);

    const warm = await getGlobalConfig();
    assert.equal(warm.source, 'cache', 'the cache should still answer with the document deleted');

    invalidateGlobalConfigCache();

    const reseeded = await getGlobalConfig();
    assert.equal(reseeded.source, 'database');
    assert.equal(reseeded.config.version, 1);
    assert.equal(await AppConfig.collection.countDocuments({ key: 'GLOBAL_CONFIG' }), 1);
  });

  await record('singleton: exactly one configuration document exists after all writes', async () => {
    assert.equal(await AppConfig.collection.countDocuments({ key: 'GLOBAL_CONFIG' }), 1);
  });

  await record('singleton: concurrent cold reads still produce exactly one document', async () => {
    await AppConfig.collection.deleteMany({ key: 'GLOBAL_CONFIG' });
    invalidateGlobalConfigCache();

    const reads = await Promise.all(Array.from({ length: 6 }, () => getGlobalConfig()));

    assert.equal(reads.length, 6);
    assert.ok(reads.every((entry) => entry.config.key === 'GLOBAL_CONFIG'));
    assert.equal(await AppConfig.collection.countDocuments({ key: 'GLOBAL_CONFIG' }), 1);
  });

  await record('model: the key index is unique and the defaults are returned fresh', async () => {
    const indexes = await AppConfig.collection.indexes();
    const keyIndex = indexes.find((index) => index.key.key === 1);
    assert.ok(keyIndex, 'AppConfig.key_1 missing');
    assert.equal(keyIndex.unique, true);

    const first = AppConfig.defaultConfigValues();
    first.globalWarningThresholds.upiRiskScoreThreshold = 1;
    first.emergencyHelplines[0].number = '000';

    const second = AppConfig.defaultConfigValues();
    assert.equal(second.globalWarningThresholds.upiRiskScoreThreshold, 70);
    assert.equal(second.emergencyHelplines[0].number, '112');
  });

  await record('model: invalid values cannot be written even without the validator', async () => {
    await assert.rejects(
      () => AppConfig.applyUpdate({ updates: { globalWarningThresholds: { upiRiskScoreThreshold: 500 } } }),
      (error) => error.name === 'ValidationError'
    );

    await assert.rejects(
      () => AppConfig.applyUpdate({ updates: { privacyPolicyUrl: 'javascript:alert(1)' } }),
      (error) => error.name === 'ValidationError'
    );

    await assert.rejects(
      () => AppConfig.applyUpdate({ updates: { unknownSetting: true } }),
      (error) => error.name === 'StrictModeError'
    );
  });

  await record('cache: a cached read is measurably faster than a database read', async () => {
    const cachedTimes = [];
    const databaseTimes = [];

    await getGlobalConfig(); // warm

    for (let index = 0; index < 25; index += 1) {
      const startedAt = process.hrtime.bigint();
      const result = await getGlobalConfig();
      cachedTimes.push(Number(process.hrtime.bigint() - startedAt) / 1e6);
      assert.equal(result.source, 'cache');
    }

    for (let index = 0; index < 25; index += 1) {
      invalidateGlobalConfigCache();
      const startedAt = process.hrtime.bigint();
      const result = await getGlobalConfig();
      databaseTimes.push(Number(process.hrtime.bigint() - startedAt) / 1e6);
      assert.equal(result.source, 'database');
    }

    const cachedMedian = median(cachedTimes);
    const databaseMedian = median(databaseTimes);

    console.log(
      `  · cached median ${cachedMedian.toFixed(3)} ms vs database median ${databaseMedian.toFixed(3)} ms (25 samples each)`
    );

    assert.ok(cachedMedian < 5, `a cached read took ${cachedMedian} ms`);
    assert.ok(
      cachedMedian < databaseMedian,
      `cached (${cachedMedian} ms) should beat database (${databaseMedian} ms)`
    );
  });

  await record('service: a cold cache with no database connection fails closed with 503', async () => {
    // Flipping readiness in-process would mean dropping the shared connection the
    // rest of this harness still needs, so the cold-cache path runs in a child
    // process that never connects: the service must refuse rather than invent
    // defaults while an admin's real values are unreachable.
    const script = [
      "process.env.NODE_ENV='test';",
      "process.env.MONGO_URI='mongodb://127.0.0.1:1/guardfi-cold-cache';",
      "process.env.JWT_SECRET='cold-cache-secret-'.padEnd(48,'0');",
      "process.env.STRICT_ENV='false';",
      "process.env.OTP_DEV_MODE='true';",
      "process.env.SMS_PROVIDER='none';",
      "require('./services/configService').getGlobalConfig()",
      ".then(() => { console.log('UNEXPECTED_SUCCESS'); process.exit(1); })",
      ".catch((error) => {",
      "  const codes = JSON.stringify(error.errors || []);",
      "  console.log(JSON.stringify({ statusCode: error.statusCode, found: codes.includes('CONFIG_STORE_UNAVAILABLE') }));",
      '  process.exit(error.statusCode === 503 && codes.includes(\'CONFIG_STORE_UNAVAILABLE\') ? 0 : 1);',
      '});',
    ].join('\n');

    const child = spawn(process.execPath, ['-e', script], { cwd: PROJECT_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => (stdout += chunk.toString()));
    child.stderr.on('data', (chunk) => (stderr += chunk.toString()));

    const exitCode = await new Promise((resolve) => child.on('close', resolve));

    assert.equal(exitCode, 0, `cold-cache probe exited ${exitCode}: ${stdout}${stderr}`);
    assert.match(stdout, /CONFIG_STORE_UNAVAILABLE|\"found\":true/);
  });

  await record('service: updateGlobalConfig invalidates the cache and versions the write', async () => {
    const before = await getGlobalConfig();
    const beforeVersion = before.config.version;

    const result = await updateGlobalConfig({
      updates: { maintenanceMode: false },
      adminId: seeded.admin.objectId,
      request: { ipAddress: '203.0.113.11', userAgent: USER_AGENT },
    });

    assert.equal(result.version, beforeVersion + 1);
    assert.equal(result.config.maintenanceMode, false);
    assert.equal(result.cacheInvalidated, true);

    const after = await getGlobalConfig();
    assert.equal(after.source, 'database', 'updateGlobalConfig must clear the cache entry');
  });
}

// ===========================================================================
// Cleanup
// ===========================================================================
async function cleanupProbeData() {
  const User = require('../models/User');
  const AuditLog = require('../models/AuditLog');
  const AppConfig = require('../models/AppConfig');

  const config = await AppConfig.collection.deleteMany({ key: 'GLOBAL_CONFIG' });
  const audits = await AuditLog.collection.deleteMany({
    userId: { $in: [seeded.admin.objectId, seeded.user.objectId] },
  });
  const users = await User.collection.deleteMany({
    _id: { $in: [seeded.admin.objectId, seeded.user.objectId] },
  });

  return {
    config: config.deletedCount || 0,
    audits: audits.deletedCount || 0,
    users: users.deletedCount || 0,
    remainingConfig: await AppConfig.collection.countDocuments({}),
    remainingAudits: await AuditLog.collection.countDocuments({
      userId: { $in: [seeded.admin.objectId, seeded.user.objectId] },
    }),
    remainingUsers: await User.collection.countDocuments({
      _id: { $in: [seeded.admin.objectId, seeded.user.objectId] },
    }),
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
    instance: { dbName: 'guardfi-phase9-verify', launchTimeout: 90_000 },
  });

  process.env.MONGO_URI = mongo.getUri('guardfi-phase9-verify');

  const { connectDatabase } = require('../config/db');
  await connectDatabase();

  try {
    console.log('▶ Seeding an admin and a plain user...');
    await seedDataset();

    console.log(`▶ Booting the server on ${MAIN_PORT}...`);
    spawnServer({ port: MAIN_PORT, label: 'config server' });
    await waitForHealth();

    console.log('▶ Server healthy. Running configuration checks...\n');
    await runPublicReadChecks();
    await runUpdateChecks();
  } catch (error) {
    results.push({ name: 'harness: server became healthy', ok: false, error: error.message });
  } finally {
    await stopServers();
  }

  if (seeded) {
    await runModelAndServiceChecks();
  }

  await record('cleanup: probe config, audit rows and users are fully removed', async () => {
    const report = await cleanupProbeData();
    assert.ok(report.config > 0, 'the probe expected a config document to clean up');
    assert.equal(report.users, 2);
    assert.equal(report.remainingConfig, 0, 'the probe config survived cleanup');
    assert.equal(report.remainingAudits, 0, 'probe audit rows survived cleanup');
    assert.equal(report.remainingUsers, 0, 'probe users survived cleanup');
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
  if (seeded) await cleanupProbeData().catch(() => {});
  if (mongo) await mongo.stop().catch(() => {});
  process.exit(1);
});
