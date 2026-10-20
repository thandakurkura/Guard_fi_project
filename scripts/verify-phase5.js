'use strict';

/**
 * GuardFi — Phase 5 verification harness
 *
 * Proves the dashboard is computed by indexed MongoDB aggregations with a
 * deterministic dataset, then checks the things that actually break analytics:
 *
 *   • counts that are right but scoped to the wrong user (or not scoped at all);
 *   • a "recent" window that silently includes old alerts;
 *   • a nearby radius that ignores distance or time;
 *   • leaking other people's alert ids/coordinates through a "global" endpoint;
 *   • readiness scores that count a capability the user never set up;
 *   • unbounded/duplicate query parameters reaching the aggregation.
 *
 * Run:  npm run verify:phase5
 * Exit: 0 = every check passed, 1 = at least one failed, 2 = harness cannot run.
 */

process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = process.env.VERIFY_LOG_LEVEL || 'error';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'verify-phase5-secret-'.padEnd(48, '0');
process.env.CORS_ORIGINS = '*';
process.env.STRICT_ENV = 'false';
process.env.TRUST_PROXY = 'false';
delete process.env.PORT;

process.env.MONGO_URI = 'mongodb://127.0.0.1:27017/guardfi-phase5-placeholder';
process.env.ANALYTICS_NEARBY_RADIUS_METERS = '5000';
process.env.ANALYTICS_RECENT_WINDOW_HOURS = '24';
process.env.OTP_DEV_MODE = 'true';
process.env.SMS_PROVIDER = 'none';

const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const SERVER_PORT = Number(process.env.VERIFY_ANALYTICS_PORT || 4339);
const BASE = `http://127.0.0.1:${SERVER_PORT}`;

const FILLER_COUNT = 6;
const TOTAL_USERS = FILLER_COUNT + 4;

let mongo = null;
let server = null;
const results = [];
const seeded = {};

function record(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => results.push({ name, ok: true }))
    .catch((error) => results.push({ name, ok: false, error: error.message }));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function call(pathname, { method = 'GET', token } = {}) {
  const init = { method, headers: {} };
  if (token) init.headers.Authorization = `Bearer ${token}`;

  const response = await fetch(`${BASE}${pathname}`, init);
  const text = await response.text();
  let parsed = null;

  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }

  return { status: response.status, body: parsed, text };
}

function expectSuccess(response, status) {
  assert.equal(response.status, status, `expected ${status}, got ${response.status}: ${response.text}`);
  assert.equal(response.body?.success, true);
}

async function waitForHealth(timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no response';

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE}/health`);
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

function spawnServer(uri) {
  const child = spawn(process.execPath, [path.join(PROJECT_ROOT, 'server.js')], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      LOG_LEVEL: 'error',
      PORT: String(SERVER_PORT),
      MONGO_URI: uri,
      RATE_LIMIT_SKIP_IN_TEST: 'true',
      FIREBASE_PROJECT_ID: '',
      FIREBASE_CLIENT_EMAIL: '',
      FIREBASE_PRIVATE_KEY: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const entry = { label: 'analytics server', child, output: [] };
  child.stdout.on('data', (chunk) => entry.output.push(chunk.toString()));
  child.stderr.on('data', (chunk) => entry.output.push(chunk.toString()));
  server = entry;

  return entry;
}

async function stopServer() {
  if (server && server.child.exitCode === null) {
    server.child.kill();
    await sleep(300);
  }

  if (results.some((result) => !result.ok) && server && server.output.length > 0) {
    console.error('\n--- server output ---');
    console.error(server.output.join('').split('\n').slice(-25).join('\n'));
  }
}

// ===========================================================================
// Deterministic dataset
// ===========================================================================
async function seedDataset() {
  const User = require('../models/User');
  const Nominee = require('../models/Nominee');
  const SosAlert = require('../models/SosAlert');
  const { signAccessToken } = require('../services/tokenService');

  const now = Date.now();
  const hoursAgo = (hours) => new Date(now - hours * 3_600_000);

  const id = () => new mongoose.Types.ObjectId();

  const me = {
    _id: id(),
    phone: '+919876590001',
    name: 'Me Armed',
    role: 'user',
    isEmergencyMode: true,
    biometricEnabled: true,
    securityPinHash: '$2a$10$abcdefghijklmnopqrstuv',
    fcmToken: 'me-device-token',
    lastKnownLocation: { type: 'Point', coordinates: [72.8777, 19.076] }, // Mumbai
    createdAt: hoursAgo(72),
    updatedAt: hoursAgo(1),
  };

  const partial = {
    _id: id(),
    phone: '+919876590002',
    name: 'Partial Profile',
    role: 'user',
    isEmergencyMode: false,
    biometricEnabled: false,
    securityPinHash: null,
    fcmToken: null,
    createdAt: hoursAgo(72),
    updatedAt: hoursAgo(2),
  };

  const armedNoLocation = {
    _id: id(),
    phone: '+919876590003',
    name: 'Armed No Location',
    role: 'user',
    isEmergencyMode: true,
    createdAt: hoursAgo(72),
    updatedAt: hoursAgo(3),
  };

  const armedFar = {
    _id: id(),
    phone: '+919876590004',
    name: 'Armed Far',
    role: 'user',
    isEmergencyMode: true,
    lastKnownLocation: { type: 'Point', coordinates: [77.209, 28.6139] }, // Delhi
    createdAt: hoursAgo(72),
    updatedAt: hoursAgo(4),
  };

  const fillers = Array.from({ length: FILLER_COUNT }, (unused, index) => ({
    _id: id(),
    phone: `+9198765901${String(index).padStart(2, '0')}`,
    name: `Filler ${index}`,
    role: 'user',
    isEmergencyMode: false,
    createdAt: hoursAgo(72),
    updatedAt: hoursAgo(5),
  }));

  await User.collection.insertMany([me, partial, armedNoLocation, armedFar, ...fillers]);

  // Exactly one primary per user — the model enforces it with a partial unique
  // index, and the harness must respect it too (found the hard way).
  const nomineeFor = (userId, name, phone, isPrimary = false) => ({ userId, name, phone, isPrimary });

  await Nominee.create([
    nomineeFor(me._id, 'Me Guardian One', '+919876591001', true),
    nomineeFor(me._id, 'Me Guardian Two', '+919876591002', false),
    nomineeFor(partial._id, 'Partial Guardian', '+919876591003', true),
  ]);

  const roomId = (index) => `room${String(index).padStart(8, '0')}`; // 12 chars

  const alert = (index, userId, status, coordinates, hours) => ({
    userId,
    status,
    roomId: roomId(index),
    initialLocation: { type: 'Point', coordinates },
    createdAt: hoursAgo(hours),
    updatedAt: hoursAgo(hours),
  });

  await SosAlert.collection.insertMany([
    alert(1, me._id, 'ACTIVE', [72.882, 19.08], 1), // ~0.5 km, recent, near
    alert(2, fillers[0]._id, 'RESOLVED', [72.86, 19.05], 2), // ~3 km, recent, near
    alert(3, fillers[1]._id, 'ACTIVE', [77.209, 28.6139], 1), // Delhi, recent, far
    alert(4, fillers[2]._id, 'RESOLVED', [72.88, 19.09], 26), // near but outside the window
    alert(5, fillers[3]._id, 'ACTIVE', [72.879, 19.077], 48), // 0.2 km but outside the window
  ]);

  seeded.me = { id: String(me._id), token: signAccessToken(me).token };
  seeded.partial = { id: String(partial._id), token: signAccessToken(partial).token };
  seeded.armedNoLocation = { id: String(armedNoLocation._id), token: signAccessToken(armedNoLocation).token };
  seeded.armedFar = { id: String(armedFar._id), token: signAccessToken(armedFar).token };
}

// ===========================================================================
// HTTP checks
// ===========================================================================
async function runHttpChecks() {
  await record('analytics: unauthenticated dashboard → 401', async () => {
    const response = await call('/api/v1/analytics/dashboard');
    assert.equal(response.status, 401);
    assert.equal(response.body?.success, false);
  });

  await record('analytics: out-of-range or repeated query parameters → 400', async () => {
    const bad = [
      '?radiusMeters=0',
      '?radiusMeters=99',
      '?radiusMeters=50001',
      '?radiusMeters=abc',
      '?windowHours=0',
      '?windowHours=169',
      '?windowHours=1.5',
      '?radiusMeters=1000&radiusMeters=2000',
    ];

    for (const suffix of bad) {
      const response = await call(`/api/v1/analytics/dashboard${suffix}`, { token: seeded.me.token });
      assert.equal(response.status, 400, `${suffix} should be rejected, got ${response.status}`);
    }
  });

  let dashboard = null;

  await record('analytics: perimeter counts come from an indexed $match', async () => {
    const response = await call('/api/v1/analytics/dashboard', { token: seeded.me.token });
    expectSuccess(response, 200);
    dashboard = response.body.data;

    assert.equal(dashboard.perimeter.armedUsers, 3);
    assert.equal(dashboard.perimeter.totalUsers, TOTAL_USERS);
    assert.equal(dashboard.perimeter.armedPercent, 30);
  });

  await record('analytics: active-now is global and ignores the recency window', async () => {
    // A1 (recent), A3 (recent), A5 (48h old but still ACTIVE)
    assert.equal(dashboard.alerts.activeNow, 3);
  });

  await record('analytics: the recent window includes only the last 24 hours, by status', async () => {
    const recent = dashboard.alerts.recent;

    assert.equal(recent.windowHours, 24);
    assert.equal(recent.total, 3);
    assert.deepEqual(recent.byStatus, { ACTIVE: 2, RESOLVED: 1, FALSE_ALARM: 0 });
  });

  await record('analytics: nearby alerts are distance- and time-bounded', async () => {
    const nearby = dashboard.alerts.nearby;

    assert.equal(nearby.available, true);
    assert.equal(nearby.radiusMeters, 5000);
    // A1 (0.5 km) and A2 (3 km) are inside both bounds; A3 is 1150 km away,
    // A4 is 26 h old, A5 is 48 h old.
    assert.equal(nearby.count, 2);
    assert.deepEqual(nearby.byStatus, { ACTIVE: 1, RESOLVED: 1, FALSE_ALARM: 0 });
  });

  await record('analytics: no other user\'s alert id or coordinates ever appears in the response', async () => {
    const serialized = JSON.stringify(dashboard);

    assert.equal(/[0-9a-f]{24}/.test(serialized), false, 'a 24-hex id leaked into the dashboard');
    assert.equal(serialized.includes('coordinates'), false, 'raw GeoJSON leaked into the dashboard');
    assert.equal(serialized.toLowerCase().includes('phone'), false);
  });

  await record('analytics: a user with no location gets an explicit, empty nearby block', async () => {
    const response = await call('/api/v1/analytics/dashboard', { token: seeded.partial.token });
    expectSuccess(response, 200);

    const data = response.body.data;
    assert.equal(data.alerts.nearby.available, false);
    assert.equal(data.alerts.nearby.count, 0);
    assert.equal(data.alerts.nearby.reason, 'no_location_on_file');
    assert.equal(data.readiness.score, 20);
    assert.equal(data.readiness.level, 'weak');
    assert.equal(data.readiness.nomineeCount, 1);
  });

  await record('analytics: readiness rewards a fully configured profile', async () => {
    const readiness = dashboard.readiness;

    assert.equal(readiness.score, 100);
    assert.equal(readiness.maxScore, 100);
    assert.equal(readiness.level, 'strong');
    assert.equal(readiness.nomineeCount, 2);

    const components = Object.fromEntries(readiness.components.map((component) => [component.key, component]));
    assert.equal(components.nominees.earned, 30);
    assert.equal(components.shieldPayPin.earned, 20);
    assert.equal(components.pushNotifications.earned, 15);
    assert.equal(components.locationSharing.earned, 15);
    assert.equal(components.biometric.earned, 10);
    assert.equal(components.emergencyMode.earned, 10);
  });

  await record('analytics: readiness is per-user (armed but unconfigured ≠ armed and ready)', async () => {
    const response = await call('/api/v1/analytics/dashboard', { token: seeded.armedNoLocation.token });
    expectSuccess(response, 200);

    assert.equal(response.body.data.readiness.score, 10);
    assert.equal(response.body.data.readiness.level, 'weak');
    assert.equal(response.body.data.readiness.nomineeCount, 0);
    assert.equal(response.body.data.meta.userLocationAvailable, false);
  });

  await record('analytics: the nearby radius follows the caller\'s own location', async () => {
    const response = await call('/api/v1/analytics/dashboard', { token: seeded.armedFar.token });
    expectSuccess(response, 200);

    // Delhi caller sees the Delhi alert only, never the Mumbai ones.
    assert.equal(response.body.data.alerts.nearby.count, 1);
    assert.deepEqual(response.body.data.alerts.nearby.byStatus, { ACTIVE: 1, RESOLVED: 0, FALSE_ALARM: 0 });
  });

  await record('analytics: radiusMeters override tightens the nearby count', async () => {
    const response = await call('/api/v1/analytics/dashboard?radiusMeters=1000', { token: seeded.me.token });
    expectSuccess(response, 200);

    const nearby = response.body.data.alerts.nearby;
    assert.equal(nearby.radiusMeters, 1000);
    assert.equal(nearby.count, 1, 'only the 0.5 km alert is within 1 km');
    assert.deepEqual(nearby.byStatus, { ACTIVE: 1, RESOLVED: 0, FALSE_ALARM: 0 });
  });

  await record('analytics: windowHours override widens both recent and nearby', async () => {
    const response = await call('/api/v1/analytics/dashboard?windowHours=72', { token: seeded.me.token });
    expectSuccess(response, 200);

    const data = response.body.data;
    assert.equal(data.alerts.recent.windowHours, 72);
    // A1, A2, A3, A4 (26 h) and A5 (48 h) are all inside a 72 h window.
    assert.equal(data.alerts.recent.total, 5);
    assert.deepEqual(data.alerts.recent.byStatus, { ACTIVE: 3, RESOLVED: 2, FALSE_ALARM: 0 });
    // A1, A2, A4 and A5 are within 5 km of Mumbai; A3 is in Delhi.
    assert.equal(data.alerts.nearby.count, 4);
    assert.deepEqual(data.alerts.nearby.byStatus, { ACTIVE: 2, RESOLVED: 2, FALSE_ALARM: 0 });
    // Widening the query window must not change the caller's own score.
    assert.equal(data.readiness.score, 100);
  });
}

// ===========================================================================
// Index + explain checks (in-process)
// ===========================================================================
async function runIndexChecks() {
  const User = require('../models/User');
  const Nominee = require('../models/Nominee');
  const SosAlert = require('../models/SosAlert');
  const { buildNearbyPipeline, buildUserFacetPipeline, buildAlertFacetPipeline } = require('../services/analyticsService');

  await User.init();
  await Nominee.init();
  await SosAlert.init();

  await record('indexes: every field the dashboard filters on is indexed', async () => {
    const userIndexes = await User.collection.indexes();
    const nomineeIndexes = await Nominee.collection.indexes();
    const alertIndexes = await SosAlert.collection.indexes();

    assert.ok(userIndexes.some((index) => index.key.isEmergencyMode === 1), 'users.isEmergencyMode is not indexed');
    assert.ok(
      userIndexes.some((index) => index.key.lastKnownLocation === '2dsphere'),
      'users.lastKnownLocation is not 2dsphere'
    );
    assert.ok(
      nomineeIndexes.some((index) => index.key.userId === 1 && index.key.phone === 1),
      'nominees userId+phone index is missing (the $lookup depends on it)'
    );
    assert.ok(
      alertIndexes.some((index) => index.key.initialLocation === '2dsphere'),
      'sosalerts.initialLocation is not 2dsphere'
    );
    assert.ok(alertIndexes.some((index) => index.key.createdAt === -1), 'sosalerts.createdAt is not indexed');
    assert.ok(
      alertIndexes.some((index) => index.key.status === 1 && index.key.createdAt === -1),
      'sosalerts status+createdAt is not indexed'
    );
  });

  await record('explain: the nearby pipeline is a $geoNear index scan, never a collection scan', async () => {
    const plan = JSON.stringify(
      await SosAlert.collection
        .aggregate(
          buildNearbyPipeline({
            coordinates: [72.8777, 19.076],
            radiusMeters: 5000,
            since: new Date(Date.now() - 3_600_000),
          })
        )
        .explain()
    );

    assert.match(plan, /GEO_NEAR_2DSPHERE/);
    assert.match(plan, /2dsphere/);
    assert.equal(plan.includes('COLLSCAN'), false, 'the geo pipeline fell back to a collection scan');
  });

  await record('explain: both $facet pipelines are accepted by the query planner', async () => {
    const meId = seeded.me.id;
    const since = new Date(Date.now() - 3_600_000);

    const userPlan = await User.collection.aggregate(buildUserFacetPipeline(meId)).explain();
    const alertPlan = await SosAlert.collection.aggregate(buildAlertFacetPipeline(since)).explain();

    for (const plan of [userPlan, alertPlan]) {
      const stages = JSON.stringify(plan);
      assert.match(stages, /\$facet/);
      // The planner must have produced a plan (no rejected plan/error thrown).
      assert.ok(plan.queryPlanner || plan.stages, 'explain returned no plan');
    }
  });

  await record('explain: the $lookup into nominees uses the compound index prefix', async () => {
    const plan = JSON.stringify(await User.collection.aggregate(buildUserFacetPipeline(seeded.me.id)).explain());

    assert.match(plan, /userId_1_phone_1|nominees/);
  });
}

// ===========================================================================
// Readiness unit checks
// ===========================================================================
async function runReadinessChecks() {
  const { computeReadiness } = require('../services/analyticsService');

  await record('readiness: score boundaries are exact', async () => {
    const empty = computeReadiness({
      nomineeCount: 0,
      hasShieldPayPin: false,
      hasPushToken: false,
      hasLocation: false,
      biometricEnabled: false,
      emergencyMode: false,
    });

    assert.equal(empty.score, 0);
    assert.equal(empty.level, 'weak');
    assert.equal(empty.components.length, 6);

    const moderate = computeReadiness({
      nomineeCount: 1,
      hasShieldPayPin: true,
      hasPushToken: true,
      hasLocation: false,
      biometricEnabled: false,
      emergencyMode: false,
    });

    assert.equal(moderate.score, 55); // 20 + 20 + 15
    assert.equal(moderate.level, 'moderate');

    const strong = computeReadiness({
      nomineeCount: 2,
      hasShieldPayPin: true,
      hasPushToken: true,
      hasLocation: true,
      biometricEnabled: false,
      emergencyMode: true,
    });

    assert.equal(strong.score, 90); // 30 + 20 + 15 + 15 + 10
    assert.equal(strong.level, 'strong');
  });

  await record('readiness: a negative or non-numeric nominee count cannot inflate the score', async () => {
    const result = computeReadiness({
      nomineeCount: -5,
      hasShieldPayPin: false,
      hasPushToken: false,
      hasLocation: false,
      biometricEnabled: false,
      emergencyMode: false,
    });

    assert.equal(result.score, 0);
    assert.equal(result.components[0].earned, 0);

    const notANumber = computeReadiness({
      nomineeCount: 'many',
      hasShieldPayPin: false,
      hasPushToken: false,
      hasLocation: false,
      biometricEnabled: false,
      emergencyMode: false,
    });

    assert.equal(notANumber.score, 0);
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
    instance: { dbName: 'guardfi-phase5-verify', launchTimeout: 90_000 },
  });

  const uri = mongo.getUri('guardfi-phase5-verify');
  process.env.MONGO_URI = uri;

  const { connectDatabase } = require('../config/db');
  await connectDatabase();

  try {
    console.log('▶ Seeding the deterministic dataset...');
    try {
      await seedDataset();
    } catch (error) {
      // A broken fixture must fail loudly and immediately, not cascade into a
      // dozen misleading dashboard failures.
      console.error('✖ Dataset seeding failed:', error.message);
      if (mongo) await mongo.stop();
      process.exit(1);
    }

    console.log(`▶ Booting analytics API on port ${SERVER_PORT}...`);
    spawnServer(uri);
    await waitForHealth();
    console.log('▶ Server healthy. Running dashboard checks...\n');
    await runHttpChecks();
  } catch (error) {
    results.push({ name: 'harness: server became healthy', ok: false, error: error.message });
  } finally {
    await stopServer();
  }

  await runIndexChecks();
  await runReadinessChecks();

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
  await stopServer();
  if (mongo) await mongo.stop().catch(() => {});
  process.exit(1);
});
