'use strict';

/**
 * GuardFi — Phase 4 verification harness
 *
 * Proves SOS alerts, GeoJSON storage, JWT-authenticated Socket.io rooms, live
 * location broadcasting and write throttling against a throwaway in-memory
 * MongoDB. Your .env, Atlas cluster, FCM project and SMS credit are untouched.
 *
 * It attacks the parts that fail in real emergencies:
 *   • unauthorised REST calls and unauthenticated/expired socket handshakes;
 *   • a stranger joining the SOS room, and a guardian trying to move the victim's
 *     marker or stop the alert;
 *   • duplicate triggers (only one ACTIVE alert, no duplicate notifications);
 *   • invalid/out-of-range coordinates and malformed socket payloads;
 *   • a 4-packets-per-second stream: broadcasts continue, database writes are
 *     throttled, the per-socket rate limit trips, and history stays capped;
 *   • push and SMS transports with injected fakes, including provider failure.
 *
 * Run:  npm run verify:phase4
 * Exit: 0 = every check passed, 1 = at least one failed, 2 = harness cannot run.
 */

// --- environment for THIS process (must precede every local require) --------
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = process.env.VERIFY_LOG_LEVEL || 'error';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'verify-phase4-secret-'.padEnd(48, '0');
process.env.CORS_ORIGINS = '*';
process.env.STRICT_ENV = 'false';
process.env.TRUST_PROXY = 'false';
delete process.env.PORT;

process.env.MONGO_URI = 'mongodb://127.0.0.1:27017/guardfi-phase4-placeholder';

process.env.SOS_LOCATION_PERSIST_INTERVAL_SECONDS = '2';
process.env.SOS_LOCATION_HISTORY_LIMIT = '10';
process.env.SOS_MAX_LOCATION_UPDATES_PER_SECOND = '3';
process.env.SOS_SMS_FALLBACK_ENABLED = 'true';

// Configured HERE so the in-process push tests can exercise the real code path
// with an injected admin factory. The spawned server explicitly blanks these so
// its notification fan-out takes the "not configured" branch deterministically.
process.env.FIREBASE_PROJECT_ID = 'guardfi-verify-project';
process.env.FIREBASE_CLIENT_EMAIL = 'verify@guardfi.test';
process.env.FIREBASE_PRIVATE_KEY = 'verify-private-key';

process.env.OTP_DEV_MODE = 'true';
process.env.SMS_PROVIDER = 'none';
process.env.TWILIO_ACCOUNT_SID = '';
process.env.TWILIO_AUTH_TOKEN = '';
process.env.TWILIO_PHONE_NUMBER = '';
process.env.FAST2SMS_API_KEY = '';

const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');
const jwt = require('jsonwebtoken');
const { io: ioClient } = require('socket.io-client');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const SERVER_PORT = Number(process.env.VERIFY_SOS_PORT || 4337);
const BASE = `http://127.0.0.1:${SERVER_PORT}`;
const PERSIST_INTERVAL_MS = 2_000;
const HISTORY_LIMIT = 10;
const LOCATION_RATE = 3;

let mongo = null;
let server = null;
const results = [];
const openClients = [];

function record(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => results.push({ name, ok: true }))
    .catch((error) => results.push({ name, ok: false, error: error.message }));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function call(pathname, { method = 'GET', body, token, headers = {} } = {}) {
  const init = { method, headers: { ...headers } };
  if (token) init.headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

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

const post = (pathname, options) => call(pathname, { ...options, method: 'POST' });

function expectSuccess(response, status) {
  assert.equal(response.status, status, `expected ${status}, got ${response.status}: ${response.text}`);
  assert.equal(response.body?.success, true);
  assert.equal(response.body?.errors, null);
}

function expectError(response, status, code) {
  assert.equal(response.status, status, `expected ${status}, got ${response.status}: ${response.text}`);
  assert.equal(response.body?.success, false);
  assert.equal(response.body?.data, null);

  if (code) {
    const codes = (response.body?.errors || []).map((entry) => entry.code);
    assert.ok(codes.includes(code), `expected code ${code}, got ${JSON.stringify(codes)}`);
  }
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
      last = `status=${response.status} db=${body?.data?.database?.state} indexes=${body?.data?.database?.indexesReady}`;
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
      // Force the deterministic "no push credentials" path inside the server.
      FIREBASE_PROJECT_ID: '',
      FIREBASE_CLIENT_EMAIL: '',
      FIREBASE_PRIVATE_KEY: '',
      SMS_PROVIDER: 'none',
      RATE_LIMIT_SKIP_IN_TEST: 'true',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const entry = { label: 'sos server', child, output: [] };
  child.stdout.on('data', (chunk) => entry.output.push(chunk.toString()));
  child.stderr.on('data', (chunk) => entry.output.push(chunk.toString()));
  server = entry;

  return entry;
}

async function stopServer() {
  for (const client of openClients.splice(0)) {
    client.close();
  }

  if (server && server.child.exitCode === null) {
    server.child.kill();
    await sleep(300);
  }

  if (results.some((result) => !result.ok) && server && server.output.length > 0) {
    console.error('\n--- server output ---');
    console.error(server.output.join('').split('\n').slice(-25).join('\n'));
  }
}

async function seedUser(phone, name) {
  const User = require('../models/User');
  const { signAccessToken } = require('../services/tokenService');

  const user = await User.create({ phone, name });
  const auth = signAccessToken(user);

  return { user, token: auth.token, phone, id: String(user._id) };
}

function openSocket(token) {
  return new Promise((resolve) => {
    const client = ioClient(BASE, {
      transports: ['websocket'],
      reconnection: false,
      forceNew: true,
      timeout: 6_000,
      auth: token ? { token } : {},
    });

    openClients.push(client);

    const timer = setTimeout(() => {
      client.close();
      resolve({ ok: false, code: 'TIMEOUT', message: 'connection timed out' });
    }, 8_000);

    client.once('connect', () => {
      clearTimeout(timer);
      // Capture server:ready here, so a fast server cannot win the race against
      // the test attaching its listener after connect resolves.
      const readyTimer = setTimeout(() => resolve({ ok: true, client, ready: null }), 2_000);
      client.once('server:ready', (payload) => {
        clearTimeout(readyTimer);
        resolve({ ok: true, client, ready: payload });
      });
    });

    client.once('connect_error', (error) => {
      clearTimeout(timer);
      client.close();
      resolve({ ok: false, code: error?.data?.code || null, message: error?.message || 'connect_error' });
    });
  });
}

function emitAck(client, event, payload, timeoutMs = 5_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`ack timeout for ${event}`)), timeoutMs);
    client.emit(event, payload, (ack) => {
      clearTimeout(timer);
      resolve(ack);
    });
  });
}

function waitForEvent(client, event, timeoutMs = 5_000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`event ${event} was not received`)), timeoutMs);
    client.once(event, (payload) => {
      clearTimeout(timer);
      resolve(payload);
    });
  });
}

// ===========================================================================
// REST: validation, lifecycle, idempotency, notification summary
// ===========================================================================
async function runHttpChecks() {
  const Nominee = require('../models/Nominee');
  const SosAlert = require('../models/SosAlert');

  const alice = await seedUser('+919876580001', 'Alice Owner');
  const bob = await seedUser('+919876580002', 'Bob Other');
  const carol = await seedUser('+919876580003', 'Carol Owner');

  await Nominee.create([
    {
      userId: alice.user._id,
      name: 'Guardian One',
      phone: '+919876581001',
      relation: 'Sister',
      isPrimary: true,
      fcmToken: 'alice-guardian-device-token',
    },
    { userId: alice.user._id, name: 'Guardian Two', phone: '+919876581002', relation: 'Friend' },
  ]);

  let aliceAlert = null;

  await record('sos: trigger without a token → 401', async () => {
    const response = await post('/api/v1/sos/trigger', {
      body: { location: { latitude: 19.076, longitude: 72.8777 } },
    });

    expectError(response, 401);
  });

  await record('sos: invalid coordinates and notes are rejected before any write', async () => {
    const cases = [
      { location: { latitude: 91, longitude: 72.8 } },
      { location: { latitude: 19.0, longitude: 181 } },
      { location: { latitude: 'abc', longitude: 72.8 } },
      { location: undefined },
      { location: { latitude: 19.0, longitude: 72.8, accuracy: -5 } },
      { location: { latitude: 19.0, longitude: 72.8 }, message: 'x'.repeat(281) },
    ];

    for (const payload of cases) {
      const response = await post('/api/v1/sos/trigger', { token: alice.token, body: payload });
      expectError(response, 400);
      assert.ok(Array.isArray(response.body.errors) && response.body.errors.length > 0);
    }

    assert.equal(await SosAlert.countDocuments({ userId: alice.user._id }), 0);
  });

  await record('sos: trigger creates one ACTIVE alert with a GeoJSON point and room id', async () => {
    const response = await post('/api/v1/sos/trigger', {
      token: alice.token,
      body: {
        location: { latitude: 19.076, longitude: 72.8777, accuracy: 12 },
        message: 'Followed from the station',
      },
    });

    expectSuccess(response, 201);

    const { alert, roomId, socket } = response.body.data;
    aliceAlert = alert;

    assert.equal(alert.status, 'ACTIVE');
    assert.match(alert.roomId, /^[A-Za-z0-9_-]{12}$/);
    assert.equal(roomId, alert.roomId);
    assert.deepEqual(alert.initialLocation, { latitude: 19.076, longitude: 72.8777 });
    assert.equal(alert.lastLocation.latitude, 19.076);
    assert.equal(alert.locationHistory.length, 1);
    assert.equal(alert.locationHistory[0].accuracy, 12);
    assert.equal(alert.notifiedCount, 2);
    assert.equal(alert.notifiedNomineeIds.length, 2);
    assert.equal(socket.room, `sos:${alert.roomId}`);
    assert.equal(socket.event, 'join_sos_room');

    // GeoJSON order is [longitude, latitude] — the classic bug is swapping it.
    const stored = await SosAlert.findById(alert.id).lean();
    assert.equal(stored.initialLocation.type, 'Point');
    assert.deepEqual(stored.initialLocation.coordinates, [72.8777, 19.076]);
  });

  await record('sos: a second trigger returns the same alert and sends no second fan-out', async () => {
    const response = await post('/api/v1/sos/trigger', {
      token: alice.token,
      body: { location: { latitude: 19.1, longitude: 72.9 } },
    });

    expectSuccess(response, 200);
    assert.equal(response.body.data.alreadyActive, true);
    assert.equal(response.body.data.alert.id, aliceAlert.id);
    assert.equal(await SosAlert.countDocuments({ userId: alice.user._id, status: 'ACTIVE' }), 1);
  });

  await record('sos: notification fan-out is recorded on the alert (push skipped, SMS skipped)', async () => {
    const deadline = Date.now() + 5_000;
    let stored = null;

    while (Date.now() < deadline) {
      stored = await SosAlert.findById(aliceAlert.id).lean();
      if (stored?.notification?.attemptedAt) break;
      await sleep(100);
    }

    assert.ok(stored?.notification?.attemptedAt, 'the fan-out summary was never written');

    // One guardian has a token, two guardians exist, no FCM credentials and no
    // SMS provider in the spawned server.
    assert.equal(stored.notification.push.attempted, 1);
    assert.equal(stored.notification.push.skipped, 1);
    assert.equal(stored.notification.sms.attempted, 2);
    assert.equal(stored.notification.sms.skipped, 2);
    assert.equal(stored.notification.push.sent, 0);
  });

  await record('sos: a user with no active alert cannot resolve someone else\'s', async () => {
    const response = await post('/api/v1/sos/resolve', { token: carol.token, body: {} });
    expectError(response, 404);
    assert.match(response.body.message, /no active/i);
  });

  await record('sos: isolation — Bob\'s alert does not replace Alice\'s', async () => {
    const bobTrigger = await post('/api/v1/sos/trigger', {
      token: bob.token,
      body: { location: { latitude: 12.9716, longitude: 77.5946 } },
    });

    expectSuccess(bobTrigger, 201);
    assert.notEqual(bobTrigger.body.data.alert.id, aliceAlert.id);

    const aliceActive = await call('/api/v1/sos/active', { token: alice.token });
    expectSuccess(aliceActive, 200);
    assert.equal(aliceActive.body.data.alert.id, aliceAlert.id);
    assert.equal(aliceActive.body.data.alert.roomId, aliceAlert.roomId);

    const bobActive = await call('/api/v1/sos/active', { token: bob.token });
    expectSuccess(bobActive, 200);
    assert.equal(bobActive.body.data.alert.id, bobTrigger.body.data.alert.id);
  });

  await record('sos: GET /active returns null when nothing is active', async () => {
    const response = await call('/api/v1/sos/active', { token: carol.token });
    expectSuccess(response, 200);
    assert.equal(response.body.data.alert, null);
  });

  await record('sos: resolve rejects an unknown status', async () => {
    const response = await post('/api/v1/sos/resolve', {
      token: alice.token,
      body: { status: 'BANANA' },
    });

    expectError(response, 400);
  });

  await record('sos: resolve closes the alert once, then reports none active', async () => {
    const resolved = await post('/api/v1/sos/resolve', {
      token: alice.token,
      body: { status: 'RESOLVED', note: 'Reached home safely' },
    });

    expectSuccess(resolved, 200);
    assert.equal(resolved.body.data.alert.status, 'RESOLVED');
    assert.ok(resolved.body.data.alert.resolvedAt);
    assert.equal(resolved.body.data.alert.resolutionNote, 'Reached home safely');

    const active = await call('/api/v1/sos/active', { token: alice.token });
    expectSuccess(active, 200);
    assert.equal(active.body.data.alert, null);

    const second = await post('/api/v1/sos/resolve', { token: alice.token, body: {} });
    expectError(second, 404);
  });

  await record('sos: a false alarm is recorded as FALSE_ALARM, not RESOLVED', async () => {
    const triggered = await post('/api/v1/sos/trigger', {
      token: carol.token,
      body: { location: { latitude: 13.0827, longitude: 80.2707 } },
    });
    expectSuccess(triggered, 201);

    const resolved = await post('/api/v1/sos/resolve', {
      token: carol.token,
      body: { status: 'false_alarm' },
    });

    expectSuccess(resolved, 200);
    assert.equal(resolved.body.data.alert.status, 'FALSE_ALARM');
  });

  // Bob's alert stays active for the socket tests' unrelated user? No — resolve
  // it here to keep the database tidy and to prove a second user can resolve
  // their own alert without touching anyone else.
  await record('sos: resolving Bob\'s alert leaves Alice\'s resolved history intact', async () => {
    const bobResolve = await post('/api/v1/sos/resolve', { token: bob.token, body: {} });
    expectSuccess(bobResolve, 200);
    assert.equal(bobResolve.body.data.alert.status, 'RESOLVED');

    assert.equal(await SosAlert.countDocuments({ userId: alice.user._id, status: 'RESOLVED' }), 1);
  });
}

// ===========================================================================
// Socket.io: handshake, room authorisation, broadcasting, throttling, stop
// ===========================================================================
async function runSocketChecks() {
  const Nominee = require('../models/Nominee');
  const SosAlert = require('../models/SosAlert');

  const grace = await seedUser('+919876580005', 'Grace Victim');
  const nina = await seedUser('+919876581005', 'Nina Guardian');
  const mallory = await seedUser('+919876580006', 'Mallory Stranger');

  await Nominee.create({
    userId: grace.user._id,
    name: 'Nina',
    phone: nina.phone,
    relation: 'Sister',
    isPrimary: true,
    fcmToken: 'nina-device-token',
  });

  const triggered = await post('/api/v1/sos/trigger', {
    token: grace.token,
    body: { location: { latitude: 28.6139, longitude: 77.209 } },
  });
  expectSuccess(triggered, 201);
  const alert = triggered.body.data.alert;

  await record('socket: missing token → connect_error AUTH_REQUIRED', async () => {
    const result = await openSocket(null);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'AUTH_REQUIRED', result.message);
  });

  await record('socket: a forged token → connect_error AUTH_INVALID', async () => {
    const forged = jwt.sign({ sub: grace.id }, 'a-completely-different-secret-000000000', {
      algorithm: 'HS256',
      expiresIn: '5m',
    });

    const result = await openSocket(forged);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'AUTH_INVALID', result.message);
  });

  await record('socket: an expired token → connect_error AUTH_EXPIRED', async () => {
    const expired = jwt.sign({ sub: grace.id }, process.env.JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn: '-10s',
    });

    const result = await openSocket(expired);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'AUTH_EXPIRED', result.message);
  });

  let graceSocket = null;
  let ninaSocket = null;
  let mallorySocket = null;

  await record('socket: owner and guardian connect; server:ready advertises phase 4', async () => {
    const [owner, guardian, stranger] = await Promise.all([
      openSocket(grace.token),
      openSocket(nina.token),
      openSocket(mallory.token),
    ]);

    assert.equal(owner.ok, true, owner.message);
    assert.equal(guardian.ok, true, guardian.message);
    assert.equal(stranger.ok, true, stranger.message);

    graceSocket = owner.client;
    ninaSocket = guardian.client;
    mallorySocket = stranger.client;

    assert.ok(owner.ready, 'server:ready was never received');
    assert.equal(owner.ready.phase, 4);
    assert.deepEqual(owner.ready.events.sort(), ['join_sos_room', 'location_update', 'stop_sos']);
  });

  await record('socket: a stranger cannot join the SOS room', async () => {
    const ack = await emitAck(mallorySocket, 'join_sos_room', { roomId: alert.roomId });
    assert.equal(ack.ok, false);
    assert.equal(ack.code, 'SOS_FORBIDDEN');
  });

  await record('socket: the guardian joins by room code and the owner by alert id', async () => {
    const guardianAck = await emitAck(ninaSocket, 'join_sos_room', { roomId: alert.roomId });
    assert.equal(guardianAck.ok, true, JSON.stringify(guardianAck));
    assert.equal(guardianAck.roomId, alert.roomId);
    assert.ok(guardianAck.participants >= 1);

    const ownerAck = await emitAck(graceSocket, 'join_sos_room', { alertId: alert.id });
    assert.equal(ownerAck.ok, true, JSON.stringify(ownerAck));
    assert.equal(ownerAck.alertId, alert.id);
  });

  await record('socket: a location packet is broadcast to the guardian and persisted once', async () => {
    const incoming = waitForEvent(ninaSocket, 'nominee_location_stream');

    const ack = await emitAck(graceSocket, 'location_update', {
      alertId: alert.id,
      latitude: 28.6145,
      longitude: 77.2095,
      accuracy: 8,
    });

    assert.equal(ack.ok, true, JSON.stringify(ack));
    assert.equal(ack.persisted, true);

    const event = await incoming;
    assert.equal(event.alertId, alert.id);
    assert.equal(event.roomId, alert.roomId);
    assert.equal(event.latitude, 28.6145);
    assert.equal(event.longitude, 77.2095);
    assert.equal(event.accuracy, 8);
  });

  await record('socket: the next packet is broadcast but NOT written (write throttling)', async () => {
    const before = await SosAlert.findById(alert.id).lean();
    const incoming = waitForEvent(ninaSocket, 'nominee_location_stream');

    const ack = await emitAck(graceSocket, 'location_update', {
      alertId: alert.id,
      latitude: 28.615,
      longitude: 77.21,
    });

    assert.equal(ack.ok, true, JSON.stringify(ack));
    assert.equal(ack.persisted, false);

    const event = await incoming;
    assert.equal(event.persisted, false);
    assert.equal(event.latitude, 28.615);

    const after = await SosAlert.findById(alert.id).lean();
    assert.equal(after.locationHistory.length, before.locationHistory.length, 'history must not grow');
  });

  await record('socket: a 4-packet burst trips the per-socket rate limit without crashing', async () => {
    const acks = await Promise.all(
      [1, 2, 3, 4].map((index) =>
        emitAck(graceSocket, 'location_update', {
          alertId: alert.id,
          latitude: 28.62 + index / 10_000,
          longitude: 77.21,
        })
      )
    );

    const limited = acks.filter((ack) => ack.ok === false && ack.code === 'SOS_RATE_LIMITED');
    assert.ok(limited.length >= 1, `expected a rate-limited packet, got ${JSON.stringify(acks)}`);
    assert.ok(acks.every((ack) => ack.ok === true || ack.code === 'SOS_RATE_LIMITED'));
  });

  await record('socket: a guardian cannot move the victim\'s marker', async () => {
    const ack = await emitAck(ninaSocket, 'location_update', {
      alertId: alert.id,
      latitude: 0,
      longitude: 0,
    });

    assert.equal(ack.ok, false);
    assert.equal(ack.code, 'SOS_FORBIDDEN');
  });

  await record('socket: malformed payloads are rejected, not thrown', async () => {
    const outOfRange = await emitAck(graceSocket, 'location_update', {
      alertId: alert.id,
      latitude: 999,
      longitude: 77.21,
    });
    assert.equal(outOfRange.ok, false);
    assert.equal(outOfRange.code, 'VALIDATION_FAILED');

    const wrongType = await emitAck(graceSocket, 'location_update', 'not-an-object');
    assert.equal(wrongType.ok, false);
    assert.equal(wrongType.code, 'VALIDATION_FAILED');

    const noReference = await emitAck(graceSocket, 'location_update', { latitude: 1, longitude: 2 });
    assert.equal(noReference.ok, false);
    assert.equal(noReference.code, 'VALIDATION_FAILED');
  });

  await record('socket: a guardian cannot stop the alert', async () => {
    const ack = await emitAck(ninaSocket, 'stop_sos', { alertId: alert.id });
    assert.equal(ack.ok, false);
    assert.equal(ack.code, 'SOS_FORBIDDEN');
  });

  await record('socket: the owner stops the alert and the guardian sees sos:stopped', async () => {
    const stoppedEvent = waitForEvent(ninaSocket, 'sos:stopped');

    const ack = await emitAck(graceSocket, 'stop_sos', { alertId: alert.id, status: 'RESOLVED' });

    assert.equal(ack.ok, true, JSON.stringify(ack));
    assert.equal(ack.status, 'RESOLVED');
    assert.ok(ack.resolvedAt);

    const event = await stoppedEvent;
    assert.equal(event.alertId, alert.id);
    assert.equal(event.status, 'RESOLVED');

    const stored = await SosAlert.findById(alert.id).lean();
    assert.equal(stored.status, 'RESOLVED');
    assert.ok(stored.resolvedAt);
  });

  await record('socket: after resolution the room and the location stream are closed', async () => {
    // Let the per-socket bucket refill so this check tests the alert state, not
    // the rate limiter from the burst above.
    await sleep(1_200);

    const update = await emitAck(graceSocket, 'location_update', {
      alertId: alert.id,
      latitude: 28.6,
      longitude: 77.2,
    });
    assert.equal(update.ok, false);
    assert.equal(update.code, 'SOS_INACTIVE');

    const join = await emitAck(ninaSocket, 'join_sos_room', { alertId: alert.id });
    assert.equal(join.ok, false);
    assert.equal(join.code, 'SOS_INACTIVE');
  });

  for (const client of [graceSocket, ninaSocket, mallorySocket]) {
    client?.close();
  }
}

// ===========================================================================
// Model + service checks (in-process, deterministic clock)
// ===========================================================================
async function runModelAndServiceChecks() {
  const SosAlert = require('../models/SosAlert');
  const Nominee = require('../models/Nominee');
  const {
    triggerSos,
    recordLocation,
    resolveSos,
    shouldPersist,
    resetLocationThrottle,
  } = require('../services/sosService');

  await SosAlert.init();

  await record('model: SOS indexes — 2dsphere, status, unique room, one ACTIVE per user', async () => {
    const indexes = await SosAlert.collection.indexes();
    const keys = indexes.map((index) => index.key);

    assert.ok(
      indexes.some((index) => index.key.initialLocation === '2dsphere'),
      `no 2dsphere index (${JSON.stringify(keys)})`
    );
    assert.ok(indexes.some((index) => index.key.userId === 1 && index.key.status === 1));
    assert.ok(indexes.some((index) => index.key.status === 1 && index.key.createdAt === -1));

    const roomIdIndex = indexes.find((index) => index.key.roomId === 1);
    assert.ok(roomIdIndex && roomIdIndex.unique === true);

    const oneActive = indexes.find((index) => index.name === 'one_active_sos_per_user');
    assert.ok(oneActive, 'the one-active partial index is missing');
    assert.equal(oneActive.unique, true);
    assert.deepEqual(oneActive.partialFilterExpression, { status: 'ACTIVE' });
  });

  await record('model: the database itself refuses a second ACTIVE alert for one user', async () => {
    const dave = await seedUser('+919876580004', 'Dave Owner');

    await SosAlert.create({
      userId: dave.user._id,
      initialLocation: { type: 'Point', coordinates: [77.5946, 12.9716] },
    });

    await assert.rejects(
      () =>
        SosAlert.create({
          userId: dave.user._id,
          initialLocation: { type: 'Point', coordinates: [77.6, 12.98] },
        }),
      (error) => error && error.code === 11_000
    );
  });

  await record('model: an invalid point is rejected by schema validation', async () => {
    const erin = await seedUser('+919876580008', 'Erin Owner');

    await assert.rejects(
      () =>
        SosAlert.create({
          userId: erin.user._id,
          initialLocation: { type: 'Point', coordinates: [200, 10] },
        }),
      (error) => error.name === 'ValidationError'
    );

    await assert.rejects(
      () => SosAlert.create({ userId: erin.user._id, initialLocation: { type: 'Point' } }),
      (error) => error.name === 'ValidationError'
    );
  });

  const frank = await seedUser('+919876580007', 'Frank Owner');
  const frankNominee = await Nominee.create({
    userId: frank.user._id,
    name: 'Frank Guardian',
    phone: '+919876581007',
    isPrimary: true,
  });

  let frankAlert = null;

  await record('service: trigger stores the initial point and notifies only this user\'s guardians', async () => {
    resetLocationThrottle();

    const result = await triggerSos({
      userId: frank.user._id,
      ownerName: 'Frank Owner',
      location: { latitude: 12.9716, longitude: 77.5946, accuracy: 5 },
      message: 'Test alert',
    });

    frankAlert = result.alert;

    assert.equal(result.alreadyActive, false);
    assert.equal(result.nominees.length, 1);
    assert.equal(frankAlert.notifiedCount, 1);
    assert.equal(frankAlert.notifiedNomineeIds[0], String(frankNominee._id));
    assert.equal(frankAlert.locationHistory.length, 1);
  });

  await record('service: shouldPersist allows one write per interval, then blocks', async () => {
    resetLocationThrottle();
    const base = Date.now();

    assert.equal(shouldPersist('probe', base), true);
    assert.equal(shouldPersist('probe', base + 100), false);
    assert.equal(shouldPersist('probe', base + PERSIST_INTERVAL_MS - 1), false);
    assert.equal(shouldPersist('probe', base + PERSIST_INTERVAL_MS + 1), true);

    resetLocationThrottle();
  });

  await record('service: recordLocation writes the first packet and skips the second', async () => {
    resetLocationThrottle();
    const now = Date.now();

    const first = await recordLocation({
      userId: frank.user._id,
      alertId: frankAlert.id,
      location: { latitude: 12.972, longitude: 77.595 },
      now,
    });

    const second = await recordLocation({
      userId: frank.user._id,
      alertId: frankAlert.id,
      location: { latitude: 12.973, longitude: 77.596 },
      now: now + 200,
    });

    assert.equal(first.persisted, true);
    assert.equal(second.persisted, false);

    const stored = await SosAlert.findById(frankAlert.id).lean();
    assert.equal(stored.locationHistory.length, 2);
    assert.equal(stored.lastLocation.coordinates[0], 77.595);
    assert.equal(stored.lastLocation.coordinates[1], 12.972);
  });

  await record('service: after the interval a packet is written again', async () => {
    const now = Date.now() + PERSIST_INTERVAL_MS + 100;

    const result = await recordLocation({
      userId: frank.user._id,
      alertId: frankAlert.id,
      location: { latitude: 12.974, longitude: 77.597, accuracy: 3 },
      now,
    });

    assert.equal(result.persisted, true);

    const stored = await SosAlert.findById(frankAlert.id).lean();
    assert.equal(stored.locationHistory.length, 3);
    assert.equal(stored.locationHistory[2].accuracy, 3);
    assert.equal(stored.lastLocationAt.getTime(), now);
  });

  await record('service: history is capped and always keeps the newest breadcrumbs', async () => {
    const start = Date.now() + 10 * PERSIST_INTERVAL_MS;

    for (let index = 0; index < 15; index += 1) {
      // eslint-disable-next-line no-await-in-loop
      await recordLocation({
        userId: frank.user._id,
        alertId: frankAlert.id,
        location: { latitude: 12.9 + index / 1_000, longitude: 77.5 + index / 1_000 },
        now: start + index * (PERSIST_INTERVAL_MS + 10),
      });
    }

    const stored = await SosAlert.findById(frankAlert.id).lean();

    assert.equal(stored.locationHistory.length, HISTORY_LIMIT);
    assert.equal(stored.locationHistory.at(-1).coordinates[1], 12.9 + 14 / 1_000);
    assert.equal(stored.locationHistory.at(-1).coordinates[0], 77.5 + 14 / 1_000);
  });

  await record('service: a resolved alert can be triggered again and rejects stale writes', async () => {
    const resolved = await resolveSos({ userId: frank.user._id, status: 'RESOLVED', note: 'done' });
    assert.equal(resolved.status, 'RESOLVED');

    await assert.rejects(
      () =>
        recordLocation({
          userId: frank.user._id,
          alertId: frankAlert.id,
          location: { latitude: 1, longitude: 2 },
          now: Date.now() + 100 * PERSIST_INTERVAL_MS,
        }),
      (error) => error.statusCode === 404 && error.code === 'SOS_INACTIVE'
    );

    const again = await triggerSos({
      userId: frank.user._id,
      ownerName: 'Frank Owner',
      location: { latitude: 13.0, longitude: 77.6 },
    });

    assert.equal(again.alreadyActive, false);
    assert.notEqual(again.alert.id, frankAlert.id);
    frankAlert = again.alert;
  });
}

// ===========================================================================
// Push + SMS transports and fan-out targeting (injected fakes)
// ===========================================================================
async function runNotificationChecks() {
  const SosAlert = require('../models/SosAlert');
  const { sendAlertPush, buildAlertPushMessage } = require('../services/pushService');
  const { sendSosSms, sosMessageTemplate } = require('../services/smsService');
  const { notifyNominees } = require('../services/sosService');

  await record('push: no tokens → no_tokens, no transport call', async () => {
    const result = await sendAlertPush({ tokens: [], title: 'x', body: 'y' });
    assert.equal(result.delivered, false);
    assert.equal(result.reason, 'no_tokens');
    assert.equal(result.attempted, 0);
  });

  await record('push: an injected FCM transport receives string data and dead tokens are reported', async () => {
    let captured = null;

    const fakeAdmin = () => ({
      messaging: () => ({
        sendEachForMulticast: async (message) => {
          captured = message;
          return {
            successCount: 1,
            failureCount: 1,
            responses: [
              { success: true },
              { success: false, error: { code: 'messaging/registration-token-not-registered' } },
            ],
          };
        },
      }),
    });

    const result = await sendAlertPush({
      tokens: ['token-a', 'token-b', 'token-a'],
      title: 'GuardFi SOS',
      body: 'Frank needs help',
      data: { alertId: 'abc123', roomId: 'room12345678', latitude: 12.97, longitude: 77.59 },
      adminFactory: fakeAdmin,
    });

    assert.equal(result.attempted, 2, 'duplicate tokens must be de-duplicated');
    assert.equal(result.sent, 1);
    assert.equal(result.failed, 1);
    assert.equal(result.delivered, true);
    assert.deepEqual(result.invalidTokens, ['token-b']);

    assert.equal(captured.title, undefined, 'title belongs on the notification object');
    assert.equal(captured.notification.title, 'GuardFi SOS');
    assert.equal(captured.data.latitude, '12.97');
    assert.equal(captured.data.alertId, 'abc123');
    assert.deepEqual(captured.tokens, ['token-a', 'token-b']);
    assert.equal(captured.android.priority, 'high');
  });

  await record('push: a throwing/admin SDK failure is reported, never thrown', async () => {
    const result = await sendAlertPush({
      tokens: ['token-a'],
      title: 't',
      body: 'b',
      adminFactory: () => {
        throw new Error('invalid service account');
      },
    });

    assert.equal(result.delivered, false);
    assert.equal(result.reason, 'firebase_error');
    assert.equal(result.failed, 1);
    assert.ok(!result.invalidTokens.length);
  });

  await record('push: the message builder converts every data value to a string', async () => {
    const message = buildAlertPushMessage({
      title: 't',
      body: 'b',
      data: { numeric: 1, boolean: true, skip: null },
    });

    assert.equal(message.data.numeric, '1');
    assert.equal(message.data.boolean, 'true');
    assert.equal(message.data.skip, undefined);
  });

  await record('sms: the SOS template names the owner, the room and an optional deep link', async () => {
    const message = sosMessageTemplate({ ownerName: 'Frank', roomId: 'abcdefghijkl', trackingUrl: 'https://app.test/sos' });

    assert.match(message, /Frank/);
    assert.match(message, /abcdefghijkl/);
    assert.match(message, /https:\/\/app\.test\/sos\?room=abcdefghijkl/);
  });

  await record('sms: Twilio carries the SOS body', async () => {
    let sentBody = null;
    const sms = {
      provider: 'auto',
      timeoutMs: 1_000,
      twilio: { accountSid: 'AC123', authToken: 'tok', phoneNumber: '+10000000000' },
      fast2sms: { apiKey: '', route: 'otp' },
    };

    const result = await sendSosSms({
      phone: '+919876581099',
      ownerName: 'Frank',
      roomId: 'abcdefghijkl',
      sms,
      clientFactory: () => ({
        messages: {
          create: async (args) => {
            sentBody = args.body;
            return { sid: 'SM123' };
          },
        },
      }),
    });

    assert.equal(result.delivered, true);
    assert.equal(result.provider, 'twilio');
    assert.match(sentBody, /abcdefghijkl/);
  });

  await record('sms: Fast2SMS uses the free-text route for an SOS', async () => {
    let payload = null;
    const sms = {
      provider: 'auto',
      timeoutMs: 1_000,
      twilio: {},
      // The OTP route is configured, but free text must still use 'q'.
      fast2sms: { apiKey: 'KEY', route: 'otp' },
    };

    const result = await sendSosSms({
      phone: '+919876581099',
      ownerName: 'Frank',
      roomId: 'abcdefghijkl',
      sms,
      fetchImpl: async (url, init) => {
        payload = JSON.parse(init.body);
        return { ok: true, status: 200, text: async () => JSON.stringify({ return: true, request_id: 'rid' }) };
      },
    });

    assert.equal(result.delivered, true);
    assert.equal(payload.route, 'q');
    assert.match(payload.message, /abcdefghijkl/);
  });

  await record('sms: a provider rejection is a value, not a throw', async () => {
    const sms = {
      provider: 'fast2sms',
      timeoutMs: 1_000,
      twilio: {},
      fast2sms: { apiKey: 'KEY', route: 'q' },
    };

    const result = await sendSosSms({
      phone: '+919876581099',
      ownerName: 'Frank',
      roomId: 'abcdefghijkl',
      sms,
      fetchImpl: async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ return: false, message: 'blocked' }) }),
    });

    assert.equal(result.delivered, false);
    assert.equal(result.reason, 'provider_rejected');
  });

  await record('fan-out: text-only guardians receive SMS, push-capable ones do not', async () => {
    const alert = await SosAlert.findOne({ userId: { $exists: true }, status: 'ACTIVE' }).lean();
    const pushCalls = [];
    const smsCalls = [];

    const summary = await notifyNominees({
      alert,
      ownerName: 'Frank',
      nominees: [
        { fcmToken: 'token-push', phone: '+919876581001' },
        { fcmToken: null, phone: '+919876581002' },
      ],
      transports: {
        sendPush: async (params) => {
          pushCalls.push(params);
          return { attempted: 1, sent: 1, failed: 0, skipped: 0, reason: 'sent' };
        },
        sendSms: async (params) => {
          smsCalls.push(params);
          return { delivered: true };
        },
      },
    });

    assert.equal(pushCalls.length, 1);
    assert.equal(smsCalls.length, 1);
    assert.equal(smsCalls[0].phone, '+919876581002');
    assert.equal(summary.push.sent, 1);
    assert.equal(summary.sms.sent, 1);

    const stored = await SosAlert.findById(alert._id).lean();
    assert.equal(stored.notification.sms.attempted, 1);
    assert.equal(stored.notification.push.attempted, 1);
  });

  await record('fan-out: when push is unavailable every guardian is texted', async () => {
    const alert = await SosAlert.findOne({ userId: { $exists: true }, status: 'ACTIVE' }).lean();
    const smsCalls = [];

    const summary = await notifyNominees({
      alert,
      ownerName: 'Frank',
      nominees: [
        { fcmToken: 'token-push', phone: '+919876581001' },
        { fcmToken: null, phone: '+919876581002' },
      ],
      transports: {
        sendPush: async () => ({ attempted: 1, sent: 0, failed: 0, skipped: 1, reason: 'not_configured' }),
        sendSms: async (params) => {
          smsCalls.push(params);
          return { delivered: true };
        },
      },
    });

    assert.equal(smsCalls.length, 2);
    assert.equal(summary.sms.sent, 2);
    assert.equal(summary.push.skipped, 1);
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
      dbName: 'guardfi-phase4-verify',
      launchTimeout: 90_000,
    },
  });

  const uri = mongo.getUri('guardfi-phase4-verify');
  process.env.MONGO_URI = uri;

  const { connectDatabase } = require('../config/db');
  await connectDatabase();

  try {
    console.log(`▶ Booting SOS API + Socket.io on port ${SERVER_PORT}...`);
    spawnServer(uri);
    await waitForHealth();
    console.log('▶ Server healthy. Running REST checks...\n');
    await runHttpChecks();

    console.log('▶ Running Socket.io checks...\n');
    await runSocketChecks();
  } catch (error) {
    results.push({ name: 'harness: server became healthy', ok: false, error: error.message });
  } finally {
    await stopServer();
  }

  await runModelAndServiceChecks();
  await runNotificationChecks();

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
