'use strict';

/**
 * GuardFi — Phase 8 verification harness (emergency biometric bypass, RBAC,
 * immutable audit trail)
 *
 * Proves, against a real Express server and a throwaway MongoDB:
 *   • emergency routes are closed to anonymous callers;
 *   • a restricted route is refused while the *database* says emergency mode is
 *     off, even though the caller's token may claim otherwise;
 *   • a properly signed, fresh, single-use biometric assertion unlocks the
 *     account, flips biometricEnabled, and writes exactly one immutable audit
 *     row carrying IP, User-Agent and device metadata;
 *   • invalid, stale, future-dated, failed and replayed assertions are refused
 *     with distinct codes and never change state;
 *   • the audit collection rejects every Mongoose update/delete/save/bulkWrite
 *     path — including after a hydrated document has been edited in memory;
 *   • the unique (userId, assertionNonce) index makes an HMAC replay a 409;
 *   • the biometric budget is enforced (429) and stays route-scoped.
 *
 * Run:  npm run verify:phase8
 * Exit: 0 = every check passed, 1 = at least one failed, 2 = harness cannot run.
 */

process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = process.env.VERIFY_LOG_LEVEL || 'error';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'verify-phase8-secret-'.padEnd(48, '0');
process.env.CORS_ORIGINS = '*';
process.env.STRICT_ENV = 'false';
process.env.TRUST_PROXY = 'false';
delete process.env.PORT;

process.env.MONGO_URI = 'mongodb://127.0.0.1:27017/guardfi-phase8-placeholder';
process.env.OTP_DEV_MODE = 'true';
process.env.SMS_PROVIDER = 'none';

const BIOMETRIC_SECRET = 'phase8-verify-hmac-secret-'.padEnd(64, 'k');
process.env.BIOMETRIC_SHARED_SECRET = BIOMETRIC_SECRET;
process.env.BIOMETRIC_MAX_ASSERTION_AGE_SECONDS = '120';
process.env.RATE_LIMIT_EMERGENCY_MAX = '200';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const MAIN_PORT = Number(process.env.VERIFY_EMERGENCY_PORT || 4342);
const BUDGET_PORT = Number(process.env.VERIFY_EMERGENCY_BUDGET_PORT || 4343);
const NO_SECRET_PORT = Number(process.env.VERIFY_EMERGENCY_NOSECRET_PORT || 4344);
const MAIN_BASE = `http://127.0.0.1:${MAIN_PORT}`;
const BUDGET_BASE = `http://127.0.0.1:${BUDGET_PORT}`;
const NO_SECRET_BASE = `http://127.0.0.1:${NO_SECRET_PORT}`;

const USER_AGENT = 'GuardFi-Phase8-Verify/1.0';
const DEVICE = Object.freeze({
  deviceId: 'probe-device-0001',
  platform: 'android',
  appVersion: '1.0.0',
  model: 'Pixel 7',
  osVersion: '14',
});

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

async function call(base, pathname, { method = 'GET', token, body, headers = {} } = {}) {
  const init = { method, headers: { 'user-agent': USER_AGENT, ...headers } };
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

async function waitForHealth(base, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no response';

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${base}/health`);
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

  throw new Error(`server at ${base} never became healthy within ${timeoutMs}ms (last: ${last})`);
}

function spawnServer({ port, env, label }) {
  const child = spawn(process.execPath, [path.join(PROJECT_ROOT, 'server.js')], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      LOG_LEVEL: 'error',
      PORT: String(port),
      MONGO_URI: process.env.MONGO_URI,
      RATE_LIMIT_SKIP_IN_TEST: 'true',
      BIOMETRIC_SHARED_SECRET: BIOMETRIC_SECRET,
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
// Deterministic dataset
// ===========================================================================
async function seedDataset() {
  const User = require('../models/User');
  const AuditLog = require('../models/AuditLog');
  const { signAccessToken } = require('../services/tokenService');

  await User.init();
  await AuditLog.init();

  const make = (phone, name) => ({
    _id: new mongoose.Types.ObjectId(),
    phone,
    name,
    role: 'user',
    securityPinHash: null,
    // Raw collection inserts bypass schema defaults, so write every field the
    // checks read. A missing isEmergencyMode would make "is it still off?"
    // compare undefined to false and hide a real regression.
    isEmergencyMode: false,
    biometricEnabled: false,
    emergencyActivatedAt: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  const me = make('+919876560001', 'Emergency User');
  const other = make('+919876560002', 'Bystander User');

  await User.collection.insertMany([me, other]);

  seeded = {
    me: { id: String(me._id), objectId: me._id, token: signAccessToken(me).token },
    other: { id: String(other._id), objectId: other._id, token: signAccessToken(other).token },
  };

  return seeded;
}

// ===========================================================================
// Assertion helpers
// ===========================================================================
function signedAssertion(
  userId,
  {
    success = true,
    verifiedAt = new Date().toISOString(),
    nonce = crypto.randomBytes(18).toString('base64url'),
    deviceMetadata = DEVICE,
    signWith = BIOMETRIC_SECRET,
    signature,
  } = {}
) {
  const { signAssertion } = require('../services/emergencyService');
  const generated = signAssertion({ userId, success, verifiedAt, nonce, secret: signWith }).signature;

  return {
    success,
    verifiedAt,
    nonce,
    signature: signature ?? generated,
    deviceMetadata,
  };
}

async function auditCount(userId) {
  const AuditLog = require('../models/AuditLog');
  return AuditLog.countDocuments({ userId });
}

async function userState(userId) {
  const User = require('../models/User');
  const user = await User.findById(userId).select('isEmergencyMode biometricEnabled emergencyActivatedAt').lean();
  return user;
}

// ===========================================================================
// HTTP checks
// ===========================================================================
async function runAuthAndValidationChecks() {
  const { me } = seeded;

  await record('auth: every emergency endpoint refuses an anonymous caller', async () => {
    const calls = [
      ['POST', '/api/v1/emergency/biometric-verify', signedAssertion(me.id)],
      ['POST', '/api/v1/emergency/restricted-action', { action: 'CONTACT_POLICE' }],
      ['POST', '/api/v1/emergency/lock', {}],
      ['GET', '/api/v1/emergency/status', undefined],
    ];

    for (const [method, pathname, body] of calls) {
      const response = await call(MAIN_BASE, pathname, { method, body });
      assert.equal(response.status, 401, `${method} ${pathname} should be 401, got ${response.status}`);
      assert.equal(response.body?.success, false);
    }
  });

  await record('validation: malformed biometric assertions are rejected before the HMAC runs', async () => {
    const base = signedAssertion(me.id);
    const cases = [
      {},
      { ...base, success: 'true' },
      (({ nonce, ...rest }) => rest)(base),
      { ...base, nonce: 'short' },
      { ...base, nonce: `${base.nonce}!` },
      { ...base, signature: 'not-hex' },
      { ...base, signature: base.signature.slice(0, 32) },
      { ...base, verifiedAt: 'not-a-date' },
      { ...base, deviceMetadata: { ...base.deviceMetadata, extra: 'not-allowed' } },
      { ...base, extra: 'not-allowed' },
    ];

    for (const body of cases) {
      const response = await call(MAIN_BASE, '/api/v1/emergency/biometric-verify', {
        method: 'POST',
        token: me.token,
        body,
      });
      assert.equal(response.status, 400, `expected 400 for ${JSON.stringify(body)}: ${response.text}`);
      assert.equal(response.body.success, false);
      assert.ok(Array.isArray(response.body.errors) && response.body.errors.length > 0, response.text);
    }
  });

  await record('biometric: without a configured secret the endpoint fails closed (503)', async () => {
    const before = await auditCount(me.objectId);
    const response = await call(NO_SECRET_BASE, '/api/v1/emergency/biometric-verify', {
      method: 'POST',
      token: me.token,
      body: signedAssertion(me.id),
    });

    expectErrorCode(response, 503, 'BIOMETRIC_VERIFIER_NOT_CONFIGURED');
    assert.equal((await userState(me.objectId)).isEmergencyMode, false);
    assert.equal(await auditCount(me.objectId), before, 'a misconfigured server must not write audit rows');
  });
}

async function runEmergencyFlowChecks() {
  const { me } = seeded;

  await record('rbac: status starts inactive and grants no emergency actions', async () => {
    const response = await call(MAIN_BASE, '/api/v1/emergency/status', { token: me.token });
    expectSuccess(response, 200);
    assert.equal(response.body.data.user.isEmergencyMode, false);
    assert.equal(response.body.data.user.biometricEnabled, false);
    assert.equal(response.body.data.emergencyPermissions.active, false);
    assert.deepEqual(response.body.data.emergencyPermissions.actions, []);
    assert.equal(response.body.data.emergencyPermissions.activatedAt, null);
  });

  await record('rbac: restricted-action is refused with 403 while emergency mode is off', async () => {
    const before = await auditCount(me.objectId);
    const response = await call(MAIN_BASE, '/api/v1/emergency/restricted-action', {
      method: 'POST',
      token: me.token,
      body: { action: 'CONTACT_POLICE' },
    });

    assert.equal(response.status, 403, response.text);
    assert.equal(response.body.success, false);
    assert.match(response.body.message, /Emergency mode is not active/i);
    assert.equal(await auditCount(me.objectId), before, 'a refused RBAC check must not write an audit row');
  });

  const firstAssertion = signedAssertion(me.id);

  await record('biometric: a signed, fresh assertion unlocks emergency mode (201)', async () => {
    const response = await call(MAIN_BASE, '/api/v1/emergency/biometric-verify', {
      method: 'POST',
      token: me.token,
      body: firstAssertion,
    });

    expectSuccess(response, 201);
    const data = response.body.data;

    assert.equal(data.user.isEmergencyMode, true);
    assert.equal(data.user.biometricEnabled, true);
    assert.equal(data.alreadyActive, false);
    assert.equal(data.emergencyPermissions.active, true);
    assert.ok(data.emergencyPermissions.actions.includes('RESTRICTED_ACTION'));
    assert.ok(data.emergencyPermissions.activatedAt);
    assert.equal(data.audit.action, 'EMERGENCY_MODE_UNLOCKED');
    assert.match(data.audit.id, /^[0-9a-f]{24}$/);
    assert.equal(response.headers.get('cache-control'), 'no-store');
  });

  await record('biometric: the unlock flips user state and writes one immutable audit row', async () => {
    const AuditLog = require('../models/AuditLog');
    const state = await userState(me.objectId);

    assert.equal(state.isEmergencyMode, true);
    assert.equal(state.biometricEnabled, true);
    assert.ok(state.emergencyActivatedAt instanceof Date);

    const rows = await AuditLog.find({ userId: me.objectId }).sort({ createdAt: 1 }).lean();
    assert.equal(rows.length, 1, `expected exactly one audit row, got ${rows.length}`);

    const row = rows[0];
    assert.equal(row.action, 'EMERGENCY_MODE_UNLOCKED');
    assert.equal(row.assertionNonce, firstAssertion.nonce);
    assert.equal(row.deviceMetadata.deviceId, DEVICE.deviceId);
    assert.equal(row.deviceMetadata.platform, 'android');
    assert.equal(row.deviceMetadata.biometricVerified, true);
    assert.equal(row.details.reason, 'BIOMETRIC_BYPASS');
    assert.ok(row.ipAddress, 'the audit row must carry the caller IP');
    assert.equal(row.userAgent, USER_AGENT);
    assert.ok(row.createdAt instanceof Date);
    assert.equal(row.updatedAt, undefined, 'an audit row has no updatedAt');
    assert.equal(row.signature, undefined, 'the HMAC itself must never be stored');
  });

  await record('validation: a malformed restricted-action body is rejected once the gate is open', async () => {
    const cases = [
      { action: 'lowercase' },
      { action: 'A' },
      { action: 'A'.repeat(81) },
      { action: 'VALID_ACTION', note: 'x'.repeat(281) },
      { action: 'VALID_ACTION', extra: true },
    ];

    const before = await auditCount(me.objectId);

    for (const body of cases) {
      const response = await call(MAIN_BASE, '/api/v1/emergency/restricted-action', {
        method: 'POST',
        token: me.token,
        body,
      });

      assert.equal(response.status, 400, `expected 400 for ${JSON.stringify(body)}: ${response.text}`);
      assert.equal(response.body.success, false);
      assert.ok(Array.isArray(response.body.errors) && response.body.errors.length > 0, response.text);
    }

    assert.equal(await auditCount(me.objectId), before, 'a rejected body must never reach the audit writer');
  });

  await record('rbac: restricted-action is permitted once the database says emergency mode is on', async () => {
    const response = await call(MAIN_BASE, '/api/v1/emergency/restricted-action', {
      method: 'POST',
      token: me.token,
      body: { action: 'CONTACT_POLICE', note: 'Home invasion reported' },
    });

    expectSuccess(response, 200);
    assert.equal(response.body.data.action, 'CONTACT_POLICE');
    assert.equal(response.body.data.emergencyPermissions.active, true);
    assert.equal(response.body.data.audit.action, 'RESTRICTED_ACTION_PERFORMED');

    const AuditLog = require('../models/AuditLog');
    const row = await AuditLog.findById(response.body.data.audit.id).lean();
    assert.equal(row.details.requestedAction, 'CONTACT_POLICE');
    assert.equal(row.details.note, 'Home invasion reported');
  });

  await record('biometric: re-verification while active is idempotent but still audited', async () => {
    const before = await auditCount(me.objectId);
    const response = await call(MAIN_BASE, '/api/v1/emergency/biometric-verify', {
      method: 'POST',
      token: me.token,
      body: signedAssertion(me.id),
    });

    expectSuccess(response, 200);
    assert.equal(response.body.data.alreadyActive, true);
    assert.equal(response.body.data.emergencyPermissions.active, true);
    assert.equal(response.body.data.audit.action, 'BIOMETRIC_BYPASS_TRIGGERED');
    assert.equal(await auditCount(me.objectId), before + 1);
  });

  await record('biometric: a replayed nonce is refused with 409 and cannot re-unlock', async () => {
    const lockResponse = await call(MAIN_BASE, '/api/v1/emergency/lock', { method: 'POST', token: me.token });
    expectSuccess(lockResponse, 200);
    assert.equal(lockResponse.body.data.user.isEmergencyMode, false);

    const replay = await call(MAIN_BASE, '/api/v1/emergency/biometric-verify', {
      method: 'POST',
      token: me.token,
      body: firstAssertion,
    });

    expectErrorCode(replay, 409, 'BIOMETRIC_ASSERTION_REPLAYED');
    assert.equal((await userState(me.objectId)).isEmergencyMode, false, 'a replay must not unlock the account');
  });

  await record('lock: state is cleared, an audit row is written, and a second lock is a no-op', async () => {
    const AuditLog = require('../models/AuditLog');
    const before = await auditCount(me.objectId);

    const response = await call(MAIN_BASE, '/api/v1/emergency/lock', { method: 'POST', token: me.token });
    expectSuccess(response, 200);
    assert.equal(response.body.data.alreadyInactive, true);
    assert.equal(response.body.data.audit, null);
    assert.equal(await auditCount(me.objectId), before, 'locking an inactive account must not add a row');

    const locked = await AuditLog.findOne({ userId: me.objectId, action: 'EMERGENCY_MODE_LOCKED' }).lean();
    assert.ok(locked, 'the earlier lock must be recorded');
    assert.equal((await userState(me.objectId)).emergencyActivatedAt, null);
  });

  await record('rbac: restricted-action is refused again after the lock', async () => {
    const response = await call(MAIN_BASE, '/api/v1/emergency/restricted-action', {
      method: 'POST',
      token: me.token,
      body: { action: 'CONTACT_POLICE' },
    });

    assert.equal(response.status, 403, response.text);
  });
}

async function runRejectionChecks() {
  const { me, other } = seeded;

  await record('biometric: an expired assertion is refused and audited', async () => {
    const stale = signedAssertion(me.id, {
      verifiedAt: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
    });

    const response = await call(MAIN_BASE, '/api/v1/emergency/biometric-verify', {
      method: 'POST',
      token: me.token,
      body: stale,
    });

    expectErrorCode(response, 401, 'BIOMETRIC_ASSERTION_EXPIRED');
    assert.equal((await userState(me.objectId)).isEmergencyMode, false);

    const AuditLog = require('../models/AuditLog');
    const row = await AuditLog.findOne({ userId: me.objectId, assertionNonce: stale.nonce }).lean();
    assert.ok(row, 'an expired but correctly signed assertion must be audited');
    assert.equal(row.action, 'BIOMETRIC_VERIFICATION_FAILED');
    assert.equal(row.details.reason, 'BIOMETRIC_ASSERTION_EXPIRED');
  });

  await record('biometric: an assertion timestamped in the future is refused', async () => {
    const future = signedAssertion(me.id, {
      verifiedAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
    });

    const response = await call(MAIN_BASE, '/api/v1/emergency/biometric-verify', {
      method: 'POST',
      token: me.token,
      body: future,
    });

    expectErrorCode(response, 401, 'BIOMETRIC_ASSERTION_EXPIRED');
    assert.equal((await userState(me.objectId)).isEmergencyMode, false);
  });

  await record('biometric: a forged signature is refused and claims no nonce', async () => {
    const forged = signedAssertion(me.id, { signWith: 'wrong-secret'.padEnd(64, 'x') });
    const before = await auditCount(me.objectId);

    const response = await call(MAIN_BASE, '/api/v1/emergency/biometric-verify', {
      method: 'POST',
      token: me.token,
      body: forged,
    });

    expectErrorCode(response, 401, 'BIOMETRIC_SIGNATURE_INVALID');
    assert.equal(await auditCount(me.objectId), before + 1);

    const AuditLog = require('../models/AuditLog');
    const claimed = await AuditLog.findOne({ userId: me.objectId, assertionNonce: forged.nonce }).lean();
    assert.equal(claimed, null, 'an unsigned assertion must not burn a nonce');
    assert.equal((await userState(me.objectId)).isEmergencyMode, false);
  });

  await record('biometric: a signed success=false result is refused with 403 and audited', async () => {
    const failed = signedAssertion(me.id, { success: false });

    const response = await call(MAIN_BASE, '/api/v1/emergency/biometric-verify', {
      method: 'POST',
      token: me.token,
      body: failed,
    });

    expectErrorCode(response, 403, 'BIOMETRIC_VERIFICATION_FAILED');
    assert.equal((await userState(me.objectId)).isEmergencyMode, false);

    const AuditLog = require('../models/AuditLog');
    const row = await AuditLog.findOne({ userId: me.objectId, assertionNonce: failed.nonce }).lean();
    assert.ok(row);
    assert.equal(row.details.reason, 'BIOMETRIC_VERIFICATION_FAILED');
  });

  await record("biometric: another user's signed assertion cannot be replayed on this account", async () => {
    const stolen = signedAssertion(other.id);
    const before = await auditCount(me.objectId);

    const response = await call(MAIN_BASE, '/api/v1/emergency/biometric-verify', {
      method: 'POST',
      token: me.token,
      body: stolen,
    });

    expectErrorCode(response, 401, 'BIOMETRIC_SIGNATURE_INVALID');
    assert.equal((await userState(me.objectId)).isEmergencyMode, false);
    assert.equal((await userState(other.objectId)).isEmergencyMode, false);
    assert.equal(await auditCount(other.objectId), 0, 'the victim account must stay untouched');
    assert.equal(await auditCount(me.objectId), before + 1);
  });
}

// ===========================================================================
// HTTP checks — server with a 3-attempt biometric budget
// ===========================================================================
async function runBudgetChecks() {
  const { me } = seeded;

  await record('limiter: the biometric budget is enforced (429) and stays route-scoped', async () => {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await call(BUDGET_BASE, '/api/v1/emergency/biometric-verify', {
        method: 'POST',
        token: me.token,
        body: signedAssertion(me.id, { signWith: 'wrong-secret'.padEnd(64, 'x') }),
      });

      assert.equal(response.status, 401, `attempt ${attempt + 1} should reach the handler: ${response.text}`);
    }

    const fourth = await call(BUDGET_BASE, '/api/v1/emergency/biometric-verify', {
      method: 'POST',
      token: me.token,
      body: signedAssertion(me.id),
    });

    assert.equal(fourth.status, 429, `the 4th attempt should be rate limited, got ${fourth.status}: ${fourth.text}`);
    assert.match(fourth.body.message, /Too many biometric unlock attempts/i);

    const health = await fetch(`${BUDGET_BASE}/health`);
    assert.equal(health.status, 200, 'the limiter must not leak onto other routes');
  });
}

// ===========================================================================
// In-process model checks
// ===========================================================================
async function runModelChecks() {
  const AuditLog = require('../models/AuditLog');
  const { AUDIT_ACTIONS } = AuditLog;

  const doc = await AuditLog.record({
    userId: seeded.me.objectId,
    action: AUDIT_ACTIONS.RESTRICTED_ACTION_PERFORMED,
    ipAddress: '203.0.113.7',
    userAgent: USER_AGENT,
    details: { requestedAction: 'MODEL_CHECK', note: 'append-only probe' },
  });

  await record('model: a valid audit row is stored with createdAt and without updatedAt', async () => {
    assert.ok(doc._id);
    assert.ok(doc.createdAt instanceof Date);
    assert.equal(doc.updatedAt, undefined);
    assert.equal(doc.action, 'RESTRICTED_ACTION_PERFORMED');
  });

  await record('model: every Mongoose update path is refused', async () => {
    const id = doc._id;
    const attempts = [
      () => AuditLog.updateOne({ _id: id }, { $set: { action: 'EMERGENCY_MODE_LOCKED' } }),
      () => AuditLog.updateMany({ userId: seeded.me.objectId }, { $set: { ipAddress: '0.0.0.0' } }),
      () => AuditLog.replaceOne({ _id: id }, { userId: seeded.me.objectId, action: 'EMERGENCY_MODE_LOCKED' }),
      () => AuditLog.findOneAndUpdate({ _id: id }, { $set: { action: 'EMERGENCY_MODE_LOCKED' } }),
      () =>
        AuditLog.findOneAndReplace(
          { _id: id },
          { userId: seeded.me.objectId, action: 'EMERGENCY_MODE_LOCKED' }
        ),
    ];

    for (const attempt of attempts) {
      await assert.rejects(attempt, (error) => error.code === 'AUDIT_LOG_IMMUTABLE', 'a mutation was not refused');
    }

    const unchanged = await AuditLog.findById(id).lean();
    assert.equal(unchanged.action, 'RESTRICTED_ACTION_PERFORMED');
    assert.equal(unchanged.ipAddress, '203.0.113.7');
  });

  await record('model: every Mongoose delete path is refused', async () => {
    const id = doc._id;
    const attempts = [
      () => AuditLog.deleteOne({ _id: id }),
      () => AuditLog.deleteMany({ userId: seeded.me.objectId }),
      () => AuditLog.findOneAndDelete({ _id: id }),
    ];

    for (const attempt of attempts) {
      await assert.rejects(attempt, (error) => error.code === 'AUDIT_LOG_IMMUTABLE', 'a delete was not refused');
    }

    const stillThere = await AuditLog.findById(id).lean();
    assert.ok(stillThere, 'the audit row was deleted despite the guards');
  });

  await record('model: a hydrated audit document cannot be saved or deleted', async () => {
    const hydrated = await AuditLog.findById(doc._id);

    hydrated.details.note = 'tampered in memory';
    await assert.rejects(
      () => hydrated.save(),
      (error) => error.code === 'AUDIT_LOG_IMMUTABLE',
      'save() on a stored row was not refused'
    );

    await assert.rejects(
      () => hydrated.deleteOne(),
      (error) => error.code === 'AUDIT_LOG_IMMUTABLE',
      'deleteOne() on a stored document was not refused'
    );

    const fresh = await AuditLog.findById(doc._id).lean();
    assert.equal(fresh.details.note, 'append-only probe');
  });

  await record('model: bulkWrite is refused wholesale', async () => {
    await assert.rejects(
      // Async wrapper: bulkWrite throws synchronously, and assert.rejects needs
      // a rejected promise rather than an escaping exception.
      async () =>
        AuditLog.bulkWrite([
          {
            insertOne: {
              document: {
                userId: seeded.me.objectId,
                action: 'EMERGENCY_MODE_LOCKED',
              },
            },
          },
        ]),
      (error) => error.code === 'AUDIT_LOG_IMMUTABLE'
    );
  });

  await record('model: an unknown field or action cannot be persisted', async () => {
    await assert.rejects(
      () =>
        AuditLog.record({
          userId: seeded.me.objectId,
          action: 'EMERGENCY_MODE_LOCKED',
          ipAdress: 'typo.example',
        }),
      (error) => error.name === 'StrictModeError' || error.name === 'ValidationError' || /not permitted|not defined/i.test(error.message)
    );

    await assert.rejects(
      () => AuditLog.record({ userId: seeded.me.objectId, action: 'NOT_A_REAL_ACTION' }),
      (error) => error.name === 'ValidationError'
    );

    await assert.rejects(
      () => AuditLog.record({ action: 'EMERGENCY_MODE_LOCKED' }),
      (error) => error.name === 'ValidationError'
    );
  });

  await record('model: the unique (userId, assertionNonce) index blocks a duplicate nonce', async () => {
    const nonce = crypto.randomBytes(18).toString('base64url');

    await AuditLog.record({
      userId: seeded.other.objectId,
      action: 'EMERGENCY_MODE_LOCKED',
      assertionNonce: nonce,
    });

    await assert.rejects(
      () =>
        AuditLog.record({
          userId: seeded.other.objectId,
          action: 'EMERGENCY_MODE_LOCKED',
          assertionNonce: nonce,
        }),
      (error) => error.code === 11_000
    );

    // The same nonce for a DIFFERENT user is fine: the nonce is scoped per account.
    await AuditLog.record({
      userId: seeded.me.objectId,
      action: 'EMERGENCY_MODE_LOCKED',
      assertionNonce: nonce,
    });
  });

  await record('model: the audit history query walks the (userId, createdAt) index', async () => {
    const plan = JSON.stringify(
      await AuditLog.find({ userId: seeded.me.objectId })
        .sort({ createdAt: -1 })
        .lean()
        .explain('executionStats')
    );

    assert.match(plan, /IXSCAN/);
    assert.match(plan, /userId_1_createdAt_-1/);
    assert.equal(plan.includes('COLLSCAN'), false, 'the audit query fell back to a collection scan');
  });

  await record('service: verification fails closed without a shared secret', async () => {
    const { verifyAssertion } = require('../services/emergencyService');
    const assertion = signedAssertion(seeded.me.id);

    const result = verifyAssertion({ ...assertion, userId: seeded.me.id, secret: '' });
    assert.equal(result.ok, false);
    assert.equal(result.statusCode, 503);
    assert.equal(result.code, 'BIOMETRIC_VERIFIER_NOT_CONFIGURED');
  });

  await record('service: the canonical signing string is exactly what the app signs', async () => {
    const { canonicalAssertion } = require('../services/emergencyService');

    assert.equal(
      canonicalAssertion({ userId: 'abc123', success: true, verifiedAt: 1_700_000_000_000, nonce: 'nonce-1234567890' }),
      'guardfi-biometric-v1|abc123|true|1700000000000|nonce-1234567890'
    );
  });

  await record('service: an uppercase hex signature is accepted', async () => {
    const { verifyAssertion } = require('../services/emergencyService');
    const assertion = signedAssertion(seeded.me.id);

    const result = verifyAssertion({ ...assertion, userId: seeded.me.id });
    assert.equal(result.ok, true, JSON.stringify(result));

    const upper = verifyAssertion({ ...assertion, userId: seeded.me.id, signature: assertion.signature.toUpperCase() });
    assert.equal(upper.ok, true, 'hex case must not matter');
  });

  await record('service: inactive permissions grant nothing and expose no secrets', async () => {
    const { buildEmergencyPermissions } = require('../services/emergencyService');

    const permissions = buildEmergencyPermissions({ active: false, biometricEnabled: false });
    assert.deepEqual(permissions.actions, []);
    assert.equal(permissions.active, false);
    assert.equal(permissions.activatedAt, null);
    assert.equal(JSON.stringify(permissions).includes(BIOMETRIC_SECRET), false);
  });
}

// ===========================================================================
// Cleanup
// ===========================================================================
async function cleanupProbeData() {
  const User = require('../models/User');
  const AuditLog = require('../models/AuditLog');
  const userIds = [seeded.me.objectId, seeded.other.objectId];

  // Deliberately the raw driver: the model is append-only, which is exactly what
  // the checks above prove. Test teardown must not need a deletion backdoor.
  const auditReport = await AuditLog.collection.deleteMany({ userId: { $in: userIds } });
  const userReport = await User.collection.deleteMany({ _id: { $in: userIds } });

  return {
    audits: auditReport.deletedCount || 0,
    users: userReport.deletedCount || 0,
    remainingAudits: await AuditLog.collection.countDocuments({ userId: { $in: userIds } }),
    remainingUsers: await User.collection.countDocuments({ _id: { $in: userIds } }),
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
    instance: { dbName: 'guardfi-phase8-verify', launchTimeout: 90_000 },
  });

  const uri = mongo.getUri('guardfi-phase8-verify');
  process.env.MONGO_URI = uri;

  const { connectDatabase } = require('../config/db');
  await connectDatabase();

  try {
    console.log('▶ Seeding two accounts...');
    await seedDataset();

    console.log(
      `▶ Booting the main server on ${MAIN_PORT}, the budget server on ${BUDGET_PORT} and the unconfigured server on ${NO_SECRET_PORT}...`
    );
    spawnServer({ port: MAIN_PORT, label: 'main server' });
    spawnServer({
      port: BUDGET_PORT,
      label: 'budget server',
      env: { RATE_LIMIT_SKIP_IN_TEST: 'false', RATE_LIMIT_EMERGENCY_MAX: '3' },
    });
    spawnServer({
      port: NO_SECRET_PORT,
      label: 'unconfigured server',
      // Blank is dropped by env sanitisation, so BIOMETRIC_SHARED_SECRET falls
      // back to its default '' and the endpoint must answer 503.
      env: { BIOMETRIC_SHARED_SECRET: '' },
    });

    await waitForHealth(MAIN_BASE);
    await waitForHealth(BUDGET_BASE);
    await waitForHealth(NO_SECRET_BASE);

    console.log('▶ Servers healthy. Running emergency flow checks...\n');
    await runAuthAndValidationChecks();
    await runEmergencyFlowChecks();
    await runRejectionChecks();
    await runBudgetChecks();
  } catch (error) {
    results.push({ name: 'harness: servers became healthy', ok: false, error: error.message });
  } finally {
    await stopServers();
  }

  await runModelChecks();

  await record('cleanup: probe audit rows and users are fully removed', async () => {
    const report = await cleanupProbeData();
    assert.ok(report.audits > 0, 'the probe expected to have audit rows to clean up');
    assert.equal(report.users, 2);
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
  await cleanupProbeData().catch(() => {});
  if (mongo) await mongo.stop().catch(() => {});
  process.exit(1);
});
