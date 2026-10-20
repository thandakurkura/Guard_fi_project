'use strict';

/**
 * GuardFi — Phase 8 verification against the LIVE Atlas cluster
 *
 * Deliberately opt-in: it WRITES to whatever MONGO_URI points at, so it refuses
 * to run unless ALLOW_ATLAS_WRITES=yes is set. Everything it creates is keyed to
 * one throwaway user and removed in a `finally` block; the cleanup is asserted,
 * not assumed.
 *
 * What it proves that the in-memory harness cannot:
 *   • the unique partial (userId, assertionNonce) index really exists on the
 *     cluster (production runs with autoIndex off, so a missing index is silent
 *     until two replays succeed);
 *   • the immutable audit collection refuses updates and deletes when the
 *     mutation reaches a real MongoDB server, not just Mongoose's local guard;
 *   • the emergency state machine behaves identically against Atlas;
 *   • the audit-history query is served by the compound index (IXSCAN, no
 *     collection scan).
 *
 * It runs as NODE_ENV=test so Mongoose is allowed to create the indexes this
 * verifier checks. It never touches any row outside its own probe user.
 *
 * Run:  ALLOW_ATLAS_WRITES=yes npm run verify:phase8:atlas
 */

require('dotenv').config({ quiet: true });

if (process.env.ALLOW_ATLAS_WRITES !== 'yes') {
  console.error(
    [
      '✖ Refusing to run: this script writes probe documents to the database in MONGO_URI.',
      '  Re-run with:  ALLOW_ATLAS_WRITES=yes npm run verify:phase8:atlas',
      '  It deletes everything it creates, and verifies that cleanup.',
    ].join('\n')
  );
  process.exit(2);
}

// A test process may build the indexes this verifier asserts exist. A custom
// secret keeps the run independent of whether the local .env has one yet.
process.env.NODE_ENV = 'test';
// This process never listens; a stray PORT=0 inherited from an IDE/shell would
// otherwise fail env validation before any check runs.
delete process.env.PORT;
process.env.BIOMETRIC_SHARED_SECRET =
  process.env.BIOMETRIC_SHARED_SECRET && process.env.BIOMETRIC_SHARED_SECRET.length >= 32
    ? process.env.BIOMETRIC_SHARED_SECRET
    : 'atlas-phase8-probe-secret-'.padEnd(64, 'a');
process.env.BIOMETRIC_MAX_ASSERTION_AGE_SECONDS = process.env.BIOMETRIC_MAX_ASSERTION_AGE_SECONDS || '120';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const SECRET = process.env.BIOMETRIC_SHARED_SECRET;
const DEVICE = Object.freeze({
  deviceId: 'atlas-probe-device',
  platform: 'android',
  appVersion: '1.0.0',
  model: 'Atlas Probe',
  osVersion: '14',
});

async function main() {
  const { connectDatabase, disconnectDatabase } = require('../config/db');
  const User = require('../models/User');
  const AuditLog = require('../models/AuditLog');
  const {
    signAssertion,
    verifyAssertion,
    activateEmergencyMode,
    deactivateEmergencyMode,
    getEmergencyStatus,
    performRestrictedAction,
  } = require('../services/emergencyService');

  console.log('▶ Connecting to Atlas (indexes are built on connect)...');
  await connectDatabase();
  await AuditLog.init();
  await User.init();

  const tag = String(Date.now()).slice(-6);
  const probePhone = `+9198${tag}`;
  const nonce = () => crypto.randomBytes(18).toString('base64url');

  const checks = [];
  const record = (name, fn) =>
    Promise.resolve()
      .then(fn)
      .then(() => checks.push({ name, ok: true }))
      .catch((error) => checks.push({ name, ok: false, error: error.message }));

  const audits = AuditLog.collection;
  const users = User.collection;

  let probeUserId = null;

  const assertion = (userId, overrides = {}) => {
    const base = {
      success: true,
      verifiedAt: new Date().toISOString(),
      nonce: nonce(),
      deviceMetadata: DEVICE,
      ...overrides,
    };
    return {
      ...base,
      signature: signAssertion({
        userId,
        success: base.success,
        verifiedAt: base.verifiedAt,
        nonce: base.nonce,
        secret: SECRET,
      }).signature,
    };
  };

  try {
    const probeUser = await User.create({
      phone: probePhone,
      name: 'Phase 8 Atlas Probe',
      isEmergencyMode: false,
      biometricEnabled: false,
    });
    probeUserId = probeUser._id;

    await record('atlas: the HMAC assertion verifies against the configured secret', async () => {
      const signed = assertion(String(probeUserId));
      const result = verifyAssertion({ ...signed, userId: String(probeUserId) });

      assert.equal(result.ok, true, JSON.stringify(result));
      assert.equal(result.nonce, signed.nonce);
    });

    let firstAssertion = null;
    let firstAuditId = null;

    await record('atlas: a signed assertion unlocks emergency mode on the live cluster', async () => {
      firstAssertion = assertion(String(probeUserId));

      const result = await activateEmergencyMode({
        userId: String(probeUserId),
        assertion: firstAssertion,
        request: { ipAddress: '203.0.113.9', userAgent: 'Atlas/Phase8' },
      });

      assert.equal(result.user.isEmergencyMode, true);
      assert.equal(result.user.biometricEnabled, true);
      assert.equal(result.audit.action, 'EMERGENCY_MODE_UNLOCKED');
      firstAuditId = result.audit.id;

      const row = await audits.findOne({ _id: new (require('mongoose').Types.ObjectId)(firstAuditId) });
      assert.ok(row, 'the unlock audit row is missing on the cluster');
      assert.equal(row.assertionNonce, firstAssertion.nonce);
      assert.equal(row.ipAddress, '203.0.113.9');
      assert.equal(row.userAgent, 'Atlas/Phase8');
      assert.equal(row.deviceMetadata.biometricVerified, true);
      assert.ok(row.createdAt instanceof Date);
      assert.equal(row.updatedAt, undefined);
    });

    await record('atlas: the live user document carries the unlocked state', async () => {
      const user = await users.findOne({ _id: probeUserId });

      assert.equal(user.isEmergencyMode, true);
      assert.equal(user.biometricEnabled, true);
      assert.ok(user.emergencyActivatedAt instanceof Date);

      const status = await getEmergencyStatus({ userId: String(probeUserId) });
      assert.equal(status.emergencyPermissions.active, true);
      assert.ok(status.emergencyPermissions.activatedAt);
    });

    await record('atlas: a restricted action is audited on the live cluster', async () => {
      const result = await performRestrictedAction({
        userId: String(probeUserId),
        action: 'ATLAS_PROBE_ACTION',
        note: 'live verification',
        request: { ipAddress: '203.0.113.9', userAgent: 'Atlas/Phase8' },
        biometricEnabled: true,
      });

      const row = await audits.findOne({ _id: new (require('mongoose').Types.ObjectId)(result.audit.id) });
      assert.ok(row);
      assert.equal(row.action, 'RESTRICTED_ACTION_PERFORMED');
      assert.equal(row.details.requestedAction, 'ATLAS_PROBE_ACTION');
      assert.equal(row.details.note, 'live verification');
    });

    await record('atlas: locking writes an audited state change and clears the timestamp', async () => {
      const result = await deactivateEmergencyMode({
        userId: String(probeUserId),
        request: { ipAddress: '203.0.113.9', userAgent: 'Atlas/Phase8' },
      });

      assert.equal(result.user.isEmergencyMode, false);
      assert.equal(result.alreadyInactive, false);

      const user = await users.findOne({ _id: probeUserId });
      assert.equal(user.isEmergencyMode, false);
      assert.equal(user.emergencyActivatedAt, null);

      const row = await audits.findOne({ _id: new (require('mongoose').Types.ObjectId)(result.audit.id) });
      assert.equal(row.action, 'EMERGENCY_MODE_LOCKED');
    });

    await record('atlas: a replayed assertion is refused with 409 and does not unlock', async () => {
      await assert.rejects(
        () =>
          activateEmergencyMode({
            userId: String(probeUserId),
            assertion: firstAssertion,
            request: { ipAddress: '203.0.113.9', userAgent: 'Atlas/Phase8' },
          }),
        (error) =>
          error.statusCode === 409 && JSON.stringify(error.errors || []).includes('BIOMETRIC_ASSERTION_REPLAYED')
      );

      const user = await users.findOne({ _id: probeUserId });
      assert.equal(user.isEmergencyMode, false, 'the replay must not unlock the account');
      assert.equal(await audits.countDocuments({ _id: new (require('mongoose').Types.ObjectId)(firstAuditId) }), 1);
    });

    await record('atlas: update and delete are refused by the live model', async () => {
      const id = new (require('mongoose').Types.ObjectId)(firstAuditId);

      await assert.rejects(
        () => AuditLog.updateOne({ _id: id }, { $set: { action: 'EMERGENCY_MODE_LOCKED' } }),
        (error) => error.code === 'AUDIT_LOG_IMMUTABLE'
      );
      await assert.rejects(
        () => AuditLog.findOneAndUpdate({ _id: id }, { $set: { ipAddress: '0.0.0.0' } }),
        (error) => error.code === 'AUDIT_LOG_IMMUTABLE'
      );
      await assert.rejects(
        () => AuditLog.deleteOne({ _id: id }),
        (error) => error.code === 'AUDIT_LOG_IMMUTABLE'
      );
      await assert.rejects(
        () => AuditLog.deleteMany({ userId: probeUserId }),
        (error) => error.code === 'AUDIT_LOG_IMMUTABLE'
      );

      const row = await audits.findOne({ _id: id });
      assert.ok(row, 'the audit row disappeared');
      assert.equal(row.action, 'EMERGENCY_MODE_UNLOCKED');
      assert.equal(row.ipAddress, '203.0.113.9');
    });

    await record('atlas: every Phase 8 index exists on the cluster', async () => {
      const indexes = await audits.indexes();

      const history = indexes.find((index) => index.key.userId === 1 && index.key.createdAt === -1);
      assert.ok(history, 'auditlogs userId_1_createdAt_-1 missing');

      const byAction = indexes.find((index) => index.key.action === 1 && index.key.createdAt === -1);
      assert.ok(byAction, 'auditlogs action_1_createdAt_-1 missing');

      const replayGuard = indexes.find((index) => index.name === 'unique_user_assertion_nonce');
      assert.ok(replayGuard, 'unique_user_assertion_nonce missing');
      assert.equal(replayGuard.unique, true);
      assert.deepEqual(replayGuard.partialFilterExpression, { assertionNonce: { $type: 'string' } });
    });

    await record('atlas: the audit history query is served by the compound index', async () => {
      const plan = JSON.stringify(
        await AuditLog.find({ userId: probeUserId }).sort({ createdAt: -1 }).lean().explain('executionStats')
      );

      assert.match(plan, /IXSCAN/);
      assert.match(plan, /userId_1_createdAt_-1/);
      assert.equal(plan.includes('COLLSCAN'), false, 'the live plan fell back to a collection scan');
    });
  } finally {
    if (probeUserId) {
      await audits.deleteMany({ userId: probeUserId });
      await users.deleteOne({ _id: probeUserId });
    }

    const leftovers = probeUserId
      ? {
          audits: await audits.countDocuments({ userId: probeUserId }),
          users: await users.countDocuments({ _id: probeUserId }),
        }
      : { audits: 0, users: 0 };

    await record('atlas: probe data is fully removed', async () => {
      assert.deepEqual(leftovers, { audits: 0, users: 0 });
    });

    await disconnectDatabase({ force: true });
  }

  const passed = checks.filter((check) => check.ok).length;
  const failed = checks.filter((check) => !check.ok);

  console.log('');
  for (const check of checks) {
    console.log(`${check.ok ? '  PASS' : '  FAIL'}  ${check.name}${check.ok ? '' : `\n          ↳ ${check.error}`}`);
  }
  console.log(`\n${passed}/${checks.length} live Atlas checks passed.`);

  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch((error) => {
  console.error('✖ Live Atlas verifier crashed:', error);
  process.exit(1);
});
