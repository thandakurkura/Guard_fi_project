'use strict';

/**
 * GuardFi — Phase 9 verification against the LIVE Atlas cluster
 *
 * Deliberately opt-in: it WRITES to whatever MONGO_URI points at, so it refuses
 * to run unless ALLOW_ATLAS_WRITES=yes is set.
 *
 * The global config is a SINGLETON, so unlike the other Atlas harnesses this one
 * cannot simply create and delete its own row without care: a real deployment
 * may already store real settings. It therefore snapshots the existing document
 * first, writes unmistakable probe values, and restores the snapshot byte for
 * byte in a `finally` block (or removes the seeded document if there was none).
 * The restore itself is asserted against the snapshot.
 *
 * What it proves that the in-memory harness cannot:
 *   • the unique `key` index exists on the cluster, so a second config document
 *     is impossible at the database level;
 *   • the auto-seed/update path behaves against the live server (version bump,
 *     partial nested thresholds, TTL-backed cache);
 *   • the audit row for an admin config change really lands in Atlas.
 *
 * Run:  ALLOW_ATLAS_WRITES=yes npm run verify:phase9:atlas
 */

require('dotenv').config({ quiet: true });

if (process.env.ALLOW_ATLAS_WRITES !== 'yes') {
  console.error(
    [
      '✖ Refusing to run: this script writes probe documents to the database in MONGO_URI.',
      '  Re-run with:  ALLOW_ATLAS_WRITES=yes npm run verify:phase9:atlas',
      '  It snapshots the real config and restores it, then verifies the restore.',
    ].join('\n')
  );
  process.exit(2);
}

process.env.NODE_ENV = 'test';
// This process never listens; a stray PORT=0 inherited from an IDE/shell would
// otherwise fail env validation before any check runs.
delete process.env.PORT;
process.env.GLOBAL_CONFIG_CACHE_TTL_SECONDS = process.env.GLOBAL_CONFIG_CACHE_TTL_SECONDS || '600';
process.env.BIOMETRIC_SHARED_SECRET = 'atlas-phase9-probe-secret-'.padEnd(64, 'a');

const assert = require('node:assert/strict');

const PROBE_URL = 'https://atlas-probe.invalid/privacy';
const PROBE_USER_AGENT = 'Atlas/Phase9';

/** Only the fields this harness touches; used to prove the restore is faithful. */
function normalizeConfig(document) {
  if (!document) return null;
  return JSON.stringify({
    key: document.key,
    privacyPolicyUrl: document.privacyPolicyUrl,
    termsUrl: document.termsUrl,
    globalWarningThresholds: document.globalWarningThresholds,
    maintenanceMode: document.maintenanceMode,
    emergencyHelplines: document.emergencyHelplines,
    version: document.version,
    updatedBy: document.updatedBy ? String(document.updatedBy) : null,
  });
}

async function main() {
  const { connectDatabase, disconnectDatabase } = require('../config/db');
  const User = require('../models/User');
  const AuditLog = require('../models/AuditLog');
  const AppConfig = require('../models/AppConfig');
  const { getGlobalConfig, invalidateGlobalConfigCache, updateGlobalConfig, getCacheTtlRemainingSeconds } = require('../services/configService');

  console.log('▶ Connecting to Atlas (indexes are built on connect)...');
  await connectDatabase();
  await AppConfig.init();
  await User.init();
  await AuditLog.init();

  const appConfigs = AppConfig.collection;
  const users = User.collection;
  const audits = AuditLog.collection;

  const snapshot = await appConfigs.findOne({ key: 'GLOBAL_CONFIG' });
  const snapshotJson = normalizeConfig(snapshot);

  const tag = String(Date.now()).slice(-6);
  const probePhone = `+9199${tag}`;

  const checks = [];
  const record = (name, fn) =>
    Promise.resolve()
      .then(fn)
      .then(() => checks.push({ name, ok: true }))
      .catch((error) => checks.push({ name, ok: false, error: error.message }));

  let probeUserId = null;

  try {
    const probeUser = await User.create({ phone: probePhone, name: 'Phase 9 Atlas Probe', role: 'admin' });
    probeUserId = probeUser._id;

    invalidateGlobalConfigCache();

    await record('atlas: a cold read auto-seeds the singleton and reports the database as its source', async () => {
      const result = await getGlobalConfig();

      assert.equal(result.source, 'database');
      assert.equal(result.config.key, 'GLOBAL_CONFIG');

      if (snapshotJson === null) {
        // Nothing existed before: the auto-seed must have produced the defaults.
        assert.deepEqual(result.config.globalWarningThresholds, {
          upiRiskScoreThreshold: 70,
          sosRadiusMeters: 5000,
          maxNomineesPerUser: 5,
        });
        assert.equal(result.config.maintenanceMode, false);
        assert.equal(result.config.emergencyHelplines.length, 3);
        assert.equal(result.config.version, 1);
      } else {
        // Something real existed: an auto-seed must never overwrite it.
        assert.equal(normalizeConfig(result.config), snapshotJson, 'the auto-seed changed an existing config');
      }

      assert.equal(await appConfigs.countDocuments({ key: 'GLOBAL_CONFIG' }), 1);
    });

    await record('atlas: a warm read is served from the local cache with the configured TTL', async () => {
      const result = await getGlobalConfig();
      assert.equal(result.source, 'cache');

      const remaining = getCacheTtlRemainingSeconds();
      assert.ok(remaining > 580 && remaining <= 600, `TTL remaining was ${remaining}s`);
    });

    await record('atlas: an admin service update bumps the version and writes the Atlas audit row', async () => {
      const before = await AppConfig.collection.findOne({ key: 'GLOBAL_CONFIG' });

      const result = await updateGlobalConfig({
        updates: {
          privacyPolicyUrl: PROBE_URL,
          maintenanceMode: true,
          globalWarningThresholds: { upiRiskScoreThreshold: 91 },
        },
        adminId: probeUserId,
        request: { ipAddress: '203.0.113.13', userAgent: PROBE_USER_AGENT },
      });

      assert.equal(result.version, before.version + 1);
      assert.equal(result.config.privacyPolicyUrl, PROBE_URL);
      assert.equal(result.config.maintenanceMode, true);
      assert.equal(result.config.globalWarningThresholds.upiRiskScoreThreshold, 91);
      assert.equal(
        result.config.globalWarningThresholds.sosRadiusMeters,
        before.globalWarningThresholds.sosRadiusMeters,
        'a partial threshold write must not replace the whole subdocument'
      );
      assert.equal(result.cacheInvalidated, true);

      const row = await audits.findOne({ _id: new (require('mongoose').Types.ObjectId)(result.audit.id) });
      assert.ok(row, 'the CONFIG_UPDATED audit row is missing on the cluster');
      assert.equal(row.action, 'CONFIG_UPDATED');
      assert.equal(row.details.requestedAction, 'UPDATE_GLOBAL_CONFIG');
      assert.equal(row.userAgent, PROBE_USER_AGENT);
      assert.equal(row.ipAddress, '203.0.113.13');

      const afterCache = await getGlobalConfig();
      assert.equal(afterCache.source, 'database', 'updateGlobalConfig must clear the cache entry');
    });

    await record('atlas: the unique key index exists and a second config document is refused', async () => {
      const indexes = await appConfigs.indexes();
      const keyIndex = indexes.find((index) => index.key.key === 1);
      assert.ok(keyIndex, 'appconfigs key_1 missing');
      assert.equal(keyIndex.unique, true);

      await assert.rejects(
        () => appConfigs.insertOne({ key: 'GLOBAL_CONFIG', maintenanceMode: true }),
        (error) => error.code === 11_000
      );

      assert.equal(await appConfigs.countDocuments({ key: 'GLOBAL_CONFIG' }), 1);
    });
  } finally {
    // Restore the real configuration exactly, then remove every probe artefact.
    if (snapshot) {
      await appConfigs.replaceOne({ _id: snapshot._id }, snapshot);
    } else {
      await appConfigs.deleteMany({ key: 'GLOBAL_CONFIG' });
    }

    if (probeUserId) {
      await audits.deleteMany({ userId: probeUserId });
      await users.deleteOne({ _id: probeUserId });
    }

    const restored = await appConfigs.findOne({ key: 'GLOBAL_CONFIG' });
    const leftovers = probeUserId
      ? {
          audits: await audits.countDocuments({ userId: probeUserId }),
          users: await users.countDocuments({ _id: probeUserId }),
        }
      : { audits: 0, users: 0 };

    await record('atlas: the real configuration is restored and probe data is gone', async () => {
      assert.equal(normalizeConfig(restored), snapshotJson, 'the real configuration was not restored faithfully');
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
