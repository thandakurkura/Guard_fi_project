'use strict';

/**
 * GuardFi — Phase 5 verification against the LIVE Atlas cluster
 *
 * Deliberately opt-in: it WRITES to whatever MONGO_URI points at, so it refuses
 * to run unless ALLOW_ATLAS_WRITES=yes is set. Every document it creates is
 * removed in a `finally` block, and the cleanup is asserted, not assumed.
 *
 * What it proves that the in-memory harness cannot:
 *   • the aggregation pipelines are accepted by the real Atlas query planner;
 *   • the 2dsphere / isEmergencyMode / createdAt indexes really exist there
 *     (production has autoIndex off, so a missing index would be silent);
 *   • $geoNear returns exactly the probe alert when the probe lives in an empty
 *     part of the ocean — so the count is deterministic even next to real data.
 *
 * Run:  ALLOW_ATLAS_WRITES=yes npm run verify:phase5:atlas
 */

require('dotenv').config({ quiet: true });

// This process never listens. Some IDE/tooling shells (the Freebuff/VSCode task
// environment included) export PORT=0, which would otherwise fail environment
// validation before a single check runs.
delete process.env.PORT;

if (process.env.ALLOW_ATLAS_WRITES !== 'yes') {
  console.error(
    [
      '✖ Refusing to run: this script writes probe documents to the database in MONGO_URI.',
      '  Re-run with:  ALLOW_ATLAS_WRITES=yes npm run verify:phase5:atlas',
      '  It deletes everything it creates, and verifies that cleanup.',
    ].join('\n')
  );
  process.exit(2);
}

const assert = require('node:assert/strict');
const mongoose = require('mongoose');

const PROBE_OCEAN = [75.0, 5.0]; // middle of the Indian Ocean, ~0.5 km from nothing
const PROBE_ALERT_OFFSET = 0.004; // ~440 m east

async function main() {
  const { connectDatabase, disconnectDatabase } = require('../config/db');
  const User = require('../models/User');
  const Nominee = require('../models/Nominee');
  const SosAlert = require('../models/SosAlert');
  const { getDashboard, buildNearbyPipeline } = require('../services/analyticsService');

  console.log('▶ Connecting to Atlas (indexes are built on connect)...');
  await connectDatabase();

  const tag = String(Date.now()).slice(-6);
  const mePhone = `+9199${tag}`;
  const guardianOnePhone = `+9198${tag}`;
  const guardianTwoPhone = `+9197${tag}`;

  const checks = [];
  const record = (name, fn) =>
    Promise.resolve()
      .then(fn)
      .then(() => checks.push({ name, ok: true }))
      .catch((error) => checks.push({ name, ok: false, error: error.message }));

  const users = mongoose.connection.collection('users');
  const nomineeCollection = mongoose.connection.collection('nominees');
  const alertCollection = mongoose.connection.collection('sosalerts');

  let meId = null;

  try {
    const me = await User.create({
      phone: mePhone,
      name: 'Phase 5 Atlas Probe',
      isEmergencyMode: true,
      biometricEnabled: true,
      securityPinHash: '$2a$10$atlasprobehashvalue000000',
      fcmToken: 'atlas-probe-device-token',
      lastKnownLocation: { type: 'Point', coordinates: PROBE_OCEAN },
    });

    meId = me._id;

    await Nominee.create([
      { userId: meId, name: 'Atlas Guardian One', phone: guardianOnePhone, isPrimary: true },
      { userId: meId, name: 'Atlas Guardian Two', phone: guardianTwoPhone },
    ]);

    const alert = await SosAlert.create({
      userId: meId,
      status: 'ACTIVE',
      initialLocation: {
        type: 'Point',
        coordinates: [PROBE_OCEAN[0] + PROBE_ALERT_OFFSET, PROBE_OCEAN[1]],
      },
    });

    await record('atlas: dashboard runs on the live cluster and scores a full profile 100', async () => {
      const dashboard = await getDashboard({ userId: String(meId) });

      assert.equal(dashboard.readiness.score, 100, JSON.stringify(dashboard.readiness));
      assert.equal(dashboard.readiness.nomineeCount, 2);
      assert.equal(dashboard.readiness.level, 'strong');
      assert.ok(dashboard.perimeter.totalUsers > 0);
      assert.ok(dashboard.alerts.activeNow >= 1, 'the probe alert must count as active');
      assert.ok(dashboard.generatedAt);
    });

    await record('atlas: $geoNear finds exactly the probe alert, bounded by distance and time', async () => {
      const dashboard = await getDashboard({ userId: String(meId) });

      assert.equal(dashboard.alerts.nearby.available, true);
      assert.equal(dashboard.alerts.nearby.count, 1, JSON.stringify(dashboard.alerts.nearby));
      assert.deepEqual(dashboard.alerts.nearby.byStatus, { ACTIVE: 1, RESOLVED: 0, FALSE_ALARM: 0 });
      assert.equal(dashboard.alerts.nearby.radiusMeters, 5000);
    });

    await record('atlas: a radius override excludes the probe alert again', async () => {
      // ~440 m away, so 100 m must not reach it.
      const dashboard = await getDashboard({ userId: String(meId) , radiusMeters: 100 });

      assert.equal(dashboard.alerts.nearby.radiusMeters, 100);
      assert.equal(dashboard.alerts.nearby.count, 0, JSON.stringify(dashboard.alerts.nearby));
    });

    await record('atlas: response carries no alert ids or coordinates', async () => {
      const dashboard = await getDashboard({ userId: String(meId) });
      const serialized = JSON.stringify(dashboard);

      assert.equal(/[0-9a-f]{24}/.test(serialized), false, 'a 24-hex id leaked');
      assert.equal(serialized.includes('coordinates'), false, 'raw GeoJSON leaked');
    });

    await record('atlas: the 2dsphere index is used (GEO_NEAR, no COLLSCAN)', async () => {
      const plan = JSON.stringify(
        await alertCollection
          .aggregate(
            buildNearbyPipeline({
              coordinates: PROBE_OCEAN,
              radiusMeters: 5000,
              since: new Date(Date.now() - 3_600_000),
            })
          )
          .explain()
      );

      assert.match(plan, /GEO_NEAR_2DSPHERE/);
      assert.equal(plan.includes('COLLSCAN'), false);
    });

    await record('atlas: every Phase 5 index exists on the cluster', async () => {
      const userIndexes = await users.indexes();
      const nomineeIndexes = await nomineeCollection.indexes();
      const alertIndexes = await alertCollection.indexes();

      assert.ok(userIndexes.some((index) => index.key.isEmergencyMode === 1), 'users.isEmergencyMode_1 missing');
      assert.ok(
        userIndexes.some((index) => index.key.lastKnownLocation === '2dsphere'),
        'users.lastKnownLocation_2dsphere missing'
      );
      assert.ok(
        nomineeIndexes.some((index) => index.key.userId === 1 && index.key.phone === 1),
        'nominees compound index missing'
      );
      assert.ok(
        alertIndexes.some((index) => index.key.initialLocation === '2dsphere'),
        'sosalerts.initialLocation_2dsphere missing'
      );
      assert.ok(alertIndexes.some((index) => index.key.createdAt === -1), 'sosalerts.createdAt_-1 missing');
      assert.ok(
        alertIndexes.some((index) => index.key.status === 1 && index.key.createdAt === -1),
        'sosalerts status+createdAt missing'
      );
    });

    assert.ok(alert.roomId);
  } finally {
    if (meId) {
      await alertCollection.deleteMany({ userId: meId });
      await nomineeCollection.deleteMany({ userId: meId });
      await users.deleteOne({ _id: meId });
    }

    const leftovers = meId
      ? {
          users: await users.countDocuments({ _id: meId }),
          nominees: await nomineeCollection.countDocuments({ userId: meId }),
          alerts: await alertCollection.countDocuments({ userId: meId }),
        }
      : { users: 0, nominees: 0, alerts: 0 };

    await record('atlas: probe data is fully removed', async () => {
      assert.deepEqual(leftovers, { users: 0, nominees: 0, alerts: 0 });
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

main().catch(async (error) => {
  console.error('✖ Live Atlas verifier crashed:', error);
  process.exit(1);
});
