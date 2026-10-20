'use strict';

/**
 * GuardFi — unified demo seed (Phase 10)
 *
 * One command prepares a complete, believable demo for the Flutter app and for
 * judges on a fresh Atlas cluster:
 *
 *   1. one demo account with a KNOWN phone number and Shield Pay PIN,
 *   2. two guardians/nominees (one primary),
 *   3. 18+ flagged UPI IDs, phishing links and phone numbers (Phase 6 dataset),
 *   4. the AppConfig singleton with its default thresholds and helplines.
 *
 * Idempotent by construction: every write is an upsert keyed on the natural
 * identifier (phone / {userId, phone} / identifier / the config singleton), so
 * running it twice leaves exactly the same database — the second run reports
 * updates, not duplicates. Re-running after a `git pull` also upgrades the
 * blocklist wording and report counts, because the seed file is the source of
 * truth and `$set` always wins.
 *
 * Run:  npm run seed:demo
 *       npm run seed:demo -- --dry-run
 *
 * SAFETY: this writes to whatever MONGO_URI points at, including Atlas. That is
 * the point — the demo data has to be on the cluster the app talks to. It never
 * deletes anything: users, nominees and blocklist rows that are not part of the
 * demo set are left untouched.
 */

require('dotenv').config({ quiet: true });

// A seeder never listens. Some IDE / tooling shells export PORT=0, which would
// otherwise fail environment validation ("PORT: expected >= 1") before a single
// row is written. Dropping a non-positive port is safe: nothing here binds it.
if (process.env.PORT !== undefined && !(Number(process.env.PORT) >= 1)) delete process.env.PORT;

const bcrypt = require('bcryptjs');

const DEMO_USER = Object.freeze({
  phone: '+919876500001',
  name: 'Aarav Sharma',
  /** The PIN the demo script and the Postman collection both use. */
  pin: '4821',
  /** Delhi — a real point, so the analytics "alerts near me" facet has data. */
  location: { longitude: 77.209, latitude: 28.6139 },
});

const DEMO_NOMINEES = Object.freeze([
  { name: 'Priya Sharma', phone: '+919876500002', relation: 'Sister', isPrimary: true },
  { name: 'Rohan Verma', phone: '+919876500003', relation: 'Friend', isPrimary: false },
]);

/**
 * @param {{ dryRun?: boolean }} [options]
 */
async function seedDemo({ dryRun = false } = {}) {
  const User = require('../models/User');
  const Nominee = require('../models/Nominee');
  const AppConfig = require('../models/AppConfig');
  const { config } = require('../config/env');
  const { seedFlaggedEntities } = require('./seedFlaggedUpi');

  const summary = {
    dryRun,
    user: { phone: DEMO_USER.phone, action: 'would-upsert' },
    nominees: { total: DEMO_NOMINEES.length, created: 0, updated: 0 },
    flagged: { total: 0, created: 0, updated: 0 },
    appConfig: { action: 'would-seed-defaults' },
  };

  if (dryRun) {
    const { FLAGGED_ENTITIES } = require('./seedFlaggedUpi');
    summary.flagged.total = FLAGGED_ENTITIES.length;
    return summary;
  }

  // --- 1. demo account -------------------------------------------------------
  const pinHash = await bcrypt.hash(DEMO_USER.pin, config.bcrypt.saltRounds);

  const existingUser = await User.findOne({ phone: DEMO_USER.phone }).select('_id').lean();

  const user = await User.findOneAndUpdate(
    { phone: DEMO_USER.phone },
    {
      $set: {
        name: DEMO_USER.name,
        // Always re-asserted: the whole point of the demo account is that the
        // PIN in the docs is the PIN that works. A bcrypt hash differs per run,
        // which is expected — the resulting login does not.
        securityPinHash: pinHash,
        lastKnownLocation: { type: 'Point', coordinates: [DEMO_USER.location.longitude, DEMO_USER.location.latitude] },
        isEmergencyMode: false,
        emergencyActivatedAt: null,
      },
      $setOnInsert: { phone: DEMO_USER.phone, role: 'user', biometricEnabled: false },
    },
    { upsert: true, returnDocument: 'after', runValidators: true }
  );

  summary.user.action = existingUser ? 'updated' : 'created';
  summary.user.id = String(user._id);

  // --- 2. guardians ----------------------------------------------------------
  // Demote first: the partial unique index permits ONE primary nominee per user,
  // so promoting ours before clearing a previously seeded primary would be an
  // E11000.
  await Nominee.updateMany({ userId: user._id }, { $set: { isPrimary: false } });

  for (const nominee of DEMO_NOMINEES) {
    const before = await Nominee.findOne({ userId: user._id, phone: nominee.phone }).select('_id').lean();

    await Nominee.findOneAndUpdate(
      { userId: user._id, phone: nominee.phone },
      { $set: { name: nominee.name, relation: nominee.relation, isPrimary: nominee.isPrimary } },
      { upsert: true, returnDocument: 'after', runValidators: true }
    );

    if (before) summary.nominees.updated += 1;
    else summary.nominees.created += 1;
  }

  // --- 3. scam blocklist -----------------------------------------------------
  const flagged = await seedFlaggedEntities();
  summary.flagged = { total: flagged.total, created: flagged.created, updated: flagged.updated };

  // --- 4. global config ------------------------------------------------------
  const beforeConfig = await AppConfig.findOne({ key: 'GLOBAL_CONFIG' }).select('version').lean();
  const appConfig = await AppConfig.getOrSeed();
  summary.appConfig = {
    action: beforeConfig ? 'existing-kept' : 'seeded-defaults',
    version: appConfig.version,
    maintenanceMode: appConfig.maintenanceMode,
    thresholds: appConfig.globalWarningThresholds,
  };

  return summary;
}

async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const { connectDatabase, disconnectDatabase } = require('../config/db');

  console.log(`▶ GuardFi demo seed${dryRun ? ' (dry run)' : ''}`);
  console.log(`  demo account : ${DEMO_USER.phone}  (PIN ${DEMO_USER.pin})`);
  console.log(`  guardians    : ${DEMO_NOMINEES.map((entry) => `${entry.name} ${entry.phone}`).join(', ')}`);
  console.log('  blocklist    : the Phase 6 flagged-entity dataset');
  console.log('  global config: AppConfig singleton with default thresholds\n');

  if (dryRun) {
    const summary = await seedDemo({ dryRun: true });
    console.log(`✔ Dry run complete — would write ${summary.flagged.total} flagged entities, 1 user, ${summary.nominees.total} nominees.`);
    console.log('  Re-run without --dry-run to write.');
    return;
  }

  await connectDatabase();

  try {
    const mongoose = require('mongoose');
    console.log(`▶ Target database: ${mongoose.connection.name} (${mongoose.connection.host})\n`);

    const summary = await seedDemo({ dryRun: false });

    console.log(`✔ Demo user ${summary.user.action}: ${DEMO_USER.phone} (${summary.user.id})`);
    console.log(
      `✔ Nominees: ${summary.nominees.created} created, ${summary.nominees.updated} updated (${summary.nominees.total} total)`
    );
    console.log(
      `✔ Flagged entities: ${summary.flagged.created} created, ${summary.flagged.updated} updated (${summary.flagged.total} total)`
    );
    console.log(`✔ AppConfig: ${summary.appConfig.action} (version ${summary.appConfig.version})`);
    console.log('\n  Demo login: POST /api/v1/auth/send-otp then /verify-otp with this number, then set nothing — the PIN is already configured.');
  } finally {
    await disconnectDatabase({ force: true });
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error('✖ Demo seed failed:', error.message);
    process.exit(1);
  });
}

module.exports = { seedDemo, DEMO_USER, DEMO_NOMINEES };
