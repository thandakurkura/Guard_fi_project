'use strict';

/**
 * GuardFi — Phase 6 verification against the LIVE Atlas cluster (Shield Pay)
 *
 * Deliberately opt-in: it WRITES to whatever MONGO_URI points at, so it refuses
 * to run unless ALLOW_ATLAS_WRITES=yes is set. Every document it creates is
 * removed in a `finally` block, and the cleanup is asserted, not assumed. All
 * probe identifiers carry an `atlasprobe-` prefix and all probe rows are keyed
 * to one throwaway user, so nothing real can be touched.
 *
 * What it proves that the in-memory harness cannot:
 *   • the real Atlas query planner accepts the blocklist lookup and serves it
 *     from the unique B-tree index (production runs with autoIndex off, so a
 *     missing index would be silent);
 *   • the pending → completed transition of the state machine behaves the same
 *     against the live server, including the single-use replay guard;
 *   • every Phase 6 index really exists on the cluster, with the TTL and partial
 *     options intact.
 *
 * Run:  ALLOW_ATLAS_WRITES=yes npm run verify:phase6:atlas
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
      '  Re-run with:  ALLOW_ATLAS_WRITES=yes npm run verify:phase6:atlas',
      '  It deletes everything it creates, and verifies that cleanup.',
    ].join('\n')
  );
  process.exit(2);
}

const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');

const PIN = '4821';

async function main() {
  const { connectDatabase, disconnectDatabase } = require('../config/db');
  const User = require('../models/User');
  const FlaggedEntity = require('../models/FlaggedEntity');
  const TransactionAudit = require('../models/TransactionAudit');
  const { checkIdentifier, proceedTransaction, normalizeIdentifierInput } = require('../services/shieldPayService');
  const { FLAGGED_ENTITIES, validateDataset } = require('./seedFlaggedUpi');

  console.log('▶ Connecting to Atlas (indexes are built on connect)...');
  await connectDatabase();

  const tag = String(Date.now()).slice(-6);
  const probePhone = `+9199${tag}`;
  const probeUpi = `atlasprobe-kyc-help-${tag}@ybl`;
  const probeUrl = `atlasprobe-phish-${tag}.verify-login.xyz`;
  const probeSafeUpi = `atlasprobe-store-${tag}@okicici`;
  const probeIdentifiers = [probeUpi, probeUrl, probeSafeUpi];

  const checks = [];
  const record = (name, fn) =>
    Promise.resolve()
      .then(fn)
      .then(() => checks.push({ name, ok: true }))
      .catch((error) => checks.push({ name, ok: false, error: error.message }));

  const audits = TransactionAudit.collection;
  const entities = FlaggedEntity.collection;
  const users = User.collection;

  let probeUserId = null;

  try {
    const probeUser = await User.create({
      phone: probePhone,
      name: 'Phase 6 Atlas Probe',
      securityPinHash: await bcrypt.hash(PIN, 8),
    });
    probeUserId = probeUser._id;

    await FlaggedEntity.insertMany([
      {
        identifier: probeUpi,
        type: 'UPI',
        riskLevel: 'DANGER',
        reportCount: 176,
        reason_en: 'This UPI ID is linked to reported phishing scams.',
        reason_hi: 'यह UPI ID रिपोर्ट किए गए धोखाधड़ी मामलों से जुड़ी है।',
      },
      {
        identifier: probeUrl,
        type: 'URL',
        riskLevel: 'DANGER',
        reportCount: 211,
        reason_en: 'Cloned payment page that harvests UPI credentials.',
        reason_hi: 'नकली भुगतान पेज, जो UPI क्रेडेंशियल चुराता है।',
      },
      {
        identifier: probeSafeUpi,
        type: 'UPI',
        riskLevel: 'SAFE',
        reportCount: 0,
        reason_en: 'Verified merchant handle used by the Atlas probe.',
        reason_hi: 'Atlas प्रोब द्वारा उपयोग किया गया सत्यापित व्यापारी हैंडल।',
      },
    ]);

    let dangerCheckId = null;

    await record('atlas: the blocklist lookup is served by the unique identifier index', async () => {
      const input = normalizeIdentifierInput(`https://${probeUrl}/login?ref=1`);

      const plan = JSON.stringify(
        await entities.find({ identifier: { $in: input.candidates } }).explain('executionStats')
      );

      assert.match(plan, /IXSCAN/);
      assert.match(plan, /unique_identifier/);
      assert.equal(plan.includes('COLLSCAN'), false, 'the live plan fell back to a collection scan');
    });

    await record('atlas: a reported payee produces the exact bilingual danger envelope', async () => {
      const verdict = await checkIdentifier({ userId: probeUserId, rawIdentifier: probeUpi });

      assert.equal(verdict.status, 'danger');
      assert.equal(verdict.riskLevel, 'DANGER');
      assert.equal(verdict.riskScore, 92, JSON.stringify(verdict));
      assert.equal(verdict.reportCount, 176);
      assert.equal(verdict.msg_en, 'Fraud Alert: This UPI ID is linked to reported phishing scams.');
      assert.match(verdict.msg_hi, /फ्रॉड अलर्ट/);
      assert.match(verdict.checkId, /^[0-9a-f]{24}$/);

      dangerCheckId = verdict.checkId;

      const pending = await TransactionAudit.findById(dangerCheckId).lean();
      assert.equal(pending.status, 'PENDING');
      assert.ok(pending.expiresAt instanceof Date && pending.expiresAt.getTime() > Date.now());
      assert.equal(pending.amount, null);
    });

    await record('atlas: a link matches through its host with the query string ignored', async () => {
      const verdict = await checkIdentifier({
        userId: probeUserId,
        rawIdentifier: `https://${probeUrl}/login?ref=1`,
      });

      assert.equal(verdict.status, 'danger');
      assert.equal(verdict.riskScore, 95); // 211 reports, capped
      assert.equal(verdict.matchedIdentifier, probeUrl);
    });

    await record('atlas: a verified-safe payee settles without any risk check', async () => {
      const verdict = await checkIdentifier({ userId: probeUserId, rawIdentifier: probeSafeUpi });
      assert.equal(verdict.status, 'safe');
      assert.equal(verdict.checkId, null);

      const receipt = await proceedTransaction({
        userId: probeUserId,
        rawIdentifier: probeSafeUpi,
        amount: 199.5,
        pin: PIN,
      });

      assert.equal(receipt.status, 'completed');
      assert.equal(receipt.risk_accepted, false);
      assert.match(receipt.transactionHash, /^[0-9a-f]{64}$/);

      const row = await TransactionAudit.findById(receipt.auditId).lean();
      assert.equal(row.status, 'COMPLETED');
      assert.equal(row.pinVerified, true);
    });

    await record('atlas: "Proceed Anyway" completes the pending check on the live cluster', async () => {
      const receipt = await proceedTransaction({
        userId: probeUserId,
        rawIdentifier: probeUpi,
        amount: 4999,
        pin: PIN,
        riskAccepted: true,
        checkId: dangerCheckId,
      });

      assert.equal(receipt.status, 'completed');
      assert.equal(receipt.risk_accepted, true);
      assert.equal(receipt.pinVerified, true);
      assert.match(receipt.transactionHash, /^[0-9a-f]{64}$/);

      const row = await TransactionAudit.findById(receipt.auditId).lean();
      assert.equal(row.status, 'COMPLETED');
      assert.equal(row.expiresAt, null, 'a completed row must leave the TTL index');
      assert.equal(row.amount, 4999);
    });

    await record('atlas: a replayed risk check is refused with no second transaction', async () => {
      await assert.rejects(
        () =>
          proceedTransaction({
            userId: probeUserId,
            rawIdentifier: probeUpi,
            amount: 4999,
            pin: PIN,
            riskAccepted: true,
            checkId: dangerCheckId,
          }),
        (error) => error.statusCode === 409 && error.code === 'RISK_CHECK_ALREADY_USED'
      );

      const completed = await audits.countDocuments({ userId: probeUserId, upiId: probeUpi, status: 'COMPLETED' });
      assert.equal(completed, 1, 'the replay must not have created a second transaction');
    });

    await record('atlas: a wrong PIN is audited and does not consume the risk check', async () => {
      const check = await checkIdentifier({ userId: probeUserId, rawIdentifier: probeUpi });

      await assert.rejects(
        () =>
          proceedTransaction({
            userId: probeUserId,
            rawIdentifier: probeUpi,
            amount: 100,
            pin: '9999',
            riskAccepted: true,
            checkId: check.checkId,
          }),
        (error) => error.statusCode === 401 && error.code === 'INVALID_PIN'
      );

      const rejected = await TransactionAudit.findOne({ userId: probeUserId, status: 'REJECTED' }).lean();
      assert.ok(rejected, 'the failed PIN attempt must be on the cluster');
      assert.equal(rejected.failureReason, 'INVALID_PIN');

      const pending = await TransactionAudit.findById(check.checkId).lean();
      assert.equal(pending.status, 'PENDING', 'a failed PIN must not burn the check');
    });

    await record('atlas: every Phase 6 index exists on the cluster', async () => {
      const entityIndexes = await entities.indexes();
      const auditIndexes = await audits.indexes();

      const identifierIndex = entityIndexes.find((index) => index.key.identifier === 1);
      assert.ok(identifierIndex, 'flaggedentities.identifier_1 missing');
      assert.equal(identifierIndex.unique, true);

      assert.ok(
        auditIndexes.some((index) => index.key.userId === 1 && index.key.createdAt === -1),
        'transactionaudits user history index missing'
      );

      const hashIndex = auditIndexes.find((index) => index.key.transactionHash === 1);
      assert.ok(hashIndex, 'transactionaudits.transactionHash_1 missing');
      assert.equal(hashIndex.unique, true);
      assert.ok(hashIndex.partialFilterExpression, 'the hash index must be partial');

      const ttlIndex = auditIndexes.find((index) => index.key.expiresAt === 1);
      assert.ok(ttlIndex, 'transactionaudits.expiresAt_1 missing');
      assert.equal(ttlIndex.expireAfterSeconds, 0);
      assert.deepEqual(ttlIndex.partialFilterExpression, { status: 'PENDING' });
    });

    await record('atlas: the seed dataset is coherent (shape-checked, not written)', async () => {
      const problems = validateDataset(FLAGGED_ENTITIES);
      assert.deepEqual(problems, [], `seed problems: ${problems.join('; ')}`);
      assert.ok(FLAGGED_ENTITIES.length >= 15, 'the demo dataset should stay substantial');
      assert.ok(
        FLAGGED_ENTITIES.some((entry) => entry.type === 'URL') &&
          FLAGGED_ENTITIES.some((entry) => entry.type === 'UPI') &&
          FLAGGED_ENTITIES.some((entry) => entry.type === 'PHONE'),
        'the dataset should cover all three identifier types'
      );
    });
  } finally {
    if (probeUserId) {
      await audits.deleteMany({ userId: probeUserId });
      await entities.deleteMany({ identifier: { $in: probeIdentifiers } });
      await users.deleteOne({ _id: probeUserId });
    }

    const leftovers = probeUserId
      ? {
          audits: await audits.countDocuments({ userId: probeUserId }),
          entities: await entities.countDocuments({ identifier: { $in: probeIdentifiers } }),
          users: await users.countDocuments({ _id: probeUserId }),
        }
      : { audits: 0, entities: 0, users: 0 };

    await record('atlas: probe data is fully removed', async () => {
      assert.deepEqual(leftovers, { audits: 0, entities: 0, users: 0 });
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
