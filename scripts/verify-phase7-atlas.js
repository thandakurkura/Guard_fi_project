'use strict';

/**
 * GuardFi — Phase 7 verification against the LIVE Atlas cluster (Scam Buster)
 *
 * Deliberately opt-in: it WRITES to whatever MONGO_URI points at, so it refuses
 * to run unless ALLOW_ATLAS_WRITES=yes is set. Every document it creates is
 * removed in a `finally` block, and the cleanup is asserted, not assumed.
 *
 * What it proves that the in-memory harness cannot:
 *   • ScamScan writes really land on the shared cluster and the history index
 *     exists there (production runs with autoIndex off, so a missing index would
 *     otherwise stay invisible until the collection grew);
 *   • the history query — plain and cursor-paged — is an IXSCAN on the live
 *     planner;
 *   • the fallback contract holds on the real database: a provider timeout is
 *     STORED as a HEURISTIC verdict, while a genuine bug still writes nothing;
 *   • with no key at all, a scan is answered by the deterministic offline screen
 *     (never a 503) and the row says so.
 *
 * Providers are INJECTED by default, so the suite runs without any AI or storage
 * credentials and never touches local disk. If GEMINI_API_KEY IS configured, one
 * extra check runs a real end-to-end analysis; otherwise it is reported as SKIP
 * — never as a pass.
 *
 * Run:  ALLOW_ATLAS_WRITES=yes npm run verify:phase7:atlas
 */

require('dotenv').config({ quiet: true });

// This script never listens on a port; a stray PORT from the shell (some
// terminals export PORT=0) must not fail the environment check.
delete process.env.PORT;

if (process.env.ALLOW_ATLAS_WRITES !== 'yes') {
  console.error(
    [
      '✖ Refusing to run: this script writes probe documents to the database in MONGO_URI.',
      '  Re-run with:  ALLOW_ATLAS_WRITES=yes npm run verify:phase7:atlas',
      '  It deletes everything it creates, and verifies that cleanup.',
    ].join('\n')
  );
  process.exit(2);
}

const assert = require('node:assert/strict');
const mongoose = require('mongoose');

const CANNED = JSON.stringify({
  isScam: true,
  riskLevel: 'DANGER',
  confidence: 93,
  explanation_en: 'Fake KYC scam asking for your UPI PIN.',
  explanation_hi: 'नकली KYC घोटाला, जो आपका UPI PIN मांगता है।',
  redFlags: ['asks for UPI PIN', 'KYC expiry threat'],
  extractedText: 'Your KYC is expiring today. Update now at the link below.',
});

const PNG_BYTES = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');

async function main() {
  const { connectDatabase, disconnectDatabase } = require('../config/db');
  const User = require('../models/User');
  const ScamScan = require('../models/ScamScan');
  const ApiError = require('../utils/ApiError');
  const { config } = require('../config/env');
  const { analyzeScan, listScans } = require('../services/scamBusterService');
  const { analyzeText } = require('../services/geminiService');

  console.log('▶ Connecting to Atlas (indexes are built on connect)...');
  await connectDatabase();

  const tag = String(Date.now()).slice(-6);
  const probePhone = `+9199${tag}`;

  const checks = [];
  const skipped = [];
  const record = (name, fn) =>
    Promise.resolve()
      .then(fn)
      .then(() => checks.push({ name, ok: true }))
      .catch((error) => checks.push({ name, ok: false, error: error.message }));

  const scans = ScamScan.collection;
  const users = User.collection;

  let probeUserId = null;

  try {
    const probeUser = await User.create({ phone: probePhone, name: 'Phase 7 Atlas Probe' });
    probeUserId = probeUser._id;

    await record('atlas: a text scan round-trips through the live cluster with both languages', async () => {
      const row = await analyzeScan({
        userId: probeUserId,
        text: 'Dear customer, share the OTP you just received or your account will be blocked.',
        requestIp: '127.0.0.1',
        deps: { analyze: async () => ({ rawText: CANNED, model: 'atlas-fake-model' }) },
      });

      const stored = await ScamScan.findById(row._id).lean();

      assert.equal(stored.isScam, true);
      assert.equal(stored.riskLevel, 'DANGER');
      assert.equal(stored.confidenceScore, 93);
      assert.equal(stored.analysisSource, 'GEMINI');
      assert.equal(stored.fallbackReason, null);
      assert.match(stored.explanation_hi, /[\u0900-\u097F]/);
      assert.deepEqual(stored.redFlags, ['asks for UPI PIN', 'KYC expiry threat']);
      assert.equal(stored.imageUrl, null);
      assert.equal(stored.aiModel, 'atlas-fake-model');
      assert.equal(String(stored.userId), String(probeUserId));
    });

    await record('atlas: a screenshot scan stores the image reference, its storage and the OCR text', async () => {
      const row = await analyzeScan({
        userId: probeUserId,
        file: { buffer: PNG_BYTES, mimetype: 'image/png' },
        deps: {
          store: async () => ({
            imageUrl: 'https://res.cloudinary.test/atlas/probe.png',
            cloudinaryPublicId: 'atlas/probe',
            storage: 'CLOUDINARY',
          }),
          analyze: async () => ({ rawText: CANNED, model: 'atlas-fake-model' }),
        },
      });

      const stored = await ScamScan.findById(row._id).lean();

      assert.equal(stored.inputType, 'IMAGE');
      assert.equal(stored.imageUrl, 'https://res.cloudinary.test/atlas/probe.png');
      assert.equal(stored.cloudinaryPublicId, 'atlas/probe');
      assert.equal(stored.imageStorage, 'CLOUDINARY');
      assert.equal(stored.extractedText, 'Your KYC is expiring today. Update now at the link below.');
    });

    await record('atlas: a provider timeout is stored as a HEURISTIC verdict, not lost', async () => {
      const row = await analyzeScan({
        userId: probeUserId,
        text: 'URGENT: your electricity connection will be disconnected today. Pay the clearance fee now.',
        deps: {
          analyze: async () => {
            throw new ApiError(504, 'timed out', { code: 'AI_TIMEOUT' });
          },
        },
      });

      const stored = await ScamScan.findById(row._id).lean();

      assert.equal(stored.analysisSource, 'HEURISTIC');
      assert.equal(stored.fallbackReason, 'AI_TIMEOUT');
      assert.equal(stored.aiModel, null);
      assert.equal(stored.isScam, true);
      assert.match(stored.explanation_hi, /[\u0900-\u097F]/);
    });

    await record('atlas: a real bug still writes nothing on the live cluster', async () => {
      const before = await scans.countDocuments({ userId: probeUserId });

      await assert.rejects(
        () => analyzeScan({ userId: probeUserId, text: 'test', deps: { analyze: async () => { throw new TypeError('boom'); } } }),
        (error) => error instanceof TypeError
      );

      assert.equal(await scans.countDocuments({ userId: probeUserId }), before);
    });

    await record('atlas: history is the owner\'s scans, newest first, and pages exactly', async () => {
      const expected = await listScans({ userId: probeUserId, limit: 50 });

      assert.ok(expected.count >= 3, `expected at least 3 probe scans, found ${expected.count}`);
      assert.equal(expected.scans[0].scanId, String((await scans.find({ userId: probeUserId }).sort({ createdAt: -1, _id: -1 }).limit(1).toArray())[0]._id));

      const collected = [];
      let before = null;

      for (let page = 0; page < expected.count + 1; page += 1) {
        const result = await listScans({ userId: probeUserId, limit: 1, before });

        if (result.count === 0) break;

        collected.push(result.scans[0].scanId);
        before = result.nextBefore;
      }

      assert.deepEqual(collected, expected.scans.map((scan) => scan.scanId), 'paging must visit each scan exactly once');

      const stranger = await listScans({ userId: new mongoose.Types.ObjectId() });
      assert.equal(stranger.count, 0, 'a stranger must see no probe scans');
    });

    await record('atlas: the scan-history index exists and both history queries are IXSCANs', async () => {
      const indexes = await scans.indexes();
      assert.ok(
        indexes.some((index) => index.key.userId === 1 && index.key.createdAt === -1),
        'scamscans user history index missing on the cluster'
      );

      const plain = JSON.stringify(
        await scans.find({ userId: probeUserId }).sort({ createdAt: -1, _id: -1 }).explain('executionStats')
      );

      assert.match(plain, /IXSCAN/);
      assert.equal(plain.includes('COLLSCAN'), false, 'the live scan-history query fell back to a collection scan');

      const at = new Date();
      const cursor = JSON.stringify(
        await scans
          .find({
            userId: probeUserId,
            $or: [{ createdAt: { $lt: at } }, { createdAt: at, _id: { $lt: new mongoose.Types.ObjectId() } }],
          })
          .sort({ createdAt: -1, _id: -1 })
          .explain('executionStats')
      );

      assert.match(cursor, /IXSCAN/);
      assert.equal(cursor.includes('COLLSCAN'), false, 'the live cursor query fell back to a collection scan');
    });

    if (config.gemini.configured) {
      await record('atlas: a real Gemini scan flags a blatant scam message', async () => {
        const { rawText } = await analyzeText({
          text: 'URGENT: Your SBI account will be blocked today. Update your KYC immediately and share the OTP sent to your phone to avoid suspension.',
        });

        const { parseAiPayload } = require('../services/scamBusterService');
        const verdict = parseAiPayload(rawText);

        assert.equal(verdict.isScam, true, `real model said safe: ${rawText.slice(0, 300)}`);
        assert.match(verdict.explanation_hi, /[\u0900-\u097F]/);
      });
    } else {
      await record('atlas: with no API key a scan is answered by the offline screen, never a 503', async () => {
        const row = await analyzeScan({
          userId: probeUserId,
          text: 'Your KYC will expire today. Share the OTP to avoid your account being blocked.',
        });

        const stored = await ScamScan.findById(row._id).lean();

        assert.equal(stored.analysisSource, 'HEURISTIC');
        assert.equal(stored.fallbackReason, 'AI_NOT_CONFIGURED');
        assert.equal(stored.isScam, true);
        assert.equal(stored.aiModel, null);
        assert.match(stored.explanation_hi, /[\u0900-\u097F]/);
      });

      skipped.push('atlas: a real Gemini scan flags a blatant scam message (GEMINI_API_KEY is not set)');
    }
  } finally {
    if (probeUserId) {
      await scans.deleteMany({ userId: probeUserId });
      await users.deleteOne({ _id: probeUserId });
    }

    const leftovers = probeUserId
      ? {
          scans: await scans.countDocuments({ userId: probeUserId }),
          users: await users.countDocuments({ _id: probeUserId }),
        }
      : { scans: 0, users: 0 };

    await record('atlas: probe data is fully removed', async () => {
      assert.deepEqual(leftovers, { scans: 0, users: 0 });
    });

    await disconnectDatabase({ force: true });
  }

  const passed = checks.filter((check) => check.ok).length;
  const failed = checks.filter((check) => !check.ok);

  console.log('');
  for (const check of checks) {
    console.log(`${check.ok ? '  PASS' : '  FAIL'}  ${check.name}${check.ok ? '' : `\n          ↳ ${check.error}`}`);
  }
  for (const name of skipped) {
    console.log(`  SKIP  ${name}`);
  }
  console.log(`\n${passed}/${checks.length} live Atlas checks passed${skipped.length ? `, ${skipped.length} skipped` : ''}.`);

  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch(async (error) => {
  console.error('✖ Live Atlas verifier crashed:', error);
  process.exit(1);
});
