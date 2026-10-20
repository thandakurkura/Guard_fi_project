'use strict';

/**
 * GuardFi — Shield Pay demo blocklist seed (Phase 6)
 *
 * Pre-populates `FlaggedEntity` with the kind of scam data a hackathon demo
 * needs: fake KYC/refund/lottery VPAs, phishing links, and reported fraud
 * numbers — every row in BOTH languages, because a bilingual API is only
 * bilingual if the data is.
 *
 * Run:  npm run seed:flagged          (idempotent upsert into MONGO_URI)
 *       npm run seed:flagged -- --dry-run
 *
 * Why upsert instead of insert: the script is meant to be re-runnable — after a
 * pull, on a new cluster, or to restore the demo dataset if someone edited a
 * verdict. The unique B-tree index on `identifier` is what makes that possible,
 * and `$set` (not `$setOnInsert`) means the file is the source of truth: the
 * numbers and wording here always win over what a previous run wrote.
 *
 * The score table in services/shieldPayService.js turns `reportCount` into the
 * 0-100 risk score, so these counts are not decoration:
 *   DANGER      → 70 + floor(reports / 8), capped at 95
 *   SUSPICIOUS  → 40 + floor(reports / 8), capped at 69
 * `paytm-kyc-help@ybl` with 176 reports is the spec's own example (score 92).
 */

require('dotenv').config({ quiet: true });

// A seeder never listens. Some IDE / tooling shells export PORT=0, which would
// otherwise fail environment validation ("PORT: expected >= 1") before a single
// row is written. Dropping a non-positive port is safe: nothing here binds it.
if (process.env.PORT !== undefined && !(Number(process.env.PORT) >= 1)) delete process.env.PORT;

const logger = require('../utils/logger');

const ENTITY = Object.freeze({ UPI: 'UPI', URL: 'URL', PHONE: 'PHONE' });
const RISK = Object.freeze({ SAFE: 'SAFE', SUSPICIOUS: 'SUSPICIOUS', DANGER: 'DANGER' });

/**
 * @type {ReadonlyArray<{ identifier: string, type: string, riskLevel: string, reportCount: number, reason_en: string, reason_hi: string }>}
 */
const FLAGGED_ENTITIES = Object.freeze([
  // --- Reported UPI IDs ------------------------------------------------------
  {
    identifier: 'paytm-kyc-help@ybl',
    type: ENTITY.UPI,
    riskLevel: RISK.DANGER,
    reportCount: 176,
    reason_en: 'This UPI ID is linked to reported phishing scams.',
    reason_hi: 'यह UPI ID रिपोर्ट किए गए धोखाधड़ी मामलों से जुड़ी है।',
  },
  {
    identifier: 'sbi.kyc.update@ybl',
    type: ENTITY.UPI,
    riskLevel: RISK.DANGER,
    reportCount: 143,
    reason_en: 'Used in fake KYC-update requests that empty the account once the PIN is entered.',
    reason_hi: 'नकली KYC अपडेट अनुरोधों में इस्तेमाल, PIN डालते ही खाता खाली कर देती है।',
  },
  {
    identifier: 'lottery-winner2026@okaxis',
    type: ENTITY.UPI,
    riskLevel: RISK.DANGER,
    reportCount: 98,
    reason_en: 'Collects a "processing fee" for lottery winnings that do not exist.',
    reason_hi: 'नकली लॉटरी के लिए "प्रोसेसिंग फीस" वसूलती है।',
  },
  {
    identifier: 'army.canteen.offer@paytm',
    type: ENTITY.UPI,
    riskLevel: RISK.DANGER,
    reportCount: 87,
    reason_en: 'Impersonates an army canteen offer and takes advance payments.',
    reason_hi: 'सेना कैंटीन ऑफ़र बताकर अग्रिम भुगतान लेती है।',
  },
  {
    identifier: 'electricity-bill-urgent@paytm',
    type: ENTITY.UPI,
    riskLevel: RISK.DANGER,
    reportCount: 64,
    reason_en: 'Sends fake electricity-disconnection threats demanding instant payment.',
    reason_hi: 'बिजली कटौती की नकली धमकी देकर तुरंत भुगतान मांगती है।',
  },
  {
    identifier: 'refund.customer.care@apl',
    type: ENTITY.UPI,
    riskLevel: RISK.DANGER,
    reportCount: 51,
    reason_en: 'Fake customer-care refund flow that asks for the UPI PIN.',
    reason_hi: 'नकली कस्टमर-केयर रिफंड प्रक्रिया, जो UPI PIN मांगती है।',
  },
  {
    identifier: 'md-refund-help@ybi',
    type: ENTITY.UPI,
    riskLevel: RISK.DANGER,
    reportCount: 22,
    reason_en: 'Look-alike handle used to pose as a payment provider.',
    reason_hi: 'भुगतान प्रदाता बनने के लिए इस्तेमाल किया गया मिलता-जुलता हैंडल।',
  },
  {
    identifier: 'quick-loan-approval@xyzpay',
    type: ENTITY.UPI,
    riskLevel: RISK.DANGER,
    reportCount: 18,
    reason_en: 'Fake instant-loan approval that collects an upfront fee.',
    reason_hi: 'नकली इंस्टेंट लोन मंजूरी, जो पहले फीस वसूलती है।',
  },

  // --- Verified-safe handles (the demo's happy path) --------------------------
  {
    identifier: 'greenbasket.store@okicici',
    type: ENTITY.UPI,
    riskLevel: RISK.SAFE,
    reportCount: 0,
    reason_en: 'Verified merchant handle used for the GuardFi demo checkout.',
    reason_hi: 'GuardFi डेमो चेकआउट के लिए सत्यापित व्यापारी हैंडल।',
  },
  {
    identifier: 'guardfi.demo@okhdfcbank',
    type: ENTITY.UPI,
    riskLevel: RISK.SAFE,
    reportCount: 0,
    reason_en: "GuardFi's own demo collection handle.",
    reason_hi: 'GuardFi का अपना डेमो कलेक्शन हैंडल।',
  },

  // --- Phishing links ---------------------------------------------------------
  {
    identifier: 'secure-paytm-kyc.verify-login.xyz',
    type: ENTITY.URL,
    riskLevel: RISK.DANGER,
    reportCount: 211,
    reason_en: 'Cloned Paytm KYC page that harvests UPI credentials.',
    reason_hi: 'नकली Paytm KYC पेज, जो UPI क्रेडेंशियल चुराता है।',
  },
  {
    identifier: 'sbi-netbanking-update.tk',
    type: ENTITY.URL,
    riskLevel: RISK.DANGER,
    reportCount: 132,
    reason_en: 'Fake SBI net-banking login page targeting account holders.',
    reason_hi: 'खाताधारकों को निशाना बनाने वाला नकली SBI नेट-बैंकिंग लॉगिन पेज।',
  },
  {
    identifier: 'free-recharge-offer.top',
    type: ENTITY.URL,
    riskLevel: RISK.DANGER,
    reportCount: 76,
    reason_en: 'Free-recharge bait that pushes a screen-sharing app to steal OTPs.',
    reason_hi: 'फ्री रिचार्ज के बहाने स्क्रीन-शेयरिंग ऐप डालकर OTP चुराता है।',
  },
  {
    identifier: 'whatsapp-lottery-prize.click',
    type: ENTITY.URL,
    riskLevel: RISK.DANGER,
    reportCount: 59,
    reason_en: 'Lottery-prize phishing link forwarded on WhatsApp.',
    reason_hi: 'WhatsApp पर फैलाया जाने वाला लॉटरी-इनाम फ़िशिंग लिंक।',
  },
  {
    identifier: 'income-tax-refund.in-verify.xyz',
    type: ENTITY.URL,
    riskLevel: RISK.SUSPICIOUS,
    reportCount: 12,
    reason_en: 'Tax-refund look-alike domain that is still being monitored.',
    reason_hi: 'टैक्स-रिफंड जैसा दिखने वाला डोमेन, जिस पर निगरानी जारी है।',
  },
  {
    identifier: 'cashback-reward.buzz',
    type: ENTITY.URL,
    riskLevel: RISK.SUSPICIOUS,
    reportCount: 9,
    reason_en: 'Cashback bait domain seen in forwarded SMS messages.',
    reason_hi: 'फॉरवर्ड SMS में दिखा कैशबैक लालच देने वाला डोमेन।',
  },

  // --- Reported phone numbers -------------------------------------------------
  {
    identifier: '+919812345678',
    type: ENTITY.PHONE,
    riskLevel: RISK.DANGER,
    reportCount: 44,
    reason_en: 'Reported as a fake bank helpline that asks for OTPs.',
    reason_hi: 'नकली बैंक हेल्पलाइन के रूप में रिपोर्ट, जो OTP मांगती है।',
  },
  {
    identifier: '+917065432198',
    type: ENTITY.PHONE,
    riskLevel: RISK.SUSPICIOUS,
    reportCount: 7,
    reason_en: 'Reported spam caller posing as a delivery agent.',
    reason_hi: 'डिलीवरी एजेंट बनकर कॉल करने वाला रिपोर्टेड स्पैम नंबर।',
  },
]);

/**
 * Shape-check the dataset before touching the database: a typo in an enum here
 * would otherwise surface as a confusing validation error mid-run.
 * @returns {string[]} problems (empty when the dataset is coherent)
 */
function validateDataset(entries = FLAGGED_ENTITIES) {
  const problems = [];
  const seen = new Set();

  for (const entry of entries) {
    if (typeof entry.identifier !== 'string' || entry.identifier === '' || entry.identifier !== entry.identifier.trim().toLowerCase()) {
      problems.push(`identifier must be a non-empty lowercase, trimmed string: "${entry.identifier}"`);
    }
    if (seen.has(entry.identifier)) problems.push(`duplicate identifier in the seed file: "${entry.identifier}"`);
    seen.add(entry.identifier);

    if (!Object.values(ENTITY).includes(entry.type)) problems.push(`bad type for "${entry.identifier}"`);
    if (!Object.values(RISK).includes(entry.riskLevel)) problems.push(`bad riskLevel for "${entry.identifier}"`);
    if (!Number.isInteger(entry.reportCount) || entry.reportCount < 0) {
      problems.push(`reportCount must be a whole number ≥ 0: "${entry.identifier}"`);
    }
    if (!entry.reason_en || !entry.reason_hi) problems.push(`both languages are required for "${entry.identifier}"`);
  }

  return problems;
}

/**
 * @param {{ dryRun?: boolean, entries?: ReadonlyArray<object> }} [options]
 */
async function seedFlaggedEntities({ dryRun = false, entries = FLAGGED_ENTITIES } = {}) {
  const problems = validateDataset(entries);
  if (problems.length > 0) {
    throw new Error(`seed dataset is invalid:\n  - ${problems.join('\n  - ')}`);
  }

  const FlaggedEntity = require('../models/FlaggedEntity');
  const summary = { created: 0, updated: 0, total: entries.length, dryRun };

  if (dryRun) return summary;

  for (const entry of entries) {
    const { created } = await FlaggedEntity.upsertReport(entry);
    if (created) summary.created += 1;
    else summary.updated += 1;
  }

  return summary;
}

async function main() {
  const dryRun = process.argv.includes('--dry-run');
  const { connectDatabase, disconnectDatabase } = require('../config/db');

  const problems = validateDataset();
  if (problems.length > 0) {
    console.error('✖ The seed dataset is invalid:');
    for (const problem of problems) console.error(`  • ${problem}`);
    process.exit(1);
  }

  console.log(`▶ FlaggedEntity seed — ${FLAGGED_ENTITIES.length} entries${dryRun ? ' (dry run)' : ''}`);

  if (!dryRun) await connectDatabase();

  try {
    if (dryRun) {
      console.log('▶ Dry run: no database connection, nothing will be written.');
      for (const entry of FLAGGED_ENTITIES.slice(0, 3)) {
        console.log(`  would upsert ${entry.type} ${entry.identifier}`);
      }
      console.log(`  … and ${Math.max(0, FLAGGED_ENTITIES.length - 3)} more.`);
      console.log('✔ Dry run complete. Re-run without --dry-run to write.');
      return;
    }

    const mongoose = require('mongoose');
    console.log(`▶ Target database: ${mongoose.connection.name}`);

    const summary = await seedFlaggedEntities();

    console.log(`✔ Seeded ${summary.total} flagged entities (${summary.created} created, ${summary.updated} updated).`);
    logger.info(`[seed] FlaggedEntity seed complete: ${summary.created} created, ${summary.updated} updated.`);
  } finally {
    if (!dryRun) await disconnectDatabase({ force: true });
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error('✖ Seed failed:', error.message);
    process.exit(1);
  });
}

module.exports = { FLAGGED_ENTITIES, validateDataset, seedFlaggedEntities, main };
