'use strict';

/**
 * GuardFi — flagged entity model (Phase 6, Shield Pay)
 *
 * The community blocklist behind `POST /api/v1/shield-pay/check-upi`. One
 * document per reported UPI ID, phishing URL or fraud phone number.
 *
 * Spec fields: identifier (UPI ID or domain/link, lowercase, trimmed, UNIQUE
 * B-tree index for O(1) lookup), type (UPI | URL | PHONE), riskLevel
 * (SAFE | SUSPICIOUS | DANGER), reportCount, reason_en, reason_hi.
 *
 * Why `identifier` is the whole point of this model:
 *   • every lookup is an equality match on one string, so the unique index turns
 *     a "is this payee a known scam?" question into a single IXSCAN — with the
 *     seed list this stays under a millisecond even on a shared Atlas cluster;
 *   • the unique constraint means a second report for the same identifier must
 *     UPDATE the existing document (see `upsertReport`), never create a rival
 *     row that two admin screens would then disagree about.
 *
 * Normalisation rules (enforced here AND in the service, defence in depth):
 *   • lowercase + trim. UPI VPAs and hostnames are case-insensitive, so
 *     "PAYTM-KYC-HELP@YBL" and "paytm-kyc-help@ybl" must be the same entity —
 *     otherwise a scammer defeats the blocklist with Caps Lock.
 *   • a `upi://pay?pa=…` QR payload is reduced to its bare VPA by the service,
 *     because that is what the user actually pays to.
 *   • a URL keeps its host+path but loses the scheme, "www." and any query
 *     string (query params are per-campaign junk and would break matching).
 *
 * `reason_hi` is required for curated rows: the whole feature is a bilingual
 * warning, and an English-only entry would silently show English to a Hindi
 * user at the exact moment they are about to send money. The message builder
 * still falls back EN → HI if an older row predates this rule.
 */

const mongoose = require('mongoose');

const ENTITY_TYPES = Object.freeze({ UPI: 'UPI', URL: 'URL', PHONE: 'PHONE' });
const RISK_LEVELS = Object.freeze({ SAFE: 'SAFE', SUSPICIOUS: 'SUSPICIOUS', DANGER: 'DANGER' });

/** Reject control characters, whitespace and the empty string. */
const IDENTIFIER_REGEX = /^[^\s\u0000-\u001F\u007F]{1,200}$/;

const flaggedEntitySchema = new mongoose.Schema(
  {
    identifier: {
      type: String,
      required: [true, 'identifier is required'],
      trim: true,
      lowercase: true,
      maxlength: [200, 'identifier cannot exceed 200 characters'],
      validate: {
        validator: (value) => typeof value === 'string' && IDENTIFIER_REGEX.test(value),
        message: 'identifier cannot contain spaces or control characters',
      },
    },

    type: {
      type: String,
      required: [true, 'type is required'],
      enum: {
        values: Object.values(ENTITY_TYPES),
        message: 'type must be UPI, URL or PHONE',
      },
    },

    riskLevel: {
      type: String,
      required: [true, 'riskLevel is required'],
      enum: {
        values: Object.values(RISK_LEVELS),
        message: 'riskLevel must be SAFE, SUSPICIOUS or DANGER',
      },
    },

    /** How many independent reports support this verdict. Drives riskScore. */
    reportCount: {
      type: Number,
      default: 0,
      min: [0, 'reportCount cannot be negative'],
      validate: {
        validator: (value) => Number.isInteger(value),
        message: 'reportCount must be a whole number',
      },
    },

    reason_en: {
      type: String,
      required: [true, 'reason_en is required'],
      trim: true,
      maxlength: [280, 'reason_en cannot exceed 280 characters'],
    },

    reason_hi: {
      type: String,
      required: [true, 'reason_hi is required'],
      trim: true,
      maxlength: [280, 'reason_hi cannot exceed 280 characters'],
    },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

// THE lookup index. A unique B-tree on one string field: every check-upi call
// is one equality seek (or a 2-element $in for a URL + its bare host), and the
// uniqueness guarantees the blocklist can never hold two verdicts for the same
// identifier. No other index exists on purpose — nothing else is ever queried,
// and every extra index is paid for on every write.
flaggedEntitySchema.index({ identifier: 1 }, { unique: true, name: 'unique_identifier' });

/**
 * Canonical stored form of an identifier. The schema options already do this on
 * write; the service calls it explicitly so its lookup candidates are built with
 * exactly the same rule the database applied.
 *
 * @param {unknown} value
 * @returns {string} lowercase, trimmed, whitespace-free identifier
 */
flaggedEntitySchema.statics.normalize = function normalize(value) {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '');
};

/**
 * Create or refresh one curated blocklist entry.
 *
 * Used by the seed script and by any future report-resolution flow. `$set`
 * (rather than `$setOnInsert`) is deliberate: re-running the seed must update a
 * verdict that changed, and a back-office action must be able to raise or clear
 * one — while the unique index keeps this to a single row per identifier.
 *
 * @param {{ identifier: string, type: string, riskLevel: string, reportCount?: number, reason_en: string, reason_hi: string }} entry
 * @returns {Promise<{ doc: import('mongoose').HydratedDocument<any>, created: boolean }>}
 */
flaggedEntitySchema.statics.upsertReport = async function upsertReport(entry) {
  const identifier = this.normalize(entry.identifier);

  const existing = await this.findOne({ identifier }).select('_id').lean();

  const doc = await this.findOneAndUpdate(
    { identifier },
    {
      $set: {
        type: entry.type,
        riskLevel: entry.riskLevel,
        reportCount: Math.max(0, Number(entry.reportCount) || 0),
        reason_en: entry.reason_en,
        reason_hi: entry.reason_hi,
      },
      $setOnInsert: { identifier },
    },
    { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true, runValidators: true }
  );

  return { doc, created: !existing };
};

module.exports = mongoose.model('FlaggedEntity', flaggedEntitySchema);
module.exports.ENTITY_TYPES = ENTITY_TYPES;
module.exports.RISK_LEVELS = RISK_LEVELS;
