'use strict';

/**
 * GuardFi — transaction audit model (Phase 6, Shield Pay)
 *
 * One document per Shield Pay event. Two shapes live here on purpose, because
 * they are two moments of the same story and must share an identity:
 *
 *   PENDING   — created by /check-upi the moment a payee is rated SUSPICIOUS or
 *               DANGER. It is the SERVER-SIDE STATE behind "Proceed Anyway": the
 *               client cannot talk its way past a warning without presenting the
 *               _id of a check this user really ran, for this payee, recently.
 *   COMPLETED — the decision itself: a safe payment, or a payment made after
 *               explicitly accepting the warning (risk_accepted = true). This
 *               is the row a dispute or a police complaint reads.
 *   REJECTED  — a credential failure that was still worth recording: a wrong
 *               Shield Pay PIN (failureReason = INVALID_PIN). Repeated rejections
 *               on one account are the classic signature of a stolen phone with
 *               someone guessing the PIN, and they must not be invisible.
 *
 * Spec fields: userId, upiId, amount, riskLevel, risk_accepted, pinVerified,
 * transactionHash, ipAddress, timestamps. Additions this phase needs are marked
 * in the comments — `status` (the state machine above), `riskScore`,
 * `identifierType`, `expiresAt` and `failureReason`. `upiId` keeps the spec's
 * name even when the payee is a URL or a phone number: it is "the identifier the
 * user is paying", and renaming it would break the spec's contract.
 *
 * Invariants enforced by the database, not by hope:
 *   • a real transactionHash is unique (partial index) — one hash, one row, so a
 *     duplicated audit trail is impossible even under a retried request;
 *   • a PENDING check deletes itself when it expires (partial TTL index). The
 *     service ALSO enforces expiry in application code, because the TTL monitor
 *     only sweeps about once a minute and a state token must not outlive its
 *     window even briefly;
 *   • the PENDING → COMPLETED transition is a single atomic `findOneAndUpdate`
 *     guarded by `status: PENDING` + `expiresAt > now` + the same payee, which is
 *     what makes "Proceed Anyway" single-use: two simultaneous taps produce one
 *     COMPLETED row and one clean 409, never two payments.
 */

const crypto = require('node:crypto');
const mongoose = require('mongoose');
const { ENTITY_TYPES, RISK_LEVELS } = require('./FlaggedEntity');

const STATUSES = Object.freeze({ PENDING: 'PENDING', COMPLETED: 'COMPLETED', REJECTED: 'REJECTED' });
const FAILURE_REASONS = Object.freeze({ INVALID_PIN: 'INVALID_PIN' });

/** 32 random bytes as hex — the only transaction id format this API ever returns. */
const TRANSACTION_HASH_REGEX = /^[0-9a-f]{64}$/;

const transactionAuditSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'userId is required'],
    },

    /** Normalised payee identifier (UPI ID, URL or phone — see the model comment). */
    upiId: {
      type: String,
      required: [true, 'upiId is required'],
      trim: true,
      lowercase: true,
      maxlength: [200, 'upiId cannot exceed 200 characters'],
    },

    identifierType: {
      type: String,
      enum: { values: Object.values(ENTITY_TYPES), message: 'identifierType must be UPI, URL or PHONE' },
      default: ENTITY_TYPES.UPI,
    },

    /** Null on PENDING and REJECTED rows: no amount was ever settled. */
    amount: {
      type: Number,
      default: null,
      min: [0, 'amount cannot be negative'],
      // Absolute backstop. The endpoint enforces the (configurable) real cap.
      max: [10_000_000, 'amount exceeds the absolute limit'],
      set: (value) => (value === null || value === undefined ? null : Math.round(value * 100) / 100),
    },

    riskLevel: {
      type: String,
      required: [true, 'riskLevel is required'],
      enum: { values: Object.values(RISK_LEVELS), message: 'riskLevel must be SAFE, SUSPICIOUS or DANGER' },
    },

    /** 0-100 verdict score, kept alongside the coarse level for analytics. */
    riskScore: {
      type: Number,
      default: 0,
      min: [0, 'riskScore cannot be negative'],
      max: [100, 'riskScore cannot exceed 100'],
    },

    status: {
      type: String,
      required: true,
      enum: { values: Object.values(STATUSES), message: 'status must be PENDING, COMPLETED or REJECTED' },
      default: STATUSES.COMPLETED,
    },

    /** True only when the user was warned and pressed "Proceed Anyway". */
    risk_accepted: {
      type: Boolean,
      default: false,
    },

    pinVerified: {
      type: Boolean,
      default: false,
    },

    transactionHash: {
      type: String,
      default: null,
      validate: {
        validator: (value) => value === null || value === undefined || TRANSACTION_HASH_REGEX.test(value),
        message: 'transactionHash must be 64 lowercase hex characters',
      },
    },

    /** Only set on REJECTED rows (e.g. INVALID_PIN). */
    failureReason: {
      type: String,
      default: null,
      maxlength: [40, 'failureReason cannot exceed 40 characters'],
    },

    ipAddress: {
      type: String,
      default: null,
      trim: true,
      maxlength: [45, 'ipAddress cannot exceed 45 characters'],
    },

    /** Set on PENDING rows only; cleared when the check is consumed. */
    expiresAt: {
      type: Date,
      default: null,
    },

    completedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

// The account's own trail ("what did I pay, and what did I wave through?").
transactionAuditSchema.index({ userId: 1, createdAt: -1 }, { name: 'user_history' });

// One hash, one row. Partial so the many null values on PENDING/REJECTED rows
// do not collide with each other (a plain unique index would allow exactly one
// null, which this schema produces constantly).
transactionAuditSchema.index(
  { transactionHash: 1 },
  {
    unique: true,
    name: 'unique_transaction_hash',
    partialFilterExpression: { transactionHash: { $type: 'string' } },
  }
);

// An unanswered warning is state, not history: delete it when it expires.
// Partial again, or the TTL would eventually delete completed audit rows too —
// the one thing an audit log must never do.
transactionAuditSchema.index(
  { expiresAt: 1 },
  {
    name: 'pending_risk_check_ttl',
    expireAfterSeconds: 0,
    partialFilterExpression: { status: STATUSES.PENDING },
  }
);

/** A 64-hex transaction id. Random, so it leaks nothing about the payment. */
transactionAuditSchema.statics.generateTransactionHash = function generateTransactionHash() {
  return crypto.randomBytes(32).toString('hex');
};

/** True once a pending check is past its window, regardless of the TTL sweeper. */
transactionAuditSchema.methods.isExpired = function isExpired(now = Date.now()) {
  if (this.status !== STATUSES.PENDING) return false;
  if (!this.expiresAt) return true;
  const expiresMs = this.expiresAt instanceof Date ? this.expiresAt.getTime() : Date.parse(this.expiresAt);
  if (!Number.isFinite(expiresMs)) return true;
  return expiresMs <= now;
};

/**
 * Record the server-side state behind a warning.
 *
 * @param {{ userId: unknown, upiId: string, identifierType: string, riskLevel: string, riskScore: number, ttlSeconds: number, ipAddress?: string|null }} params
 */
transactionAuditSchema.statics.createPendingCheck = function createPendingCheck(params) {
  return this.create({
    userId: params.userId,
    upiId: params.upiId,
    identifierType: params.identifierType,
    riskLevel: params.riskLevel,
    riskScore: params.riskScore,
    status: STATUSES.PENDING,
    risk_accepted: false,
    pinVerified: false,
    amount: null,
    transactionHash: null,
    ipAddress: params.ipAddress ?? null,
    expiresAt: new Date(Date.now() + params.ttlSeconds * 1000),
  });
};

/** A completed payment with no warning involved. */
transactionAuditSchema.statics.createCompletedTransaction = function createCompletedTransaction(params) {
  return this.create({
    userId: params.userId,
    upiId: params.upiId,
    identifierType: params.identifierType,
    riskLevel: params.riskLevel,
    riskScore: params.riskScore,
    status: STATUSES.COMPLETED,
    risk_accepted: params.riskAccepted === true,
    pinVerified: true,
    amount: params.amount,
    transactionHash: params.transactionHash || this.generateTransactionHash(),
    ipAddress: params.ipAddress ?? null,
    completedAt: new Date(),
  });
};

/** A credential failure worth remembering (wrong PIN). */
transactionAuditSchema.statics.createRejectedAttempt = function createRejectedAttempt(params) {
  return this.create({
    userId: params.userId,
    upiId: params.upiId,
    identifierType: params.identifierType,
    riskLevel: params.riskLevel,
    riskScore: params.riskScore,
    status: STATUSES.REJECTED,
    risk_accepted: params.riskAccepted === true,
    pinVerified: false,
    amount: params.amount ?? null,
    transactionHash: null,
    failureReason: params.failureReason || FAILURE_REASONS.INVALID_PIN,
    ipAddress: params.ipAddress ?? null,
  });
};

/**
 * Atomically turn a pending risk check into a completed transaction.
 *
 * Every condition of the "Proceed Anyway" contract is in the FILTER, so a
 * racing request or a replayed one simply matches nothing:
 *   _id + userId → the check belongs to this caller (no IDOR);
 *   upiId        → the check was run for the payee actually being paid;
 *   status       → single use (a consumed check can never be consumed again);
 *   expiresAt    → the user cannot accept a 20-minute-old warning as if the
 *                  payee were just re-checked.
 *
 * @returns {Promise<object|null>} the completed row, or null when the check is
 *   missing, foreign, used, expired or for a different payee.
 */
transactionAuditSchema.statics.consumePendingCheck = function consumePendingCheck(params) {
  const now = new Date();

  return this.findOneAndUpdate(
    {
      _id: params.checkId,
      userId: params.userId,
      upiId: params.upiId,
      status: STATUSES.PENDING,
      expiresAt: { $gt: now },
    },
    {
      $set: {
        status: STATUSES.COMPLETED,
        risk_accepted: true,
        pinVerified: true,
        amount: params.amount,
        transactionHash: params.transactionHash || this.generateTransactionHash(),
        ipAddress: params.ipAddress ?? null,
        completedAt: now,
        expiresAt: null,
      },
    },
    { returnDocument: 'after' }
  );
};

module.exports = mongoose.model('TransactionAudit', transactionAuditSchema);
module.exports.STATUSES = STATUSES;
module.exports.FAILURE_REASONS = FAILURE_REASONS;
module.exports.TRANSACTION_HASH_REGEX = TRANSACTION_HASH_REGEX;
