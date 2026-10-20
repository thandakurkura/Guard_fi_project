'use strict';

/**
 * GuardFi — immutable audit trail (Phase 8)
 *
 * One append-only document per security-relevant event in the emergency flow:
 * a biometric bypass, an emergency-mode unlock or lock, a restricted action
 * performed while emergency mode was active, and a rejected biometric
 * assertion.
 *
 * WHY THIS FILE IS DEFENSIVE AT THE MODEL LAYER
 * An audit trail that can be edited is not an audit trail — it is a suggestion.
 * A compromised admin session, a careless `findOneAndUpdate` in a future
 * controller, or a hotfix script would otherwise be able to rewrite history.
 * So updates and deletes are refused by Mongoose middleware, not by convention:
 *
 *   Model.updateOne / updateMany / replaceOne / findOneAndUpdate /
 *   findOneAndReplace / findOneAndDelete / deleteOne / deleteMany   → throw
 *   document.save() on a stored row (i.e. not a first insert)       → throw
 *   document.deleteOne()                                            → throw
 *   Model.bulkWrite()                                               → throw
 *
 * The guards make tampering loud and local. They are NOT a substitute for
 * database-level permissions in production (a driver-level `collection.updateOne`
 * bypasses Mongoose entirely); the Phase 10 deployment checklist should run the
 * API with a role that cannot update or delete this collection.
 *
 * Spec fields: userId, action, ipAddress, userAgent, deviceMetadata, createdAt.
 * Additions this phase needs are commented where they appear:
 *   • assertionNonce — single-use guard for a signed biometric result. The
 *     unique partial index ({ userId, assertionNonce }) turns an HMAC replay
 *     into a duplicate-key error instead of a second emergency unlock.
 *   • details — the bounded, human-readable context of the event (requested
 *     restricted action, rejection reason, optional note).
 */

const mongoose = require('mongoose');

const AUDIT_ACTIONS = Object.freeze({
  /** The assertion was accepted and the account was not in emergency mode. */
  EMERGENCY_MODE_UNLOCKED: 'EMERGENCY_MODE_UNLOCKED',
  /** Biometric proof was accepted while emergency mode was already active. */
  BIOMETRIC_BYPASS_TRIGGERED: 'BIOMETRIC_BYPASS_TRIGGERED',
  /** The user returned to the normal, locked state. */
  EMERGENCY_MODE_LOCKED: 'EMERGENCY_MODE_LOCKED',
  /** A route guarded by requireEmergencyMode actually did its job. */
  RESTRICTED_ACTION_PERFORMED: 'RESTRICTED_ACTION_PERFORMED',
  /** A signed assertion was refused: bad signature, stale timestamp or success=false. */
  BIOMETRIC_VERIFICATION_FAILED: 'BIOMETRIC_VERIFICATION_FAILED',
  /** An admin changed the global app configuration (Phase 9). */
  CONFIG_UPDATED: 'CONFIG_UPDATED',
  /**
   * The account and all of its personal data were deleted. This row is written
   * LAST and deliberately OUTLIVES every cascade: it is the only remaining
   * record that the deletion happened, and it is append-only like the rest.
   */
  ACCOUNT_DELETED: 'ACCOUNT_DELETED',
});

const ACTION_VALUES = Object.freeze(Object.values(AUDIT_ACTIONS));

const DEVICE_PLATFORMS = Object.freeze(['android', 'ios', 'web', 'unknown']);

/** Device details are informational — bound every string so a header cannot bloat a row. */
const deviceMetadataSchema = new mongoose.Schema(
  {
    deviceId: { type: String, trim: true, maxlength: 128, default: null },
    platform: {
      type: String,
      enum: { values: DEVICE_PLATFORMS, message: 'deviceMetadata.platform must be android, ios, web or unknown' },
      default: 'unknown',
    },
    appVersion: { type: String, trim: true, maxlength: 32, default: null },
    model: { type: String, trim: true, maxlength: 80, default: null },
    osVersion: { type: String, trim: true, maxlength: 32, default: null },
    /** True only when a verified biometric assertion backed this event. */
    biometricVerified: { type: Boolean, default: false },
  },
  { _id: false, versionKey: false }
);

const detailsSchema = new mongoose.Schema(
  {
    /** The restricted action name, for RESTRICTED_ACTION_PERFORMED rows. */
    requestedAction: { type: String, trim: true, maxlength: 80, default: null },
    /** Machine-readable reason for a BIOMETRIC_VERIFICATION_FAILED row. */
    reason: { type: String, trim: true, maxlength: 120, default: null },
    note: { type: String, trim: true, maxlength: 280, default: null },
  },
  { _id: false, versionKey: false }
);

const auditLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'userId is required'],
    },

    action: {
      type: String,
      required: [true, 'action is required'],
      enum: { values: ACTION_VALUES, message: 'action must be one of: ' + ACTION_VALUES.join(', ') },
    },

    /** `req.ip` with Express trust-proxy applied, or null when unavailable. */
    ipAddress: { type: String, trim: true, maxlength: 45, default: null },

    /** Raw User-Agent, truncated by the service. Never a cookie or a token. */
    userAgent: { type: String, trim: true, maxlength: 512, default: null },

    deviceMetadata: { type: deviceMetadataSchema, default: () => ({}) },

    /**
     * Nonce from the signed biometric assertion. Set only on rows whose nonce
     * came from a signature-valid assertion, and unique per user, so the same
     * signed result can never be recorded — or acted on — twice.
     */
    assertionNonce: { type: String, trim: true, maxlength: 128, default: null },

    details: { type: detailsSchema, default: () => ({}) },
  },
  {
    // createdAt only: there is no legitimate "updatedAt" for an immutable row.
    timestamps: { createdAt: true, updatedAt: false },
    versionKey: false,
    // Reject unknown fields instead of silently dropping them, so a caller that
    // typos `ipAdress` finds out here rather than in an incident review.
    strict: 'throw',
    minimize: false,
  }
);

// The hot query: "this user's emergency history, newest first".
auditLogSchema.index({ userId: 1, createdAt: -1 });
// Compliance query: "every unlock in the last 24 hours".
auditLogSchema.index({ action: 1, createdAt: -1 });
// Replay guard. Partial, so the many rows without a nonce do not collide on null.
auditLogSchema.index(
  { userId: 1, assertionNonce: 1 },
  {
    unique: true,
    partialFilterExpression: { assertionNonce: { $type: 'string' } },
    name: 'unique_user_assertion_nonce',
  }
);

/** Error thrown by every tamper attempt. `code` lets callers/tests assert precisely. */
function immutableError(operation) {
  const error = new Error(
    `AuditLog is append-only: ${operation} is not permitted. Audit records cannot be modified or deleted.`
  );
  error.name = 'AuditLogImmutableError';
  error.code = 'AUDIT_LOG_IMMUTABLE';
  error.statusCode = 405;
  return error;
}

// --- Query middleware: the Mongoose entry points that rewrite or remove rows --
for (const operation of [
  'updateOne',
  'updateMany',
  'replaceOne',
  'findOneAndUpdate',
  'findOneAndReplace',
  'deleteOne',
  'deleteMany',
  'findOneAndDelete',
]) {
  auditLogSchema.pre(operation, function blockAuditMutation() {
    throw immutableError(operation);
  });
}

// --- Document middleware: a hydrated row cannot be saved or deleted -----------
auditLogSchema.pre('save', function blockAuditSave() {
  if (this.isNew) return;
  throw immutableError('save');
});

auditLogSchema.pre('deleteOne', { document: true, query: false }, function blockAuditDocumentDelete() {
  throw immutableError('deleteOne');
});

/**
 * `bulkWrite` can carry update/delete operations and does not run the query
 * middleware above. Refuse it wholesale; inserts have `insertMany`.
 */
auditLogSchema.statics.bulkWrite = function blockAuditBulkWrite() {
  throw immutableError('bulkWrite');
};

/**
 * The only supported write path.
 * @param {object} entry
 * @returns {Promise<import('mongoose').HydratedDocument<any>>}
 */
auditLogSchema.statics.record = function record(entry) {
  return this.create(entry);
};

module.exports = mongoose.model('AuditLog', auditLogSchema);
module.exports.AUDIT_ACTIONS = AUDIT_ACTIONS;
module.exports.ACTION_VALUES = ACTION_VALUES;
module.exports.DEVICE_PLATFORMS = DEVICE_PLATFORMS;
module.exports.immutableError = immutableError;
