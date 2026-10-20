'use strict';

/**
 * GuardFi — Nominee/guardian model (Phase 3)
 *
 * A nominee is the person who gets alerted when the account owner triggers an
 * SOS. They are deliberately NOT a User reference: the whole point of a
 * guardian is that they may not have the app installed, so the relationship is
 * keyed on their phone number and an optional push token.
 *
 * Spec fields: userId (ObjectId ref User, indexed), name, phone, relation,
 * fcmToken (optional), isPrimary (Boolean), with a compound unique index on
 * { userId, phone } so the same guardian cannot be added twice by one user.
 *
 * Invariants this model enforces:
 *   • one primary guardian per user, enforced by the database (partial unique
 *     index below), not only by service code — two simultaneous "make this
 *     primary" requests can never leave a user with two primaries.
 *   • the guardian's push token is stored but never read back by default
 *     (`select: false` plus the JSON transform), exactly like User.fcmToken.
 *     Any query using `.lean()` MUST add `.select('-fcmToken')`, because lean
 *     documents skip the transform.
 */

const mongoose = require('mongoose');

/** E.164: a leading +, a non-zero country code, 8-15 digits in total. */
const E164_REGEX = /^\+[1-9]\d{7,14}$/;

/** Never serialise the guardian's push token. */
function stripSensitiveFields(doc, ret) {
  delete ret.fcmToken;
  delete ret.__v;
  return ret;
}

const nomineeSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'userId is required'],
      // No field-level `index: true`: userId is the prefix of the compound
      // unique index below, so MongoDB already indexes every userId lookup.
    },

    name: {
      type: String,
      required: [true, 'name is required'],
      trim: true,
      maxlength: [80, 'name cannot exceed 80 characters'],
    },

    phone: {
      type: String,
      required: [true, 'phone is required'],
      trim: true,
      match: [E164_REGEX, 'phone must be a valid E.164 number, e.g. +919876543210'],
    },

    relation: {
      type: String,
      trim: true,
      maxlength: [40, 'relation cannot exceed 40 characters'],
      default: null,
    },

    /** Only set when the guardian also has the app installed (Phase 4 sends with it). */
    fcmToken: {
      type: String,
      trim: true,
      default: null,
      select: false,
    },

    isPrimary: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
    versionKey: false,
    toJSON: { transform: stripSensitiveFields, virtuals: false },
    toObject: { transform: stripSensitiveFields, virtuals: false },
  }
);

// The compound index is both the duplicate guard and the userId lookup index,
// because userId is its prefix — no separate { userId: 1 } index is needed.
nomineeSchema.index({ userId: 1, phone: 1 }, { unique: true });

// ONE primary guardian per user, guaranteed by MongoDB itself. A unique partial
// index only covers documents where isPrimary is true, so the five non-primary
// nominees are unaffected while a second primary becomes an E11000 the service
// layer can translate into a clean 409. Without this, two concurrent requests
// (or a retry race) could leave two "primary" guardians and break the client's
// assumption that exactly one name is highlighted.
nomineeSchema.index(
  { userId: 1 },
  { unique: true, partialFilterExpression: { isPrimary: true }, name: 'one_primary_nominee_per_user' }
);

/**
 * Demote whichever nominee currently holds the primary flag, excluding the one
 * about to be promoted (so the caller can set the flag afterwards).
 *
 * @param {import('mongoose').Types.ObjectId|string} userId
 * @param {import('mongoose').Types.ObjectId|string} nomineeId
 */
nomineeSchema.statics.claimPrimary = async function claimPrimary(userId, nomineeId) {
  await this.updateMany(
    { userId, _id: { $ne: nomineeId }, isPrimary: true },
    { $set: { isPrimary: false } }
  );
};

/** @param {import('mongoose').Types.ObjectId|string} userId */
nomineeSchema.statics.countForUser = function countForUser(userId) {
  return this.countDocuments({ userId });
};

module.exports = mongoose.model('Nominee', nomineeSchema);
module.exports.E164_REGEX = E164_REGEX;
