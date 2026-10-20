'use strict';

/**
 * GuardFi — User model (Phase 2)
 *
 * One document per phone number. The account is created lazily on the first
 * successful OTP verification (`POST /api/v1/auth/verify-otp`), so this model
 * deliberately knows nothing about passwords: identity is the phone number.
 *
 * Spec fields: phone (unique, indexed, E.164 validated), name, fcmToken,
 * securityPinHash (bcrypt, for Shield Pay), isEmergencyMode, lastKnownLocation
 * (GeoJSON Point with a 2dsphere index), timestamps.
 *
 * Security rules baked in here:
 *   • `securityPinHash` and `fcmToken` are `select: false`, so no query returns
 *     them unless it explicitly asks — and the JSON transform strips them even
 *     then, so a hash can never leak through a controller response.
 *   • `phone` is normalised to E.164 upstream (utils/phone.js) and enforced here
 *     as a second line of defence, so two spellings can never create two users.
 */

const mongoose = require('mongoose');

/** E.164: a leading +, a non-zero country code, 8-15 digits in total. */
const E164_REGEX = /^\+[1-9]\d{7,14}$/;

// --- GeoJSON Point ----------------------------------------------------------
// Defined as its own schema with `_id: false` so the stored document is exactly
// `{ type: 'Point', coordinates: [lng, lat] }` — a 2dsphere index rejects
// anything else, and `default: undefined` keeps the field absent until a real
// location arrives (an index built over `{ type: 'Point' }` with no coordinates
// would fail to extract geo keys).
const pointSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: { values: ['Point'], message: 'lastKnownLocation.type must be "Point"' },
      required: [true, 'lastKnownLocation.type is required'],
      default: 'Point',
    },
    coordinates: {
      type: [Number],
      required: [true, 'lastKnownLocation.coordinates is required'],
      validate: [
        {
          validator: (value) => Array.isArray(value) && value.length === 2,
          message: 'lastKnownLocation.coordinates must be exactly [longitude, latitude]',
        },
        {
          validator: (value) => {
            if (!Array.isArray(value) || value.length !== 2) return true; // the length rule already reported
            const [longitude, latitude] = value;
            return (
              Number.isFinite(longitude) &&
              Number.isFinite(latitude) &&
              longitude >= -180 &&
              longitude <= 180 &&
              latitude >= -90 &&
              latitude <= 90
            );
          },
          message: 'longitude must be between -180 and 180 and latitude between -90 and 90',
        },
      ],
    },
  },
  { _id: false, versionKey: false }
);

/** Never serialise secrets, whatever query selected them. */
function stripSensitiveFields(doc, ret) {
  delete ret.securityPinHash;
  delete ret.fcmToken;
  delete ret.__v;
  return ret;
}

const userSchema = new mongoose.Schema(
  {
    phone: {
      type: String,
      required: [true, 'phone is required'],
      unique: true,
      trim: true,
      match: [E164_REGEX, 'phone must be a valid E.164 number, e.g. +919876543210'],
    },

    name: {
      type: String,
      trim: true,
      maxlength: [80, 'name cannot exceed 80 characters'],
      default: null,
    },

    /** FCM registration token, replaced on every successful sign-in (Phase 4 sends with it). */
    fcmToken: {
      type: String,
      trim: true,
      default: null,
      select: false,
    },

    /** bcrypt hash of the Shield Pay PIN (Phase 6). Never the PIN itself. */
    securityPinHash: {
      type: String,
      default: null,
      select: false,
    },

    /**
     * Role used by rbacMiddleware.requireRoles(). Not in the Phase 2 field list
     * of the master spec, added deliberately because Phase 1 already ships a
     * role check and Phase 9 needs an admin-only PUT /config/global.
     */
    role: {
      type: String,
      enum: { values: ['user', 'admin'], message: 'role must be either "user" or "admin"' },
      default: 'user',
    },

    /** Server-authoritative emergency flag. rbacMiddleware reads it from here, never from the token. */
    isEmergencyMode: {
      type: Boolean,
      default: false,
    },

    /**
     * Whether this device completed local biometric enrolment. Phase 8 flips it
     * after a verified signed result; the Phase 5 readiness score reads it as one
     * component. Default false — declaring a capability the device never proved
     * would inflate the safety score.
     */
    biometricEnabled: {
      type: Boolean,
      default: false,
    },

    /**
     * When emergency mode was last unlocked (Phase 8). Null while inactive —
     * the lock path clears it, so a stale timestamp can never make an inactive
     * account look like it is still in an emergency.
     */
    emergencyActivatedAt: {
      type: Date,
      default: null,
    },

    lastKnownLocation: {
      type: pointSchema,
      default: undefined,
    },

    lastLoginAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
    versionKey: false,
    minimize: true,
    toJSON: { transform: stripSensitiveFields, virtuals: false },
    toObject: { transform: stripSensitiveFields, virtuals: false },
  }
);

// Handled by `unique: true` on the path, which creates exactly one unique index.
userSchema.index({ lastKnownLocation: '2dsphere' });
// Phase 5 counts users whose perimeter is armed; this keeps that a covered count.
userSchema.index({ isEmergencyMode: 1 });
// Unused-but-deliberate: the dashboard's per-user facet matches `_id` (covered
// by the default index) and looks nominees up by userId (covered by the compound
// prefix in models/Nominee.js), so no extra Phase 5 index is needed here.

/**
 * Find the account for `phone`, or create it, then refresh the mutable profile
 * fields. Safe against two simultaneous verifications of the same number: the
 * unique index rejects the loser, which then re-reads the winner's document.
 *
 * @param {string} phone normalised E.164 number
 * @param {{ name?: string, fcmToken?: string }} [updates]
 * @returns {Promise<{ user: import('mongoose').HydratedDocument<any>, created: boolean }>}
 */
userSchema.statics.findOrCreateByPhone = async function findOrCreateByPhone(phone, updates = {}) {
  const now = new Date();
  const existing = await this.findOne({ phone });

  if (existing) {
    if (updates.name) existing.name = updates.name;
    if (updates.fcmToken) existing.fcmToken = updates.fcmToken;
    existing.lastLoginAt = now;
    await existing.save();
    return { user: existing, created: false };
  }

  try {
    const user = await this.create({
      phone,
      name: updates.name || null,
      fcmToken: updates.fcmToken || null,
      lastLoginAt: now,
    });
    return { user, created: true };
  } catch (error) {
    if (error && error.code === 11_000) {
      // Another request created the same phone between our read and write.
      const raced = await this.findOne({ phone });
      if (raced) {
        if (updates.name) raced.name = updates.name;
        if (updates.fcmToken) raced.fcmToken = updates.fcmToken;
        raced.lastLoginAt = now;
        await raced.save();
        return { user: raced, created: false };
      }
    }
    throw error;
  }
};

module.exports = mongoose.model('User', userSchema);
