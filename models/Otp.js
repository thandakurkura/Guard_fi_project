'use strict';

/**
 * GuardFi — OTP model (Phase 2)
 *
 * One live verification code per phone number. The code itself is NEVER stored:
 * only a bcrypt hash, so a leaked database dump (or a curious teammate with
 * Atlas access) cannot read live OTPs.
 *
 * The per-phone SEND budget deliberately does NOT live here: this document
 * deletes itself after OTP_TTL_SECONDS, so a counter kept on it would silently
 * reset every few minutes. See models/SendThrottle.js.
 *
 * Spec fields: phone (indexed), otpHash (hashed), attempts (max 3 to block
 * brute force), createdAt with a MongoDB TTL index (expires after
 * OTP_TTL_SECONDS, default 300 s) so expired codes delete themselves.
 *
 * Two deliberate details:
 *   • `otpHash` is `select: false` — verification asks for it explicitly with
 *     `.select('+otpHash')`, nothing else can read it.
 *   • The TTL monitor only sweeps about once a minute, so expiry is ALSO
 *     enforced in application code (`isExpired()`); an OTP is never valid just
 *     because the background deleter has not run yet.
 *
 * Operational note: `expires` is baked into the index at creation time. If you
 * change OTP_TTL_SECONDS you must let Mongoose rebuild the index (in
 * development it does so on boot) or drop `createdAt_1` manually — MongoDB will
 * not alter expireAfterSeconds on an existing index.
 */

const mongoose = require('mongoose');
const { config } = require('../config/env');

/** E.164: a leading +, a non-zero country code, 8-15 digits in total. */
const E164_REGEX = /^\+[1-9]\d{7,14}$/;

const otpSchema = new mongoose.Schema(
  {
    phone: {
      type: String,
      required: [true, 'phone is required'],
      unique: true,
      trim: true,
      match: [E164_REGEX, 'phone must be a valid E.164 number, e.g. +919876543210'],
    },

    otpHash: {
      type: String,
      required: [true, 'otpHash is required'],
      select: false,
    },

    /** Failed verification attempts for the current code. Reset by a resend. */
    attempts: {
      type: Number,
      default: 0,
      min: [0, 'attempts cannot be negative'],
    },

    lastAttemptAt: {
      type: Date,
      default: null,
    },

    /**
     * Stamped fresh on every resend so the TTL window starts when the user
     * receives the newest code. Declared before the TTL index below.
     */
    createdAt: {
      type: Date,
      default: Date.now,
      expires: config.otp.ttlSeconds,
    },
  },
  {
    versionKey: false,
    // No timestamps: `createdAt` IS the TTL clock and must stay writable, while
    // an auto-managed `updatedAt` would fight the atomic $inc on attempts.
    timestamps: false,
  }
);

/** True once the code is past its lifetime, regardless of the TTL sweeper. */
otpSchema.methods.isExpired = function isExpired(now = Date.now()) {
  const createdAtMs = this.createdAt instanceof Date ? this.createdAt.getTime() : Date.parse(this.createdAt);
  if (!Number.isFinite(createdAtMs)) return true;
  return now - createdAtMs >= config.otp.ttlSeconds * 1000;
};

/** Seconds the caller must wait before this code is dead. */
otpSchema.methods.secondsUntilExpiry = function secondsUntilExpiry(now = Date.now()) {
  const createdAtMs = this.createdAt instanceof Date ? this.createdAt.getTime() : Date.parse(this.createdAt);
  if (!Number.isFinite(createdAtMs)) return 0;
  return Math.max(0, Math.ceil((createdAtMs + config.otp.ttlSeconds * 1000 - now) / 1000));
};

/**
 * Atomically store a new code for `phone`, replacing any previous one and
 * resetting the attempt counter. Atomic on purpose: two concurrent /send-otp
 * calls must not be able to leave two valid codes for the same number.
 *
 * `createdAt` is restamped on every call, which restarts both the TTL window and
 * the resend cooldown — see the note above about why the send budget is not here.
 *
 * @param {string} phone normalised E.164 number
 * @param {string} otpHash bcrypt hash of the new code
 * @returns {Promise<import('mongoose').HydratedDocument<any>>}
 */
otpSchema.statics.upsertForPhone = async function upsertForPhone(phone, otpHash) {
  const now = new Date();

  const doc = await this.findOneAndUpdate(
    { phone },
    {
      $set: { otpHash, attempts: 0, lastAttemptAt: null, createdAt: now },
      $setOnInsert: { phone },
    },
    { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
  );

  return doc;
};

/**
 * Record one failed attempt without ever exceeding the cap. The `attempts < max`
 * filter makes this race-safe: a burst of parallel guesses cannot push the
 * counter past the limit, and the caller learns it is locked because the update
 * matched nothing.
 *
 * @returns {Promise<{ attempts: number, locked: boolean }>}
 */
otpSchema.statics.registerFailedAttempt = async function registerFailedAttempt(id) {
  const updated = await this.findOneAndUpdate(
    { _id: id, attempts: { $lt: config.otp.maxAttempts } },
    { $inc: { attempts: 1 }, $set: { lastAttemptAt: new Date() } },
    { returnDocument: 'after' }
  );

  if (!updated) return { attempts: config.otp.maxAttempts, locked: true };
  return { attempts: updated.attempts, locked: updated.attempts >= config.otp.maxAttempts };
};

module.exports = mongoose.model('Otp', otpSchema);
