'use strict';

/**
 * GuardFi — per-phone SMS send budget (Phase 2)
 *
 * The IP rate limiter alone cannot stop SMS bombing: one attacker with a handful
 * of proxies can keep requesting codes for the same victim number, spending the
 * project's SMS credit and harassing the victim. This collection is the
 * per-NUMBER counter that stops that, independent of where the requests come
 * from.
 *
 * WHY IT IS NOT A FIELD ON THE Otp DOCUMENT (this is a deliberate fix):
 * `otps` documents delete themselves after OTP_TTL_SECONDS (300 s) so expired
 * codes cannot linger. Keeping the send counter there silently tied the counter's
 * lifetime to the code's: ten codes in the first five minutes locked the number
 * out, the document then expired, and the budget started again — so
 * "10 per hour" was really "10 per five minutes", exactly as permissive as the
 * 30-second resend cooldown it was supposed to strengthen. The counter therefore
 * lives in its own document whose TTL is its own window, and it survives the code
 * it was protecting.
 *
 * One document per phone, which also means:
 *   • the count is bounded (no per-request rows),
 *   • the window is explicit (`windowStartedAt` + OTP_SEND_WINDOW_SECONDS),
 *   • the document expires on its own (`expiresAt` TTL), so an hour-long window
 *     does not leave stale rows behind.
 *
 * Operational note: like `expires` on Otp, the TTL index is created by Mongoose
 * when autoIndex is on (development). In production it must already exist —
 * autoIndex is off there on purpose so a schema change cannot lock a collection.
 */

const mongoose = require('mongoose');
const { config } = require('../config/env');

/** E.164: a leading +, a non-zero country code, 8-15 digits in total. */
const E164_REGEX = /^\+[1-9]\d{7,14}$/;

const sendThrottleSchema = new mongoose.Schema(
  {
    phone: {
      type: String,
      required: [true, 'phone is required'],
      unique: true,
      trim: true,
      match: [E164_REGEX, 'phone must be a valid E.164 number, e.g. +919876543210'],
    },

    /** Codes sent inside the current window. Reset when the window lapses. */
    sendCount: {
      type: Number,
      default: 0,
      min: [0, 'sendCount cannot be negative'],
    },

    windowStartedAt: {
      type: Date,
      default: Date.now,
    },

    /**
     * Deliberately stale-past dates are what MongoDB's TTL monitor deletes on, so
     * this is always windowStartedAt + OTP_SEND_WINDOW_SECONDS.
     */
    expiresAt: {
      type: Date,
      required: [true, 'expiresAt is required'],
      default: Date.now,
    },
  },
  { versionKey: false, timestamps: false }
);

// expireAfterSeconds: 0 → delete the document once `expiresAt` is in the past.
sendThrottleSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

/**
 * Read the current window for `phone` without writing anything.
 *
 * A lapsed window reports itself as empty (count 0, no start), so the caller does
 * not have to know the window arithmetic — and cannot get it wrong.
 *
 * @param {string} phone normalised E.164 number
 * @param {Date} [now]
 * @returns {Promise<{ sendCount: number, windowStartedAt: Date|null, windowExpiresAt: Date|null, windowActive: boolean }>}
 */
sendThrottleSchema.statics.readWindow = async function readWindow(phone, now = new Date()) {
  const windowMs = config.otp.sendWindowSeconds * 1000;
  const doc = await this.findOne({ phone }).lean();
  const startedAt = doc?.windowStartedAt ? new Date(doc.windowStartedAt) : null;
  const windowActive = Boolean(startedAt) && now.getTime() - startedAt.getTime() < windowMs;

  if (!windowActive) {
    return { sendCount: 0, windowStartedAt: null, windowExpiresAt: null, windowActive: false };
  }

  return {
    sendCount: Number(doc.sendCount) || 0,
    windowStartedAt: startedAt,
    windowExpiresAt: new Date(startedAt.getTime() + windowMs),
    windowActive: true,
  };
};

/**
 * Record one send and return the resulting window state.
 *
 * `window` must be the value `readWindow()` returned, so the check and the write
 * describe the same window. Two truly simultaneous requests can therefore each
 * count as one send and still both be allowed at the boundary — the resend
 * cooldown closes that window in practice, and this is deliberately
 * defence-in-depth under the per-IP limiter, not the only control.
 *
 * @param {string} phone
 * @param {{ sendCount: number, windowStartedAt: Date|null, windowActive: boolean }} window
 * @param {Date} [now]
 * @returns {Promise<{ sendCount: number, windowStartedAt: Date, windowExpiresAt: Date }>}
 */
sendThrottleSchema.statics.commitSend = async function commitSend(phone, window = {}, now = new Date()) {
  const windowMs = config.otp.sendWindowSeconds * 1000;
  const continuing = window.windowActive && window.windowStartedAt instanceof Date;
  const windowStartedAt = continuing ? window.windowStartedAt : now;
  const sendCount = continuing ? (Number(window.sendCount) || 0) + 1 : 1;
  const windowExpiresAt = new Date(windowStartedAt.getTime() + windowMs);

  const doc = await this.findOneAndUpdate(
    { phone },
    { $set: { sendCount, windowStartedAt, expiresAt: windowExpiresAt }, $setOnInsert: { phone } },
    { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true }
  );

  return {
    sendCount: doc?.sendCount ?? sendCount,
    windowStartedAt,
    windowExpiresAt,
  };
};

/**
 * Give one send back.
 *
 * Used when nothing reached the user (no SMS transport configured, provider
 * failure). No credit was spent, so charging the budget would only punish a
 * victim whose number is on a provider outage — and it would hide a real
 * configuration error behind a rate limit.
 *
 * @param {string} phone
 * @returns {Promise<{ modified: boolean }>}
 */
sendThrottleSchema.statics.refundSend = async function refundSend(phone) {
  const result = await this.updateOne({ phone, sendCount: { $gt: 0 } }, { $inc: { sendCount: -1 } });
  return { modified: (result?.modifiedCount ?? 0) > 0 };
};

module.exports = mongoose.model('SendThrottle', sendThrottleSchema);
