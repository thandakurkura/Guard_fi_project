'use strict';

/**
 * GuardFi — OTP lifecycle (Phase 2)
 *
 * All of the rules that make phone login safe live in this one file:
 *
 *   issueOtp()
 *     • optional per-number resend cooldown (OTP_RESEND_COOLDOWN_SECONDS) — the
 *       real defence against using GuardFi as a free SMS cannon;
 *     • a per-number send budget (OTP_MAX_SENDS_PER_WINDOW) kept in its own
 *       collection, so one attacker rotating IPs cannot bomb a single victim —
 *       see models/SendThrottle.js for why that counter must NOT live on the
 *       OTP document;
 *     • one live code per number, replaced atomically on resend;
 *     • the code is stored as a bcrypt hash before it is ever sent;
 *     • if delivery fails and OTP_DEV_MODE is off, the stored code is deleted,
 *       the send budget is refunded, and the caller gets a 503 — no orphaned
 *       code, no leaked secret, and no credit charged for an SMS nobody got.
 *
 *   verifyOtpAndLogin()
 *     • expiry checked in application code, not just by the TTL sweeper;
 *     • the attempt counter is incremented atomically and can never exceed the
 *       cap, so parallel guessing cannot brute-force a 6-digit code;
 *     • a code is single-use: it is deleted the instant it succeeds;
 *     • a missing code still costs a bcrypt comparison, so response timing does
 *       not reveal whether a number has a pending OTP.
 */

const { config } = require('../config/env');
const logger = require('../utils/logger');
const ApiError = require('../utils/ApiError');
const { maskPhone } = require('../utils/phone');
const { isPrivateAddress } = require('../utils/net');
const { generateOtp, hashOtp, verifyOtpHash, getDummyOtpHash } = require('../utils/otp');
const User = require('../models/User');
const Otp = require('../models/Otp');
const SendThrottle = require('../models/SendThrottle');
const { sendOtpSms } = require('./smsService');

/**
 * Create (or replace) the code for `phone` and try to deliver it.
 *
 * Two independent throttles guard this entry point, because they stop different
 * attacks: the resend cooldown stops a victim's phone being spammed from one
 * place, and the per-phone send budget stops an attacker who rotates IPs to keep
 * spending the project's SMS credit on one number.
 *
 * @param {{ phone: string, callerIp?: string|null }} params normalised E.164 phone
 */
async function issueOtp({ phone, callerIp = null }) {
  const now = new Date();

  const [existing, budget] = await Promise.all([
    Otp.findOne({ phone }).select('+otpHash').lean(),
    SendThrottle.readWindow(phone, now),
  ]);

  if (config.otp.maxSendsPerWindow > 0 && budget.windowActive && budget.sendCount >= config.otp.maxSendsPerWindow) {
    const retryAfterSeconds = Math.max(1, Math.ceil((budget.windowExpiresAt.getTime() - now.getTime()) / 1000));

    logger.warn(
      `[otp] Send budget exhausted for ${maskPhone(phone)} (${budget.sendCount}/${config.otp.maxSendsPerWindow} in this window).`
    );

    throw new ApiError(
      429,
      `Too many verification codes were requested for ${maskPhone(phone)}. Try again in ${Math.ceil(retryAfterSeconds / 60)} minute(s).`,
      {
        errors: [
          {
            field: 'phone',
            code: 'OTP_SEND_LIMIT_REACHED',
            message: `at most ${config.otp.maxSendsPerWindow} codes per ${Math.round(config.otp.sendWindowSeconds / 60)} minute(s)`,
            retryAfterSeconds,
          },
        ],
      }
    );
  }

  if (existing && config.otp.resendCooldownSeconds > 0) {
    const ageSeconds = (now.getTime() - new Date(existing.createdAt).getTime()) / 1000;

    if (ageSeconds < config.otp.resendCooldownSeconds) {
      const retryAfterSeconds = Math.max(1, Math.ceil(config.otp.resendCooldownSeconds - ageSeconds));

      throw new ApiError(429, `A verification code was just sent to ${maskPhone(phone)}. Please wait ${retryAfterSeconds}s before requesting another.`, {
        errors: [
          {
            field: 'phone',
            code: 'OTP_COOLDOWN_ACTIVE',
            message: 'a code is already live for this number',
            retryAfterSeconds,
          },
        ],
      });
    }
  }

  const otp = generateOtp();
  const otpHash = await hashOtp(otp);
  const stored = await Otp.upsertForPhone(phone, otpHash);

  if (!stored) {
    // Only reachable if the upsert was lost to a concurrent write; the caller
    // can retry immediately, so this is a transient failure, not a user error.
    throw ApiError.internal('The verification code could not be stored. Please try again.');
  }

  // Charged once the code exists, so the budget tracks what the user can actually
  // try to verify with — and so a provider outage (refunded below) cannot quietly
  // lock a real user out.
  const spend = await SendThrottle.commitSend(phone, budget, now);

  const delivery = await sendOtpSms({ phone, otp });

  if (!delivery.delivered && !config.otp.devMode) {
    // Nothing reached the user. Remove the code so a retry is clean and no
    // unusable secret is left at rest, give the send back, then say so honestly.
    await Otp.deleteOne({ _id: stored._id });
    await SendThrottle.refundSend(phone);

    throw ApiError.serviceUnavailable(
      `We could not send a verification code to ${maskPhone(phone)} right now (${delivery.reason}). Please try again shortly.`
    );
  }

  if (!delivery.delivered) {
    logger.warn(
      `[otp] SMS unavailable (${delivery.reason}) — OTP_DEV_MODE is on, so the code for ${maskPhone(phone)} is returned in the API response instead.`
    );
  }

  logger.info(`[otp] Code issued for ${maskPhone(phone)} (delivered=${delivery.delivered} via ${delivery.provider}).`);

  // Dev mode is fine on a laptop and dangerous on a public host. Say so, loudly,
  // in the same response that carries the code, so the leak cannot go unnoticed.
  const securityNotice = buildDevModeNotice(callerIp, phone);

  return {
    phone,
    expiresInSeconds: Math.max(0, config.otp.ttlSeconds - Math.floor((Date.now() - new Date(stored.createdAt).getTime()) / 1000)),
    attemptsAllowed: config.otp.maxAttempts,
    sendsRemainingInWindow:
      config.otp.maxSendsPerWindow > 0 ? Math.max(0, config.otp.maxSendsPerWindow - spend.sendCount) : null,
    delivery: { delivered: delivery.delivered, provider: delivery.provider, reason: delivery.reason ?? null },
    devMode: config.otp.devMode,
    // Present ONLY in development/hackathon mode, and only ever over HTTPS in
    // any deployed environment. Production rejects this with the 503 above.
    ...(config.otp.devMode ? { otp } : {}),
    ...(securityNotice ? { securityNotice } : {}),
  };
}

/**
 * @param {string|null} callerIp
 * @param {string} phone
 * @returns {string|null}
 */
function buildDevModeNotice(callerIp, phone) {
  if (!config.otp.devMode) return null;
  if (callerIp === null || callerIp === undefined) return null;
  if (isPrivateAddress(callerIp)) return null;

  logger.warn(
    `[otp] OTP_DEV_MODE returned a live code for ${maskPhone(phone)} to a non-private caller (${callerIp}). Anyone who can reach this address can sign in as any user.`
  );

  return (
    `OTP_DEV_MODE is on and this request came from ${callerIp}, which is not a private address. ` +
    'The verification code was returned in this response, so anyone who can reach this server can sign in as any user. ' +
    'Set OTP_DEV_MODE=false (and configure SMS delivery) before exposing this deployment.'
  );
}

/**
 * Validate a submitted code and burn one attempt on failure.
 * @param {{ phone: string, otp: string }} params
 * @returns {Promise<import('mongoose').HydratedDocument<any>>} the consumed Otp document
 */
async function consumeOtpAttempt({ phone, otp }) {
  const record = await Otp.findOne({ phone }).select('+otpHash');

  if (!record) {
    // Burn equivalent CPU time so a missing record is not distinguishable by timing.
    await verifyOtpHash(otp, await getDummyOtpHash());

    throw ApiError.badRequest('No verification code is waiting for this number. Request a new one.', [
      { field: 'otp', code: 'OTP_NOT_REQUESTED', message: 'no active code for this phone number' },
    ]);
  }

  if (record.isExpired()) {
    await Otp.deleteOne({ _id: record._id });

    throw ApiError.badRequest('This verification code has expired. Request a new one.', [
      { field: 'otp', code: 'OTP_EXPIRED', message: `codes are valid for ${config.otp.ttlSeconds} seconds` },
    ]);
  }

  if (record.attempts >= config.otp.maxAttempts) {
    throw new ApiError(429, `This code is locked after ${config.otp.maxAttempts} incorrect attempts. Request a new one.`, {
      errors: [{ field: 'otp', code: 'OTP_LOCKED', message: 'too many incorrect attempts for this code' }],
    });
  }

  const matches = await verifyOtpHash(otp, record.otpHash);

  if (!matches) {
    const { attempts, locked } = await Otp.registerFailedAttempt(record._id);
    const remaining = Math.max(0, config.otp.maxAttempts - attempts);

    logger.warn(`[otp] Incorrect code for ${maskPhone(phone)} (attempt ${attempts}/${config.otp.maxAttempts}).`);

    if (locked || remaining === 0) {
      throw new ApiError(429, `Incorrect verification code. This code is now locked after ${config.otp.maxAttempts} failed attempts — request a new one.`, {
        errors: [{ field: 'otp', code: 'OTP_LOCKED', message: 'too many incorrect attempts for this code' }],
      });
    }

    throw ApiError.badRequest(`Incorrect verification code. ${remaining} attempt(s) remaining.`, [
      { field: 'otp', code: 'OTP_INVALID', message: 'the code does not match', remainingAttempts: remaining },
    ]);
  }

  return record;
}

/**
 * Verify the code, then upsert the user and return them.
 * @param {{ phone: string, otp: string, name?: string, fcmToken?: string }} params
 * @returns {Promise<{ user: import('mongoose').HydratedDocument<any>, created: boolean }>}
 */
async function verifyOtpAndLogin({ phone, otp, name, fcmToken }) {
  const record = await consumeOtpAttempt({ phone, otp });

  const { user, created } = await User.findOrCreateByPhone(phone, { name, fcmToken });

  // Single use: a successful code can never be replayed, even inside its TTL.
  await Otp.deleteOne({ _id: record._id });

  logger.info(`[otp] ${created ? 'Account created' : 'Sign-in'} for ${maskPhone(phone)} (user ${user._id}).`);

  return { user, created };
}

module.exports = { issueOtp, consumeOtpAttempt, verifyOtpAndLogin };
