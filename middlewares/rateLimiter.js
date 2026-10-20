'use strict';

/**
 * GuardFi — rate limiting (Phase 1, extended in Phase 2)
 *
 * Five limiters:
 *   globalLimiter      — coarse protection for the whole API surface.
 *   authLimiter        — strict limiter for credential-bearing routes
 *                        (POST /api/v1/auth/verify-otp).
 *   otpSendLimiter     — separate budget for OTP *sending*, because each request
 *                        costs a real SMS. One user burning the verify budget
 *                        must not be able to unlock an SMS-bomb loop, and vice
 *                        versa.
 *   pinLimiter         — the Shield Pay PIN budget (Phase 6). A 4-6 digit PIN
 *                        is a 10 000-guess space, so /proceed-transaction and
 *                        /set-pin get a small per-IP allowance instead of the
 *                        global one; a stolen session must not be able to walk
 *                        the PIN space.
 *   scamBusterLimiter  — the AI scan budget (Phase 7). Every scan spends Gemini
 *                        tokens and, for a screenshot, a Cloudinary upload, so
 *                        the endpoint gets its own allowance rather than being
 *                        able to drain quota (or a bill) through the global one.
 *   emergencyLimiter   — the biometric-unlock budget (Phase 8). Every attempt
 *                        writes an immutable audit row, so an attacker holding a
 *                        valid session must not be able to flood the collection
 *                        (or grind a stolen signing key) at will.
 *
 * All of them are skipped when NODE_ENV=test — unless RATE_LIMIT_SKIP_IN_TEST is
 * explicitly false, which the Phase 2 verification harness uses to prove a real
 * 429 is returned. Limits are environment driven (see .env.example).
 */

const rateLimitModule = require('express-rate-limit');
const { config } = require('../config/env');
const ApiError = require('../utils/ApiError');

// Supports both `module.exports = rateLimit` and named-export builds.
const rateLimit = rateLimitModule.rateLimit || rateLimitModule.default || rateLimitModule;

const baseOptions = {
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  skip: () => config.isTest && config.rateLimit.skipInTest,
  // Trust-proxy is an explicit, documented setting here, so the library's
  // heuristic warning about X-Forwarded-For would only add noise.
  validate: { xForwardedForHeader: false },
};

const globalLimiter = rateLimit({
  ...baseOptions,
  windowMs: config.rateLimit.windowMs,
  limit: config.rateLimit.max,
  handler: (req, res, next) => {
    next(ApiError.tooManyRequests('Too many requests from this address. Please slow down and try again shortly.'));
  },
});

const authLimiter = rateLimit({
  ...baseOptions,
  windowMs: config.rateLimit.windowMs,
  limit: config.rateLimit.authMax,
  handler: (req, res, next) => {
    next(ApiError.tooManyRequests('Too many authentication attempts. Please wait before trying again.'));
  },
});

const otpSendLimiter = rateLimit({
  ...baseOptions,
  windowMs: config.rateLimit.otpWindowMs,
  limit: config.rateLimit.otpMax,
  handler: (req, res, next) => {
    next(ApiError.tooManyRequests('Too many verification codes were requested from this address. Please try again later.'));
  },
});

const pinLimiter = rateLimit({
  ...baseOptions,
  windowMs: config.rateLimit.windowMs,
  limit: config.rateLimit.pinMax,
  handler: (req, res, next) => {
    next(ApiError.tooManyRequests('Too many Shield Pay PIN attempts. Please wait before trying again.'));
  },
});

const scamBusterLimiter = rateLimit({
  ...baseOptions,
  windowMs: config.rateLimit.windowMs,
  limit: config.rateLimit.scamBusterMax,
  handler: (req, res, next) => {
    next(ApiError.tooManyRequests('Too many scam scans were requested. Please wait before trying another scan.'));
  },
});

const emergencyLimiter = rateLimit({
  ...baseOptions,
  windowMs: config.rateLimit.windowMs,
  limit: config.rateLimit.emergencyMax,
  handler: (req, res, next) => {
    next(
      ApiError.tooManyRequests('Too many biometric unlock attempts. Wait before trying again, or use your device passcode.')
    );
  },
});

module.exports = { globalLimiter, authLimiter, otpSendLimiter, pinLimiter, scamBusterLimiter, emergencyLimiter };
