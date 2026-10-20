'use strict';

/**
 * GuardFi — auth routes (Phase 2)
 *
 * Both endpoints are public by necessity (you cannot present a token before you
 * have one), so they are the most tightly limited routes in the API:
 *
 *   /send-otp   → otpSendLimiter (RATE_LIMIT_OTP_MAX, default 5 per 15 min)
 *                 plus the per-number resend cooldown inside otpService
 *   /verify-otp → authLimiter    (AUTH_RATE_LIMIT_MAX, default 10 per 15 min)
 *   /account    → authMiddleware (DELETE). The two login routes above are public
 *                 by necessity; this one is the opposite — identity must be
 *                 proven before anything is destroyed.
 *
 * Order is limiter → validator → controller, so a flood is rejected before any
 * parsing, hashing or SMS cost.
 */

const express = require('express');
const { sendOtp, verifyOtp, removeAccount } = require('../../controllers/authController');
const authMiddleware = require('../../middlewares/authMiddleware');
const { validateRequest } = require('../../middlewares/validateRequest');
const { authLimiter, otpSendLimiter } = require('../../middlewares/rateLimiter');
const { sendOtpSchema, verifyOtpSchema } = require('../../validators/auth.validator');

const router = express.Router();

router.post('/send-otp', otpSendLimiter, validateRequest({ body: sendOtpSchema }), sendOtp);
router.post('/verify-otp', authLimiter, validateRequest({ body: verifyOtpSchema }), verifyOtp);

// No dedicated limiter: this needs a valid, unexpired token and destroys the
// caller's own data, so the global budget is the right one — throttling it would
// only punish a user retrying a deletion that already half-failed.
router.delete('/account', authMiddleware, removeAccount);

module.exports = router;
