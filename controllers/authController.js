'use strict';

/**
 * GuardFi — authentication controller (Phase 2)
 *
 * Thin on purpose: parsing and validation happen in the zod middleware, the
 * rules live in services/otpService.js, and this file only turns service output
 * into the standard response envelope.
 *
 *   POST   /api/v1/auth/send-otp    → issue + deliver a code
 *   POST   /api/v1/auth/verify-otp  → verify, upsert the user, return a JWT
 *   DELETE /api/v1/auth/account     → cascade-delete the caller's account
 */

const asyncHandler = require('../utils/asyncHandler');
const { sendSuccess } = require('../utils/apiResponse');
const { issueOtp, verifyOtpAndLogin } = require('../services/otpService');
const { signAccessToken } = require('../services/tokenService');
const { deleteAccount } = require('../services/accountService');

/**
 * POST /api/v1/auth/send-otp
 * Body: { phone }
 */
const sendOtp = asyncHandler(async (req, res) => {
  const { phone } = req.body;

  // req.ip is passed through so the development fallback can tell a laptop from
  // the open internet and warn in the response when it is the latter.
  const result = await issueOtp({ phone, callerIp: req.ip });

  return sendSuccess(res, {
    statusCode: 200,
    message: result.devMode
      ? `Verification code generated for ${phone}. OTP_DEV_MODE is on, so the code is in this response instead of an SMS.`
      : `A verification code has been sent to ${phone}.`,
    data: result,
  });
});

/**
 * POST /api/v1/auth/verify-otp
 * Body: { phone, otp, name?, fcmToken? }
 */
const verifyOtp = asyncHandler(async (req, res) => {
  const { phone, otp, name, fcmToken } = req.body;

  const { user, created } = await verifyOtpAndLogin({ phone, otp, name, fcmToken });
  const auth = signAccessToken(user);

  return sendSuccess(res, {
    statusCode: 200,
    message: created ? 'Account created and signed in.' : 'Signed in successfully.',
    data: {
      // toJSON() runs the model transform, which strips securityPinHash/fcmToken.
      user: user.toJSON(),
      isNewUser: created,
      token: auth.token,
      tokenType: auth.tokenType,
      expiresIn: auth.expiresIn,
      expiresAt: auth.expiresAt,
    },
  });
});

/**
 * DELETE /api/v1/auth/account
 *
 * The identity comes from the verified token, never from the body: a caller can
 * only ever delete their own account. The response reports exactly what was
 * removed so the client can show an honest "everything is gone" screen, and the
 * token is worthless afterwards — authMiddleware resolves identity from the
 * database, so the very next request with it answers 401.
 */
const removeAccount = asyncHandler(async (req, res) => {
  const result = await deleteAccount({
    userId: req.user._id,
    phone: req.user.phone,
    request: {
      ipAddress: req.ip || null,
      userAgent: req.get('user-agent') || null,
    },
  });

  return sendSuccess(res, {
    statusCode: 200,
    message: 'Your account and all of its personal data have been permanently deleted.',
    data: result,
  });
});

module.exports = { sendOtp, verifyOtp, removeAccount };
