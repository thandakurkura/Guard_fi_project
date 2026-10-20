'use strict';

/**
 * GuardFi — auth input schemas (Phase 2)
 *
 * The master spec's folder list is config/models/controllers/routes/
 * middlewares/services/sockets/utils; `validators/` is one addition, kept so
 * "validate every req.body" lives in exactly one place per module instead of
 * being smeared through the controllers.
 *
 * Messages are written by hand rather than left to zod's defaults: a hackathon
 * teammate hitting a 400 should read "phone must be a valid phone number …"
 * and not "Invalid input: expected string, received number".
 *
 * The generic field builders live in validators/common.js since Phase 3, so
 * auth and nominee validation cannot drift apart.
 */

const { z } = require('zod');
const { config } = require('../config/env');
const { looseString, optionalString, e164Field } = require('./common');

/** Any accepted spelling is normalised to E.164 before it reaches the models. */
const phoneField = e164Field('phone');

const otpRegex = new RegExp(`^\\d{${config.otp.length}}$`);

const otpField = looseString('otp')
  .refine((value) => otpRegex.test(value), {
    message: `otp must be exactly ${config.otp.length} digits`,
  });

/** POST /api/v1/auth/send-otp */
const sendOtpSchema = z.object({
  phone: phoneField,
});

/** POST /api/v1/auth/verify-otp */
const verifyOtpSchema = z.object({
  phone: phoneField,
  otp: otpField,
  name: optionalString('name', { maxLength: 80 }),
  fcmToken: optionalString('fcmToken', { maxLength: 512 }),
});

module.exports = { sendOtpSchema, verifyOtpSchema, phoneField, otpField };
