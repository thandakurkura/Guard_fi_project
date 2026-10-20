'use strict';

/**
 * GuardFi — emergency input schemas (Phase 8)
 *
 * The signed-result contract is validated strictly before any HMAC math runs:
 * a missing field, a truncated signature or a non-ISO timestamp is a 400 with a
 * field-level message, not a confusing "signature invalid" 401. Bounds are the
 * same ones the AuditLog model enforces, so a value cannot pass validation and
 * then be rejected (or silently truncated) by the database.
 */

const { z } = require('zod');
const { optionalString } = require('./common');

/** Hex HMAC-SHA256. The service compares bytes; this rejects junk early. */
const signatureField = z
  .string({ error: 'signature is required' })
  .trim()
  .regex(/^[0-9a-f]{64}$/i, 'signature must be a 64-character hex HMAC-SHA256 digest');

const verifiedAtField = z
  .string({ error: 'verifiedAt is required' })
  .trim()
  .refine((value) => Number.isFinite(Date.parse(value)), 'verifiedAt must be an ISO-8601 timestamp');

/** A fresh random id per attempt. Bounded so it cannot become a storage vector. */
const nonceField = z
  .string({ error: 'nonce is required' })
  .trim()
  .min(16, 'nonce must be at least 16 characters')
  .max(128, 'nonce cannot exceed 128 characters')
  .regex(/^[A-Za-z0-9_-]+$/, 'nonce may only contain letters, digits, underscore and hyphen');

const deviceMetadataSchema = z
  .object({
    deviceId: optionalString('deviceId', { maxLength: 128 }),
    platform: z.enum(['android', 'ios', 'web', 'unknown']).default('unknown'),
    appVersion: optionalString('appVersion', { maxLength: 32 }),
    model: optionalString('model', { maxLength: 80 }),
    osVersion: optionalString('osVersion', { maxLength: 32 }),
  })
  .strict()
  .default({});

/** POST /api/v1/emergency/biometric-verify */
const biometricVerifySchema = z
  .object({
    success: z.boolean({ error: 'success must be true or false' }),
    verifiedAt: verifiedAtField,
    nonce: nonceField,
    signature: signatureField,
    deviceMetadata: deviceMetadataSchema,
  })
  .strict();

/** POST /api/v1/emergency/restricted-action */
const restrictedActionSchema = z
  .object({
    action: z
      .string({ error: 'action must be a string' })
      .trim()
      .regex(/^[A-Z][A-Z0-9_]{2,79}$/, 'action must be 3-80 characters of A-Z, 0-9 and underscore, e.g. CONTACT_POLICE')
      .default('EMERGENCY_ACCESS'),
    note: optionalString('note', { maxLength: 280 }),
  })
  .strict();

module.exports = {
  biometricVerifySchema,
  restrictedActionSchema,
  signatureField,
  verifiedAtField,
  nonceField,
  deviceMetadataSchema,
};
