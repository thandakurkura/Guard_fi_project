'use strict';

/**
 * GuardFi — global configuration update schema (Phase 9)
 *
 * Every field is optional (the admin PUT is a partial update) but at least one
 * must be present, and `.strict()` rejects unknown keys instead of dropping
 * them silently: a typo like `maintainanceMode` would otherwise return 200,
 * change nothing, and look like it worked.
 *
 * Bounds mirror models/AppConfig.js. The validator exists to answer with a
 * field-level 400; the model exists because scripts and future code paths do
 * not necessarily go through HTTP.
 */

const { z } = require('zod');

const httpUrlOrEmpty = (label) =>
  z
    .string({ error: `${label} must be a string` })
    .trim()
    .max(500, `${label} cannot exceed 500 characters`)
    .refine((value) => value === '' || /^https?:\/\/\S+$/i.test(value), `${label} must be an http(s) URL or an empty string`);

const boundedInt = (label, min, max) =>
  z.coerce
    .number({ error: `${label} must be a number` })
    .int(`${label} must be a whole number`)
    .min(min, `${label} must be at least ${min}`)
    .max(max, `${label} cannot exceed ${max}`);

const thresholdsSchema = z
  .object({
    upiRiskScoreThreshold: boundedInt('globalWarningThresholds.upiRiskScoreThreshold', 1, 100).optional(),
    sosRadiusMeters: boundedInt('globalWarningThresholds.sosRadiusMeters', 100, 50_000).optional(),
    maxNomineesPerUser: boundedInt('globalWarningThresholds.maxNomineesPerUser', 1, 50).optional(),
  })
  .strict()
  .refine((value) => Object.keys(value).length > 0, 'globalWarningThresholds must set at least one threshold');

const helplineSchema = z
  .object({
    name_en: z.string({ error: 'each helpline needs an English name' }).trim().min(1).max(80),
    name_hi: z.string({ error: 'each helpline needs a Hindi name' }).trim().min(1).max(80),
    number: z
      .string({ error: 'each helpline needs a number' })
      .trim()
      .regex(/^\+?[0-9][0-9 -]{1,15}$/, 'helpline number must be 2-15 digits, optionally starting with +'),
  })
  .strict();

const configUpdateSchema = z
  .object({
    privacyPolicyUrl: httpUrlOrEmpty('privacyPolicyUrl').optional(),
    termsUrl: httpUrlOrEmpty('termsUrl').optional(),
    globalWarningThresholds: thresholdsSchema.optional(),
    maintenanceMode: z.boolean({ error: 'maintenanceMode must be true or false' }).optional(),
    emergencyHelplines: z
      .array(helplineSchema, { error: 'emergencyHelplines must be an array' })
      .min(1, 'emergencyHelplines must contain at least one entry')
      .max(12, 'emergencyHelplines cannot contain more than 12 entries')
      .optional(),
  })
  .strict()
  .refine(
    (value) => Object.keys(value).length > 0,
    'Send at least one configuration field to update (privacyPolicyUrl, termsUrl, globalWarningThresholds, maintenanceMode, emergencyHelplines).'
  );

module.exports = { configUpdateSchema, thresholdsSchema, helplineSchema };
