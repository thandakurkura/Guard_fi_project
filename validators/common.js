'use strict';

/**
 * GuardFi — shared zod field builders (used by every phase's validators)
 *
 * Kept in one place so "phone is a phone number" and "name is a bounded string"
 * mean exactly the same thing at every endpoint. Duplicated copies drift: a
 * later phase adds a 40-character cap to one file and the other keeps accepting
 * 80, and nobody notices until the database rejects a write.
 *
 * The two zod 4 traps these helpers exist to avoid:
 *  • `req.body` may be undefined when no JSON parser matched the request, so a
 *    missing field must read "phone is required", not "expected object".
 *  • a field built from `z.any().transform(...)` that returns `undefined` is
 *    reported as `invalid_type: expected nonoptional` when the key is absent.
 *    The trailing `.optional()` on optionalString is load-bearing.
 */

const { z } = require('zod');
const { config } = require('../config/env');
const { normalizePhone } = require('../utils/phone');

/**
 * Required string: accepts a string (or a JSON number, because Dart ints
 * serialise without quotes), trims it, and reports absence in plain language.
 * @param {string} label
 */
function looseString(label) {
  return z.any().transform((value, ctx) => {
    if (value === undefined || value === null) {
      ctx.addIssue({ code: 'custom', message: `${label} is required` });
      return '';
    }
    if (typeof value === 'string') return value.trim();
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
    ctx.addIssue({ code: 'custom', message: `${label} must be a string` });
    return '';
  });
}

/**
 * Optional string: undefined / null / "" all normalise to undefined.
 * @param {string} label
 * @param {{ maxLength?: number }} [options]
 */
function optionalString(label, { maxLength = 512 } = {}) {
  return z
    .any()
    .transform((value, ctx) => {
      if (value === undefined || value === null) return undefined;
      if (typeof value !== 'string') {
        ctx.addIssue({ code: 'custom', message: `${label} must be a string` });
        return undefined;
      }
      const trimmed = value.trim();
      if (trimmed === '') return undefined;
      if (trimmed.length > maxLength) {
        ctx.addIssue({ code: 'custom', message: `${label} cannot exceed ${maxLength} characters` });
        return undefined;
      }
      return trimmed;
    })
    .optional();
}

/**
 * Optional boolean flag. Only real booleans are accepted: the string "true"
 * from a curl mistake must not silently become an elevated action.
 * @param {string} label
 */
function optionalBoolean(label) {
  return z
    .any()
    .transform((value, ctx) => {
      if (value === undefined || value === null) return undefined;
      if (typeof value === 'boolean') return value;
      ctx.addIssue({ code: 'custom', message: `${label} must be true or false` });
      return undefined;
    })
    .optional();
}

/**
 * Any accepted spelling is normalised to E.164 before it reaches the models.
 * @param {string} [label]
 */
function e164Field(label = 'phone') {
  return looseString(label).transform((value, ctx) => {
    const normalized = normalizePhone(value);

    if (normalized === null) {
      ctx.addIssue({
        code: 'custom',
        message: `${label} must be a valid phone number, e.g. +${config.phone.defaultCountryCode}9876543210`,
      });
      return value;
    }

    return normalized;
  });
}

/** A route-param id must be a 24-char hex ObjectId before any query sees it. */
const objectIdField = z
  .string({ error: 'id must be a string' })
  .trim()
  .regex(/^[0-9a-fA-F]{24}$/, 'id must be a valid 24-character MongoDB ObjectId')
  .transform((value) => value.toLowerCase());

module.exports = { looseString, optionalString, optionalBoolean, e164Field, objectIdField };
