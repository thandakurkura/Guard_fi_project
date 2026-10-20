'use strict';

/**
 * GuardFi — analytics query schemas (Phase 5)
 *
 * Both overrides are optional and strictly bounded, because they end up as real
 * aggregation parameters: an unbounded radius would ask MongoDB to geo-scan the
 * planet, and an unbounded window would turn a dashboard refresh into a
 * collection scan of every alert ever recorded.
 *
 * Repeated query parameters (?radiusMeters=1&radiusMeters=2) arrive as arrays
 * and are rejected rather than silently coerced to the first value.
 */

const { z } = require('zod');

/** @param {string} label @param {number} min @param {number} max */
function optionalInt(label, min, max) {
  return z
    .any()
    .transform((value, ctx) => {
      if (value === undefined || value === null || value === '') return undefined;

      if (Array.isArray(value)) {
        ctx.addIssue({ code: 'custom', message: `${label} must be provided once, not repeated` });
        return undefined;
      }

      const parsed = Number(value);

      if (!Number.isInteger(parsed) || parsed < min || parsed > max) {
        ctx.addIssue({ code: 'custom', message: `${label} must be an integer between ${min} and ${max}` });
        return undefined;
      }

      return parsed;
    })
    .optional();
}

const dashboardQuerySchema = z.object({
  radiusMeters: optionalInt('radiusMeters', 100, 50_000),
  windowHours: optionalInt('windowHours', 1, 168),
});

module.exports = { dashboardQuerySchema, optionalInt };
