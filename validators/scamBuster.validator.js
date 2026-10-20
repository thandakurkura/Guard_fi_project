'use strict';

/**
 * GuardFi — Scam Buster input schema (Phase 7)
 *
 * The whole request is a single optional text field. Everything else about the
 * request is a file, and files are validated by uploadMiddleware (MIME + size)
 * before this ever runs.
 *
 * Why the schema does not require `text`: the endpoint accepts EITHER a
 * screenshot OR text, and a zod body schema cannot see `req.file`. The
 * "at least one input" rule therefore lives in the controller, where both
 * halves are visible — and the service enforces it a third time.
 *
 * The length cap is the real content rule: 5 000 characters of pasted SMS spam
 * is generous, while an unbounded field would be token-billed by the AI provider
 * before anyone noticed.
 */

const { z } = require('zod');
const { config } = require('../config/env');
// The dashboard's bounded-integer rule, reused rather than re-implemented: two
// copies of "limit is 1-50" is exactly how the two endpoints drift apart.
const { optionalInt } = require('./analytics.validator');

const textField = z
  .any()
  .transform((value, ctx) => {
    if (value === undefined || value === null) return undefined;

    if (typeof value !== 'string') {
      ctx.addIssue({ code: 'custom', message: 'text must be a string' });
      return undefined;
    }

    const trimmed = value.trim();
    if (trimmed === '') return undefined; // an empty caption is simply absent

    if (trimmed.length > config.scamBuster.textMaxChars) {
      ctx.addIssue({
        code: 'custom',
        message: `text cannot exceed ${config.scamBuster.textMaxChars} characters`,
      });
      return undefined;
    }

    return trimmed;
  })
  .optional();

/** POST /api/v1/scam-buster/analyze (JSON body) */
const analyzeRequestSchema = z.object({ text: textField });

/**
 * GET /api/v1/scam-buster/history
 *
 * Cursor pagination, not page numbers: `before` is the `nextBefore` from the
 * previous response, and `limit` caps how much of the index one request reads.
 * An unparseable `before` is rejected rather than silently ignored, because a
 * client that thinks it is paging when it is not would loop forever on page 1.
 *
 * The cursor is `<ISO timestamp>` optionally followed by `_<scan id>` — opaque
 * to the client, which simply echoes `nextBefore`. The id is what makes paging
 * exact: two scans can share a millisecond (the offline fallback answers in
 * well under one), and a timestamp-only cursor would silently drop the sibling.
 * A bare ISO timestamp is still accepted, so hand-written clients keep working.
 */
const historyQuerySchema = z.object({
  limit: optionalInt('limit', 1, 50),
  before: z
    .any()
    .transform((value, ctx) => {
      if (value === undefined || value === null || value === '') return undefined;

      if (Array.isArray(value)) {
        ctx.addIssue({ code: 'custom', message: 'before must be provided once, not repeated' });
        return undefined;
      }

      if (typeof value !== 'string') {
        ctx.addIssue({ code: 'custom', message: 'before must be the nextBefore cursor from a previous page' });
        return undefined;
      }

      const match = /^([^_]+)(?:_([a-f0-9]{24}))?$/i.exec(value.trim());
      const at = match ? new Date(match[1]) : null;

      if (!at || Number.isNaN(at.getTime())) {
        ctx.addIssue({ code: 'custom', message: 'before must be the nextBefore cursor from a previous page' });
        return undefined;
      }

      return match[2] ? `${at.toISOString()}_${match[2].toLowerCase()}` : at.toISOString();
    })
    .optional(),
});

module.exports = { analyzeRequestSchema, historyQuerySchema, textField };
