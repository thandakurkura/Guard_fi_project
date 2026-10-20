'use strict';

/**
 * GuardFi — Scam Buster controller (Phase 7)
 *
 * Thin on purpose: uploadMiddleware parsed the file, the zod middleware bounded
 * the text, and services/scamBusterService.js owns storage, the AI call and the
 * parser. This handler enforces the one rule neither of those can see — "you
 * must send SOMETHING" — and wraps the service's stored verdict in the standard
 * response envelope.
 *
 *   POST /api/v1/scam-buster/analyze
 *     application/json       { "text": "…" }
 *     multipart/form-data    image=<file>&text=<optional caption>
 *
 *   GET  /api/v1/scam-buster/history?limit=&before=
 */

const asyncHandler = require('../utils/asyncHandler');
const ApiError = require('../utils/ApiError');
const { sendSuccess } = require('../utils/apiResponse');
const { analyzeScan, listScans, toPayload } = require('../services/scamBusterService');

const analyze = asyncHandler(async (req, res) => {
  const text = req.body && typeof req.body.text === 'string' ? req.body.text : null;
  const file = req.file || null;

  // The validator cannot see req.file, so the "at least one input" rule is
  // enforced here — before any upload or paid AI call.
  if (!file && !text) {
    throw ApiError.badRequest(
      'Provide either "text" (the suspicious message) or a screenshot in the "image" field.',
      [{ field: 'text', code: 'INPUT_REQUIRED', message: 'nothing to analyse was submitted' }]
    );
  }

  const record = await analyzeScan({
    userId: req.user._id,
    text,
    file,
    requestIp: req.ip,
  });

  return sendSuccess(res, {
    statusCode: 201,
    message: record.isScam
      ? 'Scan complete: fraud signals were detected in this message.'
      : 'Scan complete: no fraud signals were detected.',
    data: toPayload(record),
  });
});

/**
 * GET /api/v1/scam-buster/history
 * Query: { limit?, before? }
 *
 * Only the caller's own scans: the filter is `req.user._id`, never a client
 * value, so there is no id to tamper with and no IDOR to close.
 */
const history = asyncHandler(async (req, res) => {
  const { limit, before } = req.validatedQuery || {};

  const result = await listScans({
    userId: req.user._id,
    limit: limit ?? undefined,
    before: before ?? null,
  });

  return sendSuccess(res, {
    statusCode: 200,
    message: result.count === 0 ? 'No scans yet.' : `Retrieved ${result.count} scan(s).`,
    data: result,
  });
});

module.exports = { analyze, history };
