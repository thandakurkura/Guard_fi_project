'use strict';

/**
 * GuardFi — analytics controller (Phase 5)
 *
 * The only endpoint is the dashboard. All aggregation lives in
 * services/analyticsService.js; query overrides were validated and coerced by
 * the zod middleware into `req.validatedQuery` (Express 5 makes req.query
 * read-only, hence the separate property).
 *
 *   GET /api/v1/analytics/dashboard?radiusMeters=&windowHours=
 */

const asyncHandler = require('../utils/asyncHandler');
const { sendSuccess } = require('../utils/apiResponse');
const { getDashboard } = require('../services/analyticsService');

const dashboard = asyncHandler(async (req, res) => {
  const { radiusMeters, windowHours } = req.validatedQuery || {};

  const data = await getDashboard({
    userId: req.user._id,
    radiusMeters,
    windowHours,
  });

  return sendSuccess(res, {
    statusCode: 200,
    message: 'Dashboard analytics generated.',
    data,
  });
});

module.exports = { dashboard };
