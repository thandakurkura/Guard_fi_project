'use strict';

/**
 * GuardFi — global configuration controller (Phase 9)
 *
 *   GET /api/v1/config/global → 200 { source: 'cache' | 'database', config }
 *   PUT /api/v1/config/global → 200 { config, changedFields, version, audit }
 *
 * The GET is public on purpose: the app needs the privacy-policy links,
 * maintenance flag and helpline numbers before anyone signs in. It therefore
 * exposes exactly the configuration document and nothing else — no counters, no
 * cache diagnostics, no timestamps of other operations.
 */

const asyncHandler = require('../utils/asyncHandler');
const { sendSuccess } = require('../utils/apiResponse');
const { getGlobalConfig, updateGlobalConfig } = require('../services/configService');

/** @param {import('express').Request} req */
function requestMeta(req) {
  return {
    ipAddress: req.ip || null,
    userAgent: req.get('user-agent') || null,
  };
}

/** GET /api/v1/config/global — public, no authMiddleware. */
const getGlobal = asyncHandler(async (req, res) => {
  const { source, config } = await getGlobalConfig();

  return sendSuccess(res, {
    statusCode: 200,
    message:
      source === 'cache'
        ? 'Global configuration served from the in-memory cache.'
        : 'Global configuration loaded from the database and cached.',
    data: { source, config },
  });
});

/** PUT /api/v1/config/global — authMiddleware + admin role. */
const updateGlobal = asyncHandler(async (req, res) => {
  const result = await updateGlobalConfig({
    updates: req.body,
    adminId: req.user._id,
    request: requestMeta(req),
  });

  return sendSuccess(res, {
    statusCode: 200,
    message: `Global configuration updated (${result.changedFields.length} field(s)); the in-memory cache was invalidated.`,
    data: {
      config: result.config,
      changedFields: result.changedFields,
      previousVersion: result.previousVersion,
      version: result.version,
      cacheInvalidated: result.cacheInvalidated,
      audit: result.audit,
    },
  });
});

module.exports = { getGlobal, updateGlobal };
