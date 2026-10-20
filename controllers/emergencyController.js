'use strict';

/**
 * GuardFi — emergency controller (Phase 8)
 *
 * Thin transport layer over services/emergencyService.js. It extracts the two
 * pieces of request metadata the audit trail needs (`req.ip`, User-Agent) and
 * maps each outcome onto the standard envelope.
 *
 *   POST /api/v1/emergency/biometric-verify  → 200 (201 on the first unlock)
 *   POST /api/v1/emergency/restricted-action → 200, requireEmergencyMode-gated
 *   POST /api/v1/emergency/lock              → 200
 *   GET  /api/v1/emergency/status            → 200
 */

const asyncHandler = require('../utils/asyncHandler');
const { sendSuccess } = require('../utils/apiResponse');
const {
  activateEmergencyMode,
  deactivateEmergencyMode,
  getEmergencyStatus,
  performRestrictedAction,
} = require('../services/emergencyService');

/** @param {import('express').Request} req */
function requestMeta(req) {
  return {
    ipAddress: req.ip || null,
    userAgent: req.get('user-agent') || null,
  };
}

/** POST /api/v1/emergency/biometric-verify */
const verifyBiometric = asyncHandler(async (req, res) => {
  const result = await activateEmergencyMode({
    userId: req.user._id,
    assertion: req.body,
    request: requestMeta(req),
  });

  return sendSuccess(res, {
    statusCode: result.alreadyActive ? 200 : 201,
    message: result.alreadyActive
      ? 'Biometric verification accepted. Emergency mode was already active.'
      : 'Biometric verification accepted. Emergency mode is now active.',
    data: {
      user: result.user,
      emergencyPermissions: result.emergencyPermissions,
      audit: result.audit,
      alreadyActive: result.alreadyActive,
    },
  });
});

/** POST /api/v1/emergency/restricted-action */
const restrictedAction = asyncHandler(async (req, res) => {
  const { action, note } = req.body;

  const result = await performRestrictedAction({
    userId: req.user._id,
    action,
    note: note ?? null,
    request: requestMeta(req),
    biometricEnabled: req.user.biometricEnabled === true,
  });

  return sendSuccess(res, {
    statusCode: 200,
    message: 'Emergency action permitted.',
    data: {
      action: result.action,
      performedAt: result.performedAt,
      emergencyPermissions: result.emergencyPermissions,
      audit: result.audit,
    },
  });
});

/** POST /api/v1/emergency/lock */
const lock = asyncHandler(async (req, res) => {
  const result = await deactivateEmergencyMode({
    userId: req.user._id,
    request: requestMeta(req),
  });

  return sendSuccess(res, {
    statusCode: 200,
    message: result.alreadyInactive
      ? 'Emergency mode is already inactive.'
      : 'Emergency mode has been locked. Restricted routes are closed again.',
    data: {
      user: result.user,
      emergencyPermissions: result.emergencyPermissions,
      audit: result.audit,
      alreadyInactive: result.alreadyInactive,
    },
  });
});

/** GET /api/v1/emergency/status */
const status = asyncHandler(async (req, res) => {
  const result = await getEmergencyStatus({ userId: req.user._id });

  return sendSuccess(res, {
    statusCode: 200,
    message: result.user.isEmergencyMode
      ? 'Emergency mode is active for this account.'
      : 'Emergency mode is inactive for this account.',
    data: result,
  });
});

module.exports = { verifyBiometric, restrictedAction, lock, status };
