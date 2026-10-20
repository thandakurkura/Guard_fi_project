'use strict';

/**
 * GuardFi — role / state based access control (Phase 1)
 *
 * `requireEmergencyMode` implements the spec's server-side state enforcement:
 * high-stress restricted routes are reachable only while the caller's
 * emergency flag is true, regardless of what the Flutter client claims.
 */

const asyncHandler = require('../utils/asyncHandler');
const ApiError = require('../utils/ApiError');

/**
 * Requires an authenticated caller whose token carries `isEmergencyMode: true`.
 * Always mount after `authMiddleware`.
 */
const requireEmergencyMode = asyncHandler(async (req, res, next) => {
  if (!req.user) {
    throw ApiError.unauthorized('Authentication is required before an emergency check.');
  }

  if (req.user.isEmergencyMode !== true) {
    throw ApiError.forbidden('Emergency mode is not active for this account.');
  }

  return next();
});

/**
 * @param {...string} allowedRoles
 * @returns {import('express').RequestHandler}
 */
function requireRoles(...allowedRoles) {
  const roles = allowedRoles.flat().filter(Boolean);

  if (roles.length === 0) {
    throw new TypeError('requireRoles() needs at least one role.');
  }

  return asyncHandler(async (req, res, next) => {
    if (!req.user) {
      throw ApiError.unauthorized('Authentication is required before a role check.');
    }

    const callerRoles = Array.isArray(req.user.roles)
      ? req.user.roles.map(String)
      : req.user.role
        ? [String(req.user.role)]
        : [];

    if (!callerRoles.some((role) => roles.includes(role))) {
      throw ApiError.forbidden(`This action requires one of the following roles: ${roles.join(', ')}.`);
    }

    return next();
  });
}

module.exports = { requireEmergencyMode, requireRoles };
