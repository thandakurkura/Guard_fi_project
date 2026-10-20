'use strict';

/**
 * GuardFi — access token issuing (Phase 2)
 *
 * The only place in the codebase that signs a JWT, so the claim set can never
 * drift between modules. Claims:
 *   sub             the user's ObjectId (authMiddleware requires this)
 *   phone, name     display data, refreshed from the database on every request
 *   role            for rbacMiddleware.requireRoles()
 *   isEmergencyMode a hint only — rbacMiddleware.requireEmergencyMode() reads
 *                   the live value from the database, so a stale token can
 *                   never unlock (or wrongly lock) emergency routes
 *   jti             unique id per token, for log correlation and future
 *                   revocation lists
 *
 * HS256 is pinned at both ends (here and in authMiddleware) to block `alg: none`
 * and algorithm-confusion attacks.
 */

const crypto = require('node:crypto');
const jwt = require('jsonwebtoken');
const { config } = require('../config/env');

/**
 * @param {{ _id: unknown, phone: string, name?: string|null, role?: string, isEmergencyMode?: boolean }} user
 * @returns {{ token: string, tokenType: 'Bearer', expiresIn: string, expiresAt: string|null, payload: object }}
 */
function signAccessToken(user) {
  const payload = {
    sub: String(user._id),
    phone: user.phone,
    name: user.name ?? null,
    role: user.role || 'user',
    isEmergencyMode: user.isEmergencyMode === true,
    jti: crypto.randomUUID(),
  };

  const token = jwt.sign(payload, config.jwt.secret, {
    algorithm: 'HS256',
    expiresIn: config.jwt.expiresIn,
  });

  const decoded = jwt.decode(token);

  return {
    token,
    tokenType: 'Bearer',
    expiresIn: config.jwt.expiresIn,
    expiresAt: decoded?.exp ? new Date(decoded.exp * 1000).toISOString() : null,
    payload,
  };
}

module.exports = { signAccessToken };
