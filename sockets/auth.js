'use strict';

/**
 * GuardFi — Socket.io handshake authentication (Phase 4)
 *
 * Every socket must present the same JWT the REST API uses, either as
 * `auth: { token }` (the Flutter/JS client's normal way) or as an
 * `Authorization: Bearer …` header for server-side clients.
 *
 * The database is authoritative for identity, exactly as in authMiddleware:
 * the token proves *who* is connecting, and a deleted account is rejected even
 * with a cryptographically valid token.
 *
 * Failures are sent as `connect_error` with a machine-readable `data.code`
 * (AUTH_REQUIRED, AUTH_EXPIRED, AUTH_INVALID, AUTH_UNAVAILABLE) and a message
 * that never discloses whether a phone number or account exists.
 *
 * `connectionStateRecovery.skipMiddlewares` is false (see sockets/index.js), so
 * a recovered session re-runs this check rather than inheriting an old session's
 * authorisation after the token expired.
 */

const jwt = require('jsonwebtoken');
const { config } = require('../config/env');
const { isDatabaseReady } = require('../config/db');
const { isValidObjectId } = require('../utils/validateObjectId');
const logger = require('../utils/logger');
const User = require('../models/User');

/**
 * @param {string} code
 * @param {string} message
 */
function rejection(code, message) {
  const error = new Error(message);
  error.data = { code };
  return error;
}

/** @param {import('socket.io').Socket} socket */
function extractToken(socket) {
  const fromAuth = socket?.handshake?.auth?.token;
  if (typeof fromAuth === 'string' && fromAuth.trim() !== '') return fromAuth.trim();

  const header = socket?.handshake?.headers?.authorization;
  if (typeof header === 'string') {
    const [scheme, value] = header.trim().split(/\s+/);
    if (scheme && scheme.toLowerCase() === 'bearer' && value) return value;
  }

  return '';
}

/**
 * @param {import('socket.io').Socket} socket
 * @param {(error?: Error) => void} next
 */
async function socketAuth(socket, next) {
  try {
    const token = extractToken(socket);

    if (!token) {
      return next(rejection('AUTH_REQUIRED', 'Authentication token is missing. Send it as auth.token.'));
    }

    let payload;

    try {
      payload = jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] });
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        return next(rejection('AUTH_EXPIRED', 'Authentication token has expired. Please sign in again.'));
      }
      return next(rejection('AUTH_INVALID', 'Authentication token is invalid.'));
    }

    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return next(rejection('AUTH_INVALID', 'Authentication token payload is malformed.'));
    }

    const subject = String(payload.sub ?? '').trim();

    if (!isValidObjectId(subject)) {
      return next(rejection('AUTH_INVALID', 'Authentication token subject is not a valid user id.'));
    }

    // Connected but still building indexes is not "ready": identity reads and
    // all writes are refused until the database invariants exist.
    if (!isDatabaseReady()) {
      return next(rejection('AUTH_UNAVAILABLE', 'Authentication is temporarily unavailable.'));
    }

    const user = await User.findById(subject).select('_id phone name role').lean();

    if (!user) {
      return next(rejection('AUTH_INVALID', 'The account for this token no longer exists.'));
    }

    socket.data.user = Object.freeze({
      id: String(user._id),
      phone: user.phone,
      name: user.name ?? null,
      role: user.role || 'user',
    });
    socket.data.tokenId = payload.jti ?? null;

    logger.debug(`[socket] Authenticated user ${socket.data.user.id} on ${socket.id}.`);

    return next();
  } catch (error) {
    logger.error('[socket] Handshake authentication failed unexpectedly', error);
    return next(rejection('AUTH_UNAVAILABLE', 'Authentication is temporarily unavailable.'));
  }
}

module.exports = socketAuth;
module.exports.extractToken = extractToken;
module.exports.rejection = rejection;
