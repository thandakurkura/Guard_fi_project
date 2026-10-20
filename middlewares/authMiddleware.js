'use strict';

/**
 * GuardFi — JWT authentication middleware (Phase 1, made authoritative in Phase 2)
 *
 * Verifies `Authorization: Bearer <token>`, then loads the caller from MongoDB
 * and attaches:
 *   req.auth → the raw decoded claims (frozen)
 *   req.user → live identity: { _id, id, phone, name, role, roles,
 *              isEmergencyMode, biometricEnabled, tokenId, tokenIssuedAt }
 *
 * WHY THE DATABASE READ (this is a Phase 2 bug fix, not decoration):
 * Phase 1 had no `User` model, so every field came from the token. That made
 * `isEmergencyMode` a snapshot of the moment the token was signed — a token
 * issued before an emergency unlock would still say `false` minutes later, so
 * rbacMiddleware.requireEmergencyMode() would refuse a user who is in fact in an
 * emergency. The database is now the single source of truth for authorisation
 * state and the token only proves *who* is calling.
 *
 * Every failure mode still returns a clean 401/503 through the central error
 * middleware: missing header, wrong scheme, empty token, malformed token, bad
 * signature, expired token, not-yet-valid token, missing/non-ObjectId subject, a
 * token whose account was deleted, and an unreachable database.
 */

const jwt = require('jsonwebtoken');
const { config } = require('../config/env');
const { isDatabaseReady } = require('../config/db');
const asyncHandler = require('../utils/asyncHandler');
const ApiError = require('../utils/ApiError');
const { isValidObjectId } = require('../utils/validateObjectId');
const User = require('../models/User');

/** Only these paths are loaded — secrets (securityPinHash, fcmToken) are never hydrated. */
const AUTHENTICATED_USER_FIELDS = '_id phone name role isEmergencyMode biometricEnabled lastLoginAt createdAt';

/**
 * @param {Record<string, unknown>} payload
 * @returns {string} the caller's identifier from sub / _id / id
 */
function extractSubject(payload) {
  const candidate = payload.sub ?? payload._id ?? payload.id;

  if (candidate === undefined || candidate === null) return '';
  if (typeof candidate === 'object' && typeof candidate.toHexString === 'function') {
    return candidate.toHexString();
  }

  return String(candidate).trim();
}

const authMiddleware = asyncHandler(async (req, res, next) => {
  const header = req.headers.authorization;

  if (typeof header !== 'string' || header.trim() === '') {
    throw ApiError.unauthorized('Authentication token is missing. Send "Authorization: Bearer <token>".');
  }

  const parts = header.trim().split(/\s+/);

  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    throw ApiError.unauthorized('Authorization header must use the "Bearer <token>" scheme.');
  }

  const token = parts[1];

  if (!token) {
    throw ApiError.unauthorized('Authentication token is empty.');
  }

  let payload;

  try {
    // Pinning the algorithm blocks `alg: none` and HS/RS confusion attacks.
    payload = jwt.verify(token, config.jwt.secret, { algorithms: ['HS256'] });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw ApiError.unauthorized('Authentication token has expired. Please sign in again.');
    }
    if (error.name === 'NotBeforeError') {
      throw ApiError.unauthorized('Authentication token is not active yet.');
    }
    throw ApiError.unauthorized('Authentication token is invalid.');
  }

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw ApiError.unauthorized('Authentication token payload is malformed.');
  }

  const subject = extractSubject(payload);

  if (!subject) {
    throw ApiError.unauthorized('Authentication token is missing its subject claim.');
  }

  if (!isValidObjectId(subject)) {
    throw ApiError.unauthorized('Authentication token subject is not a valid user id.');
  }

  // Identity lives in the database. If it is unreachable — or merely connected
  // while its unique indexes are still building — the request must fail closed
  // with a 503 rather than pretend the caller is authenticated. Writes accepted
  // before `{ userId, phone }` is unique would defeat the constraint entirely.
  if (!isDatabaseReady()) {
    throw ApiError.serviceUnavailable('Authentication is temporarily unavailable because the database is not ready.');
  }

  const user = await User.findById(subject).select(AUTHENTICATED_USER_FIELDS).lean();

  if (!user) {
    throw ApiError.unauthorized('The account for this token no longer exists.');
  }

  const role = user.role || 'user';
  const id = String(user._id);

  req.auth = Object.freeze({ ...payload });
  req.user = Object.freeze({
    _id: id,
    id,
    phone: user.phone,
    name: user.name ?? null,
    role,
    roles: [role],
    // Authoritative, live value — never the token's claim.
    isEmergencyMode: user.isEmergencyMode === true,
    biometricEnabled: user.biometricEnabled === true,
    tokenId: payload.jti ?? null,
    tokenIssuedAt: payload.iat ?? null,
  });

  return next();
});

module.exports = authMiddleware;
module.exports.extractSubject = extractSubject;
module.exports.AUTHENTICATED_USER_FIELDS = AUTHENTICATED_USER_FIELDS;
