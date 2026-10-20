'use strict';

/**
 * GuardFi — emergency biometric bypass & server-side state (Phase 8)
 *
 * THE PROBLEM THIS FILE SOLVES
 * The Flutter app verifies a fingerprint / face locally. That result arrives on
 * the wire, and the wire is attacker-controlled: a modified client could simply
 * POST `{"success": true}` and unlock every emergency-only route. So the local
 * result must be *signed*, and the server must verify four things before it
 * changes any state:
 *
 *   1. the signature is a valid HMAC-SHA256 of the assertion, keyed with
 *      BIOMETRIC_SHARED_SECRET (the same value embedded in the app build);
 *   2. the assertion is fresh (default 120 s, small future skew allowed) — an
 *      assertion captured yesterday is not proof of a finger on the sensor now;
 *   3. the signed message names *this* caller, so a captured assertion cannot
 *      be replayed against another account;
 *   4. `success` is true.
 *
 * The nonce is then claimed by an immutable AuditLog row with a unique
 * (userId, assertionNonce) index, which is what makes the signed result
 * single-use. A replay is a clean 409, never a second unlock.
 *
 * CANONICAL SIGNING STRING (the Flutter client must reproduce it byte for byte):
 *
 *   guardfi-biometric-v1|<userId>|true|<verifiedAtEpochMs>|<nonce>
 *
 *   userId            the caller's MongoDB id (the JWT `sub`)
 *   verifiedAtEpochMs Date.parse(verifiedAt) — the ISO timestamp in the body
 *   nonce             16-128 characters of [A-Za-z0-9_-], fresh per attempt
 *   signature         lowercase or uppercase hex of HMAC-SHA256(secret, string)
 *
 * LIMITATION, STATED PLAINLY: a secret shipped inside a mobile app can be
 * extracted from it. This signature blocks the trivial "curl the endpoint"
 * attack and makes forged assertions traceable, but a rooted device with the
 * extracted key can still sign anything. Real hardware attestation (Play
 * Integrity / App Attest) is the next step, not something an HMAC can replace.
 */

const crypto = require('node:crypto');
const { config } = require('../config/env');
const ApiError = require('../utils/ApiError');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { AUDIT_ACTIONS } = AuditLog;

const CANONICAL_PREFIX = 'guardfi-biometric-v1';
const SIGNATURE_REGEX = /^[0-9a-f]{64}$/i;
/** Small clock skew tolerated on a device whose time is a few seconds fast. */
const MAX_FUTURE_SKEW_MS = 30_000;

/** The emergency-only capabilities, returned so the client never hard-codes them. */
const EMERGENCY_ACTIONS = Object.freeze(['SOS_TRIGGER', 'RESTRICTED_ACTION', 'BIOMETRIC_BYPASS']);

/**
 * @param {{ userId: string, success: boolean, verifiedAt: Date|string|number, nonce: string }} input
 * @returns {string} the exact string that is HMAC-signed
 */
function canonicalAssertion({ userId, success, verifiedAt, nonce }) {
  const epochMs = verifiedAt instanceof Date ? verifiedAt.getTime() : new Date(verifiedAt).getTime();
  return [CANONICAL_PREFIX, String(userId), success === true ? 'true' : 'false', String(epochMs), String(nonce)].join(
    '|'
  );
}

/**
 * Sign an assertion. Used by the verification harnesses; the Flutter client
 * implements the same canonical string with `Hmac(sha256, key)`.
 *
 * @param {{ userId: string, success?: boolean, verifiedAt?: Date|string|number, nonce: string, secret?: string }} input
 * @returns {{ signature: string, canonical: string }}
 */
function signAssertion({ userId, success = true, verifiedAt = new Date(), nonce, secret = config.biometric.sharedSecret }) {
  if (!secret) {
    throw new Error('Cannot sign a biometric assertion without a secret.');
  }

  const canonical = canonicalAssertion({ userId, success, verifiedAt, nonce });
  const signature = crypto.createHmac('sha256', secret).update(canonical).digest('hex');

  return { signature, canonical };
}

/**
 * Pure verification: never writes, never throws. The caller decides what to
 * audit and which HTTP status to return, which keeps the "record the rejection
 * before answering" step in one obvious place.
 *
 * @param {{
 *   userId: string,
 *   success: boolean,
 *   verifiedAt: string|Date,
 *   nonce: string,
 *   signature: string,
 *   secret?: string|null,
 *   maxAgeSeconds?: number,
 *   now?: number,
 * }} input
 * @returns {{ ok: true, verifiedAt: Date, nonce: string, nonceTrusted: true }
 *          | { ok: false, statusCode: number, code: string, message: string, nonceTrusted: boolean }}
 */
function verifyAssertion({
  userId,
  success,
  verifiedAt,
  nonce,
  signature,
  secret = config.biometric.sharedSecret,
  maxAgeSeconds = config.biometric.maxAssertionAgeSeconds,
  now = Date.now(),
}) {
  if (!secret) {
    return {
      ok: false,
      statusCode: 503,
      code: 'BIOMETRIC_VERIFIER_NOT_CONFIGURED',
      message:
        'Emergency biometric unlock is not configured on this server. Set BIOMETRIC_SHARED_SECRET to the value provisioned in the mobile app.',
      nonceTrusted: false,
    };
  }

  if (typeof signature !== 'string' || !SIGNATURE_REGEX.test(signature.trim())) {
    return {
      ok: false,
      statusCode: 401,
      code: 'BIOMETRIC_SIGNATURE_INVALID',
      message: 'The biometric verification result is not correctly signed.',
      nonceTrusted: false,
    };
  }

  const verifiedAtDate = new Date(verifiedAt);
  const verifiedAtMs = verifiedAtDate.getTime();

  if (!Number.isFinite(verifiedAtMs)) {
    return {
      ok: false,
      statusCode: 401,
      code: 'BIOMETRIC_SIGNATURE_INVALID',
      message: 'The biometric verification result has an invalid verification time.',
      nonceTrusted: false,
    };
  }

  const expected = crypto
    .createHmac('sha256', secret)
    .update(canonicalAssertion({ userId, success, verifiedAt: verifiedAtDate, nonce }))
    .digest();
  const provided = Buffer.from(signature.trim(), 'hex');

  // timingSafeEqual throws on length mismatch, so compare lengths first. The
  // length is public information (a SHA-256 digest), so this leaks nothing.
  if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
    return {
      ok: false,
      statusCode: 401,
      code: 'BIOMETRIC_SIGNATURE_INVALID',
      message: 'The biometric verification result is not correctly signed.',
      nonceTrusted: false,
    };
  }

  // Past the signature check: the nonce is genuinely the caller's, so it is safe
  // to claim it in the audit trail (and thereby burn it).
  const ageMs = now - verifiedAtMs;

  if (ageMs > maxAgeSeconds * 1000) {
    return {
      ok: false,
      statusCode: 401,
      code: 'BIOMETRIC_ASSERTION_EXPIRED',
      message: `This biometric verification is older than ${maxAgeSeconds} seconds. Verify again.`,
      nonceTrusted: true,
    };
  }

  if (ageMs < -MAX_FUTURE_SKEW_MS) {
    return {
      ok: false,
      statusCode: 401,
      code: 'BIOMETRIC_ASSERTION_EXPIRED',
      message: 'This biometric verification is timestamped in the future. Check the device clock and try again.',
      nonceTrusted: true,
    };
  }

  if (success !== true) {
    return {
      ok: false,
      statusCode: 403,
      code: 'BIOMETRIC_VERIFICATION_FAILED',
      message: 'The device reported that local biometric verification did not succeed.',
      nonceTrusted: true,
    };
  }

  return {
    ok: true,
    verifiedAt: verifiedAtDate,
    nonce,
    nonceTrusted: true,
  };
}

/**
 * Build the permissions payload the client reads instead of hard-coding routes.
 *
 * @param {{ active: boolean, biometricEnabled: boolean, activatedAt?: Date|null }} input
 */
function buildEmergencyPermissions({ active, biometricEnabled, activatedAt = null }) {
  const activatedAtDate = active && activatedAt ? new Date(activatedAt) : null;

  return {
    active: active === true,
    biometricEnabled: biometricEnabled === true,
    actions: active === true ? [...EMERGENCY_ACTIONS] : [],
    activatedAt: activatedAtDate && Number.isFinite(activatedAtDate.getTime()) ? activatedAtDate.toISOString() : null,
    restrictedActionEndpoint: '/api/v1/emergency/restricted-action',
    lockEndpoint: '/api/v1/emergency/lock',
  };
}

/**
 * @param {{ ipAddress?: string|null, userAgent?: string|null }} request
 */
function auditRequestFields(request = {}) {
  return {
    ipAddress: request.ipAddress || null,
    userAgent: request.userAgent ? String(request.userAgent).slice(0, 512) : null,
  };
}

/**
 * Best-effort audit of a refused assertion. A failure to write this row must not
 * replace the real answer (401/409) with a 500, so it is swallowed after logging
 * by the caller — but it is never skipped for a rejection the signature proved
 * genuine.
 *
 * @param {object} entry
 */
async function recordRejectedAssertion(entry) {
  try {
    await AuditLog.record({
      ...entry,
      action: AUDIT_ACTIONS.BIOMETRIC_VERIFICATION_FAILED,
      deviceMetadata: { ...(entry.deviceMetadata || {}), biometricVerified: false },
    });
  } catch (error) {
    // A duplicate nonce here means the assertion was already burned. The caller
    // is about to answer 409 anyway; a second audit row would add nothing.
    if (error && error.code === 11_000) return;
    // Never mask the verification failure with an audit failure.
    // eslint-disable-next-line no-console
    console.warn(`[emergency] could not record a rejected biometric assertion: ${error.message}`);
  }
}

/**
 * Verify a signed biometric result and unlock emergency mode.
 *
 * @param {{
 *   userId: string,
 *   assertion: { success: boolean, verifiedAt: string, nonce: string, signature: string, deviceMetadata?: object },
 *   request?: { ipAddress?: string|null, userAgent?: string|null },
 * }} input
 */
async function activateEmergencyMode({ userId, assertion, request }) {
  const requestFields = auditRequestFields(request);
  const deviceMetadata = assertion.deviceMetadata || {};

  const verification = verifyAssertion({
    userId,
    success: assertion.success,
    verifiedAt: assertion.verifiedAt,
    nonce: assertion.nonce,
    signature: assertion.signature,
  });

  if (!verification.ok) {
    if (verification.statusCode === 503) {
      throw new ApiError(503, verification.message, {
        errors: [{ field: 'biometric', code: verification.code, message: verification.message }],
      });
    }

    await recordRejectedAssertion({
      userId,
      ...requestFields,
      // Only a signature-valid assertion may claim its nonce; otherwise an
      // attacker could burn arbitrary nonces with unsigned junk.
      assertionNonce: verification.nonceTrusted ? assertion.nonce : null,
      deviceMetadata,
      details: { reason: verification.code },
    });

    throw new ApiError(verification.statusCode, verification.message, {
      errors: [{ field: 'signature', code: verification.code, message: verification.message }],
    });
  }

  const user = await User.findById(userId)
    .select('_id isEmergencyMode biometricEnabled emergencyActivatedAt')
    .lean();

  if (!user) {
    throw ApiError.unauthorized('The account for this token no longer exists.');
  }

  const wasActive = user.isEmergencyMode === true;
  const activatedAt = wasActive && user.emergencyActivatedAt ? user.emergencyActivatedAt : new Date();

  let audit;

  try {
    audit = await AuditLog.record({
      userId,
      // First unlock and re-verification are genuinely different events: one
      // changed state, the other refreshed the biometric proof while already
      // unlocked. Both are worth answering "who was in emergency mode, and when".
      action: wasActive ? AUDIT_ACTIONS.BIOMETRIC_BYPASS_TRIGGERED : AUDIT_ACTIONS.EMERGENCY_MODE_UNLOCKED,
      ...requestFields,
      deviceMetadata: { ...deviceMetadata, biometricVerified: true },
      assertionNonce: assertion.nonce,
      details: { reason: wasActive ? 'BIOMETRIC_REVERIFIED' : 'BIOMETRIC_BYPASS' },
    });
  } catch (error) {
    if (error && error.code === 11_000) {
      throw new ApiError(409, 'This biometric verification has already been used. Verify again on your device.', {
        errors: [
          {
            field: 'nonce',
            code: 'BIOMETRIC_ASSERTION_REPLAYED',
            message: 'The signed biometric result was already accepted once and cannot be replayed.',
          },
        ],
      });
    }
    throw error;
  }

  // Audit first, state second: the immutable row is the evidence that the
  // assertion was accepted. If this write fails, the request fails and no
  // unaudited unlock exists.
  const updated = await User.findByIdAndUpdate(
    userId,
    {
      $set: {
        isEmergencyMode: true,
        biometricEnabled: true,
        emergencyActivatedAt: activatedAt,
      },
    },
    { returnDocument: 'after', runValidators: true }
  )
    .select('_id isEmergencyMode biometricEnabled emergencyActivatedAt')
    .lean();

  if (!updated) {
    throw ApiError.unauthorized('The account for this token no longer exists.');
  }

  return {
    user: {
      id: String(updated._id),
      isEmergencyMode: updated.isEmergencyMode === true,
      biometricEnabled: updated.biometricEnabled === true,
    },
    emergencyPermissions: buildEmergencyPermissions({
      active: updated.isEmergencyMode === true,
      biometricEnabled: updated.biometricEnabled === true,
      activatedAt: updated.emergencyActivatedAt,
    }),
    audit: {
      id: String(audit._id),
      action: audit.action,
      createdAt: audit.createdAt,
    },
    alreadyActive: wasActive,
  };
}

/**
 * Return the account to the normal state. Idempotent: locking an account that is
 * already locked is a success and writes no audit row (nothing changed).
 *
 * @param {{ userId: string, request?: object }} input
 */
async function deactivateEmergencyMode({ userId, request }) {
  const user = await User.findById(userId).select('_id isEmergencyMode biometricEnabled').lean();

  if (!user) {
    throw ApiError.unauthorized('The account for this token no longer exists.');
  }

  if (user.isEmergencyMode !== true) {
    return {
      user: {
        id: String(user._id),
        isEmergencyMode: false,
        biometricEnabled: user.biometricEnabled === true,
      },
      emergencyPermissions: buildEmergencyPermissions({
        active: false,
        biometricEnabled: user.biometricEnabled === true,
      }),
      audit: null,
      alreadyInactive: true,
    };
  }

  const audit = await AuditLog.record({
    userId,
    action: AUDIT_ACTIONS.EMERGENCY_MODE_LOCKED,
    ...auditRequestFields(request),
    details: { reason: 'USER_REQUESTED' },
  });

  const updated = await User.findByIdAndUpdate(
    userId,
    { $set: { isEmergencyMode: false, emergencyActivatedAt: null } },
    { returnDocument: 'after', runValidators: true }
  )
    .select('_id isEmergencyMode biometricEnabled')
    .lean();

  if (!updated) {
    throw ApiError.unauthorized('The account for this token no longer exists.');
  }

  return {
    user: {
      id: String(updated._id),
      isEmergencyMode: false,
      biometricEnabled: updated.biometricEnabled === true,
    },
    emergencyPermissions: buildEmergencyPermissions({
      active: false,
      biometricEnabled: updated.biometricEnabled === true,
    }),
    audit: {
      id: String(audit._id),
      action: audit.action,
      createdAt: audit.createdAt,
    },
    alreadyInactive: false,
  };
}

/**
 * Current server-authoritative emergency state for the caller.
 *
 * @param {{ userId: string }} input
 */
async function getEmergencyStatus({ userId }) {
  const user = await User.findById(userId)
    .select('_id isEmergencyMode biometricEnabled emergencyActivatedAt')
    .lean();

  if (!user) {
    throw ApiError.unauthorized('The account for this token no longer exists.');
  }

  return {
    user: {
      id: String(user._id),
      isEmergencyMode: user.isEmergencyMode === true,
      biometricEnabled: user.biometricEnabled === true,
    },
    emergencyPermissions: buildEmergencyPermissions({
      active: user.isEmergencyMode === true,
      biometricEnabled: user.biometricEnabled === true,
      activatedAt: user.emergencyActivatedAt,
    }),
  };
}

/**
 * Perform a route whose access is already gated by requireEmergencyMode.
 * The audit row is the point: it records that the high-stress permission was
 * actually exercised, by whom, from where.
 *
 * @param {{ userId: string, action: string, note?: string|null, request?: object, biometricEnabled?: boolean }} input
 */
async function performRestrictedAction({ userId, action, note = null, request, biometricEnabled = true }) {
  const performedAt = new Date();

  const audit = await AuditLog.record({
    userId,
    action: AUDIT_ACTIONS.RESTRICTED_ACTION_PERFORMED,
    ...auditRequestFields(request),
    details: {
      requestedAction: String(action).slice(0, 80),
      note: note ? String(note).slice(0, 280) : null,
    },
  });

  return {
    action,
    performedAt: performedAt.toISOString(),
    emergencyPermissions: buildEmergencyPermissions({ active: true, biometricEnabled: biometricEnabled === true }),
    audit: {
      id: String(audit._id),
      action: audit.action,
      createdAt: audit.createdAt,
    },
  };
}

module.exports = {
  CANONICAL_PREFIX,
  EMERGENCY_ACTIONS,
  canonicalAssertion,
  signAssertion,
  verifyAssertion,
  buildEmergencyPermissions,
  activateEmergencyMode,
  deactivateEmergencyMode,
  getEmergencyStatus,
  performRestrictedAction,
};
