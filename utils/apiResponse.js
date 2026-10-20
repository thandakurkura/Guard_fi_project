'use strict';

/**
 * GuardFi — response envelope helpers.
 *
 * Every successful response uses exactly this shape so the Flutter client can
 * parse one structure forever:
 *   { success: boolean, message: string, data: object|null, errors: array|null }
 */

/**
 * @param {import('express').Response} res
 * @param {{ statusCode?: number, message?: string, data?: unknown }} [options]
 */
function sendSuccess(res, options = {}) {
  const { statusCode = 200, message = 'OK', data = null } = options;

  // API responses are per-user data; never let a proxy or the client cache them.
  res.set('Cache-Control', 'no-store');

  return res.status(statusCode).json({
    success: true,
    message,
    data,
    errors: null,
  });
}

/**
 * Build the error envelope without sending it (used by errorMiddleware).
 *
 * @param {{ message?: string, data?: unknown, errors?: Array<object>|null }} [options]
 */
function buildErrorEnvelope(options = {}) {
  const { message = 'Request failed.', data = null, errors = null } = options;
  return { success: false, message, data, errors };
}

module.exports = { sendSuccess, buildErrorEnvelope };
