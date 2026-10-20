'use strict';

/**
 * GuardFi — centralised error handling (global rule 3)
 *
 * One place translates every library-specific failure (Mongoose, JWT, Multer,
 * zod, body-parser) into the mandated envelope:
 *   { success: false, message: string, data: null, errors: array | null }
 */

const { config } = require('../config/env');
const logger = require('../utils/logger');
const ApiError = require('../utils/ApiError');

const MULTER_MESSAGES = Object.freeze({
  LIMIT_FILE_SIZE: 'The uploaded file exceeds the allowed size limit.',
  LIMIT_FILE_COUNT: 'Too many files were uploaded in one request.',
  LIMIT_UNEXPECTED_FILE: 'The upload contained an unexpected file field.',
  LIMIT_PART_COUNT: 'The upload contained too many parts.',
  LIMIT_FIELD_KEY: 'An uploaded field name is too long.',
  LIMIT_FIELD_VALUE: 'An uploaded field value is too long.',
  LIMIT_FIELD_COUNT: 'The upload contained too many fields.',
});

/**
 * Map any thrown value onto a safe, client-facing description.
 * @param {unknown} error
 */
function normaliseError(error) {
  if (error instanceof ApiError) {
    return {
      statusCode: error.statusCode,
      message: error.message,
      errors: error.errors,
      isOperational: error.isOperational,
    };
  }

  if (error && typeof error === 'object') {
    // --- zod -----------------------------------------------------------------
    if (error.name === 'ZodError' && Array.isArray(error.issues)) {
      return {
        statusCode: 400,
        message: 'Validation failed.',
        errors: error.issues.map((issue) => ({
          field: (issue.path || []).join('.') || null,
          code: issue.code || null,
          message: issue.message,
        })),
        isOperational: true,
      };
    }

    // --- body-parser (express.json) -----------------------------------------
    if (error.type === 'entity.parse.failed') {
      return { statusCode: 400, message: 'Request body is not valid JSON.', errors: null, isOperational: true };
    }
    if (error.type === 'entity.too.large') {
      return { statusCode: 413, message: 'Request body is too large.', errors: null, isOperational: true };
    }

    // --- Mongo duplicate key (E11000) ---------------------------------------
    if (error.code === 11_000 || error.code === 11_001) {
      const fields = Object.keys(error.keyValue || {});
      return {
        statusCode: 409,
        message:
          fields.length > 0
            ? `A record with this ${fields.join(', ')} already exists.`
            : 'This record conflicts with an existing one.',
        errors: fields.map((field) => ({ field, message: 'is already in use' })),
        isOperational: true,
      };
    }

    // --- Mongoose CastError (bad ObjectId / bad type) -----------------------
    if (error.name === 'CastError') {
      return {
        statusCode: 400,
        message: error.path ? `Invalid value for "${error.path}".` : 'Invalid value in the request.',
        errors: [
          {
            field: error.path || null,
            value: error.value === undefined ? null : error.value,
            message: `is not a valid ${error.kind || 'value'} for this field`,
          },
        ],
        isOperational: true,
      };
    }

    // --- Mongoose schema validation -----------------------------------------
    if (error.name === 'ValidationError' && error.errors && typeof error.errors === 'object') {
      return {
        statusCode: 400,
        message: 'Validation failed.',
        errors: Object.values(error.errors).map((detail) => ({
          field: detail.path || null,
          message: detail.message,
        })),
        isOperational: true,
      };
    }

    // --- jsonwebtoken -------------------------------------------------------
    if (error.name === 'TokenExpiredError') {
      return { statusCode: 401, message: 'Authentication token has expired.', errors: null, isOperational: true };
    }
    if (error.name === 'NotBeforeError') {
      return { statusCode: 401, message: 'Authentication token is not active yet.', errors: null, isOperational: true };
    }
    if (error.name === 'JsonWebTokenError') {
      return { statusCode: 401, message: 'Authentication token is invalid.', errors: null, isOperational: true };
    }

    // --- multer -------------------------------------------------------------
    if (error.name === 'MulterError' || (typeof error.code === 'string' && error.code.startsWith('LIMIT_'))) {
      return {
        statusCode: error.code === 'LIMIT_FILE_SIZE' ? 413 : 400,
        message: MULTER_MESSAGES[error.code] || 'The file upload was rejected.',
        errors: error.field ? [{ field: error.field, message: 'unexpected upload field' }] : null,
        isOperational: true,
      };
    }
  }

  // --- generic HTTP error carrying a status --------------------------------
  const declaredStatus = Number(error?.statusCode || error?.status);
  // A library that throws `{ statusCode: 200 }` (or 204, or 302) must not become
  // "HTTP 200 with success: false" — a success status carrying a failure body
  // breaks every client and hides the fault. Anything outside 4xx/5xx is not a
  // legitimate error status, so it collapses to 500.
  const explicitStatus =
    Number.isInteger(declaredStatus) && declaredStatus >= 400 && declaredStatus <= 599 ? declaredStatus : 500;

  return {
    statusCode: explicitStatus,
    message: (error && error.message) || 'Internal Server Error.',
    errors: null,
    isOperational: explicitStatus < 500,
  };
}

/** Query parameters whose values must never reach a log line. */
const SENSITIVE_QUERY_KEYS = Object.freeze([
  'phone',
  'otp',
  'token',
  'accesstoken',
  'access_token',
  'pin',
  'password',
  'secret',
  'apikey',
  'api_key',
  'fcmtoken',
]);

/**
 * Request URL with sensitive query values masked, for logging.
 *
 * The OTP routes take their data in the body, but nothing stops a client (or an
 * attacker probing for one) from sending `GET /anything?phone=%2B9198…`, and the
 * 404/error paths log the URL verbatim. That would write personal data into
 * every log line and into whatever log shipper consumes them.
 *
 * @param {string} url
 * @returns {string}
 */
function redactUrl(url) {
  if (typeof url !== 'string' || url === '') return '';

  const separator = url.indexOf('?');
  if (separator === -1) return url;

  const pathPart = url.slice(0, separator);
  const params = new URLSearchParams(url.slice(separator + 1));
  let redacted = false;

  for (const key of Array.from(params.keys())) {
    if (SENSITIVE_QUERY_KEYS.includes(key.toLowerCase())) {
      params.set(key, '***');
      redacted = true;
    }
  }

  return redacted ? `${pathPart}?${params.toString()}` : url;
}

/**
 * Express error middleware. Must keep all four parameters to be recognised.
 * @type {import('express').ErrorRequestHandler}
 */
// eslint-disable-next-line no-unused-vars
function errorMiddleware(error, req, res, next) {
  const { statusCode, message, errors, isOperational } = normaliseError(error);
  const context = `${req.method} ${redactUrl(req.originalUrl)} → ${statusCode}`;

  if (statusCode >= 500) {
    logger.error(`[error] ${context} ${message}`, error);
  } else {
    logger.warn(`[error] ${context} ${message}`);
  }

  // A response already started (e.g. the stream broke mid-send): hand back to
  // Express so it can destroy the socket rather than throwing headers-sent.
  if (res.headersSent) return next(error);

  const hideDetails = statusCode >= 500 && config.isProduction;
  const safeMessage = hideDetails ? 'Something went wrong on our side.' : message;

  // Verbose diagnostics for unexpected 5xx during development only. They are
  // APPENDED to the declared errors, never substituted for them: the declared
  // list carries the machine-readable codes a client acts on (503
  // SCAM_BUSTER_NOT_CONFIGURED, 504 AI_TIMEOUT, …), and replacing it with a
  // stack in development — while production kept the codes — meant the feature
  // was easiest to debug exactly where it was hardest to see.
  let safeErrors = errors;
  if (!hideDetails && statusCode >= 500 && error instanceof Error) {
    safeErrors = [
      ...(Array.isArray(errors) ? errors : []),
      {
        diagnostic: true,
        message: error.message,
        stack: error.stack ? error.stack.split('\n').slice(0, 6) : null,
      },
    ];
  }

  res.set('Cache-Control', 'no-store');

  return res.status(statusCode).json({
    success: false,
    message: safeMessage,
    data: null,
    errors: safeErrors || null,
  });
}

/** Terminal 404 handler — runs only when no route matched. */
function notFoundHandler(req, res) {
  const safeUrl = redactUrl(req.originalUrl);

  logger.debug(`[404] ${req.method} ${safeUrl}`);

  res.set('Cache-Control', 'no-store');

  return res.status(404).json({
    success: false,
    message: `Route ${req.method} ${safeUrl} was not found on this server.`,
    data: null,
    errors: null,
  });
}

module.exports = { errorMiddleware, notFoundHandler, normaliseError, redactUrl };
