'use strict';

/**
 * GuardFi — shared error type.
 *
 * Every thrown error that should reach the client with a specific status code
 * is an ApiError. Anything else is treated as an unexpected 500 by
 * middlewares/errorMiddleware.js, which hides internals in production.
 */

class ApiError extends Error {
  /**
   * @param {number} statusCode HTTP status to send.
   * @param {string} message Safe, client-facing message.
   * @param {{ errors?: Array<object>|null, code?: string, isOperational?: boolean }} [options]
   */
  constructor(statusCode, message, options = {}) {
    super(message);

    this.name = 'ApiError';
    this.statusCode = Number(statusCode) || 500;
    this.errors = options.errors ?? null;
    this.isOperational = options.isOperational ?? true;
    if (options.code !== undefined) this.code = options.code;

    Error.captureStackTrace(this, ApiError);
  }

  static badRequest(message = 'Bad request.', errors = null) {
    return new ApiError(400, message, { errors });
  }

  static unauthorized(message = 'Authentication is required.') {
    return new ApiError(401, message);
  }

  static forbidden(message = 'You are not allowed to perform this action.') {
    return new ApiError(403, message);
  }

  static notFound(message = 'The requested resource was not found.') {
    return new ApiError(404, message);
  }

  static conflict(message = 'The request conflicts with the current state of the resource.', errors = null) {
    return new ApiError(409, message, { errors });
  }

  static payloadTooLarge(message = 'The uploaded payload is too large.') {
    return new ApiError(413, message);
  }

  static tooManyRequests(message = 'Too many requests. Please try again later.') {
    return new ApiError(429, message);
  }

  static internal(message = 'Something went wrong on our side.', options = {}) {
    return new ApiError(500, message, { ...options, isOperational: false });
  }

  static serviceUnavailable(message = 'A required upstream service is unavailable.') {
    return new ApiError(503, message);
  }
}

module.exports = ApiError;
