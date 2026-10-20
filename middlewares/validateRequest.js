'use strict';

/**
 * GuardFi — request validation middleware (Phase 2, global rule 5)
 *
 * Every handler validates its `body` / `params` / `query` against a zod schema
 * BEFORE a Mongoose query runs, so bad input becomes a clean 400 envelope with
 * per-field messages instead of a CastError, a 500, or a partially applied
 * write.
 *
 * Express 5 trap this module exists to avoid: `req.query` is a **getter-only**
 * property. `req.query = parsed` throws (or silently does nothing in sloppy
 * mode) while `req.body = parsed` is fine. Validated query data is therefore
 * published as `req.validatedQuery`, and `req.params` / `req.body` are replaced
 * in place with the parsed value so controllers keep the obvious names.
 *
 * Unknown keys are stripped by zod's object schema, which also protects against
 * mass-assignment through extra JSON fields.
 */

const ApiError = require('../utils/ApiError');

/**
 * @param {import('zod').ZodError} error
 * @param {string} source
 * @returns {{ field: string, code: string, message: string }[]}
 */
function toFieldErrors(error, source) {
  return (error?.issues ?? []).map((issue) => ({
    field: issue.path && issue.path.length > 0 ? issue.path.join('.') : source,
    code: issue.code || 'invalid',
    message: issue.message,
  }));
}

/**
 * @param {{ body?: import('zod').ZodTypeAny, params?: import('zod').ZodTypeAny, query?: import('zod').ZodTypeAny }} schemas
 * @returns {import('express').RequestHandler}
 */
function validateRequest(schemas) {
  if (!schemas || typeof schemas !== 'object' || Object.keys(schemas).length === 0) {
    throw new TypeError('validateRequest() needs at least one of: body, params, query.');
  }

  return function validate(req, res, next) {
    /** @type {{ field: string, code: string, message: string }[]} */
    const issues = [];

    if (schemas.body) {
      // Express 5 leaves req.body undefined when no parser matched the request
      // (for example a missing Content-Type). Validate {} so the caller still
      // gets "phone is required" instead of "expected object, received undefined".
      const input = req.body === undefined || req.body === null ? {} : req.body;
      const result = schemas.body.safeParse(input);

      if (result.success) {
        req.body = result.data;
      } else {
        issues.push(...toFieldErrors(result.error, 'body'));
      }
    }

    if (schemas.params) {
      const result = schemas.params.safeParse(req.params || {});

      if (result.success) {
        req.params = result.data;
      } else {
        issues.push(...toFieldErrors(result.error, 'params'));
      }
    }

    if (schemas.query) {
      const result = schemas.query.safeParse(req.query || {});

      if (result.success) {
        // NOT req.query = … — see the note at the top of this file.
        req.validatedQuery = result.data;
      } else {
        issues.push(...toFieldErrors(result.error, 'query'));
      }
    }

    if (issues.length > 0) {
      return next(ApiError.badRequest('Validation failed.', issues));
    }

    return next();
  };
}

module.exports = { validateRequest, toFieldErrors };
