'use strict';

/**
 * GuardFi — async error wrapper.
 *
 * Wraps an async controller/middleware so a rejected promise is forwarded to
 * Express' error pipeline instead of becoming an unhandled rejection that
 * kills the Node process.
 *
 * @template {import('express').RequestHandler} T
 * @param {T} fn
 * @returns {import('express').RequestHandler}
 */
function asyncHandler(fn) {
  if (typeof fn !== 'function') {
    throw new TypeError('asyncHandler() expects a function.');
  }

  return function wrappedHandler(req, res, next) {
    try {
      const result = fn(req, res, next);
      // Only real thenables are awaited; sync handlers keep their normal return.
      if (result && typeof result.then === 'function') {
        result.catch(next);
      }
    } catch (error) {
      next(error);
    }
  };
}

module.exports = asyncHandler;
