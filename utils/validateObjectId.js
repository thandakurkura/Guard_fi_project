'use strict';

/**
 * GuardFi — ObjectId guard (global rule 5).
 *
 * Route params are attacker controlled. Checking them before they reach a
 * Mongoose query means an invalid id returns a clean 400 instead of a
 * CastError bubbling out of the driver.
 */

const mongoose = require('mongoose');
const ApiError = require('./ApiError');

const HEX_24 = /^[0-9a-fA-F]{24}$/;

/**
 * True only for a genuine 24-character hex ObjectId.
 * Rejects ObjectId instances of the wrong length, numbers, null and arrays.
 * @param {unknown} value
 */
function isValidObjectId(value) {
  if (value === null || value === undefined) return false;
  if (Array.isArray(value)) return false;

  let candidate;

  if (typeof value === 'string') candidate = value;
  else if (value instanceof mongoose.Types.ObjectId) candidate = value.toHexString();
  else if (typeof value === 'object' && typeof value.toHexString === 'function') candidate = value.toHexString();
  else return false;

  if (!HEX_24.test(candidate)) return false;
  return mongoose.Types.ObjectId.isValid(candidate);
}

/**
 * Throws ApiError(400) unless `value` is a valid ObjectId.
 * @returns {string} the normalised lowercase hex id
 */
function assertValidObjectId(value, fieldName = 'id') {
  if (!isValidObjectId(value)) {
    throw ApiError.badRequest(`"${fieldName}" must be a valid 24-character MongoDB ObjectId.`);
  }

  return (typeof value === 'string' ? value : value.toHexString()).toLowerCase();
}

module.exports = { isValidObjectId, assertValidObjectId };
