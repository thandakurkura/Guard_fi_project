'use strict';

/**
 * GuardFi — OTP generation & hashing (Phase 2)
 *
 * Generation uses `crypto.randomInt`, not `Math.random`: a predictable OTP is
 * the whole attack. Hashing uses bcrypt so the plaintext code exists only in
 * the outgoing SMS and in the HTTP response of the development fallback — never
 * in the database, never in a log line.
 *
 * Timing note: bcrypt.compare against a *missing* hash returns immediately,
 * which would let an attacker distinguish "no OTP requested for this number"
 * from "wrong code". `getDummyOtpHash()` gives the service a real hash to
 * compare against on that path so both cases cost the same.
 */

const crypto = require('node:crypto');
const bcrypt = require('bcryptjs');
const { config } = require('../config/env');

/**
 * @param {number} [length] number of digits (4-8, see OTP_LENGTH)
 * @returns {string} zero-padded numeric code, uniformly distributed
 */
function generateOtp(length = config.otp.length) {
  const digits = Number.isInteger(length) && length >= 4 && length <= 8 ? length : 6;
  const upperBound = 10 ** digits;
  return String(crypto.randomInt(0, upperBound)).padStart(digits, '0');
}

/** @param {string} otp @returns {Promise<string>} bcrypt hash */
async function hashOtp(otp) {
  return bcrypt.hash(String(otp), config.otp.hashRounds);
}

/**
 * @param {string} otp candidate code
 * @param {string} hash stored hash
 * @returns {Promise<boolean>} true only on an exact match
 */
async function verifyOtpHash(otp, hash) {
  if (typeof hash !== 'string' || hash === '') return false;
  try {
    return await bcrypt.compare(String(otp), hash);
  } catch {
    // A malformed hash in the database must fail closed, never throw a 500.
    return false;
  }
}

/** @type {Promise<string>|null} */
let dummyHashPromise = null;

/**
 * A hash of a throwaway value, used to burn the same time as a real comparison
 * when no OTP exists for the requested number.
 * @returns {Promise<string>}
 */
function getDummyOtpHash() {
  if (!dummyHashPromise) dummyHashPromise = hashOtp('000000');
  return dummyHashPromise;
}

module.exports = { generateOtp, hashOtp, verifyOtpHash, getDummyOtpHash };
