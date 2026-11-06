'use strict';

/**
 * GuardFi — phone number normalisation (Phase 2)
 *
 * The phone number is the account identity, so it must have exactly one
 * spelling in the database. Everything a user (or the Flutter client) might
 * type is funnelled into E.164 here, and nothing else in the codebase is
 * allowed to format a phone number.
 *
 * Accepted → E.164 with DEFAULT_PHONE_COUNTRY_CODE (91 by default):
 *   "+91 98765 43210" → "+919876543210"
 *   "09876543210"     → "+919876543210"   (national trunk prefix dropped)
 *   "9876543210"      → "+919876543210"   (10-digit national number)
 *   "919876543210"    → "+919876543210"   (already carries the country code)
 *   "00919876543210"  → "+919876543210"   (00 international prefix)
 *   "+14155552671"    → "+14155552671"    (any other country is left alone)
 *
 * Rejected: empty, letters, punctuation-only, too short, too long, a "+" that
 * is not leading. Returning null (never throwing) keeps callers simple; the zod
 * schema turns null into a field-level 400.
 *
 * A bare number must be a national number: 10 digits, or the default country
 * code followed by those 10 digits. Anything else is rejected, even when it is
 * 11-15 digits and could be read as "+98…". That reading is how a mistyped
 * Indian mobile (one extra digit) silently became an Iranian number in Phase 3
 * verification — and a guardian who never receives the SOS is a safety failure,
 * not a cosmetic one. Callers outside the default country must send a leading
 * "+", which is unambiguous.
 */

const { config } = require('../config/env');

/** E.164: a leading +, a non-zero country code, 8-15 digits in total. */
const E164_REGEX = /^\+[1-9]\d{7,14}$/;

/** Separators people actually type: spaces, dashes, dots, parentheses, slashes. */
const SEPARATORS_REGEX = /[\s\-.()/\u2010-\u2015]/g;

/** 
 * @param {unknown} value raw user input
 * @returns {string|null} E.164 number, or null when the input is not a number
 */
function normalizePhone(value) {
  if (value === null || value === undefined) return null;

  let raw;
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || !Number.isInteger(value)) return null;
    raw = String(value);
  } else if (typeof value === 'string') {
    raw = value;
  } else {
    return null;
  }

  let digits = raw.replace(SEPARATORS_REGEX, '').trim();
  if (digits === '') return null;

  // 00 is the international dialling prefix in most of the world: 00 91 … === +91 …
  if (digits.startsWith('00')) digits = `+${digits.slice(2)}`;

  const countryCode = config.phone.defaultCountryCode;

  if (digits.startsWith('+')) {
    return finalize(digits);
  }

  // Local part only: drop the national trunk prefix ("0") before deciding.
  const national = digits.replace(/^0+/, '');
  if (national === '' || !/^\d+$/.test(national)) return null;

  if (national.length === 10) {
    return finalize(`+${countryCode}${national}`);
  }

  if (national.length === 10 + countryCode.length && national.startsWith(countryCode)) {
    return finalize(`+${national}`);
  }

  // Deliberately no "any 11-15 digit number includes its country code" branch:
  // that guess turns a one-digit typo into a valid-looking foreign number. A
  // user outside the default country sends "+<cc><number>" instead.
  return null;
}

/**
 * @param {string} value candidate E.164 string
 * @returns {string|null} the number, or null when it is not valid E.164
 */
function finalize(value) {
  const candidate = value.trim();
  if (!/^\+\d+$/.test(candidate)) return null;
  if (!E164_REGEX.test(candidate)) return null;
  return candidate;
}

/** @param {unknown} value */
function isE164(value) {
  return typeof value === 'string' && E164_REGEX.test(value);
}

/**
 * Hide most of a number for logs and API messages: "+919876543210" → "+91****3210".
 * NEVER put a full phone number in a log line — it is personal data.
 * @param {string} phone
 */
function maskPhone(phone) {
  const value = String(phone ?? '');
  if (value.length <= 4) return '*'.repeat(value.length);
  const visibleHead = value.startsWith('+') ? Math.min(3, value.length - 4) : 0;
  const head = value.slice(0, visibleHead);
  const tail = value.slice(-4);
  return `${head}${'*'.repeat(Math.max(0, value.length - visibleHead - 4))}${tail}`;
}

module.exports = { normalizePhone, isE164, maskPhone, E164_REGEX };
