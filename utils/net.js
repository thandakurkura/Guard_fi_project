'use strict';

/**
 * GuardFi — network address helpers (Phase 2 hardening)
 *
 * Used to decide whether an incoming request came from the local machine, a
 * LAN/emulator address, or the open internet. The answer changes how loudly the
 * development OTP fallback should shout: handing a live OTP to a request from
 * the public internet is account takeover, while doing it for `127.0.0.1` or an
 * Android emulator is just normal local testing.
 *
 * Deliberately conservative: anything not provably private is treated as
 * public, so an unparseable address never gets the quiet path.
 */

/** IPv4 ranges that are not publicly routable. */
const PRIVATE_IPV4_PATTERNS = Object.freeze([
  /^10\./, // 10.0.0.0/8      (also covers the 10.0.2.2 Android emulator alias)
  /^127\./, // 127.0.0.0/8    loopback
  /^169\.254\./, // 169.254.0.0/16 link-local
  /^192\.168\./, // 192.168.0.0/16
  /^172\.(1[6-9]|2\d|3[01])\./, // 172.16.0.0/12
]);

/**
 * Strip the decorations a socket address can carry: IPv4-mapped IPv6
 * ("::ffff:127.0.0.1"), brackets, surrounding whitespace.
 * @param {unknown} ip
 * @returns {string}
 */
function normalizeAddress(ip) {
  if (typeof ip !== 'string') return '';

  let value = ip.trim().toLowerCase();

  if (value === '::1' || value === '0:0:0:0:0:0:0:1') return '::1';
  if (value.startsWith('::ffff:')) value = value.slice('::ffff:'.length);
  if (value === 'localhost') return '127.0.0.1';
  if (value.startsWith('[') && value.endsWith(']')) value = value.slice(1, -1);

  return value;
}

/**
 * @param {unknown} ip
 * @returns {boolean} true only for addresses that are provably not public
 */
function isPrivateAddress(ip) {
  const value = normalizeAddress(ip);

  if (value === '') return false;
  if (value === '::1') return true;
  if (value.startsWith('fe80:')) return true; // link-local IPv6
  if (value.startsWith('fc') || value.startsWith('fd')) return true; // unique local IPv6

  return PRIVATE_IPV4_PATTERNS.some((pattern) => pattern.test(value));
}

module.exports = { isPrivateAddress, normalizeAddress };
