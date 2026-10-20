'use strict';

/**
 * GuardFi — Shield Pay risk engine (Phase 6)
 *
 * One question, answered in two stages: "is this payee a known scam, and if we
 * do not know them, does anything about them smell wrong?"
 *
 *   1. BLOCKLIST — one indexed equality lookup (`identifier` unique B-tree).
 *      A curated row decides, and its own bilingual reason is used, so the
 *      warning explains THIS scam rather than a generic paragraph.
 *
 *   2. HEURISTICS — only for identifiers with no row. Pattern checks for the
 *      three shapes the API accepts (UPI VPA, link, phone) score 0-100, and the
 *      score is CAPPED at 69 so heuristics can warn but can never condemn:
 *      "danger" is reserved for community reports, and a false "Fraud Alert"
 *      on a legitimate payee is how users learn to ignore the real ones.
 *
 * STATE — the "Proceed Anyway" contract lives here, not in the client:
 *   • /check-upi writes a PENDING TransactionAudit when the verdict is not SAFE
 *     and hands back its `checkId`;
 *   • /proceed-transaction re-evaluates the payee (never trusting a client
 *     verdict), refuses a reported payee without `riskAccepted: true`, and then
 *     atomically CONSUMES the exact pending check — so a warning cannot be
 *     replayed, borrowed from another account, moved to another payee, or used
 *     after it expired.
 *
 * Normalisation is deliberately strict and mirrored by the model: a scammer
 * must not be able to defeat the blocklist with Caps Lock, a trailing slash, an
 * extra space, or by pasting the whole `upi://pay?pa=…` QR payload instead of
 * the bare VPA.
 */

const bcrypt = require('bcryptjs');
const { config } = require('../config/env');
const ApiError = require('../utils/ApiError');
const { assertValidObjectId } = require('../utils/validateObjectId');
const { isE164, normalizePhone } = require('../utils/phone');
const FlaggedEntity = require('../models/FlaggedEntity');
const TransactionAudit = require('../models/TransactionAudit');
const { ENTITY_TYPES, RISK_LEVELS } = require('../models/FlaggedEntity');
const { FAILURE_REASONS, STATUSES } = require('../models/TransactionAudit');
const User = require('../models/User');
const { composeVerdict, messageFor } = require('./shieldPayMessages');

// ===========================================================================
// Scoring constants
// ===========================================================================
const SCORES = Object.freeze({
  UNKNOWN: 10,
  UNKNOWN_HANDLE: 15,
  LOOKALIKE_HANDLE: 30,
  SCAM_KEYWORDS: 35,
  SCAM_KEYWORDS_MULTI: 50,
  NUMERIC_NAME: 10,
  RISKY_TLD: 25,
  RAW_IP_HOST: 30,
  HIDDEN_DESTINATION: 30,
  INSECURE_HTTP: 10,
  URL_WORDS: 30,
  URL_WORDS_MULTI: 45,

  /** Heuristics may reach "suspicious" but never "danger" (threshold is 70). */
  HEURISTIC_CAP: 69,

  REPORTED_DANGER_BASE: 70,
  REPORTED_DANGER_CAP: 95,
  REPORTED_SUSPICIOUS_BASE: 40,
  REPORTED_SUSPICIOUS_CAP: 69,
});

/** Report-count → score bump: every 8 reports adds a point, capped by the level. */
const REPORTS_PER_POINT = 8;

/**
 * Handles that really belong to a regulated payment provider. A VPA outside
 * this list is only mildly suspicious (new PSPs and bank-specific handles are
 * legitimate); it raises the score but never on its own crosses the threshold.
 */
const KNOWN_UPI_HANDLES = new Set([
  'ybl', 'ibl', 'axl', 'apl', 'paytm', 'okaxis', 'oksbi', 'okhdfcbank', 'okicici', 'okidfcbank',
  'upi', 'airtel', 'jio', 'freecharge', 'axisb', 'idfcbank', 'rbl', 'pnb', 'barodampay', 'cnrb',
  'kotak', 'yesbank', 'hsbc', 'icici', 'sbi', 'hdfcbank', 'fbl', 'indus', 'uco', 'utbi', 'dbs',
  'aubank', 'fino', 'bandhan', 'payu', 'slice', 'naviaxis', 'timecosmos', 'waaxis', 'waicici',
  'wasbi', 'wpaytm', 'yapl', 'pthdfc', 'abfspay', 'jkb', 'kbl', 'tjsb', 'federal', 'equitas',
  'sib', 'scb', 'citi', 'amex', 'bob', 'unionbank', 'idbi', 'centralbank', 'psb', 'ippb',
  'nsdl', 'razorpay', 'cashfree', 'phonepe', 'gpay',
]);

/** Words that appear in fake "help"/"refund"/"prize" VPAs. */
const SCAM_KEYWORDS = Object.freeze([
  'kyc', 'refund', 'lottery', 'prize', 'cashback', 'offer', 'winner', 'reward', 'lucky',
  'bonus', 'helpline', 'support', 'verify', 'verification', 'urgent', 'blocked', 'suspend',
  'expire', 'loan', 'insurance', 'policy', 'recharge', 'electricity', 'gas', 'bill', 'army',
  'canteen', 'job', 'commission', 'gift', 'free', 'claim', 'update',
]);

/** Words that appear on cloned bank / wallet pages. */
const URL_KEYWORDS = Object.freeze([
  'login', 'signin', 'sign-in', 'verify', 'verification', 'kyc', 'otp', 'refund', 'secure',
  'update', 'account', 'netbanking', 'net-banking', 'wallet', 'prize', 'lottery', 'free',
  'bonus', 'gift', 'offer', 'support', 'help', 'customer', 'care', 'alert', 'blocked',
  'suspend', 'expired', 're-kyc', 'reward', 'claim',
]);

/**
 * TLDs that are cheap (or free) to register and therefore over-represented in
 * phishing campaigns. Not every use is malicious — this is one signal of five.
 */
const RISKY_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'click', 'work', 'loan', 'zip', 'mov',
  'rest', 'quest', 'monster', 'sbs', 'icu', 'cam', 'cyou', 'look', 'shop',
]);

/** Classic PINs people pick and attackers try first. */
const WEAK_PINS = new Set([
  '1234', '12345', '123456', '654321', '1111', '11111', '111111', '0000', '00000', '000000',
  '2222', '3333', '4444', '5555', '6666', '7777', '8888', '9999', '1212', '2121', '1010',
  '1122', '4321', '6969', '2580', '1478', '0852', '1590', '123123', '112233', '121212',
]);

// ===========================================================================
// Identifier normalisation
// ===========================================================================

/**
 * Decide what the user pasted and reduce it to its canonical, comparable form.
 *
 * @param {unknown} raw
 * @returns {{
 *   identifier: string,
 *   identifierType: 'UPI'|'URL'|'PHONE',
 *   candidates: string[],
 *   details: { name?: string, handle?: string, host?: string, path?: string, query?: string, protocol?: string|null, hasUserinfo?: boolean }
 * }}
 */
function normalizeIdentifierInput(raw) {
  const value = String(raw ?? '').trim();

  if (value === '') throw ApiError.badRequest('identifier is required.');
  if (value.length > 200) throw ApiError.badRequest('identifier cannot exceed 200 characters.');
  if (/[\u0000-\u001F\u007F]/.test(value)) {
    throw ApiError.badRequest('identifier cannot contain control characters.');
  }

  // A QR payload like "upi://pay?pa=name@bank&pn=Store" — the only part that
  // matters is the payee address. Percent-encoding is decoded by URLSearchParams.
  if (/^upi:\/\//i.test(value)) {
    const payee = extractUpiPayee(value);
    if (!payee) {
      throw ApiError.badRequest('The UPI payment link has no payee (pa=) parameter.');
    }
    return buildUpi(payee);
  }

  if (/^https?:\/\//i.test(value)) return buildUrl(value, true);
  if (value.includes('@')) return buildUpi(value);

  // Phone before link: "+91 98123 45678" must not be read as a hostname.
  if (/^\+?[\d][\d\s().-]{7,}$/.test(value)) return buildPhone(value);

  if (value.includes('.')) return buildUrl(value, false);

  throw ApiError.badRequest(
    'identifier must be a UPI ID (name@provider), a payment link, or a phone number.'
  );
}

/** @param {string} value */
function extractUpiPayee(value) {
  const queryStart = value.indexOf('?');
  if (queryStart === -1) return null;

  try {
    const params = new URLSearchParams(value.slice(queryStart + 1));
    return params.get('pa');
  } catch {
    return null;
  }
}

/** @param {string} payee */
function buildUpi(payee) {
  const identifier = String(payee).trim().toLowerCase().replace(/\s+/g, '');

  if (!/^[^\s@]+@[^\s@]+$/.test(identifier) || identifier.length < 3) {
    throw ApiError.badRequest('A UPI ID must look like name@provider.');
  }

  const [name, handle] = identifier.split('@');

  return {
    identifier,
    identifierType: ENTITY_TYPES.UPI,
    candidates: [identifier],
    details: { name, handle },
  };
}

/**
 * @param {string} raw
 * @param {boolean} hadScheme whether the caller's text actually carried http(s)://
 */
function buildUrl(raw, hadScheme) {
  let url;

  try {
    url = new URL(hadScheme ? raw : `http://${raw}`);
  } catch {
    throw ApiError.badRequest('identifier is not a valid payment link.');
  }

  const host = url.hostname.toLowerCase().replace(/^www\./, '');
  const path = url.pathname.replace(/\/+$/, '');
  const query = url.search || '';

  // Query strings are per-campaign junk ("?ref=9281"), so they are kept out of
  // the lookup key but still scanned for keywords below.
  const identifier = `${host}${path}`.toLowerCase();

  return {
    identifier,
    identifierType: ENTITY_TYPES.URL,
    // Look the full path up first, then the bare host, so a curated host entry
    // still catches "evil.xyz/anything?x=1".
    candidates: identifier === host ? [host] : [identifier, host],
    details: {
      host,
      path: path.toLowerCase(),
      query: query.toLowerCase(),
      protocol: hadScheme ? url.protocol : null,
      hasUserinfo: url.username !== '' || url.password !== '',
    },
  };
}

/**
 * Phone shapes are the one place where "just strip the punctuation" is wrong:
 * "0987654321" is a national number, "0091 98765 43210" is international, and
 * "9876543210" is neither until a country code is assumed. utils/phone.js
 * already solves exactly this for account identity, so it is reused here rather
 * than re-implemented — one rule for what a phone number is, everywhere.
 *
 * @param {string} raw
 */
function buildPhone(raw) {
  const e164 = normalizePhone(raw);

  if (!e164 || !isE164(e164)) {
    throw ApiError.badRequest('identifier is not a valid phone number.');
  }

  // Both spellings, so a curated entry stored either way still matches.
  return {
    identifier: e164,
    identifierType: ENTITY_TYPES.PHONE,
    candidates: [e164, e164.slice(1)],
    details: {},
  };
}

// ===========================================================================
// Risk evaluation
// ===========================================================================

/** @param {string} code @param {number} weight */
function flag(code, weight) {
  const text = messageFor(code);
  return { code, weight, msg_en: text.en, msg_hi: text.hi };
}

/**
 * Evaluate one normalised identifier: blocklist first, heuristics only when the
 * blocklist has nothing to say.
 *
 * @param {ReturnType<typeof normalizeIdentifierInput>} input
 */
async function evaluateRisk(input) {
  const rows = await FlaggedEntity.find({ identifier: { $in: input.candidates } }).lean();

  if (rows.length > 0) return verdictFromEntity(pickMostSevere(rows, input.candidates), input);
  return heuristicVerdict(input);
}

const SEVERITY_RANK = Object.freeze({ SAFE: 1, SUSPICIOUS: 2, DANGER: 3 });

/**
 * Worst verdict wins, and an exact-identifier match breaks a tie. Contradictory
 * rows (a whitelisted host with a reported path, say) must fail safe — the user
 * is about to send money, so the scarier of two curated opinions is the one
 * they should see.
 */
function pickMostSevere(rows, candidates) {
  return [...rows].sort((a, b) => {
    const bySeverity = SEVERITY_RANK[b.riskLevel] - SEVERITY_RANK[a.riskLevel];
    if (bySeverity !== 0) return bySeverity;
    return candidates.indexOf(a.identifier) - candidates.indexOf(b.identifier);
  })[0];
}

function verdictFromEntity(entity, input) {
  const reports = Math.max(0, Math.floor(Number(entity.reportCount) || 0));
  const bump = Math.floor(reports / REPORTS_PER_POINT);

  let riskScore;
  let status;
  let reasonCode;

  if (entity.riskLevel === RISK_LEVELS.DANGER) {
    riskScore = Math.min(SCORES.REPORTED_DANGER_CAP, SCORES.REPORTED_DANGER_BASE + bump);
    status = 'danger';
    reasonCode = 'REPORTED_DANGER';
  } else if (entity.riskLevel === RISK_LEVELS.SUSPICIOUS) {
    riskScore = Math.min(SCORES.REPORTED_SUSPICIOUS_CAP, SCORES.REPORTED_SUSPICIOUS_BASE + bump);
    status = 'suspicious';
    reasonCode = 'REPORTED_SUSPICIOUS';
  } else {
    riskScore = 0;
    status = 'safe';
    reasonCode = 'VERIFIED_SAFE';
  }

  const { msg_en, msg_hi } = composeVerdict(entity.riskLevel, entity);
  const reasonText = messageFor(reasonCode);

  return {
    identifier: input.identifier,
    identifierType: input.identifierType,
    status,
    riskLevel: entity.riskLevel,
    riskScore,
    reportCount: reports,
    matchedBy: 'flagged_entity',
    matchedIdentifier: entity.identifier,
    reasonCode,
    flags: [{ code: reasonCode, msg_en: reasonText.en, msg_hi: reasonText.hi }],
    msg_en,
    msg_hi,
  };
}

function heuristicVerdict(input) {
  const flags = [];

  if (input.identifierType === ENTITY_TYPES.UPI) flags.push(...upiFlags(input.details));
  else if (input.identifierType === ENTITY_TYPES.URL) flags.push(...urlFlags(input.details));

  const base = flag(
    input.identifierType === ENTITY_TYPES.PHONE ? 'UNKNOWN_PHONE' : 'UNKNOWN_IDENTIFIER',
    SCORES.UNKNOWN
  );

  const all = [base, ...flags];
  const rawScore = all.reduce((total, entry) => total + entry.weight, 0);
  const riskScore = Math.min(SCORES.HEURISTIC_CAP, rawScore);

  const thresholds = config.shieldPay;
  let status =
    riskScore >= thresholds.dangerThreshold
      ? 'danger'
      : riskScore >= thresholds.suspiciousThreshold
        ? 'suspicious'
        : 'safe';

  // Belt and braces with the cap above: no combination of pattern checks may
  // ever produce the "Fraud Alert" level. Only a reported entity can.
  if (status === 'danger') status = 'suspicious';

  const primary = all.reduce((worst, entry) => (entry.weight > worst.weight ? entry : worst), all[0]);
  const { msg_en, msg_hi } = composeVerdict(status.toUpperCase(), {
    reason_en: primary.msg_en,
    reason_hi: primary.msg_hi,
  });

  return {
    identifier: input.identifier,
    identifierType: input.identifierType,
    status,
    riskLevel: status.toUpperCase(),
    riskScore,
    reportCount: 0,
    matchedBy: 'heuristics',
    matchedIdentifier: null,
    reasonCode: primary.code,
    flags: all.map((entry) => ({ code: entry.code, msg_en: entry.msg_en, msg_hi: entry.msg_hi })),
    msg_en,
    msg_hi,
  };
}

function upiFlags({ name = '', handle = '' }) {
  const flags = [];

  if (!KNOWN_UPI_HANDLES.has(handle)) {
    const lookalike = isLookalikeHandle(handle);
    flags.push(
      flag(
        lookalike ? 'LOOKALIKE_UPI_HANDLE' : 'UNKNOWN_UPI_HANDLE',
        lookalike ? SCORES.LOOKALIKE_HANDLE : SCORES.UNKNOWN_HANDLE
      )
    );
  }

  const keywords = matchedKeywords(name, SCAM_KEYWORDS);
  if (keywords.length > 0) {
    flags.push(flag('SCAM_KEYWORDS', keywords.length >= 2 ? SCORES.SCAM_KEYWORDS_MULTI : SCORES.SCAM_KEYWORDS));
  }

  if (/^\d{10,}$/.test(name.replace(/[.\-_]/g, ''))) {
    flags.push(flag('NUMERIC_UPI_NAME', SCORES.NUMERIC_NAME));
  }

  return flags;
}

function urlFlags({ host = '', path = '', query = '', protocol = null, hasUserinfo = false }) {
  const flags = [];
  const tld = host.split('.').pop();

  if (RISKY_TLDS.has(tld)) flags.push(flag('RISKY_TLD', SCORES.RISKY_TLD));
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) flags.push(flag('RAW_IP_HOST', SCORES.RAW_IP_HOST));
  if (hasUserinfo || host.includes('xn--')) flags.push(flag('HIDDEN_DESTINATION', SCORES.HIDDEN_DESTINATION));
  if (protocol === 'http:') flags.push(flag('INSECURE_HTTP', SCORES.INSECURE_HTTP));

  const keywords = matchedKeywords(`${host}${path}${query}`, URL_KEYWORDS);
  if (keywords.length > 0) {
    flags.push(flag('SUSPICIOUS_URL_WORDS', keywords.length >= 2 ? SCORES.URL_WORDS_MULTI : SCORES.URL_WORDS));
  }

  return flags;
}

/** @returns {string[]} which keywords matched (distinct) */
function matchedKeywords(text, keywords) {
  return keywords.filter((keyword) => text.includes(keyword));
}

/**
 * True when a handle is a near-miss of a real provider handle: "@ybi" for
 * "@ybl", "paytmofficial" for "paytm". Short handles only match on one edit
 * (otherwise every 3-letter handle would look like every other one).
 */
function isLookalikeHandle(handle) {
  for (const known of KNOWN_UPI_HANDLES) {
    if (handle === known) return false;
    if (handle.length >= 5 && handle.includes(known)) return true;
    if (editDistanceAtMostOne(handle, known)) return true;
  }
  return false;
}

function editDistanceAtMostOne(a, b) {
  if (a === b) return true;
  if (Math.abs(a.length - b.length) > 1) return false;

  if (a.length === b.length) {
    let mismatches = 0;
    for (let index = 0; index < a.length; index += 1) {
      if (a[index] !== b[index] && ++mismatches > 1) return false;
    }
    return mismatches === 1;
  }

  const [shorter, longer] = a.length < b.length ? [a, b] : [b, a];
  let i = 0;
  let j = 0;
  let skipped = false;

  while (i < shorter.length && j < longer.length) {
    if (shorter[i] === longer[j]) {
      i += 1;
      j += 1;
    } else if (skipped) {
      return false;
    } else {
      skipped = true;
      j += 1;
    }
  }

  return true;
}

// ===========================================================================
// check-upi
// ===========================================================================

/**
 * Rate one payee and, when it is not SAFE, open the server-side state that
 * "Proceed Anyway" will have to present.
 *
 * A SAFE verdict writes nothing: a lookup is not a transaction, and storing
 * every scan would turn the audit log into a query log.
 *
 * @param {{ userId: unknown, rawIdentifier: unknown, callerIp?: string|null }} params
 */
async function checkIdentifier({ userId, rawIdentifier, callerIp = null }) {
  const input = normalizeIdentifierInput(rawIdentifier);
  const verdict = await evaluateRisk(input);

  const payload = {
    ...verdict,
    checkedAt: new Date().toISOString(),
    checkId: null,
    checkExpiresAt: null,
  };

  if (verdict.riskLevel !== RISK_LEVELS.SAFE) {
    const pending = await TransactionAudit.createPendingCheck({
      userId,
      upiId: input.identifier,
      identifierType: input.identifierType,
      riskLevel: verdict.riskLevel,
      riskScore: verdict.riskScore,
      ttlSeconds: config.shieldPay.checkTtlSeconds,
      ipAddress: callerIp,
    });

    payload.checkId = String(pending._id);
    payload.checkExpiresAt = pending.expiresAt.toISOString();
  }

  return payload;
}

// ===========================================================================
// proceed-transaction
// ===========================================================================

/**
 * Settle a payment: verify the PIN, honour the stateful warning gate, and write
 * exactly one audit row.
 *
 * @param {{
 *   userId: unknown, rawIdentifier: unknown, amount: number, pin: string,
 *   riskAccepted?: boolean, checkId?: string|null, callerIp?: string|null
 * }} params
 */
async function proceedTransaction({ userId, rawIdentifier, amount, pin, riskAccepted = false, checkId = null, callerIp = null }) {
  const input = normalizeIdentifierInput(rawIdentifier);
  const verdict = await evaluateRisk(input);

  const user = await User.findById(userId).select('+securityPinHash');
  if (!user) throw ApiError.unauthorized('The account for this token no longer exists.');

  if (!user.securityPinHash) {
    throw new ApiError(409, 'Set your Shield Pay PIN before making payments.', {
      code: 'SHIELD_PAY_PIN_NOT_SET',
      errors: [{ field: 'pin', code: 'SHIELD_PAY_PIN_NOT_SET', message: 'no Shield Pay PIN is configured for this account' }],
    });
  }

  if (!(await pinMatches(pin, user.securityPinHash))) {
    // A wrong PIN is recorded even though nothing was paid: repeated failures on
    // one account are the signature of someone else holding the phone.
    await TransactionAudit.createRejectedAttempt({
      userId,
      upiId: input.identifier,
      identifierType: input.identifierType,
      riskLevel: verdict.riskLevel,
      riskScore: verdict.riskScore,
      amount,
      riskAccepted: riskAccepted === true && verdict.riskLevel !== RISK_LEVELS.SAFE,
      failureReason: FAILURE_REASONS.INVALID_PIN,
      ipAddress: callerIp,
    });

    const text = messageFor('PIN_REJECTED');
    throw new ApiError(401, 'The Shield Pay PIN is incorrect.', {
      code: 'INVALID_PIN',
      errors: [{ field: 'pin', code: 'INVALID_PIN', message: 'PIN verification failed', msg_en: text.en, msg_hi: text.hi }],
    });
  }

  if (verdict.riskLevel !== RISK_LEVELS.SAFE) {
    if (riskAccepted !== true) {
      throw new ApiError(409, 'This payee is flagged. Review the warning and confirm with riskAccepted: true to continue.', {
        code: 'RISK_ACKNOWLEDGEMENT_REQUIRED',
        errors: [
          {
            field: 'riskAccepted',
            code: 'RISK_ACKNOWLEDGEMENT_REQUIRED',
            message: verdict.msg_en,
            msg_en: verdict.msg_en,
            msg_hi: verdict.msg_hi,
            riskLevel: verdict.riskLevel,
            riskScore: verdict.riskScore,
          },
        ],
      });
    }

    if (!checkId) {
      throw new ApiError(409, 'Run POST /api/v1/shield-pay/check-upi for this payee before proceeding.', {
        code: 'RISK_CHECK_REQUIRED',
        errors: [{ field: 'checkId', code: 'RISK_CHECK_REQUIRED', message: 'a risk check is required before accepting a warning' }],
      });
    }

    assertValidObjectId(checkId, 'checkId');

    const completed = await TransactionAudit.consumePendingCheck({
      checkId,
      userId,
      upiId: input.identifier,
      amount,
      ipAddress: callerIp,
    });

    if (!completed) throw await explainCheckFailure({ checkId, userId });

    return buildReceipt(completed);
  }

  const created = await TransactionAudit.createCompletedTransaction({
    userId,
    upiId: input.identifier,
    identifierType: input.identifierType,
    riskLevel: verdict.riskLevel,
    riskScore: verdict.riskScore,
    amount,
    riskAccepted: false,
    ipAddress: callerIp,
  });

  return buildReceipt(created);
}

/** Never let a malformed stored hash crash a payment; a failed compare is a failure. */
async function pinMatches(pin, hash) {
  try {
    return await bcrypt.compare(pin, hash);
  } catch {
    return false;
  }
}

/**
 * Why did the pending check not match? The atomic consume is the gate; this read
 * only chooses a precise message and code so the client knows what to do next —
 * in every case, run the check again.
 */
async function explainCheckFailure({ checkId, userId }) {
  const row = await TransactionAudit.findOne({ _id: checkId, userId }).select('status upiId expiresAt').lean();

  const conflict = (code, message) =>
    new ApiError(409, message, { code, errors: [{ field: 'checkId', code, message }] });

  if (!row) {
    return conflict('RISK_CHECK_INVALID', 'That risk check does not exist for this account. Run the payee check again.');
  }

  if (row.status === STATUSES.COMPLETED) {
    return conflict('RISK_CHECK_ALREADY_USED', 'This risk check has already been used. Run the payee check again.');
  }

  if (!row.expiresAt || new Date(row.expiresAt).getTime() <= Date.now()) {
    return conflict('RISK_CHECK_EXPIRED', 'This risk check has expired. Run the payee check again.');
  }

  return conflict('RISK_CHECK_MISMATCH', 'This risk check was run for a different payee. Run the payee check again.');
}

function buildReceipt(row) {
  const text = row.risk_accepted === true ? messageFor('RECEIPT_ACCEPTED') : messageFor('RECEIPT_SAFE');

  return {
    auditId: String(row._id),
    status: 'completed',
    upiId: row.upiId,
    identifierType: row.identifierType,
    amount: row.amount,
    riskLevel: row.riskLevel,
    riskScore: row.riskScore,
    risk_accepted: row.risk_accepted === true,
    pinVerified: row.pinVerified === true,
    transactionHash: row.transactionHash,
    completedAt: (row.completedAt instanceof Date ? row.completedAt : new Date(row.completedAt || Date.now())).toISOString(),
    msg_en: text.en,
    msg_hi: text.hi,
  };
}

// ===========================================================================
// PIN management
// ===========================================================================

/**
 * Set or change the Shield Pay PIN.
 *
 * Changing an existing PIN requires the current one: a stolen phone with an
 * unlocked session must not be able to quietly replace the PIN and then pay.
 *
 * @param {{ userId: unknown, pin: string, currentPin?: string|null }} params
 */
async function setPin({ userId, pin, currentPin = null }) {
  const user = await User.findById(userId).select('+securityPinHash');
  if (!user) throw ApiError.unauthorized('The account for this token no longer exists.');

  if (user.securityPinHash) {
    if (!currentPin) {
      throw new ApiError(401, 'Enter your current Shield Pay PIN to change it.', {
        code: 'CURRENT_PIN_REQUIRED',
        errors: [{ field: 'currentPin', code: 'CURRENT_PIN_REQUIRED', message: 'the current PIN is required to change it' }],
      });
    }

    if (!(await pinMatches(currentPin, user.securityPinHash))) {
      throw new ApiError(401, 'The current Shield Pay PIN is incorrect.', {
        code: 'INVALID_CURRENT_PIN',
        errors: [{ field: 'currentPin', code: 'INVALID_CURRENT_PIN', message: 'current PIN does not match' }],
      });
    }
  }

  const weakReason = weakPinReason(pin, user.phone);
  if (weakReason) {
    throw ApiError.badRequest(`This PIN is too easy to guess: ${weakReason}.`, [
      { field: 'pin', code: 'WEAK_PIN', message: weakReason },
    ]);
  }

  user.securityPinHash = await bcrypt.hash(pin, config.bcrypt.saltRounds);
  await user.save();

  return {
    pinConfigured: true,
    hashAlgorithm: 'bcrypt',
    rounds: config.bcrypt.saltRounds,
    updatedAt: new Date().toISOString(),
  };
}

/**
 * @param {string} pin
 * @param {string} phone the owner's number, to refuse "the last 4 digits"
 * @returns {string|null} why the PIN is weak, or null when it is acceptable
 */
function weakPinReason(pin, phone = '') {
  const value = String(pin);

  if (/^(\d)\1+$/.test(value)) return 'every digit is the same';

  const digits = value.split('').map(Number);
  const ascending = digits.every((digit, index) => index === 0 || digit === digits[index - 1] + 1);
  const descending = digits.every((digit, index) => index === 0 || digit === digits[index - 1] - 1);
  if (ascending || descending) return 'the digits run in a straight sequence';

  if (WEAK_PINS.has(value)) return 'this is one of the most commonly used PINs';

  const local = String(phone).replace(/\D/g, '');
  if (local.length >= 4 && local.slice(-value.length) === value) return 'it matches the last digits of your phone number';

  return null;
}

module.exports = {
  normalizeIdentifierInput,
  evaluateRisk,
  checkIdentifier,
  proceedTransaction,
  setPin,
  weakPinReason,
  SCORES,
  KNOWN_UPI_HANDLES,
  SCAM_KEYWORDS,
  URL_KEYWORDS,
  RISKY_TLDS,
  WEAK_PINS,
};
