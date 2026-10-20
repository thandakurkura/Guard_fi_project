'use strict';

/**
 * GuardFi — Shield Pay bilingual message catalogue (Phase 6)
 *
 * Every verdict the API returns carries `msg_en` and `msg_hi` TOGETHER. The
 * client picks, but the server never depends on a locale header to decide
 * whether a warning exists — a missing translation must not be able to turn a
 * fraud warning into a blank screen at the moment money is about to move.
 *
 * Two sources of text, one shape:
 *   • a curated FlaggedEntity brings its own `reason_en` / `reason_hi` (a real
 *     explanation of THIS scam, written by the person who added it);
 *   • heuristic flags have no document, so their wording lives here, keyed by
 *     reason code.
 * Both are wrapped by the same level prefix, which is how the spec's example
 * line is produced: `"Fraud Alert: " + "This UPI ID is linked to reported
 * phishing scams."` → `msg_en`.
 *
 * `messageFor(code)` never returns null: an unknown code yields the generic
 * "not enough information" string in both languages, so a new heuristic that
 * forgets to add its copy still produces a complete, honest envelope.
 */

const VERDICT_PREFIXES = Object.freeze({
  DANGER: Object.freeze({ en: 'Fraud Alert: ', hi: 'फ्रॉड अलर्ट: ' }),
  SUSPICIOUS: Object.freeze({ en: 'Caution: ', hi: 'सावधान: ' }),
  SAFE: Object.freeze({ en: '', hi: '' }),
});

/** @type {Readonly<Record<string, { en: string, hi: string }>>} */
const REASON_MESSAGES = Object.freeze({
  // --- Blocklist verdicts (document text is preferred when a row exists) -----
  REPORTED_DANGER: Object.freeze({
    en: 'This identifier has been reported for fraud and is blocked by Shield Pay.',
    hi: 'यह पहचानकर्ता धोखाधड़ी के लिए रिपोर्ट किया गया है और Shield Pay द्वारा ब्लॉक है।',
  }),
  REPORTED_SUSPICIOUS: Object.freeze({
    en: 'This identifier has been reported and is under review.',
    hi: 'यह पहचानकर्ता रिपोर्ट किया गया है और समीक्षा में है।',
  }),
  VERIFIED_SAFE: Object.freeze({
    en: 'This identifier is on the verified-safe list.',
    hi: 'यह पहचानकर्ता सत्यापित-सुरक्षित सूची में है।',
  }),

  // --- Heuristic signals (no database row) -----------------------------------
  UNKNOWN_IDENTIFIER: Object.freeze({
    en: 'No fraud reports exist for this identifier yet — stay alert with first-time payees.',
    hi: 'अभी इस पहचानकर्ता के लिए कोई धोखाधड़ी रिपोर्ट नहीं है — पहली बार भुगतान करते समय सतर्क रहें।',
  }),
  UNKNOWN_UPI_HANDLE: Object.freeze({
    en: 'The UPI handle is not a recognised payment-provider handle.',
    hi: 'यह UPI हैंडल किसी मान्यता प्राप्त भुगतान प्रदाता का नहीं है।',
  }),
  LOOKALIKE_UPI_HANDLE: Object.freeze({
    en: 'The handle closely resembles a popular payment provider — possible look-alike.',
    hi: 'यह हैंडल किसी लोकप्रिय भुगतान प्रदाता से मिलता-जुलता है — नकली हो सकता है।',
  }),
  SCAM_KEYWORDS: Object.freeze({
    en: 'The name contains wording commonly used in payment scams (KYC, refund, lottery, prize).',
    hi: 'नाम में आमतौर पर भुगतान घोटालों में इस्तेमाल होने वाले शब्द हैं (KYC, रिफंड, लॉटरी, इनाम)।',
  }),
  NUMERIC_UPI_NAME: Object.freeze({
    en: 'The UPI username is only a phone number.',
    hi: 'UPI यूज़रनेम में केवल फ़ोन नंबर है।',
  }),
  RISKY_TLD: Object.freeze({
    en: 'The link uses a domain extension frequently seen in phishing.',
    hi: 'यह लिंक ऐसा डोमेन एक्सटेंशन इस्तेमाल करता है जो अक्सर फ़िशिंग में दिखता है।',
  }),
  RAW_IP_HOST: Object.freeze({
    en: 'The link points to a raw IP address instead of a real domain.',
    hi: 'यह लिंक असली डोमेन की जगह सीधे IP पते पर जाता है।',
  }),
  HIDDEN_DESTINATION: Object.freeze({
    en: 'The link hides its real destination (encoded host or credentials inside the URL).',
    hi: 'यह लिंक अपना असली पता छिपाता है (एन्कोडेड होस्ट या URL में क्रेडेंशियल)।',
  }),
  INSECURE_HTTP: Object.freeze({
    en: 'The link does not use HTTPS.',
    hi: 'यह लिंक HTTPS का उपयोग नहीं करता।',
  }),
  SUSPICIOUS_URL_WORDS: Object.freeze({
    en: 'The link contains wording common on phishing pages (login, KYC, OTP, refund).',
    hi: 'इस लिंक में फ़िशिंग पेजों जैसे शब्द हैं (लॉगिन, KYC, OTP, रिफंड)।',
  }),
  UNKNOWN_PHONE: Object.freeze({
    en: 'No reports exist for this phone number yet — verify the caller before paying.',
    hi: 'इस फ़ोन नंबर की अभी कोई रिपोर्ट नहीं है — भुगतान से पहले कॉलर की पुष्टि करें।',
  }),

  // --- Receipts (proceed-transaction) ---------------------------------------
  RECEIPT_SAFE: Object.freeze({
    en: 'Payment recorded. No fraud warning was raised for this payee.',
    hi: 'भुगतान दर्ज हो गया। इस पेयी के लिए कोई धोखाधड़ी चेतावनी नहीं मिली।',
  }),
  RECEIPT_ACCEPTED: Object.freeze({
    en: 'Payment recorded after you accepted the fraud warning.',
    hi: 'धोखाधड़ी चेतावनी स्वीकार करने के बाद भुगतान दर्ज हो गया।',
  }),
  PIN_REJECTED: Object.freeze({
    en: 'PIN verification failed. No transaction was recorded.',
    hi: 'PIN सत्यापन विफल रहा। कोई लेन-देन दर्ज नहीं हुआ।',
  }),
});

const FALLBACK = Object.freeze({
  en: 'This identifier could not be matched against the fraud database.',
  hi: 'इस पहचानकर्ता का मिलान धोखाधड़ी डेटाबेस से नहीं हो सका।',
});

/**
 * @param {string} code
 * @returns {{ en: string, hi: string }} always both languages
 */
function messageFor(code) {
  return REASON_MESSAGES[code] || FALLBACK;
}

/**
 * Compose the final bilingual sentence for a verdict.
 *
 * @param {'DANGER'|'SUSPICIOUS'|'SAFE'} level
 * @param {{ reason_en?: string|null, reason_hi?: string|null }} reason a document's own wording, if it has any
 * @returns {{ msg_en: string, msg_hi: string }}
 */
function composeVerdict(level, reason = {}) {
  const prefix = VERDICT_PREFIXES[level] || VERDICT_PREFIXES.SAFE;
  const en = String(reason.reason_en ?? '').trim();
  const hi = String(reason.reason_hi ?? '').trim();

  return {
    msg_en: `${prefix.en}${en}`.trim(),
    // Fall back to English only when a document genuinely has no Hindi reason;
    // curated rows are required to carry one.
    msg_hi: `${prefix.hi}${hi || en}`.trim(),
  };
}

module.exports = {
  VERDICT_PREFIXES,
  REASON_MESSAGES,
  messageFor,
  composeVerdict,
};
