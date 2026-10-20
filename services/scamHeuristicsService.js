'use strict';

/**
 * GuardFi — deterministic heuristic scam screen (Phase 7 fallback)
 *
 * The safety net under the AI: when GEMINI_API_KEY is missing, the provider
 * times out, or the model answers with garbage, the endpoint must still return a
 * USABLE verdict — never a 500, never a hang, and never a bare "unknown".
 *
 * Determinism is the whole point: fixed signal list, fixed weights, fixed
 * thresholds, no timestamps, no randomness. The same message always produces the
 * same verdict, which is what makes it testable, explainable to a user, and safe
 * to store next to a flagged-up row.
 *
 * It is honest about being a fallback. The verdict carries
 * `analysisSource: 'HEURISTIC'` plus the reason the AI was skipped, so the client
 * can say "we could not reach the AI — here is our best manual screening"
 * instead of pretending a pattern match is a model's judgement.
 *
 * Scope: it screens TEXT. A screenshot with no caption cannot be read without
 * OCR, and guessing at an image we cannot see would be worse than saying so —
 * that case becomes a single, explicit SUSPICIOUS verdict asking the user to
 * paste the text instead.
 *
 * Bands (deliberately conservative):
 *   score ≥ 60  → DANGER      (clear, specific fraud signals)
 *   score ≥ 25  → SUSPICIOUS  (some signals, worth a warning)
 *   otherwise   → SAFE        (nothing recognisable — not a clean bill of health)
 *   confidence  = min(85, 30 + score/2) — a heuristic never claims certainty.
 */

const MAX_RED_FLAGS = 6;

/** Weight per matched signal; kept in one place so the tests can pin them. */
const SIGNALS = Object.freeze([
  {
    code: 'OTP_OR_PIN_REQUEST',
    weight: 35,
    pattern: /\b(otp|one[- ]time password|upi pin|m?pin|cvv|password|passcode)\b/i,
    msg_en: 'It asks for an OTP, UPI PIN, CVV or password — banks and support staff never ask for these.',
    msg_hi: 'यह OTP, UPI PIN, CVV या पासवर्ड मांगता है — बैंक और सहायता कर्मचारी ये कभी नहीं मांगते।',
  },
  {
    code: 'KYC_OR_ACCOUNT_THREAT',
    weight: 25,
    pattern: /\b(kyc|re-?kyc|account (?:will be |has been )?(?:blocked|suspended|closed|frozen)|blocked|suspend(?:ed)?|deactivat|expir(?:e|y|ing)|blacklisted)\b/i,
    msg_en: 'It threatens KYC expiry, account blocking or suspension to create panic.',
    msg_hi: 'यह KYC समाप्ति, खाता ब्लॉक या निलंबन की धमकी देकर डर बनाता है।',
  },
  {
    code: 'LOTTERY_OR_PRIZE',
    weight: 30,
    pattern: /\b(lottery|lucky draw|prize|winner|won|jackpot|crorepati)\b/i,
    msg_en: 'It promises lottery, prize or lucky-draw winnings that were not entered.',
    msg_hi: 'यह लॉटरी, इनाम या लकी ड्रॉ जीत का दावा करता है, जिसमें आपने भाग नहीं लिया।',
  },
  {
    code: 'MONEY_REQUEST',
    weight: 30,
    pattern: /\b(processing fee|registration fee|advance (?:payment|fee)|pay (?:rs|inr|now)|transfer (?:rs|inr|money)|send money|deposit (?:rs|inr))\b/i,
    msg_en: 'It asks you to pay or transfer money (often a "processing fee" before a bigger payout).',
    msg_hi: 'यह पैसे भेजने या भुगतान करने के लिए कहता है (अक्सर बड़ी रकम से पहले "प्रोसेसिंग फीस")।',
  },
  {
    code: 'PAYMENT_DEMAND',
    weight: 25,
    pattern:
      /\b(?:pay|paid|send|transfer|deposit)\b[^.\n]{0,40}\b(?:fee|fees|charge|charges|amount|money|rs\.?|inr|₹)\b|\b(?:processing|clearance|handling|delivery|customs|registration|activation|re-?activation) (?:fee|fees|charge|charges)\b/i,
    msg_en: 'It demands a payment or fee — often a "clearance" or "processing" charge that no real office asks for by message.',
    msg_hi: 'यह भुगतान या फीस की मांग करता है — अक्सर "क्लीयरेंस" या "प्रोसेसिंग" शुल्क, जो कोई असली दफ़्तर संदेश से नहीं मांगता।',
  },
  {
    code: 'REMOTE_ACCESS_REQUEST',
    weight: 30,
    pattern: /\b(anydesk|teamviewer|quick ?support|screen shar\w*|remote (?:access|support)|install (?:this |the )?app|apk)\b/i,
    msg_en: 'It asks you to install an app or share your screen — a classic way to take over a phone.',
    msg_hi: 'यह ऐप इंस्टॉल करने या स्क्रीन साझा करने के लिए कहता है — फ़ोन पर कब्ज़ा करने का आम तरीका।',
  },
  {
    code: 'SUSPICIOUS_LINK',
    weight: 25,
    pattern: /(https?:\/\/|bit\.ly|tinyurl|t\.co\/|upi:\/\/|\b[\w.-]+@(?:ybl|paytm|okaxis|oksbi|okicici|okhdfcbank|upi|apl|ibl|axl)\b)/i,
    msg_en: 'It contains a link or a UPI payment address — never pay or log in through a link in a message.',
    msg_hi: 'इसमें लिंक या UPI भुगतान पता है — किसी संदेश के लिंक से कभी भुगतान या लॉगिन न करें।',
  },
  {
    code: 'REFUND_OR_OFFER',
    weight: 20,
    pattern: /\b(refund|cash ?back|reward points?|gift card|offer|discount coupon|scratch card)\b/i,
    msg_en: 'It offers a refund, cashback or an offer that is too good to be true.',
    msg_hi: 'यह रिफंड, कैशबैक या इतना अच्छा ऑफ़र देता है जो सच नहीं लगता।',
  },
  {
    code: 'JOB_OR_LOAN_BAIT',
    weight: 20,
    pattern: /\b(job|work from home|part[- ]time job|daily income|loan approved|pre-?approved loan|army canteen|canteen)\b/i,
    msg_en: 'It uses a job, loan or canteen offer as bait.',
    msg_hi: 'यह नौकरी, लोन या कैंटीन ऑफ़र का लालच देता है।',
  },
  {
    code: 'URGENCY_PRESSURE',
    weight: 15,
    pattern: /\b(urgent|immediately|right now|within \d+ ?(?:hours?|minutes?|hrs?)|today|last chance|final warning|turant|jaldi)\b|आज|तुरंत|जल्दी/i,
    msg_en: 'It pressures you to act immediately, before you can check with anyone.',
    msg_hi: 'यह तुरंत कार्रवाई का दबाव बनाता है, ताकि आप किसी से जाँच न कर सकें।',
  },
  {
    code: 'IMPERSONATION',
    weight: 20,
    pattern: /\b(sbi|hdfc|icici|axis bank|kotak|paytm|phonepe|google ?pay|gpay|income tax|gst|epfo|uidai|aadhaar|passport office|courier|parcel|customs|customer care|helpline)\b/i,
    msg_en: 'It claims to come from a bank, government office, courier or customer care.',
    msg_hi: 'यह बैंक, सरकारी दफ़्तर, कूरियर या कस्टमर केयर होने का दावा करता है।',
  },
]);

const UNREADABLE_IMAGE_SIGNAL = Object.freeze({
  code: 'IMAGE_NOT_READABLE',
  weight: 40,
  msg_en: 'This screenshot could not be read automatically. Paste the message text for a detailed check.',
  msg_hi: 'इस स्क्रीनशॉट को अपने आप पढ़ा नहीं जा सका। विस्तृत जाँच के लिए संदेश का टेक्स्ट पेस्ट करें।',
});

const LEVEL_THRESHOLDS = Object.freeze({ DANGER: 60, SUSPICIOUS: 25 });

const DEFAULT_EXPLANATIONS = Object.freeze({
  DANGER: Object.freeze({
    en: 'Several fraud signals were found in this message. Do not pay, click or share any code.',
    hi: 'इस संदेश में धोखाधड़ी के कई संकेत मिले हैं। कोई भुगतान या क्लिक न करें, कोई कोड साझा न करें।',
  }),
  SUSPICIOUS: Object.freeze({
    en: 'Some fraud signals were found. Verify the sender through an official number before acting.',
    hi: 'कुछ धोखाधड़ी संकेत मिले हैं। कार्रवाई से पहले आधिकारिक नंबर से प्रेषक की पुष्टि करें।',
  }),
  SAFE: Object.freeze({
    en: 'Nothing recognisable as fraud was found by the offline screen. Stay careful with unknown senders.',
    hi: 'ऑफ़लाइन जाँच में धोखाधड़ी जैसा कुछ नहीं मिला। अनजान प्रेषकों से सावधान रहें।',
  }),
});

/**
 * Score one piece of text.
 *
 * @param {string} text
 * @returns {{ score: number, matched: Array<{ code: string, weight: number, msg_en: string, msg_hi: string }> }}
 */
function scoreText(text) {
  const haystack = String(text ?? '');
  const matched = [];

  for (const signal of SIGNALS) {
    if (signal.pattern.test(haystack)) {
      matched.push({ code: signal.code, weight: signal.weight, msg_en: signal.msg_en, msg_hi: signal.msg_hi });
    }
  }

  const score = Math.min(100, matched.reduce((total, signal) => total + signal.weight, 0));

  return { score, matched };
}

/** @param {number} score */
function levelForScore(score) {
  if (score >= LEVEL_THRESHOLDS.DANGER) return 'DANGER';
  if (score >= LEVEL_THRESHOLDS.SUSPICIOUS) return 'SUSPICIOUS';
  return 'SAFE';
}

/** @param {number} score */
function confidenceForScore(score) {
  // A pattern match never claims certainty, and a missed pattern never claims
  // certainty either — 85/30 are the ceiling and the floor.
  return Math.min(85, Math.max(30, 30 + Math.round(score / 2)));
}

/**
 * Screen a text message (or a screenshot caption) without any provider.
 *
 * @param {{ text?: string|null }} params
 * @returns {{
 *   isScam: boolean, riskLevel: string, confidenceScore: number,
 *   explanation_en: string, explanation_hi: string, redFlags: string[], extractedText: null
 * }}
 */
function analyseTextHeuristically({ text = null } = {}) {
  const { score, matched } = scoreText(text);
  const riskLevel = levelForScore(score);
  const isScam = riskLevel !== 'SAFE';

  const top = matched.slice(0, 2);
  const fallback = DEFAULT_EXPLANATIONS[riskLevel];

  return {
    isScam,
    riskLevel,
    confidenceScore: confidenceForScore(score),
    explanation_en: top.length > 0 ? top.map((signal) => signal.msg_en).join(' ') : fallback.en,
    explanation_hi: top.length > 0 ? top.map((signal) => signal.msg_hi).join(' ') : fallback.hi,
    redFlags: matched.slice(0, MAX_RED_FLAGS).map((signal) => signal.msg_en),
    extractedText: null,
  };
}

/**
 * Screen an image we could not read: without a caption there is no text to
 * score, so the honest answer is a caution plus an instruction, not a guess.
 *
 * @param {{ caption?: string|null }} params
 */
function analyseImageHeuristically({ caption = null } = {}) {
  const captionText = typeof caption === 'string' ? caption.trim() : '';

  if (captionText !== '') {
    // The caption is real text the user wrote, so it is worth screening — but it
    // is still not the screenshot, so the floor is a caution, never "safe".
    const text = analyseTextHeuristically({ text: captionText });
    const unreadable = UNREADABLE_IMAGE_SIGNAL;

    return {
      isScam: true,
      riskLevel: text.riskLevel === 'DANGER' ? 'DANGER' : 'SUSPICIOUS',
      confidenceScore: Math.min(85, Math.max(text.confidenceScore, 50)),
      explanation_en: `${unreadable.msg_en} ${text.explanation_en}`,
      explanation_hi: `${unreadable.msg_hi} ${text.explanation_hi}`,
      redFlags: [unreadable.msg_en, ...text.redFlags].slice(0, MAX_RED_FLAGS),
      extractedText: null,
    };
  }

  return {
    isScam: true,
    riskLevel: 'SUSPICIOUS',
    confidenceScore: confidenceForScore(UNREADABLE_IMAGE_SIGNAL.weight),
    explanation_en: UNREADABLE_IMAGE_SIGNAL.msg_en,
    explanation_hi: UNREADABLE_IMAGE_SIGNAL.msg_hi,
    redFlags: [UNREADABLE_IMAGE_SIGNAL.msg_en],
    extractedText: null,
  };
}

module.exports = {
  SIGNALS,
  UNREADABLE_IMAGE_SIGNAL,
  LEVEL_THRESHOLDS,
  DEFAULT_EXPLANATIONS,
  scoreText,
  levelForScore,
  confidenceForScore,
  analyseTextHeuristically,
  analyseImageHeuristically,
};
