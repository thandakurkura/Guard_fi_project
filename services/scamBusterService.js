'use strict';

/**
 * GuardFi — Scam Buster orchestration (Phase 7)
 *
 * Turns "here is a suspicious message / screenshot" into a stored, bilingual
 * verdict. Four separable steps, each independently testable:
 *
 *   storage   → Cloudinary, else local disk, else a capped data URI, else
 *               nothing (services/scamStorageService.js). Analysis never depends
 *               on it: the screenshot is analysed from the in-memory buffer.
 *   analysis  → Gemini with a strict JSON schema, or — when the key is missing,
 *               the provider times out, or the reply cannot be parsed — the
 *               DETERMINISTIC offline screen (services/scamHeuristicsService.js).
 *               A failed analysis degrades the VERDICT, never the request: the
 *               endpoint answers with a usable verdict and says which engine
 *               produced it (`analysisSource`) and why it was used
 *               (`fallbackReason`).
 *   parsing   → strict validation of the model's JSON, with a lenient REPAIR
 *               pass in between (fenced blocks, prose wrappers, stray values).
 *   history   → the caller's own scans, newest first, cursor-paginated on the
 *               indexed `{ userId, createdAt }` (with `_id` as the tie-break) —
 *               the one query this collection serves.
 *
 * What still fails the request: bad input (400/413), authentication (401), rate
 * limiting (429), and real bugs. What never does: a missing key, a provider
 * outage, an unreadable screenshot, or full disk — none of which are the user's
 * fault, and all of which have an honest answer.
 *
 * DEPENDENCY INJECTION (`deps.analyze`, `deps.store`) follows pushService's
 * `adminFactory` precedent: it lets the verification harness prove the whole
 * pipeline — persistence, normalisation, fallbacks, error mapping — with zero
 * credentials and zero network.
 */

const mongoose = require('mongoose');
const { config } = require('../config/env');
const logger = require('../utils/logger');
const ApiError = require('../utils/ApiError');
const ScamScan = require('../models/ScamScan');
const geminiService = require('./geminiService');
const scamStorageService = require('./scamStorageService');
const scamHeuristicsService = require('./scamHeuristicsService');
const { RISK_LEVELS, INPUT_TYPES, ANALYSIS_SOURCES, IMAGE_STORAGE } = require('../models/ScamScan');

/** Verdicts the AI can return; every level has a bilingual fallback sentence. */
const DEFAULT_EXPLANATIONS = Object.freeze({
  DANGER: Object.freeze({
    en: 'This message shows clear signs of fraud. Do not pay, click, or share any OTP, PIN or password.',
    hi: 'इस संदेश में धोखाधड़ी के स्पष्ट संकेत हैं। कोई भुगतान न करें, लिंक पर क्लिक न करें, और OTP, PIN या पासवर्ड साझा न करें।',
  }),
  SUSPICIOUS: Object.freeze({
    en: 'This message looks suspicious. Verify the sender through an official number before acting on it.',
    hi: 'यह संदेश संदिग्ध लगता है। कार्रवाई से पहले आधिकारिक नंबर से प्रेषक की पुष्टि करें।',
  }),
  SAFE: Object.freeze({
    en: 'No fraud signals were found in this message.',
    hi: 'इस संदेश में धोखाधड़ी के कोई संकेत नहीं मिले।',
  }),
});

/**
 * Errors that switch the pipeline to the offline screen instead of failing.
 * Anything else (a genuine bug, a bad dependency) still propagates, because
 * masking a programming error behind a heuristic verdict would hide it forever.
 */
const FALLBACK_CODES = Object.freeze([
  'AI_NOT_CONFIGURED',
  'AI_TIMEOUT',
  'AI_PROVIDER_ERROR',
  'AI_RESPONSE_EMPTY',
  'AI_RESPONSE_INVALID',
]);

const MAX_RED_FLAGS = 6;
const MAX_RED_FLAG_LENGTH = 120;

const ALLOWED_IMAGE_MIME = new Set(['image/jpeg', 'image/png', 'image/webp']);

// ===========================================================================
// Parsing the model's answer
// ===========================================================================

/**
 * Pull the JSON object out of whatever the model actually returned.
 * Order matters: fenced blocks first (the common case), then the widest
 * `{ … }` span, so prose before or after the object is tolerated.
 *
 * @param {string} text
 * @returns {string}
 */
function extractJsonObject(text) {
  const value = String(text ?? '').trim();

  const fenced = value.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced ? fenced[1].trim() : value;

  if (candidate.startsWith('{') && candidate.endsWith('}')) return candidate;

  const start = candidate.indexOf('{');
  const end = candidate.lastIndexOf('}');

  if (start === -1 || end === -1 || end <= start) return candidate;

  return candidate.slice(start, end + 1);
}

/** @param {unknown} value */
function coerceBoolean(value) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalised = value.trim().toLowerCase();
    if (['true', 'yes', 'y', '1', 'scam', 'fraud'].includes(normalised)) return true;
    if (['false', 'no', 'n', '0', 'safe', 'legitimate'].includes(normalised)) return false;
  }
  if (typeof value === 'number') return value !== 0;
  return null;
}

/** @param {unknown} value */
function toFiniteNumber(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value.trim());
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

/** @param {string} level */
function defaultConfidence(level) {
  if (level === RISK_LEVELS.DANGER) return 85;
  if (level === RISK_LEVELS.SUSPICIOUS) return 55;
  return 5;
}

/**
 * Clean up the red-flag list: strings only, trimmed, de-duplicated
 * case-insensitively, capped in length and count.
 * @param {unknown} value
 * @returns {string[]}
 */
function normaliseRedFlags(value) {
  if (!Array.isArray(value)) return [];

  const seen = new Set();
  const cleaned = [];

  for (const entry of value) {
    if (typeof entry !== 'string') continue;
    const trimmed = entry.trim().replace(/\s+/g, ' ').slice(0, MAX_RED_FLAG_LENGTH);
    if (trimmed === '') continue;

    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;

    seen.add(key);
    cleaned.push(trimmed);
    if (cleaned.length >= MAX_RED_FLAGS) break;
  }

  return cleaned;
}

/**
 * Validate and normalise a parsed model payload into the exact shape the
 * database and the API promise. Every value is either repaired or rejected —
 * nothing is passed through on trust.
 *
 * @param {unknown} parsed
 */
function normalisePayload(parsed) {
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new ApiError(502, 'The scam analysis service returned an unusable answer. Please try again.', {
      code: 'AI_RESPONSE_INVALID',
      errors: [{ code: 'AI_RESPONSE_INVALID', message: 'response was not a JSON object' }],
    });
  }

  const rawLevel = typeof parsed.riskLevel === 'string' ? parsed.riskLevel.trim().toUpperCase() : '';
  let riskLevel = RISK_LEVELS[rawLevel] ? RISK_LEVELS[rawLevel] : null;
  let isScam = coerceBoolean(parsed.isScam);

  // Without a verdict of SOME kind there is nothing to repair — inventing one
  // would be putting words in the model's mouth about someone's money.
  if (riskLevel === null && isScam === null) {
    throw new ApiError(502, 'The scam analysis service returned an unusable answer. Please try again.', {
      code: 'AI_RESPONSE_INVALID',
      errors: [{ code: 'AI_RESPONSE_INVALID', message: 'neither isScam nor riskLevel was present' }],
    });
  }

  if (riskLevel === null) riskLevel = isScam ? RISK_LEVELS.DANGER : RISK_LEVELS.SAFE;
  if (isScam === null) isScam = riskLevel !== RISK_LEVELS.SAFE;

  let confidence = toFiniteNumber(parsed.confidence);
  confidence = confidence === null ? defaultConfidence(riskLevel) : Math.round(confidence);
  confidence = Math.min(100, Math.max(0, confidence));

  const fallback = DEFAULT_EXPLANATIONS[riskLevel];
  const explanation_en = (typeof parsed.explanation_en === 'string' ? parsed.explanation_en.trim() : '') || fallback.en;
  const explanation_hi = (typeof parsed.explanation_hi === 'string' ? parsed.explanation_hi.trim() : '') || fallback.hi;

  const extractedTextRaw = typeof parsed.extractedText === 'string' ? parsed.extractedText.trim() : '';
  const extractedText = extractedTextRaw === '' ? null : extractedTextRaw.slice(0, config.scamBuster.textMaxChars);

  return {
    isScam,
    riskLevel,
    confidenceScore: confidence,
    explanation_en: explanation_en.slice(0, 1000),
    explanation_hi: explanation_hi.slice(0, 1000),
    redFlags: normaliseRedFlags(parsed.redFlags),
    extractedText,
  };
}

/**
 * The fallback parser: repair what can be repaired, reject what cannot.
 * A rejection is not fatal here — the caller swaps in the offline screen.
 * @param {string} rawText
 */
function parseAiPayload(rawText) {
  const source = typeof rawText === 'string' ? rawText.trim() : '';

  if (source === '') {
    throw new ApiError(502, 'The scam analysis service returned an empty answer. Please try again.', {
      code: 'AI_RESPONSE_EMPTY',
      errors: [{ code: 'AI_RESPONSE_EMPTY', message: 'provider returned no text' }],
    });
  }

  const jsonText = extractJsonObject(source);

  let parsed;

  try {
    parsed = JSON.parse(jsonText);
  } catch (error) {
    throw new ApiError(502, 'The scam analysis service returned an unusable answer. Please try again.', {
      code: 'AI_RESPONSE_INVALID',
      errors: [
        {
          code: 'AI_RESPONSE_INVALID',
          message: (error instanceof Error ? error.message : 'invalid JSON').slice(0, 200),
        },
      ],
    });
  }

  return normalisePayload(parsed);
}

// ===========================================================================
// Orchestration
// ===========================================================================

/**
 * @param {{ text: string|null, image: { buffer: Buffer, mimeType: string }|null }} params
 */
async function defaultAnalyze({ text, image }) {
  if (image) {
    return geminiService.analyzeImage({ buffer: image.buffer, mimeType: image.mimeType, caption: text });
  }

  return geminiService.analyzeText({ text });
}

/**
 * Decide whether an analysis failure should degrade to the offline screen.
 * @param {unknown} error
 * @returns {string|null} the fallback reason, or null when the error must surface
 */
function fallbackReasonFor(error) {
  const code = error instanceof ApiError ? error.code : null;
  return typeof code === 'string' && FALLBACK_CODES.includes(code) ? code : null;
}

/** @param {unknown} record */
function toPayload(record, { includeCheckedAt = true } = {}) {
  const payload = {
    scanId: String(record._id),
    inputType: record.inputType,
    imageUrl: record.imageUrl ?? null,
    imageStorage: record.imageStorage ?? null,
    isScam: record.isScam === true,
    riskLevel: record.riskLevel,
    confidenceScore: record.confidenceScore,
    explanation_en: record.explanation_en,
    explanation_hi: record.explanation_hi,
    redFlags: Array.isArray(record.redFlags) ? [...record.redFlags] : [],
    extractedText: record.extractedText ?? null,
    analysisSource: record.analysisSource ?? ANALYSIS_SOURCES.GEMINI,
    fallbackReason: record.fallbackReason ?? null,
    aiModel: record.aiModel ?? null,
    analysisMs: record.analysisMs ?? null,
    createdAt: record.createdAt instanceof Date ? record.createdAt.toISOString() : null,
  };

  if (includeCheckedAt) payload.checkedAt = new Date().toISOString();

  return payload;
}

/**
 * Analyse one submission and store the verdict.
 *
 * @param {{
 *   userId: unknown,
 *   text?: string|null,
 *   file?: { buffer: Buffer, mimetype: string, size?: number }|null,
 *   requestIp?: string|null,
 *   deps?: {
 *     analyze?: (input: { text: string|null, image: { buffer: Buffer, mimeType: string }|null }) => Promise<{ rawText: string, model?: string }>,
 *     store?: (input: { buffer: Buffer, mimeType: string, userId: unknown }) => Promise<{ imageUrl: string|null, cloudinaryPublicId: string|null, storage: string }>
 *   }
 * }} params
 */
async function analyzeScan({ userId, text = null, file = null, requestIp = null, deps = {} }) {
  const cleanText = typeof text === 'string' && text.trim() !== '' ? text.trim() : null;
  const hasFile = Boolean(file && file.buffer);
  const inputType = hasFile ? INPUT_TYPES.IMAGE : INPUT_TYPES.TEXT;

  if (!hasFile && !cleanText) {
    throw ApiError.badRequest('Provide either "text" (the suspicious message) or a screenshot in the "image" field.', [
      { field: 'text', code: 'INPUT_REQUIRED', message: 'nothing to analyse was submitted' },
    ]);
  }

  if (cleanText && cleanText.length > config.scamBuster.textMaxChars) {
    throw ApiError.badRequest(`text cannot exceed ${config.scamBuster.textMaxChars} characters.`, [
      { field: 'text', code: 'TEXT_TOO_LONG', message: `the limit is ${config.scamBuster.textMaxChars} characters` },
    ]);
  }

  // Defence in depth: the Multer middleware already enforced both of these, but
  // a service is a public boundary too (cron jobs, future callers, tests).
  if (hasFile) {
    if (!ALLOWED_IMAGE_MIME.has(file.mimetype)) {
      throw ApiError.badRequest('The screenshot must be a JPEG, PNG or WebP image.', [
        { field: 'image', code: 'UNSUPPORTED_IMAGE_TYPE', message: `received ${file.mimetype}` },
      ]);
    }

    if (file.buffer.length > config.scamBuster.maxImageBytes) {
      throw ApiError.payloadTooLarge(
        `The screenshot cannot exceed ${(config.scamBuster.maxImageBytes / (1024 * 1024)).toFixed(1)} MB.`
      );
    }
  }

  // Storage never blocks analysis: the buffer is in memory, and a missing
  // bucket is not a reason to refuse to check a message for fraud.
  let storedImage = null;

  if (hasFile) {
    if (deps.store) {
      // An injected store is a test double: its failures must surface so the
      // harness can prove error propagation, not be papered over.
      storedImage = await deps.store({ buffer: file.buffer, mimeType: file.mimetype, userId });
    } else {
      try {
        storedImage = await scamStorageService.storeScreenshot({ buffer: file.buffer, mimeType: file.mimetype, userId });
      } catch (error) {
        // Cloudinary is configured but unreachable. A dead bucket must not cost
        // the user their scan, so the offline half of the chain takes over.
        logger.warn(
          `[scam-buster] screenshot storage failed (${error.code || error.message}); falling back to the offline chain.`
        );
        storedImage = await scamStorageService.storeWithoutCloudinary({
          buffer: file.buffer,
          mimeType: file.mimetype,
          userId,
        });
      }
    }
  }

  const analyze = deps.analyze || defaultAnalyze;
  let analysis = null;
  let fallbackReason = null;
  const analysisStartedAt = Date.now();

  try {
    analysis = await analyze({
      text: cleanText,
      image: hasFile ? { buffer: file.buffer, mimeType: file.mimetype } : null,
    });
  } catch (error) {
    fallbackReason = fallbackReasonFor(error);

    // A real bug must not hide behind a heuristic verdict.
    if (!fallbackReason) throw error;

    logger.warn(`[scam-buster] AI analysis unavailable (${fallbackReason}); using the offline heuristic screen.`);
  }

  let verdict = null;
  let analysisSource = ANALYSIS_SOURCES.GEMINI;

  if (analysis) {
    try {
      verdict = parseAiPayload(analysis.rawText);
    } catch (error) {
      // The provider answered, but the answer is unusable: repair could not save
      // it, so the offline screen takes over rather than failing the scan.
      fallbackReason = error.code || 'AI_RESPONSE_INVALID';
      logger.warn(`[scam-buster] AI answer was unusable (${fallbackReason}); using the offline heuristic screen.`);
    }
  }

  if (!verdict) {
    analysisSource = ANALYSIS_SOURCES.HEURISTIC;
    fallbackReason = fallbackReason || 'AI_RESPONSE_INVALID';
    verdict = hasFile
      ? scamHeuristicsService.analyseImageHeuristically({ caption: cleanText })
      : scamHeuristicsService.analyseTextHeuristically({ text: cleanText });
  }

  // Provenance belongs to the verdict that was STORED, not to the call that was
  // attempted: an unparseable answer leaves a HEURISTIC verdict, so naming the
  // model on that row would claim a judgement the model never made.
  const usedModel = analysisSource === ANALYSIS_SOURCES.GEMINI && Boolean(analysis);

  // Model latency only: the offline screen runs in well under a millisecond, and
  // reporting that as "analysis time" would make a degraded scan look fast.
  const analysisMs = usedModel ? Date.now() - analysisStartedAt : null;

  const record = await ScamScan.create({
    userId,
    inputType,
    imageUrl: storedImage ? storedImage.imageUrl : null,
    cloudinaryPublicId: storedImage ? storedImage.cloudinaryPublicId ?? null : null,
    imageStorage: storedImage ? storedImage.storage : null,
    // The model's OCR wins for screenshots; the user's own text is the fallback.
    extractedText: verdict.extractedText || cleanText || null,
    isScam: verdict.isScam,
    riskLevel: verdict.riskLevel,
    confidenceScore: verdict.confidenceScore,
    explanation_en: verdict.explanation_en,
    explanation_hi: verdict.explanation_hi,
    redFlags: verdict.redFlags,
    analysisSource,
    fallbackReason,
    aiModel: usedModel ? analysis.model || config.gemini.model || null : null,
    analysisMs,
    requestIp,
  });

  logger.info(
    `[scam-buster] ${inputType} scan stored (${record.riskLevel}, ${record.confidenceScore}%) via ${record.analysisSource}${record.fallbackReason ? ` (fallback: ${record.fallbackReason})` : ''}.`
  );

  return record;
}

/**
 * Parse a `before` cursor: `<ISO timestamp>` or `<ISO timestamp>_<scan id>`.
 * Returns null for anything unusable, which the caller treats as "first page"
 * (the validator has already rejected malformed cursors over HTTP).
 *
 * @param {unknown} before
 * @returns {{ at: Date, id: import('mongoose').Types.ObjectId|null }|null}
 */
function parseCursor(before) {
  if (!before) return null;
  if (before instanceof Date) return Number.isNaN(before.getTime()) ? null : { at: before, id: null };

  const [atPart, idPart] = String(before).trim().split('_');
  const at = new Date(atPart);

  if (Number.isNaN(at.getTime())) return null;

  return { at, id: idPart && /^[a-f0-9]{24}$/i.test(idPart) ? new mongoose.Types.ObjectId(idPart) : null };
}

/**
 * The caller's own scans, newest first, cursor-paginated.
 *
 * Cursor (not offset) pagination on `createdAt`: it walks the
 * `{ userId, createdAt: -1 }` index directly, so page 50 costs the same as page
 * 1 and a scan inserted between two requests cannot shift rows the way `skip`
 * makes them shift. The `_id` half of the cursor keeps it exact when two scans
 * share a millisecond.
 *
 * @param {{ userId: unknown, limit?: number, before?: Date|string|null }} params
 */
async function listScans({ userId, limit = 20, before = null }) {
  const size = Math.min(50, Math.max(1, Number(limit) || 20));

  const filter = { userId };
  const cursor = parseCursor(before);

  if (cursor) {
    filter.$or = cursor.id
      ? [{ createdAt: { $lt: cursor.at } }, { createdAt: cursor.at, _id: { $lt: cursor.id } }]
      : [{ createdAt: { $lt: cursor.at } }];
  }

  const rows = await ScamScan.find(filter)
    .sort({ createdAt: -1, _id: -1 })
    .limit(size)
    .lean();

  const scans = rows.map((row) => toPayload(row, { includeCheckedAt: false }));
  const last = rows.length === size ? rows[rows.length - 1] : null;

  return {
    scans,
    count: scans.length,
    hasMore: rows.length === size,
    // Opaque to the client: it echoes this back as `before`.
    nextBefore:
      last && last.createdAt ? `${new Date(last.createdAt).toISOString()}_${String(last._id)}` : null,
  };
}

module.exports = {
  analyzeScan,
  listScans,
  parseAiPayload,
  normalisePayload,
  normaliseRedFlags,
  extractJsonObject,
  coerceBoolean,
  fallbackReasonFor,
  toPayload,
  parseCursor,
  DEFAULT_EXPLANATIONS,
  FALLBACK_CODES,
  MAX_RED_FLAGS,
  ALLOWED_IMAGE_MIME,
  IMAGE_STORAGE,
  ANALYSIS_SOURCES,
};
