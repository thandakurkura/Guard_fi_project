'use strict';

/**
 * GuardFi — Scam Buster scan model (Phase 7)
 *
 * One document per analysed message or screenshot. It is a RECORD of what the
 * user showed the AI and what the AI answered — never the image itself: only a
 * Cloudinary URL (plus its public id, so a future retention job can delete the
 * stored screenshot on request) and the extracted text.
 *
 * Spec fields: userId, inputType (IMAGE | TEXT), imageUrl (Cloudinary URL),
 * extractedText, isScam, confidenceScore, explanation_en, explanation_hi,
 * redFlags, timestamps. Additions this phase needs are marked below — the spec
 * describes the API response, and a few bookkeeping fields are required to make
 * that response reproducible later:
 *   • riskLevel          — the same SAFE/SUSPICIOUS/DANGER band the rest of the
 *                          app uses (Shield Pay), so a scan can be shown next to
 *                          a payment warning without translating verdicts;
 *   • cloudinaryPublicId — Cloudinary's handle for exactly this upload, the only
 *                          way to honour a later "delete my screenshot" request
 *                          (the account-deletion cascade destroys every one);
 *   • aiModel            — which model produced the verdict; a stored verdict
 *                          with no provenance cannot be re-audited when models
 *                          change;
 *   • analysisMs         — latency, so a slow provider is visible in the data
 *                          instead of only in logs;
 *   • requestIp          — caller IP, like TransactionAudit, for abuse review.
 *
 * Both languages are REQUIRED. A fraud explanation that only exists in English
 * is not a feature for the user this app is built for.
 *
 * The 16 MB document limit is a hard wall, so `extractedText` and every string
 * here is length-capped at the schema level: a 5 MB screenshot can legitimately
 * contain a lot of text, and a runaway OCR result must not be able to make the
 * write itself fail.
 */

const mongoose = require('mongoose');

const INPUT_TYPES = Object.freeze({ IMAGE: 'IMAGE', TEXT: 'TEXT' });
const RISK_LEVELS = Object.freeze({ SAFE: 'SAFE', SUSPICIOUS: 'SUSPICIOUS', DANGER: 'DANGER' });

/** Where the screenshot ended up (see services/scamStorageService.js). */
const IMAGE_STORAGE = Object.freeze({
  CLOUDINARY: 'CLOUDINARY',
  LOCAL: 'LOCAL',
  DATA_URI: 'DATA_URI',
  NONE: 'NONE',
});

/** Which engine produced the verdict: the model, or the offline screen. */
const ANALYSIS_SOURCES = Object.freeze({ GEMINI: 'GEMINI', HEURISTIC: 'HEURISTIC' });

const scamScanSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'userId is required'],
      // No field-level index: userId is the prefix of the history index below.
    },

    inputType: {
      type: String,
      required: [true, 'inputType is required'],
      enum: { values: Object.values(INPUT_TYPES), message: 'inputType must be IMAGE or TEXT' },
    },

    /**
     * Where the screenshot lives: a Cloudinary secure URL, a
     * `local://scam-scans/<file>` reference, or (last resort, no storage
     * available) a data URI. Null for text scans.
     *
     * The 2.1 MB cap is not paranoia about URLs: it is sized for the inline
     * DATA_URI fallback, where a 1 MB screenshot becomes ~1.4 MB of base64. A
     * tighter limit would silently reject the exact case the fallback exists
     * for, while remaining far below MongoDB's 16 MB document limit.
     */
    imageUrl: {
      type: String,
      default: null,
      trim: true,
      maxlength: [2_100_000, 'imageUrl cannot exceed the inline-image limit'],
    },

    /**
     * Cloudinary public id, kept so the screenshot can be deleted on request and
     * so the account-deletion cascade can destroy every stored asset. Null for a
     * text scan or a screenshot that never reached Cloudinary.
     */
    cloudinaryPublicId: {
      type: String,
      default: null,
      trim: true,
      maxlength: [512, 'cloudinaryPublicId cannot exceed 512 characters'],
    },

    /** Which storage strategy actually stored (or dropped) the screenshot. */
    imageStorage: {
      type: String,
      enum: { values: Object.values(IMAGE_STORAGE), message: 'imageStorage must be CLOUDINARY, LOCAL, DATA_URI or NONE' },
      default: null,
    },

    /** Text the user submitted, or the text the model read out of a screenshot. */
    extractedText: {
      type: String,
      default: null,
      maxlength: [5000, 'extractedText cannot exceed 5000 characters'],
    },

    isScam: {
      type: Boolean,
      required: [true, 'isScam is required'],
    },

    riskLevel: {
      type: String,
      enum: { values: Object.values(RISK_LEVELS), message: 'riskLevel must be SAFE, SUSPICIOUS or DANGER' },
      default: RISK_LEVELS.SAFE,
    },

    confidenceScore: {
      type: Number,
      default: 0,
      min: [0, 'confidenceScore cannot be negative'],
      max: [100, 'confidenceScore cannot exceed 100'],
    },

    explanation_en: {
      type: String,
      required: [true, 'explanation_en is required'],
      trim: true,
      maxlength: [1000, 'explanation_en cannot exceed 1000 characters'],
    },

    explanation_hi: {
      type: String,
      required: [true, 'explanation_hi is required'],
      trim: true,
      maxlength: [1000, 'explanation_hi cannot exceed 1000 characters'],
    },

    redFlags: {
      type: [{ type: String, trim: true, maxlength: [120, 'a red flag cannot exceed 120 characters'] }],
      default: [],
    },

    aiModel: {
      type: String,
      default: null,
      trim: true,
      maxlength: [80, 'aiModel cannot exceed 80 characters'],
    },

    /** GEMINI when the model answered, HEURISTIC when the offline screen did. */
    analysisSource: {
      type: String,
      enum: { values: Object.values(ANALYSIS_SOURCES), message: 'analysisSource must be GEMINI or HEURISTIC' },
      default: ANALYSIS_SOURCES.GEMINI,
    },

    /**
     * Why the offline screen was used, when it was: AI_NOT_CONFIGURED,
     * AI_TIMEOUT, AI_PROVIDER_ERROR, AI_RESPONSE_EMPTY, AI_RESPONSE_INVALID.
     * Null when the model produced the verdict. Kept so a degraded scan is
     * never mistaken for a model-verified one during a later review.
     */
    fallbackReason: {
      type: String,
      default: null,
      maxlength: [40, 'fallbackReason cannot exceed 40 characters'],
    },

    analysisMs: {
      type: Number,
      default: null,
      min: [0, 'analysisMs cannot be negative'],
    },

    requestIp: {
      type: String,
      default: null,
      trim: true,
      maxlength: [45, 'requestIp cannot exceed 45 characters'],
    },
  },
  {
    timestamps: true,
    versionKey: false,
  }
);

// The only query this collection serves: "my scans, newest first".
scamScanSchema.index({ userId: 1, createdAt: -1 }, { name: 'user_scan_history' });

module.exports = mongoose.model('ScamScan', scamScanSchema);
module.exports.INPUT_TYPES = INPUT_TYPES;
module.exports.RISK_LEVELS = RISK_LEVELS;
module.exports.IMAGE_STORAGE = IMAGE_STORAGE;
module.exports.ANALYSIS_SOURCES = ANALYSIS_SOURCES;
