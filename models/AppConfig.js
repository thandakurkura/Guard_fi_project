'use strict';

/**
 * GuardFi — global app configuration (Phase 9)
 *
 * ONE document, forever. The `key` field is pinned to the singleton literal and
 * carries a unique index, so a second config document is a duplicate-key error
 * rather than a "which one wins?" situation. Reads go through
 * services/configService.js (node-cache, 600 s) and writes go through the
 * admin-only PUT, so nothing in the app has to agree about defaults.
 *
 * Spec fields: privacyPolicyUrl, termsUrl, globalWarningThresholds
 * ({ upiRiskScoreThreshold, sosRadiusMeters, maxNomineesPerUser }), maintenanceMode,
 * emergencyHelplines.
 *
 * Deliberate additions, each earning its place:
 *   • `key`            — the singleton guard described above.
 *   • `version`        — bumped on every accepted PUT. A cached copy can be
 *                        compared against the database, and a client can tell
 *                        "did the config change since I last fetched it?".
 *   • `updatedBy`      — the admin who last wrote it, for the same reason the
 *                        AuditLog exists.
 *
 * Bounds are duplicated in validators/config.validator.js on purpose: the API
 * rejects bad input early with a field message, and the model refuses it again
 * if a script ever writes directly. Both layers exist because either one alone
 * has already failed in real systems.
 */

const mongoose = require('mongoose');

const GLOBAL_CONFIG_KEY = 'GLOBAL_CONFIG';

/** Every default lives here, so an auto-seeded document and a schema default can never disagree. */
const DEFAULT_GLOBAL_WARNING_THRESHOLDS = Object.freeze({
  upiRiskScoreThreshold: 70,
  sosRadiusMeters: 5_000,
  maxNomineesPerUser: 5,
});

const DEFAULT_EMERGENCY_HELPLINES = Object.freeze([
  { name_en: 'Police', name_hi: 'पुलिस', number: '112' },
  { name_en: 'Cyber Crime Helpline', name_hi: 'साइबर अपराध हेल्पलाइन', number: '1930' },
  { name_en: 'Women Helpline', name_hi: 'महिला हेल्पलाइन', number: '1091' },
]);

/**
 * E.164-ish helpline numbers plus the short codes India actually uses (112, 1930):
 * an optional leading +, then 2-15 digits, spaces and dashes allowed for display.
 */
const HELPLINE_NUMBER_REGEX = /^\+?[0-9][0-9 -]{1,15}$/;

/** An empty string means "not published yet"; a non-empty value must be http(s). */
function httpUrlOrEmpty(label) {
  return {
    validator(value) {
      if (value === '' || value === null || value === undefined) return true;
      return /^https?:\/\/\S+$/i.test(value);
    },
    message: `${label} must be an http(s) URL or an empty string`,
  };
}

const thresholdsSchema = new mongoose.Schema(
  {
    upiRiskScoreThreshold: {
      type: Number,
      min: [1, 'globalWarningThresholds.upiRiskScoreThreshold must be at least 1'],
      max: [100, 'globalWarningThresholds.upiRiskScoreThreshold cannot exceed 100'],
      default: DEFAULT_GLOBAL_WARNING_THRESHOLDS.upiRiskScoreThreshold,
    },
    sosRadiusMeters: {
      type: Number,
      min: [100, 'globalWarningThresholds.sosRadiusMeters must be at least 100'],
      max: [50_000, 'globalWarningThresholds.sosRadiusMeters cannot exceed 50000'],
      default: DEFAULT_GLOBAL_WARNING_THRESHOLDS.sosRadiusMeters,
    },
    maxNomineesPerUser: {
      type: Number,
      min: [1, 'globalWarningThresholds.maxNomineesPerUser must be at least 1'],
      max: [50, 'globalWarningThresholds.maxNomineesPerUser cannot exceed 50'],
      default: DEFAULT_GLOBAL_WARNING_THRESHOLDS.maxNomineesPerUser,
    },
  },
  { _id: false, versionKey: false }
);

const helplineSchema = new mongoose.Schema(
  {
    name_en: { type: String, required: [true, 'each helpline needs an English name'], trim: true, maxlength: 80 },
    name_hi: { type: String, required: [true, 'each helpline needs a Hindi name'], trim: true, maxlength: 80 },
    number: {
      type: String,
      required: [true, 'each helpline needs a number'],
      trim: true,
      maxlength: 16,
      match: [HELPLINE_NUMBER_REGEX, 'helpline number must be 2-15 digits, optionally starting with +'],
    },
  },
  { _id: false, versionKey: false }
);

const appConfigSchema = new mongoose.Schema(
  {
    key: {
      type: String,
      required: true,
      unique: true,
      enum: { values: [GLOBAL_CONFIG_KEY], message: `key must be "${GLOBAL_CONFIG_KEY}"` },
      default: GLOBAL_CONFIG_KEY,
    },

    privacyPolicyUrl: {
      type: String,
      trim: true,
      maxlength: 500,
      default: '',
      validate: httpUrlOrEmpty('privacyPolicyUrl'),
    },

    termsUrl: {
      type: String,
      trim: true,
      maxlength: 500,
      default: '',
      validate: httpUrlOrEmpty('termsUrl'),
    },

    globalWarningThresholds: { type: thresholdsSchema, default: () => ({}) },

    maintenanceMode: { type: Boolean, default: false },

    emergencyHelplines: {
      type: [helplineSchema],
      default: () => DEFAULT_EMERGENCY_HELPLINES.map((entry) => ({ ...entry })),
      validate: {
        validator(value) {
          return Array.isArray(value) && value.length >= 1 && value.length <= 12;
        },
        message: 'emergencyHelplines must contain between 1 and 12 entries',
      },
    },

    /** Incremented by every accepted PUT. */
    version: { type: Number, default: 1, min: 1 },

    /** Admin who last wrote the document (Phase 9 PUT). */
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  },
  {
    timestamps: true,
    versionKey: false,
    strict: 'throw',
    toJSON: { virtuals: false },
  }
);

// `unique: true` on `key` already creates the single index this model needs; a
// second index here would only double the write cost of a collection that
// effectively holds one row.

/**
 * The values an auto-seed writes. Returned as a fresh object every call so a
 * caller cannot mutate the defaults for the rest of the process.
 */
function defaultConfigValues() {
  return {
    key: GLOBAL_CONFIG_KEY,
    privacyPolicyUrl: '',
    termsUrl: '',
    globalWarningThresholds: { ...DEFAULT_GLOBAL_WARNING_THRESHOLDS },
    maintenanceMode: false,
    emergencyHelplines: DEFAULT_EMERGENCY_HELPLINES.map((entry) => ({ ...entry })),
    version: 1,
    updatedBy: null,
  };
}

/**
 * Fetch the singleton, creating it from the defaults on first use.
 *
 * The upsert is a single atomic `findOneAndUpdate` instead of
 * `findOne()` then `create()`: two requests arriving on a cold cache would
 * otherwise both decide the document is missing and race to insert it. The
 * unique index makes the loser fail, and the retry path below turns that
 * failure into the winner's document.
 *
 * @returns {Promise<import('mongoose').HydratedDocument<any>>}
 */
appConfigSchema.statics.getOrSeed = async function getOrSeed() {
  try {
    return await this.findOneAndUpdate(
      { key: GLOBAL_CONFIG_KEY },
      { $setOnInsert: defaultConfigValues() },
      { upsert: true, returnDocument: 'after', setDefaultsOnInsert: true, runValidators: true }
    );
  } catch (error) {
    // Duplicate key: another request seeded it between our upsert and its index
    // check. Read the winner instead of failing a GET on a cold cache.
    if (error && error.code === 11_000) {
      const existing = await this.findOne({ key: GLOBAL_CONFIG_KEY });
      if (existing) return existing;
    }
    throw error;
  }
};

/**
 * Apply a validated partial update and bump the version.
 *
 * @param {{ updates: object, adminId?: unknown }} input
 * @returns {Promise<import('mongoose').HydratedDocument<any>>}
 */
appConfigSchema.statics.applyUpdate = async function applyUpdate({ updates, adminId = null }) {
  const $set = { ...updates };

  if (updates.globalWarningThresholds && typeof updates.globalWarningThresholds === 'object') {
    // $set with a nested object would REPLACE the subdocument and silently drop
    // the threshold keys the admin did not send. Dot-path the provided keys so
    // the update is genuinely partial.
    delete $set.globalWarningThresholds;
    for (const [field, value] of Object.entries(updates.globalWarningThresholds)) {
      $set[`globalWarningThresholds.${field}`] = value;
    }
  }

  if (adminId) $set.updatedBy = adminId;

  await this.getOrSeed();

  return this.findOneAndUpdate(
    { key: GLOBAL_CONFIG_KEY },
    { $set, $inc: { version: 1 } },
    { returnDocument: 'after', runValidators: true }
  );
};

module.exports = mongoose.model('AppConfig', appConfigSchema);
module.exports.GLOBAL_CONFIG_KEY = GLOBAL_CONFIG_KEY;
module.exports.DEFAULT_GLOBAL_WARNING_THRESHOLDS = DEFAULT_GLOBAL_WARNING_THRESHOLDS;
module.exports.DEFAULT_EMERGENCY_HELPLINES = DEFAULT_EMERGENCY_HELPLINES;
module.exports.defaultConfigValues = defaultConfigValues;
module.exports.HELPLINE_NUMBER_REGEX = HELPLINE_NUMBER_REGEX;
