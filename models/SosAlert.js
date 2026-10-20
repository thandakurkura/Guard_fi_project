'use strict';

/**
 * GuardFi — SOS alert model (Phase 4)
 *
 * One document per triggered SOS. It holds the alert's identity, its lifecycle
 * status, the GeoJSON starting point, a bounded trail of live-location
 * breadcrumbs, and which guardians were notified.
 *
 * Design decisions that matter:
 *
 *   • ONE ACTIVE ALERT PER USER, enforced by a partial unique index. A double
 *     tap on the SOS button, a retried request, or two phones signed into the
 *     same account must not create two rooms with two different guardian
 *     audiences. The service turns the resulting E11000 into "already active,
 *     join this room instead".
 *
 *   • `initialLocation` carries a 2dsphere index (the spec's requirement) so
 *     Phase 5's `$geoNear` can find alerts near a point without loading the
 *     collection into Node.
 *
 *   • `locationHistory` is CAPPED at SOS_LOCATION_HISTORY_LIMIT by the same
 *     atomic `$push` that adds a point (`$slice`), never by a read-then-write.
 *     A five-minute emergency at 10 updates/second would otherwise produce a
 *     document that grows without bound and eventually exceeds the 16 MB limit.
 *
 *   • Persistence itself is throttled in services/sosService.js — the array is
 *     the durable trail, not a log of every packet. Broadcasts are in RAM.
 *
 *   • `roomId` is a short random bearer-ish code (12 URL-safe characters), not
 *     the ObjectId. It is safe to put in an SMS and cannot be guessed by walking
 *     ObjectIds. Joining still requires a verified socket identity that is either
 *     the owner or one of the notified guardians (see sosService.authorizeRoom).
 */

const crypto = require('node:crypto');
const mongoose = require('mongoose');

const STATUSES = Object.freeze({ ACTIVE: 'ACTIVE', RESOLVED: 'RESOLVED', FALSE_ALARM: 'FALSE_ALARM' });

/** GeoJSON Point: [longitude, latitude], both in range. */
const pointSchema = new mongoose.Schema(
  {
    type: {
      type: String,
      enum: { values: ['Point'], message: 'location.type must be "Point"' },
      default: 'Point',
      required: true,
    },
    coordinates: {
      type: [Number],
      required: [true, 'location.coordinates is required'],
      validate: [
        {
          validator: (value) => Array.isArray(value) && value.length === 2,
          message: 'location.coordinates must be exactly [longitude, latitude]',
        },
        {
          validator: (value) => {
            if (!Array.isArray(value) || value.length !== 2) return true;
            const [longitude, latitude] = value;
            return (
              Number.isFinite(longitude) &&
              Number.isFinite(latitude) &&
              longitude >= -180 &&
              longitude <= 180 &&
              latitude >= -90 &&
              latitude <= 90
            );
          },
          message: 'longitude must be within [-180, 180] and latitude within [-90, 90]',
        },
      ],
    },
  },
  { _id: false, versionKey: false }
);

/**
 * A breadcrumb stays a plain [lng, lat] pair rather than a second GeoJSON
 * object: history is about the client's polyline, not about spatial queries, and
 * the compact shape keeps a 200-point trail small.
 */
const breadcrumbSchema = new mongoose.Schema(
  {
    coordinates: {
      type: [Number],
      required: true,
      validate: [
        {
          validator: (value) => Array.isArray(value) && value.length === 2,
          message: 'coordinates must be exactly [longitude, latitude]',
        },
        {
          validator: (value) => {
            if (!Array.isArray(value) || value.length !== 2) return true;
            const [longitude, latitude] = value;
            return (
              Number.isFinite(longitude) &&
              Number.isFinite(latitude) &&
              longitude >= -180 &&
              longitude <= 180 &&
              latitude >= -90 &&
              latitude <= 90
            );
          },
          message: 'longitude must be within [-180, 180] and latitude within [-90, 90]',
        },
      ],
    },
    accuracy: {
      type: Number,
      default: null,
      min: [0, 'accuracy cannot be negative'],
      max: [100_000, 'accuracy is implausibly large'],
    },
    recordedAt: {
      type: Date,
      default: Date.now,
    },
  },
  { _id: false, versionKey: false }
);

const counterSchema = new mongoose.Schema(
  {
    attempted: { type: Number, default: 0, min: 0 },
    sent: { type: Number, default: 0, min: 0 },
    failed: { type: Number, default: 0, min: 0 },
    skipped: { type: Number, default: 0, min: 0 },
  },
  { _id: false, versionKey: false }
);

const sosAlertSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'userId is required'],
    },

    status: {
      type: String,
      enum: { values: Object.values(STATUSES), message: 'status must be ACTIVE, RESOLVED or FALSE_ALARM' },
      default: STATUSES.ACTIVE,
      required: true,
    },

    /**
     * Short unguessable code shared with guardians and used as the Socket.io
     * room key (`sos:<roomId>`). Defaulted in the schema so no code path can
     * create an alert without one.
     */
    roomId: {
      type: String,
      required: true,
      unique: true,
      default: () => crypto.randomBytes(9).toString('base64url'),
      match: [/^[A-Za-z0-9_-]{12}$/, 'roomId must be 12 URL-safe characters'],
    },

    initialLocation: {
      type: pointSchema,
      required: [true, 'initialLocation is required'],
    },

    /** Latest persisted point. Updated only on a throttled write, never per packet. */
    lastLocation: {
      type: pointSchema,
      default: undefined,
    },

    lastLocationAt: {
      type: Date,
      default: null,
    },

    /** Capped trail; see the model comment. */
    locationHistory: {
      type: [breadcrumbSchema],
      default: [],
    },

    /** Guardians that were fanned out to when the alert opened. */
    notifiedNominees: {
      type: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Nominee' }],
      default: [],
    },

    /** Outcome of the push/SMS fan-out, for support without reading logs. */
    notification: {
      attemptedAt: { type: Date, default: null },
      push: { type: counterSchema, default: () => ({}) },
      sms: { type: counterSchema, default: () => ({}) },
    },

    /** Optional user-supplied context ("followed by a car since the station"). */
    triggerNote: {
      type: String,
      trim: true,
      maxlength: [280, 'triggerNote cannot exceed 280 characters'],
      default: null,
    },

    resolvedAt: { type: Date, default: null },

    resolutionNote: {
      type: String,
      trim: true,
      maxlength: [280, 'resolutionNote cannot exceed 280 characters'],
      default: null,
    },
  },
  {
    timestamps: true,
    versionKey: false,
    toJSON: {
      transform: (doc, ret) => {
        delete ret.__v;
        return ret;
      },
      virtuals: false,
    },
  }
);

// Ownership + status lookups ("do I already have an ACTIVE alert?").
sosAlertSchema.index({ userId: 1, status: 1 });
// Phase 5 needs recent alerts by status without a collection scan.
sosAlertSchema.index({ status: 1, createdAt: -1 });
// The dashboard's "last N hours" facet starts with a createdAt range, which the
// status-prefixed compound index cannot serve; this one keeps it an index scan.
sosAlertSchema.index({ createdAt: -1 });
// The spec's geo index, so "alerts near me" is a $geoNear in Phase 5.
sosAlertSchema.index({ initialLocation: '2dsphere' });

// ONE active alert per user. Partial, so resolved history is unlimited.
sosAlertSchema.index(
  { userId: 1 },
  { unique: true, partialFilterExpression: { status: STATUSES.ACTIVE }, name: 'one_active_sos_per_user' }
);

/** @param {import('mongoose').Types.ObjectId|string} userId */
sosAlertSchema.statics.findActiveForUser = function findActiveForUser(userId) {
  return this.findOne({ userId, status: STATUSES.ACTIVE });
};

/**
 * Append one breadcrumb and update the last-known point atomically.
 *
 * `$slice: -limit` keeps the newest N entries in the same round-trip, so this
 * can never produce an unbounded document even under a flood of writes.
 *
 * @param {import('mongoose').Types.ObjectId|string} alertId
 * @param {{ coordinates: [number, number], accuracy?: number|null, recordedAt?: Date }} breadcrumb
 * @param {number} limit
 */
sosAlertSchema.statics.appendBreadcrumb = async function appendBreadcrumb(alertId, breadcrumb, limit) {
  const recordedAt = breadcrumb.recordedAt || new Date();
  const result = await this.updateOne(
    { _id: alertId, status: STATUSES.ACTIVE },
    {
      $set: {
        lastLocation: { type: 'Point', coordinates: breadcrumb.coordinates },
        lastLocationAt: recordedAt,
      },
      $push: {
        locationHistory: {
          $each: [
            {
              coordinates: breadcrumb.coordinates,
              accuracy: breadcrumb.accuracy ?? null,
              recordedAt,
            },
          ],
          $slice: -Math.max(1, limit),
        },
      },
    }
  );

  return { modified: (result?.modifiedCount ?? 0) > 0 };
};

module.exports = mongoose.model('SosAlert', sosAlertSchema);
module.exports.STATUSES = STATUSES;
