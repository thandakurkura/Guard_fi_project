'use strict';

/**
 * GuardFi — dashboard analytics (Phase 5)
 *
 * Everything is computed by MongoDB, never by loading collections into Node.
 * There are two/three bounded pipelines, run in parallel:
 *
 *   1. users $facet:
 *        armed     → { $match: { isEmergencyMode: true } } + $count  (uses isEmergencyMode_1)
 *        total     → $count
 *        me        → _id match + $lookup into nominees (uses the compound prefix)
 *                    + $project computing readiness booleans WITHOUT ever
 *                    returning securityPinHash or fcmToken
 *
 *   2. sosalerts $facet:
 *        active         → status match + $count        (uses status_1_createdAt_-1)
 *        recent         → createdAt range + $group      (uses createdAt_-1)
 *        recentTotal    → createdAt range + $count
 *
 *   3. sosalerts $geoNear (only when the caller has a location on file):
 *        initialLocation 2dsphere, maxDistance = radius, query limited to the same
 *        recency window → $group by status.
 *
 * Why $geoNear is a separate pipeline rather than a fourth facet: MongoDB
 * requires $geoNear to be the FIRST stage of its pipeline, and $facet
 * sub-pipelines cannot be led by it. The extra round-trip runs in parallel and
 * is skipped entirely for users without a location.
 *
 * PRIVACY: the nearby aggregate returns COUNTS BY STATUS only. No alert ids, no
 * coordinates, no names of other people's emergencies — the dashboard is global
 * awareness, not a victim-tracking API. Even a nearest-distance value is
 * omitted, because repeated radius queries could triangulate a victim.
 */

const mongoose = require('mongoose');
const { config } = require('../config/env');
const ApiError = require('../utils/ApiError');
const { assertValidObjectId } = require('../utils/validateObjectId');
const User = require('../models/User');
const SosAlert = require('../models/SosAlert');

const MAX_READINESS_SCORE = 100;

/** Weights sum to 100. Partial credit only for guardians (1 = 20, 2+ = 30). */
const READINESS_WEIGHTS = Object.freeze({
  nominees: 30,
  shieldPayPin: 20,
  pushNotifications: 15,
  locationSharing: 15,
  biometric: 10,
  emergencyMode: 10,
});

function emptyStatusCounts() {
  return { ACTIVE: 0, RESOLVED: 0, FALSE_ALARM: 0 };
}

/**
 * @param {string} userId
 * @returns {object[]} aggregation pipeline
 */
function buildUserFacetPipeline(userId) {
  const id = new mongoose.Types.ObjectId(assertValidObjectId(userId, 'userId'));

  return [
    {
      $facet: {
        armed: [{ $match: { isEmergencyMode: true } }, { $count: 'count' }],
        total: [{ $count: 'count' }],
        me: [
          { $match: { _id: id } },
          {
            $lookup: {
              from: 'nominees',
              let: { uid: '$_id' },
              pipeline: [
                { $match: { $expr: { $eq: ['$userId', '$$uid'] } } },
                { $count: 'count' },
              ],
              as: 'nomineeStats',
            },
          },
          {
            $project: {
              isEmergencyMode: 1,
              hasLocation: { $ne: [{ $ifNull: ['$lastKnownLocation', null] }, null] },
              lastKnownLocation: 1,
              // Presence only. The hash itself never leaves MongoDB.
              hasShieldPayPin: { $gt: [{ $strLenCP: { $ifNull: ['$securityPinHash', ''] } }, 0] },
              hasPushToken: { $gt: [{ $strLenCP: { $ifNull: ['$fcmToken', ''] } }, 0] },
              biometricEnabled: { $eq: ['$biometricEnabled', true] },
              nomineeCount: { $ifNull: [{ $first: '$nomineeStats.count' }, 0] },
            },
          },
        ],
      },
    },
  ];
}

/**
 * @param {Date} since
 * @returns {object[]} aggregation pipeline
 */
function buildAlertFacetPipeline(since) {
  return [
    {
      $facet: {
        active: [{ $match: { status: 'ACTIVE' } }, { $count: 'count' }],
        recent: [
          { $match: { createdAt: { $gte: since } } },
          { $group: { _id: '$status', count: { $sum: 1 } } },
        ],
        recentTotal: [{ $match: { createdAt: { $gte: since } } }, { $count: 'count' }],
      },
    },
  ];
}

/**
 * @param {{ coordinates: [number, number], radiusMeters: number, since: Date }} params
 * @returns {object[]} aggregation pipeline
 */
function buildNearbyPipeline({ coordinates, radiusMeters, since }) {
  return [
    {
      $geoNear: {
        near: { type: 'Point', coordinates },
        key: 'initialLocation',
        distanceField: 'distanceMeters',
        maxDistance: radiusMeters,
        spherical: true,
        // Historial alerts are not "nearby right now".
        query: { createdAt: { $gte: since } },
      },
    },
    { $group: { _id: '$status', count: { $sum: 1 } } },
  ];
}

/**
 * @param {{
 *   nomineeCount: number,
 *   hasShieldPayPin: boolean,
 *   hasPushToken: boolean,
 *   hasLocation: boolean,
 *   biometricEnabled: boolean,
 *   emergencyMode: boolean
 * }} profile
 */
function computeReadiness(profile) {
  const nomineeCount = Math.max(0, Number(profile.nomineeCount) || 0);

  const components = [
    {
      key: 'nominees',
      label: 'Guardians on file',
      weight: READINESS_WEIGHTS.nominees,
      earned: nomineeCount >= 2 ? 30 : nomineeCount === 1 ? 20 : 0,
      satisfied: nomineeCount >= 2,
      detail: `${nomineeCount} guardian${nomineeCount === 1 ? '' : 's'}`,
    },
    {
      key: 'shieldPayPin',
      label: 'Shield Pay PIN configured',
      weight: READINESS_WEIGHTS.shieldPayPin,
      earned: profile.hasShieldPayPin ? 20 : 0,
      satisfied: profile.hasShieldPayPin === true,
    },
    {
      key: 'pushNotifications',
      label: 'Push notifications registered',
      weight: READINESS_WEIGHTS.pushNotifications,
      earned: profile.hasPushToken ? 15 : 0,
      satisfied: profile.hasPushToken === true,
    },
    {
      key: 'locationSharing',
      label: 'Location on file',
      weight: READINESS_WEIGHTS.locationSharing,
      earned: profile.hasLocation ? 15 : 0,
      satisfied: profile.hasLocation === true,
    },
    {
      key: 'biometric',
      label: 'Biometric enrolment',
      weight: READINESS_WEIGHTS.biometric,
      earned: profile.biometricEnabled ? 10 : 0,
      satisfied: profile.biometricEnabled === true,
    },
    {
      key: 'emergencyMode',
      label: 'Perimeter armed',
      weight: READINESS_WEIGHTS.emergencyMode,
      earned: profile.emergencyMode ? 10 : 0,
      satisfied: profile.emergencyMode === true,
    },
  ];

  const score = Math.min(
    MAX_READINESS_SCORE,
    components.reduce((total, component) => total + component.earned, 0)
  );

  return {
    score,
    maxScore: MAX_READINESS_SCORE,
    level: score >= 80 ? 'strong' : score >= 50 ? 'moderate' : 'weak',
    components,
  };
}

/**
 * @param {{ userId: string, radiusMeters?: number, windowHours?: number }} params
 */
async function getDashboard({ userId, radiusMeters, windowHours } = {}) {
  const id = assertValidObjectId(userId, 'userId');

  const radius = Number.isFinite(radiusMeters) ? radiusMeters : config.analytics.nearbyRadiusMeters;
  const hours = Number.isFinite(windowHours) ? windowHours : config.analytics.recentWindowHours;
  const since = new Date(Date.now() - hours * 3_600_000);

  const [userFacets, alertFacets] = await Promise.all([
    User.aggregate(buildUserFacetPipeline(id)),
    SosAlert.aggregate(buildAlertFacetPipeline(since)),
  ]);

  const facet = userFacets[0] || {};
  const me = Array.isArray(facet.me) ? facet.me[0] : null;

  if (!me) {
    throw ApiError.notFound('The account for this token no longer exists.');
  }

  const armedUsers = facet.armed?.[0]?.count || 0;
  const totalUsers = facet.total?.[0]?.count || 0;

  const recentByStatus = emptyStatusCounts();
  for (const row of alertFacets[0]?.recent || []) {
    if (row && row._id in recentByStatus) recentByStatus[row._id] = row.count;
  }

  /** @type {{ available: boolean, radiusMeters: number, count: number, byStatus: Record<string, number>, reason?: string }} */
  const nearby = {
    available: false,
    radiusMeters: radius,
    count: 0,
    byStatus: emptyStatusCounts(),
    reason: 'no_location_on_file',
  };

  const coordinates = me.lastKnownLocation?.coordinates;

  if (me.hasLocation === true && Array.isArray(coordinates) && coordinates.length === 2) {
    const rows = await SosAlert.aggregate(
      buildNearbyPipeline({ coordinates, radiusMeters: radius, since })
    );

    const byStatus = emptyStatusCounts();
    let count = 0;

    for (const row of rows) {
      if (!row || !(row._id in byStatus)) continue;
      byStatus[row._id] = row.count;
      count += row.count;
    }

    nearby.available = true;
    nearby.count = count;
    nearby.byStatus = byStatus;
    delete nearby.reason;
  }

  const nomineeCount = me.nomineeCount || 0;

  const readiness = computeReadiness({
    nomineeCount,
    hasShieldPayPin: me.hasShieldPayPin === true,
    hasPushToken: me.hasPushToken === true,
    hasLocation: me.hasLocation === true,
    biometricEnabled: me.biometricEnabled === true,
    emergencyMode: me.isEmergencyMode === true,
  });

  return {
    generatedAt: new Date().toISOString(),
    perimeter: {
      armedUsers,
      totalUsers,
      armedPercent: totalUsers > 0 ? Math.round((armedUsers / totalUsers) * 100) : 0,
    },
    alerts: {
      activeNow: alertFacets[0]?.active?.[0]?.count || 0,
      recent: {
        windowHours: hours,
        total: alertFacets[0]?.recentTotal?.[0]?.count || 0,
        byStatus: recentByStatus,
      },
      nearby,
    },
    readiness: {
      ...readiness,
      nomineeCount,
    },
    meta: {
      radiusMeters: radius,
      windowHours: hours,
      userLocationAvailable: me.hasLocation === true,
    },
  };
}

module.exports = {
  getDashboard,
  computeReadiness,
  buildUserFacetPipeline,
  buildAlertFacetPipeline,
  buildNearbyPipeline,
  READINESS_WEIGHTS,
  MAX_READINESS_SCORE,
};
