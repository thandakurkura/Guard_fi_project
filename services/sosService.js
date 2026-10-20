'use strict';

/**
 * GuardFi — SOS lifecycle (Phase 4)
 *
 * This file owns the rules that make an emergency alert trustworthy:
 *
 *   triggerSos()
 *     • one ACTIVE alert per user (service check + database partial unique index),
 *       so a double tap joins the existing room instead of opening a second one;
 *     • the GeoJSON starting point is written once, then the alert is snapshotted
 *       for the client;
 *     • the guardians are resolved and stored on the alert BEFORE notifications
 *       go out, so "who was told" survives an SMS provider outage.
 *
 *   resolveSos()
 *     • the atomic `{ userId, status: 'ACTIVE' }` filter is the whole authorisation
 *       story: you can only close your own alert, and only while it is active.
 *
 *   recordLocation()
 *     • persistence is throttled per alert (SOS_LOCATION_PERSIST_INTERVAL_SECONDS):
 *       the socket handler broadcasts every packet from RAM, but MongoDB sees at
 *       most one write per interval;
 *     • the breadcrumb append is atomic and capped ($push + $slice), so a flood
 *       of packets cannot grow the document without bound.
 *
 *   authorizeRoom()
 *     • a socket may join `sos:<roomId>` only if it is the owner or a guardian
 *       stored on that alert. A leaked room code alone is not enough.
 *
 * Notification delivery is deliberately detached from the HTTP response: an SOS
 * must be acknowledged immediately even when FCM or an SMS gateway is slow. The
 * fan-out runs in the background and its outcome is persisted on the alert.
 */

const { config } = require('../config/env');
const logger = require('../utils/logger');
const ApiError = require('../utils/ApiError');
const Nominee = require('../models/Nominee');
const SosAlert = require('../models/SosAlert');
const { sendAlertPush } = require('./pushService');
const { sendSosSms } = require('./smsService');

const ROOM_PREFIX = 'sos:';
const MAX_THROTTLE_ENTRIES = 5_000;

/** alertId → epoch ms of the last persisted breadcrumb. */
const lastPersistedAt = new Map();

/** @param {{ roomId: string }} alert */
function roomName(alert) {
  return `${ROOM_PREFIX}${alert.roomId}`;
}

/** Socket room for one user's own alerts (survives a missed room join). */
function userRoom(userId) {
  return `user:${String(userId)}`;
}

/**
 * @param {{ latitude: number, longitude: number }} location
 * @returns {{ type: 'Point', coordinates: [number, number] }}
 */
function toGeoPoint(location) {
  return { type: 'Point', coordinates: [location.longitude, location.latitude] };
}

/** GeoJSON → API shape (latitude/longitude are what the Dart client renders). */
function serializeLocation(point) {
  if (!point || !Array.isArray(point.coordinates) || point.coordinates.length !== 2) return null;
  const [longitude, latitude] = point.coordinates;
  return { latitude, longitude };
}

/** API shape for the stored alert. Never returns a push token (none is stored here). */
function serializeAlert(alert) {
  const raw = typeof alert.toObject === 'function' ? alert.toObject() : alert;

  return {
    id: String(raw._id),
    status: raw.status,
    roomId: raw.roomId,
    initialLocation: serializeLocation(raw.initialLocation),
    lastLocation: serializeLocation(raw.lastLocation),
    lastLocationAt: raw.lastLocationAt ?? null,
    locationHistory: (raw.locationHistory || []).map((crumb) => ({
      latitude: crumb.coordinates?.[1] ?? null,
      longitude: crumb.coordinates?.[0] ?? null,
      accuracy: crumb.accuracy ?? null,
      recordedAt: crumb.recordedAt ?? null,
    })),
    notifiedNomineeIds: (raw.notifiedNominees || []).map((id) => String(id)),
    notifiedCount: Array.isArray(raw.notifiedNominees) ? raw.notifiedNominees.length : 0,
    notification: raw.notification ?? null,
    triggerNote: raw.triggerNote ?? null,
    resolvedAt: raw.resolvedAt ?? null,
    resolutionNote: raw.resolutionNote ?? null,
    createdAt: raw.createdAt ?? null,
    updatedAt: raw.updatedAt ?? null,
  };
}

/**
 * Should this alert's location be written to MongoDB now?
 *
 * Mutates the throttle when it returns true (the caller is about to write), so a
 * failed write still charges the interval — one lost breadcrumb is preferable to
 * a retry storm against an overloaded database during an emergency.
 *
 * @param {string|import('mongoose').Types.ObjectId} alertId
 * @param {number} [now] epoch ms, injectable for tests
 */
function shouldPersist(alertId, now = Date.now()) {
  const key = String(alertId);
  const intervalMs = config.sos.persistIntervalSeconds * 1000;
  const last = lastPersistedAt.get(key);

  if (last !== undefined && now - last < intervalMs) return false;

  // Bound the map: only active alerts should be here, but a crashed shutdown can
  // leave entries behind. Evict the oldest insertion order.
  if (!lastPersistedAt.has(key) && lastPersistedAt.size >= MAX_THROTTLE_ENTRIES) {
    const oldest = lastPersistedAt.keys().next().value;
    if (oldest !== undefined) lastPersistedAt.delete(oldest);
  }

  lastPersistedAt.set(key, now);
  return true;
}

function clearThrottle(alertId) {
  lastPersistedAt.delete(String(alertId));
}

/** Test hook. */
function resetLocationThrottle() {
  lastPersistedAt.clear();
}

/**
 * Fetch an alert by id or room code. Deliberately unscoped: the caller must
 * still authorise, and scoping only by `userId` would make a guardian's lookup
 * impossible.
 *
 * @param {{ alertId?: string, roomId?: string }} reference
 */
async function findAlert(reference) {
  const filter = reference.alertId ? { _id: reference.alertId } : { roomId: reference.roomId };
  const alert = await SosAlert.findOne(filter);

  if (!alert) throw new ApiError(404, 'That SOS alert was not found.', { code: 'SOS_NOT_FOUND' });

  return alert;
}

/**
 * Authorise a socket join. An alert that is no longer active is refused even for
 * its owner: the room is a live channel, not an archive.
 *
 * @param {{ user: { id: string, phone: string }, alertId?: string, roomId?: string }} params
 */
async function authorizeRoom({ user, alertId, roomId }) {
  const alert = await findAlert({ alertId, roomId });

  if (alert.status !== SosAlert.STATUSES.ACTIVE) {
    throw new ApiError(409, 'This SOS alert is no longer active.', { code: 'SOS_INACTIVE' });
  }

  if (String(alert.userId) === String(user.id)) return alert;

  const isGuardian = await Nominee.exists({ userId: alert.userId, phone: user.phone });

  if (!isGuardian) {
    throw new ApiError(403, 'You are not the owner or a guardian on this alert.', { code: 'SOS_FORBIDDEN' });
  }

  return alert;
}

/**
 * Open an alert, or return the one that is already open.
 *
 * @param {{ userId: string, ownerName?: string|null, location: { latitude: number, longitude: number, accuracy?: number|null }, message?: string|null }} params
 */
async function triggerSos({ userId, ownerName = null, location, message = null }) {
  const existing = await SosAlert.findActiveForUser(userId);

  if (existing) {
    logger.info(`[sos] User ${userId} already has ACTIVE alert ${existing._id}; returning it instead of duplicating.`);
    return { alert: serializeAlert(existing), alreadyActive: true, nominees: [] };
  }

  const now = new Date();
  const point = toGeoPoint(location);

  let alert;

  try {
    alert = await SosAlert.create({
      userId,
      status: SosAlert.STATUSES.ACTIVE,
      initialLocation: point,
      lastLocation: point,
      lastLocationAt: now,
      locationHistory: [
        {
          coordinates: point.coordinates,
          accuracy: location.accuracy ?? null,
          recordedAt: now,
        },
      ],
      triggerNote: message ?? null,
    });
  } catch (error) {
    // Two taps in the same instant: the partial unique index rejects the second
    // insert. The winner's alert is the right answer for both requests.
    if (error && error.code === 11_000) {
      const raced = await SosAlert.findActiveForUser(userId);

      if (raced) return { alert: serializeAlert(raced), alreadyActive: true, nominees: [] };
    }

    throw error;
  }

  const nominees = await Nominee.find({ userId }).select('name phone +fcmToken').lean();

  if (nominees.length > 0) {
    await SosAlert.updateOne(
      { _id: alert._id, status: SosAlert.STATUSES.ACTIVE },
      { $set: { notifiedNominees: nominees.map((nominee) => nominee._id) } }
    );
    alert.notifiedNominees = nominees.map((nominee) => nominee._id);
  }

  logger.warn(
    `[sos] ALERT ${alert._id} opened by user ${userId} (room ${alert.roomId}) with ${nominees.length} guardian(s) on file.`
  );

  return { alert: serializeAlert(alert), alreadyActive: false, nominees };
}

/**
 * Close the caller's active alert.
 * @param {{ userId: string, status?: 'RESOLVED'|'FALSE_ALARM', note?: string|null }} params
 */
async function resolveSos({ userId, status = 'RESOLVED', note = null }) {
  const alert = await SosAlert.findOneAndUpdate(
    { userId, status: SosAlert.STATUSES.ACTIVE },
    { $set: { status, resolvedAt: new Date(), resolutionNote: note ?? null } },
    { returnDocument: 'after', runValidators: true }
  );

  if (!alert) {
    throw new ApiError(404, 'You have no active SOS alert to resolve.', { code: 'SOS_NONE_ACTIVE' });
  }

  clearThrottle(alert._id);
  logger.warn(`[sos] ALERT ${alert._id} closed as ${status} by user ${userId}.`);

  return serializeAlert(alert);
}

/** @param {string} userId @returns {Promise<object|null>} */
async function getActiveSos(userId) {
  const alert = await SosAlert.findActiveForUser(userId);
  return alert ? serializeAlert(alert) : null;
}

/**
 * Validate ownership and record one location packet, subject to the throttle.
 *
 * @param {{
 *   userId: string,
 *   alertId: string,
 *   location: { latitude: number, longitude: number, accuracy?: number|null },
 *   now?: number
 * }} params
 */
async function recordLocation({ userId, alertId, location, now = Date.now() }) {
  const alert = await SosAlert.findOne({
    _id: alertId,
    userId,
    status: SosAlert.STATUSES.ACTIVE,
  }).select('_id roomId');

  if (!alert) {
    throw new ApiError(404, 'No active SOS alert matches that id.', { code: 'SOS_INACTIVE' });
  }

  const recordedAt = new Date(now);
  const allowed = shouldPersist(alert._id, now);

  if (!allowed) {
    return { persisted: false, recordedAt, roomId: alert.roomId };
  }

  const { modified } = await SosAlert.appendBreadcrumb(
    alert._id,
    {
      coordinates: [location.longitude, location.latitude],
      accuracy: location.accuracy ?? null,
      recordedAt,
    },
    config.sos.historyLimit
  );

  // The alert was resolved between the ownership read and the write.
  if (!modified) {
    throw new ApiError(409, 'This SOS alert is no longer active.', { code: 'SOS_INACTIVE' });
  }

  return { persisted: true, recordedAt, roomId: alert.roomId };
}

/**
 * Push + SMS fan-out to the alert's guardians. Never throws: it is called in the
 * background after the SOS has already been acknowledged.
 *
 * Fallback rule (worth being explicit about):
 *   • guardians without a push token always get an SMS;
 *   • if push was not configured / failed entirely, EVERY guardian gets the SMS;
 *   • a partial push failure does not trigger duplicate texts, because the
 *     per-token result cannot be mapped back to a guardian after de-duplication.
 *
 * `transports` is a test seam: the harness injects deterministic push/SMS
 * implementations to prove targeting without credentials or credit. In
 * production it is empty and the real transports are used.
 *
 * @param {{
 *   alert: object,
 *   nominees: object[],
 *   ownerName?: string|null,
 *   transports?: { sendPush?: Function, sendSms?: Function }
 * }} params
 */
async function notifyNominees({ alert, nominees, ownerName = null, transports = {} }) {
  const sendPush = transports.sendPush || sendAlertPush;
  const sendSms = transports.sendSms || sendSosSms;
  const recipients = Array.isArray(nominees) ? nominees : [];
  const pushTokens = recipients.map((nominee) => nominee.fcmToken).filter(Boolean);

  const push =
    pushTokens.length > 0
      ? await sendPush({
          tokens: pushTokens,
          title: 'GuardFi SOS',
          body: `${ownerName || 'Someone you guard'} triggered an SOS. Open GuardFi to follow their live location.`,
          data: {
            type: 'SOS_ALERT',
            alertId: String(alert.id ?? alert._id),
            roomId: alert.roomId,
            latitude: alert.initialLocation?.latitude,
            longitude: alert.initialLocation?.longitude,
          },
        })
      : { attempted: 0, sent: 0, failed: 0, skipped: 0, reason: 'no_tokens' };

  const pushUnavailable =
    push.reason === 'not_configured' || push.reason === 'firebase_error' || push.reason === 'all_failed';

  const smsTargets = config.sos.smsFallbackEnabled
    ? recipients.filter((nominee) => pushUnavailable || !nominee.fcmToken)
    : [];

  const smsResults = await Promise.all(
    smsTargets.map((nominee) =>
      sendSms({
        phone: nominee.phone,
        ownerName,
        roomId: alert.roomId,
        trackingUrl: config.sos.trackingBaseUrl,
      })
    )
  );

  const smsSent = smsResults.filter((result) => result.delivered).length;
  const smsSkipped = smsResults.filter((result) => result.reason === 'not_configured').length;
  const smsFailed = smsResults.length - smsSent - smsSkipped;

  const summary = {
    attemptedAt: new Date(),
    push: {
      attempted: push.attempted ?? 0,
      sent: push.sent ?? 0,
      failed: push.failed ?? 0,
      skipped: push.skipped ?? 0,
    },
    sms: {
      attempted: smsResults.length,
      sent: smsSent,
      failed: smsFailed,
      skipped: smsSkipped,
    },
  };

  try {
    await SosAlert.updateOne({ _id: alert._id ?? alert.id }, { $set: { notification: summary } });
  } catch (error) {
    logger.error(`[sos] Could not persist the notification summary for alert ${alert._id ?? alert.id}.`, error);
  }

  logger.info(
    `[sos] Fan-out for alert ${alert._id ?? alert.id}: push ${summary.push.sent}/${summary.push.attempted}, SMS ${summary.sms.sent}/${summary.sms.attempted}.`
  );

  return summary;
}

/**
 * Fire-and-forget wrapper. The SOS response must never wait for (or fail because
 * of) a third-party notification API.
 */
function dispatchSosNotifications(params) {
  return notifyNominees(params).catch((error) => {
    logger.error('[sos] Notification fan-out failed unexpectedly; the alert itself is unaffected.', error);
    return null;
  });
}

module.exports = {
  triggerSos,
  resolveSos,
  getActiveSos,
  recordLocation,
  authorizeRoom,
  findAlert,
  notifyNominees,
  dispatchSosNotifications,
  serializeAlert,
  serializeLocation,
  toGeoPoint,
  roomName,
  userRoom,
  shouldPersist,
  clearThrottle,
  resetLocationThrottle,
  ROOM_PREFIX,
};
