'use strict';

/**
 * GuardFi — SOS Socket.io events (Phase 4)
 *
 * Registered per authenticated connection (sockets/auth.js has already attached
 * `socket.data.user`).
 *
 *   join_sos_room          { alertId } | { roomId }     → ack { alertId, roomId, participants }
 *   location_update        victim only                  → ack { persisted, recordedAt }
 *                          broadcasts `nominee_location_stream` to the room
 *   stop_sos               owner only                   → ack { status, resolvedAt }
 *                          broadcasts `sos:stopped` to the room
 *
 * Hard rules:
 *   • Every payload is validated with the same zod schemas the REST API uses; a
 *     bad packet becomes an ack with `ok:false, code:VALIDATION_FAILED`, never a
 *     thrown exception that could take the process down.
 *   • Only the alert's owner may send `location_update` or `stop_sos`. A guardian
 *     can join and watch, not move the victim's marker or end the alert.
 *   • Every handler is wrapped so a rejected promise, a CastError or a database
 *     outage produces a clean ack. Socket.io has no Express error middleware.
 *   • `location_update` is rate-limited PER SOCKET (SOS_MAX_LOCATION_UPDATES_PER_SECOND)
 *     before it touches the database, and persistence itself is further
 *     throttled per alert in sosService. Broadcasts still go out every packet:
 *     live tracking comes from RAM, durability is sampled.
 */

const { config } = require('../config/env');
const logger = require('../utils/logger');
const ApiError = require('../utils/ApiError');
const SosAlert = require('../models/SosAlert');
const {
  authorizeRoom,
  findAlert,
  recordLocation,
  resolveSos,
  roomName,
  userRoom,
} = require('../services/sosService');
const {
  joinSosRoomSchema,
  locationUpdateSchema,
  stopSosSchema,
  zodIssues,
} = require('../validators/sos.validator');

/**
 * Wrap a handler so it can never reject into the socket.
 * @param {((payload: any) => Promise<object>)|Function} ackOrHandler
 * @param {Function} maybeHandler
 */
function respond(ackOrHandler, maybeHandler) {
  const ack = typeof ackOrHandler === 'function' ? ackOrHandler : null;
  const handler = maybeHandler || ackOrHandler;

  Promise.resolve()
    .then(handler)
    .then((result) => {
      if (typeof ack === 'function') ack({ ok: true, ...(result || {}) });
    })
    .catch((error) => {
      const isApiError = error instanceof ApiError;
      const payload = {
        ok: false,
        code: isApiError ? error.code || `HTTP_${error.statusCode}` : 'SOS_INTERNAL',
        message: isApiError ? error.message : 'The request could not be completed.',
        ...(isApiError && error.errors ? { errors: error.errors } : {}),
      };

      if (!isApiError) logger.error('[socket] SOS handler failed unexpectedly', error);

      if (typeof ack === 'function') ack(payload);
    });
}

/**
 * @param {import('zod').ZodTypeAny} schema
 * @param {unknown} payload
 */
function parseOrThrow(schema, payload) {
  const result = schema.safeParse(payload === undefined || payload === null ? {} : payload);

  if (!result.success) {
    throw new ApiError(400, 'Validation failed.', { errors: zodIssues(result.error), code: 'VALIDATION_FAILED' });
  }

  return result.data;
}

/**
 * Token bucket, per socket, in memory. Predictable cost, no Redis needed, and
 * reset automatically when the socket disconnects.
 *
 * @param {import('socket.io').Socket} socket
 * @param {number} [now]
 */
function consumeLocationBudget(socket, now = Date.now()) {
  const max = config.sos.maxLocationUpdatesPerSecond;
  const bucket = socket.data.locationRateLimit || { tokens: max, updatedAt: now };

  const elapsedMs = Math.max(0, now - bucket.updatedAt);
  bucket.tokens = Math.min(max, bucket.tokens + (elapsedMs / 1000) * max);
  bucket.updatedAt = now;

  if (bucket.tokens < 1) {
    socket.data.locationRateLimit = bucket;
    return false;
  }

  bucket.tokens -= 1;
  socket.data.locationRateLimit = bucket;
  return true;
}

/**
 * Owner-only operations must resolve the alert first and check ownership.
 * @param {{ alertId?: string, roomId?: string }} reference
 * @param {{ id: string }} user
 */
async function requireOwnedActiveAlert(reference, user) {
  const alert = await findAlert(reference);

  if (String(alert.userId) !== String(user.id)) {
    throw new ApiError(403, 'Only the person who triggered this alert can update or stop it.', {
      code: 'SOS_FORBIDDEN',
    });
  }

  if (alert.status !== SosAlert.STATUSES.ACTIVE) {
    throw new ApiError(409, 'This SOS alert is no longer active.', { code: 'SOS_INACTIVE' });
  }

  return alert;
}

/**
 * @param {import('socket.io').Server} io
 * @param {import('socket.io').Socket} socket
 */
function registerSosHandlers(io, socket) {
  const user = socket.data.user;

  // Personal room: REST-triggered events (sos:created / sos:resolved) reach every
  // device on this account even before it joins an alert room.
  socket.join(userRoom(user.id));

  socket.emit('server:ready', {
    phase: 4,
    userId: user.id,
    events: ['join_sos_room', 'location_update', 'stop_sos'],
  });

  socket.on('join_sos_room', (payload, ack) =>
    respond(ack, async () => {
      const parsed = parseOrThrow(joinSosRoomSchema, payload);
      const alert = await authorizeRoom({ user, alertId: parsed.alertId, roomId: parsed.roomId });
      const room = roomName(alert);

      await socket.join(room);

      const participants = io.sockets.adapter.rooms.get(room)?.size ?? 1;

      socket.emit('sos_joined', {
        alertId: String(alert._id),
        roomId: alert.roomId,
        status: alert.status,
      });

      logger.info(`[socket] User ${user.id} joined SOS room ${alert.roomId} (${participants} participant(s)).`);

      return {
        alertId: String(alert._id),
        roomId: alert.roomId,
        status: alert.status,
        participants,
      };
    })
  );

  socket.on('location_update', (payload, ack) =>
    respond(ack, async () => {
      const parsed = parseOrThrow(locationUpdateSchema, payload);

      if (!consumeLocationBudget(socket)) {
        throw new ApiError(429, 'Location updates are arriving too quickly; some were dropped.', {
          code: 'SOS_RATE_LIMITED',
        });
      }

      const alert = await requireOwnedActiveAlert(parsed, user);

      const result = await recordLocation({
        userId: user.id,
        alertId: String(alert._id),
        location: parsed,
      });

      const broadcast = {
        alertId: String(alert._id),
        roomId: alert.roomId,
        latitude: parsed.latitude,
        longitude: parsed.longitude,
        accuracy: parsed.accuracy ?? null,
        recordedAt: result.recordedAt.toISOString(),
        // False means "broadcast only, not written": the client can still draw
        // the point; only the durable trail is sampled.
        persisted: result.persisted,
      };

      // Union of the alert room and the owner's personal room. Socket.io
      // deduplicates, so an owner who is also in the room receives it once.
      io.to(roomName(alert)).to(userRoom(user.id)).emit('nominee_location_stream', broadcast);

      return {
        persisted: result.persisted,
        recordedAt: broadcast.recordedAt,
        roomId: alert.roomId,
      };
    })
  );

  socket.on('stop_sos', (payload, ack) =>
    respond(ack, async () => {
      const parsed = parseOrThrow(stopSosSchema, payload);
      const alert = await requireOwnedActiveAlert(parsed, user);

      const snapshot = await resolveSos({ userId: user.id, status: parsed.status, note: parsed.note });

      const event = {
        alertId: snapshot.id,
        roomId: snapshot.roomId,
        status: snapshot.status,
        resolvedAt: snapshot.resolvedAt,
        resolvedBy: user.id,
      };

      io.to(roomName(alert)).to(userRoom(user.id)).emit('sos:stopped', event);

      return {
        alertId: snapshot.id,
        roomId: snapshot.roomId,
        status: snapshot.status,
        resolvedAt: snapshot.resolvedAt,
      };
    })
  );

  socket.on('disconnect', (reason) => {
    logger.debug(`[socket] User ${user.id} disconnected from ${socket.id} (${reason}).`);
  });
}

/**
 * Tear down every live Socket.io session this user holds — used by the
 * account-deletion cascade (Phase 11) before the alert documents disappear.
 *
 * Two separate problems are solved here:
 *   1. an SOS room whose alert is about to be deleted must not stay open for the
 *      victim or their guardians (they would keep broadcasting to a room nothing
 *      can ever resolve);
 *   2. a socket authenticated against an account that no longer exists must be
 *      closed, not left attached to a dead identity until it reconnects and is
 *      rejected by the handshake.
 *
 * Partial failures are counted, never thrown: the deletion itself must proceed.
 *
 * @param {import('socket.io').Server | null} io
 * @param {string} userId
 * @param {{ reason?: string }} [options]
 */
async function closeUserSosSessions(io, userId, { reason = 'ACCOUNT_DELETED' } = {}) {
  const summary = { alertsClosed: 0, roomsEmptied: 0, socketsDisconnected: 0 };

  if (!io) return summary;

  try {
    const alerts = await SosAlert.find({ userId, status: SosAlert.STATUSES.ACTIVE })
      .select('_id roomId')
      .lean();

    for (const alert of alerts) {
      const room = roomName(alert);

      io.in(room).emit('sos:stopped', {
        alertId: String(alert._id),
        roomId: alert.roomId,
        status: 'DELETED',
        reason,
      });
      // `socketsLeave` evicts every socket in the room, guardians included.
      io.in(room).socketsLeave(room);

      summary.alertsClosed += 1;
      summary.roomsEmptied += 1;
    }

    const personalRoom = userRoom(userId);
    const live = await io.in(personalRoom).fetchSockets();
    summary.socketsDisconnected = live.length;

    io.in(personalRoom).emit('account:deleted', { reason, at: new Date().toISOString() });
    // true = close the underlying connection, not just leave the room.
    io.in(personalRoom).disconnectSockets(true);
  } catch (error) {
    logger.error(`[socket] Could not close SOS sessions for user ${userId}: ${error.message}`);
  }

  return summary;
}

module.exports = { registerSosHandlers, consumeLocationBudget, requireOwnedActiveAlert, closeUserSosSessions };
