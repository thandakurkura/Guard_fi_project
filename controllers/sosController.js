'use strict';

/**
 * GuardFi — SOS controller (Phase 4)
 *
 * Thin transport layer over services/sosService.js. Its only extra job is to
 * publish REST-triggered lifecycle events to Socket.io:
 *
 *   POST /trigger → `sos:created`  to `user:<id>` (every device on the account)
 *   POST /resolve → `sos:stopped`  to the alert room AND `user:<id>`
 *
 * Notification fan-out is started but NOT awaited: the SOS acknowledgement must
 * not wait for FCM or an SMS gateway, and a provider outage must not turn a
 * successful alert into a 500.
 *
 *   POST /api/v1/sos/trigger → 201 (or 200 when an alert is already active)
 *   POST /api/v1/sos/resolve → 200
 *   GET  /api/v1/sos/active  → 200 { alert | null }
 */

const asyncHandler = require('../utils/asyncHandler');
const { sendSuccess } = require('../utils/apiResponse');
const {
  triggerSos,
  resolveSos,
  getActiveSos,
  dispatchSosNotifications,
  roomName,
  userRoom,
} = require('../services/sosService');
const { getSocket } = require('../sockets');

/**
 * @param {string} event
 * @param {string[]} rooms
 * @param {object} payload
 */
function emitToRooms(event, rooms, payload) {
  const io = getSocket();
  if (!io) return;

  // io.to(a).to(b) is a union with per-socket de-duplication.
  let target = io;
  for (const room of rooms) target = target.to(room);
  target.emit(event, payload);
}

/** POST /api/v1/sos/trigger */
const trigger = asyncHandler(async (req, res) => {
  const { location, message } = req.body;

  const result = await triggerSos({
    userId: req.user._id,
    ownerName: req.user.name,
    location,
    message,
  });

  const snapshot = {
    ...result.alert,
    alreadyActive: result.alreadyActive,
  };

  emitToRooms('sos:created', [userRoom(req.user._id)], snapshot);

  if (!result.alreadyActive) {
    // Deliberately not awaited. dispatchSosNotifications() catches its own
    // errors and persists the outcome on the alert.
    void dispatchSosNotifications({
      alert: result.alert,
      nominees: result.nominees,
      ownerName: req.user.name,
    });
  }

  return sendSuccess(res, {
    statusCode: result.alreadyActive ? 200 : 201,
    message: result.alreadyActive
      ? 'You already have an active SOS alert. Join its room instead of starting a second one.'
      : 'SOS alert created. Your guardians are being notified.',
    data: {
      alert: result.alert,
      alreadyActive: result.alreadyActive,
      roomId: result.alert.roomId,
      socket: {
        event: 'join_sos_room',
        room: roomName(result.alert),
        roomId: result.alert.roomId,
      },
    },
  });
});

/** POST /api/v1/sos/resolve */
const resolve = asyncHandler(async (req, res) => {
  const { status, note } = req.body;

  const alert = await resolveSos({ userId: req.user._id, status, note });

  const payload = {
    alertId: alert.id,
    roomId: alert.roomId,
    status: alert.status,
    resolvedAt: alert.resolvedAt,
    resolvedBy: req.user._id,
  };

  emitToRooms('sos:stopped', [roomName(alert), userRoom(req.user._id)], payload);
  emitToRooms('sos:resolved', [userRoom(req.user._id)], payload);

  return sendSuccess(res, {
    statusCode: 200,
    message: status === 'FALSE_ALARM' ? 'SOS alert closed as a false alarm.' : 'SOS alert resolved.',
    data: { alert },
  });
});

/** GET /api/v1/sos/active */
const active = asyncHandler(async (req, res) => {
  const alert = await getActiveSos(req.user._id);

  return sendSuccess(res, {
    statusCode: 200,
    message: alert ? 'You have an active SOS alert.' : 'You have no active SOS alert.',
    data: {
      alert,
      socket: alert ? { event: 'join_sos_room', room: roomName(alert), roomId: alert.roomId } : null,
    },
  });
});

module.exports = { trigger, resolve, active };
