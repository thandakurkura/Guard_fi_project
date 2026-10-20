'use strict';

/**
 * GuardFi — Socket.io engine bootstrap (Phase 1, hardened in Phase 4)
 *
 * Wraps the HTTP server, applies the connection budget, authenticates every
 * handshake with the same JWT as the REST API (sockets/auth.js), and registers
 * the SOS events (sockets/sosSocket.js).
 *
 * Ordering is deliberate:
 *   connection budget → JWT handshake → per-user room + event handlers.
 * The budget is counted at the Engine.IO layer, so unauthenticated floods are
 * refused before any database read, and the handshake check runs before any
 * application event can be delivered.
 */

const { Server } = require('socket.io');
const { socketCorsOptions } = require('../config/cors');
const { config } = require('../config/env');
const logger = require('../utils/logger');
const { normalizeAddress } = require('../utils/net');
const socketAuth = require('./auth');
const { registerSosHandlers } = require('./sosSocket');

/** @type {import('socket.io').Server | null} */
let io = null;

/**
 * Live connection budget, per remote address and in total.
 *
 * Counted at the Engine.IO layer ("connection" / "close") rather than inside
 * `allowRequest`, because engine.io calls `allowRequest` for EVERY request on
 * the socket path — handshakes, polling reads and websocket upgrades alike — so
 * incrementing there would count one client dozens of times.
 *
 * @returns {{ allowed: (req: any) => { ok: boolean, reason?: string }, snapshot: () => { perIp: number, total: number } }}
 */
function createConnectionBudget() {
  const perIp = new Map();
  let total = 0;

  return {
    /**
     * Decide a HANDSHAKE. Follow-up requests on an existing session carry a sid
     * and were already counted, so they always pass.
     * @param {any} req engine.io request
     */
    allowed(req) {
      if (req?._query?.sid) return { ok: true };

      const address = normalizeAddress(req?.socket?.remoteAddress);
      const key = address || 'unknown';
      const current = perIp.get(key) || 0;

      if (config.socket.maxConnectionsPerIp > 0 && current >= config.socket.maxConnectionsPerIp) {
        return { ok: false, reason: `too many concurrent connections from ${key}` };
      }

      if (config.socket.maxConnections > 0 && total >= config.socket.maxConnections) {
        return { ok: false, reason: 'the server is at its connection capacity' };
      }

      return { ok: true };
    },

    add(key) {
      perIp.set(key, (perIp.get(key) || 0) + 1);
      total += 1;
    },

    remove(key) {
      const current = perIp.get(key) || 0;
      if (current <= 1) perIp.delete(key);
      else perIp.set(key, current - 1);
      total = Math.max(0, total - 1);
    },

    snapshot() {
      return { perIp: perIp.size, total };
    },
  };
}

/**
 * @param {import('node:http').Server} httpServer
 * @returns {import('socket.io').Server}
 */
function initSocket(httpServer) {
  if (io) return io;

  // Declared before the Server so `allowRequest` can never observe it unset.
  const budget = createConnectionBudget();

  io = new Server(httpServer, {
    path: '/socket.io',
    serveClient: false,
    cors: socketCorsOptions(),
    transports: ['websocket', 'polling'],
    pingTimeout: 25_000,
    pingInterval: 20_000,
    maxHttpBufferSize: 1e6,
    connectionStateRecovery: {
      maxDisconnectionDuration: 2 * 60 * 1000,
      // MUST stay false. With `true`, a client that briefly drops can be
      // re-attached to its recovered session WITHOUT re-running namespace
      // middleware — so in Phase 4 an expired or revoked token would sail past
      // the JWT handshake check by reconnecting. Recovery still works; it just
      // re-authenticates like a fresh connection.
      skipMiddlewares: false,
    },
    allowRequest: (req, callback) => {
      const decision = budget.allowed(req);

      if (!decision.ok) {
        logger.warn(`[socket] Rejected a handshake from ${req?.socket?.remoteAddress}: ${decision.reason}.`);
        return callback(decision.reason, false);
      }

      return callback(null, true);
    },
  });

  // Engine.IO level, so the count is right for polling and websocket alike and
  // is released even when the failure happens before a namespace is joined.
  io.engine.on('connection', (rawSocket) => {
    const key = normalizeAddress(rawSocket.request?.socket?.remoteAddress) || 'unknown';

    budget.add(key);
    rawSocket.once('close', () => budget.remove(key));
  });

  // Runs before 'connection', for every transport (websocket and polling) and
  // again after a connection-state recovery, because skipMiddlewares is false.
  io.use(socketAuth);

  io.on('connection', (socket) => {
    const user = socket.data.user;

    logger.info(`[socket] connected ${socket.id} as user ${user.id}`);

    socket.on('error', (error) => {
      logger.error(`[socket] error on ${socket.id} (user ${user.id})`, error?.message || error);
    });

    registerSosHandlers(io, socket);
  });

  logger.info('[socket] JWT handshake authentication is enforced for every connection.');
  logger.info(
    `[socket] Connection budget: ${config.socket.maxConnectionsPerIp || 'unlimited'} per address, ${config.socket.maxConnections || 'unlimited'} in total.`
  );

  return io;
}

/** Close the engine so the process can exit cleanly. */
async function closeSocket() {
  if (!io) return;

  await new Promise((resolve) => io.close(() => resolve()));
  io = null;
  logger.info('[socket] Socket.io server closed.');
}

/** @returns {import('socket.io').Server | null} */
function getSocket() {
  return io;
}

module.exports = { initSocket, closeSocket, getSocket };
module.exports.createConnectionBudget = createConnectionBudget;
