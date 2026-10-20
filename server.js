'use strict';

/**
 * GuardFi — server entry point (Phase 1)
 *
 * Responsibilities:
 *   • validate the environment (imported first, fails fast)
 *   • create the HTTP server and attach Socket.io to it
 *   • listen, then connect to MongoDB (so /health answers while retrying)
 *   • shut down gracefully on SIGINT / SIGTERM, or on a fatal error
 */

const { config } = require('./config/env');

const http = require('node:http');
const logger = require('./utils/logger');
const app = require('./app');
const { connectDatabase, disconnectDatabase } = require('./config/db');
const { initSocket, closeSocket } = require('./sockets');

const httpServer = http.createServer(app);

// Defensive timeouts: a stalled client must not hold a socket forever.
httpServer.headersTimeout = 65_000;
httpServer.requestTimeout = 60_000;
httpServer.keepAliveTimeout = 61_000;

initSocket(httpServer);

let shuttingDown = false;

/**
 * Close everything once, then exit.
 * @param {string} reason
 * @param {number} [exitCode]
 */
async function shutdown(reason, exitCode = 0) {
  if (shuttingDown) return;
  shuttingDown = true;

  logger.warn(`[server] Shutting down (${reason})...`);

  // Hard ceiling: never hang forever waiting for a socket to drain.
  const forceExit = setTimeout(() => {
    logger.error(`[server] Graceful shutdown exceeded ${config.shutdownTimeoutMs}ms — forcing exit.`);
    process.exit(exitCode === 0 ? 1 : exitCode);
  }, config.shutdownTimeoutMs);
  forceExit.unref();

  try {
    await closeSocket();
  } catch (error) {
    logger.error('[server] Socket.io shutdown failed', error);
  }

  httpServer.closeIdleConnections?.();
  const drainTimer = setTimeout(() => httpServer.closeAllConnections?.(), 2_000);
  drainTimer.unref();

  try {
    await new Promise((resolve) => httpServer.close(() => resolve()));
    logger.info('[server] HTTP server closed.');
  } catch (error) {
    logger.error('[server] HTTP server shutdown failed', error);
  }

  try {
    await disconnectDatabase({ force: true });
  } catch (error) {
    logger.error('[server] Database shutdown failed', error);
  }

  clearTimeout(forceExit);
  clearTimeout(drainTimer);

  logger.info('[server] Shutdown complete.');
  process.exit(exitCode);
}

httpServer.on('error', (error) => {
  if (error && error.code === 'EADDRINUSE') {
    logger.error(
      `[server] Port ${config.port} is already in use. Stop the process using it, or change PORT in .env.`
    );
  } else {
    logger.error('[server] HTTP server error', error);
  }

  shutdown('http-server-error', 1);
});

httpServer.listen(config.port, () => {
  logger.info(`[server] GuardFi backend listening on http://localhost:${config.port} (${config.env})`);
  logger.info(`[server] Health check: http://localhost:${config.port}/health`);
});

// Connect after listening so health checks can report a degraded database
// instead of the port staying silent while the driver retries.
connectDatabase()
  .then(() => logger.info('[server] Database ready.'))
  .catch((error) => {
    logger.error('[server] Fatal: could not establish the database connection.', error);
    return shutdown('database-connection-failed', 1);
  });

process.on('SIGINT', () => void shutdown('SIGINT'));
process.on('SIGTERM', () => void shutdown('SIGTERM'));

process.on('unhandledRejection', (reason) => {
  logger.error('[server] Unhandled promise rejection', reason);
  void shutdown('unhandledRejection', 1);
});

process.on('uncaughtException', (error) => {
  logger.error('[server] Uncaught exception', error);
  void shutdown('uncaughtException', 1);
});
