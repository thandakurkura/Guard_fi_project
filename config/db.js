'use strict';

/**
 * GuardFi — MongoDB connection (Phase 1)
 *
 *  • retry with exponential backoff + jitter
 *  • explicit connection pooling
 *  • lifecycle event logging
 *  • graceful close on shutdown
 *  • a health probe used by GET /health
 *
 * The HTTP listener starts before this module connects, so /health can answer
 * (503, "degraded") while the driver is still retrying instead of the whole
 * process hanging with a silent port.
 */

const mongoose = require('mongoose');
const { config } = require('./env');
const logger = require('../utils/logger');

const READY_STATE_LABELS = Object.freeze({
  0: 'disconnected',
  1: 'connected',
  2: 'connecting',
  3: 'disconnecting',
  99: 'uninitialized',
});

let listenersBound = false;

/**
 * False until every registered model has finished creating its indexes.
 *
 * This is a readiness gate, not decoration. Mongoose builds indexes in the
 * background after `connect()` resolves, so with only `readyState === 1` as the
 * test the API accepts writes for a short window in which the unique indexes do
 * not exist yet. The Phase 3 harness found exactly that: two nominees with the
 * same phone number were inserted before `{ userId, phone }` was unique, and the
 * later index build then failed. Serving anonymously is better than serving
 * without the constraints that define correctness.
 */
let indexesReady = false;

// Set once connectDatabase() has given up and reported the failure, so the
// driver's later 'error' event during teardown does not log a duplicate,
// misleading second failure.
let connectionFailureReported = false;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function bindConnectionListeners() {
  if (listenersBound) return;
  listenersBound = true;

  const connection = mongoose.connection;

  connection.on('connected', () => {
    logger.info(
      `[db] Connected to MongoDB (${connection.host || 'unknown host'}/${connection.name || config.mongo.dbName})`
    );
  });
  connection.on('reconnected', () => logger.info('[db] MongoDB reconnected.'));
  connection.on('disconnected', () => logger.warn('[db] MongoDB disconnected — the driver will keep retrying.'));
  connection.on('close', () => logger.debug('[db] MongoDB connection closed.'));
  connection.on('error', (error) => {
    if (connectionFailureReported) {
      logger.debug(`[db] Driver reported an additional error after a failed connection attempt: ${error.message}`);
      return;
    }
    logger.error('[db] MongoDB connection error', error);
  });
}

function connectionOptions() {
  return {
    // config/env.js resolved this: the URI's database name when it has one,
    // otherwise MONGO_DB_NAME. Passing it explicitly means a connection string
    // without a database (or with a stray "/") can never dump GuardFi data into
    // a database called "test".
    dbName: config.mongo.dbName,
    maxPoolSize: config.mongo.maxPoolSize,
    minPoolSize: config.mongo.minPoolSize,
    serverSelectionTimeoutMS: config.mongo.serverSelectionTimeoutMs,
    connectTimeoutMS: 10_000,
    socketTimeoutMS: 45_000,
    heartbeatFrequencyMS: 10_000,
    autoIndex: config.mongo.autoIndex,
    // Queries against a dropped connection fail immediately instead of
    // queueing for the buffer timeout and stalling the request.
    bufferCommands: false,
  };
}

/**
 * Connect to MongoDB, retrying with exponential backoff.
 * @returns {Promise<import('mongoose').Connection>}
 */
async function connectDatabase() {
  const connection = mongoose.connection;

  if (connection.readyState === 1) {
    logger.debug('[db] Already connected; reusing the existing pool.');
    // Models may have been registered after the first connect (the harnesses
    // connect before they require any model). init() is memoised, so this is
    // free once the indexes exist.
    await ensureModelIndexes();
    return connection;
  }

  bindConnectionListeners();

  const maxAttempts = config.mongo.retries + 1;
  const options = connectionOptions();

  let connected = false;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      await mongoose.connect(config.mongo.uri, options);
      connectionFailureReported = false;
      connected = true;
      break;
    } catch (error) {
      if (attempt >= maxAttempts) {
        connectionFailureReported = true;

        // The driver's own message is accurate but buries the action. A TLS / server
        // selection failure happens BEFORE authentication, so the credentials are
        // almost never the problem — the source IP is missing from the Atlas
        // access list. Say that once, here, instead of making someone decode
        // "tlsv1 alert internal error" at 2am.
        // Only meaningful for Atlas (*.mongodb.net). A refused local mongod must
        // not be blamed on an access list the user never configured.
        const targetIsAtlas = /mongodb\.net/i.test(config.mongo.uri);
        const looksLikeAccessList =
          targetIsAtlas &&
          /ServerSelection|Server selection|MongoDB Atlas cluster|whitelist|tlsv1 alert|ssl3_read_bytes|ETIMEDOUT|ECONNREFUSED/i.test(
            error.message || ''
          );
        const hint = looksLikeAccessList
          ? ' This failure happens before authentication: add this machine\'s public IP under Atlas → Network Access (Security → Network Access → Add Current IP Address), then restart. Run `npm run diagnose:atlas` to locate the failing layer.'
          : '';

        logger.error(`[db] Could not connect to MongoDB after ${attempt} attempt(s).${hint}`, error);
        throw new Error(`MongoDB connection failed after ${attempt} attempt(s): ${error.message}${hint}`);
      }

      const backoff = Math.min(config.mongo.retryBaseDelayMs * 2 ** (attempt - 1), 30_000);
      const jitter = Math.floor(Math.random() * 250);
      logger.warn(
        `[db] Connection attempt ${attempt}/${maxAttempts} failed (${error.message}). Retrying in ${backoff + jitter}ms...`
      );
      await sleep(backoff + jitter);
    }
  }

  if (!connected) throw new Error('MongoDB connection failed for an unknown reason.');

  // Deliberately outside the retry loop: a failure here is a data/schema
  // problem, not an unreachable server, and reconnecting cannot fix it.
  await ensureModelIndexes();

  return connection;
}

/**
 * Wait until every model that is already registered has its indexes built.
 *
 * Mongoose resolves `connect()` before `createIndex()` calls finish, so a
 * client that starts writing immediately can insert data that the not-yet-built
 * unique index would have rejected — and once that happens the index build
 * fails forever until someone cleans the collection by hand.
 *
 * A failure here is fatal on purpose: an API whose "cannot be duplicated" and
 * "only one primary" rules are not enforced is not safe to serve.
 *
 * In production `autoIndex` is deliberately off, so `init()` completes without
 * creating anything: the indexes must be created by the deployment step (Phase
 * 10). The flag then means "the driver finished its startup work", not "every
 * index is verified present".
 *
 * @returns {Promise<void>}
 */
async function ensureModelIndexes() {
  const models = Object.values(mongoose.models);

  if (models.length === 0) {
    // A caller connected before requiring any model (the harnesses do this).
    // Nothing to build yet; a later model.init() will create its own indexes.
    indexesReady = true;
    return;
  }

  const results = await Promise.allSettled(models.map((model) => model.init()));
  const failure = results.find((result) => result.status === 'rejected');

  if (failure) {
    indexesReady = false;
    throw new Error(
      `MongoDB index creation failed: ${failure.reason?.message || failure.reason}. ` +
        'Fix the data that violates the index (usually duplicates) and restart; serving without the index would break the invariant it protects.'
    );
  }

  indexesReady = true;
  logger.debug(`[db] Indexes ready for ${models.length} model(s).`);
}

/**
 * True only when the connection is live AND the unique/TTL indexes are in
 * place. Routes that write should fail closed while this is false.
 */
function isDatabaseReady() {
  return mongoose.connection.readyState === 1 && indexesReady;
}

/**
 * Close the connection. `force` skips waiting for in-flight operations, which
 * is what a shutdown path wants.
 */
async function disconnectDatabase({ force = false } = {}) {
  const connection = mongoose.connection;
  indexesReady = false;

  if (connection.readyState === 0) {
    logger.debug('[db] Already disconnected; nothing to close.');
    return;
  }

  await connection.close(force);
  logger.info('[db] MongoDB connection closed.');
}

/**
 * Snapshot of the driver state for the health endpoint (never throws).
 *
 * `poolSize` reports the pool BOUND from configuration, not a driver internal:
 * Mongoose does not expose the live pool size, so the earlier
 * `typeof connection.poolSize === 'number'` probe was always null — a field in
 * the health contract that could never carry a value.
 */
function getDatabaseStatus() {
  const connection = mongoose.connection;
  const readyState = connection.readyState;
  const livePoolSize = typeof connection.poolSize === 'number' ? connection.poolSize : null;

  return {
    state: READY_STATE_LABELS[readyState] || 'unknown',
    readyState,
    connected: readyState === 1,
    database: connection.name || null,
    host: connection.host || null,
    poolSize: livePoolSize === null ? config.mongo.maxPoolSize : livePoolSize,
    poolSizeIsConfiguredMax: livePoolSize === null,
    // Lets a probe (and the verification harness) distinguish "connected" from
    // "safe to accept writes".
    indexesReady: indexesReady && readyState === 1,
  };
}

/** Round-trip ping so /health proves the database is actually answering. */
async function pingDatabase() {
  const connection = mongoose.connection;

  if (connection.readyState !== 1 || !connection.db) {
    return { ok: false, latencyMs: null };
  }

  const startedAt = process.hrtime.bigint();

  try {
    await connection.db.admin().command({ ping: 1 });
  } catch (error) {
    logger.warn(`[db] Ping failed: ${error.message}`);
    return { ok: false, latencyMs: null };
  }

  const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
  return { ok: true, latencyMs: Number(elapsedMs.toFixed(1)) };
}

module.exports = {
  connectDatabase,
  disconnectDatabase,
  getDatabaseStatus,
  pingDatabase,
  connectionOptions,
  ensureModelIndexes,
  isDatabaseReady,
};
