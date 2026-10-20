'use strict';

/**
 * GuardFi — global configuration cache (Phase 9)
 *
 * GET /api/v1/config/global is public and hit on every app launch, so it must
 * not become a database read per launch. One node-cache entry (`GLOBAL_CONFIG`,
 * TTL 600 s) holds the whole document:
 *
 *   cache hit  → return it, no database round trip at all;
 *   cache miss → read (auto-seeding the singleton when it does not exist yet),
 *                store a plain-object clone, return source: 'database'.
 *
 * `useClones: false` is deliberate. The cached value is already a plain object
 * produced by toObject(), it is never handed to a caller that could mutate it
 * (the controller serialises it into the response), and cloning a config on
 * every cache hit would defeat the point of caching a document that never
 * changes between writes.
 *
 * Invalidation is not best-effort: the admin PUT deletes the key BEFORE it
 * returns, so the next public read can never serve a value the admin just
 * changed. A TTL is a safety net for forgotten writes, never the mechanism.
 */

const NodeCache = require('node-cache');
const { config } = require('../config/env');
const { isDatabaseReady } = require('../config/db');
const ApiError = require('../utils/ApiError');
const AppConfig = require('../models/AppConfig');
const AuditLog = require('../models/AuditLog');
const { AUDIT_ACTIONS } = AuditLog;

const GLOBAL_CONFIG_CACHE_KEY = 'GLOBAL_CONFIG';

const cache = new NodeCache({
  stdTTL: config.appConfig.cacheTtlSeconds,
  checkperiod: Math.min(120, config.appConfig.cacheTtlSeconds),
  useClones: false,
});

/** @returns {{ keys: number, hits: number, misses: number, ksize: number, vsize: number }} */
function getCacheStats() {
  return cache.getStats();
}

/** Remaining TTL for the config entry, in seconds. 0 when it is not cached. */
function getCacheTtlRemainingSeconds() {
  const expiresAt = cache.getTtl(GLOBAL_CONFIG_CACHE_KEY);
  if (!expiresAt) return 0;
  return Math.max(0, Math.round((expiresAt - Date.now()) / 1000));
}

/**
 * Drop the cached config. Called by the admin PUT immediately after MongoDB
 * accepts the write.
 * @returns {number} number of keys removed (0 or 1)
 */
function invalidateGlobalConfigCache() {
  return cache.del(GLOBAL_CONFIG_CACHE_KEY);
}

/** Seed the cache without going through a request (used by the harnesses). */
function primeGlobalConfigCache(document) {
  const plain = document && typeof document.toObject === 'function' ? document.toObject() : document;
  cache.set(GLOBAL_CONFIG_CACHE_KEY, plain, config.appConfig.cacheTtlSeconds);
  return plain;
}

/**
 * @returns {Promise<{ source: 'cache'|'database', config: object }>}
 */
async function getGlobalConfig() {
  const cached = cache.get(GLOBAL_CONFIG_CACHE_KEY);

  if (cached) {
    return { source: 'cache', config: cached };
  }

  // A cache miss is the only path that touches MongoDB, and it must fail closed:
  // answering with hard-coded defaults while the database is unreachable would
  // silently hide an admin's maintenanceMode or threshold change.
  if (!isDatabaseReady()) {
    throw new ApiError(503, 'Global configuration is temporarily unavailable because the database is not ready.', {
      errors: [
        {
          field: 'config',
          code: 'CONFIG_STORE_UNAVAILABLE',
          message: 'The configuration store is not ready; retry shortly.',
        },
      ],
    });
  }

  const document = await AppConfig.getOrSeed();
  const plain = primeGlobalConfigCache(document);

  return { source: 'database', config: plain };
}

/**
 * Apply an admin update, invalidate the cache and write the audit row.
 *
 * Order matters: MongoDB first (so a rejected write never clears the cache),
 * then invalidation, then the audit row. A failed audit write surfaces as a
 * 500 — the configuration has changed and the caller must not believe the
 * operation was a no-op.
 *
 * @param {{
 *   updates: object,
 *   adminId: unknown,
 *   request?: { ipAddress?: string|null, userAgent?: string|null },
 * }} input
 */
async function updateGlobalConfig({ updates, adminId, request = {} }) {
  const changedFields = Object.keys(updates);
  const before = await AppConfig.getOrSeed();

  const document = await AppConfig.applyUpdate({ updates, adminId });

  // Never serve the previous value again.
  invalidateGlobalConfigCache();

  const audit = await AuditLog.record({
    userId: adminId,
    action: AUDIT_ACTIONS.CONFIG_UPDATED,
    ipAddress: request.ipAddress || null,
    userAgent: request.userAgent ? String(request.userAgent).slice(0, 512) : null,
    details: {
      requestedAction: 'UPDATE_GLOBAL_CONFIG',
      reason: 'ADMIN_PUT',
      note: changedFields.join(', ').slice(0, 280),
    },
  });

  return {
    config: document.toObject(),
    changedFields,
    previousVersion: before.version,
    version: document.version,
    cacheInvalidated: true,
    audit: {
      id: String(audit._id),
      action: audit.action,
      createdAt: audit.createdAt,
    },
  };
}

module.exports = {
  GLOBAL_CONFIG_CACHE_KEY,
  getCacheStats,
  getCacheTtlRemainingSeconds,
  invalidateGlobalConfigCache,
  primeGlobalConfigCache,
  getGlobalConfig,
  updateGlobalConfig,
};
