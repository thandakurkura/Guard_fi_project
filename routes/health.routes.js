'use strict';

/**
 * GuardFi — health endpoint (Phase 1)
 *
 * Public and unauthenticated on purpose: Render/Railway health checks and the
 * Flutter client both need to know whether the API and its database are up.
 *
 * 200 → API up and the database answered a ping.
 * 503 → API up but the database is unreachable (so a load balancer pulls it).
 */

const express = require('express');
const asyncHandler = require('../utils/asyncHandler');
const { config } = require('../config/env');
const { getDatabaseStatus, pingDatabase } = require('../config/db');
const { resolveProvider } = require('../services/smsService');
const packageJson = require('../package.json');

const router = express.Router();

/**
 * OTP readiness, so "why did nobody get a code?" is answerable from one URL.
 * Reports no secrets: only whether a transport is configured and which mode is
 * active (dev mode returns codes in the response — see config/env.js for the
 * production guard that stops that from ever happening by accident).
 */
function otpReadiness() {
  const smsProvider = resolveProvider(config.sms);

  return {
    devMode: config.otp.devMode,
    smsProvider,
    smsDeliveryConfigured: smsProvider !== 'none',
    codeLength: config.otp.length,
    ttlSeconds: config.otp.ttlSeconds,
    maxAttempts: config.otp.maxAttempts,
    resendCooldownSeconds: config.otp.resendCooldownSeconds,
    // Both throttles are reported so "a real user is blocked" can be answered
    // without guessing: the cooldown is per code, the budget is per number.
    maxSendsPerWindow: config.otp.maxSendsPerWindow,
    sendWindowSeconds: config.otp.sendWindowSeconds,
  };
}

router.get(
  '/',
  asyncHandler(async (req, res) => {
    const database = getDatabaseStatus();
    const ping = await pingDatabase();
    const healthy = database.connected && ping.ok;

    // Health checks only need "up or not". The cluster hostname, database name
    // and pool size are free reconnaissance for anyone scanning public hosts, so
    // they are reported in development and omitted in production.
    const databasePayload = config.isProduction
      ? {
          state: database.state,
          readyState: database.readyState,
          connected: database.connected,
          // Not infrastructure detail: tells a probe whether unique indexes are
          // built yet (see config/db.js). Exposed in production too because
          // "connected but not safe to write" must be observable.
          indexesReady: database.indexesReady,
          ping,
        }
      : { ...database, ping };

    const payload = {
      status: healthy ? 'ok' : 'degraded',
      service: 'guardfi-backend',
      version: packageJson.version,
      environment: config.env,
      uptimeSeconds: Math.round(process.uptime()),
      timestamp: new Date().toISOString(),
      database: databasePayload,
      otp: otpReadiness(),
    };

    res.set('Cache-Control', 'no-store');

    return res.status(healthy ? 200 : 503).json({
      success: healthy,
      message: healthy
        ? 'GuardFi API is healthy.'
        : 'GuardFi API is running, but the database is unavailable.',
      data: payload,
      errors: healthy ? null : [{ field: 'database', message: 'no successful ping to MongoDB' }],
    });
  })
);

module.exports = router;
