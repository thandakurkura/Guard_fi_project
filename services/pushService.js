'use strict';

/**
 * GuardFi — Firebase Cloud Messaging transport (Phase 4)
 *
 * Delivery is a VALUE, not an exception: `{ delivered, attempted, sent, failed,
 * skipped, reason }`. An SOS must still be recorded, streamed and texted when
 * FCM is down, so a push failure can never abort the alert.
 *
 * `firebase-admin` is required lazily and its app is initialised once. That
 * matters for three reasons:
 *   • a missing/broken dependency becomes `firebase_error`, not a crash at boot;
 *   • a malformed service-account key is discovered on the first send instead of
 *     preventing the API from starting;
 *   • the Phase 4 harness can inject a fake admin object and prove the message
 *     shape without any credentials.
 *
 * Tokens are never logged. Invalid/expired tokens are RETURNED so the caller can
 * clear them from the nominee/user document in a later phase.
 */

const { config } = require('../config/env');
const logger = require('../utils/logger');

/** @type {any | null} */
let cachedAdmin = null;

function isFcmConfigured() {
  return config.fcm.configured === true;
}

/**
 * @param {{ projectId: string, clientEmail: string, privateKey: string }} fcm
 * @returns {any} firebase-admin module
 */
function defaultAdminFactory(fcm) {
  if (cachedAdmin) return cachedAdmin;

  // eslint-disable-next-line global-require
  const admin = require('firebase-admin');

  if (!Array.isArray(admin.apps) || admin.apps.length === 0) {
    admin.initializeApp({
      credential: admin.credential.cert({
        projectId: fcm.projectId,
        clientEmail: fcm.clientEmail,
        privateKey: fcm.privateKey,
      }),
    });
  }

  cachedAdmin = admin;
  return admin;
}

/**
 * Build the FCM message. Exported because the harness asserts the data payload
 * is all-strings (FCM rejects numbers with a runtime error) and that the alert
 * identifiers survive the trip.
 *
 * @param {{ title: string, body: string, data?: Record<string, unknown> }} params
 */
function buildAlertPushMessage({ title, body, data = {} }) {
  const stringData = {};

  for (const [key, value] of Object.entries(data)) {
    if (value === undefined || value === null) continue;
    stringData[key] = String(value);
  }

  return {
    notification: { title, body },
    data: stringData,
    android: {
      priority: 'high',
      ttl: 3_600_000,
      notification: {
        channelId: 'guardfi_sos',
        sound: 'default',
        priority: 'max',
        visibility: 'public',
      },
    },
    apns: {
      headers: { 'apns-priority': '10' },
      payload: { aps: { sound: 'default', 'interruption-level': 'time-sensitive' } },
    },
  };
}

/**
 * Send one alert to many device tokens.
 *
 * @param {{
 *   tokens: string[],
 *   title: string,
 *   body: string,
 *   data?: Record<string, unknown>,
 *   adminFactory?: (fcm: object) => any
 * }} params
 * @returns {Promise<{ delivered: boolean, attempted: number, sent: number, failed: number, skipped: number, reason: string, invalidTokens: string[], detail?: string }>}
 */
async function sendAlertPush({ tokens, title, body, data = {}, adminFactory = defaultAdminFactory }) {
  const uniqueTokens = [...new Set((Array.isArray(tokens) ? tokens : []).filter((token) => typeof token === 'string' && token.trim() !== ''))];

  if (uniqueTokens.length === 0) {
    return { delivered: false, attempted: 0, sent: 0, failed: 0, skipped: 0, reason: 'no_tokens', invalidTokens: [] };
  }

  if (!isFcmConfigured()) {
    logger.warn(
      `[push] FCM is not configured; ${uniqueTokens.length} SOS push(es) skipped. The SMS fallback is the delivery path.`
    );
    return {
      delivered: false,
      attempted: uniqueTokens.length,
      sent: 0,
      failed: 0,
      skipped: uniqueTokens.length,
      reason: 'not_configured',
      invalidTokens: [],
    };
  }

  try {
    const admin = adminFactory(config.fcm);
    const messaging = admin.messaging();

    const message = { ...buildAlertPushMessage({ title, body, data }), tokens: uniqueTokens };
    const result = await messaging.sendEachForMulticast(message);

    const invalidTokens = [];

    (result.responses || []).forEach((response, index) => {
      if (response?.success) return;
      const code = response?.error?.code || '';
      if (code === 'messaging/invalid-registration-token' || code === 'messaging/registration-token-not-registered') {
        invalidTokens.push(uniqueTokens[index]);
      }
    });

    const sent = Number(result.successCount) || 0;
    const failed = Number(result.failureCount) || 0;

    if (sent > 0) logger.info(`[push] SOS delivered to ${sent}/${uniqueTokens.length} device(s).`);
    if (failed > 0) logger.warn(`[push] ${failed} SOS push(es) failed${invalidTokens.length ? ` (${invalidTokens.length} dead token(s))` : ''}.`);

    return {
      delivered: sent > 0,
      attempted: uniqueTokens.length,
      sent,
      failed,
      skipped: 0,
      reason: failed === 0 ? 'sent' : sent > 0 ? 'partial_failure' : 'all_failed',
      invalidTokens,
    };
  } catch (error) {
    // A malformed key, a disabled API, or a network outage. Never the SOS's problem.
    logger.warn(`[push] FCM send failed: ${String(error?.message || error).slice(0, 200)}`);

    return {
      delivered: false,
      attempted: uniqueTokens.length,
      sent: 0,
      failed: uniqueTokens.length,
      skipped: 0,
      reason: 'firebase_error',
      detail: String(error?.message || error).slice(0, 200),
      invalidTokens: [],
    };
  }
}

/** Test hook: forget the initialised app (used by the harness). */
function resetFcmForTests() {
  cachedAdmin = null;
}

module.exports = {
  isFcmConfigured,
  sendAlertPush,
  buildAlertPushMessage,
  defaultAdminFactory,
  resetFcmForTests,
};
