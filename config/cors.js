'use strict';

/**
 * GuardFi — CORS policy (Phase 1)
 *
 * One shared origin decision, used by both Express (`cors`) and Socket.io so a
 * browser cannot be allowed by one transport and blocked by the other.
 *
 * A missing Origin header is allowed on purpose: the Flutter/Dart HTTP client,
 * curl and server-to-server calls do not send one, and CORS is a browser-only
 * mechanism — it is not an authentication control.
 */

const { config } = require('./env');
const ApiError = require('../utils/ApiError');

function isOriginAllowed(origin) {
  if (config.http.allowAllOrigins) return true;
  return config.http.corsOrigins.includes(origin);
}

/**
 * `origin` callback in the shape expected by both `cors` and Socket.io.
 * @param {string | undefined} origin
 * @param {(error: Error | null, allowed?: boolean) => void} callback
 */
function corsOriginHandler(origin, callback) {
  if (!origin) return callback(null, true);
  if (isOriginAllowed(origin)) return callback(null, true);

  return callback(new ApiError(403, `Origin "${origin}" is not allowed by the CORS policy.`));
}

/**
 * Credentialed cross-origin requests are only enabled alongside an explicit
 * origin allow-list.
 *
 * Why this matters: GuardFi authenticates with a Bearer token in the
 * Authorization header, so browsers never need to attach credentials (cookies,
 * client certs). But `credentials: true` together with `CORS_ORIGINS=*` would
 * make Access-Control-Allow-Credentials echo for ANY origin, which is how a
 * random website starts reading responses from a signed-in user's browser. The
 * wildcard dev default therefore turns it off, and a real allow-list turns it
 * back on.
 */
function allowCredentials() {
  return !config.http.allowAllOrigins;
}

function expressCorsOptions() {
  return {
    origin: corsOriginHandler,
    credentials: allowCredentials(),
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86_400,
    optionsSuccessStatus: 204,
  };
}

function socketCorsOptions() {
  return {
    origin: corsOriginHandler,
    credentials: allowCredentials(),
    methods: ['GET', 'POST'],
  };
}

module.exports = {
  isOriginAllowed,
  allowCredentials,
  corsOriginHandler,
  expressCorsOptions,
  socketCorsOptions,
};
