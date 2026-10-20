'use strict';

/**
 * GuardFi — Express application (Phase 1)
 *
 * Builds the middleware chain only. Listening, Socket.io and shutdown live in
 * server.js so the app can also be imported by tests without opening a port.
 *
 * Order matters and is intentional:
 *   security headers → CORS → rate limit → body parsers → routes → 404 → errors
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const { config } = require('./config/env');
const { expressCorsOptions } = require('./config/cors');
const routes = require('./routes');
const { globalLimiter } = require('./middlewares/rateLimiter');
const { notFoundHandler, errorMiddleware } = require('./middlewares/errorMiddleware');

const app = express();

// Do not advertise the framework.
app.disable('x-powered-by');
// ETags add nothing for a JSON API and can leak resource identity.
app.disable('etag');
// Behind Render/Railway this makes req.ip the real client, which matters for
// rate limiting, audit logs and emergency metadata.
app.set('trust proxy', config.trustProxy);
// Pretty JSON locally makes Flutter integration readable; compact in production.
app.set('json spaces', config.isProduction ? 0 : 2);

app.use(
  helmet({
    // This service returns JSON, so a document CSP is not applicable.
    contentSecurityPolicy: false,
    // Cloudinary-hosted screenshots (Phase 7) must be loadable cross-origin.
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
);

app.use(cors(expressCorsOptions()));

// The rate limiter runs BEFORE the body parsers on purpose. When it sat after
// them, an unauthenticated client could make the server allocate and parse a 1 MB
// JSON document on every request without ever touching a limit — a free
// denial-of-service amplifier. Rejecting cheaply first is the whole point.
app.use(globalLimiter);

// Bounded body parsing: an oversized payload is rejected before any handler runs.
app.use(express.json({ limit: config.http.jsonBodyLimit, strict: true }));
app.use(express.urlencoded({ extended: true, limit: config.http.jsonBodyLimit }));

app.use('/', routes);

// Terminal handlers — must be registered last, in this order.
app.use(notFoundHandler);
app.use(errorMiddleware);

module.exports = app;
