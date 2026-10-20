'use strict';

/**
 * GuardFi — route aggregator (Phase 1)
 *
 * Everything mounted here is reachable from app.js with a single app.use('/').
 */

const express = require('express');
const healthRoutes = require('./health.routes');
const v1Routes = require('./v1');

const router = express.Router();

// Infrastructure endpoints (unversioned, so probes never move).
router.use('/health', healthRoutes);

// Versioned product API.
router.use('/api/v1', v1Routes);

module.exports = router;
