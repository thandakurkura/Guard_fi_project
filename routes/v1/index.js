'use strict';

/**
 * GuardFi — API v1 router (Phase 1)
 *
 * This file is the single mount point for every versioned module. Later phases
 * only add lines here; no existing route path has to change.
 */

const express = require('express');
const { sendSuccess } = require('../../utils/apiResponse');

const router = express.Router();

// Phase 2
router.use('/auth', require('./auth.routes'));

// Phase 3
router.use('/nominees', require('./nominee.routes'));

// Phase 4
router.use('/sos', require('./sos.routes'));

// Phase 5
router.use('/analytics', require('./analytics.routes'));

// Phase 6
router.use('/shield-pay', require('./shieldPay.routes'));

// Phase 7
router.use('/scam-buster', require('./scamBuster.routes'));

// Phase 8
router.use('/emergency', require('./emergency.routes'));

// Phase 9
router.use('/config', require('./config.routes'));

// Phase 10 mounts live here:
//   the deployment checklist needs no new routes.

const mountedModules = ['auth', 'nominees', 'sos', 'analytics', 'shield-pay', 'scam-buster', 'emergency', 'config'];

router.get('/', (req, res) =>
  sendSuccess(res, {
    message: 'GuardFi API v1 foundation is online.',
    data: {
      version: 'v1',
      mountedModules,
    },
  })
);

module.exports = router;
