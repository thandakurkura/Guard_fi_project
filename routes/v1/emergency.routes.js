'use strict';

/**
 * GuardFi — emergency routes (Phase 8)
 *
 *   POST /biometric-verify   verify the app's signed local biometric result,
 *                            unlock emergency mode, write an immutable audit row
 *   POST /restricted-action  authMiddleware + requireEmergencyMode: server-side
 *                            state enforcement, not client-side trust
 *   POST /lock               leave emergency mode (audited), closing the gate
 *   GET  /status             recovery endpoint after an app restart
 *
 * Every route is authenticated. `requireEmergencyMode` reads the *database*
 * value through authMiddleware, so a token signed before the unlock cannot be
 * used to claim it — and a token signed while unlocked cannot be used after the
 * lock. That is the whole point of the phase.
 */

const express = require('express');
const authMiddleware = require('../../middlewares/authMiddleware');
const { validateRequest } = require('../../middlewares/validateRequest');
const { requireEmergencyMode } = require('../../middlewares/rbacMiddleware');
const { emergencyLimiter } = require('../../middlewares/rateLimiter');
const { biometricVerifySchema, restrictedActionSchema } = require('../../validators/emergency.validator');
const emergencyController = require('../../controllers/emergencyController');

const router = express.Router();

router.use(authMiddleware);

// Biometric attempts write an audit row each time, so they get their own small
// budget instead of being able to flood the immutable collection.
router.post(
  '/biometric-verify',
  emergencyLimiter,
  validateRequest({ body: biometricVerifySchema }),
  emergencyController.verifyBiometric
);

router.post(
  '/restricted-action',
  requireEmergencyMode,
  validateRequest({ body: restrictedActionSchema }),
  emergencyController.restrictedAction
);

router.post('/lock', emergencyController.lock);
router.get('/status', emergencyController.status);

module.exports = router;
