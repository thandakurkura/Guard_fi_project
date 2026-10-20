'use strict';

/**
 * GuardFi — global configuration routes (Phase 9)
 *
 *   GET /global  PUBLIC — no authMiddleware. The app needs policy links,
 *                the maintenance flag and helpline numbers before sign-in.
 *                node-cache serves it; only a miss touches MongoDB.
 *   PUT /global  authMiddleware + requireRoles('admin'). A global setting is
 *                not user data: one signed-in account must not be able to flip
 *                maintenanceMode for everybody or point the privacy policy at
 *                an attacker's URL.
 *
 * The PUT is deliberately NOT behind rate limiting beyond the global limiter:
 * it is an admin action, audited on every call.
 */

const express = require('express');
const authMiddleware = require('../../middlewares/authMiddleware');
const { requireRoles } = require('../../middlewares/rbacMiddleware');
const { validateRequest } = require('../../middlewares/validateRequest');
const { configUpdateSchema } = require('../../validators/config.validator');
const configController = require('../../controllers/configController');

const router = express.Router();

router.get('/global', configController.getGlobal);

router.put(
  '/global',
  authMiddleware,
  requireRoles('admin'),
  validateRequest({ body: configUpdateSchema }),
  configController.updateGlobal
);

module.exports = router;
