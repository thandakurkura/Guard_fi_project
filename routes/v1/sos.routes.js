'use strict';

/**
 * GuardFi — SOS routes (Phase 4)
 *
 * All three endpoints are protected: an alert belongs to the signed-in user, and
 * every service call is scoped by `req.user._id`.
 *
 *   POST /trigger  validate body → create or return the active alert
 *   POST /resolve  close the caller's active alert (RESOLVED | FALSE_ALARM)
 *   GET  /active   recovery endpoint for app resume / crash restart
 *
 * The global limiter applies. Triggering again while an alert is active is
 * idempotent and sends no second round of notifications, so a panicking user
 * cannot spam guardians or the SMS bill.
 */

const express = require('express');
const authMiddleware = require('../../middlewares/authMiddleware');
const { validateRequest } = require('../../middlewares/validateRequest');
const { triggerSosSchema, resolveSosSchema } = require('../../validators/sos.validator');
const sosController = require('../../controllers/sosController');

const router = express.Router();

router.use(authMiddleware);

router.post('/trigger', validateRequest({ body: triggerSosSchema }), sosController.trigger);
router.post('/resolve', validateRequest({ body: resolveSosSchema }), sosController.resolve);
router.get('/active', sosController.active);

module.exports = router;
