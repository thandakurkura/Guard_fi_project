'use strict';

/**
 * GuardFi — analytics routes (Phase 5)
 *
 *   GET /api/v1/analytics/dashboard
 *
 * Protected: the caller's own readiness profile is part of the response, and
 * the per-user facet is matched on `req.user._id`, never on client input.
 */

const express = require('express');
const authMiddleware = require('../../middlewares/authMiddleware');
const { validateRequest } = require('../../middlewares/validateRequest');
const { dashboardQuerySchema } = require('../../validators/analytics.validator');
const analyticsController = require('../../controllers/analyticsController');

const router = express.Router();

router.use(authMiddleware);

router.get('/dashboard', validateRequest({ query: dashboardQuerySchema }), analyticsController.dashboard);

module.exports = router;
