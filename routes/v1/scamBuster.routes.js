'use strict';

/**
 * GuardFi — Scam Buster routes (Phase 7)
 *
 *   POST /api/v1/scam-buster/analyze   (protected, AI quota limiter)
 *   GET  /api/v1/scam-buster/history   (protected, read-only)
 *
 * Every scan spends AI quota and (for screenshots) storage, so /analyze sits
 * behind its own small budget — `scamBusterLimiter` — rather than only the
 * global one. The order is deliberate:
 *
 *   limiter → upload → validator → controller
 *
 * The limiter runs first so a flood is rejected before a single byte is parsed
 * into memory; Multer runs before validation because a multipart body only
 * becomes `req.body`/`req.file` once it has been parsed; the validator then sees
 * a clean `text` field, and the controller is the last place that can still say
 * "you sent nothing at all".
 *
 * /history is deliberately NOT behind the AI limiter: reading your own audit
 * trail is cheap, indexed, and exactly what a worried user does repeatedly
 * after a scam attempt — throttling that would punish the wrong person.
 */

const express = require('express');
const authMiddleware = require('../../middlewares/authMiddleware');
const { validateRequest } = require('../../middlewares/validateRequest');
const { scamBusterLimiter } = require('../../middlewares/rateLimiter');
const { singleImageUpload } = require('../../middlewares/uploadMiddleware');
const { analyzeRequestSchema, historyQuerySchema } = require('../../validators/scamBuster.validator');
const scamBusterController = require('../../controllers/scamBusterController');

const router = express.Router();

router.use(authMiddleware);

router.post(
  '/analyze',
  scamBusterLimiter,
  singleImageUpload,
  validateRequest({ body: analyzeRequestSchema }),
  scamBusterController.analyze
);

router.get('/history', validateRequest({ query: historyQuerySchema }), scamBusterController.history);

module.exports = router;
