'use strict';

/**
 * GuardFi — Shield Pay routes (Phase 6)
 *
 *   POST /api/v1/shield-pay/check-upi            (protected)
 *   POST /api/v1/shield-pay/proceed-transaction  (protected, PIN limiter)
 *   POST /api/v1/shield-pay/set-pin              (protected, PIN limiter)
 *
 * Every route is authenticated: the blocklist is a private safety layer, and
 * /proceed-transaction spends the caller's own PIN attempts. The two routes that
 * touch the PIN sit behind `pinLimiter` — `globalLimiter` alone (300 requests /
 * 15 min) would let an attacker with a stolen session try thousands of 4-digit
 * PINs, which is why credential routes get their own, much smaller budget.
 *
 * Order is limiter → validator → controller, so a flood or a malformed body is
 * rejected before any bcrypt comparison or database write happens.
 */

const express = require('express');
const authMiddleware = require('../../middlewares/authMiddleware');
const { validateRequest } = require('../../middlewares/validateRequest');
const { pinLimiter } = require('../../middlewares/rateLimiter');
const {
  checkUpiSchema,
  proceedTransactionSchema,
  setPinSchema,
} = require('../../validators/shieldPay.validator');
const shieldPayController = require('../../controllers/shieldPayController');

const router = express.Router();

router.use(authMiddleware);

router.post('/check-upi', validateRequest({ body: checkUpiSchema }), shieldPayController.checkUpi);
router.post(
  '/proceed-transaction',
  pinLimiter,
  validateRequest({ body: proceedTransactionSchema }),
  shieldPayController.proceed
);
router.post('/set-pin', pinLimiter, validateRequest({ body: setPinSchema }), shieldPayController.configurePin);

module.exports = router;
