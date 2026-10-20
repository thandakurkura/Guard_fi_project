'use strict';

/**
 * GuardFi — Shield Pay controller (Phase 6)
 *
 * Thin by design: the zod middleware already parsed and bounded every field,
 * and services/shieldPayService.js owns the risk rules and the state machine.
 * These handlers only pass the caller's identity through (never a client-supplied
 * userId) and wrap service output in the standard response envelope.
 *
 *   POST /api/v1/shield-pay/check-upi            → bilingual risk verdict
 *   POST /api/v1/shield-pay/proceed-transaction  → settle, honouring the warning gate
 *   POST /api/v1/shield-pay/set-pin              → create/change the Shield Pay PIN
 */

const asyncHandler = require('../utils/asyncHandler');
const { sendSuccess } = require('../utils/apiResponse');
const { checkIdentifier, proceedTransaction, setPin } = require('../services/shieldPayService');

/**
 * POST /api/v1/shield-pay/check-upi
 * Body: { identifier } (alias: upiId)
 */
const checkUpi = asyncHandler(async (req, res) => {
  const { identifier } = req.body;

  const verdict = await checkIdentifier({
    userId: req.user._id,
    rawIdentifier: identifier,
    callerIp: req.ip,
  });

  return sendSuccess(res, {
    statusCode: 200,
    message: `Payee rated ${verdict.status.toUpperCase()} (risk score ${verdict.riskScore}/100).`,
    data: verdict,
  });
});

/**
 * POST /api/v1/shield-pay/proceed-transaction
 * Body: { identifier, amount, pin, riskAccepted?, checkId? }
 */
const proceed = asyncHandler(async (req, res) => {
  const { identifier, amount, pin, riskAccepted, checkId } = req.body;

  const receipt = await proceedTransaction({
    userId: req.user._id,
    rawIdentifier: identifier,
    amount,
    pin,
    riskAccepted,
    checkId,
    callerIp: req.ip,
  });

  return sendSuccess(res, {
    statusCode: 201,
    message: receipt.risk_accepted
      ? 'Transaction recorded after the fraud warning was accepted.'
      : 'Transaction recorded.',
    data: receipt,
  });
});

/**
 * POST /api/v1/shield-pay/set-pin
 * Body: { pin, currentPin? }
 */
const configurePin = asyncHandler(async (req, res) => {
  const { pin, currentPin } = req.body;

  const result = await setPin({ userId: req.user._id, pin, currentPin });

  return sendSuccess(res, {
    statusCode: 200,
    message: 'Shield Pay PIN saved.',
    data: result,
  });
});

module.exports = { checkUpi, proceed, configurePin };
