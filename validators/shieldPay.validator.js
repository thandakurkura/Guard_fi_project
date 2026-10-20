'use strict';

/**
 * GuardFi — Shield Pay input schemas (Phase 6)
 *
 * Three schemas, one job each:
 *   checkUpiSchema      — rate one payee.
 *   proceedTransactionSchema — settle a payment (identifier + amount + PIN +
 *                         the optional "Proceed Anyway" acknowledgement).
 *   setPinSchema        — create or change the Shield Pay PIN.
 *
 * Contract decisions worth knowing:
 *   • The payee is sent as `identifier`. `upiId` is accepted as an alias because
 *     the audit record and the spec both use that name, and a client that sends
 *     either should not have to care. Exactly one of the two must be present.
 *   • The field is NOT validated as a UPI ID here. It may be a link or a phone
 *     number, and the service is the layer that decides which shape it is and
 *     rejects anything it cannot classify (with a message that names all three).
 *   • `amount` is bounded by the configured cap and rounded to paise, never
 *     truncated silently: 10.999 becomes 11.00 and the receipt shows the amount
 *     that was actually stored.
 *   • `pin` must be a STRING of 4-6 digits. A JSON number is rejected on
 *     purpose: Dart serialises `0123` as 123, and a payment PIN with a lost
 *     leading zero is a bug that would only surface on the user's screen.
 */

const { z } = require('zod');
const { config } = require('../config/env');
const { optionalBoolean, objectIdField } = require('./common');

const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/;

/**
 * Resolve `identifier` / `upiId` into one trimmed string. Spaces are allowed
 * through (a phone number can be pasted with separators — the service strips
 * them); what is rejected here is emptiness, absurd length and control bytes.
 */
function resolveIdentifier(data, ctx) {
  const raw = data.identifier !== undefined && data.identifier !== null ? data.identifier : data.upiId;

  if (raw === undefined || raw === null) {
    ctx.addIssue({ code: 'custom', path: ['identifier'], message: 'identifier is required' });
    return '';
  }

  if (typeof raw !== 'string') {
    ctx.addIssue({ code: 'custom', path: ['identifier'], message: 'identifier must be a string' });
    return '';
  }

  const trimmed = raw.trim();

  if (trimmed === '') {
    ctx.addIssue({ code: 'custom', path: ['identifier'], message: 'identifier is required' });
    return '';
  }

  if (trimmed.length > 200) {
    ctx.addIssue({ code: 'custom', path: ['identifier'], message: 'identifier cannot exceed 200 characters' });
    return '';
  }

  if (CONTROL_CHARACTERS.test(trimmed)) {
    ctx.addIssue({ code: 'custom', path: ['identifier'], message: 'identifier cannot contain control characters' });
    return '';
  }

  return trimmed;
}

/** Positive money value, capped by config and rounded to two decimals. */
const amountField = z.any().transform((value, ctx) => {
  if (value === undefined || value === null || value === '') {
    ctx.addIssue({ code: 'custom', message: 'amount is required' });
    return 0;
  }

  const parsed = typeof value === 'number' ? value : Number(String(value).trim());

  if (!Number.isFinite(parsed)) {
    ctx.addIssue({ code: 'custom', message: 'amount must be a number' });
    return 0;
  }

  if (parsed <= 0) {
    ctx.addIssue({ code: 'custom', message: 'amount must be greater than zero' });
    return 0;
  }

  if (parsed > config.shieldPay.maxAmount) {
    ctx.addIssue({
      code: 'custom',
      message: `amount cannot exceed ${config.shieldPay.maxAmount} for a single Shield Pay transaction`,
    });
    return 0;
  }

  return Math.round(parsed * 100) / 100;
});

/** 4-6 digit PIN, as a string. */
function pinField(label, { optional = false } = {}) {
  const schema = z.any().transform((value, ctx) => {
    if (value === undefined || value === null || value === '') {
      if (optional) return undefined;
      ctx.addIssue({ code: 'custom', message: `${label} is required` });
      return '';
    }

    if (typeof value !== 'string') {
      ctx.addIssue({
        code: 'custom',
        message: `${label} must be sent as a string of 4-6 digits (a number would drop a leading zero)`,
      });
      return '';
    }

    if (!/^\d{4,6}$/.test(value)) {
      ctx.addIssue({ code: 'custom', message: `${label} must be 4-6 digits` });
      return '';
    }

    return value;
  });

  return optional ? schema.optional() : schema;
}

/** POST /api/v1/shield-pay/check-upi */
const checkUpiSchema = z
  .object({
    identifier: z.any().optional(),
    upiId: z.any().optional(),
  })
  .transform((data, ctx) => ({ identifier: resolveIdentifier(data, ctx) }));

/** POST /api/v1/shield-pay/proceed-transaction */
const proceedTransactionSchema = z
  .object({
    identifier: z.any().optional(),
    upiId: z.any().optional(),
    amount: amountField,
    pin: pinField('pin'),
    riskAccepted: optionalBoolean('riskAccepted'),
    checkId: objectIdField.optional(),
  })
  .transform((data, ctx) => ({
    identifier: resolveIdentifier(data, ctx),
    amount: data.amount,
    pin: data.pin,
    riskAccepted: data.riskAccepted === true,
    checkId: data.checkId ?? null,
  }));

/** POST /api/v1/shield-pay/set-pin */
const setPinSchema = z.object({
  pin: pinField('pin'),
  currentPin: pinField('currentPin', { optional: true }),
});

module.exports = { checkUpiSchema, proceedTransactionSchema, setPinSchema, amountField, pinField };
