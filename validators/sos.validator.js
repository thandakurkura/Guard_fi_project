'use strict';

/**
 * GuardFi — SOS input schemas (Phase 4)
 *
 * Used by both transports: the REST controller through validateRequest, and the
 * Socket.io handlers through `.safeParse()` (a rejected payload becomes an ack
 * with a field message, never a thrown exception on the socket).
 *
 * Coordinates are validated as real numbers in range — `NaN`, `"12abc"`,
 * `null`, arrays and booleans are rejected here, so nothing downstream can write
 * an invalid GeoJSON point. Numeric strings are accepted because form-encoded
 * clients send them; they are converted, not trusted.
 */

const { z } = require('zod');
const { optionalString, objectIdField } = require('./common');

const STATUS_VALUES = ['RESOLVED', 'FALSE_ALARM'];

/** @param {string} label @param {number} min @param {number} max */
function boundedNumber(label, min, max) {
  return z.any().transform((value, ctx) => {
    let parsed = null;

    if (typeof value === 'number') parsed = value;
    else if (typeof value === 'string' && value.trim() !== '') parsed = Number(value);

    if (!Number.isFinite(parsed)) {
      ctx.addIssue({ code: 'custom', message: `${label} must be a number` });
      return 0;
    }

    if (parsed < min || parsed > max) {
      ctx.addIssue({ code: 'custom', message: `${label} must be between ${min} and ${max}` });
      return 0;
    }

    return parsed;
  });
}

const latitudeField = boundedNumber('latitude', -90, 90);
const longitudeField = boundedNumber('longitude', -180, 180);

const accuracyField = z
  .any()
  .transform((value, ctx) => {
    if (value === undefined || value === null || value === '') return null;
    const parsed = typeof value === 'number' ? value : Number(value);
    if (!Number.isFinite(parsed) || parsed < 0 || parsed > 100_000) {
      ctx.addIssue({ code: 'custom', message: 'accuracy must be a number between 0 and 100000 metres' });
      return null;
    }
    return parsed;
  })
  .optional();

const locationSchema = z.object({
  latitude: latitudeField,
  longitude: longitudeField,
  accuracy: accuracyField,
});

const roomIdField = z
  .string({ error: 'roomId must be a string' })
  .trim()
  .regex(/^[A-Za-z0-9_-]{12}$/, 'roomId must be a 12-character alert room code');

const statusField = z
  .any()
  .transform((value, ctx) => {
    if (value === undefined || value === null || value === '') return 'RESOLVED';
    const normalized = String(value).trim().toUpperCase();
    if (!STATUS_VALUES.includes(normalized)) {
      ctx.addIssue({ code: 'custom', message: 'status must be RESOLVED or FALSE_ALARM' });
      return 'RESOLVED';
    }
    return normalized;
  })
  .default('RESOLVED');

/** POST /api/v1/sos/trigger */
const triggerSosSchema = z.object({
  location: locationSchema,
  message: optionalString('message', { maxLength: 280 }),
});

/** POST /api/v1/sos/resolve */
const resolveSosSchema = z.object({
  status: statusField,
  note: optionalString('note', { maxLength: 280 }),
});

/**
 * Socket payloads may address an alert by id or by the SMS-safe room code.
 * Exactly one is enough; sending neither is a validation error.
 */
function alertReferenceRefinement(data) {
  return Boolean(data.alertId || data.roomId);
}

const joinSosRoomSchema = z
  .object({
    alertId: objectIdField.optional(),
    roomId: roomIdField.optional(),
  })
  .refine(alertReferenceRefinement, { message: 'Send either alertId or roomId.' });

const locationUpdateSchema = z
  .object({
    alertId: objectIdField.optional(),
    roomId: roomIdField.optional(),
    latitude: latitudeField,
    longitude: longitudeField,
    accuracy: accuracyField,
  })
  .refine(alertReferenceRefinement, { message: 'Send either alertId or roomId.' });

const stopSosSchema = z
  .object({
    alertId: objectIdField.optional(),
    roomId: roomIdField.optional(),
    status: statusField,
    note: optionalString('note', { maxLength: 280 }),
  })
  .refine(alertReferenceRefinement, { message: 'Send either alertId or roomId.' });

/**
 * Flatten a zod failure into the field list used everywhere else.
 * @param {import('zod').ZodError} error
 */
function zodIssues(error) {
  return (error?.issues ?? []).map((issue) => ({
    field: issue.path && issue.path.length > 0 ? issue.path.join('.') : null,
    code: issue.code || 'invalid',
    message: issue.message,
  }));
}

module.exports = {
  triggerSosSchema,
  resolveSosSchema,
  joinSosRoomSchema,
  locationUpdateSchema,
  stopSosSchema,
  locationSchema,
  zodIssues,
  STATUS_VALUES,
};
