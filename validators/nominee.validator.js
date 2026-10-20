'use strict';

/**
 * GuardFi — nominee input schemas (Phase 3)
 *
 * Every rule the Nominee API promises is enforced here first, so the service
 * and the database only ever see clean data:
 *   name       1-80 characters, trimmed, no control characters (they corrupt
 *              logs and make a display name unrenderable in Flutter)
 *   phone      any spelling → E.164 (utils/phone.js), the same normalisation
 *              the User model uses, so "098765…" and "+9198765…" cannot become
 *              two different guardians
 *   relation   optional, ≤40 characters, null clears it
 *   isPrimary  optional real boolean — the string "true" is rejected
 *   fcmToken   optional, never returned by any endpoint
 *
 * Unknown keys are stripped by zod, which is what stops a client from
 * mass-assigning `userId` and attaching a guardian to someone else's account.
 */

const { z } = require('zod');
const { looseString, optionalString, optionalBoolean, e164Field, objectIdField } = require('./common');

const CONTROL_CHARACTERS = /[\u0000-\u001F\u007F]/;

const nameField = looseString('name').transform((value, ctx) => {
  if (value === '') {
    ctx.addIssue({ code: 'custom', message: 'name is required' });
    return '';
  }
  if (value.length > 80) {
    ctx.addIssue({ code: 'custom', message: 'name cannot exceed 80 characters' });
    return '';
  }
  if (CONTROL_CHARACTERS.test(value)) {
    ctx.addIssue({ code: 'custom', message: 'name cannot contain control characters' });
    return '';
  }
  return value;
});

const relationField = z
  .any()
  .transform((value, ctx) => {
    if (value === undefined) return undefined;
    if (value === null) return null; // explicit "remove the relation"
    if (typeof value !== 'string') {
      ctx.addIssue({ code: 'custom', message: 'relation must be a string' });
      return undefined;
    }
    const trimmed = value.trim();
    if (trimmed === '') return null;
    if (trimmed.length > 40) {
      ctx.addIssue({ code: 'custom', message: 'relation cannot exceed 40 characters' });
      return undefined;
    }
    if (CONTROL_CHARACTERS.test(trimmed)) {
      ctx.addIssue({ code: 'custom', message: 'relation cannot contain control characters' });
      return undefined;
    }
    return trimmed;
  })
  .optional();

/** POST /api/v1/nominees/add */
const addNomineeSchema = z.object({
  name: nameField,
  phone: e164Field('phone'),
  relation: relationField,
  isPrimary: optionalBoolean('isPrimary'),
  fcmToken: optionalString('fcmToken', { maxLength: 512 }),
});

/**
 * PATCH /api/v1/nominees/:id
 * Phone is intentionally not editable: it is the guardian's identity and the
 * duplicate guard, so changing it is "remove and add" — which also makes the
 * client confirm it is a different person rather than a typo fixup.
 */
const updateNomineeSchema = z
  .object({
    name: nameField.optional(),
    relation: relationField,
    isPrimary: optionalBoolean('isPrimary'),
    fcmToken: optionalString('fcmToken', { maxLength: 512 }),
  })
  .refine(
    (data) => Object.values(data).some((value) => value !== undefined),
    { message: 'Provide at least one field to update: name, relation, isPrimary or fcmToken.' }
  );

/** DELETE /api/v1/nominees/remove/:id and PATCH /api/v1/nominees/:id */
const nomineeIdParamsSchema = z.object({ id: objectIdField });

module.exports = { addNomineeSchema, updateNomineeSchema, nomineeIdParamsSchema };
