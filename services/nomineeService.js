'use strict';

/**
 * GuardFi — nominee/guardian rules (Phase 3)
 *
 * Everything the endpoint contract promises lives here so the controller stays
 * a translator and the routes stay declarative:
 *
 *   • the cap (MAX_NOMINEES_PER_USER, default 5) is enforced AFTER the insert,
 *     so two concurrent adds at max-1 cannot both squeeze in;
 *   • a phone number already on the list is a 409 from the compound unique
 *     index, translated here into a message that names the field;
 *   • the owner cannot add their own number — an SOS that "notifies" the victim
 *     is a silent failure, and it would burn a slot that must go to a real
 *     guardian;
 *   • exactly one nominee is primary at all times: the first one is promoted
 *     automatically, promoting another demotes the previous one, and deleting
 *     the primary promotes the oldest remaining nominee. The one-primary rule is
 *     also a partial unique index in the model, so the database refuses to break
 *     it even under concurrent requests;
 *   • every query is scoped by `userId` taken from the verified token, never
 *     from the request body/params. A nominee belonging to another user answers
 *     404, not 403, so the endpoint cannot be used to discover which ids exist.
 *
 * The guardian's fcmToken is accepted but never serialised back.
 */

const { config } = require('../config/env');
const logger = require('../utils/logger');
const ApiError = require('../utils/ApiError');
const { normalizePhone, maskPhone } = require('../utils/phone');
const Nominee = require('../models/Nominee');

/** Never select the push token. `.lean()` documents skip toJSON, so list() must be explicit. */
const PUBLIC_FIELDS = '-fcmToken';

/**
 * @param {import('mongoose').HydratedDocument<any>|Record<string, any>} doc
 * @returns {{ _id: string, name: string, phone: string, relation: string|null, isPrimary: boolean, createdAt: Date, updatedAt: Date }}
 */
function serialize(doc) {
  const raw = typeof doc.toObject === 'function' ? doc.toObject() : doc;

  return {
    _id: String(raw._id),
    name: raw.name,
    phone: raw.phone,
    relation: raw.relation ?? null,
    isPrimary: raw.isPrimary === true,
    createdAt: raw.createdAt,
    updatedAt: raw.updatedAt,
  };
}

function limitReachedError() {
  return new ApiError(409, `You can have at most ${config.nominees.maxPerUser} nominees. Remove one before adding another.`, {
    errors: [
      {
        field: 'nominees',
        code: 'NOMINEE_LIMIT_REACHED',
        message: `the per-user cap is ${config.nominees.maxPerUser}`,
      },
    ],
  });
}

function duplicateError() {
  return new ApiError(409, 'That phone number is already one of your nominees.', {
    errors: [{ field: 'phone', code: 'NOMINEE_DUPLICATE', message: 'this number is already on your nominee list' }],
  });
}

function notFoundError() {
  return ApiError.notFound('Nominee not found.');
}

/**
 * Promote one nominee to primary and demote whoever held the flag.
 *
 * The `claimPrimary` demotion runs first; the `$set` that follows can then fail
 * with E11000 only if a competing request re-created a primary in between. That
 * failure is retried once — the partial unique index is what turns a silent
 * double-primary bug into a detectable, recoverable event.
 *
 * @param {string} userId
 * @param {string} nomineeId
 */
async function promoteToPrimary(userId, nomineeId) {
  for (let attempt = 1; attempt <= 2; attempt += 1) {
    const exists = await Nominee.exists({ _id: nomineeId, userId });
    if (!exists) throw notFoundError();

    await Nominee.claimPrimary(userId, nomineeId);

    try {
      await Nominee.updateOne({ _id: nomineeId, userId }, { $set: { isPrimary: true } });
      return;
    } catch (error) {
      if (!error || error.code !== 11_000) throw error;
      logger.warn(`[nominee] Primary promotion raced for user ${userId}; retrying with the flag demoted again.`);
    }
  }

  throw ApiError.conflict('Another nominee was made primary at the same time. Please try again.', [
    { code: 'NOMINEE_PRIMARY_RACE', message: 'the primary guardian changed concurrently' },
  ]);
}

/**
 * @param {{ userId: string, ownerPhone?: string|null, input: { name: string, phone: string, relation?: string|null, isPrimary?: boolean, fcmToken?: string|null } }} params
 */
async function addNominee({ userId, ownerPhone = null, input }) {
  // The validator already normalised this; normalising again keeps the service
  // safe when it is called directly (Phase 4 will, to expand a contact).
  const phone = normalizePhone(input.phone);

  if (!phone) {
    throw ApiError.badRequest('phone must be a valid phone number.', [
      { field: 'phone', code: 'NOMINEE_PHONE_INVALID', message: 'not a valid phone number' },
    ]);
  }

  const owner = normalizePhone(ownerPhone);

  if (owner && owner === phone) {
    throw ApiError.badRequest('You cannot add your own number as a nominee.', [
      {
        field: 'phone',
        code: 'NOMINEE_SELF',
        message: 'a nominee must be a different phone number from the account owner',
      },
    ]);
  }

  const max = config.nominees.maxPerUser;
  const existingCount = await Nominee.countForUser(userId);

  if (existingCount >= max) throw limitReachedError();

  // Friendly duplicate check BEFORE the insert. The unique index is still the
  // authority (and the E11000 catch below handles the race), but this also keeps
  // the API correct during a window where that index is not built yet — an
  // insert accepted then would make the index build fail permanently.
  if (await Nominee.exists({ userId, phone })) throw duplicateError();

  let nominee;

  try {
    nominee = await Nominee.create({
      userId, // from the verified token — never from req.body
      name: input.name,
      phone,
      relation: input.relation ?? null,
      fcmToken: input.fcmToken ?? null,
      // Inserted non-primary; promoteToPrimary() below is the only writer that
      // flips the flag, so the partial unique index is never tripped by a
      // first/second nominee race.
      isPrimary: false,
    });
  } catch (error) {
    if (error && error.code === 11_000) throw duplicateError();
    throw error;
  }

  // Race-safe cap: two requests that both read max-1 above will both insert, so
  // the winner is decided here. The loser is deleted again and told the truth.
  const countAfter = await Nominee.countForUser(userId);

  if (countAfter > max) {
    await Nominee.deleteOne({ _id: nominee._id, userId });
    logger.warn(`[nominee] Discarded an over-cap insert for user ${userId}.`);
    throw limitReachedError();
  }

  // The first guardian is primary by default; the client may ask for another.
  if (input.isPrimary === true || countAfter === 1) {
    await promoteToPrimary(userId, nominee._id);
    nominee.isPrimary = true;
  }

  logger.info(`[nominee] Added ${maskPhone(phone)} for user ${userId}${nominee.isPrimary ? ' as primary' : ''}.`);

  return serialize(nominee);
}

/** @param {string} userId */
async function listNominees(userId) {
  const max = config.nominees.maxPerUser;

  // `.lean()` per the spec: this is a read-only projection and hydrated
  // documents buy nothing. Because lean skips the model's toJSON transform, the
  // fcmToken exclusion has to be an explicit projection.
  const nominees = await Nominee.find({ userId })
    .select(PUBLIC_FIELDS)
    .sort({ isPrimary: -1, createdAt: 1 })
    .lean();

  return {
    nominees: nominees.map(serialize),
    count: nominees.length,
    maxNominees: max,
    remainingSlots: Math.max(0, max - nominees.length),
  };
}

/**
 * @param {{ userId: string, nomineeId: string, patch: { name?: string, relation?: string|null, isPrimary?: boolean, fcmToken?: string|null } }} params
 */
async function updateNominee({ userId, nomineeId, patch }) {
  const nominee = await Nominee.findOne({ _id: nomineeId, userId });

  if (!nominee) throw notFoundError();

  // A user with guardians must always have exactly one primary. Demoting the
  // current one directly would leave none, so the caller is told to promote a
  // replacement instead.
  if (patch.isPrimary === false && nominee.isPrimary) {
    throw ApiError.badRequest(
      'A user must always have exactly one primary guardian. Make another nominee primary instead.',
      [
        {
          field: 'isPrimary',
          code: 'NOMINEE_PRIMARY_REQUIRED',
          message: 'demoting the only primary is not allowed; promote a different nominee',
        },
      ]
    );
  }

  if (patch.name !== undefined) nominee.name = patch.name;
  if (patch.relation !== undefined) nominee.relation = patch.relation;
  if (patch.fcmToken !== undefined) nominee.fcmToken = patch.fcmToken;

  if (nominee.isModified()) await nominee.save();

  if (patch.isPrimary === true && !nominee.isPrimary) {
    await promoteToPrimary(userId, nominee._id);
    nominee.isPrimary = true;
  }

  logger.info(`[nominee] Updated ${nominee._id} for user ${userId}.`);

  return serialize(nominee);
}

/**
 * Remove a nominee. `findOneAndDelete({ _id, userId })` is the IDOR guard from
 * the spec: the filter — not a post-read check — decides ownership, so there is
 * no window where another user's document is loaded and then discarded.
 *
 * @param {{ userId: string, nomineeId: string }} params
 */
async function removeNominee({ userId, nomineeId }) {
  const removed = await Nominee.findOneAndDelete({ _id: nomineeId, userId });

  if (!removed) throw notFoundError();

  let promotedNomineeId = null;
  let promotedName = null;

  if (removed.isPrimary) {
    // Keep "at least one primary when any nominee exists" true.
    const next = await Nominee.findOne({ userId }).sort({ createdAt: 1 }).select('_id name').lean();

    if (next) {
      await promoteToPrimary(userId, next._id);
      promotedNomineeId = String(next._id);
      promotedName = next.name;
    }
  }

  const remaining = await Nominee.countForUser(userId);

  logger.info(`[nominee] Removed ${removed._id} for user ${userId}; ${remaining} remaining.`);

  return {
    removed: serialize(removed),
    promotedNomineeId,
    promotedName,
    remaining,
  };
}

module.exports = { addNominee, listNominees, updateNominee, removeNominee, promoteToPrimary };
