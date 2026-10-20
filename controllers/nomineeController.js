'use strict';

/**
 * GuardFi — nominee controller (Phase 3)
 *
 * Thin by design: zod has already rejected malformed input, services/
 * nomineeService.js owns every rule, and this file only maps service output
 * onto the shared response envelope. The caller's id always comes from
 * `req.user` (the verified token), never from the body — that is the difference
 * between "a user manages their guardians" and an IDOR.
 *
 *   POST   /api/v1/nominees/add       → 201 { nominee }
 *   GET    /api/v1/nominees/list      → 200 { nominees, count, maxNominees, remainingSlots }
 *   PATCH  /api/v1/nominees/:id       → 200 { nominee }
 *   DELETE /api/v1/nominees/remove/:id → 200 { removed, promotedNomineeId, promotedName, remaining }
 */

const asyncHandler = require('../utils/asyncHandler');
const { sendSuccess } = require('../utils/apiResponse');
const { addNominee, listNominees, updateNominee, removeNominee } = require('../services/nomineeService');

/** POST /api/v1/nominees/add */
const add = asyncHandler(async (req, res) => {
  const nominee = await addNominee({
    userId: req.user._id,
    ownerPhone: req.user.phone,
    input: req.body,
  });

  return sendSuccess(res, {
    statusCode: 201,
    message: `${nominee.name} was added as a nominee.`,
    data: { nominee },
  });
});

/** GET /api/v1/nominees/list */
const list = asyncHandler(async (req, res) => {
  const result = await listNominees(req.user._id);

  return sendSuccess(res, {
    statusCode: 200,
    message: result.count === 0 ? 'You have not added any nominees yet.' : `${result.count} nominee(s) on file.`,
    data: result,
  });
});

/** PATCH /api/v1/nominees/:id */
const update = asyncHandler(async (req, res) => {
  const nominee = await updateNominee({
    userId: req.user._id,
    nomineeId: req.params.id,
    patch: req.body,
  });

  return sendSuccess(res, {
    statusCode: 200,
    message: `${nominee.name} was updated.`,
    data: { nominee },
  });
});

/** DELETE /api/v1/nominees/remove/:id */
const remove = asyncHandler(async (req, res) => {
  const result = await removeNominee({
    userId: req.user._id,
    nomineeId: req.params.id,
  });

  return sendSuccess(res, {
    statusCode: 200,
    message: result.promotedNomineeId
      ? `${result.removed.name} was removed. ${result.promotedName} is now your primary nominee.`
      : `${result.removed.name} was removed.`,
    data: result,
  });
});

module.exports = { add, list, update, remove };
