'use strict';

/**
 * GuardFi — nominee routes (Phase 3)
 *
 * Every route is protected by authMiddleware: a nominee list is personal data,
 * and the caller's identity is what scopes every query. Order per route is
 * auth → validation → controller, so an unauthenticated request never reaches
 * the validator and a malformed id never reaches Mongoose.
 *
 * The master spec's paths are kept verbatim (`/add`, `/list`, `/remove/:id`) so
 * the Flutter client and the Postman collection built against the spec keep
 * working; PATCH `/:id` is the "U" that CRUD implies.
 */

const express = require('express');
const authMiddleware = require('../../middlewares/authMiddleware');
const { validateRequest } = require('../../middlewares/validateRequest');
const {
  addNomineeSchema,
  updateNomineeSchema,
  nomineeIdParamsSchema,
} = require('../../validators/nominee.validator');
const nomineeController = require('../../controllers/nomineeController');

const router = express.Router();

// Public by nothing: every endpoint below belongs to the signed-in user.
router.use(authMiddleware);

router.post('/add', validateRequest({ body: addNomineeSchema }), nomineeController.add);
router.get('/list', nomineeController.list);

router.patch(
  '/:id',
  validateRequest({ params: nomineeIdParamsSchema, body: updateNomineeSchema }),
  nomineeController.update
);

// Registered before any future `DELETE /:id` alias would be, and with the
// spec's exact path so clients built from the spec keep working.
router.delete('/remove/:id', validateRequest({ params: nomineeIdParamsSchema }), nomineeController.remove);

module.exports = router;
