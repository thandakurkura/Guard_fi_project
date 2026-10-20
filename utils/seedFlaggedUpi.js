'use strict';

/**
 * GuardFi — spec-path entry point for the FlaggedEntity seed (Phase 6)
 *
 * The master prompt names this file `utils/seedFlaggedUpi.js`; the
 * implementation lives in `scripts/seedFlaggedUpi.js` because that is where
 * every runnable script in this project lives (`npm run seed:flagged`, and
 * scripts/verify-phase6.js imports the dataset from there).
 *
 * This module exists so both paths resolve to ONE implementation — copying the
 * dataset here would be exactly the kind of duplication that drifts (one copy
 * gets a new scam row, the other does not, and the demo shows stale data).
 *
 *   const { FLAGGED_ENTITIES, seedFlaggedEntities } = require('utils/seedFlaggedUpi');
 */

module.exports = require('../scripts/seedFlaggedUpi');
