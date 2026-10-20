'use strict';

/**
 * GuardFi — screenshot upload middleware (Phase 7, Scam Buster)
 *
 * One job: get a screenshot from the multipart request into `req.file.buffer`,
 * or reject it before any controller, database write or paid AI call happens.
 *
 * Enforced here (and re-checked in the service, because a service is a boundary
 * too):
 *   • memory storage — the buffer never touches the local filesystem, so a
 *     hostile filename cannot path-traverse and no temp files leak on crash;
 *   • 5 MB cap (SCAM_BUSTER_MAX_IMAGE_BYTES) — a scam screenshot is a phone
 *     screen, not a RAW photo; the AI and the user's data plan both pay per byte;
 *   • strict MIME allow-list jpeg/png/webp — the spec's list. MIME is a client
 *     claim, so the size cap and the service-layer checks are what actually
 *     bound the damage; the filter stops the obvious cases with a clear message
 *     instead of a mysterious AI failure;
 *   • exactly one file (`files: 1`) and bounded field counts, so a request
 *     cannot smuggle an array of images or thousands of parts into memory.
 *
 * The middleware is CONDITIONAL on multipart/form-data: the same endpoint also
 * accepts `application/json` with just `{ "text": … }`, and Multer would
 * otherwise reject a text-only JSON request with a misleading error.
 *
 * Multer's own errors (LIMIT_FILE_SIZE and friends) are already translated to
 * 413/400 by middlewares/errorMiddleware.js.
 */

const multer = require('multer');
const { config } = require('../config/env');
const ApiError = require('../utils/ApiError');

const IMAGE_FIELD = 'image';

const ALLOWED_IMAGE_MIME = new Set(['image/jpeg', 'image/png', 'image/webp']);

const UPLOAD_LIMITS = Object.freeze({
  fileSize: config.scamBuster.maxImageBytes,
  files: 1,
  fields: 10,
  fieldSize: 10_000,
});

/**
 * Accept only real image MIME types. Exported so the harness can prove the
 * allow-list without going through Multer.
 *
 * @type {import('multer').Options['fileFilter']}
 */
function imageFileFilter(req, file, callback) {
  if (ALLOWED_IMAGE_MIME.has(file.mimetype)) return callback(null, true);

  return callback(
    ApiError.badRequest(`The screenshot must be a JPEG, PNG or WebP image (received "${file.mimetype}").`, [
      {
        field: IMAGE_FIELD,
        code: 'UNSUPPORTED_IMAGE_TYPE',
        message: `allowed types: ${[...ALLOWED_IMAGE_MIME].join(', ')}`,
      },
    ])
  );
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: UPLOAD_LIMITS,
  fileFilter: imageFileFilter,
});

/**
 * Parse a multipart upload when the request actually is one; otherwise pass
 * through untouched so JSON/text requests reach the validator normally.
 *
 * @type {import('express').RequestHandler}
 */
function singleImageUpload(req, res, next) {
  if (!req.is('multipart/form-data')) return next();

  return upload.single(IMAGE_FIELD)(req, res, next);
}

module.exports = {
  singleImageUpload,
  imageFileFilter,
  upload,
  UPLOAD_LIMITS,
  IMAGE_FIELD,
  ALLOWED_IMAGE_MIME,
};
