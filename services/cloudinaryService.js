'use strict';

/**
 * GuardFi — Cloudinary upload transport (Phase 7)
 *
 * Stores one screenshot and returns where it lives. Nothing about the analysis
 * belongs here: Scam Buster treats storage as a separate, replaceable step, and
 * the image is analysed from the in-memory buffer (inline base64), never by
 * asking Gemini to fetch the Cloudinary URL. That matters for privacy — the
 * screenshot is never publicly readable by the model's crawlers — and for
 * robustness, since analysis does not fail when storage is slow.
 *
 * DELIVERY IS A VALUE where it can be, and a typed error where it cannot: a
 * missing key or a dead provider becomes `CLOUDINARY_NOT_CONFIGURED` (503) or
 * `CLOUDINARY_UPLOAD_FAILED` (503) — operational failures, not GuardFi bugs.
 *
 * The uploader itself is injectable (`uploader` parameter) for the same reason
 * pushService takes an `adminFactory`: the verification harness must be able to
 * prove the whole flow — including what gets stored on the ScamScan row — with
 * zero credentials and zero network.
 *
 * A timeout races every upload and destroys the stream on expiry, so a stalled
 * upload cannot pin a request (or a socket) open forever, and the timer is
 * unref'd so a fast success leaves no handle keeping the process alive.
 */

const { config } = require('../config/env');
const logger = require('../utils/logger');
const ApiError = require('../utils/ApiError');

const ALLOWED_FORMATS = Object.freeze(['jpg', 'jpeg', 'png', 'webp']);

/** @type {any | null} */
let configuredSdk = null;

function isCloudinaryConfigured() {
  return config.cloudinary.configured === true;
}

/**
 * Configure the SDK once, lazily. Keeping it out of module scope means a missing
 * dependency or bad credentials cannot stop the API from booting.
 * @returns {any} the cloudinary v2 API
 */
function defaultSdkFactory() {
  if (configuredSdk) return configuredSdk;

  // eslint-disable-next-line global-require
  const cloudinary = require('cloudinary').v2;

  cloudinary.config({
    cloud_name: config.cloudinary.cloudName,
    api_key: config.cloudinary.apiKey,
    api_secret: config.cloudinary.apiSecret,
    secure: true,
  });

  configuredSdk = cloudinary;
  return configuredSdk;
}

/**
 * Upload one image buffer.
 *
 * @param {{
 *   buffer: Buffer,
 *   mimeType: string,
 *   folder?: string,
 *   uploader?: (buffer: Buffer, options: object) => Promise<{ secureUrl: string, publicId: string|null }>
 * }} params
 * @returns {Promise<{ secureUrl: string, publicId: string|null }>}
 */
async function uploadImage({ buffer, mimeType, folder, uploader = null }) {
  if (uploader) return uploader(buffer, { mimeType, folder: folder || config.cloudinary.folder });

  if (!isCloudinaryConfigured()) {
    throw new ApiError(503, 'Screenshot storage is not configured on this server (Cloudinary credentials are missing).', {
      code: 'CLOUDINARY_NOT_CONFIGURED',
      errors: [
        {
          code: 'CLOUDINARY_NOT_CONFIGURED',
          message: 'set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET to accept screenshots',
        },
      ],
    });
  }

  return uploadWithSdk({ buffer, mimeType, folder: folder || config.cloudinary.folder });
}

async function uploadWithSdk({ buffer, mimeType, folder }) {
  const cloudinary = defaultSdkFactory();
  const startedAt = Date.now();
  const timeoutMs = config.cloudinary.timeoutMs;

  let stream = null;
  let timer = null;

  try {
    const upload = new Promise((resolve, reject) => {
      stream = cloudinary.uploader.upload_stream(
        {
          folder,
          resource_type: 'image',
          // Defence in depth: the Multer filter already refused anything else.
          allowed_formats: ALLOWED_FORMATS,
          overwrite: false,
          unique_filename: true,
        },
        (error, result) => (error ? reject(error) : resolve(result))
      );

      stream.end(buffer);
    });

    const result = await Promise.race([
      upload,
      new Promise((resolve, reject) => {
        timer = setTimeout(() => {
          // Free the socket rather than leaving the stream half-written.
          if (stream && typeof stream.destroy === 'function') stream.destroy();
          reject(
            new ApiError(503, 'The screenshot could not be stored because the storage service timed out.', {
              code: 'CLOUDINARY_UPLOAD_FAILED',
              errors: [{ code: 'CLOUDINARY_UPLOAD_FAILED', message: `no answer within ${timeoutMs}ms` }],
            })
          );
        }, timeoutMs);
        if (typeof timer.unref === 'function') timer.unref();
      }),
    ]);

    const secureUrl = result?.secure_url || result?.url || null;

    if (!secureUrl) {
      throw new Error('upload succeeded without a URL');
    }

    logger.debug(`[cloudinary] stored ${mimeType} (${buffer.length} bytes) in ${Date.now() - startedAt}ms.`);

    return { secureUrl, publicId: result.public_id || null };
  } catch (error) {
    if (error instanceof ApiError) throw error;

    throw new ApiError(503, 'The screenshot could not be stored right now. Please try again.', {
      code: 'CLOUDINARY_UPLOAD_FAILED',
      errors: [
        {
          code: 'CLOUDINARY_UPLOAD_FAILED',
          message: (error instanceof Error ? error.message : String(error ?? '')).slice(0, 200) || 'unknown storage failure',
        },
      ],
    });
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Interpret one Cloudinary destroy response.
 *
 * `not found` counts as GONE, not as a failure: the account-deletion cascade is
 * re-runnable and an asset that a previous run (or the Cloudinary dashboard)
 * already removed must not be reported as an error the user has to care about.
 *
 * @param {string} publicId
 * @param {any} result
 */
function normaliseDestroyResult(publicId, result) {
  const outcome = result && typeof result === 'object' ? result.result : undefined;

  if (outcome === 'ok') return { publicId, destroyed: true, reason: null };
  if (outcome === 'not found') return { publicId, destroyed: true, reason: 'ALREADY_DELETED' };

  return {
    publicId,
    destroyed: false,
    reason: 'DESTROY_FAILED',
    message: `unexpected destroy response: ${String(outcome ?? result ?? 'empty').slice(0, 120)}`,
  };
}

/**
 * Delete ONE stored asset, and NEVER throw.
 *
 * Account deletion is the caller. A missing Cloudinary key, a dead provider, an
 * asset deleted by hand five minutes ago or a hung request must all degrade to a
 * report on the summary — never to an HTTP 500 that leaves the user's personal
 * data in MongoDB because a screenshot could not be tidied up. That is why this
 * returns a result object instead of rejecting.
 *
 * `destroyer` is injectable for the same reason `uploader` is: the verification
 * harness proves the cascade wipes exactly the right public ids with no
 * credentials and no network.
 *
 * @param {string|null|undefined} publicId
 * @param {{ destroyer?: ((publicId: string) => Promise<any>) | null }} [options]
 * @returns {Promise<{ publicId: string|null, destroyed: boolean, reason: string|null, message?: string }>}
 */
async function destroyImage(publicId, { destroyer = null } = {}) {
  if (typeof publicId !== 'string' || publicId.trim() === '') {
    return { publicId: publicId ?? null, destroyed: false, reason: 'NO_PUBLIC_ID' };
  }

  const id = publicId.trim();

  if (destroyer) {
    try {
      return normaliseDestroyResult(id, await destroyer(id));
    } catch (error) {
      return {
        publicId: id,
        destroyed: false,
        reason: 'DESTROY_FAILED',
        message: (error instanceof Error ? error.message : String(error ?? '')).slice(0, 200) || 'destroyer threw',
      };
    }
  }

  if (!isCloudinaryConfigured()) {
    return { publicId: id, destroyed: false, reason: 'CLOUDINARY_NOT_CONFIGURED' };
  }

  const cloudinary = defaultSdkFactory();
  const timeoutMs = config.cloudinary.timeoutMs;

  let timer = null;

  try {
    const result = await Promise.race([
      cloudinary.uploader.destroy(id, { resource_type: 'image', invalidate: true }),
      new Promise((resolve) => {
        // Resolve (not reject): a timeout must not escape as an exception, and the
        // sentinel keeps "the provider never answered" distinguishable from "the
        // provider said no".
        timer = setTimeout(() => resolve({ __timedOut: true }), timeoutMs);
        if (timer && typeof timer.unref === 'function') timer.unref();
      }),
    ]);

    if (result && result.__timedOut) {
      return { publicId: id, destroyed: false, reason: 'DESTROY_TIMEOUT' };
    }

    const outcome = normaliseDestroyResult(id, result);

    if (outcome.destroyed) {
      logger.debug(`[cloudinary] destroyed ${id} (${outcome.reason || 'ok'}).`);
    } else {
      logger.warn(`[cloudinary] could not destroy ${id}: ${outcome.message || outcome.reason}`);
    }

    return outcome;
  } catch (error) {
    logger.warn(`[cloudinary] destroy threw for ${id}: ${error.message}`);
    return {
      publicId: id,
      destroyed: false,
      reason: 'DESTROY_FAILED',
      message: (error instanceof Error ? error.message : String(error ?? '')).slice(0, 200) || 'unknown destroy failure',
    };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Destroy a list of assets with bounded concurrency.
 *
 * Bounded on purpose: an account with 300 screenshots must not open 300 sockets
 * to Cloudinary in one burst. Every item still resolves to a report entry, so the
 * caller's summary stays exact.
 *
 * @param {Array<string|null|undefined>} publicIds
 * @param {{ destroyer?: Function|null, concurrency?: number }} [options]
 */
async function destroyImages(publicIds, { destroyer = null, concurrency = 5 } = {}) {
  const unique = [...new Set((publicIds || []).filter((id) => typeof id === 'string' && id.trim() !== ''))];
  const results = new Array(unique.length);
  const workers = Math.max(1, Math.min(Number(concurrency) || 5, unique.length || 1));
  let cursor = 0;

  await Promise.all(
    Array.from({ length: workers }, async () => {
      while (cursor < unique.length) {
        const index = cursor;
        cursor += 1;
        results[index] = await destroyImage(unique[index], { destroyer });
      }
    })
  );

  return {
    requested: unique.length,
    destroyed: results.filter((entry) => entry.destroyed).length,
    failed: results.filter((entry) => !entry.destroyed).length,
    results,
  };
}

module.exports = {
  isCloudinaryConfigured,
  uploadImage,
  uploadWithSdk,
  normaliseDestroyResult,
  destroyImage,
  destroyImages,
  ALLOWED_FORMATS,
};
