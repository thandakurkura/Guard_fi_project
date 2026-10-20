'use strict';

/**
 * GuardFi — screenshot storage strategy (Phase 7)
 *
 * One question, four answers, in order of preference:
 *
 *   1. CLOUDINARY — when credentials are configured (or the operator pinned
 *      SCAM_BUSTER_STORAGE_MODE=cloudinary). Durable, CDN-served, the production
 *      answer.
 *   2. LOCAL      — when Cloudinary is not set up yet: the file is written to
 *      SCAM_BUSTER_LOCAL_STORAGE_DIR (default `uploads/scam-scans`, mode 0600)
 *      and referenced as `local://scam-scans/<file>`. This is the "works before
 *      the hackathon account is approved" path — and it is LOUD about it in the
 *      logs, because a local disk on a deployed host is ephemeral.
 *   3. DATA_URI   — when the local write itself fails (read-only filesystem,
 *      full disk, a container with no volume). Small screenshots (≤ 1 MB by
 *      default) are inlined as a data URI so the scan keeps its image; the
 *      default cap keeps the MongoDB document far below the 16 MB limit.
 *   4. NONE       — anything bigger that could not be written is dropped, with
 *      imageUrl = null and a warning. Analysis never depends on storage: the
 *      screenshot is analysed from the in-memory buffer, so even this case
 *      produces a full verdict.
 *
 * Why the image stays out of the response path: the client already has the
 * screenshot it just took. The stored copy is the audit trail, so a storage
 * failure must degrade the TRAIL, never the analysis — which is exactly the
 * difference between this chain and a 503.
 *
 * Filenames are generated server-side from a MIME allow-list; the client's own
 * filename is never used, so a hostile name cannot traverse paths or choose an
 * executable extension.
 */

const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const { config } = require('../config/env');
const logger = require('../utils/logger');
const cloudinaryService = require('./cloudinaryService');

const STORAGE = Object.freeze({
  CLOUDINARY: 'CLOUDINARY',
  LOCAL: 'LOCAL',
  DATA_URI: 'DATA_URI',
  NONE: 'NONE',
});

const EXTENSION_BY_MIME = Object.freeze({ 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' });

const LOCAL_URI_PREFIX = 'local://scam-scans/';

/** Absolute directory the local fallback writes into. */
function resolveLocalDir() {
  const dir = config.scamBuster.localStorageDir;
  return path.isAbsolute(dir) ? dir : path.resolve(process.cwd(), dir);
}

/**
 * Turn `local://scam-scans/<file>` back into an absolute path (used by cleanup
 * and by a future delete-my-scan endpoint). Returns null for any other scheme.
 * @param {string} imageUrl
 */
function resolveLocalPath(imageUrl) {
  if (typeof imageUrl !== 'string' || !imageUrl.startsWith(LOCAL_URI_PREFIX)) return null;

  const name = path.basename(imageUrl.slice(LOCAL_URI_PREFIX.length));
  if (!/^[a-zA-Z0-9_-]+\.(?:jpg|png|webp)$/.test(name)) return null;

  return path.join(resolveLocalDir(), name);
}

function prefersCloudinary() {
  const mode = config.scamBuster.storageMode;

  if (mode === 'local') return false;
  // mode 'cloudinary' is validated at boot (env.js refuses to start without
  // credentials), so reaching here configured is the normal case; the check
  // below is belt-and-braces for direct service use.
  if (mode === 'cloudinary') return cloudinaryService.isCloudinaryConfigured();

  return cloudinaryService.isCloudinaryConfigured();
}

/**
 * Store one screenshot using the best available strategy.
 *
 * @param {{ buffer: Buffer, mimeType: string, userId?: unknown }} params
 * @returns {Promise<{ imageUrl: string|null, cloudinaryPublicId: string|null, storage: string }>}
 */
async function storeScreenshot({ buffer, mimeType, userId = null }) {
  if (prefersCloudinary()) {
    const uploaded = await cloudinaryService.uploadImage({ buffer, mimeType });
    return { imageUrl: uploaded.secureUrl, cloudinaryPublicId: uploaded.publicId ?? null, storage: STORAGE.CLOUDINARY };
  }

  return storeWithoutCloudinary({ buffer, mimeType, userId });
}

/**
 * The offline half of the chain: local file → capped data URI → nothing.
 * Exported so a CONFIGURED Cloudinary that is merely down can still be skipped
 * instead of failing the scan.
 *
 * @param {{ buffer: Buffer, mimeType: string, userId?: unknown }} params
 */
async function storeWithoutCloudinary({ buffer, mimeType, userId = null }) {
  try {
    const name = await writeLocalFile({ buffer, mimeType, userId });
    logger.warn(`[scam-buster] screenshot stored on local disk as ${name} (Cloudinary not in use).`);
    return { imageUrl: `${LOCAL_URI_PREFIX}${name}`, cloudinaryPublicId: null, storage: STORAGE.LOCAL };
  } catch (error) {
    logger.warn(`[scam-buster] local screenshot storage failed (${error.message}); trying an inline copy.`);
  }

  if (buffer.length <= config.scamBuster.inlineImageMaxBytes) {
    return {
      imageUrl: `data:${mimeType};base64,${buffer.toString('base64')}`,
      cloudinaryPublicId: null,
      storage: STORAGE.DATA_URI,
    };
  }

  logger.warn('[scam-buster] screenshot could not be stored at all (local failed, too large to inline).');

  return { imageUrl: null, cloudinaryPublicId: null, storage: STORAGE.NONE };
}

/**
 * @param {{ buffer: Buffer, mimeType: string, userId?: unknown }} params
 * @returns {Promise<string>} the generated filename
 */
async function writeLocalFile({ buffer, mimeType, userId }) {
  const dir = resolveLocalDir();
  await fs.mkdir(dir, { recursive: true });

  const extension = EXTENSION_BY_MIME[mimeType] || 'bin';
  const owner = String(userId ?? 'anonymous').replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24) || 'anonymous';
  const name = `${owner}-${Date.now().toString(36)}-${crypto.randomBytes(6).toString('hex')}.${extension}`;

  await fs.writeFile(path.join(dir, name), buffer, { mode: 0o600 });

  return name;
}

module.exports = {
  STORAGE,
  storeScreenshot,
  storeWithoutCloudinary,
  writeLocalFile,
  resolveLocalDir,
  resolveLocalPath,
  prefersCloudinary,
  LOCAL_URI_PREFIX,
  EXTENSION_BY_MIME,
};
