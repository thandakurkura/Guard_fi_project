'use strict';

/**
 * GuardFi — cascading account deletion (Phase 11)
 *
 * "Delete my account" in India's DPDP Act (and the GDPR before it) means the
 * personal data is actually gone, not flagged. GuardFi's data is spread across
 * seven collections plus a screenshot bucket, so deletion is a cascade with one
 * ordering rule that matters:
 *
 *   1. READ what the screenshots are (`cloudinaryPublicId`) BEFORE deleting the
 *      rows that name them. Deleting ScamScan first would orphan every asset in
 *      Cloudinary forever — the exact failure a "delete everything" button is
 *      supposed to prevent.
 *   2. DESTROY the assets. Never allowed to fail the request: a missing key, a
 *      provider outage or an asset deleted by hand degrades to a line in the
 *      summary. A screenshot is the user's data, but leaving the REST of their
 *      data behind because a CDN call failed would be worse.
 *   3. CLOSE the live sessions (SOS rooms + the user's sockets) while the alert
 *      documents still exist, so guardians are told the room is over instead of
 *      sitting in a room whose alert no longer exists.
 *   4. DELETE the rows in parallel — they are independent — and then the User
 *      last, so a crash mid-cascade leaves an account that can be deleted again
 *      rather than orphaned rows with no owner to delete them from.
 *   5. WRITE one immutable AuditLog row AFTER the cascade. It is the only record
 *      that survives, which is exactly why it is written last: an audit entry
 *      claiming a deletion that then failed would be a lie.
 *
 * The AuditLog is deliberately NOT deleted. It is append-only by construction,
 * carries no screenshots or message text, and is the company's proof that the
 * request was honoured — personal data is what disappears, not the paper trail.
 */

const User = require('../models/User');
const Nominee = require('../models/Nominee');
const SosAlert = require('../models/SosAlert');
const ScamScan = require('../models/ScamScan');
const TransactionAudit = require('../models/TransactionAudit');
const Otp = require('../models/Otp');
const SendThrottle = require('../models/SendThrottle');
const AuditLog = require('../models/AuditLog');
const cloudinaryService = require('./cloudinaryService');
const logger = require('../utils/logger');

/** `destroyImages` opens at most this many Cloudinary requests at once. */
const DESTROY_CONCURRENCY = 5;

/**
 * @param {{ userId: string, phone: string, request?: { ipAddress?: string|null, userAgent?: string|null },
 *           deps?: { destroyImages?: Function } }} input
 */
async function deleteAccount({ userId, phone, request = {}, deps = {} }) {
  const destroyImages = deps.destroyImages || cloudinaryService.destroyImages;

  // --- 1. read the asset handles before their rows disappear -----------------
  const scans = await ScamScan.find({ userId, cloudinaryPublicId: { $ne: null } })
    .select('cloudinaryPublicId')
    .lean();

  const publicIds = scans.map((scan) => scan.cloudinaryPublicId).filter(Boolean);

  // --- 2. destroy the assets, never fatally ----------------------------------
  // `destroyImages` already converts every per-asset failure into a report
  // entry, but the cascade must survive a destroyer that throws anyway (an
  // injected fake in a test, or a future provider swap) — the user's OTHER data
  // must never stay behind because a CDN call misbehaved.
  let cloudinary = { requested: 0, destroyed: 0, failed: 0, results: [] };

  if (publicIds.length > 0) {
    try {
      cloudinary = await destroyImages(publicIds, { concurrency: DESTROY_CONCURRENCY });
    } catch (error) {
      logger.warn(`[account] Screenshot destruction threw for user ${userId}: ${error.message}`);
      cloudinary = {
        requested: publicIds.length,
        destroyed: 0,
        failed: publicIds.length,
        results: publicIds.map((publicId) => ({
          publicId,
          destroyed: false,
          reason: 'DESTROY_FAILED',
          message: (error instanceof Error ? error.message : String(error ?? '')).slice(0, 200),
        })),
      };
    }
  }

  if (cloudinary.failed > 0) {
    logger.warn(
      `[account] ${cloudinary.failed}/${cloudinary.requested} screenshot(s) could not be destroyed for user ${userId}; the account deletion proceeds.`
    );
  }

  // --- 3. close live sessions while the alerts still exist -------------------
  let sockets = { alertsClosed: 0, roomsEmptied: 0, socketsDisconnected: 0 };

  try {
    // Required lazily: services must not depend on socket bootstrap at module
    // load, and a CLI/script context has no socket server at all.
    const { getSocket } = require('../sockets');
    const { closeUserSosSessions } = require('../sockets/sosSocket');

    sockets = await closeUserSosSessions(getSocket(), userId);
  } catch (error) {
    logger.error(`[account] Could not close socket sessions for user ${userId}: ${error.message}`);
  }

  // --- 4. cascade the collections in parallel, user last ---------------------
  const [nomineeReport, alertReport, scanReport, auditReport, otpReport, throttleReport] = await Promise.all([
    Nominee.deleteMany({ userId }),
    SosAlert.deleteMany({ userId }),
    ScamScan.deleteMany({ userId }),
    TransactionAudit.deleteMany({ userId }),
    // Identity is the phone number: OTP codes and the SMS send budget are keyed
    // by it, not by the user id, so they are deleted by phone.
    Otp.deleteMany({ phone }),
    SendThrottle.deleteMany({ phone }),
  ]);

  const deletedUser = await User.findByIdAndDelete(userId);

  if (!deletedUser) {
    // authMiddleware already proved the account existed; reaching here means a
    // concurrent deletion won the race. Every row above is already gone, so this
    // is a success from the user's point of view — do not pretend otherwise.
    logger.warn(`[account] User ${userId} was already deleted by a concurrent request.`);
  }

  const deleted = {
    user: deletedUser ? 1 : 0,
    nominees: nomineeReport.deletedCount ?? 0,
    sosAlerts: alertReport.deletedCount ?? 0,
    scamScans: scanReport.deletedCount ?? 0,
    transactionAudits: auditReport.deletedCount ?? 0,
    otps: otpReport.deletedCount ?? 0,
    sendThrottles: throttleReport.deletedCount ?? 0,
  };

  // --- 5. the one row that outlives everything -------------------------------
  const audit = await AuditLog.record({
    userId,
    action: AuditLog.AUDIT_ACTIONS.ACCOUNT_DELETED,
    ipAddress: request.ipAddress || null,
    userAgent: request.userAgent ? String(request.userAgent).slice(0, 512) : null,
    details: {
      requestedAction: 'DELETE_ACCOUNT',
      reason: 'USER_REQUESTED',
      note: `nominees=${deleted.nominees} alerts=${deleted.sosAlerts} scans=${deleted.scamScans} transactions=${deleted.transactionAudits} otps=${deleted.otps} screenshots=${cloudinary.destroyed}/${cloudinary.requested}`.slice(
        0,
        280
      ),
    },
  });

  logger.info(
    `[account] Deleted user ${userId}: ${deleted.nominees} nominees, ${deleted.sosAlerts} alerts, ${deleted.scamScans} scans, ${deleted.transactionAudits} transactions, ${cloudinary.destroyed}/${cloudinary.requested} screenshots.`
  );

  return {
    deleted,
    cloudinary,
    sockets,
    audit: {
      id: String(audit._id),
      action: audit.action,
      createdAt: audit.createdAt,
    },
  };
}

module.exports = { deleteAccount, DESTROY_CONCURRENCY };
