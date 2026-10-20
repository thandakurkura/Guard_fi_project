'use strict';

/**
 * GuardFi — cascading account deletion verification
 *
 * Proves, against a real Express + Socket.io server and a throwaway MongoDB:
 *   • DELETE /api/v1/auth/account is authenticated: anonymous 401, and a caller
 *     can only ever delete their own account;
 *   • every ScamScan cloudinaryPublicId for the caller is destroyed through the
 *     Cloudinary transport (injected destroyer + a real unconfigured-server run),
 *     and a destroyer that throws still cannot block the deletion;
 *   • live Socket.io sessions are closed: the caller's socket is told the account
 *     is gone and is disconnected;
 *   • the cascade empties User, Nominee, SosAlert, ScamScan, TransactionAudit,
 *     Otp and SendThrottle for the caller — and nothing else;
 *   • the final immutable AuditLog ACCOUNT_DELETED row survives the cascade and
 *     is itself tamper-proof;
 *   • the old token is worthless afterwards (identity is read from the database);
 *   • the scanner really persists cloudinaryPublicId on the scan row.
 *
 * Run:  npm run verify:account-deletion
 * Exit: 0 = every check passed, 1 = at least one failed, 2 = harness cannot run.
 */

process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = process.env.VERIFY_LOG_LEVEL || 'error';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'verify-account-deletion-secret-'.padEnd(48, '0');
process.env.CORS_ORIGINS = '*';
process.env.STRICT_ENV = 'false';
process.env.TRUST_PROXY = 'false';
delete process.env.PORT;

process.env.MONGO_URI = 'mongodb://127.0.0.1:27017/guardfi-account-deletion-placeholder';
process.env.OTP_DEV_MODE = 'true';
process.env.SMS_PROVIDER = 'none';
// Unconfigured on purpose: the HTTP run must prove that a missing Cloudinary key
// never blocks a deletion.
process.env.CLOUDINARY_CLOUD_NAME = '';
process.env.CLOUDINARY_API_KEY = '';
process.env.CLOUDINARY_API_SECRET = '';
process.env.SCAM_BUSTER_STORAGE_MODE = 'auto';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const path = require('node:path');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const PORT = Number(process.env.VERIFY_ACCOUNT_PORT || 4349);
const BASE = `http://127.0.0.1:${PORT}`;
const USER_AGENT = 'GuardFi-Account-Deletion/1.0';

let mongo = null;
const servers = [];
const results = [];
const seeded = {};

function record(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => results.push({ name, ok: true }))
    .catch((error) => results.push({ name, ok: false, error: error.message }));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function call(pathname, { method = 'GET', token, body } = {}) {
  const init = { method, headers: { 'user-agent': USER_AGENT } };
  if (token) init.headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const response = await fetch(`${BASE}${pathname}`, init);
  const text = await response.text();
  let parsed = null;

  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }

  return { status: response.status, body: parsed, text };
}

async function waitForHealth(timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no response';

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE}/health`);
      const body = await response.json();
      if (response.status === 200 && body?.data?.database?.connected === true) return body;
      last = `status=${response.status}`;
    } catch (error) {
      last = error.message;
    }
    await sleep(400);
  }

  throw new Error(`server never became healthy within ${timeoutMs}ms (last: ${last})`);
}

function spawnServer(env = {}) {
  const child = spawn(process.execPath, [path.join(PROJECT_ROOT, 'server.js')], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      LOG_LEVEL: 'error',
      PORT: String(PORT),
      MONGO_URI: process.env.MONGO_URI,
      RATE_LIMIT_SKIP_IN_TEST: 'true',
      FIREBASE_PROJECT_ID: '',
      FIREBASE_CLIENT_EMAIL: '',
      FIREBASE_PRIVATE_KEY: '',
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const entry = { child, output: [] };
  child.stdout.on('data', (chunk) => entry.output.push(chunk.toString()));
  child.stderr.on('data', (chunk) => entry.output.push(chunk.toString()));
  servers.push(entry);

  return entry;
}

async function stopServers() {
  for (const entry of servers) {
    if (entry.child.exitCode === null) {
      entry.child.kill();
      await sleep(200);
    }
  }

  if (results.some((result) => !result.ok)) {
    for (const entry of servers) {
      if (!entry.output.length) continue;
      console.error('\n--- server output ---');
      console.error(entry.output.join('').split('\n').slice(-25).join('\n'));
    }
  }
}

// ===========================================================================
// Dataset
// ===========================================================================
const hash = () => crypto.randomBytes(32).toString('hex');

async function seedDataset() {
  const User = require('../models/User');
  const Nominee = require('../models/Nominee');
  const SosAlert = require('../models/SosAlert');
  const ScamScan = require('../models/ScamScan');
  const TransactionAudit = require('../models/TransactionAudit');
  const Otp = require('../models/Otp');
  const SendThrottle = require('../models/SendThrottle');
  const { signAccessToken } = require('../services/tokenService');

  await Promise.all([User.init(), Nominee.init(), SosAlert.init(), ScamScan.init(), TransactionAudit.init()]);

  const now = new Date();
  const makeUser = (phone, name) => ({
    _id: new mongoose.Types.ObjectId(),
    phone,
    name,
    role: 'user',
    securityPinHash: null,
    isEmergencyMode: false,
    biometricEnabled: false,
    emergencyActivatedAt: null,
    createdAt: now,
    updatedAt: now,
  });

  const victim = makeUser('+919876590001', 'Victim Account');
  const bystander = makeUser('+919876590002', 'Bystander Account');
  const serviceProbe = makeUser('+919876590003', 'Service Probe Account');

  await User.collection.insertMany([victim, bystander, serviceProbe]);

  await Nominee.collection.insertMany([
    { userId: victim._id, name: 'Victim Guardian One', phone: '+919876590011', relation: 'Sister', isPrimary: true, fcmToken: null, createdAt: now, updatedAt: now },
    { userId: victim._id, name: 'Victim Guardian Two', phone: '+919876590012', relation: 'Friend', isPrimary: false, fcmToken: null, createdAt: now, updatedAt: now },
    { userId: bystander._id, name: 'Bystander Guardian', phone: '+919876590013', relation: 'Brother', isPrimary: true, fcmToken: null, createdAt: now, updatedAt: now },
  ]);

  const victimActiveAlert = {
    _id: new mongoose.Types.ObjectId(),
    userId: victim._id,
    status: 'ACTIVE',
    roomId: 'victimroom01', // 12 chars — the schema's exact room-code length, unique per alert
    initialLocation: { type: 'Point', coordinates: [77.209, 28.6139] },
    locationHistory: [],
    notifiedNominees: [],
    createdAt: now,
    updatedAt: now,
  };

  await SosAlert.collection.insertMany([
    victimActiveAlert,
    {
      _id: new mongoose.Types.ObjectId(),
      userId: victim._id,
      status: 'RESOLVED',
      roomId: 'victimroom02',
      initialLocation: { type: 'Point', coordinates: [77.21, 28.62] },
      locationHistory: [],
      notifiedNominees: [],
      resolvedAt: now,
      createdAt: now,
      updatedAt: now,
    },
    {
      _id: new mongoose.Types.ObjectId(),
      userId: bystander._id,
      status: 'ACTIVE',
      roomId: 'bystander001',
      initialLocation: { type: 'Point', coordinates: [77.22, 28.63] },
      locationHistory: [],
      notifiedNominees: [],
      createdAt: now,
      updatedAt: now,
    },
  ]);

  const makeScan = (userId, publicId, index) => ({
    userId,
    inputType: 'IMAGE',
    imageUrl: publicId ? `https://res.cloudinary.com/demo/${publicId}.png` : 'local://scam-scans/probe.png',
    cloudinaryPublicId: publicId,
    imageStorage: publicId ? 'CLOUDINARY' : 'LOCAL',
    extractedText: 'probe screenshot',
    isScam: true,
    riskLevel: 'DANGER',
    confidenceScore: 88,
    explanation_en: 'Probe scan.',
    explanation_hi: 'प्रोब स्कैन।',
    redFlags: [],
    createdAt: new Date(now.getTime() + index),
    updatedAt: now,
  });

  await ScamScan.collection.insertMany([
    makeScan(victim._id, 'guardfi/victim-scan-1', 1),
    makeScan(victim._id, 'guardfi/victim-scan-2', 2),
    makeScan(victim._id, null, 3),
    makeScan(bystander._id, 'guardfi/bystander-scan-1', 4),
  ]);

  const makeAudit = (userId) => ({
    userId,
    upiId: 'probe@okicici',
    amount: 100,
    riskLevel: 'SAFE',
    riskScore: 0,
    risk_accepted: false,
    pinVerified: true,
    status: 'COMPLETED',
    transactionHash: hash(),
    ipAddress: '203.0.113.5',
    createdAt: now,
    updatedAt: now,
  });

  await TransactionAudit.collection.insertMany([
    makeAudit(victim._id),
    makeAudit(victim._id),
    makeAudit(bystander._id),
  ]);

  await Otp.collection.insertMany([
    { phone: victim.phone, otpHash: 'victim-hash', purpose: 'LOGIN', expires: new Date(now.getTime() + 300_000), attempts: 0, createdAt: now, updatedAt: now },
    { phone: bystander.phone, otpHash: 'bystander-hash', purpose: 'LOGIN', expires: new Date(now.getTime() + 300_000), attempts: 0, createdAt: now, updatedAt: now },
  ]);

  await SendThrottle.collection.insertMany([
    { phone: victim.phone, count: 2, windowStartedAt: now, expiresAt: new Date(now.getTime() + 3_600_000), createdAt: now, updatedAt: now },
    { phone: bystander.phone, count: 1, windowStartedAt: now, expiresAt: new Date(now.getTime() + 3_600_000), createdAt: now, updatedAt: now },
  ]);

  seeded.victim = { id: String(victim._id), objectId: victim._id, phone: victim.phone, token: signAccessToken(victim).token };
  seeded.bystander = { id: String(bystander._id), objectId: bystander._id, phone: bystander.phone, token: signAccessToken(bystander).token };
  seeded.serviceProbe = { id: String(serviceProbe._id), objectId: serviceProbe._id, phone: serviceProbe.phone };
  seeded.alertId = String(victimActiveAlert._id);
  seeded.roomId = victimActiveAlert.roomId;
}

async function countsFor(userId, phone) {
  const Nominee = require('../models/Nominee');
  const SosAlert = require('../models/SosAlert');
  const ScamScan = require('../models/ScamScan');
  const TransactionAudit = require('../models/TransactionAudit');

  const [nominees, alerts, scans, transactions] = await Promise.all([
    Nominee.countDocuments({ userId }),
    SosAlert.countDocuments({ userId }),
    ScamScan.countDocuments({ userId }),
    TransactionAudit.countDocuments({ userId }),
  ]);

  const Otp = require('../models/Otp');
  const SendThrottle = require('../models/SendThrottle');

  return { nominees, alerts, scans, transactions, otps: await Otp.countDocuments({ phone }), throttles: await SendThrottle.countDocuments({ phone }) };
}

// ===========================================================================
// HTTP + socket checks
// ===========================================================================
async function runHttpChecks() {
  const { io } = require('socket.io-client');
  const { victim, bystander } = seeded;

  await record('auth: the deletion endpoint refuses anonymous callers', async () => {
    const response = await call('/api/v1/auth/account', { method: 'DELETE' });
    assert.equal(response.status, 401, response.text);
    assert.equal(response.body.success, false);
  });

  let socketDisconnected = false;
  let accountDeletedEvent = null;

  await record('socket: the victim joins their live SOS room before deletion', async () => {
    const socket = io(BASE, { auth: { token: victim.token }, transports: ['websocket'], reconnection: false });

    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('socket did not connect')), 6_000);
      socket.on('connect', () => {
        clearTimeout(timer);
        resolve();
      });
      socket.on('connect_error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });

    const ack = await new Promise((resolve) => {
      socket.emit('join_sos_room', { alertId: seeded.alertId }, resolve);
    });

    assert.equal(ack.ok, true, JSON.stringify(ack));
    assert.equal(ack.roomId, seeded.roomId);

    socket.on('account:deleted', (payload) => {
      accountDeletedEvent = payload;
    });
    socket.on('disconnect', () => {
      socketDisconnected = true;
    });

    seeded.victimSocket = socket;
  });

  let deletion = null;

  await record('cascade: DELETE removes every collection for the caller and reports the counts', async () => {
    const response = await call('/api/v1/auth/account', { method: 'DELETE', token: victim.token });
    assert.equal(response.status, 200, response.text);
    assert.equal(response.body.success, true);
    deletion = response.body.data;

    assert.equal(deletion.deleted.user, 1);
    assert.equal(deletion.deleted.nominees, 2);
    assert.equal(deletion.deleted.sosAlerts, 2);
    assert.equal(deletion.deleted.scamScans, 3);
    assert.equal(deletion.deleted.transactionAudits, 2);
    assert.equal(deletion.deleted.otps, 1);
    assert.equal(deletion.deleted.sendThrottles, 1);

    // This server has no Cloudinary credentials: the two assets are reported as
    // failures, and the deletion still succeeded — which is the guarantee.
    assert.equal(deletion.cloudinary.requested, 2, JSON.stringify(deletion.cloudinary));
    assert.equal(deletion.cloudinary.failed, 2);
    assert.ok(
      deletion.cloudinary.results.every((entry) => entry.reason === 'CLOUDINARY_NOT_CONFIGURED'),
      JSON.stringify(deletion.cloudinary.results)
    );

    assert.equal(deletion.sockets.alertsClosed, 1);
    assert.equal(deletion.sockets.socketsDisconnected, 1, JSON.stringify(deletion.sockets));
    assert.equal(deletion.audit.action, 'ACCOUNT_DELETED');
  });

  await record('socket: the deleted account is disconnected from its SOS room', async () => {
    const deadline = Date.now() + 3_000;

    while (!socketDisconnected && Date.now() < deadline) await sleep(100);

    assert.ok(accountDeletedEvent, 'the socket never received account:deleted');
    assert.equal(accountDeletedEvent.reason, 'ACCOUNT_DELETED');
    assert.equal(socketDisconnected, true, 'the socket was not disconnected');

    seeded.victimSocket.close();
    seeded.victimSocket = null;
  });

  await record('cascade: nothing is left in the database for the deleted account', async () => {
    const User = require('../models/User');
    const victimCounts = await countsFor(victim.objectId, victim.phone);

    assert.deepEqual(victimCounts, { nominees: 0, alerts: 0, scans: 0, transactions: 0, otps: 0, throttles: 0 });
    assert.equal(await User.countDocuments({ _id: victim.objectId }), 0);
  });

  await record('cascade: a bystander account is untouched', async () => {
    const User = require('../models/User');
    const bystanderCounts = await countsFor(bystander.objectId, bystander.phone);

    assert.deepEqual(bystanderCounts, { nominees: 1, alerts: 1, scans: 1, transactions: 1, otps: 1, throttles: 1 });
    assert.equal(await User.countDocuments({ _id: bystander.objectId }), 1);
  });

  await record('audit: one immutable ACCOUNT_DELETED row survives the cascade', async () => {
    const AuditLog = require('../models/AuditLog');
    const rows = await AuditLog.find({ userId: victim.objectId }).lean();

    assert.equal(rows.length, 1, `expected exactly one audit row, got ${rows.length}`);
    const row = rows[0];

    assert.equal(row.action, 'ACCOUNT_DELETED');
    assert.ok(row.ipAddress && row.ipAddress.includes('127.0.0.1'), `unexpected audit ip: ${row.ipAddress}`);
    assert.equal(row.userAgent, USER_AGENT);
    assert.equal(row.details.reason, 'USER_REQUESTED');
    assert.match(row.details.note, /nominees=2/);
    assert.match(row.details.note, /screenshots=0\/2/);

    await assert.rejects(
      () => AuditLog.updateOne({ _id: row._id }, { $set: { action: 'EMERGENCY_MODE_LOCKED' } }),
      (error) => error.code === 'AUDIT_LOG_IMMUTABLE'
    );
    await assert.rejects(
      () => AuditLog.deleteOne({ _id: row._id }),
      (error) => error.code === 'AUDIT_LOG_IMMUTABLE'
    );

    assert.equal(await AuditLog.countDocuments({ userId: victim.objectId }), 1);
  });

  await record('auth: the deleted account token is worthless afterwards', async () => {
    const list = await call('/api/v1/nominees/list', { token: victim.token });
    assert.equal(list.status, 401, list.text);
    assert.match(list.body.message, /no longer exists/i);

    const secondDelete = await call('/api/v1/auth/account', { method: 'DELETE', token: victim.token });
    assert.equal(secondDelete.status, 401, secondDelete.text);
  });
}

// ===========================================================================
// Service-level checks (injected destroyer, unit semantics, scan wiring)
// ===========================================================================
async function runServiceChecks() {
  const User = require('../models/User');
  const ScamScan = require('../models/ScamScan');
  const AuditLog = require('../models/AuditLog');
  const cloudinaryService = require('../services/cloudinaryService');
  const { deleteAccount } = require('../services/accountService');

  const { serviceProbe } = seeded;
  const now = new Date();

  await ScamScan.collection.insertMany([
    {
      userId: serviceProbe.objectId,
      inputType: 'IMAGE',
      imageUrl: 'https://res.cloudinary.test/probe-1.png',
      cloudinaryPublicId: 'guardfi/probe-scan-1',
      imageStorage: 'CLOUDINARY',
      isScam: false,
      riskLevel: 'SAFE',
      confidenceScore: 20,
      explanation_en: 'Probe.',
      explanation_hi: 'प्रोब।',
      redFlags: [],
      createdAt: now,
      updatedAt: now,
    },
    {
      userId: serviceProbe.objectId,
      inputType: 'IMAGE',
      imageUrl: 'https://res.cloudinary.test/probe-2.png',
      cloudinaryPublicId: 'guardfi/probe-scan-2',
      imageStorage: 'CLOUDINARY',
      isScam: false,
      riskLevel: 'SAFE',
      confidenceScore: 20,
      explanation_en: 'Probe.',
      explanation_hi: 'प्रोब।',
      redFlags: [],
      createdAt: new Date(now.getTime() + 1),
      updatedAt: now,
    },
    {
      userId: serviceProbe.objectId,
      inputType: 'TEXT',
      imageUrl: null,
      cloudinaryPublicId: null,
      imageStorage: null,
      isScam: false,
      riskLevel: 'SAFE',
      confidenceScore: 10,
      explanation_en: 'Probe text.',
      explanation_hi: 'प्रोब टेक्स्ट।',
      redFlags: [],
      createdAt: new Date(now.getTime() + 2),
      updatedAt: now,
    },
  ]);

  await record('cloudinary: destroyImage never throws and reports every outcome', async () => {
    const unconfigured = await cloudinaryService.destroyImage('guardfi/whatever');
    assert.equal(unconfigured.destroyed, false);
    assert.equal(unconfigured.reason, 'CLOUDINARY_NOT_CONFIGURED');

    const noId = await cloudinaryService.destroyImage(null);
    assert.equal(noId.reason, 'NO_PUBLIC_ID');

    const ok = await cloudinaryService.destroyImage('guardfi/x', { destroyer: async () => ({ result: 'ok' }) });
    assert.equal(ok.destroyed, true);
    assert.equal(ok.reason, null);

    const missing = await cloudinaryService.destroyImage('guardfi/x', { destroyer: async () => ({ result: 'not found' }) });
    assert.equal(missing.destroyed, true, 'an already-deleted asset is gone, not a failure');
    assert.equal(missing.reason, 'ALREADY_DELETED');

    const thrown = await cloudinaryService.destroyImage('guardfi/x', {
      destroyer: async () => {
        throw new Error('provider exploded');
      },
    });
    assert.equal(thrown.destroyed, false);
    assert.equal(thrown.reason, 'DESTROY_FAILED');
    assert.match(thrown.message, /provider exploded/);

    const odd = cloudinaryService.normaliseDestroyResult('guardfi/x', { result: 'rate limited' });
    assert.equal(odd.destroyed, false);
    assert.match(odd.message, /rate limited/);
  });

  await record('cloudinary: destroyImages de-duplicates, bounds concurrency and reports exact counts', async () => {
    const seen = [];
    let inFlight = 0;
    let peak = 0;

    const summary = await cloudinaryService.destroyImages(
      ['a/1', 'a/2', 'a/1', null, 'a/3'],
      {
        concurrency: 2,
        destroyer: async (publicId) => {
          seen.push(publicId);
          inFlight += 1;
          peak = Math.max(peak, inFlight);
          await sleep(30);
          inFlight -= 1;
          return { result: publicId === 'a/3' ? 'not found' : 'ok' };
        },
      }
    );

    assert.deepEqual([...seen].sort(), ['a/1', 'a/2', 'a/3']);
    assert.ok(peak <= 2, `concurrency exceeded: peak ${peak}`);
    assert.equal(summary.requested, 3);
    assert.equal(summary.destroyed, 3);
    assert.equal(summary.failed, 0);
  });

  await record('cascade: an injected destroyer receives exactly this account public ids', async () => {
    const captured = [];

    const result = await deleteAccount({
      userId: serviceProbe.id,
      phone: serviceProbe.phone,
      request: { ipAddress: '203.0.113.77', userAgent: 'ServiceProbe/1.0' },
      deps: {
        destroyImages: async (publicIds, options) => {
          captured.push(...publicIds);
          assert.equal(options.concurrency, 5, 'the cascade should bound Cloudinary concurrency');
          return {
            requested: publicIds.length,
            destroyed: publicIds.length,
            failed: 0,
            results: publicIds.map((publicId) => ({ publicId, destroyed: true, reason: null })),
          };
        },
      },
    });

    assert.deepEqual([...captured].sort(), ['guardfi/probe-scan-1', 'guardfi/probe-scan-2']);
    assert.equal(result.cloudinary.destroyed, 2);
    assert.equal(result.deleted.scamScans, 3);
    assert.equal(result.deleted.user, 1);

    const leftovers = await countsFor(serviceProbe.objectId, serviceProbe.phone);
    assert.deepEqual(leftovers, { nominees: 0, alerts: 0, scans: 0, transactions: 0, otps: 0, throttles: 0 });
    assert.equal(await User.countDocuments({ _id: serviceProbe.objectId }), 0);

    const row = await AuditLog.findOne({ userId: serviceProbe.objectId }).lean();
    assert.equal(row.action, 'ACCOUNT_DELETED');
    assert.equal(row.ipAddress, '203.0.113.77');
    assert.match(row.details.note, /screenshots=2\/2/);
  });

  await record('cascade: a destroyer that throws still deletes the whole account', async () => {
    const User2 = require('../models/User');
    const probe = {
      _id: new mongoose.Types.ObjectId(),
      phone: '+919876590004',
      name: 'Throwing Probe',
      role: 'user',
      isEmergencyMode: false,
      biometricEnabled: false,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    await User2.collection.insertMany([probe]);
    await ScamScan.collection.insertMany([
      {
        userId: probe._id,
        inputType: 'IMAGE',
        imageUrl: 'https://res.cloudinary.test/throwing.png',
        cloudinaryPublicId: 'guardfi/throwing-probe',
        imageStorage: 'CLOUDINARY',
        isScam: false,
        riskLevel: 'SAFE',
        confidenceScore: 10,
        explanation_en: 'Probe.',
        explanation_hi: 'प्रोब।',
        redFlags: [],
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ]);

    const result = await deleteAccount({
      userId: String(probe._id),
      phone: probe.phone,
      deps: {
        destroyImages: async () => {
          throw new Error('cloudinary is down');
        },
      },
    });

    assert.equal(result.cloudinary.failed, 1);
    assert.equal(result.cloudinary.results[0].reason, 'DESTROY_FAILED');
    assert.equal(result.deleted.user, 1);
    assert.equal(result.deleted.scamScans, 1);
    assert.equal(await User2.countDocuments({ _id: probe._id }), 0);
    seeded.throwingProbe = { objectId: probe._id, phone: probe.phone };
  });

  await record('scanner: an uploaded screenshot persists its cloudinaryPublicId', async () => {
    const { analyzeScan } = require('../services/scamBusterService');
    const probeUser = new mongoose.Types.ObjectId();

    const recordRow = await analyzeScan({
      userId: probeUser,
      file: { buffer: Buffer.from('fake-image-bytes'), mimetype: 'image/png', originalname: 'x.png' },
      deps: {
        store: async () => ({
          imageUrl: 'https://res.cloudinary.test/stored.png',
          cloudinaryPublicId: 'guardfi/wiring-probe',
          storage: 'CLOUDINARY',
        }),
        analyze: async () => ({
          isScam: false,
          riskLevel: 'SAFE',
          confidenceScore: 40,
          explanation_en: 'Looks fine.',
          explanation_hi: 'ठीक लगता है।',
          redFlags: [],
          extractedText: '',
        }),
      },
    });

    assert.equal(recordRow.cloudinaryPublicId, 'guardfi/wiring-probe');
    assert.equal(recordRow.imageUrl, 'https://res.cloudinary.test/stored.png');

    const stored = await ScamScan.findById(recordRow._id).lean();
    assert.equal(stored.cloudinaryPublicId, 'guardfi/wiring-probe');

    seeded.wiringScan = { userId: probeUser };
  });

  await record('model: cloudinaryPublicId defaults to null and is bounded', async () => {
    const textScan = await ScamScan.create({
      userId: seeded.wiringScan.userId,
      inputType: 'TEXT',
      extractedText: 'hello',
      isScam: false,
      riskLevel: 'SAFE',
      confidenceScore: 5,
      explanation_en: 'Text.',
      explanation_hi: 'टेक्स्ट।',
    });

    assert.equal(textScan.cloudinaryPublicId, null);

    await assert.rejects(
      () =>
        ScamScan.create({
          userId: seeded.wiringScan.userId,
          inputType: 'IMAGE',
          cloudinaryPublicId: 'x'.repeat(600),
          isScam: false,
          riskLevel: 'SAFE',
          confidenceScore: 5,
          explanation_en: 'Too long.',
          explanation_hi: 'बहुत लंबा।',
        }),
      (error) => error.name === 'ValidationError'
    );
  });
}

// ===========================================================================
// Cleanup
// ===========================================================================
async function cleanupProbeData() {
  const User = require('../models/User');
  const Nominee = require('../models/Nominee');
  const SosAlert = require('../models/SosAlert');
  const ScamScan = require('../models/ScamScan');
  const TransactionAudit = require('../models/TransactionAudit');
  const Otp = require('../models/Otp');
  const SendThrottle = require('../models/SendThrottle');
  const AuditLog = require('../models/AuditLog');

  const ids = [seeded.victim.objectId, seeded.bystander.objectId, seeded.serviceProbe.objectId];
  if (seeded.throwingProbe) ids.push(seeded.throwingProbe.objectId);
  if (seeded.wiringScan) ids.push(seeded.wiringScan.userId);

  const phones = [seeded.victim.phone, seeded.bystander.phone, seeded.serviceProbe.phone];
  if (seeded.throwingProbe) phones.push(seeded.throwingProbe.phone);

  await Promise.all([
    Nominee.collection.deleteMany({ userId: { $in: ids } }),
    SosAlert.collection.deleteMany({ userId: { $in: ids } }),
    ScamScan.collection.deleteMany({ userId: { $in: ids } }),
    TransactionAudit.collection.deleteMany({ userId: { $in: ids } }),
    Otp.collection.deleteMany({ phone: { $in: phones } }),
    SendThrottle.collection.deleteMany({ phone: { $in: phones } }),
    AuditLog.collection.deleteMany({ userId: { $in: ids } }),
  ]);

  const users = await User.collection.deleteMany({ _id: { $in: ids } });

  return {
    users: users.deletedCount || 0,
    remainingUsers: await User.collection.countDocuments({ _id: { $in: ids } }),
    remainingAudits: await AuditLog.collection.countDocuments({ userId: { $in: ids } }),
    remainingScans: await ScamScan.collection.countDocuments({ userId: { $in: ids } }),
    remainingAlerts: await SosAlert.collection.countDocuments({ userId: { $in: ids } }),
    remainingNominees: await Nominee.collection.countDocuments({ userId: { $in: ids } }),
    remainingTransactions: await TransactionAudit.collection.countDocuments({ userId: { $in: ids } }),
  };
}

// ===========================================================================
async function main() {
  let MongoMemoryServer;

  try {
    ({ MongoMemoryServer } = require('mongodb-memory-server'));
  } catch {
    console.error('✖ mongodb-memory-server is not installed. Run: npm install');
    process.exit(2);
  }

  console.log('▶ Starting throwaway in-memory MongoDB...');
  mongo = await MongoMemoryServer.create({
    instance: { dbName: 'guardfi-account-deletion', launchTimeout: 90_000 },
  });

  process.env.MONGO_URI = mongo.getUri('guardfi-account-deletion');

  const { connectDatabase } = require('../config/db');
  await connectDatabase();

  try {
    console.log('▶ Seeding a victim, a bystander and a service probe with full data...');
    await seedDataset();

    console.log(`▶ Booting the server on ${PORT} (Cloudinary deliberately unconfigured)...`);
    spawnServer();
    await waitForHealth();

    console.log('▶ Running the account-deletion checks...\n');
    await runHttpChecks();
  } catch (error) {
    // Print immediately as well as recording it: a setup failure must say what
    // broke instead of surfacing later as an unrelated "undefined" crash.
    console.error(`✖ Setup failed: ${error.stack || error.message}`);
    results.push({ name: 'harness: setup and server health', ok: false, error: error.message });
  } finally {
    await stopServers();
  }

  if (seeded.victimSocket) seeded.victimSocket.close();

  if (seeded.victim && seeded.bystander && seeded.serviceProbe) {
    await runServiceChecks();
  } else {
    results.push({ name: 'service checks: probe data was seeded', ok: false, error: 'the dataset was not seeded' });
  }

  await record('cleanup: every probe document is removed', async () => {
    const report = await cleanupProbeData();

    // Ninety-percent of the probe users are already gone (the cascade deleted
    // them); only the bystander is left for teardown to remove.
    assert.ok(report.users >= 1, `expected the bystander probe user, removed ${report.users}`);
    for (const [key, value] of Object.entries(report)) {
      if (key === 'users') continue;
      assert.equal(value, 0, `${key} left probe data behind`);
    }
  });

  const passed = results.filter((result) => result.ok).length;
  const failed = results.filter((result) => !result.ok);

  console.log('');
  for (const result of results) {
    console.log(`${result.ok ? '  PASS' : '  FAIL'}  ${result.name}${result.ok ? '' : `\n          ↳ ${result.error}`}`);
  }
  console.log(`\n${passed}/${results.length} checks passed.`);

  if (mongo) await mongo.stop();

  process.exit(failed.length === 0 ? 0 : 1);
}

main().catch(async (error) => {
  console.error('✖ Harness crashed:', error);
  await stopServers();
  if (mongo) await mongo.stop().catch(() => {});
  process.exit(1);
});
