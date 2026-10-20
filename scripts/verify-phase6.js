'use strict';

/**
 * GuardFi — Phase 6 verification harness (Shield Pay)
 *
 * Proves the fraud engine end to end against a real Express server, a real
 * Mongoose layer and a throwaway MongoDB: normalisation, blocklist lookups,
 * heuristic scoring, the stateful "Proceed Anyway" gate, PIN handling and the
 * audit trail.
 *
 * The things this suite exists to catch (each one has burned a real product):
 *   • a scammer defeating the blocklist with capital letters, an extra space or
 *     a pasted `upi://pay?pa=…` payload;
 *   • heuristics producing a "Fraud Alert" on their own (false positives are how
 *     users learn to tap through warnings);
 *   • a warning that can be replayed, borrowed from another account, moved to a
 *     different payee, or used after it expired;
 *   • a wrong PIN that is accepted, or a payment that records nothing;
 *   • a PIN or its hash ever appearing in a response body;
 *   • a lookup that silently became a collection scan.
 *
 * Run:  npm run verify:phase6
 * Exit: 0 = every check passed, 1 = at least one failed, 2 = harness cannot run.
 */

process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = process.env.VERIFY_LOG_LEVEL || 'error';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'verify-phase6-secret-'.padEnd(48, '0');
process.env.CORS_ORIGINS = '*';
process.env.STRICT_ENV = 'false';
process.env.TRUST_PROXY = 'false';
delete process.env.PORT;

process.env.MONGO_URI = 'mongodb://127.0.0.1:27017/guardfi-phase6-placeholder';
process.env.OTP_DEV_MODE = 'true';
process.env.SMS_PROVIDER = 'none';
process.env.SHIELD_PAY_SUSPICIOUS_THRESHOLD = '30';
process.env.SHIELD_PAY_DANGER_THRESHOLD = '70';
process.env.SHIELD_PAY_RISK_CHECK_TTL_SECONDS = '900';
process.env.SHIELD_PAY_MAX_AMOUNT = '200000';

const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const SERVER_PORT = Number(process.env.VERIFY_SHIELD_PAY_PORT || 4341);
const BASE = `http://127.0.0.1:${SERVER_PORT}`;

const PIN = '4821';
const OTHER_PIN = '7391';
const NEW_PIN = '6842';

let mongo = null;
let server = null;
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
  const init = { method, headers: {} };
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

function expectSuccess(response, status) {
  assert.equal(response.status, status, `expected ${status}, got ${response.status}: ${response.text}`);
  assert.equal(response.body?.success, true);
}

function expectErrorCode(response, status, code) {
  assert.equal(response.status, status, `expected ${status}, got ${response.status}: ${response.text}`);
  assert.equal(response.body?.success, false);
  const haystack = `${response.body?.code || ''} ${JSON.stringify(response.body?.errors || [])}`;
  assert.ok(haystack.includes(code), `expected code ${code} in ${response.text}`);
}

async function waitForHealth(timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no response';

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE}/health`);
      const body = await response.json();
      if (
        response.status === 200 &&
        body?.data?.database?.connected === true &&
        body?.data?.database?.indexesReady === true
      ) {
        return body;
      }
      last = `status=${response.status} db=${body?.data?.database?.state}`;
    } catch (error) {
      last = error.message;
    }
    await sleep(400);
  }

  throw new Error(`server never became healthy within ${timeoutMs}ms (last: ${last})`);
}

function spawnServer(uri) {
  const child = spawn(process.execPath, [path.join(PROJECT_ROOT, 'server.js')], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      LOG_LEVEL: 'error',
      PORT: String(SERVER_PORT),
      MONGO_URI: uri,
      RATE_LIMIT_SKIP_IN_TEST: 'true',
      FIREBASE_PROJECT_ID: '',
      FIREBASE_CLIENT_EMAIL: '',
      FIREBASE_PRIVATE_KEY: '',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const entry = { label: 'shield pay server', child, output: [] };
  child.stdout.on('data', (chunk) => entry.output.push(chunk.toString()));
  child.stderr.on('data', (chunk) => entry.output.push(chunk.toString()));
  server = entry;

  return entry;
}

async function stopServer() {
  if (server && server.child.exitCode === null) {
    server.child.kill();
    await sleep(300);
  }

  if (results.some((result) => !result.ok) && server && server.output.length > 0) {
    console.error('\n--- server output ---');
    console.error(server.output.join('').split('\n').slice(-25).join('\n'));
  }
}

// ===========================================================================
// Deterministic dataset
// ===========================================================================
async function seedDataset() {
  const User = require('../models/User');
  const FlaggedEntity = require('../models/FlaggedEntity');
  const TransactionAudit = require('../models/TransactionAudit');
  const { signAccessToken } = require('../services/tokenService');
  const { FLAGGED_ENTITIES } = require('./seedFlaggedUpi');

  await FlaggedEntity.init();
  await TransactionAudit.init();

  const now = new Date();
  const id = () => new mongoose.Types.ObjectId();

  const pinUser = {
    _id: id(),
    phone: '+919876540001',
    name: 'PIN User',
    role: 'user',
    securityPinHash: await bcrypt.hash(PIN, 8),
    createdAt: now,
    updatedAt: now,
  };

  const otherPinUser = {
    _id: id(),
    phone: '+919876540003',
    name: 'Other PIN User',
    role: 'user',
    securityPinHash: await bcrypt.hash(OTHER_PIN, 8),
    createdAt: now,
    updatedAt: now,
  };

  const noPinUser = {
    _id: id(),
    phone: '+919876540002',
    name: 'PIN Fresh User',
    role: 'user',
    securityPinHash: null,
    createdAt: now,
    updatedAt: now,
  };

  // Never gets a PIN: proves the "set one first" path stays reachable even after
  // other accounts have configured theirs.
  const pinlessUser = {
    _id: id(),
    phone: '+919876540004',
    name: 'No PIN User',
    role: 'user',
    securityPinHash: null,
    createdAt: now,
    updatedAt: now,
  };

  await User.collection.insertMany([pinUser, otherPinUser, noPinUser, pinlessUser]);

  // The real demo dataset, so the harness also proves the seed file itself is
  // coherent — clones, because insertMany stamps _id onto the documents.
  await FlaggedEntity.insertMany(FLAGGED_ENTITIES.map((entry) => ({ ...entry })));

  seeded.pinUser = { id: String(pinUser._id), token: signAccessToken(pinUser).token };
  seeded.otherPinUser = { id: String(otherPinUser._id), token: signAccessToken(otherPinUser).token };
  seeded.noPinUser = { id: String(noPinUser._id), token: signAccessToken(noPinUser).token };
  seeded.pinlessUser = { id: String(pinlessUser._id), token: signAccessToken(pinlessUser).token };
}

// ===========================================================================
// HTTP checks
// ===========================================================================
const DANGER_UPI = 'paytm-kyc-help@ybl';
const DANGER_UPI_TWO = 'sbi.kyc.update@ybl';
const SAFE_UPI = 'guardfi.demo@okhdfcbank';
const DANGER_URL = 'secure-paytm-kyc.verify-login.xyz';
const DANGER_PHONE = '+919812345678';

async function runHttpChecks() {
  const { pinUser, otherPinUser, noPinUser, pinlessUser } = seeded;

  await record('auth: every Shield Pay endpoint refuses an anonymous caller', async () => {
    for (const pathname of ['/api/v1/shield-pay/check-upi', '/api/v1/shield-pay/proceed-transaction', '/api/v1/shield-pay/set-pin']) {
      const response = await call(pathname, { method: 'POST', body: {} });
      assert.equal(response.status, 401, `${pathname} should be 401`);
      assert.equal(response.body?.success, false);
    }
  });

  await record('validation: malformed bodies are rejected before any database work', async () => {
    const cases = [
      ['/api/v1/shield-pay/check-upi', {}],
      ['/api/v1/shield-pay/check-upi', { identifier: 42 }],
      ['/api/v1/shield-pay/check-upi', { identifier: 'x'.repeat(201) }],
      ['/api/v1/shield-pay/check-upi', { identifier: 'not-an-identifier' }],
      ['/api/v1/shield-pay/proceed-transaction', { identifier: SAFE_UPI, pin: PIN }],
      ['/api/v1/shield-pay/proceed-transaction', { identifier: SAFE_UPI, amount: 0, pin: PIN }],
      ['/api/v1/shield-pay/proceed-transaction', { identifier: SAFE_UPI, amount: -5, pin: PIN }],
      ['/api/v1/shield-pay/proceed-transaction', { identifier: SAFE_UPI, amount: 200001, pin: PIN }],
      ['/api/v1/shield-pay/proceed-transaction', { identifier: SAFE_UPI, amount: 100, pin: '12' }],
      ['/api/v1/shield-pay/proceed-transaction', { identifier: SAFE_UPI, amount: 100, pin: 4821 }],
      ['/api/v1/shield-pay/proceed-transaction', { identifier: SAFE_UPI, amount: 100, pin: PIN, checkId: 'nope' }],
      ['/api/v1/shield-pay/set-pin', { pin: 'ab12' }],
    ];

    for (const [pathname, body] of cases) {
      const response = await call(pathname, { method: 'POST', token: pinUser.token, body });
      assert.equal(response.status, 400, `${pathname} ${JSON.stringify(body)} should be 400, got ${response.status}: ${response.text}`);
    }
  });

  await record('check-upi: a reported UPI returns the exact bilingual danger envelope', async () => {
    const response = await call('/api/v1/shield-pay/check-upi', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: DANGER_UPI },
    });

    expectSuccess(response, 200);
    const data = response.body.data;

    assert.equal(data.status, 'danger');
    assert.equal(data.riskLevel, 'DANGER');
    assert.equal(data.riskScore, 92, JSON.stringify(data));
    assert.equal(data.reportCount, 176);
    assert.equal(data.matchedBy, 'flagged_entity');
    assert.equal(data.msg_en, 'Fraud Alert: This UPI ID is linked to reported phishing scams.');
    assert.match(data.msg_hi, /फ्रॉड अलर्ट/);
    assert.match(data.msg_hi, /[\u0900-\u097F]/);
    assert.match(data.checkId, /^[0-9a-f]{24}$/);
    assert.ok(new Date(data.checkExpiresAt).getTime() > Date.now());
  });

  await record('check-upi: case, whitespace and a upi:// QR payload all normalise to the same entity', async () => {
    const variants = ['  PAYTM-KYC-HELP@YBL  ', 'upi://pay?pa=paytm-kyc-help%40ybl&pn=Paytm%20KYC&am=4999'];

    for (const identifier of variants) {
      const response = await call('/api/v1/shield-pay/check-upi', {
        method: 'POST',
        token: pinUser.token,
        body: { identifier },
      });

      expectSuccess(response, 200);
      assert.equal(response.body.data.identifier, DANGER_UPI, `${identifier} did not normalise`);
      assert.equal(response.body.data.riskScore, 92, `${identifier} scored differently`);
    }
  });

  await record('check-upi: a link with a path still matches its curated host', async () => {
    const response = await call('/api/v1/shield-pay/check-upi', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: `https://${DANGER_URL}/kyc?step=2&ref=9281` },
    });

    expectSuccess(response, 200);
    assert.equal(response.body.data.status, 'danger');
    assert.equal(response.body.data.riskScore, 95); // 211 reports, capped
    assert.equal(response.body.data.matchedIdentifier, DANGER_URL);
  });

  await record('check-upi: a verified-safe handle is safe and opens no risk check', async () => {
    const response = await call('/api/v1/shield-pay/check-upi', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: SAFE_UPI },
    });

    expectSuccess(response, 200);
    assert.equal(response.body.data.status, 'safe');
    assert.equal(response.body.data.riskScore, 0);
    assert.equal(response.body.data.matchedBy, 'flagged_entity');
    assert.equal(response.body.data.checkId, null);
    assert.equal(response.body.data.msg_en.includes('Fraud Alert'), false);
  });

  await record('check-upi: an unknown but clean UPI is safe with an explicit "unknown" signal', async () => {
    const response = await call('/api/v1/shield-pay/check-upi', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: 'new.neighbour@okhdfcbank' },
    });

    expectSuccess(response, 200);
    const data = response.body.data;

    assert.equal(data.status, 'safe');
    assert.equal(data.riskScore, 10);
    assert.equal(data.matchedBy, 'heuristics');
    assert.equal(data.checkId, null);
    assert.ok(data.flags.some((entry) => entry.code === 'UNKNOWN_IDENTIFIER'));
  });

  await record('check-upi: scam wording raises a caution without condemning', async () => {
    const response = await call('/api/v1/shield-pay/check-upi', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: 'kyc-refund-help@unknownpsp' },
    });

    expectSuccess(response, 200);
    const data = response.body.data;

    assert.equal(data.status, 'suspicious');
    assert.equal(data.reasonCode, 'SCAM_KEYWORDS');
    assert.ok(data.flags.some((entry) => entry.code === 'SCAM_KEYWORDS'));
    assert.ok(data.msg_en.startsWith('Caution: '), data.msg_en);
    assert.ok(data.checkId, 'a suspicious verdict must open a risk check');
  });

  await record('check-upi: a look-alike provider handle is flagged as suspicious', async () => {
    const response = await call('/api/v1/shield-pay/check-upi', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: 'ramesh@ybi' },
    });

    expectSuccess(response, 200);
    const data = response.body.data;

    assert.equal(data.status, 'suspicious');
    assert.equal(data.riskScore, 40); // 10 base + 30 look-alike
    assert.equal(data.reasonCode, 'LOOKALIKE_UPI_HANDLE');
  });

  await record('check-upi: a plain phone-number username is a signal, not a verdict', async () => {
    const response = await call('/api/v1/shield-pay/check-upi', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: '9876543210@ybl' },
    });

    expectSuccess(response, 200);
    const data = response.body.data;

    assert.equal(data.status, 'safe');
    assert.equal(data.riskScore, 20); // 10 base + 10 numeric name
    assert.ok(data.flags.some((entry) => entry.code === 'NUMERIC_UPI_NAME'));
  });

  await record('check-upi: heuristics are capped below DANGER even when everything fires', async () => {
    const response = await call('/api/v1/shield-pay/check-upi', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: 'kyc.refund.9876543210@ybi' },
    });

    expectSuccess(response, 200);
    const data = response.body.data;

    assert.equal(data.riskScore, 69, 'the heuristic cap must clamp the sum');
    assert.equal(data.status, 'suspicious');
    assert.equal(data.riskLevel, 'SUSPICIOUS');
  });

  await record('check-upi: a phishing-shaped link stacks raw IP, keywords and HTTP', async () => {
    const response = await call('/api/v1/shield-pay/check-upi', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: 'http://192.168.1.77/login-kyc' },
    });

    expectSuccess(response, 200);
    const data = response.body.data;

    assert.equal(data.status, 'suspicious');
    assert.equal(data.riskScore, 69);
    for (const code of ['RAW_IP_HOST', 'SUSPICIOUS_URL_WORDS', 'INSECURE_HTTP']) {
      assert.ok(data.flags.some((entry) => entry.code === code), `${code} missing`);
    }
  });

  await record('check-upi: a risky TLD alone is a low-confidence caution', async () => {
    const response = await call('/api/v1/shield-pay/check-upi', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: 'https://shop-deals.cyou' },
    });

    expectSuccess(response, 200);
    const data = response.body.data;

    assert.equal(data.status, 'suspicious');
    assert.equal(data.riskScore, 35); // 10 base + 25 risky TLD
  });

  await record('check-upi: a reported phone number is dangerous, an unknown one is only unknown', async () => {
    const flagged = await call('/api/v1/shield-pay/check-upi', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: DANGER_PHONE },
    });

    expectSuccess(flagged, 200);
    assert.equal(flagged.body.data.status, 'danger');
    assert.equal(flagged.body.data.riskLevel, 'DANGER');
    assert.equal(flagged.body.data.riskScore, 75); // 70 + floor(44 / 8)

    const unknown = await call('/api/v1/shield-pay/check-upi', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: '+91 90000 00123' },
    });

    expectSuccess(unknown, 200);
    assert.equal(unknown.body.data.identifierType, 'PHONE');
    assert.equal(unknown.body.data.status, 'safe');
    assert.equal(unknown.body.data.riskScore, 10);
    assert.ok(unknown.body.data.flags.some((entry) => entry.code === 'UNKNOWN_PHONE'));
  });

  await record('check-upi: a safe verdict writes no audit state at all', async () => {
    const TransactionAudit = require('../models/TransactionAudit');
    const before = await TransactionAudit.countDocuments({ userId: pinUser.id, status: 'PENDING' });

    await call('/api/v1/shield-pay/check-upi', { method: 'POST', token: pinUser.token, body: { identifier: 'shopkeeper@oksbi' } });

    const after = await TransactionAudit.countDocuments({ userId: pinUser.id, status: 'PENDING' });
    assert.equal(after, before, 'a safe check must not create pending state');
  });

  await record('proceed: a safe payment settles, is audited and carries no warning', async () => {
    const response = await call('/api/v1/shield-pay/proceed-transaction', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: SAFE_UPI, amount: 249.5, pin: PIN },
    });

    expectSuccess(response, 201);
    const receipt = response.body.data;

    assert.equal(receipt.status, 'completed');
    assert.equal(receipt.riskLevel, 'SAFE');
    assert.equal(receipt.risk_accepted, false);
    assert.equal(receipt.pinVerified, true);
    assert.equal(receipt.amount, 249.5);
    assert.match(receipt.transactionHash, /^[0-9a-f]{64}$/);
    assert.equal(receipt.msg_en.includes('accepted'), false);

    const TransactionAudit = require('../models/TransactionAudit');
    const row = await TransactionAudit.findById(receipt.auditId).lean();
    assert.equal(row.status, 'COMPLETED');
    assert.equal(row.pinVerified, true);
    assert.equal(row.risk_accepted, false);
    assert.equal(String(row.userId), pinUser.id);
  });

  let dangerCheckId = null;

  await record('proceed: a flagged payee cannot be paid without acknowledging the warning', async () => {
    const check = await call('/api/v1/shield-pay/check-upi', { method: 'POST', token: pinUser.token, body: { identifier: DANGER_UPI } });
    dangerCheckId = check.body?.data?.checkId;

    const response = await call('/api/v1/shield-pay/proceed-transaction', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: DANGER_UPI, amount: 4999, pin: PIN },
    });

    expectErrorCode(response, 409, 'RISK_ACKNOWLEDGEMENT_REQUIRED');
    const error = response.body.errors[0];
    assert.equal(error.msg_en, 'Fraud Alert: This UPI ID is linked to reported phishing scams.');
    assert.match(error.msg_hi, /फ्रॉड अलर्ट/);

    const TransactionAudit = require('../models/TransactionAudit');
    const completed = await TransactionAudit.countDocuments({ userId: pinUser.id, upiId: DANGER_UPI, status: 'COMPLETED' });
    assert.equal(completed, 0, 'a refused payment must not leave a completed row');
  });

  await record('proceed: accepting the warning without a check id is refused', async () => {
    const response = await call('/api/v1/shield-pay/proceed-transaction', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: DANGER_UPI, amount: 4999, pin: PIN, riskAccepted: true },
    });

    expectErrorCode(response, 409, 'RISK_CHECK_REQUIRED');
  });

  await record('proceed: a wrong PIN is refused, recorded, and does not consume the check', async () => {
    const response = await call('/api/v1/shield-pay/proceed-transaction', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: DANGER_UPI, amount: 4999, pin: '9999', riskAccepted: true, checkId: dangerCheckId },
    });

    expectErrorCode(response, 401, 'INVALID_PIN');
    assert.match(response.body.errors[0].msg_hi, /[\u0900-\u097F]/);

    const TransactionAudit = require('../models/TransactionAudit');
    const rejected = await TransactionAudit.findOne({ userId: pinUser.id, status: 'REJECTED' }).lean();
    assert.ok(rejected, 'the failed PIN attempt must be audited');
    assert.equal(rejected.failureReason, 'INVALID_PIN');
    assert.equal(rejected.pinVerified, false);

    const pending = await TransactionAudit.findById(dangerCheckId).lean();
    assert.equal(pending.status, 'PENDING', 'a failed PIN must not burn the risk check');
  });

  await record('proceed: "Proceed Anyway" completes the audited transaction', async () => {
    const response = await call('/api/v1/shield-pay/proceed-transaction', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: DANGER_UPI, amount: 4999.999, pin: PIN, riskAccepted: true, checkId: dangerCheckId },
    });

    expectSuccess(response, 201);
    const receipt = response.body.data;

    assert.equal(receipt.status, 'completed');
    assert.equal(receipt.riskLevel, 'DANGER');
    assert.equal(receipt.risk_accepted, true);
    assert.equal(receipt.pinVerified, true);
    assert.equal(receipt.amount, 5000, 'amounts round to paise');
    assert.match(receipt.transactionHash, /^[0-9a-f]{64}$/);
    assert.ok(receipt.msg_en.includes('accepted'), receipt.msg_en);

    const TransactionAudit = require('../models/TransactionAudit');
    const row = await TransactionAudit.findById(receipt.auditId).lean();
    assert.equal(row.status, 'COMPLETED');
    assert.equal(row.expiresAt, null, 'a completed row must leave the TTL index');
    assert.equal(row.transactionHash, receipt.transactionHash);
    assert.equal(row.amount, 5000);
  });

  await record('proceed: a risk check is single-use', async () => {
    const response = await call('/api/v1/shield-pay/proceed-transaction', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: DANGER_UPI, amount: 4999, pin: PIN, riskAccepted: true, checkId: dangerCheckId },
    });

    expectErrorCode(response, 409, 'RISK_CHECK_ALREADY_USED');

    const TransactionAudit = require('../models/TransactionAudit');
    const completed = await TransactionAudit.countDocuments({ userId: pinUser.id, upiId: DANGER_UPI, status: 'COMPLETED' });
    assert.equal(completed, 1, 'replay must not create a second transaction');
  });

  await record('proceed: another account cannot borrow a risk check', async () => {
    const check = await call('/api/v1/shield-pay/check-upi', { method: 'POST', token: pinUser.token, body: { identifier: DANGER_UPI } });
    const foreignCheckId = check.body.data.checkId;

    const response = await call('/api/v1/shield-pay/proceed-transaction', {
      method: 'POST',
      token: otherPinUser.token,
      body: { identifier: DANGER_UPI, amount: 100, pin: OTHER_PIN, riskAccepted: true, checkId: foreignCheckId },
    });

    expectErrorCode(response, 409, 'RISK_CHECK_INVALID');

    const TransactionAudit = require('../models/TransactionAudit');
    const stillPending = await TransactionAudit.findById(foreignCheckId).lean();
    assert.equal(stillPending.status, 'PENDING', 'the owner\'s check must survive an outsider\'s attempt');
  });

  await record('proceed: a risk check cannot be moved to a different payee', async () => {
    const check = await call('/api/v1/shield-pay/check-upi', { method: 'POST', token: pinUser.token, body: { identifier: DANGER_UPI } });
    const checkId = check.body.data.checkId;

    const response = await call('/api/v1/shield-pay/proceed-transaction', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: DANGER_UPI_TWO, amount: 100, pin: PIN, riskAccepted: true, checkId },
    });

    expectErrorCode(response, 409, 'RISK_CHECK_MISMATCH');

    const TransactionAudit = require('../models/TransactionAudit');
    const row = await TransactionAudit.findById(checkId).lean();
    assert.equal(row.status, 'PENDING');
  });

  await record('proceed: an expired risk check is refused even though the row still exists', async () => {
    const check = await call('/api/v1/shield-pay/check-upi', { method: 'POST', token: pinUser.token, body: { identifier: DANGER_UPI } });
    const checkId = check.body.data.checkId;

    const TransactionAudit = require('../models/TransactionAudit');
    await TransactionAudit.collection.updateOne(
      { _id: new mongoose.Types.ObjectId(checkId) },
      { $set: { expiresAt: new Date(Date.now() - 1_000) } }
    );

    const response = await call('/api/v1/shield-pay/proceed-transaction', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: DANGER_UPI, amount: 100, pin: PIN, riskAccepted: true, checkId },
    });

    expectErrorCode(response, 409, 'RISK_CHECK_EXPIRED');
  });

  await record('proceed: concurrent taps of one check produce exactly one transaction', async () => {
    const check = await call('/api/v1/shield-pay/check-upi', { method: 'POST', token: pinUser.token, body: { identifier: DANGER_UPI } });
    const checkId = check.body.data.checkId;

    const body = { identifier: DANGER_UPI, amount: 777, pin: PIN, riskAccepted: true, checkId };
    const [first, second] = await Promise.all([
      call('/api/v1/shield-pay/proceed-transaction', { method: 'POST', token: pinUser.token, body }),
      call('/api/v1/shield-pay/proceed-transaction', { method: 'POST', token: pinUser.token, body }),
    ]);

    const statuses = [first.status, second.status].sort();
    assert.deepEqual(statuses, [201, 409], `expected one win and one conflict, got ${first.status}/${second.status}`);

    const TransactionAudit = require('../models/TransactionAudit');
    const completed = await TransactionAudit.countDocuments({ userId: pinUser.id, upiId: DANGER_UPI, status: 'COMPLETED' });
    // The earlier "Proceed Anyway" plus exactly one of these two taps.
    assert.equal(completed, 2, 'two concurrent taps must settle one transaction, not two');
  });

  await record('proceed: a PIN change is gated on the current PIN', async () => {
    const withoutCurrent = await call('/api/v1/shield-pay/set-pin', {
      method: 'POST',
      token: noPinUser.token,
      body: { pin: NEW_PIN },
    });
    expectSuccess(withoutCurrent, 200);
    assert.equal(withoutCurrent.body.data.pinConfigured, true);
    assert.equal(withoutCurrent.text.includes(NEW_PIN), false, 'the PIN must never be echoed');

    const wrongCurrent = await call('/api/v1/shield-pay/set-pin', {
      method: 'POST',
      token: noPinUser.token,
      body: { pin: '9173', currentPin: '0000' },
    });
    expectErrorCode(wrongCurrent, 401, 'INVALID_CURRENT_PIN');

    const missingCurrent = await call('/api/v1/shield-pay/set-pin', {
      method: 'POST',
      token: noPinUser.token,
      body: { pin: '9173' },
    });
    expectErrorCode(missingCurrent, 401, 'CURRENT_PIN_REQUIRED');

    const changed = await call('/api/v1/shield-pay/set-pin', {
      method: 'POST',
      token: noPinUser.token,
      body: { pin: '9173', currentPin: NEW_PIN },
    });
    expectSuccess(changed, 200);

    const User = require('../models/User');
    const stored = await User.findById(noPinUser.id).select('+securityPinHash').lean();
    assert.notEqual(stored.securityPinHash, '9173');
    assert.match(stored.securityPinHash, /^\$2[aby]\$/);
    assert.equal(await bcrypt.compare('9173', stored.securityPinHash), true);
    assert.equal(await bcrypt.compare(NEW_PIN, stored.securityPinHash), false);
  });

  await record('set-pin: guessable PINs are refused with a reason', async () => {
    for (const [pin, hint] of [
      ['1234', 'sequence'],
      ['4321', 'descending'],
      ['1111', 'repeated'],
      ['2580', 'common'],
      ['0002', 'phone'],
    ]) {
      const response = await call('/api/v1/shield-pay/set-pin', {
        method: 'POST',
        token: noPinUser.token,
        body: { pin, currentPin: '9173' },
      });
      assert.equal(response.status, 400, `${pin} (${hint}) should be refused, got ${response.status}: ${response.text}`);
      assert.ok(JSON.stringify(response.body.errors).includes('WEAK_PIN'));
    }
  });

  await record('proceed: an account with no PIN is told exactly what to do', async () => {
    const response = await call('/api/v1/shield-pay/proceed-transaction', {
      method: 'POST',
      token: pinlessUser.token,
      body: { identifier: SAFE_UPI, amount: 10, pin: '9173' },
    });

    expectErrorCode(response, 409, 'SHIELD_PAY_PIN_NOT_SET');
  });

  await record('privacy: no response ever carries a PIN or its hash', async () => {
    const responses = [
      await call('/api/v1/shield-pay/check-upi', { method: 'POST', token: pinUser.token, body: { identifier: DANGER_UPI } }),
      await call('/api/v1/shield-pay/proceed-transaction', {
        method: 'POST',
        token: pinUser.token,
        body: { identifier: SAFE_UPI, amount: 42, pin: PIN },
      }),
      await call('/api/v1/shield-pay/set-pin', { method: 'POST', token: pinUser.token, body: { pin: '6354', currentPin: PIN } }),
    ];

    for (const response of responses) {
      assert.equal(response.text.includes('securityPinHash'), false);
      assert.equal(response.text.includes('$2a$'), false);
      assert.equal(response.text.includes('"pin"'), false);
      assert.equal(response.body?.data?.pin, undefined);
    }
  });

  await record('proceed: after a PIN change the old PIN stops working', async () => {
    const oldPin = await call('/api/v1/shield-pay/proceed-transaction', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: SAFE_UPI, amount: 20, pin: PIN },
    });
    assert.equal(oldPin.status, 401, 'the replaced PIN must be dead');

    const newPin = await call('/api/v1/shield-pay/proceed-transaction', {
      method: 'POST',
      token: pinUser.token,
      body: { identifier: SAFE_UPI, amount: 20, pin: '6354' },
    });
    expectSuccess(newPin, 201);
  });
}

// ===========================================================================
// Index + explain + unit checks (in-process)
// ===========================================================================
async function runIndexChecks() {
  const FlaggedEntity = require('../models/FlaggedEntity');
  const TransactionAudit = require('../models/TransactionAudit');

  await FlaggedEntity.init();
  await TransactionAudit.init();

  await record('indexes: the identifier lookup is a unique B-tree index', async () => {
    const indexes = await FlaggedEntity.collection.indexes();
    const identifierIndex = indexes.find((index) => index.key.identifier === 1);

    assert.ok(identifierIndex, 'flaggedentities.identifier is not indexed');
    assert.equal(identifierIndex.unique, true, 'the identifier index must be unique');
  });

  await record('indexes: the audit trail carries its own history, hash and TTL indexes', async () => {
    const indexes = await TransactionAudit.collection.indexes();

    assert.ok(
      indexes.some((index) => index.key.userId === 1 && index.key.createdAt === -1),
      'transactionaudits user history index missing'
    );

    const hashIndex = indexes.find((index) => index.key.transactionHash === 1);
    assert.ok(hashIndex, 'transactionHash is not indexed');
    assert.equal(hashIndex.unique, true);
    assert.ok(hashIndex.partialFilterExpression, 'the hash index must be partial (many rows have no hash)');

    const ttlIndex = indexes.find((index) => index.key.expiresAt === 1);
    assert.ok(ttlIndex, 'the pending-check TTL index is missing');
    assert.equal(ttlIndex.expireAfterSeconds, 0);
    assert.deepEqual(ttlIndex.partialFilterExpression, { status: 'PENDING' }, 'TTL must only cover PENDING rows');
  });

  await record('explain: the blocklist lookup is an IXSCAN, never a collection scan', async () => {
    const plan = await FlaggedEntity.find({ identifier: { $in: ['paytm-kyc-help@ybl', 'paytm-kyc-help@ybl'] } }).explain('executionStats');
    const serialized = JSON.stringify(plan);

    assert.match(serialized, /IXSCAN/);
    assert.match(serialized, /unique_identifier/);
    assert.equal(serialized.includes('COLLSCAN'), false, 'the identifier lookup fell back to a collection scan');
  });

  await record('explain: a URL lookup by two candidates stays indexed', async () => {
    const plan = await FlaggedEntity.find({
      identifier: { $in: ['secure-paytm-kyc.verify-login.xyz/kyc', 'secure-paytm-kyc.verify-login.xyz'] },
    }).explain('executionStats');
    const serialized = JSON.stringify(plan);

    assert.match(serialized, /IXSCAN/);
    assert.equal(serialized.includes('COLLSCAN'), false);
  });

  await record('state: pending rows have a deadline, completed rows do not', async () => {
    const TransactionAudit = require('../models/TransactionAudit');
    const pending = await TransactionAudit.findOne({ status: 'PENDING' }).lean();
    const completed = await TransactionAudit.findOne({ status: 'COMPLETED' }).lean();

    assert.ok(pending, 'expected a pending row from the checks above');
    assert.ok(pending.expiresAt instanceof Date, 'a pending check must carry expiresAt');
    assert.equal(pending.amount, null);
    assert.equal(pending.transactionHash, null);
    assert.equal(pending.risk_accepted, false);

    assert.ok(completed, 'expected a completed row');
    assert.equal(completed.expiresAt, null);
  });
}

async function runUnitChecks() {
  const { normalizeIdentifierInput, weakPinReason, evaluateRisk } = require('../services/shieldPayService');

  await record('unit: phone normalisation accepts every spelling a user might paste', async () => {
    for (const raw of ['+91 98123 45678', '+919812345678', '0091 98123 45678']) {
      const input = normalizeIdentifierInput(raw);
      assert.equal(input.identifierType, 'PHONE', `${raw} should be a phone`);
      assert.equal(input.identifier, '+919812345678', `${raw} normalised wrong`);
    }
  });

  await record('unit: a bad identifier is rejected with a message that names all three shapes', async () => {
    for (const raw of ['', '   ', 'not-an-identifier', 'nope@', '@nope']) {
      assert.throws(() => normalizeIdentifierInput(raw), /UPI ID|identifier/, `${raw} should be rejected`);
    }
  });

  await record('unit: weak-PIN detection is exact', async () => {
    assert.ok(weakPinReason('1234'));
    assert.ok(weakPinReason('9876'));
    assert.ok(weakPinReason('5555'));
    assert.ok(weakPinReason('2580'));
    assert.ok(weakPinReason('0002', '+919876540002'));
    assert.equal(weakPinReason('7391', '+919876540003'), null);
    assert.equal(weakPinReason('6354', '+919876540001'), null);
  });

  await record('unit: the same identifier always produces the same verdict', async () => {
    const input = normalizeIdentifierInput('paytm-kyc-help@ybl');
    const first = await evaluateRisk(input);
    const second = await evaluateRisk(input);

    assert.deepEqual(first, second);
  });
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
    instance: { dbName: 'guardfi-phase6-verify', launchTimeout: 90_000 },
  });

  const uri = mongo.getUri('guardfi-phase6-verify');
  process.env.MONGO_URI = uri;

  const { connectDatabase } = require('../config/db');
  await connectDatabase();

  try {
    console.log('▶ Seeding the flagged-entity dataset and three accounts...');
    try {
      await seedDataset();
    } catch (error) {
      console.error('✖ Dataset seeding failed:', error.message);
      if (mongo) await mongo.stop();
      process.exit(1);
    }

    console.log(`▶ Booting Shield Pay API on port ${SERVER_PORT}...`);
    spawnServer(uri);
    await waitForHealth();
    console.log('▶ Server healthy. Running Shield Pay checks...\n');
    await runHttpChecks();
  } catch (error) {
    results.push({ name: 'harness: server became healthy', ok: false, error: error.message });
  } finally {
    await stopServer();
  }

  await runIndexChecks();
  await runUnitChecks();

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
  await stopServer();
  if (mongo) await mongo.stop().catch(() => {});
  process.exit(1);
});
