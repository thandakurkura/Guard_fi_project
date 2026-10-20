'use strict';

/**
 * GuardFi — Phase 7 verification harness (Scam Buster)
 *
 * Proves the scan pipeline end to end WITHOUT any Gemini or Cloudinary
 * credentials, on purpose: "no key, no bucket, provider down" are exactly the
 * states this phase must survive, and a harness that needs paid keys is a
 * harness nobody runs.
 *
 * Four layers:
 *   1. HTTP on a credential-less server — auth, every validation path, the real
 *      Multer limits (bad MIME, oversize file, wrong field name), and the
 *      HEURISTIC fallback: a scan answers 201 with a usable bilingual verdict
 *      instead of a 503, and a screenshot lands on local disk (imageStorage
 *      LOCAL) instead of failing on the missing Cloudinary config.
 *   2. HTTP on a second server with a 3-request scan budget — proves the AI
 *      quota limiter is enforced (429 on the 4th scan) and stays route-scoped.
 *   3. In-process parser, heuristic, storage, service and model checks with
 *      INJECTED providers — the happy path, persistence, the JSON repair parser,
 *      a timeout/garbage/bug from the provider, and the storage chain
 *      (Cloudinary → local file → capped data URI → none).
 *   4. History: GET /history is the caller's own scans, newest first, cursor
 *      paginated, and cannot be pointed at another user's rows.
 *
 * Cleanup is part of the contract: every screenshot this harness stores, and
 * every probe row it writes, is removed before the process exits.
 *
 * Run:  npm run verify:phase7
 * Exit: 0 = every check passed, 1 = at least one failed, 2 = harness cannot run.
 */

process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = process.env.VERIFY_LOG_LEVEL || 'error';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'verify-phase7-secret-'.padEnd(48, '0');
process.env.CORS_ORIGINS = '*';
process.env.STRICT_ENV = 'false';
process.env.TRUST_PROXY = 'false';
delete process.env.PORT;

// The harness runs with NO provider credentials; the spawned servers decide
// their own, and the in-process checks inject their providers.
delete process.env.GEMINI_API_KEY;
delete process.env.CLOUDINARY_CLOUD_NAME;
delete process.env.CLOUDINARY_API_KEY;
delete process.env.CLOUDINARY_API_SECRET;

process.env.MONGO_URI = 'mongodb://127.0.0.1:27017/guardfi-phase7-placeholder';
process.env.OTP_DEV_MODE = 'true';
process.env.SMS_PROVIDER = 'none';
process.env.SCAM_BUSTER_MAX_IMAGE_BYTES = '5242880';
process.env.SCAM_BUSTER_TEXT_MAX_CHARS = '5000';
process.env.SCAM_BUSTER_STORAGE_MODE = 'auto';
// A dedicated directory, so cleanup can delete the whole thing without ever
// touching a developer's real uploads.
process.env.SCAM_BUSTER_LOCAL_STORAGE_DIR = 'uploads/verify-phase7-scans';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');
const mongoose = require('mongoose');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const MAIN_PORT = Number(process.env.VERIFY_SCAM_BUSTER_PORT || 4342);
const BUDGET_PORT = Number(process.env.VERIFY_SCAM_BUSTER_BUDGET_PORT || 4343);

const MAIN_BASE = `http://127.0.0.1:${MAIN_PORT}`;
const BUDGET_BASE = `http://127.0.0.1:${BUDGET_PORT}`;

const IMAGE_FIELD = 'image';
const ANALYZE_PATH = '/api/v1/scam-buster/analyze';
const HISTORY_PATH = '/api/v1/scam-buster/history';

let mongo = null;
const servers = [];
const results = [];

function record(name, fn) {
  return Promise.resolve()
    .then(fn)
    .then(() => results.push({ name, ok: true }))
    .catch((error) => results.push({ name, ok: false, error: error.message }));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** JSON/text request helper. */
async function call(base, pathname, { method = 'GET', token, body } = {}) {
  const init = { method, headers: {} };
  if (token) init.headers.Authorization = `Bearer ${token}`;
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  const response = await fetch(`${base}${pathname}`, init);
  const text = await response.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  return { status: response.status, body: parsed, text, headers: response.headers };
}

/** Multipart request helper — real FormData/Blob, so Multer does real work. */
async function callMultipart(base, pathname, { token, fields = {}, file = null } = {}) {
  const form = new FormData();

  for (const [key, value] of Object.entries(fields)) form.append(key, value);

  if (file) {
    form.append(file.field || IMAGE_FIELD, new Blob([file.buffer], { type: file.mimeType }), file.filename || 'shot.png');
  }

  const init = { method: 'POST', body: form, headers: {} };
  if (token) init.headers.Authorization = `Bearer ${token}`;

  const response = await fetch(`${base}${pathname}`, init);
  const text = await response.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  return { status: response.status, body: parsed, text, headers: response.headers };
}

function expectErrorCode(response, status, code) {
  assert.equal(response.status, status, `expected ${status}, got ${response.status}: ${response.text}`);
  assert.equal(response.body?.success, false);
  const haystack = `${response.body?.code || ''} ${response.body?.message || ''} ${JSON.stringify(response.body?.errors || [])}`;
  assert.ok(haystack.includes(code), `expected code ${code} in ${response.text}`);
}

async function waitForHealth(base, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no response';

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${base}/health`);
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

  throw new Error(`server at ${base} never became healthy within ${timeoutMs}ms (last: ${last})`);
}

function spawnServer({ port, env, label }) {
  const child = spawn(process.execPath, [path.join(PROJECT_ROOT, 'server.js')], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      LOG_LEVEL: 'error',
      PORT: String(port),
      MONGO_URI: process.env.MONGO_URI,
      RATE_LIMIT_SKIP_IN_TEST: 'true',
      FIREBASE_PROJECT_ID: '',
      FIREBASE_CLIENT_EMAIL: '',
      FIREBASE_PRIVATE_KEY: '',
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const entry = { label, child, output: [] };
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
      console.error(`\n--- ${entry.label} output ---`);
      console.error(entry.output.join('').split('\n').slice(-20).join('\n'));
    }
  }
}

// A 1x1 PNG header is enough: nothing in these paths decodes the image.
const PNG_BYTES = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');

async function seedDataset() {
  const User = require('../models/User');
  const { signAccessToken } = require('../services/tokenService');

  const make = (phone, name) => ({
    _id: new mongoose.Types.ObjectId(),
    phone,
    name,
    role: 'user',
    securityPinHash: null,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  const me = make('+919876550001', 'Scam Buster User');
  const other = make('+919876550002', 'Unrelated User');

  await User.collection.insertMany([me, other]);

  return {
    id: String(me._id),
    token: signAccessToken(me).token,
    otherId: String(other._id),
    otherToken: signAccessToken(other).token,
  };
}

// ===========================================================================
// HTTP checks — credential-less server
// ===========================================================================
async function runUnconfiguredChecks(seeded) {
  const { token } = seeded;

  await record('auth: an anonymous caller cannot request a scan', async () => {
    const response = await call(MAIN_BASE, ANALYZE_PATH, { method: 'POST', body: { text: 'hello' } });
    assert.equal(response.status, 401);
    assert.equal(response.body?.success, false);
  });

  await record('auth: an anonymous caller cannot read the history', async () => {
    const response = await call(MAIN_BASE, HISTORY_PATH);
    assert.equal(response.status, 401);
    assert.equal(response.body?.success, false);
  });

  await record('validation: missing, non-string and over-long text are all rejected', async () => {
    const cases = [
      [{}, 'INPUT_REQUIRED'],
      [{ text: 42 }, 'text must be a string'],
      [{ text: '   ' }, 'INPUT_REQUIRED'],
      [{ text: 'x'.repeat(5001) }, 'cannot exceed 5000 characters'],
    ];

    for (const [body, expected] of cases) {
      const response = await call(MAIN_BASE, ANALYZE_PATH, { method: 'POST', token, body });
      assert.equal(response.status, 400, `${JSON.stringify(body).slice(0, 60)} should be 400, got ${response.status}: ${response.text}`);
      assert.ok(response.text.includes(expected), `expected "${expected}" in ${response.text}`);
    }
  });

  await record('multipart: a non-image file is refused before any analysis', async () => {
    const response = await callMultipart(MAIN_BASE, ANALYZE_PATH, {
      token,
      file: { buffer: Buffer.from('not an image'), mimeType: 'text/plain', filename: 'notes.txt' },
    });

    expectErrorCode(response, 400, 'UNSUPPORTED_IMAGE_TYPE');
  });

  await record('multipart: the 5 MB screenshot cap is enforced as a 413', async () => {
    const oversize = Buffer.alloc(5 * 1024 * 1024 + 1024, 7);

    const response = await callMultipart(MAIN_BASE, ANALYZE_PATH, {
      token,
      file: { buffer: oversize, mimeType: 'image/png' },
    });

    assert.equal(response.status, 413, `expected 413, got ${response.status}: ${response.text}`);
    assert.ok(response.text.toLowerCase().includes('size'), response.text);
  });

  await record('multipart: an unexpected file field is refused', async () => {
    const response = await callMultipart(MAIN_BASE, ANALYZE_PATH, {
      token,
      file: { buffer: PNG_BYTES, mimeType: 'image/png', field: 'screenshot' },
    });

    // Multer's LIMIT_UNEXPECTED_FILE arrives as a plain-English 400 through
    // errorMiddleware (the code itself never reaches the client).
    assert.equal(response.status, 400, `expected 400, got ${response.status}: ${response.text}`);
    assert.ok(response.text.includes('unexpected file field'), response.text);
  });

  await record('routing: the scan endpoint is POST-only', async () => {
    const response = await call(MAIN_BASE, ANALYZE_PATH, { token });
    assert.equal(response.status, 404);
  });

  let textScan = null;

  await record('fallback: without GEMINI_API_KEY a text scan answers 201 with the offline verdict', async () => {
    const response = await call(MAIN_BASE, ANALYZE_PATH, {
      method: 'POST',
      token,
      body: { text: 'Dear customer, your KYC will expire today. Share your OTP to avoid account block.' },
    });

    assert.equal(response.status, 201, `expected 201, got ${response.status}: ${response.text}`);
    assert.equal(response.body?.success, true);

    textScan = response.body.data;

    assert.equal(textScan.inputType, 'TEXT');
    assert.equal(textScan.analysisSource, 'HEURISTIC');
    assert.equal(textScan.fallbackReason, 'AI_NOT_CONFIGURED');
    assert.equal(textScan.isScam, true);
    assert.equal(textScan.riskLevel, 'DANGER');
    assert.ok(textScan.confidenceScore >= 30 && textScan.confidenceScore <= 85, `confidence out of heuristic band: ${textScan.confidenceScore}`);
    assert.match(textScan.explanation_en, /OTP|KYC/i);
    assert.match(textScan.explanation_hi, /[\u0900-\u097F]/, 'the Hindi explanation must be real Devanagari');
    assert.ok(Array.isArray(textScan.redFlags) && textScan.redFlags.length >= 2, 'expected at least two red flags');
    assert.equal(textScan.extractedText.includes('KYC'), true, 'the submitted text is the extracted text');
    assert.equal(textScan.aiModel, null, 'a heuristic verdict has no model');
    assert.equal(textScan.analysisMs, null, 'a heuristic verdict reports no model latency');
    assert.equal(textScan.imageUrl, null);
    assert.match(String(textScan.scanId), /^[a-f0-9]{24}$/);
    assert.ok(textScan.checkedAt, 'checkedAt is part of the scan response');
    assert.match(response.body.message, /fraud signals/i);
  });

  await record('privacy: scan responses are never cacheable', async () => {
    const analyze = await call(MAIN_BASE, ANALYZE_PATH, {
      method: 'POST',
      token,
      body: { text: 'Hello, see you at 6pm.' },
    });
    const history = await call(MAIN_BASE, HISTORY_PATH, { token });

    assert.equal(analyze.headers.get('cache-control'), 'no-store');
    assert.equal(history.headers.get('cache-control'), 'no-store');
  });

  await record('fallback: a screenshot with no Cloudinary config is stored locally, not refused', async () => {
    const response = await callMultipart(MAIN_BASE, ANALYZE_PATH, {
      token,
      file: { buffer: PNG_BYTES, mimeType: 'image/png' },
    });

    assert.equal(response.status, 201, `expected 201, got ${response.status}: ${response.text}`);

    const scan = response.body.data;

    assert.equal(scan.inputType, 'IMAGE');
    assert.equal(scan.imageStorage, 'LOCAL');
    assert.match(String(scan.imageUrl), /^local:\/\/scam-scans\/[a-zA-Z0-9_-]+\.png$/);
    assert.equal(scan.isScam, true, 'an unreadable screenshot must not be called safe');
    assert.equal(scan.riskLevel, 'SUSPICIOUS');
    assert.equal(scan.analysisSource, 'HEURISTIC');
    assert.equal(scan.fallbackReason, 'AI_NOT_CONFIGURED');
    assert.equal(scan.extractedText, null);
    assert.match(scan.explanation_hi, /[\u0900-\u097F]/);

    const { resolveLocalPath } = require('../services/scamStorageService');
    const storedPath = resolveLocalPath(scan.imageUrl);

    assert.ok(storedPath, `imageUrl is not resolvable: ${scan.imageUrl}`);

    const stats = await fs.stat(storedPath);
    assert.equal(stats.size, PNG_BYTES.length, 'the stored file must be the uploaded bytes');
  });

  await record('history: the caller sees only their own scans, newest first', async () => {
    const ScamScan = require('../models/ScamScan');

    const mine = await ScamScan.find({ userId: seeded.id }).sort({ createdAt: -1, _id: -1 }).lean();
    const response = await call(MAIN_BASE, `${HISTORY_PATH}?limit=50`, { token });

    assert.equal(response.status, 200, response.text);
    assert.equal(response.body.success, true);
    assert.equal(response.body.data.count, mine.length, 'history must contain exactly the caller\'s scans');
    assert.deepEqual(
      response.body.data.scans.map((scan) => scan.scanId),
      mine.map((row) => String(row._id)),
      'history must be newest first'
    );
    assert.equal(response.body.data.scans.some((scan) => scan.checkedAt), false, 'stored scans carry no fresh checkedAt');

    const other = await call(MAIN_BASE, HISTORY_PATH, { token: seeded.otherToken });
    assert.equal(other.status, 200);
    assert.equal(other.body.data.count, 0, 'another user must never see these scans');
    assert.deepEqual(other.body.data.scans, []);
  });

  await record('history: the cursor pages without repeating or skipping a scan', async () => {
    const ScamScan = require('../models/ScamScan');
    const expected = (
      await ScamScan.find({ userId: seeded.id }).sort({ createdAt: -1, _id: -1 }).lean()
    ).map((row) => String(row._id));

    assert.ok(expected.length >= 3, `need at least 3 scans to page, found ${expected.length}`);

    const collected = [];
    let before = null;

    for (let page = 0; page < expected.length + 1; page += 1) {
      const query = `?limit=1${before ? `&before=${encodeURIComponent(before)}` : ''}`;
      const response = await call(MAIN_BASE, `${HISTORY_PATH}${query}`, { token });

      assert.equal(response.status, 200, response.text);
      assert.ok(response.body.data.count <= 1);

      if (response.body.data.count === 0) break;

      const [scan] = response.body.data.scans;
      collected.push(scan.scanId);

      if (!response.body.data.hasMore) break;

      assert.match(String(response.body.data.nextBefore), /Z_[a-f0-9]{24}$/, 'the cursor is timestamp + id');
      before = response.body.data.nextBefore;
    }

    assert.deepEqual(collected, expected, 'paging must visit every scan exactly once, in order');
  });

  await record('history: malformed page parameters are rejected, not ignored', async () => {
    const cases = [
      '?before=not-a-date',
      '?before=2026-13-45T99:99:99Z',
      '?limit=0',
      '?limit=51',
      '?limit=two',
      '?before=2026-10-18T10:00:00Z&before=2026-10-18T11:00:00Z',
    ];

    for (const query of cases) {
      const response = await call(MAIN_BASE, `${HISTORY_PATH}${query}`, { token });
      assert.equal(response.status, 400, `${query} should be 400, got ${response.status}: ${response.text}`);
      assert.equal(response.body.success, false);
      assert.ok(Array.isArray(response.body.errors) && response.body.errors.length > 0, response.text);
    }
  });

  await record('multipart: a caption without a file behaves like a text scan', async () => {
    const response = await callMultipart(MAIN_BASE, ANALYZE_PATH, {
      token,
      fields: { text: 'Is this message a scam?' },
    });

    assert.equal(response.status, 201, response.text);
    assert.equal(response.body.data.inputType, 'TEXT');
    assert.equal(response.body.data.analysisSource, 'HEURISTIC');
  });
}

// ===========================================================================
// HTTP checks — server with a 3-request scan budget
// ===========================================================================
async function runBudgetChecks(token) {
  await record('limiter: the scan budget is enforced (429) and stays scoped to the route', async () => {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const response = await call(BUDGET_BASE, ANALYZE_PATH, {
        method: 'POST',
        token,
        body: { text: 'Your electricity connection will be disconnected today. Pay now on this link.' },
      });

      assert.equal(response.status, 201, `scan ${attempt + 1} should succeed, got ${response.status}: ${response.text}`);
      assert.equal(response.body.data.analysisSource, 'HEURISTIC');
    }

    const fourth = await call(BUDGET_BASE, ANALYZE_PATH, {
      method: 'POST',
      token,
      body: { text: 'one more scan' },
    });

    assert.equal(fourth.status, 429, `the 4th scan should be rate limited, got ${fourth.status}: ${fourth.text}`);
    assert.ok(fourth.text.includes('Too many scam scans'), fourth.text);

    const health = await fetch(`${BUDGET_BASE}/health`);
    assert.equal(health.status, 200, 'the limiter must not leak onto other routes');
  });
}

// ===========================================================================
// In-process parser, heuristic and service checks
// ===========================================================================
const CANNED_DANGER = JSON.stringify({
  isScam: true,
  riskLevel: 'DANGER',
  confidence: 91,
  explanation_en: 'This is a KYC scam that asks for your PIN.',
  explanation_hi: 'यह एक KYC घोटाला है जो आपका PIN मांगता है।',
  redFlags: ['asks for UPI PIN', 'urgency threat', 'look-alike domain'],
  extractedText: '',
});

async function runParserChecks() {
  const { parseAiPayload, normalisePayload, normaliseRedFlags, extractJsonObject } = require('../services/scamBusterService');

  await record('parser: fenced and prose-wrapped JSON is repaired', async () => {
    const fenced = parseAiPayload('```json\n' + CANNED_DANGER + '\n```');
    assert.equal(fenced.isScam, true);
    assert.equal(fenced.riskLevel, 'DANGER');
    assert.equal(fenced.confidenceScore, 91);

    const wrapped = parseAiPayload(`Here is the analysis you asked for:\n${CANNED_DANGER}\nHope this helps!`);
    assert.equal(wrapped.isScam, true);

    assert.equal(extractJsonObject('no braces at all'), 'no braces at all');
  });

  await record('parser: loose values are coerced, not trusted', async () => {
    const coerced = parseAiPayload('{"isScam":"yes","riskLevel":" danger ","confidence":"92","explanation_en":"  ","explanation_hi":"","redFlags":["A","a","  ","B"],"extractedText":42}');
    assert.equal(coerced.isScam, true);
    assert.equal(coerced.riskLevel, 'DANGER');
    assert.equal(coerced.confidenceScore, 92);
    assert.equal(coerced.explanation_en.length > 0, true, 'empty explanation must fall back');
    assert.match(coerced.explanation_hi, /[\u0900-\u097F]/);
    assert.deepEqual(coerced.redFlags, ['A', 'B']);
    assert.equal(coerced.extractedText, null);
  });

  await record('parser: confidence is clamped and can be derived from the level', async () => {
    assert.equal(normalisePayload({ isScam: true, riskLevel: 'DANGER', confidence: 150 }).confidenceScore, 100);
    assert.equal(normalisePayload({ isScam: true, riskLevel: 'DANGER', confidence: -5 }).confidenceScore, 0);
    assert.equal(normalisePayload({ isScam: true, riskLevel: 'DANGER' }).confidenceScore, 85);
    assert.equal(normalisePayload({ isScam: false, riskLevel: 'SAFE' }).confidenceScore, 5);
  });

  await record('parser: a missing level is derived, and a missing verdict is refused', async () => {
    assert.equal(normalisePayload({ isScam: false }).riskLevel, 'SAFE');
    assert.equal(normalisePayload({ isScam: 'yes' }).riskLevel, 'DANGER');

    assert.throws(() => parseAiPayload('not json at all'), (error) => error.statusCode === 502 && error.code === 'AI_RESPONSE_INVALID');
    assert.throws(() => parseAiPayload('[]'), (error) => error.statusCode === 502);
    assert.throws(() => parseAiPayload('{}'), (error) => error.statusCode === 502 && error.code === 'AI_RESPONSE_INVALID');
    assert.throws(() => parseAiPayload('   '), (error) => error.statusCode === 502 && error.code === 'AI_RESPONSE_EMPTY');
  });

  await record('parser: red flags are cleaned, de-duplicated, capped and bounded', async () => {
    assert.deepEqual(normaliseRedFlags([' asks   for UPI PIN ', 'asks for upi pin', 7, '']), ['asks for UPI PIN']);

    const many = normaliseRedFlags(Array.from({ length: 20 }, (unused, index) => `flag ${index}`));
    assert.equal(many.length, 6, 'at most 6 red flags');

    const long = normaliseRedFlags(['x'.repeat(500)]);
    assert.equal(long[0].length, 120, 'each red flag is capped at 120 characters');
  });
}

async function runHeuristicChecks() {
  const heuristics = require('../services/scamHeuristicsService');

  await record('heuristics: the same message always produces the same verdict', async () => {
    const message = 'URGENT: your SBI account will be blocked today. Re-KYC now at http://sbi-kyc.top and share OTP.';
    const first = heuristics.analyseTextHeuristically({ text: message });
    const second = heuristics.analyseTextHeuristically({ text: message });

    assert.deepEqual(first, second, 'the offline screen must be deterministic');
    assert.equal(first.riskLevel, 'DANGER');
    assert.equal(first.isScam, true);
    assert.ok(first.confidenceScore >= 60 && first.confidenceScore <= 85);
    assert.match(first.explanation_hi, /[\u0900-\u097F]/);
    assert.ok(first.redFlags.length >= 3);
    assert.ok(first.redFlags.some((flag) => /OTP/i.test(flag)));
  });

  await record('heuristics: an ordinary message is not flagged, and a bare screenshot is', async () => {
    const benign = heuristics.analyseTextHeuristically({ text: 'See you at 6 pm near the metro station. I will bring the book.' });
    assert.equal(benign.riskLevel, 'SAFE');
    assert.equal(benign.isScam, false);
    assert.deepEqual(benign.redFlags, []);

    const empty = heuristics.analyseTextHeuristically({ text: null });
    assert.equal(empty.riskLevel, 'SAFE');
    assert.equal(empty.isScam, false);

    const screenshot = heuristics.analyseImageHeuristically({ caption: null });
    assert.equal(screenshot.riskLevel, 'SUSPICIOUS');
    assert.equal(screenshot.isScam, true);
    assert.match(screenshot.explanation_en, /Paste the message text/i);
    assert.match(screenshot.explanation_hi, /[\u0900-\u097F]/);
  });

  await record('heuristics: every level has bilingual copy and confidence is capped at 85', async () => {
    for (const level of ['SAFE', 'SUSPICIOUS', 'DANGER']) {
      assert.match(heuristics.DEFAULT_EXPLANATIONS[level].hi, /[\u0900-\u097F]/);
      assert.ok(heuristics.DEFAULT_EXPLANATIONS[level].en.length > 10);
    }

    // The band is a promise: a pattern match never claims certainty.
    assert.ok(heuristics.confidenceForScore(100) <= 85, 'a pattern match must never claim certainty');
    assert.equal(heuristics.confidenceForScore(100), 80, 'confidence is 30 + score/2, capped at 85');
    assert.equal(heuristics.confidenceForScore(0), 30);
    assert.equal(heuristics.levelForScore(60), 'DANGER');
    assert.equal(heuristics.levelForScore(59), 'SUSPICIOUS');
    assert.equal(heuristics.levelForScore(24), 'SAFE');
  });
}

async function runServiceChecks(userId) {
  const ScamScan = require('../models/ScamScan');
  const { analyzeScan, listScans, toPayload } = require('../services/scamBusterService');
  const ApiError = require('../utils/ApiError');
  const { config } = require('../config/env');

  await record('service: a text scan with an injected provider is stored with both languages', async () => {
    let storeCalled = false;

    const row = await analyzeScan({
      userId,
      text: 'Dear customer, your account will be blocked. Share OTP now.',
      requestIp: '127.0.0.1',
      deps: {
        analyze: async ({ text, image }) => {
          assert.equal(image, null, 'a text scan must not fabricate an image');
          assert.match(text, /blocked/);
          return { rawText: CANNED_DANGER, model: 'verify-fake-model' };
        },
        store: async () => {
          storeCalled = true;
          return { imageUrl: 'https://example.test/none.png', cloudinaryPublicId: 'none', storage: 'CLOUDINARY' };
        },
      },
    });

    assert.equal(storeCalled, false, 'a text scan must never touch image storage');
    assert.equal(row.inputType, 'TEXT');
    assert.equal(row.imageUrl, null);
    assert.equal(row.analysisSource, 'GEMINI');
    assert.equal(row.fallbackReason, null);
    assert.equal(row.isScam, true);
    assert.equal(row.riskLevel, 'DANGER');
    assert.equal(row.confidenceScore, 91);
    assert.match(row.explanation_hi, /[\u0900-\u097F]/);
    assert.deepEqual(row.redFlags, ['asks for UPI PIN', 'urgency threat', 'look-alike domain']);
    assert.equal(row.extractedText, 'Dear customer, your account will be blocked. Share OTP now.');
    assert.equal(row.aiModel, 'verify-fake-model');
    assert.equal(typeof row.analysisMs, 'number');

    const stored = await ScamScan.findById(row._id).lean();
    assert.equal(stored.isScam, true);
    assert.equal(String(stored.userId), String(userId));
  });

  await record('service: a screenshot scan stores the image URL and the model\'s OCR text', async () => {
    let storedWith = null;

    const row = await analyzeScan({
      userId,
      text: 'Someone sent me this on WhatsApp',
      file: { buffer: PNG_BYTES, mimetype: 'image/png' },
      deps: {
        analyze: async ({ image, text }) => {
          assert.ok(image && Buffer.isBuffer(image.buffer), 'the image must reach the analyzer as a buffer');
          assert.equal(image.mimeType, 'image/png');
          assert.equal(text, 'Someone sent me this on WhatsApp');
          return {
            rawText: JSON.stringify({
              isScam: true,
              riskLevel: 'DANGER',
              confidence: 88,
              explanation_en: 'Fake bank alert.',
              explanation_hi: 'नकली बैंक अलर्ट।',
              redFlags: ['fake sender id'],
              extractedText: 'Your KYC is expiring. Click here to update.',
            }),
            model: 'verify-fake-model',
          };
        },
        store: async (input) => {
          storedWith = input;
          return { imageUrl: 'https://res.cloudinary.test/demo/scan.png', cloudinaryPublicId: 'demo/scan', storage: 'CLOUDINARY' };
        },
      },
    });

    assert.equal(row.inputType, 'IMAGE');
    assert.equal(row.imageUrl, 'https://res.cloudinary.test/demo/scan.png');
    assert.equal(row.cloudinaryPublicId, 'demo/scan');
    assert.equal(row.imageStorage, 'CLOUDINARY');
    assert.equal(row.extractedText, 'Your KYC is expiring. Click here to update.', 'the OCR text wins for screenshots');
    assert.equal(storedWith.mimeType, 'image/png');
    assert.equal(Buffer.compare(storedWith.buffer, PNG_BYTES), 0);
    assert.equal(String(storedWith.userId), String(userId));
  });

  await record('service: a provider timeout degrades to the offline verdict, it does not fail', async () => {
    const row = await analyzeScan({
      userId,
      text: 'Congratulations! You won Rs 25,00,000. Send your UPI PIN to claim.',
      deps: {
        analyze: async () => {
          throw new ApiError(504, 'timed out', { code: 'AI_TIMEOUT' });
        },
      },
    });

    assert.equal(row.analysisSource, 'HEURISTIC');
    assert.equal(row.fallbackReason, 'AI_TIMEOUT');
    assert.equal(row.riskLevel, 'DANGER');
    assert.equal(row.isScam, true);
    assert.equal(row.aiModel, null);
    assert.equal(row.analysisMs, null);
    assert.match(row.explanation_hi, /[\u0900-\u097F]/);
  });

  await record('service: an unparseable model answer also degrades, it does not 502', async () => {
    const row = await analyzeScan({
      userId,
      text: 'Your parcel is held at customs. Pay the clearance fee to release it.',
      deps: { analyze: async () => ({ rawText: '<html>service unavailable</html>', model: 'verify-fake-model' }) },
    });

    assert.equal(row.analysisSource, 'HEURISTIC');
    assert.equal(row.fallbackReason, 'AI_RESPONSE_INVALID');
    assert.ok(row.riskLevel === 'DANGER' || row.riskLevel === 'SUSPICIOUS');
    assert.equal(row.aiModel, null);
  });

  await record('service: a real bug is never hidden behind a heuristic verdict', async () => {
    const before = await ScamScan.countDocuments({ userId });

    await assert.rejects(
      () => analyzeScan({ userId, text: 'test', deps: { analyze: async () => { throw new TypeError('boom'); } } }),
      (error) => error instanceof TypeError
    );

    // An injected store is a test double: its failure must surface, not be
    // silently swallowed by the storage chain.
    await assert.rejects(
      () =>
        analyzeScan({
          userId,
          file: { buffer: PNG_BYTES, mimetype: 'image/png' },
          deps: {
            store: async () => { throw new ApiError(503, 'bucket down', { code: 'CLOUDINARY_UPLOAD_FAILED' }); },
            analyze: async () => ({ rawText: CANNED_DANGER }),
          },
        }),
      (error) => error.statusCode === 503
    );

    assert.equal(await ScamScan.countDocuments({ userId }), before, 'no verdict may be stored for a failed scan');
  });

  await record('storage: a configured-but-broken Cloudinary degrades to a local file', async () => {
    const cloudinaryService = require('../services/cloudinaryService');
    const originalConfigured = cloudinaryService.isCloudinaryConfigured;
    const originalUpload = cloudinaryService.uploadImage;

    cloudinaryService.isCloudinaryConfigured = () => true;
    cloudinaryService.uploadImage = async () => {
      throw new ApiError(503, 'cloudinary is down', { code: 'CLOUDINARY_UPLOAD_FAILED' });
    };

    try {
      const row = await analyzeScan({
        userId,
        file: { buffer: PNG_BYTES, mimetype: 'image/png' },
        deps: { analyze: async () => ({ rawText: CANNED_DANGER, model: 'verify-fake-model' }) },
      });

      assert.equal(row.imageStorage, 'LOCAL', 'a dead bucket must fall back to disk, not fail the scan');
      assert.match(String(row.imageUrl), /^local:\/\/scam-scans\//);
      assert.equal(row.riskLevel, 'DANGER');

      const { resolveLocalPath } = require('../services/scamStorageService');
      const stats = await fs.stat(resolveLocalPath(row.imageUrl));
      assert.equal(stats.size, PNG_BYTES.length);
    } finally {
      cloudinaryService.isCloudinaryConfigured = originalConfigured;
      cloudinaryService.uploadImage = originalUpload;
    }
  });

  await record('storage: a read-only disk degrades to a capped data URI, then to nothing', async () => {
    const { storeScreenshot, STORAGE, resolveLocalPath } = require('../services/scamStorageService');
    const fsp = require('node:fs/promises');
    const originalWriteFile = fsp.writeFile;

    fsp.writeFile = async () => {
      throw new Error('EROFS: read-only file system');
    };

    try {
      const small = await storeScreenshot({ buffer: PNG_BYTES, mimeType: 'image/png' });
      assert.equal(small.storage, STORAGE.DATA_URI);
      assert.match(String(small.imageUrl), /^data:image\/png;base64,/);

      const huge = await storeScreenshot({
        buffer: Buffer.alloc(config.scamBuster.inlineImageMaxBytes + 1, 1),
        mimeType: 'image/png',
      });
      assert.equal(huge.storage, STORAGE.NONE);
      assert.equal(huge.imageUrl, null);
    } finally {
      fsp.writeFile = originalWriteFile;
    }

    // A stored reference is only ever a server-generated name in our own folder.
    assert.equal(resolveLocalPath('https://evil.test/a.png'), null);
    assert.equal(resolveLocalPath('local://scam-scans/../../etc/passwd'), null);
    assert.equal(resolveLocalPath('local://scam-scans/evil.exe'), null);
    assert.ok(resolveLocalPath('local://scam-scans/abc.png'));
  });

  await record('service: bad files and empty input are refused before storage or AI run', async () => {
    const calls = { analyze: 0, store: 0 };
    const deps = {
      analyze: async () => {
        calls.analyze += 1;
        return { rawText: CANNED_DANGER };
      },
      store: async () => {
        calls.store += 1;
        return { imageUrl: 'x', cloudinaryPublicId: 'x', storage: 'CLOUDINARY' };
      },
    };

    await assert.rejects(
      () => analyzeScan({ userId, file: { buffer: PNG_BYTES, mimetype: 'image/gif' }, deps }),
      (error) => error.statusCode === 400 && /JPEG, PNG or WebP/.test(error.message)
    );

    await assert.rejects(
      () => analyzeScan({ userId, file: { buffer: Buffer.alloc(5 * 1024 * 1024 + 1), mimetype: 'image/png' }, deps }),
      (error) => error.statusCode === 413
    );

    await assert.rejects(() => analyzeScan({ userId }), (error) => error.statusCode === 400);
    await assert.rejects(() => analyzeScan({ userId, text: 'x'.repeat(5001) }), (error) => error.statusCode === 400);

    assert.deepEqual(calls, { analyze: 0, store: 0 }, 'invalid input must never reach storage or the provider');
  });

  await record('history: listScans is scoped to the caller and walks the index', async () => {
    const owner = new mongoose.Types.ObjectId();
    const stranger = new mongoose.Types.ObjectId();

    await ScamScan.create([
      {
        userId: owner,
        inputType: 'TEXT',
        extractedText: 'older',
        isScam: false,
        riskLevel: 'SAFE',
        confidenceScore: 5,
        explanation_en: 'x',
        explanation_hi: 'x',
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        updatedAt: new Date('2026-01-01T00:00:00.000Z'),
      },
      {
        userId: owner,
        inputType: 'TEXT',
        extractedText: 'newer',
        isScam: true,
        riskLevel: 'DANGER',
        confidenceScore: 90,
        explanation_en: 'x',
        explanation_hi: 'x',
        createdAt: new Date('2026-01-02T00:00:00.000Z'),
        updatedAt: new Date('2026-01-02T00:00:00.000Z'),
      },
      {
        userId: stranger,
        inputType: 'TEXT',
        extractedText: 'not mine',
        isScam: true,
        riskLevel: 'DANGER',
        confidenceScore: 90,
        explanation_en: 'x',
        explanation_hi: 'x',
      },
    ]);

    const mine = await listScans({ userId: owner });
    assert.equal(mine.count, 2);
    assert.deepEqual(mine.scans.map((scan) => scan.extractedText), ['newer', 'older']);
    assert.equal(mine.hasMore, false);
    assert.equal(mine.scans.some((scan) => scan.extractedText === 'not mine'), false);
  });

  await record('history: same-millisecond scans are neither skipped nor repeated', async () => {
    const owner = new mongoose.Types.ObjectId();
    const at = new Date('2026-02-01T00:00:00.000Z');

    await ScamScan.create(
      ['a', 'b', 'c'].map((label) => ({
        userId: owner,
        inputType: 'TEXT',
        extractedText: label,
        isScam: true,
        riskLevel: 'SUSPICIOUS',
        confidenceScore: 40,
        explanation_en: 'x',
        explanation_hi: 'x',
        createdAt: at,
        updatedAt: at,
      }))
    );

    const all = await listScans({ userId: owner, limit: 10 });
    assert.equal(all.count, 3);

    const collected = [];
    let before = null;

    for (let page = 0; page < 5; page += 1) {
      const result = await listScans({ userId: owner, limit: 1, before });

      if (result.count === 0) break;

      collected.push(result.scans[0].extractedText);
      before = result.nextBefore;
    }

    assert.deepEqual(collected, all.scans.map((scan) => scan.extractedText));
    assert.equal(new Set(collected).size, 3, 'every scan must be visited exactly once');
  });

  await record('privacy: payloads carry no image bytes and no secrets', async () => {
    const row = await ScamScan.findOne({ userId, inputType: 'IMAGE' }).lean();
    const serialized = JSON.stringify(toPayload(row));

    assert.equal(serialized.includes('base64'), false);
    assert.equal(serialized.includes('iVBOR'), false, 'PNG base64 magic must never appear in a payload');
    assert.equal(serialized.includes('GEMINI_API_KEY'), false);
    assert.equal(serialized.includes('api_secret'), false);
    assert.equal(serialized.includes('CLOUDINARY_API_SECRET'), false);
  });
}

async function runModelChecks() {
  const ScamScan = require('../models/ScamScan');

  await ScamScan.init();

  await record('model: the scan history index exists and the history query uses it', async () => {
    const indexes = await ScamScan.collection.indexes();
    assert.ok(
      indexes.some((index) => index.key.userId === 1 && index.key.createdAt === -1),
      'scamscans user history index missing'
    );

    const userId = new mongoose.Types.ObjectId();

    const plain = JSON.stringify(
      await ScamScan.find({ userId }).sort({ createdAt: -1, _id: -1 }).explain('executionStats')
    );
    assert.match(plain, /IXSCAN/);
    assert.equal(plain.includes('COLLSCAN'), false, 'the scan history query fell back to a collection scan');

    const paged = JSON.stringify(
      await ScamScan.find({
        userId,
        $or: [
          { createdAt: { $lt: new Date() } },
          { createdAt: new Date(), _id: { $lt: new mongoose.Types.ObjectId() } },
        ],
      })
        .sort({ createdAt: -1, _id: -1 })
        .explain('executionStats')
    );
    assert.match(paged, /IXSCAN/);
    assert.equal(paged.includes('COLLSCAN'), false, 'the cursor query fell back to a collection scan');
  });

  await record('model: an invalid scan cannot be persisted', async () => {
    await assert.rejects(() => ScamScan.create({ userId: new mongoose.Types.ObjectId(), inputType: 'TEXT' }));
    await assert.rejects(() =>
      ScamScan.create({
        userId: new mongoose.Types.ObjectId(),
        inputType: 'AUDIO',
        isScam: false,
        explanation_en: 'x',
        explanation_hi: 'x',
      })
    );
    await assert.rejects(() =>
      ScamScan.create({
        userId: new mongoose.Types.ObjectId(),
        inputType: 'TEXT',
        imageStorage: 'S3',
        isScam: false,
        explanation_en: 'x',
        explanation_hi: 'x',
      })
    );
    await assert.rejects(() =>
      ScamScan.create({
        userId: new mongoose.Types.ObjectId(),
        inputType: 'TEXT',
        isScam: false,
        confidenceScore: 101,
        explanation_en: 'x',
        explanation_hi: 'x',
      })
    );
  });
}

async function runContractChecks() {
  await record('gemini: the strict response schema covers the spec fields', async () => {
    const { buildResponseSchema, isGeminiConfigured, analyzeText } = require('../services/geminiService');

    assert.equal(isGeminiConfigured(), false, 'the harness must run without a Gemini key');

    const schema = buildResponseSchema();
    assert.deepEqual([...schema.required].sort(), ['explanation_en', 'explanation_hi', 'isScam', 'redFlags', 'riskLevel']);
    assert.deepEqual(schema.properties.riskLevel.enum, ['SAFE', 'SUSPICIOUS', 'DANGER']);
    assert.equal(schema.properties.isScam.type, 'boolean');
    assert.equal(schema.properties.redFlags.type, 'array');

    // No key: the provider layer must say exactly which code is missing, so the
    // orchestrator can degrade instead of crashing.
    await assert.rejects(
      () => analyzeText({ text: 'hello' }),
      (error) => error.statusCode === 503 && error.code === 'AI_NOT_CONFIGURED'
    );
  });

  await record('upload middleware: the allow-list, the limits and the field name are exact', async () => {
    const { imageFileFilter, UPLOAD_LIMITS, IMAGE_FIELD, ALLOWED_IMAGE_MIME } = require('../middlewares/uploadMiddleware');
    const { config } = require('../config/env');

    assert.equal(IMAGE_FIELD, 'image');
    assert.equal(UPLOAD_LIMITS.fileSize, config.scamBuster.maxImageBytes);
    assert.equal(UPLOAD_LIMITS.files, 1);
    assert.deepEqual([...ALLOWED_IMAGE_MIME].sort(), ['image/jpeg', 'image/png', 'image/webp']);

    for (const allowed of ['image/jpeg', 'image/png', 'image/webp']) {
      await new Promise((resolve, reject) => {
        imageFileFilter({}, { mimetype: allowed }, (error, accepted) => {
          try {
            assert.equal(error, null, `${allowed} should be accepted`);
            assert.equal(accepted, true);
            resolve();
          } catch (assertionError) {
            reject(assertionError);
          }
        });
      });
    }

    await new Promise((resolve) => {
      imageFileFilter({}, { mimetype: 'image/gif' }, (error) => {
        assert.ok(error, 'gif must be refused');
        assert.equal(error.statusCode, 400);
        resolve();
      });
    });
  });

  await record('contract: the scan response carries every field the client promises', async () => {
    const ScamScan = require('../models/ScamScan');
    const { toPayload } = require('../services/scamBusterService');
    const row = await ScamScan.findOne({ inputType: 'IMAGE' }).lean();

    assert.ok(row, 'expected a stored image scan');

    const payload = toPayload(row);

    for (const key of [
      'scanId',
      'inputType',
      'imageUrl',
      'imageStorage',
      'isScam',
      'riskLevel',
      'confidenceScore',
      'explanation_en',
      'explanation_hi',
      'redFlags',
      'extractedText',
      'analysisSource',
      'fallbackReason',
      'aiModel',
      'analysisMs',
      'createdAt',
      'checkedAt',
    ]) {
      assert.ok(Object.prototype.hasOwnProperty.call(payload, key), `payload is missing ${key}`);
    }
  });
}

// ===========================================================================
// Cleanup
// ===========================================================================
async function cleanupArtifacts() {
  const report = { files: 0, dir: null, rows: 0 };

  const dir = path.resolve(PROJECT_ROOT, process.env.SCAM_BUSTER_LOCAL_STORAGE_DIR);

  try {
    report.files = (await fs.readdir(dir)).length;
  } catch {
    report.files = 0;
  }

  await fs.rm(dir, { recursive: true, force: true });
  report.dir = dir;

  const ScamScan = require('../models/ScamScan');
  const { deletedCount } = await ScamScan.deleteMany({});
  report.rows = deletedCount ?? 0;

  return report;
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
    instance: { dbName: 'guardfi-phase7-verify', launchTimeout: 90_000 },
  });

  const uri = mongo.getUri('guardfi-phase7-verify');
  process.env.MONGO_URI = uri;

  const { connectDatabase } = require('../config/db');
  await connectDatabase();

  let seeded = null;

  try {
    console.log('▶ Seeding two accounts...');
    seeded = await seedDataset();

    console.log(`▶ Booting the credential-less server on ${MAIN_PORT} and the budget server on ${BUDGET_PORT}...`);
    spawnServer({
      port: MAIN_PORT,
      label: 'main server',
      env: { GEMINI_API_KEY: '', CLOUDINARY_CLOUD_NAME: '', CLOUDINARY_API_KEY: '', CLOUDINARY_API_SECRET: '' },
    });
    spawnServer({
      port: BUDGET_PORT,
      label: 'budget server',
      env: {
        GEMINI_API_KEY: '',
        CLOUDINARY_CLOUD_NAME: '',
        CLOUDINARY_API_KEY: '',
        CLOUDINARY_API_SECRET: '',
        RATE_LIMIT_SKIP_IN_TEST: 'false',
        RATE_LIMIT_SCAM_BUSTER_MAX: '3',
      },
    });

    await waitForHealth(MAIN_BASE);
    await waitForHealth(BUDGET_BASE);

    console.log('▶ Servers healthy. Running HTTP checks...\n');
    await runUnconfiguredChecks(seeded);
    await runBudgetChecks(seeded.token);
  } catch (error) {
    results.push({ name: 'harness: servers became healthy', ok: false, error: error.message });
  } finally {
    await stopServers();
  }

  if (seeded) {
    await runParserChecks();
    await runHeuristicChecks();
    await runServiceChecks(seeded.id);
    await runContractChecks();
  }

  await runModelChecks();

  // Probe records and stored screenshots are not left behind, and the cleanup
  // itself is asserted rather than assumed.
  await record('cleanup: probe scans and stored screenshots are removed', async () => {
    const report = await cleanupArtifacts();
    const ScamScan = require('../models/ScamScan');

    assert.equal(await ScamScan.countDocuments({}), 0, 'probe rows survived cleanup');

    let dirExists = true;
    try {
      await fs.stat(report.dir);
    } catch {
      dirExists = false;
    }

    assert.equal(dirExists, false, `the verification upload directory still exists: ${report.dir}`);
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
  await cleanupArtifacts().catch(() => {});
  if (mongo) await mongo.stop().catch(() => {});
  process.exit(1);
});
