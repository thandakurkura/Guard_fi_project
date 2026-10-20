'use strict';

/**
 * GuardFi — Phase 3 verification harness
 *
 * Proves the nominee/guardian API end to end against a throwaway in-memory
 * MongoDB: real Express, real Mongoose, real indexes, real JWT authentication.
 * Your .env, your Atlas cluster and your data are never touched.
 *
 * What it attacks, not just what it exercises:
 *   • missing / malformed tokens on every route;
 *   • IDOR — another user's nominee id on PATCH and DELETE (must be 404, and the
 *     document must survive);
 *   • mass assignment — a `userId` in the body must be ignored;
 *   • the 5-nominee cap, including three simultaneous adds at the boundary;
 *   • the one-primary invariant, including two simultaneous promotions, and the
 *     database-level partial unique index that makes it unbreakable;
 *   • self-nomination, duplicate numbers spelled three different ways, control
 *     characters in names, uneditable phone numbers, invalid ObjectIds;
 *   • push tokens: accepted, stored, never serialised.
 *
 * Run:  npm run verify:phase3
 * Exit: 0 = every check passed, 1 = at least one failed, 2 = harness cannot run.
 */

// --- environment for THIS process (must precede every local require) --------
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = process.env.VERIFY_LOG_LEVEL || 'error';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'verify-phase3-secret-'.padEnd(48, '0');
process.env.CORS_ORIGINS = '*';
process.env.STRICT_ENV = 'false';
process.env.TRUST_PROXY = 'false';
process.env.MAX_NOMINEES_PER_USER = '5';
delete process.env.PORT;

// Placeholder until the in-memory server is up, so dotenv can never make this
// run talk to the real Atlas cluster.
process.env.MONGO_URI = 'mongodb://127.0.0.1:27017/guardfi-phase3-placeholder';

const assert = require('node:assert/strict');
const path = require('node:path');
const { spawn } = require('node:child_process');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const SERVER_PORT = Number(process.env.VERIFY_NOMINEE_PORT || 4325);
const BASE = `http://127.0.0.1:${SERVER_PORT}`;

const MAX = 5;
const ID_HEX = /^[0-9a-f]{24}$/;

let mongo = null;
/** @type {{ label: string, child: import('node:child_process').ChildProcess, output: string[] } | null} */
let server = null;
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

async function call(pathname, { method = 'POST', body, token, headers = {} } = {}) {
  const init = { method, headers: { ...headers } };

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

  return { status: response.status, body: parsed, text, headers: response.headers };
}

async function waitForHealth(timeoutMs = 40_000) {
  const deadline = Date.now() + timeoutMs;
  let last = 'no response';

  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${BASE}/health`);
      const body = await response.json();
      // Ready means safe to write: the server awaits unique-index creation, so a
      // 200 here guarantees the nominee indexes already exist.
      if (
        response.status === 200 &&
        body?.data?.database?.connected === true &&
        body?.data?.database?.indexesReady === true
      ) {
        return body;
      }
      last = `status=${response.status} db=${body?.data?.database?.state} indexes=${body?.data?.database?.indexesReady}`;
    } catch (error) {
      last = error.message;
    }
    await sleep(400);
  }

  throw new Error(`server never became healthy within ${timeoutMs}ms (last: ${last})`);
}

function spawnServer({ uri }) {
  const child = spawn(process.execPath, [path.join(PROJECT_ROOT, 'server.js')], {
    cwd: PROJECT_ROOT,
    env: {
      ...process.env,
      NODE_ENV: 'test',
      LOG_LEVEL: 'error',
      PORT: String(SERVER_PORT),
      MONGO_URI: uri,
      MAX_NOMINEES_PER_USER: String(MAX),
      OTP_DEV_MODE: 'true',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const entry = { label: 'nominee server', child, output: [] };
  child.stdout.on('data', (chunk) => entry.output.push(chunk.toString()));
  child.stderr.on('data', (chunk) => entry.output.push(chunk.toString()));
  server = entry;

  return entry;
}

async function stopServer() {
  if (server && server.child.exitCode === null) {
    server.child.kill();
    await sleep(200);
  }

  if (results.some((result) => !result.ok) && server && server.output.length > 0) {
    console.error('\n--- server output ---');
    console.error(server.output.join('').split('\n').slice(-20).join('\n'));
  }
}

/** Assert the standard error envelope with a specific status and error code. */
function expectError(response, status, code) {
  assert.equal(response.status, status, `expected ${status}, got ${response.status}: ${response.text}`);
  assert.equal(response.body?.success, false, 'error envelope must have success:false');
  assert.equal(response.body?.data, null, 'error envelope must have data:null');
  assert.ok(Array.isArray(response.body?.errors) || response.body?.errors === null, 'errors must be an array or null');

  if (code) {
    const codes = (response.body?.errors || []).map((entry) => entry.code);
    assert.ok(codes.includes(code), `expected error code ${code}, got ${JSON.stringify(codes)}`);
  }
}

function expectSuccess(response, status = 200) {
  assert.equal(response.status, status, `expected ${status}, got ${response.status}: ${response.text}`);
  assert.equal(response.body?.success, true);
  assert.equal(response.body?.errors, null);
  assert.ok(response.body?.data && typeof response.body.data === 'object');
}

/** Seed a real user document and a real signed token for them. */
async function seedUser(phone, name) {
  const User = require('../models/User');
  const { signAccessToken } = require('../services/tokenService');

  const user = await User.create({ phone, name });
  const auth = signAccessToken(user);

  return { user, token: auth.token, phone, id: String(user._id) };
}

// ===========================================================================
// HTTP checks
// ===========================================================================
async function runHttpChecks() {
  const Nominee = require('../models/Nominee');

  const alice = await seedUser('+919876570001', 'Alice Owner');
  const bob = await seedUser('+919876570002', 'Bob Other');

  // --- authentication -------------------------------------------------------
  await record('auth: POST /add without a token → 401 envelope', async () => {
    const response = await call('/api/v1/nominees/add', {
      body: { name: 'No Token', phone: '9876577201' },
    });

    expectError(response, 401);
    assert.match(response.body.message, /token/i);
  });

  await record('auth: GET /list with a non-Bearer scheme → 401', async () => {
    const response = await call('/api/v1/nominees/list', {
      method: 'GET',
      headers: { Authorization: 'Basic YWJjOjEyMw==' },
    });

    expectError(response, 401);
  });

  await record('api: GET /api/v1 lists the nominees module', async () => {
    const response = await call('/api/v1', { method: 'GET' });
    expectSuccess(response, 200);
    assert.ok(response.body.data.mountedModules.includes('nominees'));
  });

  await record('health: reports unique indexes as built before serving writes', async () => {
    const response = await call('/health', { method: 'GET' });
    expectSuccess(response, 200);
    assert.equal(response.body.data.database.connected, true);
    assert.equal(response.body.data.database.indexesReady, true);
  });

  // --- add: happy path ------------------------------------------------------
  let primary = null;

  await record('add: first nominee → 201, E.164 phone, automatically primary', async () => {
    const response = await call('/api/v1/nominees/add', {
      token: alice.token,
      body: { name: 'Asha Guardian', phone: '9876577101', relation: 'Mother' },
    });

    expectSuccess(response, 201);
    const nominee = response.body.data.nominee;

    primary = nominee;

    assert.match(nominee._id, ID_HEX);
    assert.equal(nominee.name, 'Asha Guardian');
    assert.equal(nominee.phone, '+919876577101');
    assert.equal(nominee.relation, 'Mother');
    assert.equal(nominee.isPrimary, true, 'the first nominee must become primary');
    assert.equal(nominee.userId, undefined, 'the owner id must not be echoed back');
    assert.equal(nominee.fcmToken, undefined);
  });

  await record('add: national 0-prefix second nominee → normalised, not primary, token never echoed', async () => {
    const response = await call('/api/v1/nominees/add', {
      token: alice.token,
      body: { name: 'Ravi Guardian', phone: '09876577102', fcmToken: 'fcm-secret-token-value' },
    });

    expectSuccess(response, 201);
    const nominee = response.body.data.nominee;

    assert.equal(nominee.phone, '+919876577102');
    assert.equal(nominee.relation, null);
    assert.equal(nominee.isPrimary, false);
    assert.ok(!response.text.includes('fcm-secret-token-value'), 'the push token must never be serialised');

    const stored = await Nominee.findById(nominee._id).select('+fcmToken');
    assert.equal(stored.fcmToken, 'fcm-secret-token-value', 'the token should still be stored for Phase 4');
    assert.equal(stored.toJSON().fcmToken, undefined, 'even an explicit select must not serialise it');
  });

  await record('add: duplicate number (different spelling) → 409 NOMINEE_DUPLICATE', async () => {
    const response = await call('/api/v1/nominees/add', {
      token: alice.token,
      body: { name: 'Duplicate Asha', phone: '+91 98765 77101' },
    });

    expectError(response, 409, 'NOMINEE_DUPLICATE');
  });

  await record('add: a national-number duplicate → 409 NOMINEE_DUPLICATE', async () => {
    const response = await call('/api/v1/nominees/add', {
      token: alice.token,
      body: { name: 'Duplicate Ravi', phone: '9876577102' },
    });

    expectError(response, 409, 'NOMINEE_DUPLICATE');
  });

  await record('add: the owner cannot nominate their own number → 400 NOMINEE_SELF', async () => {
    const response = await call('/api/v1/nominees/add', {
      token: alice.token,
      body: { name: 'Myself', phone: '+919876570001' },
    });

    expectError(response, 400, 'NOMINEE_SELF');
  });

  await record('add: invalid phone / missing name / long name / control characters → 400', async () => {
    const badPhone = await call('/api/v1/nominees/add', {
      token: alice.token,
      body: { name: 'Bad Phone', phone: '12345' },
    });
    expectError(badPhone, 400, 'custom');
    assert.match(badPhone.body.errors[0].message, /valid phone number/);

    const missingName = await call('/api/v1/nominees/add', {
      token: alice.token,
      body: { phone: '9876577203' },
    });
    expectError(missingName, 400, 'custom');
    assert.ok(missingName.body.errors.some((entry) => entry.field === 'name' && /required/.test(entry.message)));

    const longName = await call('/api/v1/nominees/add', {
      token: alice.token,
      body: { name: 'x'.repeat(81), phone: '9876577204' },
    });
    expectError(longName, 400);
    assert.ok(longName.body.errors.some((entry) => /80 characters/.test(entry.message)));

    const controlName = await call('/api/v1/nominees/add', {
      token: alice.token,
      body: { name: 'Bad\u0007Name', phone: '9876577205' },
    });
    expectError(controlName, 400);
    assert.ok(controlName.body.errors.some((entry) => /control characters/.test(entry.message)));

    const badFlag = await call('/api/v1/nominees/add', {
      token: alice.token,
      body: { name: 'String Flag', phone: '9876577206', isPrimary: 'true' },
    });
    expectError(badFlag, 400, 'custom');
    assert.ok(badFlag.body.errors.some((entry) => entry.field === 'isPrimary'));
  });

  await record('add: body userId is ignored (mass assignment cannot attach a guardian to Bob)', async () => {
    const response = await call('/api/v1/nominees/add', {
      token: alice.token,
      body: { userId: bob.id, name: 'Mass Assign', phone: '9876577207' },
    });

    expectSuccess(response, 201);

    const nominee = await Nominee.findById(response.body.data.nominee._id).lean();
    assert.equal(String(nominee.userId), alice.id);
    assert.equal(await Nominee.countDocuments({ userId: bob.id }), 0);
  });

  // --- cap ------------------------------------------------------------------
  await record('cap: filling to 5 works, the 6th is refused with NOMINEE_LIMIT_REACHED', async () => {
    for (const suffix of ['7208', '7209']) {
      const added = await call('/api/v1/nominees/add', {
        token: alice.token,
        body: { name: `Guardian ${suffix}`, phone: `987657${suffix}` },
      });
      expectSuccess(added, 201);
    }

    const overflow = await call('/api/v1/nominees/add', {
      token: alice.token,
      body: { name: 'One Too Many', phone: '9876577210' },
    });

    expectError(overflow, 409, 'NOMINEE_LIMIT_REACHED');
    assert.match(overflow.body.message, /at most 5 nominees/);
    assert.equal(await Nominee.countDocuments({ userId: alice.id }), MAX);
  });

  // --- list -----------------------------------------------------------------
  await record('list: 5 nominees, primary first, no secrets, cap metadata', async () => {
    const response = await call('/api/v1/nominees/list', { method: 'GET', token: alice.token });
    expectSuccess(response, 200);

    const { nominees, count, maxNominees, remainingSlots } = response.body.data;

    assert.equal(count, 5);
    assert.equal(nominees.length, 5);
    assert.equal(maxNominees, 5);
    assert.equal(remainingSlots, 0);

    assert.equal(nominees[0].isPrimary, true, 'the primary nominee must sort first');
    assert.equal(nominees.filter((nominee) => nominee.isPrimary).length, 1);

    for (const nominee of nominees) {
      assert.match(nominee._id, ID_HEX);
      assert.equal(nominee.fcmToken, undefined);
      assert.equal(nominee.userId, undefined);
      assert.equal(nominee.__v, undefined);
      assert.match(nominee.phone, /^\+919876577\d{3}$/);
    }

    assert.ok(!response.text.includes('fcm-secret-token-value'));
  });

  await record('list: a user with no nominees gets an empty list, not an error', async () => {
    const response = await call('/api/v1/nominees/list', { method: 'GET', token: bob.token });
    expectSuccess(response, 200);
    assert.deepEqual(response.body.data.nominees, []);
    assert.equal(response.body.data.count, 0);
    assert.equal(response.body.data.remainingSlots, 5);
  });

  // --- isolation / IDOR -----------------------------------------------------
  let bobNominee = null;

  await record('isolation: Bob adds a nominee and Alice cannot see it', async () => {
    const added = await call('/api/v1/nominees/add', {
      token: bob.token,
      body: { name: 'Bob Guardian', phone: '9876577301' },
    });

    expectSuccess(added, 201);
    bobNominee = added.body.data.nominee;

    const bobList = await call('/api/v1/nominees/list', { method: 'GET', token: bob.token });
    expectSuccess(bobList, 200);
    assert.equal(bobList.body.data.count, 1);

    const aliceList = await call('/api/v1/nominees/list', { method: 'GET', token: alice.token });
    expectSuccess(aliceList, 200);
    assert.ok(!aliceList.text.includes(bobNominee._id), 'Bob\'s nominee must not appear in Alice\'s list');
  });

  await record('IDOR: PATCH another user\'s nominee → 404 and the document is unchanged', async () => {
    const response = await call(`/api/v1/nominees/${bobNominee._id}`, {
      method: 'PATCH',
      token: alice.token,
      body: { name: 'Hijacked' },
    });

    expectError(response, 404);

    const stored = await Nominee.findById(bobNominee._id).lean();
    assert.equal(stored.name, 'Bob Guardian');
  });

  await record('IDOR: DELETE another user\'s nominee → 404 and the document survives', async () => {
    const response = await call(`/api/v1/nominees/remove/${bobNominee._id}`, {
      method: 'DELETE',
      token: alice.token,
    });

    expectError(response, 404);
    assert.equal(await Nominee.countDocuments({ _id: bobNominee._id }), 1);
  });

  // --- update ---------------------------------------------------------------
  const carol = await seedUser('+919876570003', 'Carol Owner');
  const carolNominees = [];

  await record('update: name and relation are persisted; phone is not editable', async () => {
    for (const suffix of ['7401', '7402', '7403']) {
      const added = await call('/api/v1/nominees/add', {
        token: carol.token,
        body: { name: `Carol Guardian ${suffix}`, phone: `987657${suffix}` },
      });
      expectSuccess(added, 201);
      carolNominees.push(added.body.data.nominee);
    }

    const renamed = await call(`/api/v1/nominees/${carolNominees[0]._id}`, {
      method: 'PATCH',
      token: carol.token,
      body: { name: 'Renamed Guardian', relation: 'Sister' },
    });

    expectSuccess(renamed, 200);
    assert.equal(renamed.body.data.nominee.name, 'Renamed Guardian');
    assert.equal(renamed.body.data.nominee.relation, 'Sister');
    assert.equal(renamed.body.data.nominee.isPrimary, true);

    const stored = await Nominee.findById(carolNominees[0]._id).lean();
    assert.equal(stored.name, 'Renamed Guardian');
    assert.equal(stored.relation, 'Sister');

    // `phone` is stripped by the schema, so this body has no updatable field.
    const phoneAttempt = await call(`/api/v1/nominees/${carolNominees[0]._id}`, {
      method: 'PATCH',
      token: carol.token,
      body: { phone: '9876599999' },
    });

    expectError(phoneAttempt, 400);
    assert.equal((await Nominee.findById(carolNominees[0]._id).lean()).phone, '+919876577401');

    const empty = await call(`/api/v1/nominees/${carolNominees[0]._id}`, {
      method: 'PATCH',
      token: carol.token,
      body: {},
    });
    expectError(empty, 400);
  });

  await record('update: promoting another nominee demotes the previous primary', async () => {
    const response = await call(`/api/v1/nominees/${carolNominees[1]._id}`, {
      method: 'PATCH',
      token: carol.token,
      body: { isPrimary: true },
    });

    expectSuccess(response, 200);
    assert.equal(response.body.data.nominee.isPrimary, true);

    const primaries = await Nominee.find({ userId: carol.id, isPrimary: true }).lean();
    assert.equal(primaries.length, 1);
    assert.equal(String(primaries[0]._id), carolNominees[1]._id);

    // Idempotent repeat.
    const again = await call(`/api/v1/nominees/${carolNominees[1]._id}`, {
      method: 'PATCH',
      token: carol.token,
      body: { isPrimary: true },
    });

    expectSuccess(again, 200);
    assert.equal(await Nominee.countDocuments({ userId: carol.id, isPrimary: true }), 1);
  });

  await record('update: demoting the only primary → 400 NOMINEE_PRIMARY_REQUIRED', async () => {
    const response = await call(`/api/v1/nominees/${carolNominees[1]._id}`, {
      method: 'PATCH',
      token: carol.token,
      body: { isPrimary: false },
    });

    expectError(response, 400, 'NOMINEE_PRIMARY_REQUIRED');
    assert.equal(await Nominee.countDocuments({ userId: carol.id, isPrimary: true }), 1);
  });

  await record('update: malformed id → 400 (no CastError), missing id → 404', async () => {
    const malformed = await call('/api/v1/nominees/not-an-object-id', {
      method: 'PATCH',
      token: carol.token,
      body: { name: 'Nope' },
    });

    expectError(malformed, 400);

    const missing = await call('/api/v1/nominees/507f1f77bcf86cd799439011', {
      method: 'PATCH',
      token: carol.token,
      body: { name: 'Nope' },
    });

    expectError(missing, 404);
  });

  // --- delete ---------------------------------------------------------------
  await record('delete: non-primary removal does not promote anyone', async () => {
    const response = await call(`/api/v1/nominees/remove/${carolNominees[2]._id}`, {
      method: 'DELETE',
      token: carol.token,
    });

    expectSuccess(response, 200);
    assert.equal(response.body.data.remaining, 2);
    assert.equal(response.body.data.promotedNomineeId, null);
    assert.equal(await Nominee.countDocuments({ userId: carol.id }), 2);
  });

  await record('delete: removing the primary promotes the oldest remaining nominee', async () => {
    const response = await call(`/api/v1/nominees/remove/${carolNominees[1]._id}`, {
      method: 'DELETE',
      token: carol.token,
    });

    expectSuccess(response, 200);
    assert.equal(response.body.data.promotedNomineeId, carolNominees[0]._id);
    assert.equal(response.body.data.promotedName, 'Renamed Guardian');

    const primaries = await Nominee.find({ userId: carol.id, isPrimary: true }).lean();
    assert.equal(primaries.length, 1);
    assert.equal(String(primaries[0]._id), carolNominees[0]._id);
  });

  await record('delete: removing the last nominee leaves an empty, valid list', async () => {
    const response = await call(`/api/v1/nominees/remove/${carolNominees[0]._id}`, {
      method: 'DELETE',
      token: carol.token,
    });

    expectSuccess(response, 200);
    assert.equal(response.body.data.remaining, 0);

    const list = await call('/api/v1/nominees/list', { method: 'GET', token: carol.token });
    expectSuccess(list, 200);
    assert.equal(list.body.data.count, 0);
  });

  await record('delete: malformed id → 400, unknown id → 404', async () => {
    const malformed = await call('/api/v1/nominees/remove/abc', { method: 'DELETE', token: carol.token });
    expectError(malformed, 400);

    const missing = await call('/api/v1/nominees/remove/507f1f77bcf86cd799439011', {
      method: 'DELETE',
      token: carol.token,
    });
    expectError(missing, 404);
  });

  // --- concurrency ----------------------------------------------------------
  await record('race: two simultaneous promotions leave exactly one primary', async () => {
    const dave = await seedUser('+919876570004', 'Dave Owner');
    const created = [];

    for (const suffix of ['7501', '7502']) {
      const added = await call('/api/v1/nominees/add', {
        token: dave.token,
        body: { name: `Dave Guardian ${suffix}`, phone: `987657${suffix}` },
      });
      expectSuccess(added, 201);
      created.push(added.body.data.nominee);
    }

    const [first, second] = await Promise.all([
      call(`/api/v1/nominees/${created[0]._id}`, {
        method: 'PATCH',
        token: dave.token,
        body: { isPrimary: true },
      }),
      call(`/api/v1/nominees/${created[1]._id}`, {
        method: 'PATCH',
        token: dave.token,
        body: { isPrimary: true },
      }),
    ]);

    assert.ok([200, 409].includes(first.status), `unexpected status ${first.status}`);
    assert.ok([200, 409].includes(second.status), `unexpected status ${second.status}`);

    const primaries = await Nominee.find({ userId: dave.id, isPrimary: true }).lean();
    assert.equal(primaries.length, 1, 'the one-primary invariant must survive the race');
  });

  await record('race: three simultaneous adds at the cap never exceed it, and never 500', async () => {
    const erin = await seedUser('+919876570005', 'Erin Owner');

    for (const suffix of ['7601', '7602', '7603', '7604']) {
      const added = await call('/api/v1/nominees/add', {
        token: erin.token,
        body: { name: `Erin Guardian ${suffix}`, phone: `987657${suffix}` },
      });
      expectSuccess(added, 201);
    }

    const responses = await Promise.all(
      ['7605', '7606', '7607'].map((suffix) =>
        call('/api/v1/nominees/add', {
          token: erin.token,
          body: { name: `Erin Race ${suffix}`, phone: `987657${suffix}` },
        })
      )
    );

    for (const response of responses) {
      assert.ok([201, 409].includes(response.status), `unexpected status ${response.status}: ${response.text}`);
    }

    const total = await Nominee.countDocuments({ userId: erin.id });
    assert.ok(total <= MAX, `cap exceeded: ${total} documents`);
    assert.ok(total >= MAX - 1, `cap should still be nearly full, got ${total}`);
  });
}

// ===========================================================================
// Model / index checks (in-process)
// ===========================================================================
async function runModelChecks() {
  const Nominee = require('../models/Nominee');

  await Nominee.init();

  await record('phone: an ambiguous bare number is rejected, never guessed into +98…', async () => {
    const { normalizePhone } = require('../utils/phone');

    // One extra digit: the regression this check exists for. Reading it as an
    // international number would notify a stranger in another country.
    assert.equal(normalizePhone('98765772208'), null);
    assert.equal(normalizePhone('098765772208'), null);

    assert.equal(normalizePhone('9876577220'), '+919876577220');
    assert.equal(normalizePhone('919876577220'), '+919876577220');
    assert.equal(normalizePhone('00919876577220'), '+919876577220');
    assert.equal(normalizePhone('+14155552671'), '+14155552671');
  });

  await record('model: compound unique index on { userId, phone }', async () => {
    const indexes = await Nominee.collection.indexes();
    const compound = indexes.find((index) => index.key && index.key.userId === 1 && index.key.phone === 1);

    assert.ok(compound, `no { userId, phone } index (${JSON.stringify(indexes.map((i) => i.key))})`);
    assert.equal(compound.unique, true);
  });

  await record('model: partial unique index allows only one primary per user', async () => {
    const indexes = await Nominee.collection.indexes();
    const partial = indexes.find((index) => index.name === 'one_primary_nominee_per_user');

    assert.ok(partial, 'the one-primary index is missing');
    assert.equal(partial.unique, true);
    assert.deepEqual(partial.key, { userId: 1 });
    assert.deepEqual(partial.partialFilterExpression, { isPrimary: true });
  });

  await record('model: the database itself rejects a second primary', async () => {
    const owner = await seedUser('+919876570006', 'Index Owner');

    await Nominee.create({
      userId: owner.user._id,
      name: 'Primary One',
      phone: '+919876577701',
      isPrimary: true,
    });

    await assert.rejects(
      () =>
        Nominee.create({
          userId: owner.user._id,
          name: 'Primary Two',
          phone: '+919876577702',
          isPrimary: true,
        }),
      (error) => error && error.code === 11_000
    );
  });

  await record('model: fcmToken is select:false and never appears in JSON', async () => {
    const owner = await seedUser('+919876570007', 'Token Owner');
    const nominee = await Nominee.create({
      userId: owner.user._id,
      name: 'Token Guardian',
      phone: '+919876577801',
      fcmToken: 'model-secret-token',
      isPrimary: true,
    });

    const plain = await Nominee.findById(nominee._id);
    assert.equal(plain.fcmToken, undefined);

    const explicit = await Nominee.findById(nominee._id).select('+fcmToken');
    assert.equal(explicit.fcmToken, 'model-secret-token');
    assert.equal(JSON.stringify(explicit.toJSON()).includes('model-secret-token'), false);
  });

  await record('model: duplicate phone for the same owner is rejected by the index', async () => {
    const owner = await seedUser('+919876570008', 'Dup Owner');

    await Nominee.create({ userId: owner.user._id, name: 'One', phone: '+919876577901' });

    await assert.rejects(
      () => Nominee.create({ userId: owner.user._id, name: 'Two', phone: '+919876577901' }),
      (error) => error && error.code === 11_000
    );

    // ...while a different owner may nominate the same person.
    const other = await seedUser('+919876570009', 'Other Owner');
    const shared = await Nominee.create({ userId: other.user._id, name: 'Shared', phone: '+919876577901' });
    assert.ok(shared._id);
  });

  await record('model: an invalid stored phone fails schema validation', async () => {
    const owner = await seedUser('+919876570010', 'Bad Phone Owner');

    await assert.rejects(
      () => Nominee.create({ userId: owner.user._id, name: 'Bad', phone: '98765' }),
      (error) => error.name === 'ValidationError'
    );
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
    instance: {
      dbName: 'guardfi-phase3-verify',
      launchTimeout: 90_000,
    },
  });

  const uri = mongo.getUri('guardfi-phase3-verify');
  process.env.MONGO_URI = uri;

  const { connectDatabase } = require('../config/db');
  await connectDatabase();

  try {
    console.log(`▶ Booting nominee API on port ${SERVER_PORT}...`);
    spawnServer({ uri });
    await waitForHealth();
    console.log('▶ Server healthy. Running HTTP checks...\n');
    await runHttpChecks();
  } catch (error) {
    results.push({ name: 'harness: server became healthy', ok: false, error: error.message });
  } finally {
    await stopServer();
  }

  await runModelChecks();

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
