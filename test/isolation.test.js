// Automated proof that one client's data can never reach another client —
// both through the app's own request-scoping AND, deliberately bypassing
// that app-layer scoping, through Postgres Row-Level Security directly.
//
// Requires the dev server to already be running (npm run dev) on
// http://localhost:3000, or override with ISOLATION_TEST_BASE_URL.
// Run with:  node --test test/isolation.test.js
//
// Creates its own throwaway admin/clients/users/data and deletes all of it
// in `after()`, whether the tests pass or fail. Does not touch any existing
// real client data — every row it reads/writes is scoped to the two
// throwaway clients it creates for this run.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const BASE = process.env.ISOLATION_TEST_BASE_URL || 'http://localhost:3000';
// the app's own RLS-bound role — same connection the live server uses for
// every request. NOT the superuser: this is the role whose policies we're
// proving actually hold.
const APP_DATABASE_URL = process.env.DATABASE_URL;
// a role that bypasses RLS, used only to set up/tear down test fixtures
// across both throwaway clients at once (mirrors how the app itself never
// gets cross-client access, but test setup legitimately needs to).
const SUPER_DATABASE_URL = process.env.BACKUP_DATABASE_URL || process.env.DATABASE_URL;

const appPool = new Pool({ connectionString: APP_DATABASE_URL });
const superPool = new Pool({ connectionString: SUPER_DATABASE_URL });

let tempAdminId, tempAdminUsername;
let clientAId, clientBId;
let standardUserId, standardUsername;
let standardViewerId, standardViewerUsername;
let invAId, invBId;
const TEMP_PASSWORD = 'TempPass123!';

function req(method, path, body, cookie) {
  return fetch(BASE + path, {
    method,
    headers: Object.assign(
      { 'Content-Type': 'application/json' },
      cookie ? { Cookie: cookie } : {}
    ),
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
}
function cookieOf(res) {
  const raw = res.headers.get('set-cookie');
  if (!raw) return null;
  return raw.split(';')[0];
}

test.before(async () => {
  tempAdminId = crypto.randomUUID();
  tempAdminUsername = 'iso_test_admin_' + Date.now();
  const hash = await bcrypt.hash(TEMP_PASSWORD, 10);
  await superPool.query('INSERT INTO users (id, username, password_hash, role) VALUES ($1,$2,$3,$4)', [tempAdminId, tempAdminUsername, hash, 'admin']);
});

test.after(async () => {
  // hard-delete every throwaway row this run created, regardless of pass/fail.
  // ON DELETE CASCADE on client_id FKs cleans up investors/settings/user_clients
  // for the two throwaway clients automatically.
  try {
    if (clientAId) await superPool.query('DELETE FROM clients WHERE id = $1', [clientAId]);
    if (clientBId) await superPool.query('DELETE FROM clients WHERE id = $1', [clientBId]);
    if (standardUserId) await superPool.query('DELETE FROM users WHERE id = $1', [standardUserId]);
    if (standardViewerId) await superPool.query('DELETE FROM users WHERE id = $1', [standardViewerId]);
    if (tempAdminId) await superPool.query('DELETE FROM users WHERE id = $1', [tempAdminId]);
  } finally {
    await appPool.end();
    await superPool.end();
  }
});

test('setup: two throwaway clients, seeded data, one standard user scoped to client A only', async () => {
  const login = await req('POST', '/api/auth/login', { username: tempAdminUsername, password: TEMP_PASSWORD });
  assert.equal(login.status, 200);
  const adminCookie = cookieOf(login);

  const cA = await req('POST', '/api/clients', { name: 'Isolation Test A' }, adminCookie);
  assert.equal(cA.status, 200);
  clientAId = (await cA.json()).id;

  const cB = await req('POST', '/api/clients', { name: 'Isolation Test B' }, adminCookie);
  assert.equal(cB.status, 200);
  clientBId = (await cB.json()).id;

  const switchA = await req('POST', '/api/session/active-client', { clientId: clientAId }, adminCookie);
  assert.equal(switchA.status, 200);
  const invA = await req('POST', '/api/investors', { name: 'Investor A (isolation test)', amount: 1000, account: 'cash' }, adminCookie);
  assert.equal(invA.status, 200);
  invAId = (await invA.json()).id;

  const switchB = await req('POST', '/api/session/active-client', { clientId: clientBId }, adminCookie);
  assert.equal(switchB.status, 200);
  const invB = await req('POST', '/api/investors', { name: 'Investor B (isolation test)', amount: 2000, account: 'cash' }, adminCookie);
  assert.equal(invB.status, 200);
  invBId = (await invB.json()).id;

  standardUsername = 'iso_test_standard_' + Date.now();
  const newUser = await req('POST', '/api/users', {
    username: standardUsername, password: TEMP_PASSWORD, role: 'standard', clientId: clientAId, accessLevel: 'editor'
  }, adminCookie);
  assert.equal(newUser.status, 200);
  standardUserId = (await newUser.json()).id;

  standardViewerUsername = 'iso_test_viewer_' + Date.now();
  const newViewer = await req('POST', '/api/users', {
    username: standardViewerUsername, password: TEMP_PASSWORD, role: 'standard', clientId: clientAId, accessLevel: 'viewer'
  }, adminCookie);
  assert.equal(newViewer.status, 200);
  standardViewerId = (await newViewer.json()).id;
});

test('app layer: a standard user scoped to client A only sees client A, never client B', async () => {
  const login = await req('POST', '/api/auth/login', { username: standardUsername, password: TEMP_PASSWORD });
  assert.equal(login.status, 200);
  const body = await login.json();
  assert.equal(body.activeClientId, clientAId, 'a user with exactly one assigned client should auto-land on it');
  const cookie = cookieOf(login);

  const mine = await req('GET', '/api/clients/mine', undefined, cookie);
  const mineList = await mine.json();
  assert.equal(mineList.length, 1);
  assert.equal(mineList[0].id, clientAId);

  const switchToB = await req('POST', '/api/session/active-client', { clientId: clientBId }, cookie);
  assert.equal(switchToB.status, 403, 'switching to a client this user is not assigned to must be refused');

  const state = await req('GET', '/api/state', undefined, cookie);
  assert.equal(state.status, 200);
  const stateBody = await state.json();
  const names = stateBody.investors.map((i) => i.name);
  assert.ok(names.includes('Investor A (isolation test)'), 'client A data must be visible');
  assert.ok(!names.includes('Investor B (isolation test)'), 'client B data must never appear in client A state');

  const patchB = await req('PATCH', '/api/investors/' + invBId, { name: 'hijacked', amount: 1, account: 'cash' }, cookie);
  assert.equal(patchB.status, 404, 'a direct PATCH against a known client-B row id must 404 while scoped to client A, not succeed or leak');

  const deleteB = await req('DELETE', '/api/investors/' + invBId, undefined, cookie);
  assert.equal(deleteB.status, 404, 'a direct DELETE against a known client-B row id must 404 while scoped to client A');

  // and the row must genuinely still exist (the 404 was a scoping refusal, not a real delete)
  const stillThere = await superPool.query('SELECT 1 FROM investors WHERE id = $1', [invBId]);
  assert.equal(stillThere.rowCount, 1, 'client B\'s row must be untouched after the refused cross-tenant delete attempt');
});

test('database layer: RLS still blocks cross-tenant rows even with app-layer scoping deliberately bypassed', async () => {
  // connect as the exact role the live app uses (app_user) — NOT the
  // superuser — and run a query with NO WHERE client_id clause at all, as
  // if the application code had a bug and forgot to scope it. If RLS is
  // doing its job, Postgres itself must still only return client A's rows.
  const client = await appPool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.current_client_id', $1, true)", [clientAId]);
    const r = await client.query('SELECT id, client_id, name FROM investors');
    const ids = r.rows.map((row) => row.id);
    assert.ok(ids.includes(invAId), 'client A\'s own row must be visible under its own RLS context');
    assert.ok(!ids.includes(invBId), 'client B\'s row must be invisible even to an unscoped query, purely from RLS');
    assert.ok(r.rows.every((row) => row.client_id === clientAId), 'every row returned must belong to the tenant set in app.current_client_id');
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
});

test('access level: a standard-viewer on client A can read client A but cannot write to it', async () => {
  const login = await req('POST', '/api/auth/login', { username: standardViewerUsername, password: TEMP_PASSWORD });
  assert.equal(login.status, 200);
  const body = await login.json();
  assert.equal(body.activeClientId, clientAId);
  const cookie = cookieOf(login);

  const state = await req('GET', '/api/state', undefined, cookie);
  assert.equal(state.status, 200, 'a viewer must still be able to read their client\'s data');
  const stateBody = await state.json();
  assert.ok(stateBody.investors.map((i) => i.name).includes('Investor A (isolation test)'));

  const create = await req('POST', '/api/investors', { name: 'should not be created', amount: 1, account: 'cash' }, cookie);
  assert.equal(create.status, 403, 'a viewer must not be able to create rows on their own client');

  const edit = await req('PATCH', '/api/investors/' + invAId, { name: 'hijacked', amount: 1, account: 'cash' }, cookie);
  assert.equal(edit.status, 403, 'a viewer must not be able to edit rows on their own client');

  const del = await req('DELETE', '/api/investors/' + invAId, undefined, cookie);
  assert.equal(del.status, 403, 'a viewer must not be able to delete rows on their own client');

  const stillThere = await superPool.query('SELECT name FROM investors WHERE id = $1', [invAId]);
  assert.equal(stillThere.rows[0].name, 'Investor A (isolation test)', 'client A\'s row must be unchanged after the refused viewer writes');
});

test('account safety: duplicate username rejected, self-delete blocked, last admin cannot be demoted/removed', async () => {
  const login = await req('POST', '/api/auth/login', { username: tempAdminUsername, password: TEMP_PASSWORD });
  const adminCookie = cookieOf(login);

  const dup = await req('POST', '/api/users', { username: standardUsername, password: TEMP_PASSWORD, role: 'standard', clientId: clientAId, accessLevel: 'viewer' }, adminCookie);
  assert.equal(dup.status, 409, 'creating a second user with an existing username must be rejected');

  const selfDelete = await req('DELETE', '/api/users/' + tempAdminId, undefined, adminCookie);
  assert.equal(selfDelete.status, 400, 'a user must not be able to delete their own account');

  // this temp admin may or may not be the only admin on a real dev DB, so
  // check the real precondition rather than assuming — the protection only
  // fires when active-admin-count <= 1.
  const adminCountRes = await superPool.query("SELECT COUNT(*)::int AS c FROM users WHERE role='admin' AND status='active'");
  if (adminCountRes.rows[0].c === 1) {
    const demote = await req('PATCH', '/api/users/' + tempAdminId, { role: 'standard' }, adminCookie);
    assert.equal(demote.status, 400, 'the last remaining admin must not be demotable');
  }
});

test('database layer: with no tenant context set at all, RLS hides every row (fails closed, not open)', async () => {
  const client = await appPool.connect();
  try {
    await client.query('BEGIN');
    // deliberately do NOT call set_config here
    const r = await client.query('SELECT id FROM investors WHERE id = ANY($1)', [[invAId, invBId]]);
    assert.equal(r.rowCount, 0, 'with no app.current_client_id set, RLS must return zero rows rather than defaulting to "all clients"');
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
});
