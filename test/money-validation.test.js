// Automated proof that every money-amount field rejects 0, negative, and
// unrealistically large values (QA: several forms silently accepted a
// negative amount — e.g. a Supplier Payment of -50 raised the bank balance
// instead of lowering it; a Receipt of -100,000 drove Cash negative with no
// warning at all). Also proves the money-OUT endpoints that had no
// overdraft guard at all (Supplier Payment, Expense, Payout) now have one,
// and that Cheque clearing still enforces it.
//
// Requires the dev server to already be running (npm run dev) on
// http://localhost:3000, or override with ISOLATION_TEST_BASE_URL.
// Run with:  node --test test/money-validation.test.js
//
// Creates one throwaway admin/client and deletes all of it in `after()`,
// whether the tests pass or fail. Does not touch any existing real client.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const BASE = process.env.ISOLATION_TEST_BASE_URL || 'http://localhost:3000';
const SUPER_DATABASE_URL = process.env.BACKUP_DATABASE_URL || process.env.DATABASE_URL;
const superPool = new Pool({ connectionString: SUPER_DATABASE_URL });

const TEMP_PASSWORD = 'TempPass123!';
let adminId, adminUsername, clientId, cookie, bankId, investorId, partnerId, loanId;

function req(method, path, body) {
  return fetch(BASE + path, {
    method,
    headers: Object.assign({ 'Content-Type': 'application/json' }, cookie ? { Cookie: cookie } : {}),
    body: body !== undefined ? JSON.stringify(body) : undefined
  });
}
function cookieOf(res) {
  const raw = res.headers.get('set-cookie');
  if (!raw) return null;
  return raw.split(';')[0];
}
async function countRows(table) {
  const r = await superPool.query(`SELECT COUNT(*)::int AS c FROM ${table} WHERE client_id=$1`, [clientId]);
  return r.rows[0].c;
}
// shared shape for the "-1, 0, 1e12 all rejected, nothing created" check
async function assertAllRejected(table, path, bodyFor) {
  const before = await countRows(table);
  for (const bad of [-1, 0, 1e12]) {
    const r = await req('POST', path, bodyFor(bad));
    assert.equal(r.status, 400, `amount ${bad} on ${path} should be rejected`);
    assert.match((await r.json()).error, /greater than zero/i);
  }
  assert.equal(await countRows(table), before, `${path} must not create a row for a rejected amount`);
}

test.before(async () => {
  adminId = crypto.randomUUID();
  adminUsername = 'money_val_test_admin_' + Date.now();
  const hash = await bcrypt.hash(TEMP_PASSWORD, 10);
  await superPool.query(`INSERT INTO users (id, username, password_hash, role) VALUES ($1,$2,$3,'admin')`, [adminId, adminUsername, hash]);
  const login = await req('POST', '/api/auth/login', { username: adminUsername, password: TEMP_PASSWORD });
  assert.equal(login.status, 200);
  cookie = cookieOf(login);

  const c = await req('POST', '/api/clients', { name: 'Money Validation Test' });
  assert.equal(c.status, 200);
  clientId = (await c.json()).id;
  await req('POST', '/api/session/active-client', { clientId });
  await req('PATCH', '/api/settings', { openingCash: 500000 });
  const bank = await req('POST', '/api/banks', { name: 'MV Test Bank', openingBalance: 300000 });
  bankId = (await bank.json()).id;
  const inv = await req('POST', '/api/investors', { name: 'MV Investor', amount: 50000, account: 'cash' });
  investorId = (await inv.json()).id;
  const partner = await req('POST', '/api/partners', { name: 'MV Agent', openingProfit: 20000 });
  partnerId = (await partner.json()).id;
  const loan = await req('POST', '/api/personal-loans', { date: '2026-10-14', lender: 'MV Lender', amount: 10000, account: 'cash' });
  loanId = (await loan.json()).id;
});

test.after(async () => {
  try {
    if (clientId) await superPool.query('DELETE FROM clients WHERE id=$1', [clientId]);
    if (adminId) await superPool.query('DELETE FROM users WHERE id=$1', [adminId]);
  } finally {
    await superPool.end();
  }
});

test('Receipt: rejects -1/0/1e12, accepts a valid amount', async () => {
  await assertAllRejected('receipts', '/api/receipts', (amount) => ({ date: '2026-10-14', party: 'MV Buyer', amount, account: 'cash' }));
  const ok = await req('POST', '/api/receipts', { date: '2026-10-14', party: 'MV Buyer', amount: 1000, account: 'cash' });
  assert.equal(ok.status, 200);
  const row = await ok.json();
  await superPool.query('DELETE FROM receipts WHERE id=$1', [row.id]);
});

test('Edit Receipt: rejects -1/0/1e12 (amount unchanged), accepts a valid amount', async () => {
  const created = await req('POST', '/api/receipts', { date: '2026-10-14', party: 'MV Buyer', amount: 1000, account: 'cash' });
  const row = await created.json();
  for (const bad of [-1, 0, 1e12]) {
    const r = await req('PATCH', '/api/receipts/' + row.id, { date: '2026-10-14', party: 'MV Buyer', amount: bad, account: 'cash' });
    assert.equal(r.status, 400);
  }
  const check = await superPool.query('SELECT amount FROM receipts WHERE id=$1', [row.id]);
  assert.equal(Number(check.rows[0].amount), 1000, 'rejected edit must not change the stored amount');
  const ok = await req('PATCH', '/api/receipts/' + row.id, { date: '2026-10-14', party: 'MV Buyer', amount: 1500, account: 'cash' });
  assert.equal(ok.status, 200);
  await superPool.query('DELETE FROM receipts WHERE id=$1', [row.id]);
});

test('Supplier Payment: rejects -1/0/1e12 and an overdraft amount, accepts a valid amount', async () => {
  await assertAllRejected('supplier_payments', '/api/supplier-payments', (amount) => ({ date: '2026-10-14', supplier: 'MV Supplier', amount, account: 'cash' }));
  const before = await countRows('supplier_payments');
  const overdraft = await req('POST', '/api/supplier-payments', { date: '2026-10-14', supplier: 'MV Supplier', amount: 999999999, account: 'cash' });
  assert.equal(overdraft.status, 400, 'a positive but unaffordable amount must be rejected (no overdraft guard existed before)');
  assert.match((await overdraft.json()).error, /short|insufficient/i);
  assert.equal(await countRows('supplier_payments'), before);
  const ok = await req('POST', '/api/supplier-payments', { date: '2026-10-14', supplier: 'MV Supplier', amount: 1000, account: 'cash' });
  assert.equal(ok.status, 200);
  const row = await ok.json();
  await superPool.query('DELETE FROM supplier_payments WHERE id=$1', [row.id]);
});

test('Edit Supplier Payment: rejects -1/0/1e12 (amount unchanged), accepts a valid amount', async () => {
  const created = await req('POST', '/api/supplier-payments', { date: '2026-10-14', supplier: 'MV Supplier', amount: 1000, account: 'cash' });
  const row = await created.json();
  for (const bad of [-1, 0, 1e12]) {
    const r = await req('PATCH', '/api/supplier-payments/' + row.id, { date: '2026-10-14', supplier: 'MV Supplier', amount: bad, account: 'cash' });
    assert.equal(r.status, 400);
  }
  const check = await superPool.query('SELECT amount FROM supplier_payments WHERE id=$1', [row.id]);
  assert.equal(Number(check.rows[0].amount), 1000);
  const ok = await req('PATCH', '/api/supplier-payments/' + row.id, { date: '2026-10-14', supplier: 'MV Supplier', amount: 1200, account: 'cash' });
  assert.equal(ok.status, 200);
  await superPool.query('DELETE FROM supplier_payments WHERE id=$1', [row.id]);
});

test('Add Cheque: rejects -1/0/1e12, accepts a valid amount', async () => {
  await assertAllRejected('cheques', '/api/cheques', (amount) => ({ date: '2026-10-14', party: 'MV Cheque Party', amount, dueDate: '2026-11-01', direction: 'received' }));
  const ok = await req('POST', '/api/cheques', { date: '2026-10-14', party: 'MV Cheque Party', amount: 5000, dueDate: '2026-11-01', direction: 'received' });
  assert.equal(ok.status, 200);
  const row = await ok.json();
  await superPool.query('DELETE FROM cheques WHERE id=$1', [row.id]);
});

test('Edit Cheque: rejects -1/0/1e12 (amount unchanged), accepts a valid amount', async () => {
  const created = await req('POST', '/api/cheques', { date: '2026-10-14', party: 'MV Cheque Party', amount: 5000, dueDate: '2026-11-01', direction: 'received' });
  const row = await created.json();
  for (const bad of [-1, 0, 1e12]) {
    const r = await req('PATCH', '/api/cheques/' + row.id, { date: '2026-10-14', party: 'MV Cheque Party', amount: bad, dueDate: '2026-11-01', direction: 'received' });
    assert.equal(r.status, 400);
  }
  const check = await superPool.query('SELECT amount FROM cheques WHERE id=$1', [row.id]);
  assert.equal(Number(check.rows[0].amount), 5000);
  const ok = await req('PATCH', '/api/cheques/' + row.id, { date: '2026-10-14', party: 'MV Cheque Party', amount: 6000, dueDate: '2026-11-01', direction: 'received' });
  assert.equal(ok.status, 200);
  await superPool.query('DELETE FROM cheques WHERE id=$1', [row.id]);
});

test('Clear Cheque: a legacy negative-amount cheque is refused (defensive check), an issued cheque beyond funds is refused (overdraft)', async () => {
  // simulate pre-existing bad data directly (the API itself can no longer
  // create one) to prove the clear endpoint's own defensive check works.
  const badId = crypto.randomUUID();
  await superPool.query(
    `INSERT INTO cheques (id, client_id, date, party, amount, due_date, account_id, status, direction) VALUES ($1,$2,$3,$4,$5,$6,$7,'pending','received')`,
    [badId, clientId, '2026-10-14', 'MV Legacy Party', -500, '2026-11-01', 'cash']
  );
  const clearBad = await req('POST', '/api/cheques/' + badId + '/clear', {});
  assert.equal(clearBad.status, 400);
  const stillPending = await superPool.query('SELECT status FROM cheques WHERE id=$1', [badId]);
  assert.equal(stillPending.rows[0].status, 'pending', 'a cheque with an invalid stored amount must not be clearable');
  await superPool.query('DELETE FROM cheques WHERE id=$1', [badId]);

  // issued cheque larger than available funds must be refused, not clear
  // and drive the account negative.
  const issued = await req('POST', '/api/cheques', { date: '2026-10-14', party: 'MV Supplier Chq', amount: 999999999, dueDate: '2026-11-01', direction: 'issued' });
  const issuedRow = await issued.json();
  const clearIssued = await req('POST', '/api/cheques/' + issuedRow.id + '/clear', {});
  assert.equal(clearIssued.status, 400);
  assert.match((await clearIssued.json()).error, /short|insufficient/i);
  const stillPending2 = await superPool.query('SELECT status FROM cheques WHERE id=$1', [issuedRow.id]);
  assert.equal(stillPending2.rows[0].status, 'pending');
  await superPool.query('DELETE FROM cheques WHERE id=$1', [issuedRow.id]);
});

test('Expenses: rejects -1/0/1e12 and an overdraft amount, accepts a valid amount', async () => {
  await assertAllRejected('expenses', '/api/expenses', (amount) => ({ date: '2026-10-14', desc: 'MV Expense', amount, account: 'cash' }));
  const before = await countRows('expenses');
  const overdraft = await req('POST', '/api/expenses', { date: '2026-10-14', desc: 'MV Expense', amount: 999999999, account: 'cash' });
  assert.equal(overdraft.status, 400, 'a positive but unaffordable expense must be rejected (no overdraft guard existed before)');
  assert.equal(await countRows('expenses'), before);
  const ok = await req('POST', '/api/expenses', { date: '2026-10-14', desc: 'MV Expense', amount: 500, account: 'cash' });
  assert.equal(ok.status, 200);
  const row = await ok.json();
  await superPool.query('DELETE FROM expenses WHERE id=$1', [row.id]);
});

test('Edit Expense: rejects -1/0/1e12 (amount unchanged), accepts a valid amount', async () => {
  const created = await req('POST', '/api/expenses', { date: '2026-10-14', desc: 'MV Expense', amount: 500, account: 'cash' });
  const row = await created.json();
  for (const bad of [-1, 0, 1e12]) {
    const r = await req('PATCH', '/api/expenses/' + row.id, { date: '2026-10-14', desc: 'MV Expense', amount: bad, account: 'cash' });
    assert.equal(r.status, 400);
  }
  const check = await superPool.query('SELECT amount FROM expenses WHERE id=$1', [row.id]);
  assert.equal(Number(check.rows[0].amount), 500);
  const ok = await req('PATCH', '/api/expenses/' + row.id, { date: '2026-10-14', desc: 'MV Expense', amount: 600, account: 'cash' });
  assert.equal(ok.status, 200);
  await superPool.query('DELETE FROM expenses WHERE id=$1', [row.id]);
});

test('Personal Loan (take a loan): rejects -1/0/1e12, accepts a valid amount', async () => {
  await assertAllRejected('personal_loans', '/api/personal-loans', (amount) => ({ date: '2026-10-14', lender: 'MV Lender2', amount, account: 'cash' }));
  const ok = await req('POST', '/api/personal-loans', { date: '2026-10-14', lender: 'MV Lender2', amount: 2000, account: 'cash' });
  assert.equal(ok.status, 200);
  const row = await ok.json();
  await superPool.query('DELETE FROM personal_loans WHERE id=$1', [row.id]);
});

test('Personal Loan repayment (Payout): rejects -1/0/1e12 and an overdraft amount, accepts a valid amount', async () => {
  await assertAllRejected('payouts', '/api/payouts', (amount) => ({ date: '2026-10-14', recipientType: 'loan', recipientId: loanId, amount, account: 'cash' }));
  const before = await countRows('payouts');
  const overdraft = await req('POST', '/api/payouts', { date: '2026-10-14', recipientType: 'loan', recipientId: loanId, amount: 999999999, account: 'cash' });
  assert.equal(overdraft.status, 400, 'a positive but unaffordable payout must be rejected (no overdraft guard existed before)');
  assert.equal(await countRows('payouts'), before);
  const ok = await req('POST', '/api/payouts', { date: '2026-10-14', recipientType: 'loan', recipientId: loanId, amount: 100, account: 'cash' });
  assert.equal(ok.status, 200);
  const row = await ok.json();
  await superPool.query('DELETE FROM payouts WHERE id=$1', [row.id]);
});

test('Edit Payout: rejects -1/0/1e12 (amount unchanged), accepts a valid amount', async () => {
  const created = await req('POST', '/api/payouts', { date: '2026-10-14', recipientType: 'loan', recipientId: loanId, amount: 100, account: 'cash' });
  const row = await created.json();
  for (const bad of [-1, 0, 1e12]) {
    const r = await req('PATCH', '/api/payouts/' + row.id, { date: '2026-10-14', recipientId: loanId, amount: bad, account: 'cash' });
    assert.equal(r.status, 400);
  }
  const check = await superPool.query('SELECT amount FROM payouts WHERE id=$1', [row.id]);
  assert.equal(Number(check.rows[0].amount), 100);
  const ok = await req('PATCH', '/api/payouts/' + row.id, { date: '2026-10-14', recipientId: loanId, amount: 150, account: 'cash' });
  assert.equal(ok.status, 200);
  await superPool.query('DELETE FROM payouts WHERE id=$1', [row.id]);
});

test('Investor Payout: rejects -1/0/1e12, accepts a valid amount', async () => {
  await assertAllRejected('payouts', '/api/payouts', (amount) => ({ date: '2026-10-14', recipientType: 'investor', recipientId: investorId, amount, account: 'cash' }));
  const ok = await req('POST', '/api/payouts', { date: '2026-10-14', recipientType: 'investor', recipientId: investorId, amount: 100, account: 'cash' });
  assert.equal(ok.status, 200);
  const row = await ok.json();
  await superPool.query('DELETE FROM payouts WHERE id=$1', [row.id]);
});

test('Commission Agent Payout: rejects -1/0/1e12, accepts a valid amount', async () => {
  await assertAllRejected('payouts', '/api/payouts', (amount) => ({ date: '2026-10-14', recipientType: 'partner', recipientId: partnerId, amount, account: 'cash' }));
  const ok = await req('POST', '/api/payouts', { date: '2026-10-14', recipientType: 'partner', recipientId: partnerId, amount: 100, account: 'cash' });
  assert.equal(ok.status, 200);
  const row = await ok.json();
  await superPool.query('DELETE FROM payouts WHERE id=$1', [row.id]);
});

test('Investor (add): rejects -1/0/1e12, accepts a valid amount', async () => {
  await assertAllRejected('investors', '/api/investors', (amount) => ({ name: 'MV Investor2', amount, account: 'cash' }));
  const ok = await req('POST', '/api/investors', { name: 'MV Investor2', amount: 1000, account: 'cash' });
  assert.equal(ok.status, 200);
  const row = await ok.json();
  await superPool.query('DELETE FROM investors WHERE id=$1', [row.id]);
});

test('Edit Investor: rejects -1/0/1e12 (amount unchanged), accepts a valid amount', async () => {
  const created = await req('POST', '/api/investors', { name: 'MV Investor3', amount: 1000, account: 'cash' });
  const row = await created.json();
  for (const bad of [-1, 0, 1e12]) {
    const r = await req('PATCH', '/api/investors/' + row.id, { name: 'MV Investor3', amount: bad, account: 'cash' });
    assert.equal(r.status, 400);
  }
  const check = await superPool.query('SELECT amount FROM investors WHERE id=$1', [row.id]);
  assert.equal(Number(check.rows[0].amount), 1000);
  const ok = await req('PATCH', '/api/investors/' + row.id, { name: 'MV Investor3', amount: 1200, account: 'cash' });
  assert.equal(ok.status, 200);
  await superPool.query('DELETE FROM investors WHERE id=$1', [row.id]);
});

test('Commission Agent (add): rejects a negative opening balance, accepts zero and a positive amount', async () => {
  const before = await countRows('partners');
  const negative = await req('POST', '/api/partners', { name: 'MV Agent Bad', openingProfit: -1 });
  assert.equal(negative.status, 400);
  assert.equal(await countRows('partners'), before);
  // zero IS valid for an opening balance (no prior history) -- unlike the
  // strict transaction-amount fields above.
  const zero = await req('POST', '/api/partners', { name: 'MV Agent Zero', openingProfit: 0 });
  assert.equal(zero.status, 200);
  const zeroRow = await zero.json();
  await superPool.query('DELETE FROM partners WHERE id=$1', [zeroRow.id]);
  const huge = await req('POST', '/api/partners', { name: 'MV Agent Huge', openingProfit: 1e12 });
  assert.equal(huge.status, 400);
  const ok = await req('POST', '/api/partners', { name: 'MV Agent OK', openingProfit: 5000 });
  assert.equal(ok.status, 200);
  const row = await ok.json();
  await superPool.query('DELETE FROM partners WHERE id=$1', [row.id]);
});
