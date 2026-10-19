const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const cron = require('node-cron');
const { Pool, types } = require('pg');
const pgSession = require('connect-pg-simple')(session);
require('dotenv').config();

const PG_DUMP_BIN = process.env.PG_DUMP_BIN || 'pg_dump';
const PG_RESTORE_BIN = process.env.PG_RESTORE_BIN || 'pg_restore';
// pg_dump/pg_restore for whole-database backups must connect as a role that
// BYPASSES Row-Level Security (a superuser, typically) — app_user's FORCE
// ROW LEVEL SECURITY correctly blocks it from ever seeing more than one
// client's rows per request, but a backup legitimately needs every client's
// data at once. Falls back to DATABASE_URL if unset, which will fail loudly
// (not silently under-back-up) against an RLS-forced role — see .env.example.
const BACKUP_DATABASE_URL = process.env.BACKUP_DATABASE_URL || process.env.DATABASE_URL;

// return DATE columns as plain 'YYYY-MM-DD' strings and NUMERIC columns as
// JS numbers, so the frontend never has to deal with pg's Date objects /
// numeric-as-string quirks.
types.setTypeParser(1082, (val) => val); // date
types.setTypeParser(1700, (val) => (val === null ? null : parseFloat(val))); // numeric

const app = express();
const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/yarn_manager';
const SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  console.error('SESSION_SECRET is not set. Copy .env.example to .env and set a random value.');
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL });

app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(
  session({
    store: new pgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
    name: 'dhaaga.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production',
      maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
    }
  })
);
app.use(express.static(__dirname));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  next();
}
// global admin: every client + Settings (Clients/Users/Backup tabs). Not client-scoped.
function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

// resolves which client the request operates on (req.clientId) from the
// caller's session. Must run after requireAuth, before any tenant-table query.
function resolveActiveClient(req, res, next) {
  const clientId = req.session.user.activeClientId;
  if (!clientId) return res.status(400).json({ error: 'No active client selected' });
  req.clientId = clientId;
  next();
}
// checks the caller may access req.clientId at least at `minLevel`
// ('viewer' or 'editor'). Global admins always pass. Must run after
// resolveActiveClient.
function requireClientAccess(minLevel) {
  return async (req, res, next) => {
    if (req.session.user.role === 'admin') return next();
    try {
      const r = await pool.query(
        'SELECT access_level FROM user_clients WHERE user_id = $1 AND client_id = $2',
        [req.session.user.id, req.clientId]
      );
      const level = r.rows[0] && r.rows[0].access_level;
      if (!level) return res.status(403).json({ error: 'No access to this client' });
      if (minLevel === 'editor' && level !== 'editor') return res.status(403).json({ error: 'Read-only access to this client' });
      next();
    } catch (err) {
      console.error('requireClientAccess error:', err);
      res.status(500).json({ error: 'Unable to verify access' });
    }
  };
}
// Runs `fn(client)` inside a transaction with the RLS session variable set
// for that transaction only (SET LOCAL resets automatically at COMMIT/
// ROLLBACK, so it can never leak into a pooled connection reused by a
// different request/tenant afterwards). Use set_config(), not a literal
// SET LOCAL string, so the client_id is a bound parameter, not interpolated SQL.
async function withTenantDb(clientId, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SELECT set_config('app.current_client_id', $1, true)", [clientId]);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}
// picks the client a freshly-logged-in user should land on: their only
// assigned client if there's exactly one (covers today's real usage), else
// null (frontend must show the client switcher before anything loads).
async function resolveInitialClientId(userId, role) {
  if (role === 'admin') {
    const r = await pool.query("SELECT id FROM clients WHERE status = 'active' ORDER BY client_number LIMIT 2");
    return r.rows.length === 1 ? r.rows[0].id : null;
  }
  const r = await pool.query('SELECT client_id FROM user_clients WHERE user_id = $1 LIMIT 2', [userId]);
  return r.rows.length === 1 ? r.rows[0].client_id : null;
}

// ---------- backups (whole-database, global — not client-scoped; admin-only) ----------
function backupDir(location) {
  const dir = path.isAbsolute(location) ? location : path.join(__dirname, location);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}
async function getBackupSettings() {
  const r = await pool.query('SELECT * FROM backup_settings WHERE id = 1');
  return r.rows[0];
}
function runPgDumpToFile(file) {
  return new Promise((resolve, reject) => {
    const url = new URL(BACKUP_DATABASE_URL);
    const dbName = url.pathname.replace(/^\//, '');
    const args = ['-Fc', '-h', url.hostname, '-p', url.port || '5432', '-U', url.username, '-d', dbName, '-f', file];
    const child = spawn(PG_DUMP_BIN, args, { env: { ...process.env, PGPASSWORD: url.password } });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (code) => { code === 0 ? resolve() : reject(new Error(stderr || `pg_dump exited with code ${code}`)); });
  });
}
const GIT_BIN = process.env.GIT_BIN || 'git';
function runGit(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(GIT_BIN, args, { cwd: __dirname });
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (code) => { code === 0 ? resolve(stdout) : reject(Object.assign(new Error(stderr || stdout || `git ${args[0]} exited with code ${code}`), { code })); });
  });
}
async function backupSourceCode() {
  await runGit(['add', '-A']);
  const stamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  let committed = true;
  try {
    await runGit(['commit', '-m', `Source backup ${stamp}`]);
  } catch (err) {
    // "nothing to commit" is not a failure — it just means no source files
    // changed since the last backup. Anything else (e.g. no git identity
    // configured) is a real error and should surface to the user.
    if (/nothing to commit/i.test(err.message)) { committed = false; } else { throw err; }
  }
  await runGit(['push']);
  return { committed };
}
function runPgRestoreFromFile(file) {
  return new Promise((resolve, reject) => {
    const url = new URL(BACKUP_DATABASE_URL);
    const dbName = url.pathname.replace(/^\//, '');
    const args = ['--clean', '--if-exists', '-h', url.hostname, '-p', url.port || '5432', '-U', url.username, '-d', dbName, file];
    const child = spawn(PG_RESTORE_BIN, args, { env: { ...process.env, PGPASSWORD: url.password } });
    let stderr = '';
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', reject);
    // pg_restore commonly exits non-zero on benign warnings (e.g. "does not
    // exist, skipping" during --clean) even on an otherwise-successful
    // restore — surface stderr as a warning rather than failing the request.
    child.on('close', (code) => resolve({ warnings: code === 0 ? null : stderr }));
  });
}
async function pruneOldBackups(retentionCount) {
  const r = await pool.query("SELECT id, location FROM backups WHERE status='success' ORDER BY created_at DESC OFFSET $1", [retentionCount]);
  for (const row of r.rows) {
    try { if (row.location && fs.existsSync(row.location)) fs.unlinkSync(row.location); } catch (e) { /* ignore */ }
    await pool.query('DELETE FROM backups WHERE id = $1', [row.id]);
  }
}
async function takeBackup(type) {
  const settings = await getBackupSettings();
  const dir = backupDir(settings.location);
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  // this is a whole-database dump (every client, not just one) — name the
  // file after every active client it actually contains, so a downloaded
  // backup is identifiable at a glance instead of just "manual_<timestamp>".
  // Prefer each client's own short display name (Settings > Preferences >
  // Company Name) over its full registered name, since that's what keeps
  // this readable once there's more than one or two clients. settings is
  // RLS-protected per-client, so each one must be read under its own tenant
  // context (same pattern GET /api/clients uses for reading every client's
  // theme) — the pool's own app_user role sees zero rows otherwise.
  const clients = await pool.query("SELECT id, name FROM clients WHERE status = 'active' ORDER BY client_number");
  const labels = await Promise.all(clients.rows.map(async (c) => {
    const s = await withTenantDb(c.id, (db) => db.query('SELECT company_name FROM settings WHERE client_id = $1', [c.id]));
    const companyName = s.rows[0] ? s.rows[0].company_name : null;
    return (companyName && companyName.trim()) || c.name;
  }));
  const clientPart = labels
    .map((label) => label.trim().replace(/[\\/:*?"<>|]/g, ''))
    .filter(Boolean)
    .join(' & ') || 'AllClients';
  const file = path.join(dir, `${clientPart} - ${type} - ${stamp}.dump`);
  const id = crypto.randomUUID();
  try {
    await runPgDumpToFile(file);
    const size = fs.statSync(file).size;
    await pool.query('INSERT INTO backups (id, type, status, file_size, location) VALUES ($1,$2,$3,$4,$5)', [id, type, 'success', size, file]);
    await pruneOldBackups(settings.retention_count);
    return { id, status: 'success', fileSize: size };
  } catch (err) {
    await pool.query('INSERT INTO backups (id, type, status, error_message) VALUES ($1,$2,$3,$4)', [id, type, 'failed', err.message]);
    throw err;
  }
}
let scheduledBackupTask = null;
function cronExpressionFor(frequency, timeOfDay) {
  const [hh, mm] = (timeOfDay || '02:00').split(':').map((n) => parseInt(n, 10) || 0);
  if (frequency === 'hourly') return `${mm} * * * *`;
  if (frequency === 'weekly') return `${mm} ${hh} * * 0`;
  if (frequency === 'monthly') return `${mm} ${hh} 1 * *`;
  return `${mm} ${hh} * * *`; // daily
}
async function rescheduleBackupCron() {
  if (scheduledBackupTask) { scheduledBackupTask.stop(); scheduledBackupTask = null; }
  const settings = await getBackupSettings();
  if (!settings.schedule_enabled) return;
  scheduledBackupTask = cron.schedule(
    cronExpressionFor(settings.frequency, settings.time_of_day),
    () => { takeBackup('scheduled').catch((err) => console.error('Scheduled backup failed:', err.message)); },
    { timezone: settings.timezone || 'Asia/Karachi' }
  );
}

async function ensureSchema() {
  // Phase 1 (safe, runs on every boot): create the new SaaS tables if missing,
  // and add client_id as a NULLABLE column to every existing business table.
  // This must NOT enable RLS or add NOT NULL/FK constraints here — the
  // currently-running single-tenant database still has rows with no
  // client_id, and this function runs unconditionally on every server start.
  // The actual cutover (backfill client_id, enforce NOT NULL, enable RLS,
  // convert user roles) is a separate, explicitly-run, reviewed step —
  // see migrate-to-saas.js. Do not merge that logic into this function.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin','viewer')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

    CREATE TABLE IF NOT EXISTS clients (
      id TEXT PRIMARY KEY,
      client_number SERIAL UNIQUE,
      name TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS user_clients (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      access_level TEXT NOT NULL CHECK (access_level IN ('editor','viewer')),
      PRIMARY KEY (user_id, client_id)
    );
    -- parties: SaaS-native table (no legacy single-tenant shape to preserve),
    -- created client_id-scoped and RLS-enabled directly below.
    CREATE TABLE IF NOT EXISTS parties (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      opening_balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      UNIQUE (client_id, name)
    );
    ALTER TABLE parties ADD COLUMN IF NOT EXISTS due_date DATE;
    DO $do2$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'parties' AND relrowsecurity) THEN
        ALTER TABLE parties ENABLE ROW LEVEL SECURITY;
        ALTER TABLE parties FORCE ROW LEVEL SECURITY;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'parties' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON parties
          USING (client_id = current_setting('app.current_client_id', true))
          WITH CHECK (client_id = current_setting('app.current_client_id', true));
      END IF;
    END $do2$;
    CREATE TABLE IF NOT EXISTS suppliers (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      opening_balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      UNIQUE (client_id, name)
    );
    ALTER TABLE suppliers ADD COLUMN IF NOT EXISTS due_date DATE;
    DO $do3$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'suppliers' AND relrowsecurity) THEN
        ALTER TABLE suppliers ENABLE ROW LEVEL SECURITY;
        ALTER TABLE suppliers FORCE ROW LEVEL SECURITY;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'suppliers' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON suppliers
          USING (client_id = current_setting('app.current_client_id', true))
          WITH CHECK (client_id = current_setting('app.current_client_id', true));
      END IF;
    END $do3$;
    -- supplier_payments: pooled payments against a supplier's credit purchases
    -- (payable side), mirrors receipts (pooled payments against a buyer's
    -- credit sales / receivable side) exactly.
    CREATE TABLE IF NOT EXISTS supplier_payments (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      supplier TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      account_id TEXT NOT NULL DEFAULT 'cash',
      note TEXT
    );
    DO $do4$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'supplier_payments' AND relrowsecurity) THEN
        ALTER TABLE supplier_payments ENABLE ROW LEVEL SECURITY;
        ALTER TABLE supplier_payments FORCE ROW LEVEL SECURITY;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'supplier_payments' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON supplier_payments
          USING (client_id = current_setting('app.current_client_id', true))
          WITH CHECK (client_id = current_setting('app.current_client_id', true));
      END IF;
    END $do4$;
    -- transfers: moving money between the client's own cash/bank accounts —
    -- affects each account's running balance but is not income or expense.
    CREATE TABLE IF NOT EXISTS transfers (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      from_account TEXT NOT NULL,
      to_account TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      note TEXT
    );
    ALTER TABLE transfers ADD COLUMN IF NOT EXISTS funding_transfer_ids TEXT;
    ALTER TABLE transfers ADD COLUMN IF NOT EXISTS funding_loan_ids TEXT;
    DO $do5$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'transfers' AND relrowsecurity) THEN
        ALTER TABLE transfers ENABLE ROW LEVEL SECURITY;
        ALTER TABLE transfers FORCE ROW LEVEL SECURITY;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'transfers' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON transfers
          USING (client_id = current_setting('app.current_client_id', true))
          WITH CHECK (client_id = current_setting('app.current_client_id', true));
      END IF;
    END $do5$;
    -- personal_loans: money a person (not a tracked investor) put in on the
    -- spot to cover a shortfall in an account — a liability the business
    -- owes back to that person, separate from Total Investment. Repayments
    -- reuse the payouts table (recipient_type='loan').
    CREATE TABLE IF NOT EXISTS personal_loans (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      lender TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      account_id TEXT NOT NULL DEFAULT 'cash',
      note TEXT
    );
    DO $do6$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'personal_loans' AND relrowsecurity) THEN
        ALTER TABLE personal_loans ENABLE ROW LEVEL SECURITY;
        ALTER TABLE personal_loans FORCE ROW LEVEL SECURITY;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'personal_loans' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON personal_loans
          USING (client_id = current_setting('app.current_client_id', true))
          WITH CHECK (client_id = current_setting('app.current_client_id', true));
      END IF;
    END $do6$;
    -- trade_summaries: a saved snapshot of the Dashboard's Trade Summary
    -- (Total Sales − Total Purchases, plus the commission figures shown
    -- alongside it) for a chosen period ('month' or 'all'), so a past
    -- summary can be looked back at or sent on even after today's live
    -- numbers have moved. Pure record-keeping — no stock/balance side effects.
    CREATE TABLE IF NOT EXISTS trade_summaries (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      period TEXT NOT NULL CHECK (period IN ('month','all')),
      period_label TEXT NOT NULL,
      sales NUMERIC(14,2) NOT NULL,
      purchases NUMERIC(14,2) NOT NULL,
      commission_new NUMERIC(14,2) NOT NULL DEFAULT 0,
      commission_opening NUMERIC(14,2) NOT NULL DEFAULT 0,
      profit NUMERIC(14,2) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    -- expenses: the business Expenses total for this snapshot's period —
    -- displayed as its own reference line (profit itself stays Sales −
    -- Purchases only). NULL for summaries saved before this column existed.
    ALTER TABLE trade_summaries ADD COLUMN IF NOT EXISTS expenses NUMERIC(14,2);
    DO $do7$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'trade_summaries' AND relrowsecurity) THEN
        ALTER TABLE trade_summaries ENABLE ROW LEVEL SECURITY;
        ALTER TABLE trade_summaries FORCE ROW LEVEL SECURITY;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'trade_summaries' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON trade_summaries
          USING (client_id = current_setting('app.current_client_id', true))
          WITH CHECK (client_id = current_setting('app.current_client_id', true));
      END IF;
    END $do7$;
    -- investor_summaries: a saved per-investor snapshot (investment, profit
    -- share, expense share, paid out, net balance owed) for a chosen period
    -- ('month' or 'all'), so a summary can be sent to that specific investor
    -- and still match what they were shown even after live numbers move.
    -- investor_name is captured at save time (not just investor_id) so the
    -- record stays meaningful even if that investor is later removed/renamed.
    CREATE TABLE IF NOT EXISTS investor_summaries (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      investor_id TEXT,
      investor_name TEXT NOT NULL,
      date DATE NOT NULL,
      period TEXT NOT NULL CHECK (period IN ('month','all')),
      period_label TEXT NOT NULL,
      investment NUMERIC(14,2) NOT NULL,
      profit_share NUMERIC(14,2) NOT NULL,
      expense_share NUMERIC(14,2) NOT NULL,
      paid_out NUMERIC(14,2) NOT NULL,
      net_owed NUMERIC(14,2) NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    -- expense_share/profit_share/investment/paid_out/net_owed above are the
    -- TOTALS (kept for simple queries and as a fallback display for rows
    -- saved before the "rows" column existed). expense_share_month/all are
    -- legacy columns from an earlier iteration of this feature, kept for
    -- backward compatibility only — new saves default them to 0 and rely on
    -- "rows" instead.
    ALTER TABLE investor_summaries ADD COLUMN IF NOT EXISTS expense_share_month NUMERIC(14,2) NOT NULL DEFAULT 0;
    ALTER TABLE investor_summaries ADD COLUMN IF NOT EXISTS expense_share_all NUMERIC(14,2) NOT NULL DEFAULT 0;
    -- rows: the full per-investor breakdown at save time (name, investment,
    -- % of total, deposited-into, expense share, net profit, paid out, net
    -- owed) — one element for a single-investor save, one per investor for
    -- an "All Investors" save — so the saved/downloaded summary can be
    -- rendered as the same table the Investors List itself shows. NULL for
    -- rows saved before this column existed; the frontend falls back to the
    -- flat totals columns above for those.
    ALTER TABLE investor_summaries ADD COLUMN IF NOT EXISTS rows JSONB;
    DO $do8$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'investor_summaries' AND relrowsecurity) THEN
        ALTER TABLE investor_summaries ENABLE ROW LEVEL SECURITY;
        ALTER TABLE investor_summaries FORCE ROW LEVEL SECURITY;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'investor_summaries' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON investor_summaries
          USING (client_id = current_setting('app.current_client_id', true))
          WITH CHECK (client_id = current_setting('app.current_client_id', true));
      END IF;
    END $do8$;
    CREATE TABLE IF NOT EXISTS backups (
      id TEXT PRIMARY KEY,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      type TEXT NOT NULL CHECK (type IN ('manual','scheduled','safety')),
      status TEXT NOT NULL CHECK (status IN ('success','failed')),
      file_size BIGINT,
      location TEXT,
      error_message TEXT
    );
    CREATE TABLE IF NOT EXISTS backup_settings (
      id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      schedule_enabled BOOLEAN NOT NULL DEFAULT FALSE,
      frequency TEXT NOT NULL DEFAULT 'daily' CHECK (frequency IN ('hourly','daily','weekly','monthly')),
      time_of_day TEXT NOT NULL DEFAULT '02:00',
      timezone TEXT NOT NULL DEFAULT 'Asia/Karachi',
      location TEXT NOT NULL DEFAULT './backups',
      retention_count INTEGER NOT NULL DEFAULT 14
    );
    INSERT INTO backup_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
    DO $do$ BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'backup_settings_frequency_check' AND pg_get_constraintdef(oid) LIKE '%hourly%'
      ) THEN
        ALTER TABLE backup_settings DROP CONSTRAINT IF EXISTS backup_settings_frequency_check;
        ALTER TABLE backup_settings ADD CONSTRAINT backup_settings_frequency_check CHECK (frequency IN ('hourly','daily','weekly','monthly'));
      END IF;
    END $do$;

    -- legacy single-tenant shape, only actually created on a brand-new DB
    -- that has never run migrate-to-saas.js; once migrated, this table's
    -- real primary key is client_id (see migrate-to-saas.js), so there is
    -- no singleton row to seed here anymore — settings rows are created
    -- per-client (in migrate-to-saas.js today; in the client-creation
    -- endpoint going forward).
    CREATE TABLE IF NOT EXISTS settings (
      id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
      company_name TEXT NOT NULL DEFAULT '',
      business_label TEXT NOT NULL DEFAULT '',
      opening_cash NUMERIC(14,2) NOT NULL DEFAULT 0,
      cheque_reminder_days INTEGER NOT NULL DEFAULT 3,
      credit_reminder_days INTEGER NOT NULL DEFAULT 3,
      setup_mode BOOLEAN NOT NULL DEFAULT FALSE
    );
    ALTER TABLE settings ADD COLUMN IF NOT EXISTS theme_color TEXT NOT NULL DEFAULT '#2563EB';
    ALTER TABLE settings ADD COLUMN IF NOT EXISTS font_size TEXT NOT NULL DEFAULT 'medium';
    ALTER TABLE settings ADD COLUMN IF NOT EXISTS hide_other_cards BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE settings ADD COLUMN IF NOT EXISTS hide_total_investment BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE settings ADD COLUMN IF NOT EXISTS hide_trade_summary BOOLEAN NOT NULL DEFAULT TRUE;
    ALTER TABLE settings ALTER COLUMN hide_other_cards SET DEFAULT TRUE;
    ALTER TABLE settings ALTER COLUMN hide_total_investment SET DEFAULT TRUE;
    ALTER TABLE settings ALTER COLUMN hide_trade_summary SET DEFAULT TRUE;
    CREATE TABLE IF NOT EXISTS bank_accounts (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, opening_balance NUMERIC(14,2) NOT NULL DEFAULT 0
    );
    ALTER TABLE bank_accounts ADD COLUMN IF NOT EXISTS is_locker BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE TABLE IF NOT EXISTS partners (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, opening_profit NUMERIC(14,2) NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS stock (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, unit TEXT NOT NULL DEFAULT 'kg',
      qty NUMERIC(14,3) NOT NULL DEFAULT 0, rate NUMERIC(14,2) NOT NULL DEFAULT 0,
      avg_cost NUMERIC(14,2) NOT NULL DEFAULT 0, UNIQUE (name, unit)
    );
    ALTER TABLE stock ADD COLUMN IF NOT EXISTS opening_qty NUMERIC(14,3) NOT NULL DEFAULT 0;
    ALTER TABLE stock ADD COLUMN IF NOT EXISTS opening_rate NUMERIC(14,2) NOT NULL DEFAULT 0;
    CREATE TABLE IF NOT EXISTS sales (
      id TEXT PRIMARY KEY, date DATE NOT NULL, party TEXT NOT NULL, item TEXT NOT NULL,
      qty NUMERIC(14,3) NOT NULL, unit TEXT NOT NULL DEFAULT 'kg', rate NUMERIC(14,2) NOT NULL,
      total NUMERIC(14,2) NOT NULL, type TEXT NOT NULL CHECK (type IN ('cash','credit')),
      account_id TEXT NOT NULL DEFAULT 'cash', paid BOOLEAN NOT NULL DEFAULT FALSE,
      due_date DATE, credit_days INTEGER, profit NUMERIC(14,2),
      partner_id TEXT REFERENCES partners(id) ON DELETE SET NULL, partner_percent NUMERIC(5,2)
    );
    CREATE INDEX IF NOT EXISTS idx_sales_date ON sales(date);
    ALTER TABLE sales ADD COLUMN IF NOT EXISTS staged BOOLEAN NOT NULL DEFAULT FALSE;
    -- a sale can name the exact purchase (batch/lot) its stock and cost came
    -- from, instead of profit being a blended average across every purchase
    -- of that item — each purchase is its own batch, tracked by its own id.
    ALTER TABLE sales ADD COLUMN IF NOT EXISTS source_purchase_id TEXT;
    CREATE TABLE IF NOT EXISTS purchases (
      id TEXT PRIMARY KEY, date DATE NOT NULL, supplier TEXT NOT NULL, item TEXT NOT NULL,
      qty NUMERIC(14,3) NOT NULL, unit TEXT NOT NULL DEFAULT 'kg', rate NUMERIC(14,2) NOT NULL,
      total NUMERIC(14,2) NOT NULL, type TEXT NOT NULL CHECK (type IN ('cash','credit')),
      account_id TEXT NOT NULL DEFAULT 'cash', paid BOOLEAN NOT NULL DEFAULT FALSE
    );
    CREATE INDEX IF NOT EXISTS idx_purchases_date ON purchases(date);
    ALTER TABLE purchases ADD COLUMN IF NOT EXISTS staged BOOLEAN NOT NULL DEFAULT FALSE;
    -- QA Round 17: a cash purchase that needed "Cover Shortfall From" creates
    -- its own transfer(s)/personal loan(s) first so funds are available. These
    -- two columns (added identically to supplier_payments/payouts/expenses/
    -- transfers below) record which ones, as a JSON array of ids, so deleting
    -- this purchase can also reverse the money it borrowed to exist.
    ALTER TABLE purchases ADD COLUMN IF NOT EXISTS funding_transfer_ids TEXT;
    ALTER TABLE purchases ADD COLUMN IF NOT EXISTS funding_loan_ids TEXT;
    -- purchase_returns / sales_returns: goods sent back to a supplier or
    -- brought back by a buyer, each tied to the specific purchase/sale it's
    -- returning (same batch-tracking principle sales already use via
    -- source_purchase_id) so stock and FIFO math both stay exact. settlement
    -- is chosen per return, not fixed by the original entry's cash/credit
    -- type: 'refund' moves money through account_id, 'credit' instead folds
    -- into the same FIFO pool as a payment/receipt would (see
    -- supplierPurchaseFifoAppliedDb/partySaleFifoAppliedDb below). Both are
    -- SaaS-native tables (no pre-SaaS legacy rows to migrate), so RLS is
    -- enabled directly here, same as supplier_payments/transfers above.
    CREATE TABLE IF NOT EXISTS purchase_returns (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      purchase_id TEXT NOT NULL REFERENCES purchases(id) ON DELETE RESTRICT,
      qty NUMERIC(14,3) NOT NULL,
      rate NUMERIC(14,2) NOT NULL,
      total NUMERIC(14,2) NOT NULL,
      settlement TEXT NOT NULL CHECK (settlement IN ('refund','credit')),
      account_id TEXT,
      note TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_purchase_returns_purchase ON purchase_returns(purchase_id);
    DO $do9$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'purchase_returns' AND relrowsecurity) THEN
        ALTER TABLE purchase_returns ENABLE ROW LEVEL SECURITY;
        ALTER TABLE purchase_returns FORCE ROW LEVEL SECURITY;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'purchase_returns' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON purchase_returns
          USING (client_id = current_setting('app.current_client_id', true))
          WITH CHECK (client_id = current_setting('app.current_client_id', true));
      END IF;
    END $do9$;
    CREATE TABLE IF NOT EXISTS sales_returns (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      sale_id TEXT NOT NULL REFERENCES sales(id) ON DELETE RESTRICT,
      qty NUMERIC(14,3) NOT NULL,
      rate NUMERIC(14,2) NOT NULL,
      total NUMERIC(14,2) NOT NULL,
      settlement TEXT NOT NULL CHECK (settlement IN ('refund','credit')),
      account_id TEXT,
      note TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_sales_returns_sale ON sales_returns(sale_id);
    DO $do10$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'sales_returns' AND relrowsecurity) THEN
        ALTER TABLE sales_returns ENABLE ROW LEVEL SECURITY;
        ALTER TABLE sales_returns FORCE ROW LEVEL SECURITY;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'sales_returns' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON sales_returns
          USING (client_id = current_setting('app.current_client_id', true))
          WITH CHECK (client_id = current_setting('app.current_client_id', true));
      END IF;
    END $do10$;
    -- purchase_advances: money issued to a supplier before the actual yarn
    -- purchase (qty/rate/item) is known — "held" for that purchase, resumed
    -- later via POST .../complete which fills in the purchase details and
    -- creates the real purchases row. The advance amount reduces ONLY that
    -- specific linked purchase's effective payable (same per-record
    -- principle as purchase_returns — never generically pooled), so it can
    -- never be misapplied to an unrelated purchase from the same supplier.
    -- The advance itself is always counted as a real outflow (the money
    -- left the account the moment it was issued), regardless of status.
    CREATE TABLE IF NOT EXISTS purchase_advances (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      supplier TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      account_id TEXT NOT NULL DEFAULT 'cash',
      note TEXT,
      status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','completed')),
      purchase_id TEXT REFERENCES purchases(id) ON DELETE SET NULL,
      funding_transfer_ids TEXT,
      funding_loan_ids TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_purchase_advances_purchase ON purchase_advances(purchase_id);
    DO $do11$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'purchase_advances' AND relrowsecurity) THEN
        ALTER TABLE purchase_advances ENABLE ROW LEVEL SECURITY;
        ALTER TABLE purchase_advances FORCE ROW LEVEL SECURITY;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'purchase_advances' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON purchase_advances
          USING (client_id = current_setting('app.current_client_id', true))
          WITH CHECK (client_id = current_setting('app.current_client_id', true));
      END IF;
    END $do11$;
    CREATE TABLE IF NOT EXISTS cheques (
      id TEXT PRIMARY KEY, date DATE NOT NULL, party TEXT NOT NULL, bank TEXT,
      amount NUMERIC(14,2) NOT NULL, due_date DATE NOT NULL, account_id TEXT NOT NULL DEFAULT 'cash',
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','cleared')), receipt_id TEXT
    );
    ALTER TABLE cheques ADD COLUMN IF NOT EXISTS account_id TEXT NOT NULL DEFAULT 'cash';
    ALTER TABLE cheques ADD COLUMN IF NOT EXISTS receipt_id TEXT;
    ALTER TABLE cheques ADD COLUMN IF NOT EXISTS direction TEXT NOT NULL DEFAULT 'received';
    ALTER TABLE cheques DROP CONSTRAINT IF EXISTS cheques_direction_check;
    ALTER TABLE cheques ADD CONSTRAINT cheques_direction_check CHECK (direction IN ('received','issued'));
    ALTER TABLE cheques ADD COLUMN IF NOT EXISTS payment_id TEXT;
    CREATE TABLE IF NOT EXISTS investors (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, amount NUMERIC(14,2) NOT NULL,
      ratio NUMERIC(5,2) NOT NULL DEFAULT 0, account_id TEXT NOT NULL DEFAULT 'cash'
    );
    ALTER TABLE investors ADD COLUMN IF NOT EXISTS staged BOOLEAN NOT NULL DEFAULT FALSE;
    -- nullable: existing investor rows (entered before this column existed)
    -- have no real date on record — left NULL rather than guessed at, so
    -- Net Worth Growth can tell "unknown date" apart from a real one.
    ALTER TABLE investors ADD COLUMN IF NOT EXISTS date DATE;
    CREATE TABLE IF NOT EXISTS expenses (
      id TEXT PRIMARY KEY, date DATE NOT NULL, description TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL, account_id TEXT NOT NULL DEFAULT 'cash'
    );
    ALTER TABLE expenses ADD COLUMN IF NOT EXISTS funding_transfer_ids TEXT;
    ALTER TABLE expenses ADD COLUMN IF NOT EXISTS funding_loan_ids TEXT;
    -- a one-time historical balance correction (see misc_income below) still
    -- needs to move real money for the account balance to be right, but it
    -- isn't real trading performance — this keeps it out of Trade Summary,
    -- Gross Profit, and Net Worth Growth while still landing in the account.
    ALTER TABLE expenses ADD COLUMN IF NOT EXISTS exclude_from_profit BOOLEAN NOT NULL DEFAULT FALSE;
    -- misc_income: the inverse of an Expense — money coming IN that isn't a
    -- sale. Either real cash/bank (mode='cash', adds to account_id) or a
    -- non-cash credit against a supplier's payable (mode='supplier' — a
    -- rebate/discount received, reduces what's owed without any money
    -- actually moving, same principle as a credit-settled Purchase Return
    -- but not tied to a specific purchase).
    CREATE TABLE IF NOT EXISTS misc_income (
      id TEXT PRIMARY KEY,
      client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
      date DATE NOT NULL,
      description TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      mode TEXT NOT NULL CHECK (mode IN ('cash','supplier')),
      account_id TEXT,
      supplier TEXT,
      note TEXT
    );
    ALTER TABLE misc_income ADD COLUMN IF NOT EXISTS exclude_from_profit BOOLEAN NOT NULL DEFAULT FALSE;
    DO $do12$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = 'misc_income' AND relrowsecurity) THEN
        ALTER TABLE misc_income ENABLE ROW LEVEL SECURITY;
        ALTER TABLE misc_income FORCE ROW LEVEL SECURITY;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = 'misc_income' AND policyname = 'tenant_isolation') THEN
        CREATE POLICY tenant_isolation ON misc_income
          USING (client_id = current_setting('app.current_client_id', true))
          WITH CHECK (client_id = current_setting('app.current_client_id', true));
      END IF;
    END $do12$;
    CREATE TABLE IF NOT EXISTS receipts (
      id TEXT PRIMARY KEY, date DATE NOT NULL, party TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL, account_id TEXT NOT NULL DEFAULT 'cash', note TEXT
    );
    ALTER TABLE receipts ADD COLUMN IF NOT EXISTS staged BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE supplier_payments ADD COLUMN IF NOT EXISTS staged BOOLEAN NOT NULL DEFAULT FALSE;
    ALTER TABLE supplier_payments ADD COLUMN IF NOT EXISTS funding_transfer_ids TEXT;
    ALTER TABLE supplier_payments ADD COLUMN IF NOT EXISTS funding_loan_ids TEXT;
    CREATE TABLE IF NOT EXISTS payouts (
      id TEXT PRIMARY KEY, date DATE NOT NULL,
      recipient_type TEXT NOT NULL CHECK (recipient_type IN ('investor','partner')),
      recipient_id TEXT NOT NULL, amount NUMERIC(14,2) NOT NULL,
      account_id TEXT NOT NULL DEFAULT 'cash', note TEXT
    );
    ALTER TABLE payouts ADD COLUMN IF NOT EXISTS funding_transfer_ids TEXT;
    ALTER TABLE payouts ADD COLUMN IF NOT EXISTS funding_loan_ids TEXT;
    ALTER TABLE payouts DROP CONSTRAINT IF EXISTS payouts_recipient_type_check;
    ALTER TABLE payouts ADD CONSTRAINT payouts_recipient_type_check CHECK (recipient_type IN ('investor','partner','loan'));
    CREATE TABLE IF NOT EXISTS audit_log (
      id TEXT PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('sale','purchase','investor','partner','bank','cheque','receipt','payout','user')),
      action TEXT NOT NULL CHECK (action IN ('edit','delete')), action_date DATE NOT NULL,
      before JSONB, after JSONB, entry JSONB
    );
    ALTER TABLE audit_log DROP CONSTRAINT IF EXISTS audit_log_kind_check;
    ALTER TABLE audit_log ADD CONSTRAINT audit_log_kind_check CHECK (kind IN ('sale','purchase','investor','partner','bank','expense','cheque','receipt','payout','user','party','stock','supplier','supplier_payment','transfer','personal_loan','purchase_return','sale_return','purchase_advance','misc_income'));

    -- Phase 1 SaaS prep: add client_id as a NULLABLE column to every business
    -- table. Nullable on purpose — existing rows have no client yet, and this
    -- runs on every boot. migrate-to-saas.js backfills these, then enforces
    -- NOT NULL + FK + enables RLS in one reviewed, backed-up pass.
    ALTER TABLE settings ADD COLUMN IF NOT EXISTS client_id TEXT;
    ALTER TABLE bank_accounts ADD COLUMN IF NOT EXISTS client_id TEXT;
    ALTER TABLE partners ADD COLUMN IF NOT EXISTS client_id TEXT;
    ALTER TABLE stock ADD COLUMN IF NOT EXISTS client_id TEXT;
    ALTER TABLE sales ADD COLUMN IF NOT EXISTS client_id TEXT;
    ALTER TABLE purchases ADD COLUMN IF NOT EXISTS client_id TEXT;
    ALTER TABLE cheques ADD COLUMN IF NOT EXISTS client_id TEXT;
    ALTER TABLE investors ADD COLUMN IF NOT EXISTS client_id TEXT;
    ALTER TABLE expenses ADD COLUMN IF NOT EXISTS client_id TEXT;
    ALTER TABLE receipts ADD COLUMN IF NOT EXISTS client_id TEXT;
    ALTER TABLE payouts ADD COLUMN IF NOT EXISTS client_id TEXT;
    ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS client_id TEXT;
  `);
}

// ---------- mapping helpers: db row (snake_case) <-> frontend shape (camelCase) ----------
const mapSale = (r) => ({
  id: r.id, date: r.date, party: r.party, item: r.item, qty: r.qty, unit: r.unit, rate: r.rate,
  total: r.total, type: r.type, account: r.account_id, paid: r.paid, dueDate: r.due_date,
  creditDays: r.credit_days, profit: r.profit, partnerId: r.partner_id, partnerPercent: r.partner_percent,
  staged: r.staged, sourcePurchaseId: r.source_purchase_id
});
const mapPurchase = (r) => ({
  id: r.id, date: r.date, supplier: r.supplier, item: r.item, qty: r.qty, unit: r.unit,
  rate: r.rate, total: r.total, type: r.type, account: r.account_id, paid: r.paid, staged: r.staged,
  fundingTransferIds: parseIdList(r.funding_transfer_ids), fundingLoanIds: parseIdList(r.funding_loan_ids)
});
const mapPurchaseReturn = (r) => ({ id: r.id, date: r.date, purchaseId: r.purchase_id, qty: r.qty, rate: r.rate, total: r.total, settlement: r.settlement, account: r.account_id, note: r.note });
const mapPurchaseAdvance = (r) => ({
  id: r.id, date: r.date, supplier: r.supplier, amount: r.amount, account: r.account_id, note: r.note,
  status: r.status, purchaseId: r.purchase_id,
  fundingTransferIds: parseIdList(r.funding_transfer_ids), fundingLoanIds: parseIdList(r.funding_loan_ids)
});
const mapSaleReturn = (r) => ({ id: r.id, date: r.date, saleId: r.sale_id, qty: r.qty, rate: r.rate, total: r.total, settlement: r.settlement, account: r.account_id, note: r.note });
const mapCheque = (r) => ({ id: r.id, date: r.date, party: r.party, bank: r.bank, amount: r.amount, dueDate: r.due_date, account: r.account_id, status: r.status, receiptId: r.receipt_id, direction: r.direction, paymentId: r.payment_id });
const mapInvestor = (r) => ({ id: r.id, name: r.name, amount: r.amount, ratio: r.ratio, account: r.account_id, staged: r.staged, date: r.date });
const mapPartner = (r) => ({ id: r.id, name: r.name, openingProfit: r.opening_profit });
const mapParty = (r) => ({ id: r.id, name: r.name, openingBalance: r.opening_balance, dueDate: r.due_date });
const mapSupplier = (r) => ({ id: r.id, name: r.name, openingBalance: r.opening_balance, dueDate: r.due_date });
const mapExpense = (r) => ({ id: r.id, date: r.date, desc: r.description, amount: r.amount, account: r.account_id, fundingTransferIds: parseIdList(r.funding_transfer_ids), fundingLoanIds: parseIdList(r.funding_loan_ids), excludeFromProfit: r.exclude_from_profit });
const mapMiscIncome = (r) => ({ id: r.id, date: r.date, desc: r.description, amount: r.amount, mode: r.mode, account: r.account_id, supplier: r.supplier, note: r.note, excludeFromProfit: r.exclude_from_profit });
const mapBank = (r) => ({ id: r.id, name: r.name, openingBalance: r.opening_balance, locker: r.is_locker });
const mapStock = (r) => ({ id: r.id, name: r.name, qty: r.qty, unit: r.unit, rate: r.rate, avgCost: r.avg_cost, openingQty: r.opening_qty, openingRate: r.opening_rate });
const mapReceipt = (r) => ({ id: r.id, date: r.date, party: r.party, amount: r.amount, account: r.account_id, note: r.note, staged: r.staged });
const mapSupplierPayment = (r) => ({ id: r.id, date: r.date, supplier: r.supplier, amount: r.amount, account: r.account_id, note: r.note, staged: r.staged, fundingTransferIds: parseIdList(r.funding_transfer_ids), fundingLoanIds: parseIdList(r.funding_loan_ids) });
const mapTransfer = (r) => ({ id: r.id, date: r.date, fromAccount: r.from_account, toAccount: r.to_account, amount: r.amount, note: r.note, fundingTransferIds: parseIdList(r.funding_transfer_ids), fundingLoanIds: parseIdList(r.funding_loan_ids) });
const mapPersonalLoan = (r) => ({ id: r.id, date: r.date, lender: r.lender, amount: r.amount, account: r.account_id, note: r.note });
const mapTradeSummary = (r) => ({ id: r.id, date: r.date, period: r.period, periodLabel: r.period_label, sales: r.sales, purchases: r.purchases, commissionNew: r.commission_new, commissionOpening: r.commission_opening, expenses: r.expenses, profit: r.profit, createdAt: r.created_at });
const mapInvestorSummary = (r) => ({ id: r.id, investorId: r.investor_id, investorName: r.investor_name, date: r.date, period: r.period, periodLabel: r.period_label, investment: r.investment, profitShare: r.profit_share, expenseShare: r.expense_share, expenseShareMonth: r.expense_share_month, expenseShareAll: r.expense_share_all, paidOut: r.paid_out, netOwed: r.net_owed, rows: r.rows, createdAt: r.created_at });
const mapPayout = (r) => ({ id: r.id, date: r.date, recipientType: r.recipient_type, recipientId: r.recipient_id, amount: r.amount, account: r.account_id, note: r.note, fundingTransferIds: parseIdList(r.funding_transfer_ids), fundingLoanIds: parseIdList(r.funding_loan_ids) });
const mapAudit = (r) => ({ id: r.id, kind: r.kind, action: r.action, actionDate: r.action_date, before: r.before, after: r.after, entry: r.entry });

// ---------- server-side stock + audit helpers (used by the per-entity routes below) ----------
// A stock item's avgCost is a plain weighted average over ALL of that item's
// purchases for this client — order-independent, so it's always correct no
// matter how many times an old purchase gets edited/deleted later (same
// design as the client-side recomputeStock() this replaces).
// Cost basis for a sale's profit must be the SAME weighted-average cost the
// Stock page shows (opening_qty/opening_rate blended with all purchases —
// see recomputeStockItem) — read it directly from the stock row itself
// rather than recomputing purchases-only, which silently ignored opening
// stock (giving cost=0, i.e. 100% "profit") and diverged from the Stock
// page's own valuation whenever opening stock was involved.
async function currentAvgCostDb(db, clientId, name, unit) {
  const r = await db.query(
    'SELECT avg_cost FROM stock WHERE client_id=$1 AND name=$2 AND unit=$3',
    [clientId, name, unit]
  );
  return r.rows[0] ? Number(r.rows[0].avg_cost) || 0 : 0;
}
// Per-request: profit no longer comes from a blended average cost — each
// sale names the exact batch (a specific purchase, or the material's own
// opening stock) it's drawn from, and profit is (rate - that batch's own
// rate) * qty. sourcePurchaseId is either a real purchases.id, the literal
// string 'opening' (the opening_qty/opening_rate "virtual" batch already
// used by recomputeStockItem), or falsy (no batch named — only valid when
// nothing is available to name, profit then stays 0).
async function resolveSaleBatch(db, clientId, item, unit, sourcePurchaseId, excludeSaleId) {
  if (!sourcePurchaseId) return null;
  if (sourcePurchaseId === 'opening') {
    const stockRow = await db.query('SELECT opening_qty, opening_rate FROM stock WHERE client_id=$1 AND name=$2 AND unit=$3', [clientId, item, unit]);
    if (!stockRow.rows[0]) return { notFound: true };
    const openingQty = Number(stockRow.rows[0].opening_qty) || 0;
    const openingRate = Number(stockRow.rows[0].opening_rate) || 0;
    const params = [clientId, item, unit];
    let sql = `SELECT id, qty FROM sales WHERE client_id=$1 AND item=$2 AND unit=$3 AND source_purchase_id='opening' AND NOT staged`;
    if (excludeSaleId) { sql += ' AND id != $4'; params.push(excludeSaleId); }
    const salesRows = (await db.query(sql, params)).rows;
    const soldQty = salesRows.reduce((a, r) => a + Number(r.qty), 0);
    const saleIds = salesRows.map((r) => r.id);
    // a sales return brings that qty back into the batch it came from, so
    // it offsets what the sale(s) above drew down.
    const returnedQty = saleIds.length
      ? Number((await db.query('SELECT COALESCE(SUM(qty),0) AS s FROM sales_returns WHERE sale_id = ANY($1::text[])', [saleIds])).rows[0].s)
      : 0;
    return { rate: openingRate, remaining: openingQty - soldQty + returnedQty };
  }
  const purch = await db.query('SELECT qty, rate, item, unit FROM purchases WHERE id=$1 AND client_id=$2', [sourcePurchaseId, clientId]);
  if (!purch.rows[0]) return { notFound: true };
  if (purch.rows[0].item !== item || purch.rows[0].unit !== unit) return { mismatch: true };
  const params2 = [clientId, sourcePurchaseId];
  let sql2 = 'SELECT id, qty FROM sales WHERE client_id=$1 AND source_purchase_id=$2 AND NOT staged';
  if (excludeSaleId) { sql2 += ' AND id != $3'; params2.push(excludeSaleId); }
  const salesRows2 = (await db.query(sql2, params2)).rows;
  const soldQty2 = salesRows2.reduce((a, r) => a + Number(r.qty), 0);
  const saleIds2 = salesRows2.map((r) => r.id);
  const salesReturnedQty = saleIds2.length
    ? Number((await db.query('SELECT COALESCE(SUM(qty),0) AS s FROM sales_returns WHERE sale_id = ANY($1::text[])', [saleIds2])).rows[0].s)
    : 0;
  // a purchase return draws down this same batch exactly like a sale would
  // (the goods leave stock, just back to the supplier instead of a buyer).
  const purchaseReturnedQty = Number((await db.query('SELECT COALESCE(SUM(qty),0) AS s FROM purchase_returns WHERE purchase_id=$1', [sourcePurchaseId])).rows[0].s);
  return { rate: Number(purch.rows[0].rate), remaining: Number(purch.rows[0].qty) - soldQty2 + salesReturnedQty - purchaseReturnedQty };
}
// A purchase being edited (qty reduced) or deleted (newQty=0) can't leave
// less in that batch than what sales/returns already named it for — the
// mirror of recomputeStockItem()'s NEGATIVE_STOCK guard, but scoped to one
// lot instead of the whole item's aggregate stock.
async function assertPurchaseLotNotOversold(db, clientId, purchaseId, newQty) {
  const salesRows = (await db.query(
    'SELECT id, qty FROM sales WHERE client_id=$1 AND source_purchase_id=$2 AND NOT staged',
    [clientId, purchaseId]
  )).rows;
  const soldQty = salesRows.reduce((a, r) => a + Number(r.qty), 0);
  const saleIds = salesRows.map((r) => r.id);
  const salesReturnedQty = saleIds.length
    ? Number((await db.query('SELECT COALESCE(SUM(qty),0) AS s FROM sales_returns WHERE sale_id = ANY($1::text[])', [saleIds])).rows[0].s)
    : 0;
  const purchaseReturnedQty = Number((await db.query('SELECT COALESCE(SUM(qty),0) AS s FROM purchase_returns WHERE purchase_id=$1', [purchaseId])).rows[0].s);
  const used = soldQty - salesReturnedQty + purchaseReturnedQty;
  if (used > Number(newQty) + 0.001) {
    const e = new Error(`This purchase batch already has ${used} sold/returned against it — it can't be reduced below that (or deleted). Edit/remove those sales or returns first.`);
    e.code = 'NEGATIVE_STOCK';
    throw e;
  }
}
async function recomputeStockItem(db, clientId, name, unit) {
  // opening_qty/opening_rate (set via /api/stock, editable independently of
  // purchase/sale history) act as one extra "virtual" purchase lot in the
  // weighted average — same principle as a bank account's opening_balance
  // being the base that later transactions add on top of.
  const existing = await db.query('SELECT opening_qty, opening_rate FROM stock WHERE client_id=$1 AND name=$2 AND unit=$3', [clientId, name, unit]);
  const openingQty = existing.rows[0] ? Number(existing.rows[0].opening_qty) || 0 : 0;
  const openingRate = existing.rows[0] ? Number(existing.rows[0].opening_rate) || 0 : 0;
  // Entries made while Historical Data Entry Mode (settings.setup_mode) is
  // on are marked staged=true and stay invisible to stock (and, on the
  // frontend, cash/bank) until the mode is turned off, at which point
  // unstageHistoricalEntries() below flips them all live and recomputes.
  // Bulk-entering old records rarely happens in perfect chronological order,
  // so the usual live guards (oversell, unit-mismatch) would otherwise block
  // valid historical data just because its matching purchase/sale hasn't
  // been typed in yet.
  const purch = await db.query(
    `SELECT COALESCE(SUM(qty),0) AS qty, COALESCE(SUM(qty*rate),0) AS value,
            (SELECT rate FROM purchases WHERE client_id=$1 AND item=$2 AND unit=$3 AND NOT staged ORDER BY date DESC LIMIT 1) AS last_rate
     FROM purchases WHERE client_id=$1 AND item=$2 AND unit=$3 AND NOT staged`,
    [clientId, name, unit]
  );
  const sale = await db.query('SELECT COALESCE(SUM(qty),0) AS qty FROM sales WHERE client_id=$1 AND item=$2 AND unit=$3 AND NOT staged', [clientId, name, unit]);
  // goods sent back to a supplier leave stock exactly like a purchase that
  // never happened (qty AND its value both come back out of the averaging
  // pool); goods a buyer sends back rejoin stock exactly like a sale that
  // never happened. Each return is tied to a specific purchase/sale, so
  // join through it to reach this item/unit.
  const purchReturn = await db.query(
    `SELECT COALESCE(SUM(pr.qty),0) AS qty, COALESCE(SUM(pr.qty*pr.rate),0) AS value
     FROM purchase_returns pr JOIN purchases p ON pr.purchase_id = p.id
     WHERE p.client_id=$1 AND p.item=$2 AND p.unit=$3 AND NOT p.staged`,
    [clientId, name, unit]
  );
  const saleReturn = await db.query(
    `SELECT COALESCE(SUM(sr.qty),0) AS qty
     FROM sales_returns sr JOIN sales s ON sr.sale_id = s.id
     WHERE s.client_id=$1 AND s.item=$2 AND s.unit=$3 AND NOT s.staged`,
    [clientId, name, unit]
  );
  const purchQty = (Number(purch.rows[0].qty) || 0) - (Number(purchReturn.rows[0].qty) || 0);
  const totalQty = openingQty + purchQty;
  const totalValue = (openingQty * openingRate) + Number(purch.rows[0].value) - Number(purchReturn.rows[0].value);
  const qty = totalQty - ((Number(sale.rows[0].qty) || 0) - (Number(saleReturn.rows[0].qty) || 0));
  // Guards elsewhere block a NEW sale from overselling and block a NEW
  // negative opening quantity — but editing/deleting a PAST purchase, or
  // reducing an existing material's opening quantity, can retroactively pull
  // the rug out from under sales that already happened against that stock,
  // which neither of those guards catches. Block it here instead, at the
  // one place every such change ultimately passes through — throwing here
  // rolls back the whole surrounding transaction (see withTenantDb), so the
  // purchase/stock edit that caused it never takes effect.
  if (qty < -0.0001) {
    const e = new Error(`This change would leave "${name}" (${unit}) at ${qty.toFixed(2)} in stock — ${Math.abs(qty).toFixed(2)} ${unit} has already been sold against it. Reduce or remove the related sale(s) first.`);
    e.code = 'NEGATIVE_STOCK';
    throw e;
  }
  const avgCost = totalQty > 0 ? totalValue / totalQty : 0;
  const lastRate = Number(purch.rows[0].last_rate) || openingRate || 0;
  await db.query(
    `INSERT INTO stock (id, client_id, name, unit, qty, avg_cost, rate) VALUES ($1,$2,$3,$4,$5,$6,$7)
     ON CONFLICT (client_id, name, unit) DO UPDATE SET qty=$5, avg_cost=$6, rate=$7`,
    [crypto.randomUUID(), clientId, name, unit, qty, avgCost, lastRate]
  );
}
// Server-side mirror of accountBalance() in dhaaga-manager.html — the
// frontend's "Cover Shortfall" flow is the normal path to keep any account
// non-negative, but it's still only a client-side convenience. This is the
// backstop: a handful of draw-down endpoints (transfer, mark-paid, clearing
// an issued cheque) call it and reject outright if the account can't cover
// the amount, the same way recomputeStockItem() above backstops stock.
async function computeAccountBalanceDb(db, clientId, accId) {
  accId = accId || 'cash';
  const settingsRow = await db.query('SELECT opening_cash FROM settings WHERE client_id=$1', [clientId]);
  let bal;
  if (accId === 'cash') {
    bal = settingsRow.rows[0] ? Number(settingsRow.rows[0].opening_cash) || 0 : 0;
  } else {
    const bankRow = await db.query('SELECT opening_balance FROM bank_accounts WHERE client_id=$1 AND id=$2', [clientId, accId]);
    bal = bankRow.rows[0] ? Number(bankRow.rows[0].opening_balance) || 0 : 0;
  }
  const add = (rows, field) => rows.forEach((r) => { bal += Number(r[field]); });
  const sub = (rows, field) => rows.forEach((r) => { bal -= Number(r[field]); });

  add((await db.query('SELECT amount FROM investors WHERE client_id=$1 AND account_id=$2 AND NOT staged', [clientId, accId])).rows, 'amount');
  add((await db.query('SELECT amount FROM personal_loans WHERE client_id=$1 AND account_id=$2', [clientId, accId])).rows, 'amount');
  add((await db.query("SELECT total FROM sales WHERE client_id=$1 AND account_id=$2 AND type='cash' AND NOT staged", [clientId, accId])).rows, 'total');
  add((await db.query('SELECT amount FROM receipts WHERE client_id=$1 AND account_id=$2 AND NOT staged', [clientId, accId])).rows, 'amount');
  // a refund-settled purchase return is money the supplier actually hands
  // back (like a receipt, just from a supplier instead of a buyer); a
  // refund-settled sales return is money handed back to a buyer (like a
  // supplier payment, just paid out to a buyer instead). A credit-settled
  // return touches neither account balance — it only shifts the FIFO pool
  // (see supplierPurchaseFifoAppliedDb / partySaleFifoAppliedDb).
  add((await db.query("SELECT total AS amount FROM purchase_returns WHERE client_id=$1 AND account_id=$2 AND settlement='refund'", [clientId, accId])).rows, 'amount');
  sub((await db.query("SELECT total AS amount FROM sales_returns WHERE client_id=$1 AND account_id=$2 AND settlement='refund'", [clientId, accId])).rows, 'amount');

  const purchases = (await db.query("SELECT total, type, paid FROM purchases WHERE client_id=$1 AND account_id=$2 AND NOT staged", [clientId, accId])).rows;
  purchases.forEach((r) => { if (r.type === 'cash' || r.paid) bal -= Number(r.total); });

  sub((await db.query('SELECT amount FROM supplier_payments WHERE client_id=$1 AND account_id=$2 AND NOT staged', [clientId, accId])).rows, 'amount');
  // a purchase advance is real money handed to the supplier the moment it's
  // issued — it keeps counting as an outflow even after it's later
  // "completed" into a purchase, since that purchase itself is created
  // unpaid (credit) specifically so this is the only place the money leaves.
  sub((await db.query('SELECT amount FROM purchase_advances WHERE client_id=$1 AND account_id=$2', [clientId, accId])).rows, 'amount');
  // the inverse of the sub() above — cash-mode misc income is real money
  // coming in; supplier-mode never touches an account at all (see schema).
  add((await db.query("SELECT amount FROM misc_income WHERE client_id=$1 AND mode='cash' AND account_id=$2", [clientId, accId])).rows, 'amount');
  sub((await db.query('SELECT amount FROM expenses WHERE client_id=$1 AND account_id=$2', [clientId, accId])).rows, 'amount');
  sub((await db.query('SELECT amount FROM payouts WHERE client_id=$1 AND account_id=$2', [clientId, accId])).rows, 'amount');

  const trOut = await db.query('SELECT COALESCE(SUM(amount),0) s FROM transfers WHERE client_id=$1 AND from_account=$2', [clientId, accId]);
  bal -= Number(trOut.rows[0].s);
  const trIn = await db.query('SELECT COALESCE(SUM(amount),0) s FROM transfers WHERE client_id=$1 AND to_account=$2', [clientId, accId]);
  bal += Number(trIn.rows[0].s);

  return bal;
}
async function assertFundsAvailable(db, clientId, accId, amount) {
  const balance = await computeAccountBalanceDb(db, clientId, accId);
  if (Number(amount) > balance + 0.009) {
    const e = new Error(`Insufficient funds: this account only has Rs ${balance.toFixed(2)} available, but Rs ${Number(amount).toFixed(2)} is needed.`);
    e.code = 'INSUFFICIENT_FUNDS';
    throw e;
  }
}
// mirrors the frontend's partyLedgerRows() FIFO pooling (party's full
// receipts total, applied oldest-credit-sale-first) so a per-sale delete
// check agrees with what the Ledger already shows for that sale.
async function partySaleFifoAppliedDb(db, clientId, party, saleId) {
  const salesRes = await db.query(
    'SELECT id, type, total FROM sales WHERE client_id=$1 AND party=$2 ORDER BY date, id',
    [clientId, party]
  );
  const receiptsRes = await db.query(
    'SELECT COALESCE(SUM(amount),0) s FROM receipts WHERE client_id=$1 AND party=$2',
    [clientId, party]
  );
  // a return (either settlement) means less was actually kept, so it always
  // reduces THIS sale's own effective total before the party's receipts
  // pool is applied — not a generic addition to the pool, which would let
  // it get FIFO-applied against some OTHER, unrelated sale instead. Only a
  // refund-settled return additionally moves cash (see computeAccountBalanceDb);
  // a credit-settled return needs nothing further here, since shrinking the
  // total already reduces what the pool has to cover.
  const returnsRes = await db.query(
    `SELECT sale_id, COALESCE(SUM(total),0) s FROM sales_returns WHERE sale_id IN
     (SELECT id FROM sales WHERE client_id=$1 AND party=$2) GROUP BY sale_id`,
    [clientId, party]
  );
  const returnsBySale = new Map(returnsRes.rows.map((r) => [r.sale_id, Number(r.s)]));
  let pool = Number(receiptsRes.rows[0].s);
  for (const s of salesRes.rows) {
    if (s.type === 'cash') continue;
    const total = Math.max(0, Number(s.total) - (returnsBySale.get(s.id) || 0));
    const applied = Math.min(pool, total);
    pool -= applied;
    if (s.id === saleId) return applied;
  }
  return 0;
}
// the payable-side mirror, matching supplierLedgerRows().
async function supplierPurchaseFifoAppliedDb(db, clientId, supplier, purchaseId) {
  const purchasesRes = await db.query(
    'SELECT id, type, paid, total FROM purchases WHERE client_id=$1 AND supplier=$2 ORDER BY date, id',
    [clientId, supplier]
  );
  const paymentsRes = await db.query(
    'SELECT COALESCE(SUM(amount),0) s FROM supplier_payments WHERE client_id=$1 AND supplier=$2',
    [clientId, supplier]
  );
  const miscIncomeRes = await db.query(
    "SELECT COALESCE(SUM(amount),0) s FROM misc_income WHERE client_id=$1 AND mode='supplier' AND supplier=$2",
    [clientId, supplier]
  );
  const paymentsPool = Number(paymentsRes.rows[0].s) + Number(miscIncomeRes.rows[0].s);
  // same principle as the sales side above: a return always shrinks THIS
  // purchase's own effective total first, rather than joining the pool.
  const returnsRes = await db.query(
    `SELECT purchase_id, COALESCE(SUM(total),0) s FROM purchase_returns WHERE purchase_id IN
     (SELECT id FROM purchases WHERE client_id=$1 AND supplier=$2) GROUP BY purchase_id`,
    [clientId, supplier]
  );
  const returnsByPurchase = new Map(returnsRes.rows.map((r) => [r.purchase_id, Number(r.s)]));
  // a completed Purchase Advance always settles its own specific linked
  // purchase first, same per-record principle as returns — never pooled,
  // so it can never be misapplied to a different purchase from this supplier.
  const advancesRes = await db.query(
    `SELECT purchase_id, COALESCE(SUM(amount),0) s FROM purchase_advances WHERE status='completed' AND purchase_id IN
     (SELECT id FROM purchases WHERE client_id=$1 AND supplier=$2) GROUP BY purchase_id`,
    [clientId, supplier]
  );
  const advancesByPurchase = new Map(advancesRes.rows.map((r) => [r.purchase_id, Number(r.s)]));
  let pool = paymentsPool;
  for (const p of purchasesRes.rows) {
    if (p.type === 'cash' || p.paid) continue;
    const total = Math.max(0, Number(p.total) - (returnsByPurchase.get(p.id) || 0) - (advancesByPurchase.get(p.id) || 0));
    const applied = Math.min(pool, total);
    pool -= applied;
    if (p.id === purchaseId) return applied;
  }
  return 0;
}
// Money-amount guards (QA: negative/zero amounts were silently accepted on
// several forms — e.g. a Supplier Payment of -50 raised the bank balance,
// a Receipt of -100,000 drove Cash negative with no warning). Every actual
// transaction amount must be a finite number strictly greater than zero;
// an opening-balance-style field (can legitimately be 0 for "no history
// yet") uses the non-negative variant instead — still rejects negative/NaN/
// Infinity, but allows exactly 0.
// every amount/total column is NUMERIC(14,2) — 12 integer digits, so
// anything at or above 1e12 would overflow it outright (a raw Postgres
// error, not a friendly one) long before it's a plausible real transaction;
// reject it here with a clear message instead.
const MAX_SANE_AMOUNT = 1e11;
function isPositiveAmount(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 && n < MAX_SANE_AMOUNT;
}
function isNonNegativeAmount(v) {
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 && n < MAX_SANE_AMOUNT;
}
function parseIdList(raw) {
  if (!raw) return [];
  try { const a = JSON.parse(raw); return Array.isArray(a) ? a : []; } catch { return []; }
}
function fundingIdsJson(ids) {
  return Array.isArray(ids) && ids.length ? JSON.stringify(ids) : null;
}
// QA Round 17: a cash entry (purchase, supplier payment, payout, expense,
// transfer) that needed "Cover Shortfall From" creates its own
// transfer(s)/personal loan(s) first so funds are available, before the
// entry itself is created. Deleting that entry later left those auto-
// created movements behind as orphans, inflating Cash/Bank. Reverses them
// here, in the same transaction as the entry's own delete. A linked
// personal loan that has already had a repayment recorded against it is
// left alone and blocks the delete instead — same principle as the
// sale/purchase "has payment history" guards elsewhere.
async function deleteFundingLinks(db, clientId, fundingTransferIdsRaw, fundingLoanIdsRaw) {
  const loanIds = parseIdList(fundingLoanIdsRaw);
  for (const loanId of loanIds) {
    const payoutCheck = await db.query(
      "SELECT 1 FROM payouts WHERE client_id=$1 AND recipient_type='loan' AND recipient_id=$2 LIMIT 1",
      [clientId, loanId]
    );
    if (payoutCheck.rows[0]) {
      const e = new Error('A Personal Loan taken to cover a shortfall for this entry already has a repayment recorded against it — delete that repayment first, then this entry.');
      e.code = 'HAS_PAYMENTS';
      throw e;
    }
  }
  const transferIds = parseIdList(fundingTransferIdsRaw);
  if (transferIds.length) {
    await db.query('DELETE FROM transfers WHERE client_id=$1 AND id = ANY($2::text[])', [clientId, transferIds]);
  }
  for (const loanId of loanIds) {
    await db.query('DELETE FROM personal_loans WHERE client_id=$1 AND id=$2', [clientId, loanId]);
  }
}
async function writeAudit(db, clientId, kind, action, payload) {
  await db.query(
    'INSERT INTO audit_log (id, client_id, kind, action, action_date, before, after, entry) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
    [crypto.randomUUID(), clientId, kind, action, new Date().toISOString().slice(0, 10), payload.before || null, payload.after || null, payload.entry || null]
  );
}
const editorAccess = [requireAuth, resolveActiveClient, requireClientAccess('editor')];
const viewerAccess = [requireAuth, resolveActiveClient, requireClientAccess('viewer')];

// ---------- auth ----------
app.get('/api/auth/status', async (req, res) => {
  try {
    const r = await pool.query("SELECT EXISTS(SELECT 1 FROM users WHERE role='admin') AS has_admin");
    res.json({ hasAdmin: r.rows[0].has_admin });
  } catch (err) {
    console.error('GET /api/auth/status error:', err);
    res.status(500).json({ error: 'Unable to check status' });
  }
});

app.post('/api/auth/setup-admin', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const existing = await pool.query("SELECT 1 FROM users WHERE role='admin' LIMIT 1");
    if (existing.rowCount > 0) return res.status(409).json({ error: 'An admin account already exists' });
    const hash = await bcrypt.hash(password, 10);
    const id = crypto.randomUUID();
    await pool.query('INSERT INTO users (id, username, password_hash, role) VALUES ($1,$2,$3,$4)', [id, username, hash, 'admin']);
    const activeClientId = await resolveInitialClientId(id, 'admin');
    req.session.user = { id, username, role: 'admin', activeClientId };
    res.json(req.session.user);
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username already exists' });
    console.error('POST /api/auth/setup-admin error:', err);
    res.status(500).json({ error: 'Unable to create admin account' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  try {
    const r = await pool.query("SELECT id, username, password_hash, role FROM users WHERE username = $1 AND status = 'active'", [username]);
    const user = r.rows[0];
    const ok = user && (await bcrypt.compare(password, user.password_hash));
    if (!ok) return res.status(401).json({ error: 'Incorrect username or password' });
    const activeClientId = await resolveInitialClientId(user.id, user.role);
    req.session.user = { id: user.id, username: user.username, role: user.role, activeClientId };
    res.json(req.session.user);
  } catch (err) {
    console.error('POST /api/auth/login error:', err);
    res.status(500).json({ error: 'Unable to login' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/session', (req, res) => {
  res.json(req.session.user || null);
});

// ---------- clients (tenants) ----------
// clients the current user may access — admins see every active client,
// standard users see only what's in user_clients. Drives the header switcher.
app.get('/api/clients/mine', requireAuth, async (req, res) => {
  try {
    if (req.session.user.role === 'admin') {
      const r = await pool.query("SELECT id, client_number, name FROM clients WHERE status = 'active' ORDER BY name");
      res.json(r.rows.map((c) => ({ id: c.id, clientNumber: c.client_number, name: c.name, accessLevel: 'editor' })));
    } else {
      const r = await pool.query(
        `SELECT c.id, c.client_number, c.name, uc.access_level FROM user_clients uc
         JOIN clients c ON c.id = uc.client_id WHERE uc.user_id = $1 AND c.status = 'active' ORDER BY c.name`,
        [req.session.user.id]
      );
      res.json(r.rows.map((c) => ({ id: c.id, clientNumber: c.client_number, name: c.name, accessLevel: c.access_level })));
    }
  } catch (err) {
    console.error('GET /api/clients/mine error:', err);
    res.status(500).json({ error: 'Unable to load clients' });
  }
});

// admin-only client management (Settings > Clients tab)
app.get('/api/clients', requireAuth, requireAdmin, async (req, res) => {
  try {
    const r = await pool.query('SELECT id, client_number, name, status, created_at FROM clients ORDER BY client_number');
    // settings is RLS-protected per-client — an admin listing every client's
    // theme must read each one under its own tenant context in turn, same
    // as any other cross-client admin view; there is no single unscoped
    // query that could return every client's settings at once under RLS.
    const withTheme = await Promise.all(r.rows.map(async (c) => {
      const s = await withTenantDb(c.id, (db) => db.query('SELECT theme_color, font_size FROM settings WHERE client_id = $1', [c.id]));
      const row = s.rows[0];
      return {
        id: c.id, clientNumber: c.client_number, name: c.name, status: c.status, createdAt: c.created_at,
        themeColor: row ? row.theme_color : '#2563EB', fontSize: row ? row.font_size : 'medium'
      };
    }));
    res.json(withTheme);
  } catch (err) {
    console.error('GET /api/clients error:', err);
    res.status(500).json({ error: 'Unable to load clients' });
  }
});

app.post('/api/clients', requireAuth, requireAdmin, async (req, res) => {
  const name = (req.body && req.body.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Client name required' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const id = crypto.randomUUID();
    await client.query('INSERT INTO clients (id, name) VALUES ($1,$2)', [id, name]);
    // settings is RLS-protected like every other tenant table — the new
    // row's own client_id must be the active tenant context for its INSERT
    // to satisfy the policy's WITH CHECK, same as withTenantDb() does elsewhere.
    await client.query("SELECT set_config('app.current_client_id', $1, true)", [id]);
    await client.query('INSERT INTO settings (client_id) VALUES ($1)', [id]);
    await client.query('COMMIT');
    res.json({ id, name, status: 'active' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('POST /api/clients error:', err);
    res.status(500).json({ error: 'Unable to create client' });
  } finally {
    client.release();
  }
});

app.patch('/api/clients/:id', requireAuth, requireAdmin, async (req, res) => {
  const { name, status, themeColor, fontSize } = req.body || {};
  if (status && !['active', 'inactive'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  try {
    const current = await pool.query('SELECT * FROM clients WHERE id = $1', [req.params.id]);
    if (!current.rows[0]) return res.status(404).json({ error: 'Client not found' });
    const row = current.rows[0];
    const newName = name !== undefined ? name.trim() || row.name : row.name;
    const newStatus = status || row.status;
    const r = await pool.query(
      'UPDATE clients SET name=$1, status=$2, updated_at=NOW() WHERE id=$3 RETURNING id, client_number, name, status',
      [newName, newStatus, req.params.id]
    );
    let s = { theme_color: '#2563EB', font_size: 'medium' };
    if (themeColor !== undefined || fontSize !== undefined) {
      const validColor = /^#[0-9a-fA-F]{6}$/.test(themeColor || '') ? themeColor : '#2563EB';
      const validSize = ['small', 'medium', 'large'].includes(fontSize) ? fontSize : 'medium';
      const upserted = await withTenantDb(req.params.id, (db) =>
        db.query(
          `INSERT INTO settings (client_id, theme_color, font_size) VALUES ($1,$2,$3)
           ON CONFLICT (client_id) DO UPDATE SET theme_color=$2, font_size=$3 RETURNING theme_color, font_size`,
          [req.params.id, validColor, validSize]
        ).then((rr) => rr.rows[0])
      );
      s = upserted;
    } else {
      const existing = await withTenantDb(req.params.id, (db) => db.query('SELECT theme_color, font_size FROM settings WHERE client_id = $1', [req.params.id]));
      if (existing.rows[0]) s = existing.rows[0];
    }
    res.json({
      id: r.rows[0].id, clientNumber: r.rows[0].client_number, name: r.rows[0].name, status: r.rows[0].status,
      themeColor: s.theme_color, fontSize: s.font_size
    });
  } catch (err) {
    console.error('PATCH /api/clients/:id error:', err);
    res.status(500).json({ error: 'Unable to update client' });
  }
});

// switch which client the session is currently scoped to
app.post('/api/session/active-client', requireAuth, async (req, res) => {
  const { clientId } = req.body || {};
  if (!clientId) return res.status(400).json({ error: 'clientId required' });
  try {
    if (req.session.user.role !== 'admin') {
      const r = await pool.query('SELECT 1 FROM user_clients WHERE user_id = $1 AND client_id = $2', [req.session.user.id, clientId]);
      if (r.rowCount === 0) return res.status(403).json({ error: 'No access to this client' });
    } else {
      const r = await pool.query("SELECT 1 FROM clients WHERE id = $1 AND status = 'active'", [clientId]);
      if (r.rowCount === 0) return res.status(404).json({ error: 'Client not found' });
    }
    req.session.user.activeClientId = clientId;
    res.json(req.session.user);
  } catch (err) {
    console.error('POST /api/session/active-client error:', err);
    res.status(500).json({ error: 'Unable to switch client' });
  }
});

// ---------- user management (global admin only) ----------
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT u.id, u.username, u.role, u.status,
        COALESCE(json_agg(json_build_object('clientId', uc.client_id, 'clientName', c.name, 'accessLevel', uc.access_level))
          FILTER (WHERE uc.client_id IS NOT NULL), '[]') AS clients
      FROM users u
      LEFT JOIN user_clients uc ON uc.user_id = u.id
      LEFT JOIN clients c ON c.id = uc.client_id
      GROUP BY u.id ORDER BY u.username
    `);
    res.json(r.rows);
  } catch (err) {
    console.error('GET /api/users error:', err);
    res.status(500).json({ error: 'Unable to load users' });
  }
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { username, password, role, clientId, accessLevel } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (!['admin', 'standard'].includes(role)) return res.status(400).json({ error: 'Invalid role' });
  if (role === 'standard' && (!clientId || !['editor', 'viewer'].includes(accessLevel))) {
    return res.status(400).json({ error: 'Standard users need a client and access level (editor/viewer)' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const hash = await bcrypt.hash(password, 10);
    const id = crypto.randomUUID();
    await client.query('INSERT INTO users (id, username, password_hash, role) VALUES ($1,$2,$3,$4)', [id, username, hash, role]);
    if (role === 'standard') {
      await client.query('INSERT INTO user_clients (user_id, client_id, access_level) VALUES ($1,$2,$3)', [id, clientId, accessLevel]);
    }
    await client.query('COMMIT');
    res.json({ id, username, role });
  } catch (err) {
    await client.query('ROLLBACK');
    if (err.code === '23505') return res.status(409).json({ error: 'Username already exists' });
    console.error('POST /api/users error:', err);
    res.status(500).json({ error: 'Unable to add user' });
  } finally {
    client.release();
  }
});

app.patch('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  const { username, password, role, clientId, accessLevel } = req.body || {};
  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');
    const current = await dbClient.query('SELECT id, username, role FROM users WHERE id = $1', [req.params.id]);
    const target = current.rows[0];
    if (!target) { await dbClient.query('ROLLBACK'); return res.status(404).json({ error: 'User not found' }); }

    const newRole = role || target.role;
    if (!['admin', 'standard'].includes(newRole)) { await dbClient.query('ROLLBACK'); return res.status(400).json({ error: 'Invalid role' }); }

    if (target.role === 'admin' && newRole !== 'admin') {
      const adminCount = await dbClient.query("SELECT COUNT(*)::int AS c FROM users WHERE role='admin' AND status='active'");
      if (adminCount.rows[0].c <= 1) { await dbClient.query('ROLLBACK'); return res.status(400).json({ error: 'At least one admin account must remain' }); }
    }

    const newUsername = username ? username.trim() : target.username;
    if (!newUsername) { await dbClient.query('ROLLBACK'); return res.status(400).json({ error: 'Username cannot be empty' }); }

    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await dbClient.query('UPDATE users SET username=$1, password_hash=$2, role=$3 WHERE id=$4', [newUsername, hash, newRole, target.id]);
    } else {
      await dbClient.query('UPDATE users SET username=$1, role=$2 WHERE id=$3', [newUsername, newRole, target.id]);
    }

    if (newRole === 'standard' && clientId && ['editor', 'viewer'].includes(accessLevel)) {
      // single-client assignment today (matches user_clients' primary key) — replace any existing one
      await dbClient.query('DELETE FROM user_clients WHERE user_id = $1', [target.id]);
      await dbClient.query('INSERT INTO user_clients (user_id, client_id, access_level) VALUES ($1,$2,$3)', [target.id, clientId, accessLevel]);
    } else if (newRole === 'admin') {
      await dbClient.query('DELETE FROM user_clients WHERE user_id = $1', [target.id]); // admins don't need explicit rows
    }

    await dbClient.query('COMMIT');
    if (req.session.user.id === target.id) {
      req.session.user = { ...req.session.user, username: newUsername, role: newRole };
    }
    res.json({ id: target.id, username: newUsername, role: newRole });
  } catch (err) {
    await dbClient.query('ROLLBACK');
    if (err.code === '23505') return res.status(409).json({ error: 'Username already exists' });
    console.error('PATCH /api/users/:id error:', err);
    res.status(500).json({ error: 'Unable to update user' });
  } finally {
    dbClient.release();
  }
});

app.delete('/api/users/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    if (req.params.id === req.session.user.id) {
      return res.status(400).json({ error: 'You cannot remove your own account' });
    }
    const target = await pool.query("SELECT role FROM users WHERE id = $1 AND status = 'active'", [req.params.id]);
    if (target.rows[0] && target.rows[0].role === 'admin') {
      const adminCount = await pool.query("SELECT COUNT(*)::int AS c FROM users WHERE role='admin' AND status='active'");
      if (adminCount.rows[0].c <= 1) return res.status(400).json({ error: 'At least one admin account must remain' });
    }
    // soft delete — keeps audit_log/history referencing this user meaningful
    await pool.query("UPDATE users SET status = 'inactive' WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/users/:id error:', err);
    res.status(500).json({ error: 'Unable to remove user' });
  }
});

// ---------- business state (client-scoped; RLS is the backstop, every
// query below is additionally scoped by client_id at the app layer too) ----------
app.get('/api/state', requireAuth, resolveActiveClient, requireClientAccess('viewer'), async (req, res) => {
  try {
    const data = await withTenantDb(req.clientId, async (db) => {
      const cid = req.clientId;
      const [settings, banks, partners, parties, suppliers, stock, sales, purchases, cheques, investors, expenses, receipts, payouts, auditLog, supplierPayments, transfers, personalLoans, tradeSummaries, investorSummaries, purchaseReturns, salesReturns, purchaseAdvances, miscIncome] = await Promise.all([
        db.query('SELECT * FROM settings WHERE client_id = $1', [cid]),
        db.query('SELECT * FROM bank_accounts WHERE client_id = $1 ORDER BY name', [cid]),
        db.query('SELECT * FROM partners WHERE client_id = $1 ORDER BY name', [cid]),
        db.query('SELECT * FROM parties WHERE client_id = $1 ORDER BY name', [cid]),
        db.query('SELECT * FROM suppliers WHERE client_id = $1 ORDER BY name', [cid]),
        db.query('SELECT * FROM stock WHERE client_id = $1 ORDER BY name', [cid]),
        db.query('SELECT * FROM sales WHERE client_id = $1 ORDER BY date, id', [cid]),
        db.query('SELECT * FROM purchases WHERE client_id = $1 ORDER BY date, id', [cid]),
        db.query('SELECT * FROM cheques WHERE client_id = $1 ORDER BY date', [cid]),
        db.query('SELECT * FROM investors WHERE client_id = $1 ORDER BY name', [cid]),
        db.query('SELECT * FROM expenses WHERE client_id = $1 ORDER BY date', [cid]),
        db.query('SELECT * FROM receipts WHERE client_id = $1 ORDER BY date', [cid]),
        db.query('SELECT * FROM payouts WHERE client_id = $1 ORDER BY date', [cid]),
        db.query('SELECT * FROM audit_log WHERE client_id = $1 ORDER BY action_date', [cid]),
        db.query('SELECT * FROM supplier_payments WHERE client_id = $1 ORDER BY date', [cid]),
        db.query('SELECT * FROM transfers WHERE client_id = $1 ORDER BY date', [cid]),
        db.query('SELECT * FROM personal_loans WHERE client_id = $1 ORDER BY date', [cid]),
        db.query('SELECT * FROM trade_summaries WHERE client_id = $1 ORDER BY created_at DESC', [cid]),
        db.query('SELECT * FROM investor_summaries WHERE client_id = $1 ORDER BY created_at DESC', [cid]),
        db.query('SELECT * FROM purchase_returns WHERE client_id = $1 ORDER BY date', [cid]),
        db.query('SELECT * FROM sales_returns WHERE client_id = $1 ORDER BY date', [cid]),
        db.query('SELECT * FROM purchase_advances WHERE client_id = $1 ORDER BY date', [cid]),
        db.query('SELECT * FROM misc_income WHERE client_id = $1 ORDER BY date', [cid])
      ]);
      return { settings: settings.rows[0], banks, partners, parties, suppliers, stock, sales, purchases, cheques, investors, expenses, receipts, payouts, auditLog, supplierPayments, transfers, personalLoans, tradeSummaries, investorSummaries, purchaseReturns, salesReturns, purchaseAdvances, miscIncome };
    });
    const s = data.settings;
    res.json({
      settings: s ? {
        companyName: s.company_name,
        businessLabel: s.business_label,
        openingCash: s.opening_cash,
        chequeReminderDays: s.cheque_reminder_days,
        creditReminderDays: s.credit_reminder_days,
        setupMode: s.setup_mode,
        themeColor: s.theme_color,
        fontSize: s.font_size,
        hideOtherCards: s.hide_other_cards,
        hideTotalInvestment: s.hide_total_investment,
        hideTradeSummary: s.hide_trade_summary
      } : { companyName: '', businessLabel: '', openingCash: 0, chequeReminderDays: 3, creditReminderDays: 3, setupMode: false, themeColor: '#2563EB', fontSize: 'medium', hideOtherCards: true, hideTotalInvestment: true, hideTradeSummary: true },
      banks: data.banks.rows.map(mapBank),
      partners: data.partners.rows.map(mapPartner),
      parties: data.parties.rows.map(mapParty),
      suppliers: data.suppliers.rows.map(mapSupplier),
      stock: data.stock.rows.map(mapStock),
      sales: data.sales.rows.map(mapSale),
      purchases: data.purchases.rows.map(mapPurchase),
      cheques: data.cheques.rows.map(mapCheque),
      investors: data.investors.rows.map(mapInvestor),
      expenses: data.expenses.rows.map(mapExpense),
      receipts: data.receipts.rows.map(mapReceipt),
      payouts: data.payouts.rows.map(mapPayout),
      auditLog: data.auditLog.rows.map(mapAudit),
      supplierPayments: data.supplierPayments.rows.map(mapSupplierPayment),
      transfers: data.transfers.rows.map(mapTransfer),
      personalLoans: data.personalLoans.rows.map(mapPersonalLoan),
      tradeSummaries: data.tradeSummaries.rows.map(mapTradeSummary),
      investorSummaries: data.investorSummaries.rows.map(mapInvestorSummary),
      purchaseReturns: data.purchaseReturns.rows.map(mapPurchaseReturn),
      salesReturns: data.salesReturns.rows.map(mapSaleReturn),
      purchaseAdvances: data.purchaseAdvances.rows.map(mapPurchaseAdvance),
      miscIncome: data.miscIncome.rows.map(mapMiscIncome)
    });
  } catch (err) {
    console.error('GET /api/state error:', err);
    res.status(500).json({ error: 'Unable to load state' });
  }
});

// Deprecated: full-state replace. Kept only so the current single-page
// frontend keeps working during the Phase 4 rewire to per-entity endpoints
// (see the /api/sales, /api/purchases, etc. routes below, which are the
// real target — this handler still scopes every statement by client_id so
// it is RLS-safe in the meantime, but it is not how new code should save data).
app.post('/api/state', requireAuth, resolveActiveClient, requireClientAccess('editor'), async (req, res) => {
  const b = req.body || {};
  const settings = b.settings || {};
  try {
    await withTenantDb(req.clientId, async (client) => {
      const cid = req.clientId;
      await client.query(
        `INSERT INTO settings (client_id, company_name, business_label, opening_cash, cheque_reminder_days, credit_reminder_days, setup_mode)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (client_id) DO UPDATE SET company_name=$2, business_label=$3, opening_cash=$4, cheque_reminder_days=$5, credit_reminder_days=$6, setup_mode=$7`,
        [cid, settings.companyName || '', settings.businessLabel || '', Number(settings.openingCash) || 0,
          Number(settings.chequeReminderDays) || 0, Number(settings.creditReminderDays) || 0, !!settings.setupMode]
      );

      // children that reference partners must be replaced before partners
      for (const t of ['sales', 'purchases', 'cheques', 'investors', 'expenses', 'receipts', 'payouts', 'audit_log', 'stock', 'partners', 'bank_accounts']) {
        await client.query(`DELETE FROM ${t} WHERE client_id = $1`, [cid]);
      }

      for (const x of b.banks || []) {
        await client.query('INSERT INTO bank_accounts (id, client_id, name, opening_balance) VALUES ($1,$2,$3,$4)', [x.id, cid, x.name, Number(x.openingBalance) || 0]);
      }
      for (const x of b.partners || []) {
        await client.query('INSERT INTO partners (id, client_id, name, opening_profit) VALUES ($1,$2,$3,$4)', [x.id, cid, x.name, Number(x.openingProfit) || 0]);
      }
      for (const x of b.stock || []) {
        await client.query('INSERT INTO stock (id, client_id, name, unit, qty, rate, avg_cost) VALUES ($1,$2,$3,$4,$5,$6,$7)', [x.id, cid, x.name, x.unit || 'kg', Number(x.qty) || 0, Number(x.rate) || 0, Number(x.avgCost) || 0]);
      }
      for (const x of b.sales || []) {
        await client.query(
          `INSERT INTO sales (id,client_id,date,party,item,qty,unit,rate,total,type,account_id,paid,due_date,credit_days,profit,partner_id,partner_percent)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
          [x.id, cid, x.date, x.party, x.item, Number(x.qty) || 0, x.unit || 'kg', Number(x.rate) || 0, Number(x.total) || 0,
            x.type, x.account || 'cash', !!x.paid, x.dueDate || null, x.creditDays || null, x.profit != null ? Number(x.profit) : null,
            x.partnerId || null, x.partnerPercent != null ? Number(x.partnerPercent) : null]
        );
      }
      for (const x of b.purchases || []) {
        await client.query(
          `INSERT INTO purchases (id,client_id,date,supplier,item,qty,unit,rate,total,type,account_id,paid)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
          [x.id, cid, x.date, x.supplier, x.item, Number(x.qty) || 0, x.unit || 'kg', Number(x.rate) || 0, Number(x.total) || 0, x.type, x.account || 'cash', !!x.paid]
        );
      }
      for (const x of b.cheques || []) {
        await client.query('INSERT INTO cheques (id,client_id,date,party,bank,amount,due_date,account_id,status,receipt_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)', [x.id, cid, x.date, x.party, x.bank || null, Number(x.amount) || 0, x.dueDate, x.account || 'cash', x.status || 'pending', x.receiptId || null]);
      }
      for (const x of b.investors || []) {
        await client.query('INSERT INTO investors (id,client_id,name,amount,ratio,account_id) VALUES ($1,$2,$3,$4,$5,$6)', [x.id, cid, x.name, Number(x.amount) || 0, Number(x.ratio) || 0, x.account || 'cash']);
      }
      for (const x of b.expenses || []) {
        await client.query('INSERT INTO expenses (id,client_id,date,description,amount,account_id) VALUES ($1,$2,$3,$4,$5,$6)', [x.id, cid, x.date, x.desc, Number(x.amount) || 0, x.account || 'cash']);
      }
      for (const x of b.receipts || []) {
        await client.query('INSERT INTO receipts (id,client_id,date,party,amount,account_id,note) VALUES ($1,$2,$3,$4,$5,$6,$7)', [x.id, cid, x.date, x.party, Number(x.amount) || 0, x.account || 'cash', x.note || null]);
      }
      for (const x of b.payouts || []) {
        await client.query('INSERT INTO payouts (id,client_id,date,recipient_type,recipient_id,amount,account_id,note) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [x.id, cid, x.date, x.recipientType, x.recipientId, Number(x.amount) || 0, x.account || 'cash', x.note || null]);
      }
      for (const x of b.auditLog || []) {
        await client.query('INSERT INTO audit_log (id,client_id,kind,action,action_date,before,after,entry) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', [x.id, cid, x.kind, x.action, x.actionDate, x.before || null, x.after || null, x.entry || null]);
      }
    });
    res.json({ ok: true });
  } catch (err) {
    console.error('POST /api/state error:', err);
    res.status(500).json({ error: 'Unable to save state' });
  }
});

// =====================================================================
// Per-entity REST endpoints — the real target API (see GET/POST /api/state
// above, which is deprecated but kept for the current frontend). Each of
// these is client-scoped via withTenantDb (RLS + app-layer WHERE), and
// writes its own audit_log row for edit/delete, matching what the old
// client-side entrySnapshot()/logAudit() calls used to do.
// =====================================================================

// ---------- sales ----------
app.post('/api/sales', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.party || !x.item || !x.qty || !x.rate) return res.status(400).json({ error: 'Missing required fields' });
  if (Number(x.qty) <= 0 || Number(x.rate) <= 0) return res.status(400).json({ error: 'Quantity and rate must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const total = Number(x.qty) * Number(x.rate);
      const settingsRow = await db.query('SELECT setup_mode FROM settings WHERE client_id=$1', [req.clientId]);
      const staged = !!(settingsRow.rows[0] && settingsRow.rows[0].setup_mode);
      // Historical Data Entry Mode: a staged sale is invisible to stock (see
      // recomputeStockItem) and to cash/bank (frontend filters it out), so
      // there's nothing meaningful to check it against yet — skip the
      // oversell guard entirely for it. Its real profit gets computed once
      // it goes live (see unstageHistoricalEntries).
      let profit = 0;
      let sourcePurchaseId = null;
      if (!staged) {
        const stockRow = await db.query('SELECT qty FROM stock WHERE client_id=$1 AND name=$2 AND unit=$3', [req.clientId, x.item, x.unit || 'kg']);
        const available = stockRow.rows[0] ? Number(stockRow.rows[0].qty) : 0;
        if (Number(x.qty) > available) {
          const e = new Error(`Only ${available} ${x.unit || 'kg'} of "${x.item}" in stock — cannot sell ${x.qty}`);
          e.code = 'INSUFFICIENT_STOCK';
          throw e;
        }
        // profit comes from the exact batch named, never a blended average —
        // if stock exists at all, a batch must be named.
        if (available > 0.001 && !x.sourcePurchaseId) {
          const e = new Error(`Select which purchase batch this sale of "${x.item}" is coming from.`);
          e.code = 'INSUFFICIENT_STOCK';
          throw e;
        }
        if (x.sourcePurchaseId) {
          const batch = await resolveSaleBatch(db, req.clientId, x.item, x.unit || 'kg', x.sourcePurchaseId, null);
          if (!batch || batch.notFound) { const e = new Error('Selected purchase batch not found.'); e.code = 'INSUFFICIENT_STOCK'; throw e; }
          if (batch.mismatch) { const e = new Error('Selected purchase batch does not match this item/unit.'); e.code = 'INSUFFICIENT_STOCK'; throw e; }
          if (Number(x.qty) > batch.remaining + 0.001) { const e = new Error(`That purchase batch only has ${batch.remaining} ${x.unit || 'kg'} left — cannot sell ${x.qty}.`); e.code = 'INSUFFICIENT_STOCK'; throw e; }
          profit = (Number(x.rate) - batch.rate) * Number(x.qty);
          sourcePurchaseId = x.sourcePurchaseId;
        }
      }
      const id = crypto.randomUUID();
      const r = await db.query(
        `INSERT INTO sales (id,client_id,date,party,item,qty,unit,rate,total,type,account_id,paid,due_date,credit_days,profit,partner_id,partner_percent,staged,source_purchase_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) RETURNING *`,
        [id, req.clientId, x.date, x.party, x.item, Number(x.qty), x.unit || 'kg', Number(x.rate), total, x.type,
          x.account || 'cash', false, x.type === 'credit' ? x.dueDate || null : null, x.type === 'credit' ? x.creditDays || null : null,
          profit, x.partnerId || null, x.partnerPercent != null ? Number(x.partnerPercent) : null, staged, sourcePurchaseId]
      );
      await recomputeStockItem(db, req.clientId, x.item, x.unit || 'kg');
      // a buyer typed here for the first time should immediately show up as
      // an editable Buyer in Master Record (so a Due Date can be set on
      // their running balance later) — matching the Buyer form's own
      // long-standing "created automatically" note, which nothing actually
      // implemented until now.
      await db.query(
        'INSERT INTO parties (id,client_id,name,opening_balance) VALUES ($1,$2,$3,0) ON CONFLICT (client_id,name) DO NOTHING',
        [crypto.randomUUID(), req.clientId, x.party]
      );
      return r.rows[0];
    });
    res.json(mapSale(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_STOCK' || err.code === 'NEGATIVE_STOCK') return res.status(400).json({ error: err.message });
    console.error('POST /api/sales error:', err);
    res.status(500).json({ error: 'Unable to add sale' });
  }
});

app.patch('/api/sales/:id', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (Number(x.qty) <= 0 || Number(x.rate) <= 0) return res.status(400).json({ error: 'Quantity and rate must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const before = await db.query('SELECT * FROM sales WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!before.rows[0]) return null;
      const old = before.rows[0];
      const total = Number(x.qty) * Number(x.rate);
      // staged-ness is set once at creation (by whatever setup_mode was at
      // that time) and only ever cleared in bulk by unstageHistoricalEntries
      // — editing a still-staged sale must keep skipping the live checks.
      const staged = old.staged;
      let profit = old.profit;
      let sourcePurchaseId = old.source_purchase_id;
      if (!staged) {
        // this sale's OLD qty is still baked into the current stock.qty (until
        // the recompute below runs), so add it back to know what's really
        // available for the edited qty being saved now.
        const sameItem = old.item === x.item && old.unit === (x.unit || 'kg');
        const stockRow = await db.query('SELECT qty FROM stock WHERE client_id=$1 AND name=$2 AND unit=$3', [req.clientId, x.item, x.unit || 'kg']);
        const rawAvailable = stockRow.rows[0] ? Number(stockRow.rows[0].qty) : 0;
        const available = sameItem ? rawAvailable + Number(old.qty) : rawAvailable;
        if (Number(x.qty) > available) {
          const e = new Error(`Only ${available} ${x.unit || 'kg'} of "${x.item}" in stock — cannot sell ${x.qty}`);
          e.code = 'INSUFFICIENT_STOCK';
          throw e;
        }
        const requestedBatch = x.sourcePurchaseId !== undefined ? x.sourcePurchaseId : old.source_purchase_id;
        if (available > 0.001 && !requestedBatch) {
          const e = new Error(`Select which purchase batch this sale of "${x.item}" is coming from.`);
          e.code = 'INSUFFICIENT_STOCK';
          throw e;
        }
        if (requestedBatch) {
          const batch = await resolveSaleBatch(db, req.clientId, x.item, x.unit || 'kg', requestedBatch, req.params.id);
          if (!batch || batch.notFound) { const e = new Error('Selected purchase batch not found.'); e.code = 'INSUFFICIENT_STOCK'; throw e; }
          if (batch.mismatch) { const e = new Error('Selected purchase batch does not match this item/unit.'); e.code = 'INSUFFICIENT_STOCK'; throw e; }
          if (Number(x.qty) > batch.remaining + 0.001) { const e = new Error(`That purchase batch only has ${batch.remaining} ${x.unit || 'kg'} left — cannot sell ${x.qty}.`); e.code = 'INSUFFICIENT_STOCK'; throw e; }
          profit = (Number(x.rate) - batch.rate) * Number(x.qty);
          sourcePurchaseId = requestedBatch;
        } else {
          profit = 0;
          sourcePurchaseId = null;
        }
      }
      const r = await db.query(
        `UPDATE sales SET date=$1,party=$2,item=$3,qty=$4,unit=$5,rate=$6,total=$7,type=$8,account_id=$9,
           due_date=$10,credit_days=$11,profit=$12,partner_id=$13,partner_percent=$14,source_purchase_id=$17
         WHERE id=$15 AND client_id=$16 RETURNING *`,
        [x.date, x.party, x.item, Number(x.qty), x.unit || 'kg', Number(x.rate), total, x.type, x.account || 'cash',
          x.type === 'credit' ? x.dueDate || null : null, x.type === 'credit' ? x.creditDays || null : null,
          profit, x.partnerId || null, x.partnerPercent != null ? Number(x.partnerPercent) : null, req.params.id, req.clientId, sourcePurchaseId]
      );
      await recomputeStockItem(db, req.clientId, old.item, old.unit);
      if (old.item !== x.item || old.unit !== (x.unit || 'kg')) await recomputeStockItem(db, req.clientId, x.item, x.unit || 'kg');
      if (old.party !== x.party) {
        await db.query(
          'INSERT INTO parties (id,client_id,name,opening_balance) VALUES ($1,$2,$3,0) ON CONFLICT (client_id,name) DO NOTHING',
          [crypto.randomUUID(), req.clientId, x.party]
        );
      }
      await writeAudit(db, req.clientId, 'sale', 'edit', {
        before: { date: old.date, who: old.party, item: old.item, qty: old.qty, unit: old.unit, rate: old.rate, total: old.total },
        after: { date: x.date, who: x.party, item: x.item, qty: x.qty, unit: x.unit, rate: x.rate, total }
      });
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Sale not found' });
    res.json(mapSale(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_STOCK' || err.code === 'NEGATIVE_STOCK') return res.status(400).json({ error: err.message });
    console.error('PATCH /api/sales/:id error:', err);
    res.status(500).json({ error: 'Unable to update sale' });
  }
});

app.delete('/api/sales/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM sales WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      // QA Round 16: blocking used to key off "does this party have ANY
      // receipt at all", which wrongly blocked unrelated unpaid sales for
      // the same party. Check this specific sale's own FIFO-applied amount
      // instead (same pooling the Ledger already uses) — only a sale that
      // has actually drawn money from the pool blocks its own deletion.
      if (old.type === 'credit') {
        const applied = await partySaleFifoAppliedDb(db, req.clientId, old.party, old.id);
        if (applied > 0.009) {
          const e = new Error(`Rs ${applied.toFixed(2)} has already been received against this sale (FIFO-applied from ${old.party}'s receipts) — delete or edit that receipt from the Ledger first, then this sale.`);
          e.code = 'HAS_PAYMENTS';
          throw e;
        }
      }
      const returnCheck = await db.query('SELECT 1 FROM sales_returns WHERE sale_id=$1 LIMIT 1', [req.params.id]);
      if (returnCheck.rows[0]) {
        const e = new Error('This sale has a Sales Return recorded against it — delete that return first, then this sale.');
        e.code = 'HAS_PAYMENTS';
        throw e;
      }
      await db.query('DELETE FROM sales WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await recomputeStockItem(db, req.clientId, old.item, old.unit);
      await writeAudit(db, req.clientId, 'sale', 'delete', {
        entry: { date: old.date, who: old.party, item: old.item, qty: old.qty, unit: old.unit, rate: old.rate, total: old.total }
      });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Sale not found' });
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 'NEGATIVE_STOCK' || err.code === 'HAS_PAYMENTS') return res.status(400).json({ error: err.message });
    console.error('DELETE /api/sales/:id error:', err);
    res.status(500).json({ error: 'Unable to delete sale' });
  }
});

// ---------- sales returns (goods a buyer sends back) ----------
app.post('/api/sales-returns', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.saleId || !x.date || !x.qty || !x.settlement) return res.status(400).json({ error: 'Missing required fields' });
  if (!['refund', 'credit'].includes(x.settlement)) return res.status(400).json({ error: 'Settlement must be refund or credit' });
  if (Number(x.qty) <= 0) return res.status(400).json({ error: 'Quantity must be greater than zero' });
  if (x.settlement === 'refund' && !x.account) return res.status(400).json({ error: 'Choose which account the refund is paid from' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const saleRow = await db.query('SELECT * FROM sales WHERE id=$1 AND client_id=$2', [x.saleId, req.clientId]);
      if (!saleRow.rows[0]) { const e = new Error('Sale not found'); e.code = 'NOT_FOUND'; throw e; }
      const sale = saleRow.rows[0];
      if (sale.staged) { const e = new Error('Cannot record a return against a Historical (staged) sale.'); e.code = 'NEGATIVE_STOCK'; throw e; }
      // 'credit' settlement works by shrinking THIS sale's own effective
      // total (see partySaleFifoAppliedDb) — meaningless on a cash sale,
      // which never draws from the receipts pool at all. Refund is the
      // only settlement that actually moves anything in that case.
      if (x.settlement === 'credit' && sale.type === 'cash') {
        const e = new Error('This is a cash sale — there is no receivable for a credit settlement to reduce. Choose Refund instead.');
        e.code = 'NEGATIVE_STOCK';
        throw e;
      }
      const alreadyReturned = Number((await db.query('SELECT COALESCE(SUM(qty),0) s FROM sales_returns WHERE sale_id=$1', [x.saleId])).rows[0].s);
      const returnable = Number(sale.qty) - alreadyReturned;
      if (Number(x.qty) > returnable + 0.001) {
        const e = new Error(`Only ${returnable} ${sale.unit} from this sale can still be returned (${alreadyReturned} already returned).`);
        e.code = 'NEGATIVE_STOCK';
        throw e;
      }
      const rate = Number(sale.rate);
      const total = Number(x.qty) * rate;
      if (x.settlement === 'refund') await assertFundsAvailable(db, req.clientId, x.account, total);
      const id = crypto.randomUUID();
      const r = await db.query(
        `INSERT INTO sales_returns (id, client_id, date, sale_id, qty, rate, total, settlement, account_id, note)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
        [id, req.clientId, x.date, x.saleId, Number(x.qty), rate, total, x.settlement, x.settlement === 'refund' ? x.account : null, x.note || null]
      );
      await recomputeStockItem(db, req.clientId, sale.item, sale.unit);
      return r.rows[0];
    });
    res.json(mapSaleReturn(row));
  } catch (err) {
    if (err.code === 'NOT_FOUND') return res.status(404).json({ error: err.message });
    if (err.code === 'NEGATIVE_STOCK' || err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('POST /api/sales-returns error:', err);
    res.status(500).json({ error: 'Unable to record sales return' });
  }
});

app.delete('/api/sales-returns/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM sales_returns WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      const sale = (await db.query('SELECT item, unit, party FROM sales WHERE id=$1', [old.sale_id])).rows[0];
      await db.query('DELETE FROM sales_returns WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (sale) await recomputeStockItem(db, req.clientId, sale.item, sale.unit);
      await writeAudit(db, req.clientId, 'sale_return', 'delete', {
        entry: { date: old.date, who: sale ? sale.party : '—', item: sale ? sale.item : '—', qty: old.qty, unit: sale ? sale.unit : '', rate: old.rate, total: old.total }
      });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Sales return not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/sales-returns/:id error:', err);
    res.status(500).json({ error: 'Unable to delete sales return' });
  }
});

// ---------- purchases ----------
app.post('/api/purchases', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.supplier || !x.item || !x.qty || !x.rate) return res.status(400).json({ error: 'Missing required fields' });
  if (Number(x.qty) <= 0 || Number(x.rate) <= 0) return res.status(400).json({ error: 'Quantity and rate must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const unit = x.unit || 'kg';
      const settingsRow = await db.query('SELECT setup_mode FROM settings WHERE client_id=$1', [req.clientId]);
      const staged = !!(settingsRow.rows[0] && settingsRow.rows[0].setup_mode);
      // A material is defined by its name alone, so it should only ever
      // have one stock-tracking unit. Block only the case that WOULD create
      // a genuinely new/third unit-variant for this name — i.e. no stock row
      // exists yet for (name, this unit), but a row already exists for
      // (name, some OTHER unit). If a row for (name, this unit) already
      // exists — including a legacy-fragmented material that already has
      // more than one unit from before this guard existed — this purchase
      // is just adding to that existing pool and must stay allowed, or a
      // material with pre-existing fragmentation would become permanently
      // un-purchasable in every unit (blocked no matter which one is picked).
      // Skipped entirely while staged — see recomputeStockItem.
      if (!staged) {
        const sameUnitRow = await db.query('SELECT 1 FROM stock WHERE client_id=$1 AND name=$2 AND unit=$3', [req.clientId, x.item, unit]);
        if (!sameUnitRow.rows[0]) {
          const otherUnit = await db.query('SELECT unit FROM stock WHERE client_id=$1 AND name=$2 AND unit<>$3 LIMIT 1', [req.clientId, x.item, unit]);
          if (otherUnit.rows[0]) {
            const e = new Error(`"${x.item}" is already tracked in ${otherUnit.rows[0].unit} — please use ${otherUnit.rows[0].unit} for this material.`);
            e.code = 'UNIT_MISMATCH';
            throw e;
          }
        }
      }
      const total = Number(x.qty) * Number(x.rate);
      const id = crypto.randomUUID();
      const r = await db.query(
        `INSERT INTO purchases (id,client_id,date,supplier,item,qty,unit,rate,total,type,account_id,paid,staged,funding_transfer_ids,funding_loan_ids)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,
        [id, req.clientId, x.date, x.supplier, x.item, Number(x.qty), unit, Number(x.rate), total, x.type, x.account || 'cash', false, staged,
          fundingIdsJson(x.fundingTransferIds), fundingIdsJson(x.fundingLoanIds)]
      );
      await recomputeStockItem(db, req.clientId, x.item, unit);
      // same as sales auto-creating a Buyer — a supplier typed here for the
      // first time should immediately be editable in Master Record.
      await db.query(
        'INSERT INTO suppliers (id,client_id,name,opening_balance) VALUES ($1,$2,$3,0) ON CONFLICT (client_id,name) DO NOTHING',
        [crypto.randomUUID(), req.clientId, x.supplier]
      );
      return r.rows[0];
    });
    res.json(mapPurchase(row));
  } catch (err) {
    if (err.code === 'UNIT_MISMATCH' || err.code === 'NEGATIVE_STOCK') return res.status(400).json({ error: err.message });
    console.error('POST /api/purchases error:', err);
    res.status(500).json({ error: 'Unable to add purchase' });
  }
});

app.patch('/api/purchases/:id', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (Number(x.qty) <= 0 || Number(x.rate) <= 0) return res.status(400).json({ error: 'Quantity and rate must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const before = await db.query('SELECT * FROM purchases WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!before.rows[0]) return null;
      const old = before.rows[0];
      const unit = x.unit || 'kg';
      // staged-ness is fixed at creation, only cleared in bulk when
      // Historical Data Entry Mode is turned off (unstageHistoricalEntries).
      if (!old.staged && (old.item !== x.item || old.unit !== unit)) {
        const sameUnitRow = await db.query('SELECT 1 FROM stock WHERE client_id=$1 AND name=$2 AND unit=$3', [req.clientId, x.item, unit]);
        const otherUnit = sameUnitRow.rows[0] ? { rows: [] } : await db.query('SELECT unit FROM stock WHERE client_id=$1 AND name=$2 AND unit<>$3 LIMIT 1', [req.clientId, x.item, unit]);
        if (otherUnit.rows[0]) {
          const e = new Error(`"${x.item}" is already tracked in ${otherUnit.rows[0].unit} — please use ${otherUnit.rows[0].unit} for this material.`);
          e.code = 'UNIT_MISMATCH';
          throw e;
        }
      }
      if (!old.staged) {
        const itemChanged = old.item !== x.item || old.unit !== unit;
        if (itemChanged || Number(x.qty) < Number(old.qty)) {
          await assertPurchaseLotNotOversold(db, req.clientId, req.params.id, itemChanged ? 0 : Number(x.qty));
        }
      }
      const total = Number(x.qty) * Number(x.rate);
      const r = await db.query(
        `UPDATE purchases SET date=$1,supplier=$2,item=$3,qty=$4,unit=$5,rate=$6,total=$7,type=$8,account_id=$9
         WHERE id=$10 AND client_id=$11 RETURNING *`,
        [x.date, x.supplier, x.item, Number(x.qty), unit, Number(x.rate), total, x.type, x.account || 'cash', req.params.id, req.clientId]
      );
      await recomputeStockItem(db, req.clientId, old.item, old.unit);
      if (old.item !== x.item || old.unit !== unit) await recomputeStockItem(db, req.clientId, x.item, unit);
      if (old.supplier !== x.supplier) {
        await db.query(
          'INSERT INTO suppliers (id,client_id,name,opening_balance) VALUES ($1,$2,$3,0) ON CONFLICT (client_id,name) DO NOTHING',
          [crypto.randomUUID(), req.clientId, x.supplier]
        );
      }
      await writeAudit(db, req.clientId, 'purchase', 'edit', {
        before: { date: old.date, who: old.supplier, item: old.item, qty: old.qty, unit: old.unit, rate: old.rate, total: old.total },
        after: { date: x.date, who: x.supplier, item: x.item, qty: x.qty, unit: x.unit, rate: x.rate, total }
      });
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Purchase not found' });
    res.json(mapPurchase(row));
  } catch (err) {
    if (err.code === 'UNIT_MISMATCH' || err.code === 'NEGATIVE_STOCK') return res.status(400).json({ error: err.message });
    console.error('PATCH /api/purchases/:id error:', err);
    res.status(500).json({ error: 'Unable to update purchase' });
  }
});

app.post('/api/purchases/:id/mark-paid', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const existing = await db.query("SELECT total FROM purchases WHERE id=$1 AND client_id=$2 AND type='credit' AND NOT staged", [req.params.id, req.clientId]);
      if (!existing.rows[0]) return null;
      await assertFundsAvailable(db, req.clientId, x.account || 'cash', Number(existing.rows[0].total));
      const r = await db.query("UPDATE purchases SET paid=true, account_id=$1 WHERE id=$2 AND client_id=$3 AND type='credit' AND NOT staged RETURNING *",
        [x.account || 'cash', req.params.id, req.clientId]);
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Purchase not found, or it is still Historical (turn off Historical Data Entry Mode first)' });
    res.json(mapPurchase(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('POST /api/purchases/:id/mark-paid error:', err);
    res.status(500).json({ error: 'Unable to mark purchase paid' });
  }
});

app.delete('/api/purchases/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM purchases WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      if (!old.staged) await assertPurchaseLotNotOversold(db, req.clientId, req.params.id, 0);
      // QA Round 16 — same per-record fix as the sales delete check above:
      // only block when THIS purchase has actually drawn money from the
      // supplier's FIFO-pooled payments, not merely because the supplier
      // has payments recorded somewhere.
      if (old.type === 'credit' && !old.paid) {
        const applied = await supplierPurchaseFifoAppliedDb(db, req.clientId, old.supplier, old.id);
        if (applied > 0.009) {
          const e = new Error(`Rs ${applied.toFixed(2)} has already been paid against this purchase (FIFO-applied from ${old.supplier}'s payments) — delete or edit that payment from the Ledger first, then this purchase.`);
          e.code = 'HAS_PAYMENTS';
          throw e;
        }
      }
      await deleteFundingLinks(db, req.clientId, old.funding_transfer_ids, old.funding_loan_ids);
      // a purchase created via Complete Purchase on a Supplier Advance
      // carries that advance's money — deleting it must reopen the advance
      // (not just null the FK) so the money isn't silently lost from view.
      await db.query("UPDATE purchase_advances SET status='open', purchase_id=NULL WHERE purchase_id=$1 AND client_id=$2", [req.params.id, req.clientId]);
      await db.query('DELETE FROM purchases WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await recomputeStockItem(db, req.clientId, old.item, old.unit);
      await writeAudit(db, req.clientId, 'purchase', 'delete', {
        entry: { date: old.date, who: old.supplier, item: old.item, qty: old.qty, unit: old.unit, rate: old.rate, total: old.total }
      });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Purchase not found' });
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 'NEGATIVE_STOCK' || err.code === 'HAS_PAYMENTS') return res.status(400).json({ error: err.message });
    console.error('DELETE /api/purchases/:id error:', err);
    res.status(500).json({ error: 'Unable to delete purchase' });
  }
});

// ---------- purchase returns (goods sent back to a supplier) ----------
app.post('/api/purchase-returns', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.purchaseId || !x.date || !x.qty || !x.settlement) return res.status(400).json({ error: 'Missing required fields' });
  if (!['refund', 'credit'].includes(x.settlement)) return res.status(400).json({ error: 'Settlement must be refund or credit' });
  if (Number(x.qty) <= 0) return res.status(400).json({ error: 'Quantity must be greater than zero' });
  if (x.settlement === 'refund' && !x.account) return res.status(400).json({ error: 'Choose which account the refund is paid into' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const purchaseRow = await db.query('SELECT * FROM purchases WHERE id=$1 AND client_id=$2', [x.purchaseId, req.clientId]);
      if (!purchaseRow.rows[0]) { const e = new Error('Purchase not found'); e.code = 'NOT_FOUND'; throw e; }
      const purchase = purchaseRow.rows[0];
      if (purchase.staged) { const e = new Error('Cannot record a return against a Historical (staged) purchase.'); e.code = 'NEGATIVE_STOCK'; throw e; }
      // 'credit' settlement works by shrinking THIS purchase's own effective
      // total (see supplierPurchaseFifoAppliedDb) — meaningless on a cash or
      // already-fully-paid purchase, since there's no pending balance left
      // to shrink. Refund is the only settlement that actually moves
      // anything in that case.
      if (x.settlement === 'credit' && (purchase.type === 'cash' || purchase.paid)) {
        const e = new Error('This purchase is cash (or already fully paid) — there is no pending balance for a credit settlement to reduce. Choose Refund instead.');
        e.code = 'NEGATIVE_STOCK';
        throw e;
      }
      // same "remaining in this batch" math as assertPurchaseLotNotOversold —
      // a return can't take out more than is actually left of this purchase
      // once what's already been sold (net of sales returns) and already
      // returned are accounted for.
      const salesRows = (await db.query('SELECT id, qty FROM sales WHERE client_id=$1 AND source_purchase_id=$2 AND NOT staged', [req.clientId, x.purchaseId])).rows;
      const soldQty = salesRows.reduce((a, r) => a + Number(r.qty), 0);
      const saleIds = salesRows.map((r) => r.id);
      const salesReturnedQty = saleIds.length
        ? Number((await db.query('SELECT COALESCE(SUM(qty),0) s FROM sales_returns WHERE sale_id = ANY($1::text[])', [saleIds])).rows[0].s)
        : 0;
      const alreadyReturned = Number((await db.query('SELECT COALESCE(SUM(qty),0) s FROM purchase_returns WHERE purchase_id=$1', [x.purchaseId])).rows[0].s);
      const returnable = Number(purchase.qty) - soldQty + salesReturnedQty - alreadyReturned;
      if (Number(x.qty) > returnable + 0.001) {
        const e = new Error(`Only ${returnable} ${purchase.unit} from this purchase can still be returned (${soldQty - salesReturnedQty} already sold, ${alreadyReturned} already returned).`);
        e.code = 'NEGATIVE_STOCK';
        throw e;
      }
      const rate = Number(purchase.rate);
      const total = Number(x.qty) * rate;
      const id = crypto.randomUUID();
      const r = await db.query(
        `INSERT INTO purchase_returns (id, client_id, date, purchase_id, qty, rate, total, settlement, account_id, note)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
        [id, req.clientId, x.date, x.purchaseId, Number(x.qty), rate, total, x.settlement, x.settlement === 'refund' ? x.account : null, x.note || null]
      );
      await recomputeStockItem(db, req.clientId, purchase.item, purchase.unit);
      return r.rows[0];
    });
    res.json(mapPurchaseReturn(row));
  } catch (err) {
    if (err.code === 'NOT_FOUND') return res.status(404).json({ error: err.message });
    if (err.code === 'NEGATIVE_STOCK') return res.status(400).json({ error: err.message });
    console.error('POST /api/purchase-returns error:', err);
    res.status(500).json({ error: 'Unable to record purchase return' });
  }
});

app.delete('/api/purchase-returns/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM purchase_returns WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      const purchase = (await db.query('SELECT item, unit, supplier FROM purchases WHERE id=$1', [old.purchase_id])).rows[0];
      await db.query('DELETE FROM purchase_returns WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (purchase) await recomputeStockItem(db, req.clientId, purchase.item, purchase.unit);
      await writeAudit(db, req.clientId, 'purchase_return', 'delete', {
        entry: { date: old.date, who: purchase ? purchase.supplier : '—', item: purchase ? purchase.item : '—', qty: old.qty, unit: purchase ? purchase.unit : '', rate: old.rate, total: old.total }
      });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Purchase return not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/purchase-returns/:id error:', err);
    res.status(500).json({ error: 'Unable to delete purchase return' });
  }
});

// ---------- purchase advances (money issued to a supplier before the
// purchase's qty/rate/item is known — see schema comment above) ----------
app.post('/api/purchase-advances', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.supplier || !x.date) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const account = x.account || 'cash';
      await assertFundsAvailable(db, req.clientId, account, Number(x.amount));
      const r = await db.query(
        `INSERT INTO purchase_advances (id, client_id, date, supplier, amount, account_id, note, status, funding_transfer_ids, funding_loan_ids)
         VALUES ($1,$2,$3,$4,$5,$6,$7,'open',$8,$9) RETURNING *`,
        [crypto.randomUUID(), req.clientId, x.date, x.supplier, Number(x.amount), account, x.note || null, fundingIdsJson(x.fundingTransferIds), fundingIdsJson(x.fundingLoanIds)]
      );
      return r.rows[0];
    });
    res.json(mapPurchaseAdvance(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('POST /api/purchase-advances error:', err);
    res.status(500).json({ error: 'Unable to issue purchase advance' });
  }
});

app.post('/api/purchase-advances/:id/complete', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.item || !x.qty || !x.rate) return res.status(400).json({ error: 'Missing required fields' });
  if (Number(x.qty) <= 0 || Number(x.rate) <= 0) return res.status(400).json({ error: 'Quantity and rate must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const advRow = await db.query('SELECT * FROM purchase_advances WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!advRow.rows[0]) { const e = new Error('Advance not found'); e.code = 'NOT_FOUND'; throw e; }
      const adv = advRow.rows[0];
      if (adv.status !== 'open') { const e = new Error('This advance has already been completed.'); e.code = 'ALREADY_DONE'; throw e; }
      const unit = x.unit || 'kg';
      const total = Number(x.qty) * Number(x.rate);
      // created unpaid (credit) on purpose — the money already left the
      // account when the advance itself was issued (see
      // computeAccountBalanceDb); this purchase must never deduct it again.
      // supplierPurchaseFifoAppliedDb then settles up to the advance amount
      // against this specific purchase, same as a credit-settled return.
      const purchaseId = crypto.randomUUID();
      const pr = await db.query(
        `INSERT INTO purchases (id, client_id, date, supplier, item, qty, unit, rate, total, type, account_id, paid)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'credit',$10,false) RETURNING *`,
        [purchaseId, req.clientId, adv.date, adv.supplier, x.item, Number(x.qty), unit, Number(x.rate), total, adv.account_id]
      );
      await recomputeStockItem(db, req.clientId, x.item, unit);
      const updated = await db.query(
        "UPDATE purchase_advances SET status='completed', purchase_id=$1 WHERE id=$2 AND client_id=$3 RETURNING *",
        [purchaseId, req.params.id, req.clientId]
      );
      return { advance: updated.rows[0], purchase: pr.rows[0] };
    });
    res.json({ advance: mapPurchaseAdvance(row.advance), purchase: mapPurchase(row.purchase) });
  } catch (err) {
    if (err.code === 'NOT_FOUND') return res.status(404).json({ error: err.message });
    if (err.code === 'ALREADY_DONE') return res.status(400).json({ error: err.message });
    console.error('POST /api/purchase-advances/:id/complete error:', err);
    res.status(500).json({ error: 'Unable to complete purchase' });
  }
});

app.delete('/api/purchase-advances/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM purchase_advances WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      if (old.status !== 'open') { const e = new Error('This advance has already been completed — delete the linked purchase instead to undo it.'); e.code = 'ALREADY_DONE'; throw e; }
      await deleteFundingLinks(db, req.clientId, old.funding_transfer_ids, old.funding_loan_ids);
      await db.query('DELETE FROM purchase_advances WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'purchase_advance', 'delete', { entry: { date: old.date, supplier: old.supplier, amount: old.amount, account: old.account_id } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Advance not found' });
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 'ALREADY_DONE') return res.status(400).json({ error: err.message });
    if (err.code === 'HAS_PAYMENTS') return res.status(400).json({ error: err.message });
    console.error('DELETE /api/purchase-advances/:id error:', err);
    res.status(500).json({ error: 'Unable to delete advance' });
  }
});

// ---------- cheques ----------
app.post('/api/cheques', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.party || !x.dueDate) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  const direction = x.direction === 'issued' ? 'issued' : 'received';
  try {
    const row = await withTenantDb(req.clientId, (db) =>
      db.query(
        'INSERT INTO cheques (id,client_id,date,party,bank,amount,due_date,account_id,status,direction) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.date, x.party, x.bank || null, Number(x.amount), x.dueDate, x.account || 'cash', 'pending', direction]
      ).then((r) => r.rows[0])
    );
    res.json(mapCheque(row));
  } catch (err) {
    console.error('POST /api/cheques error:', err);
    res.status(500).json({ error: 'Unable to add cheque' });
  }
});

app.patch('/api/cheques/:id', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.party || !x.dueDate) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  const direction = x.direction === 'issued' ? 'issued' : 'received';
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const before = await db.query('SELECT * FROM cheques WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!before.rows[0]) return null;
      const old = before.rows[0];
      // once cleared, the cheque's amount/direction/etc. already moved real
      // money into a receipt/supplier_payment row — editing those basic
      // details here wouldn't update that linked row, so this only allows
      // changing a cheque while it's still Pending. Edit the resulting
      // receipt/payment directly (Ledger) once a cheque has cleared.
      if (old.status !== 'pending') {
        const e = new Error('This cheque has already cleared — edit the receipt/payment it created from the Ledger instead.');
        e.code = 'ALREADY_CLEARED';
        throw e;
      }
      const r = await db.query(
        'UPDATE cheques SET date=$1, party=$2, bank=$3, amount=$4, due_date=$5, account_id=$6, direction=$7 WHERE id=$8 AND client_id=$9 RETURNING *',
        [x.date, x.party, x.bank || null, Number(x.amount), x.dueDate, x.account || 'cash', direction, req.params.id, req.clientId]
      );
      await writeAudit(db, req.clientId, 'cheque', 'edit', {
        before: { date: old.date, party: old.party, bank: old.bank, amount: old.amount, dueDate: old.due_date, direction: old.direction },
        after: { date: x.date, party: x.party, bank: x.bank, amount: x.amount, dueDate: x.dueDate, direction }
      });
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Cheque not found' });
    res.json(mapCheque(row));
  } catch (err) {
    if (err.code === 'ALREADY_CLEARED') return res.status(400).json({ error: err.message });
    console.error('PATCH /api/cheques/:id error:', err);
    res.status(500).json({ error: 'Unable to update cheque' });
  }
});

// Clearing a cheque records the matching cash movement: a RECEIVED cheque
// (from a buyer) becomes a receipt (money in, against that party's
// receivable); an ISSUED cheque (to a supplier) becomes a supplier payment
// (money out, against that supplier's payable) — same two-entry idea the
// user asked for (issue/receive the cheque, then clear it at the bank).
app.post('/api/cheques/:id/clear', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const c = await db.query('SELECT * FROM cheques WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!c.rows[0]) return null;
      const cheque = c.rows[0];
      // defensive: POST/PATCH /api/cheques already reject a non-positive
      // amount at entry, but clearing is the step that actually moves real
      // money, so double-check the stored value too — in case of old data
      // from before that guard existed.
      if (!isPositiveAmount(cheque.amount)) {
        const e = new Error('This cheque has an invalid amount and cannot be cleared — edit it to a positive amount first.');
        e.code = 'INSUFFICIENT_FUNDS';
        throw e;
      }
      const today = new Date().toISOString().slice(0, 10);
      // the account chosen when the cheque was first entered was only a
      // guess at whether it'd end up cashed or banked — clearing is when
      // that's actually known, so an account passed here overrides it.
      const account = x.account || cheque.account_id;
      if (cheque.direction === 'issued') {
        await assertFundsAvailable(db, req.clientId, account, Number(cheque.amount));
        const paymentId = crypto.randomUUID();
        await db.query('INSERT INTO supplier_payments (id,client_id,date,supplier,amount,account_id,note) VALUES ($1,$2,$3,$4,$5,$6,$7)', [
          paymentId, req.clientId, today, cheque.party, cheque.amount, account,
          `Cheque cleared${cheque.bank ? ' (' + cheque.bank + ')' : ''}`
        ]);
        const r = await db.query(
          "UPDATE cheques SET status='cleared', payment_id=$1, account_id=$2 WHERE id=$3 AND client_id=$4 RETURNING *",
          [paymentId, account, req.params.id, req.clientId]
        );
        return r.rows[0];
      }
      const receiptId = crypto.randomUUID();
      await db.query('INSERT INTO receipts (id,client_id,date,party,amount,account_id,note) VALUES ($1,$2,$3,$4,$5,$6,$7)', [
        receiptId, req.clientId, today, cheque.party, cheque.amount, account,
        `Cheque cleared${cheque.bank ? ' (' + cheque.bank + ')' : ''}`
      ]);
      const r = await db.query(
        "UPDATE cheques SET status='cleared', receipt_id=$1, account_id=$2 WHERE id=$3 AND client_id=$4 RETURNING *",
        [receiptId, account, req.params.id, req.clientId]
      );
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Cheque not found' });
    res.json(mapCheque(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('POST /api/cheques/:id/clear error:', err);
    res.status(500).json({ error: 'Unable to clear cheque' });
  }
});

app.delete('/api/cheques/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM cheques WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      if (old.receipt_id) await db.query('DELETE FROM receipts WHERE id=$1 AND client_id=$2', [old.receipt_id, req.clientId]);
      if (old.payment_id) await db.query('DELETE FROM supplier_payments WHERE id=$1 AND client_id=$2', [old.payment_id, req.clientId]);
      await db.query('DELETE FROM cheques WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'cheque', 'delete', {
        entry: { date: old.date, party: old.party, bank: old.bank, amount: old.amount, dueDate: old.due_date, status: old.status }
      });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Cheque not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/cheques/:id error:', err);
    res.status(500).json({ error: 'Unable to delete cheque' });
  }
});

// ---------- investors ----------
app.post('/api/investors', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.name) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const settingsRow = await db.query('SELECT setup_mode FROM settings WHERE client_id=$1', [req.clientId]);
      const staged = !!(settingsRow.rows[0] && settingsRow.rows[0].setup_mode);
      // Historical Data Entry Mode: a staged investor's capital counts toward
      // Total Investment / Trade Summary and the debt summary immediately,
      // but never toward Cash/Bank (see accountBalance() in the frontend) —
      // matching how staged sales/purchases are permanently excluded there.
      const r = await db.query(
        'INSERT INTO investors (id,client_id,name,amount,ratio,account_id,staged,date) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.name, Number(x.amount), 0, x.account || 'cash', staged, x.date || null]
      );
      return r.rows[0];
    });
    res.json(mapInvestor(row));
  } catch (err) {
    console.error('POST /api/investors error:', err);
    res.status(500).json({ error: 'Unable to add investor' });
  }
});

app.patch('/api/investors/:id', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const before = await db.query('SELECT * FROM investors WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!before.rows[0]) return null;
      const old = before.rows[0];
      const newAccount = x.account || 'cash';
      const r = await db.query('UPDATE investors SET name=$1, amount=$2, account_id=$3, date=$4 WHERE id=$5 AND client_id=$6 RETURNING *',
        [x.name, Number(x.amount), newAccount, x.date || null, req.params.id, req.clientId]);
      // QA: no overdraft guard existed on this edit path — a reduced
      // investment can leave an account that was already spent against it
      // negative, same risk as any other money-moving edit in this app.
      if (!old.staged) {
        const bal = await computeAccountBalanceDb(db, req.clientId, newAccount);
        if (bal < -0.009) {
          const e = new Error(`This edit would leave ${newAccount==='cash'?'Cash':'that account'} short by Rs ${Math.abs(bal).toFixed(2)} — reduce the amount, or pick a different account.`);
          e.code = 'INSUFFICIENT_FUNDS';
          throw e;
        }
      }
      await writeAudit(db, req.clientId, 'investor', 'edit', {
        before: { name: old.name, amount: old.amount, account: old.account_id },
        after: { name: x.name, amount: x.amount, account: x.account }
      });
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Investor not found' });
    res.json(mapInvestor(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('PATCH /api/investors/:id error:', err);
    res.status(500).json({ error: 'Unable to update investor' });
  }
});

app.delete('/api/investors/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM investors WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await db.query('DELETE FROM investors WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'investor', 'delete', { entry: { name: old.name, amount: old.amount, account: old.account_id } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Investor not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/investors/:id error:', err);
    res.status(500).json({ error: 'Unable to delete investor' });
  }
});

// ---------- commission agents (partners) ----------
app.post('/api/partners', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.name) return res.status(400).json({ error: 'Name required' });
  // opening balance may legitimately be 0 (a new agent with no prior
  // history) — only reject negative/NaN/Infinity, not zero.
  if (x.openingProfit !== undefined && x.openingProfit !== null && x.openingProfit !== '' && !isNonNegativeAmount(x.openingProfit)) {
    return res.status(400).json({ error: 'Opening Commission must be zero or greater' });
  }
  try {
    const row = await withTenantDb(req.clientId, (db) =>
      db.query('INSERT INTO partners (id,client_id,name,opening_profit) VALUES ($1,$2,$3,$4) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.name, Number(x.openingProfit) || 0]).then((r) => r.rows[0])
    );
    res.json(mapPartner(row));
  } catch (err) {
    console.error('POST /api/partners error:', err);
    res.status(500).json({ error: 'Unable to add partner' });
  }
});

app.delete('/api/partners/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM partners WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await db.query('DELETE FROM partners WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'partner', 'delete', { entry: { name: old.name, openingProfit: old.opening_profit } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Partner not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/partners/:id error:', err);
    res.status(500).json({ error: 'Unable to delete partner' });
  }
});

// ---------- bank accounts ----------
app.post('/api/banks', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.name) return res.status(400).json({ error: 'Name required' });
  try {
    const row = await withTenantDb(req.clientId, (db) =>
      db.query('INSERT INTO bank_accounts (id,client_id,name,opening_balance,is_locker) VALUES ($1,$2,$3,$4,$5) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.name, Number(x.openingBalance) || 0, !!x.locker]).then((r) => r.rows[0])
    );
    res.json(mapBank(row));
  } catch (err) {
    console.error('POST /api/banks error:', err);
    res.status(500).json({ error: 'Unable to add bank' });
  }
});

app.patch('/api/banks/:id', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const before = await db.query('SELECT * FROM bank_accounts WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!before.rows[0]) return null;
      const old = before.rows[0];
      const r = await db.query('UPDATE bank_accounts SET name=$1, opening_balance=$2, is_locker=$3 WHERE id=$4 AND client_id=$5 RETURNING *',
        [x.name, Number(x.openingBalance) || 0, !!x.locker, req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'bank', 'edit', {
        before: { name: old.name, openingBalance: old.opening_balance, locker: old.is_locker },
        after: { name: x.name, openingBalance: x.openingBalance, locker: x.locker }
      });
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Bank not found' });
    res.json(mapBank(row));
  } catch (err) {
    console.error('PATCH /api/banks/:id error:', err);
    res.status(500).json({ error: 'Unable to update bank' });
  }
});

app.delete('/api/banks/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM bank_accounts WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await db.query('DELETE FROM bank_accounts WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'bank', 'delete', { entry: { name: old.name, openingBalance: old.opening_balance } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Bank not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/banks/:id error:', err);
    res.status(500).json({ error: 'Unable to delete bank' });
  }
});

// ---------- parties (customers/suppliers — Party Ledger opening balances) ----------
app.post('/api/parties', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  const name = (x.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Name required' });
  try {
    const row = await withTenantDb(req.clientId, (db) =>
      db.query('INSERT INTO parties (id,client_id,name,opening_balance,due_date) VALUES ($1,$2,$3,$4,$5) RETURNING *',
        [crypto.randomUUID(), req.clientId, name, Number(x.openingBalance) || 0, x.dueDate || null]).then((r) => r.rows[0])
    );
    res.json(mapParty(row));
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A party with this name already exists' });
    console.error('POST /api/parties error:', err);
    res.status(500).json({ error: 'Unable to add party' });
  }
});

app.patch('/api/parties/:id', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const before = await db.query('SELECT * FROM parties WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!before.rows[0]) return null;
      const old = before.rows[0];
      const r = await db.query('UPDATE parties SET name=$1, opening_balance=$2, due_date=$3 WHERE id=$4 AND client_id=$5 RETURNING *',
        [(x.name || old.name).trim(), Number(x.openingBalance) || 0, x.dueDate || null, req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'party', 'edit', {
        before: { name: old.name, openingBalance: old.opening_balance },
        after: { name: r.rows[0].name, openingBalance: r.rows[0].opening_balance }
      });
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Party not found' });
    res.json(mapParty(row));
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A party with this name already exists' });
    console.error('PATCH /api/parties/:id error:', err);
    res.status(500).json({ error: 'Unable to update party' });
  }
});

app.delete('/api/parties/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM parties WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await db.query('DELETE FROM parties WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'party', 'delete', { entry: { name: old.name, openingBalance: old.opening_balance } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Party not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/parties/:id error:', err);
    res.status(500).json({ error: 'Unable to delete party' });
  }
});

// ---------- suppliers (Purchases master list) ----------
app.post('/api/suppliers', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  const name = (x.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Name required' });
  try {
    const row = await withTenantDb(req.clientId, (db) =>
      db.query('INSERT INTO suppliers (id,client_id,name,opening_balance,due_date) VALUES ($1,$2,$3,$4,$5) RETURNING *',
        [crypto.randomUUID(), req.clientId, name, Number(x.openingBalance) || 0, x.dueDate || null]).then((r) => r.rows[0])
    );
    res.json(mapSupplier(row));
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A supplier with this name already exists' });
    console.error('POST /api/suppliers error:', err);
    res.status(500).json({ error: 'Unable to add supplier' });
  }
});

app.patch('/api/suppliers/:id', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const before = await db.query('SELECT * FROM suppliers WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!before.rows[0]) return null;
      const old = before.rows[0];
      const r = await db.query('UPDATE suppliers SET name=$1, opening_balance=$2, due_date=$3 WHERE id=$4 AND client_id=$5 RETURNING *',
        [(x.name || old.name).trim(), Number(x.openingBalance) || 0, x.dueDate || null, req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'supplier', 'edit', {
        before: { name: old.name, openingBalance: old.opening_balance },
        after: { name: r.rows[0].name, openingBalance: r.rows[0].opening_balance }
      });
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Supplier not found' });
    res.json(mapSupplier(row));
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'A supplier with this name already exists' });
    console.error('PATCH /api/suppliers/:id error:', err);
    res.status(500).json({ error: 'Unable to update supplier' });
  }
});

app.delete('/api/suppliers/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM suppliers WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await db.query('DELETE FROM suppliers WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'supplier', 'delete', { entry: { name: old.name, openingBalance: old.opening_balance } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Supplier not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/suppliers/:id error:', err);
    res.status(500).json({ error: 'Unable to delete supplier' });
  }
});

// ---------- stock (usually auto-derived from purchases/sales; this lets an
// item's opening quantity/rate be set explicitly, e.g. when first switching
// to this app with existing inventory on hand) ----------
app.post('/api/stock', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  const name = (x.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Item name required' });
  const unit = x.unit || 'kg';
  if (Number(x.openingQty) < 0 || Number(x.openingRate) < 0) return res.status(400).json({ error: 'Opening quantity/rate cannot be negative' });
  try {
    const result = await withTenantDb(req.clientId, async (db) => {
      const existing = await db.query('SELECT id FROM stock WHERE client_id=$1 AND name=$2 AND unit=$3', [req.clientId, name, unit]);
      if (existing.rows[0]) { const e = new Error('EXISTS'); e.code = 'EXISTS'; throw e; }
      await db.query(
        'INSERT INTO stock (id, client_id, name, unit, opening_qty, opening_rate) VALUES ($1,$2,$3,$4,$5,$6)',
        [crypto.randomUUID(), req.clientId, name, unit, Number(x.openingQty) || 0, Number(x.openingRate) || 0]
      );
      await recomputeStockItem(db, req.clientId, name, unit);
      await writeAudit(db, req.clientId, 'stock', 'edit', { after: { name, unit, openingQty: x.openingQty, openingRate: x.openingRate } });
      const r = await db.query('SELECT * FROM stock WHERE client_id=$1 AND name=$2 AND unit=$3', [req.clientId, name, unit]);
      return r.rows[0];
    });
    res.json(mapStock(result));
  } catch (err) {
    if (err.code === 'EXISTS') return res.status(409).json({ error: 'An item with this name/unit already exists — edit it instead' });
    if (err.code === 'NEGATIVE_STOCK') return res.status(400).json({ error: err.message });
    console.error('POST /api/stock error:', err);
    res.status(500).json({ error: 'Unable to add stock item' });
  }
});

app.patch('/api/stock/:id', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (Number(x.openingQty) < 0 || Number(x.openingRate) < 0) return res.status(400).json({ error: 'Opening quantity/rate cannot be negative' });
  try {
    const result = await withTenantDb(req.clientId, async (db) => {
      const before = await db.query('SELECT * FROM stock WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!before.rows[0]) return null;
      const old = before.rows[0];
      await db.query('UPDATE stock SET opening_qty=$1, opening_rate=$2 WHERE id=$3 AND client_id=$4',
        [Number(x.openingQty) || 0, Number(x.openingRate) || 0, req.params.id, req.clientId]);
      await recomputeStockItem(db, req.clientId, old.name, old.unit);
      await writeAudit(db, req.clientId, 'stock', 'edit', {
        before: { name: old.name, openingQty: old.opening_qty, openingRate: old.opening_rate },
        after: { name: old.name, openingQty: x.openingQty, openingRate: x.openingRate }
      });
      const r = await db.query('SELECT * FROM stock WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      return r.rows[0];
    });
    if (!result) return res.status(404).json({ error: 'Stock item not found' });
    res.json(mapStock(result));
  } catch (err) {
    if (err.code === 'NEGATIVE_STOCK') return res.status(400).json({ error: err.message });
    console.error('PATCH /api/stock/:id error:', err);
    res.status(500).json({ error: 'Unable to update stock item' });
  }
});

app.delete('/api/stock/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM stock WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await db.query('DELETE FROM stock WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'stock', 'delete', {
        entry: { name: old.name, unit: old.unit, openingQty: old.opening_qty, openingRate: old.opening_rate }
      });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Stock item not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/stock/:id error:', err);
    res.status(500).json({ error: 'Unable to delete stock item' });
  }
});

// ---------- expenses ----------
app.post('/api/expenses', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.desc) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const account = x.account || 'cash';
      await assertFundsAvailable(db, req.clientId, account, Number(x.amount));
      return db.query('INSERT INTO expenses (id,client_id,date,description,amount,account_id,funding_transfer_ids,funding_loan_ids,exclude_from_profit) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.date, x.desc, Number(x.amount), account, fundingIdsJson(x.fundingTransferIds), fundingIdsJson(x.fundingLoanIds), !!x.excludeFromProfit]).then((r) => r.rows[0]);
    });
    res.json(mapExpense(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('POST /api/expenses error:', err);
    res.status(500).json({ error: 'Unable to add expense' });
  }
});

app.patch('/api/expenses/:id', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const before = await db.query('SELECT * FROM expenses WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!before.rows[0]) return null;
      const old = before.rows[0];
      const newAccount = x.account || 'cash';
      const newExcludeFromProfit = x.excludeFromProfit !== undefined ? !!x.excludeFromProfit : old.exclude_from_profit;
      const r = await db.query('UPDATE expenses SET date=$1, description=$2, amount=$3, account_id=$4, exclude_from_profit=$5 WHERE id=$6 AND client_id=$7 RETURNING *',
        [x.date, x.desc, Number(x.amount), newAccount, newExcludeFromProfit, req.params.id, req.clientId]);
      // QA: no overdraft guard existed on this edit path at all.
      const bal = await computeAccountBalanceDb(db, req.clientId, newAccount);
      if (bal < -0.009) {
        const e = new Error(`This edit would leave ${newAccount==='cash'?'Cash':'that account'} short by Rs ${Math.abs(bal).toFixed(2)} — reduce the amount, or pick a different account.`);
        e.code = 'INSUFFICIENT_FUNDS';
        throw e;
      }
      await writeAudit(db, req.clientId, 'expense', 'edit', {
        before: { date: old.date, desc: old.description, amount: old.amount, account: old.account_id },
        after: { date: x.date, desc: x.desc, amount: x.amount, account: x.account }
      });
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Expense not found' });
    res.json(mapExpense(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('PATCH /api/expenses/:id error:', err);
    res.status(500).json({ error: 'Unable to update expense' });
  }
});

app.delete('/api/expenses/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM expenses WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await deleteFundingLinks(db, req.clientId, old.funding_transfer_ids, old.funding_loan_ids);
      await db.query('DELETE FROM expenses WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'expense', 'delete', { entry: { date: old.date, desc: old.description, amount: old.amount, account: old.account_id } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Expense not found' });
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 'HAS_PAYMENTS') return res.status(400).json({ error: err.message });
    console.error('DELETE /api/expenses/:id error:', err);
    res.status(500).json({ error: 'Unable to delete expense' });
  }
});

// ---------- misc income (the inverse of an Expense — see schema comment) ----------
app.post('/api/misc-income', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.desc || !x.date || !x.mode) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  if (!['cash', 'supplier'].includes(x.mode)) return res.status(400).json({ error: 'Mode must be cash or supplier' });
  if (x.mode === 'supplier' && !x.supplier) return res.status(400).json({ error: 'Choose which supplier to credit' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const account = x.mode === 'cash' ? (x.account || 'cash') : null;
      const r = await db.query(
        'INSERT INTO misc_income (id, client_id, date, description, amount, mode, account_id, supplier, note, exclude_from_profit) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.date, x.desc, Number(x.amount), x.mode, account, x.mode === 'supplier' ? x.supplier : null, x.note || null, !!x.excludeFromProfit]
      );
      return r.rows[0];
    });
    res.json(mapMiscIncome(row));
  } catch (err) {
    console.error('POST /api/misc-income error:', err);
    res.status(500).json({ error: 'Unable to add misc income' });
  }
});

app.delete('/api/misc-income/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM misc_income WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await db.query('DELETE FROM misc_income WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'misc_income', 'delete', { entry: { date: old.date, desc: old.description, amount: old.amount, mode: old.mode, account: old.account_id, supplier: old.supplier } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Misc income entry not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/misc-income/:id error:', err);
    res.status(500).json({ error: 'Unable to delete misc income' });
  }
});

// ---------- receipts (Party Ledger / Receiving) ----------
app.post('/api/receipts', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.party || !x.date) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const settingsRow = await db.query('SELECT setup_mode FROM settings WHERE client_id=$1', [req.clientId]);
      const staged = !!(settingsRow.rows[0] && settingsRow.rows[0].setup_mode);
      // Historical Data Entry Mode: a staged receipt still reduces the
      // party's receivable immediately (see partyReceiptsTotal, unfiltered),
      // but never counts toward Cash/Bank — same permanent-exclusion rule
      // as staged sales/purchases/investors.
      const r = await db.query(
        'INSERT INTO receipts (id,client_id,date,party,amount,account_id,note,staged) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.date, x.party, Number(x.amount), x.account || 'cash', x.note || null, staged]
      );
      return r.rows[0];
    });
    res.json(mapReceipt(row));
  } catch (err) {
    console.error('POST /api/receipts error:', err);
    res.status(500).json({ error: 'Unable to add receipt' });
  }
});

app.patch('/api/receipts/:id', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.party || !x.date) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const before = await db.query('SELECT * FROM receipts WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!before.rows[0]) return null;
      const old = before.rows[0];
      // staged (Historical) is set once at creation and never changed by an
      // edit — same rule as every other entry type in the app.
      const r = await db.query(
        'UPDATE receipts SET date=$1, party=$2, amount=$3, account_id=$4, note=$5 WHERE id=$6 AND client_id=$7 RETURNING *',
        [x.date, x.party, Number(x.amount), x.account || 'cash', x.note || null, req.params.id, req.clientId]
      );
      // QA Round 15, Bug 1: editing had no server-side guard at all. Check
      // the resulting balance AFTER applying the edit (within this same
      // transaction) — a reduced receipt could leave an account that was
      // already spent against it negative, same risk as any other
      // money-moving edit in this app.
      if (!old.staged) {
        const newAccount = x.account || 'cash';
        const bal = await computeAccountBalanceDb(db, req.clientId, newAccount);
        if (bal < -0.009) {
          const e = new Error(`This edit would leave ${newAccount==='cash'?'Cash':'that account'} short by Rs ${Math.abs(bal).toFixed(2)} — reduce the amount, or pick a different account.`);
          e.code = 'INSUFFICIENT_FUNDS';
          throw e;
        }
      }
      await writeAudit(db, req.clientId, 'receipt', 'edit', {
        before: { date: old.date, party: old.party, amount: old.amount, account: old.account_id, note: old.note },
        after: { date: x.date, party: x.party, amount: x.amount, account: x.account, note: x.note }
      });
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Receipt not found' });
    res.json(mapReceipt(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('PATCH /api/receipts/:id error:', err);
    res.status(500).json({ error: 'Unable to update receipt' });
  }
});

app.delete('/api/receipts/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM receipts WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await db.query('DELETE FROM receipts WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      // QA Round 14, Bug 6: a cheque cleared via "Mark Cleared" stores this
      // receipt's id — if the receipt is instead deleted directly from the
      // Ledger, the cheque was left stuck showing Cleared with a dangling
      // reference. Put it back to Pending so Cheques List and the Ledger agree.
      await db.query("UPDATE cheques SET status='pending', receipt_id=NULL WHERE client_id=$1 AND receipt_id=$2", [req.clientId, req.params.id]);
      await writeAudit(db, req.clientId, 'receipt', 'delete', { entry: { date: old.date, party: old.party, amount: old.amount, account: old.account_id, note: old.note } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Receipt not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/receipts/:id error:', err);
    res.status(500).json({ error: 'Unable to delete receipt' });
  }
});

// ---------- payouts (payments to investors / commission agents) ----------
app.post('/api/payouts', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.recipientId || !x.date) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const account = x.account || 'cash';
      // QA: this endpoint had no overdraft guard — a payout (to an investor,
      // commission agent, or as a personal-loan repayment) is money leaving
      // an account just like a supplier payment or expense.
      await assertFundsAvailable(db, req.clientId, account, Number(x.amount));
      return db.query('INSERT INTO payouts (id,client_id,date,recipient_type,recipient_id,amount,account_id,note,funding_transfer_ids,funding_loan_ids) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.date, x.recipientType, x.recipientId, Number(x.amount), account, x.note || null, fundingIdsJson(x.fundingTransferIds), fundingIdsJson(x.fundingLoanIds)]).then((r) => r.rows[0]);
    });
    res.json(mapPayout(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('POST /api/payouts error:', err);
    res.status(500).json({ error: 'Unable to add payout' });
  }
});

// one endpoint covers all three recipient types this table serves
// (investor / partner-commission-agent / personal-loan repayment).
app.patch('/api/payouts/:id', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.recipientId || !x.date) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const before = await db.query('SELECT * FROM payouts WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!before.rows[0]) return null;
      const old = before.rows[0];
      const newAccount = x.account || 'cash';
      // only touched when the client explicitly sends it (the Edit Payout
      // modal's "Linked Shortfall-Cover Transfer" field) — every other edit
      // path (amount/date/account/note) must leave existing links alone.
      const newFundingTransferIds = x.fundingTransferIds !== undefined ? fundingIdsJson(x.fundingTransferIds) : old.funding_transfer_ids;
      const newFundingLoanIds = x.fundingLoanIds !== undefined ? fundingIdsJson(x.fundingLoanIds) : old.funding_loan_ids;
      const r = await db.query(
        'UPDATE payouts SET date=$1, recipient_id=$2, amount=$3, account_id=$4, note=$5, funding_transfer_ids=$6, funding_loan_ids=$7 WHERE id=$8 AND client_id=$9 RETURNING *',
        [x.date, x.recipientId, Number(x.amount), newAccount, x.note || null, newFundingTransferIds, newFundingLoanIds, req.params.id, req.clientId]
      );
      // QA: no overdraft guard existed on this edit path at all.
      const bal = await computeAccountBalanceDb(db, req.clientId, newAccount);
      if (bal < -0.009) {
        const e = new Error(`This edit would leave ${newAccount==='cash'?'Cash':'that account'} short by Rs ${Math.abs(bal).toFixed(2)} — reduce the amount, or pick a different account.`);
        e.code = 'INSUFFICIENT_FUNDS';
        throw e;
      }
      await writeAudit(db, req.clientId, 'payout', 'edit', {
        before: { date: old.date, recipientType: old.recipient_type, amount: old.amount, account: old.account_id, note: old.note },
        after: { date: x.date, recipientType: old.recipient_type, amount: x.amount, account: x.account, note: x.note }
      });
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Payout not found' });
    res.json(mapPayout(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('PATCH /api/payouts/:id error:', err);
    res.status(500).json({ error: 'Unable to update payout' });
  }
});

app.delete('/api/payouts/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM payouts WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await deleteFundingLinks(db, req.clientId, old.funding_transfer_ids, old.funding_loan_ids);
      await db.query('DELETE FROM payouts WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'payout', 'delete', { entry: { date: old.date, recipientType: old.recipient_type, amount: old.amount, account: old.account_id, note: old.note } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Payout not found' });
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 'HAS_PAYMENTS') return res.status(400).json({ error: err.message });
    console.error('DELETE /api/payouts/:id error:', err);
    res.status(500).json({ error: 'Unable to delete payout' });
  }
});

// ---------- supplier payments (Party Ledger / Paying — payable side, mirrors receipts) ----------
app.post('/api/supplier-payments', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.supplier || !x.date) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const settingsRow = await db.query('SELECT setup_mode FROM settings WHERE client_id=$1', [req.clientId]);
      const staged = !!(settingsRow.rows[0] && settingsRow.rows[0].setup_mode);
      const account = x.account || 'cash';
      // QA: this endpoint had no overdraft guard at all — money leaving an
      // account is never just a warning anywhere else in this app.
      if (!staged) await assertFundsAvailable(db, req.clientId, account, Number(x.amount));
      const r = await db.query(
        'INSERT INTO supplier_payments (id,client_id,date,supplier,amount,account_id,note,staged,funding_transfer_ids,funding_loan_ids) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.date, x.supplier, Number(x.amount), account, x.note || null, staged, fundingIdsJson(x.fundingTransferIds), fundingIdsJson(x.fundingLoanIds)]
      );
      return r.rows[0];
    });
    res.json(mapSupplierPayment(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('POST /api/supplier-payments error:', err);
    res.status(500).json({ error: 'Unable to add supplier payment' });
  }
});

app.patch('/api/supplier-payments/:id', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.supplier || !x.date) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      const before = await db.query('SELECT * FROM supplier_payments WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!before.rows[0]) return null;
      const old = before.rows[0];
      const r = await db.query(
        'UPDATE supplier_payments SET date=$1, supplier=$2, amount=$3, account_id=$4, note=$5 WHERE id=$6 AND client_id=$7 RETURNING *',
        [x.date, x.supplier, Number(x.amount), x.account || 'cash', x.note || null, req.params.id, req.clientId]
      );
      // QA Round 15, Bug 1: same guard as receipts — check the account's
      // resulting balance after applying the edit, inside this transaction,
      // so an increased payment can never push it negative.
      if (!old.staged) {
        const newAccount = x.account || 'cash';
        const bal = await computeAccountBalanceDb(db, req.clientId, newAccount);
        if (bal < -0.009) {
          const e = new Error(`This edit would leave ${newAccount==='cash'?'Cash':'that account'} short by Rs ${Math.abs(bal).toFixed(2)} — reduce the amount, or pick a different account.`);
          e.code = 'INSUFFICIENT_FUNDS';
          throw e;
        }
      }
      await writeAudit(db, req.clientId, 'supplier_payment', 'edit', {
        before: { date: old.date, party: old.supplier, amount: old.amount, account: old.account_id, note: old.note },
        after: { date: x.date, party: x.supplier, amount: x.amount, account: x.account, note: x.note }
      });
      return r.rows[0];
    });
    if (!row) return res.status(404).json({ error: 'Supplier payment not found' });
    res.json(mapSupplierPayment(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('PATCH /api/supplier-payments/:id error:', err);
    res.status(500).json({ error: 'Unable to update supplier payment' });
  }
});

app.delete('/api/supplier-payments/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM supplier_payments WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await deleteFundingLinks(db, req.clientId, old.funding_transfer_ids, old.funding_loan_ids);
      await db.query('DELETE FROM supplier_payments WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      // QA Round 14, Bug 6 — same as receipts: put the cheque back to
      // Pending if this payment was the one created by clearing it.
      await db.query("UPDATE cheques SET status='pending', payment_id=NULL WHERE client_id=$1 AND payment_id=$2", [req.clientId, req.params.id]);
      await writeAudit(db, req.clientId, 'supplier_payment', 'delete', { entry: { date: old.date, party: old.supplier, amount: old.amount, account: old.account_id, note: old.note } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Supplier payment not found' });
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 'HAS_PAYMENTS') return res.status(400).json({ error: err.message });
    console.error('DELETE /api/supplier-payments/:id error:', err);
    res.status(500).json({ error: 'Unable to delete supplier payment' });
  }
});

// ---------- bank/cash transfers (moving money between the client's own accounts) ----------
app.post('/api/transfers', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.date || !x.amount || !x.fromAccount || !x.toAccount) return res.status(400).json({ error: 'Missing required fields' });
  if (x.fromAccount === x.toAccount) return res.status(400).json({ error: 'From and To accounts must be different' });
  if (Number(x.amount) <= 0) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, async (db) => {
      await assertFundsAvailable(db, req.clientId, x.fromAccount, Number(x.amount));
      const r = await db.query('INSERT INTO transfers (id,client_id,date,from_account,to_account,amount,note,funding_transfer_ids,funding_loan_ids) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.date, x.fromAccount, x.toAccount, Number(x.amount), x.note || null, fundingIdsJson(x.fundingTransferIds), fundingIdsJson(x.fundingLoanIds)]);
      return r.rows[0];
    });
    res.json(mapTransfer(row));
  } catch (err) {
    if (err.code === 'INSUFFICIENT_FUNDS') return res.status(400).json({ error: err.message });
    console.error('POST /api/transfers error:', err);
    res.status(500).json({ error: 'Unable to add transfer' });
  }
});

app.delete('/api/transfers/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM transfers WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await deleteFundingLinks(db, req.clientId, old.funding_transfer_ids, old.funding_loan_ids);
      await db.query('DELETE FROM transfers WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'transfer', 'delete', { entry: { date: old.date, amount: old.amount, fromAccount: old.from_account, toAccount: old.to_account, note: old.note } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Transfer not found' });
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 'HAS_PAYMENTS') return res.status(400).json({ error: err.message });
    console.error('DELETE /api/transfers/:id error:', err);
    res.status(500).json({ error: 'Unable to delete transfer' });
  }
});

// ---------- personal loans (a person covers a shortfall on the spot; a
// liability owed back to them, tracked separately from Total Investment —
// repayment reuses /api/payouts with recipientType='loan') ----------
app.post('/api/personal-loans', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.lender || !x.date) return res.status(400).json({ error: 'Missing required fields' });
  if (!isPositiveAmount(x.amount)) return res.status(400).json({ error: 'Amount must be greater than zero' });
  try {
    const row = await withTenantDb(req.clientId, (db) =>
      db.query('INSERT INTO personal_loans (id,client_id,date,lender,amount,account_id,note) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.date, x.lender, Number(x.amount), x.account || 'cash', x.note || null]).then((r) => r.rows[0])
    );
    res.json(mapPersonalLoan(row));
  } catch (err) {
    console.error('POST /api/personal-loans error:', err);
    res.status(500).json({ error: 'Unable to add personal loan' });
  }
});

app.delete('/api/personal-loans/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('SELECT * FROM personal_loans WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      if (!r.rows[0]) return false;
      const old = r.rows[0];
      await db.query('DELETE FROM personal_loans WHERE id=$1 AND client_id=$2', [req.params.id, req.clientId]);
      await writeAudit(db, req.clientId, 'personal_loan', 'delete', { entry: { date: old.date, lender: old.lender, amount: old.amount, account: old.account_id, note: old.note } });
      return true;
    });
    if (!found) return res.status(404).json({ error: 'Personal loan not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/personal-loans/:id error:', err);
    res.status(500).json({ error: 'Unable to delete personal loan' });
  }
});

// ---------- trade summaries (saved Dashboard snapshots — pure record,
// no stock/balance side effects) ----------
app.post('/api/trade-summaries', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.date || !['month', 'all'].includes(x.period) || !x.periodLabel) return res.status(400).json({ error: 'Missing required fields' });
  if (x.sales === undefined || x.purchases === undefined || x.profit === undefined || x.expenses === undefined) return res.status(400).json({ error: 'Missing required fields' });
  try {
    const row = await withTenantDb(req.clientId, (db) =>
      db.query(
        'INSERT INTO trade_summaries (id,client_id,date,period,period_label,sales,purchases,commission_new,commission_opening,expenses,profit) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.date, x.period, x.periodLabel, Number(x.sales), Number(x.purchases), Number(x.commissionNew) || 0, Number(x.commissionOpening) || 0, Number(x.expenses), Number(x.profit)]
      ).then((r) => r.rows[0])
    );
    res.json(mapTradeSummary(row));
  } catch (err) {
    console.error('POST /api/trade-summaries error:', err);
    res.status(500).json({ error: 'Unable to save trade summary' });
  }
});

app.delete('/api/trade-summaries/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('DELETE FROM trade_summaries WHERE id=$1 AND client_id=$2 RETURNING id', [req.params.id, req.clientId]);
      return !!r.rows[0];
    });
    if (!found) return res.status(404).json({ error: 'Trade summary not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/trade-summaries/:id error:', err);
    res.status(500).json({ error: 'Unable to delete trade summary' });
  }
});

// ---------- investor summaries (saved per-investor snapshots — pure
// record, no stock/balance side effects) ----------
app.post('/api/investor-summaries', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  if (!x.date || !['month', 'all'].includes(x.period) || !x.periodLabel || !x.investorName) return res.status(400).json({ error: 'Missing required fields' });
  if (x.investment === undefined || x.profitShare === undefined || x.expenseShare === undefined || x.paidOut === undefined || x.netOwed === undefined) return res.status(400).json({ error: 'Missing required fields' });
  try {
    const row = await withTenantDb(req.clientId, (db) =>
      db.query(
        'INSERT INTO investor_summaries (id,client_id,investor_id,investor_name,date,period,period_label,investment,profit_share,expense_share,expense_share_month,expense_share_all,paid_out,net_owed,rows) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *',
        [crypto.randomUUID(), req.clientId, x.investorId || null, x.investorName, x.date, x.period, x.periodLabel, Number(x.investment), Number(x.profitShare), Number(x.expenseShare), Number(x.expenseShareMonth) || 0, Number(x.expenseShareAll) || 0, Number(x.paidOut), Number(x.netOwed), x.rows ? JSON.stringify(x.rows) : null]
      ).then((r) => r.rows[0])
    );
    res.json(mapInvestorSummary(row));
  } catch (err) {
    console.error('POST /api/investor-summaries error:', err);
    res.status(500).json({ error: 'Unable to save investor summary' });
  }
});

app.delete('/api/investor-summaries/:id', ...editorAccess, async (req, res) => {
  try {
    const found = await withTenantDb(req.clientId, async (db) => {
      const r = await db.query('DELETE FROM investor_summaries WHERE id=$1 AND client_id=$2 RETURNING id', [req.params.id, req.clientId]);
      return !!r.rows[0];
    });
    if (!found) return res.status(404).json({ error: 'Investor summary not found' });
    res.json({ ok: true });
  } catch (err) {
    console.error('DELETE /api/investor-summaries/:id error:', err);
    res.status(500).json({ error: 'Unable to delete investor summary' });
  }
});

// ---------- settings (per-client) ----------
app.patch('/api/settings', ...editorAccess, async (req, res) => {
  const x = req.body || {};
  try {
    const themeColor = /^#[0-9a-fA-F]{6}$/.test(x.themeColor || '') ? x.themeColor : '#2563EB';
    const fontSize = ['small', 'medium', 'large'].includes(x.fontSize) ? x.fontSize : 'medium';
    // setup_mode only decides how a sale/purchase is tagged at the moment
    // it's created (see POST /api/sales, POST /api/purchases) — flipping it
    // here is a plain preference change with no side effects of its own.
    // A row already tagged staged=true stays permanently excluded from
    // Stock/Cash/Bank/Profit (see recomputeStockItem, accountBalance, etc.
    // on the frontend) — historical data is meant only to seed the party/
    // supplier ledger, receivable/payable totals and reminders, nothing else.
    const row = await withTenantDb(req.clientId, (db) =>
      db.query(
        `INSERT INTO settings (client_id, company_name, business_label, opening_cash, cheque_reminder_days, credit_reminder_days, setup_mode, theme_color, font_size, hide_other_cards, hide_total_investment, hide_trade_summary)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         ON CONFLICT (client_id) DO UPDATE SET company_name=$2, business_label=$3, opening_cash=$4, cheque_reminder_days=$5, credit_reminder_days=$6, setup_mode=$7, theme_color=$8, font_size=$9, hide_other_cards=$10, hide_total_investment=$11, hide_trade_summary=$12
         RETURNING *`,
        [req.clientId, x.companyName || '', x.businessLabel || '', Number(x.openingCash) || 0, Number(x.chequeReminderDays) || 0, Number(x.creditReminderDays) || 0, !!x.setupMode, themeColor, fontSize, !!x.hideOtherCards, !!x.hideTotalInvestment, !!x.hideTradeSummary]
      ).then((r) => r.rows[0])
    );
    res.json({
      companyName: row.company_name, businessLabel: row.business_label, openingCash: row.opening_cash,
      chequeReminderDays: row.cheque_reminder_days, creditReminderDays: row.credit_reminder_days, setupMode: row.setup_mode,
      themeColor: row.theme_color, fontSize: row.font_size,
      hideOtherCards: row.hide_other_cards, hideTotalInvestment: row.hide_total_investment, hideTradeSummary: row.hide_trade_summary
    });
  } catch (err) {
    console.error('PATCH /api/settings error:', err);
    res.status(500).json({ error: 'Unable to update settings' });
  }
});

app.get('/api/backup/history', requireAuth, requireAdmin, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM backups ORDER BY created_at DESC LIMIT 3');
    res.json(r.rows.map((b) => ({
      id: b.id, createdAt: b.created_at, type: b.type, status: b.status,
      fileSize: b.file_size, errorMessage: b.error_message,
      fileName: b.location ? path.basename(b.location) : null
    })));
  } catch (err) {
    console.error('GET /api/backup/history error:', err);
    res.status(500).json({ error: 'Unable to load backup history' });
  }
});

app.post('/api/backup/source', requireAuth, requireAdmin, async (req, res) => {
  try {
    res.json(await backupSourceCode());
  } catch (err) {
    console.error('POST /api/backup/source error:', err);
    res.status(500).json({ error: 'Source backup failed: ' + err.message });
  }
});

app.post('/api/backup/run', requireAuth, requireAdmin, async (req, res) => {
  try {
    res.json(await takeBackup('manual'));
  } catch (err) {
    console.error('POST /api/backup/run error:', err);
    res.status(500).json({ error: 'Backup failed: ' + err.message });
  }
});

app.get('/api/backup/download/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM backups WHERE id = $1', [req.params.id]);
    const b = r.rows[0];
    if (!b || b.status !== 'success' || !b.location || !fs.existsSync(b.location)) {
      return res.status(404).json({ error: 'Backup file not found' });
    }
    res.download(b.location, path.basename(b.location));
  } catch (err) {
    console.error('GET /api/backup/download/:id error:', err);
    res.status(500).json({ error: 'Unable to download backup' });
  }
});

app.get('/api/backup/settings', requireAuth, requireAdmin, async (req, res) => {
  try {
    const s = await getBackupSettings();
    res.json({
      scheduleEnabled: s.schedule_enabled, frequency: s.frequency, timeOfDay: s.time_of_day,
      timezone: s.timezone, location: s.location, retentionCount: s.retention_count
    });
  } catch (err) {
    console.error('GET /api/backup/settings error:', err);
    res.status(500).json({ error: 'Unable to load backup settings' });
  }
});

app.patch('/api/backup/settings', requireAuth, requireAdmin, async (req, res) => {
  const x = req.body || {};
  try {
    const r = await pool.query(
      `UPDATE backup_settings SET schedule_enabled=$1, frequency=$2, time_of_day=$3, timezone=$4, location=$5, retention_count=$6 WHERE id=1 RETURNING *`,
      [!!x.scheduleEnabled, ['hourly', 'daily', 'weekly', 'monthly'].includes(x.frequency) ? x.frequency : 'daily', x.timeOfDay || '02:00',
       x.timezone || 'Asia/Karachi', x.location || './backups', Number(x.retentionCount) || 14]
    );
    await rescheduleBackupCron();
    const s = r.rows[0];
    res.json({
      scheduleEnabled: s.schedule_enabled, frequency: s.frequency, timeOfDay: s.time_of_day,
      timezone: s.timezone, location: s.location, retentionCount: s.retention_count
    });
  } catch (err) {
    console.error('PATCH /api/backup/settings error:', err);
    res.status(500).json({ error: 'Unable to update backup settings' });
  }
});

app.post('/api/backup/restore', requireAuth, requireAdmin, express.raw({ type: 'application/octet-stream', limit: '500mb' }), async (req, res) => {
  if (req.query.confirm !== 'RESTORE') return res.status(400).json({ error: 'Type RESTORE to confirm' });
  if (!Buffer.isBuffer(req.body) || !req.body.length) return res.status(400).json({ error: 'No backup file uploaded' });
  const settings = await getBackupSettings();
  const dir = backupDir(settings.location);
  const uploadFile = path.join(dir, `upload_${Date.now()}.dump`);
  try {
    fs.writeFileSync(uploadFile, req.body);
    await takeBackup('safety'); // always safety-backup the current data before overwriting it
    const result = await runPgRestoreFromFile(uploadFile);
    res.json({ ok: true, warnings: result.warnings || null });
  } catch (err) {
    console.error('POST /api/backup/restore error:', err);
    res.status(500).json({ error: 'Restore failed: ' + err.message });
  } finally {
    try { fs.unlinkSync(uploadFile); } catch (e) { /* ignore */ }
  }
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'postgres connected' });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'dhaaga-manager.html'));
});

ensureSchema()
  .then(() => rescheduleBackupCron().catch((err) => console.error('Could not schedule backups:', err.message)))
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Yarn manager backend running on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Database init failed:', err.message);
    process.exit(1);
  });
