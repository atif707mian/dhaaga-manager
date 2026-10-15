-- Yarn Trading Manager — multi-tenant SaaS schema
-- This file reflects the TARGET end-state for a fresh install.
-- An already-running single-tenant database must NOT run this file directly —
-- use `node migrate-to-saas.js` instead (see that file for the one-time,
-- reviewed, backed-up migration of existing data).
-- Run once against a fresh database: psql -f schema.sql

CREATE DATABASE yarn_manager;

\c yarn_manager;

-- =====================================================================
-- GLOBAL TABLES (no client_id — shared across every tenant)
-- =====================================================================

-- ---------- users & auth ----------
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','standard')), -- admin = every client + Settings
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')), -- soft delete
  must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- session store used by connect-pg-simple (server.js creates this
-- automatically via createTableIfMissing, listed here for reference only)
-- CREATE TABLE user_sessions (sid TEXT PRIMARY KEY, sess JSON NOT NULL, expire TIMESTAMP NOT NULL);

-- ---------- clients (tenants) ----------
CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY,
  client_number SERIAL UNIQUE, -- auto-generated, read-only, never entered by a user
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive')), -- soft delete
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------- which standard users may access which clients, and at what level ----------
CREATE TABLE IF NOT EXISTS user_clients (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  access_level TEXT NOT NULL CHECK (access_level IN ('editor','viewer')),
  PRIMARY KEY (user_id, client_id)
);

-- ---------- backup history + schedule config ----------
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
  time_of_day TEXT NOT NULL DEFAULT '02:00', -- HH:MM, interpreted in `timezone` below
  timezone TEXT NOT NULL DEFAULT 'Asia/Karachi',
  location TEXT NOT NULL DEFAULT './backups', -- server folder path today; swap for a cloud URI later
  retention_count INTEGER NOT NULL DEFAULT 14
);
INSERT INTO backup_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

-- =====================================================================
-- TENANT-SCOPED TABLES (every row belongs to exactly one client)
-- Row-Level Security is the non-negotiable backstop: even if application
-- code forgets a client_id filter, Postgres itself will not return or
-- accept rows for any client other than the one set via
-- `SET LOCAL app.current_client_id` for the current transaction.
-- The connecting DB role must NOT be a superuser / BYPASSRLS role, or
-- these policies are silently skipped. See migrate-to-saas.js, which
-- creates a dedicated non-superuser `app_user` role for this.
-- =====================================================================

-- ---------- business settings (one row per client) ----------
CREATE TABLE IF NOT EXISTS settings (
  client_id TEXT PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
  company_name TEXT NOT NULL DEFAULT '',
  business_label TEXT NOT NULL DEFAULT '',
  opening_cash NUMERIC(14,2) NOT NULL DEFAULT 0,
  cheque_reminder_days INTEGER NOT NULL DEFAULT 3,
  credit_reminder_days INTEGER NOT NULL DEFAULT 3,
  setup_mode BOOLEAN NOT NULL DEFAULT FALSE,
  theme_color TEXT NOT NULL DEFAULT '#2563EB',
  font_size TEXT NOT NULL DEFAULT 'medium' CHECK (font_size IN ('small','medium','large'))
);

-- ---------- accounts ----------
CREATE TABLE IF NOT EXISTS bank_accounts (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  opening_balance NUMERIC(14,2) NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_bank_accounts_client ON bank_accounts(client_id);

-- ---------- commission agents ----------
CREATE TABLE IF NOT EXISTS partners (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  opening_profit NUMERIC(14,2) NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_partners_client ON partners(client_id);

-- ---------- parties (customers/suppliers tracked in the Party Ledger) ----------
CREATE TABLE IF NOT EXISTS parties (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  opening_balance NUMERIC(14,2) NOT NULL DEFAULT 0, -- amount they already owed before using this app
  UNIQUE (client_id, name)
);
CREATE INDEX IF NOT EXISTS idx_parties_client ON parties(client_id);

-- ---------- stock ----------
CREATE TABLE IF NOT EXISTS stock (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  unit TEXT NOT NULL DEFAULT 'kg',
  qty NUMERIC(14,3) NOT NULL DEFAULT 0,
  rate NUMERIC(14,2) NOT NULL DEFAULT 0,
  avg_cost NUMERIC(14,2) NOT NULL DEFAULT 0,
  opening_qty NUMERIC(14,3) NOT NULL DEFAULT 0,
  opening_rate NUMERIC(14,2) NOT NULL DEFAULT 0,
  UNIQUE (client_id, name, unit)
);
CREATE INDEX IF NOT EXISTS idx_stock_client ON stock(client_id);

-- ---------- sales ----------
CREATE TABLE IF NOT EXISTS sales (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  party TEXT NOT NULL,
  item TEXT NOT NULL,
  qty NUMERIC(14,3) NOT NULL,
  unit TEXT NOT NULL DEFAULT 'kg',
  rate NUMERIC(14,2) NOT NULL,
  total NUMERIC(14,2) NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('cash','credit')),
  account_id TEXT NOT NULL DEFAULT 'cash',
  paid BOOLEAN NOT NULL DEFAULT FALSE,
  due_date DATE,
  credit_days INTEGER,
  profit NUMERIC(14,2),
  partner_id TEXT REFERENCES partners(id) ON DELETE SET NULL,
  partner_percent NUMERIC(5,2)
);
CREATE INDEX IF NOT EXISTS idx_sales_client_date ON sales(client_id, date);
CREATE INDEX IF NOT EXISTS idx_sales_client_due ON sales(client_id, due_date) WHERE type = 'credit' AND NOT paid;

-- ---------- purchases ----------
CREATE TABLE IF NOT EXISTS purchases (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  supplier TEXT NOT NULL,
  item TEXT NOT NULL,
  qty NUMERIC(14,3) NOT NULL,
  unit TEXT NOT NULL DEFAULT 'kg',
  rate NUMERIC(14,2) NOT NULL,
  total NUMERIC(14,2) NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('cash','credit')),
  account_id TEXT NOT NULL DEFAULT 'cash',
  paid BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_purchases_client_date ON purchases(client_id, date);

-- ---------- cheques ----------
CREATE TABLE IF NOT EXISTS cheques (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  party TEXT NOT NULL,
  bank TEXT,
  amount NUMERIC(14,2) NOT NULL,
  due_date DATE NOT NULL,
  account_id TEXT NOT NULL DEFAULT 'cash',
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','cleared')),
  receipt_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_cheques_client_due ON cheques(client_id, due_date) WHERE status = 'pending';

-- ---------- investors ----------
CREATE TABLE IF NOT EXISTS investors (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  amount NUMERIC(14,2) NOT NULL,
  ratio NUMERIC(5,2) NOT NULL DEFAULT 0,
  account_id TEXT NOT NULL DEFAULT 'cash'
);
CREATE INDEX IF NOT EXISTS idx_investors_client ON investors(client_id);

-- ---------- expenses ----------
CREATE TABLE IF NOT EXISTS expenses (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  description TEXT NOT NULL,
  amount NUMERIC(14,2) NOT NULL,
  account_id TEXT NOT NULL DEFAULT 'cash'
);
CREATE INDEX IF NOT EXISTS idx_expenses_client_date ON expenses(client_id, date);

-- ---------- receipts (payments received against a party's credit sales) ----------
CREATE TABLE IF NOT EXISTS receipts (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  party TEXT NOT NULL,
  amount NUMERIC(14,2) NOT NULL,
  account_id TEXT NOT NULL DEFAULT 'cash',
  note TEXT
);
CREATE INDEX IF NOT EXISTS idx_receipts_client_party ON receipts(client_id, party);

-- ---------- payouts (money paid out to investors / commission agents) ----------
CREATE TABLE IF NOT EXISTS payouts (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  recipient_type TEXT NOT NULL CHECK (recipient_type IN ('investor','partner')),
  recipient_id TEXT NOT NULL,
  amount NUMERIC(14,2) NOT NULL,
  account_id TEXT NOT NULL DEFAULT 'cash',
  note TEXT
);
CREATE INDEX IF NOT EXISTS idx_payouts_client_recipient ON payouts(client_id, recipient_type, recipient_id);

-- ---------- edit/delete audit trail ----------
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('sale','purchase','investor','partner','bank','expense','cheque','receipt','payout','user')),
  action TEXT NOT NULL CHECK (action IN ('edit','delete')),
  action_date DATE NOT NULL,
  before JSONB,
  after JSONB,
  entry JSONB
);
CREATE INDEX IF NOT EXISTS idx_audit_log_client_date ON audit_log(client_id, action_date);

-- =====================================================================
-- ROW-LEVEL SECURITY
-- =====================================================================
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['settings','bank_accounts','partners','parties','stock','sales','purchases',
                            'cheques','investors','expenses','receipts','payouts','audit_log']
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t); -- applies even to the table owner
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (client_id = current_setting(''app.current_client_id'', true)) WITH CHECK (client_id = current_setting(''app.current_client_id'', true))',
      t
    );
  END LOOP;
END $$;
