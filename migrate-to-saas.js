// One-time, manually-run migration: converts the existing single-tenant
// database into the multi-tenant shape (backfills client_id, enforces
// NOT NULL + FK, enables Row-Level Security, creates a non-superuser DB role
// for RLS to actually apply, migrates user roles).
//
// This is NOT run automatically by server.js. Run it yourself:
//   node migrate-to-saas.js
//
// It always takes an automatic pg_dump safety backup first, prints a summary
// of exactly what it is about to do, and requires you to type `yes` before
// touching any data. Safe to re-run — every step checks whether it already
// happened.

const { Pool } = require('pg');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');
const readline = require('readline');
require('dotenv').config();

const DATABASE_URL = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/yarn_manager';
const PG_DUMP_BIN = process.env.PG_DUMP_BIN || 'pg_dump'; // override on Windows dev boxes if not on PATH, e.g. "C:\\Program Files\\PostgreSQL\\17\\bin\\pg_dump.exe"
const APP_ROLE = process.env.SAAS_APP_ROLE || 'app_user';
const APP_ROLE_PASSWORD = process.env.SAAS_APP_ROLE_PASSWORD || crypto.randomBytes(18).toString('base64').replace(/[/+=]/g, '');

const pool = new Pool({ connectionString: DATABASE_URL });

// A single shared readline interface, asked from only if the answer isn't
// already supplied via env vars. This script is meant to be run by a human
// at a real terminal, but also supports non-interactive use (env vars) —
// readline over redirected/piped stdin is unreliable here: the stream hits
// EOF and auto-closes the interface as soon as all bytes are consumed,
// which can happen before a later `question()` call is even issued once
// there's async work (DB calls) between prompts.
let rl = null;
function ask(question, envValue) {
  if (envValue !== undefined && envValue !== '') return Promise.resolve(envValue);
  if (!rl) rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(question, resolve));
}

async function takeSafetyBackup() {
  const url = new URL(DATABASE_URL);
  const dbName = url.pathname.replace(/^\//, '');
  const backupDir = path.join(__dirname, 'backups');
  fs.mkdirSync(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const file = path.join(backupDir, `pre-saas-migration_${stamp}.dump`);
  console.log(`\nTaking a safety backup before touching anything: ${file}`);
  const args = ['-Fc', '-h', url.hostname, '-p', url.port || '5432', '-U', url.username, '-d', dbName, '-f', file];
  const res = spawnSync(PG_DUMP_BIN, args, { env: { ...process.env, PGPASSWORD: url.password }, stdio: 'inherit' });
  if (res.status !== 0) {
    throw new Error(`pg_dump failed (exit ${res.status}). Set PG_DUMP_BIN to the full path to pg_dump if it isn't on PATH, then re-run.`);
  }
  console.log('Safety backup complete.\n');
  return file;
}

const TENANT_TABLES = ['settings', 'bank_accounts', 'partners', 'stock', 'sales', 'purchases', 'cheques', 'investors', 'expenses', 'receipts', 'payouts', 'audit_log'];

async function main() {
  console.log('=== Convert to multi-tenant SaaS — migration plan ===\n');
  console.log('This will, in order:');
  console.log('  1. Take a pg_dump safety backup (already about to happen, below).');
  console.log('  2. Create one "clients" row for your existing data (you\'ll be asked for its name).');
  console.log(`  3. Stamp every existing row in [${TENANT_TABLES.join(', ')}] with that client_id.`);
  console.log('  4. Make client_id NOT NULL + add the foreign key on each of those tables.');
  console.log('  5. Convert existing users: role admin stays admin (global); role viewer becomes');
  console.log('     role=standard + a user_clients row (access_level=viewer) scoped to the new client.');
  console.log(`  6. Create a non-superuser DB role "${APP_ROLE}" and enable Row-Level Security —`);
  console.log('     the app MUST connect as this role afterwards, or RLS is silently bypassed.');
  console.log('  7. Print the new DATABASE_URL you need to put in .env.\n');

  const client = await pool.connect();
  try {
    const { rows: existingClients } = await client.query('SELECT id, name FROM clients LIMIT 1');
    if (existingClients.length) {
      console.log(`Looks like this already ran — client "${existingClients[0].name}" already exists.`);
      console.log('Re-run with a fresh check if you believe this is wrong. Exiting without changes.');
      return;
    }

    await takeSafetyBackup();

    const answer = await ask('Type "yes" to proceed with the migration, anything else to cancel: ', process.env.MIGRATE_CONFIRM);
    if (answer.trim().toLowerCase() !== 'yes') { console.log('Cancelled. No changes made.'); return; }

    const clientName = (await ask('Name for the existing business as a client (e.g. "Bismillah Traders"): ', process.env.MIGRATE_CLIENT_NAME)).trim() || 'Default Client';
    const clientId = crypto.randomUUID();

    await client.query('BEGIN');

    // 2. create the client
    await client.query('INSERT INTO clients (id, name) VALUES ($1,$2)', [clientId, clientName]);
    console.log(`Created client "${clientName}" (${clientId}).`);

    // 3. backfill client_id on every tenant table
    for (const t of TENANT_TABLES) {
      const r = await client.query(`UPDATE ${t} SET client_id = $1 WHERE client_id IS NULL`, [clientId]);
      console.log(`  ${t}: stamped ${r.rowCount} row(s)`);
    }

    // settings: this DB might not have a row yet (fresh installs insert it in
    // ensureSchema keyed by id=1) — make sure exactly one settings row exists
    // for this client before we move its primary key.
    const settingsCount = await client.query('SELECT count(*)::int AS c FROM settings WHERE client_id = $1', [clientId]);
    if (settingsCount.rows[0].c === 0) {
      await client.query('INSERT INTO settings (client_id) VALUES ($1)', [clientId]);
    }

    // 4. enforce NOT NULL + FK on client_id for every tenant table
    for (const t of TENANT_TABLES) {
      await client.query(`ALTER TABLE ${t} ALTER COLUMN client_id SET NOT NULL`);
      await client.query(`
        DO $$ BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = '${t}_client_id_fkey') THEN
            ALTER TABLE ${t} ADD CONSTRAINT ${t}_client_id_fkey FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE;
          END IF;
        END $$;
      `);
    }

    // stock's old UNIQUE(name, unit) predates multi-tenancy and would wrongly
    // block two different clients from both stocking, say, "Cotton"/"kg" —
    // replace it with a client-scoped uniqueness constraint.
    const stockUnique = await client.query(`
      SELECT conname FROM pg_constraint WHERE conrelid = 'stock'::regclass AND contype = 'u'
    `);
    for (const row of stockUnique.rows) {
      await client.query(`ALTER TABLE stock DROP CONSTRAINT ${row.conname}`);
    }
    await client.query(`
      DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'stock_client_name_unit_key') THEN
          ALTER TABLE stock ADD CONSTRAINT stock_client_name_unit_key UNIQUE (client_id, name, unit);
        END IF;
      END $$;
    `);

    // settings: move the primary key from the old id=1 singleton to client_id
    const pk = await client.query(`
      SELECT constraint_name FROM information_schema.table_constraints
      WHERE table_name = 'settings' AND constraint_type = 'PRIMARY KEY'
    `);
    if (pk.rows[0] && pk.rows[0].constraint_name !== 'settings_pkey_client') {
      await client.query(`ALTER TABLE settings DROP CONSTRAINT ${pk.rows[0].constraint_name}`);
      await client.query('ALTER TABLE settings ADD CONSTRAINT settings_pkey_client PRIMARY KEY (client_id)');
      await client.query('ALTER TABLE settings DROP COLUMN IF EXISTS id');
    }

    // 5. migrate user roles: admin stays global; viewer -> standard + user_clients(viewer)
    // Order matters: drop the OLD constraint (admin/viewer only) first — the
    // UPDATE to 'standard' would violate it — then update, then add the NEW
    // constraint (admin/standard only), which validates cleanly since every
    // row is already one of those two values by that point.
    const { rows: viewers } = await client.query("SELECT id FROM users WHERE role = 'viewer'");
    await client.query("ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check");
    for (const u of viewers) {
      await client.query("UPDATE users SET role = 'standard' WHERE id = $1", [u.id]);
      await client.query(
        `INSERT INTO user_clients (user_id, client_id, access_level) VALUES ($1,$2,'viewer')
         ON CONFLICT (user_id, client_id) DO NOTHING`,
        [u.id, clientId]
      );
    }
    await client.query("ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('admin','standard'))");
    console.log(`Converted ${viewers.length} existing viewer account(s) to standard+viewer on "${clientName}".`);

    // 6. RLS — create/ensure the non-superuser app role, then enable RLS + policy per table
    const roleExists = await client.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [APP_ROLE]);
    if (roleExists.rowCount === 0) {
      await client.query(`CREATE ROLE ${APP_ROLE} LOGIN PASSWORD '${APP_ROLE_PASSWORD.replace(/'/g, "''")}'`);
      console.log(`Created DB role "${APP_ROLE}".`);
    } else {
      console.log(`DB role "${APP_ROLE}" already exists — leaving its password as-is.`);
    }
    const dbNameRes = await client.query('SELECT current_database() AS db');
    const dbName = dbNameRes.rows[0].db;
    await client.query(`GRANT CONNECT ON DATABASE ${dbName} TO ${APP_ROLE}`);
    await client.query(`GRANT USAGE ON SCHEMA public TO ${APP_ROLE}`);
    await client.query(`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${APP_ROLE}`);
    await client.query(`GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ${APP_ROLE}`);

    for (const t of TENANT_TABLES) {
      await client.query(`ALTER TABLE ${t} ENABLE ROW LEVEL SECURITY`);
      await client.query(`ALTER TABLE ${t} FORCE ROW LEVEL SECURITY`);
      const policyExists = await client.query(
        `SELECT 1 FROM pg_policies WHERE tablename = $1 AND policyname = 'tenant_isolation'`, [t]
      );
      if (policyExists.rowCount === 0) {
        await client.query(`
          CREATE POLICY tenant_isolation ON ${t}
            USING (client_id = current_setting('app.current_client_id', true))
            WITH CHECK (client_id = current_setting('app.current_client_id', true))
        `);
      }
    }
    console.log('Row-Level Security enabled on all tenant tables.');

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('\nMigration FAILED and was rolled back — no partial changes were kept.');
    console.error(err);
    process.exitCode = 1;
    return;
  } finally {
    client.release();
  }

  const url = new URL(DATABASE_URL);
  const newUrl = `postgresql://${APP_ROLE}:${APP_ROLE_PASSWORD}@${url.hostname}:${url.port || 5432}${url.pathname}`;
  console.log('\n=== Migration complete ===');
  console.log('IMPORTANT — update your .env DATABASE_URL to the non-superuser role, or RLS is bypassed:');
  console.log(`  DATABASE_URL=${newUrl}`);
  console.log('\nThen restart the server. Existing users can still log in with their same username/password.');
}

main().finally(() => { if (rl) rl.close(); pool.end(); });
