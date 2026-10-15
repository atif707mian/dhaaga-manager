require('dotenv').config();
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.BACKUP_DATABASE_URL || process.env.DATABASE_URL });
const BASE = 'http://localhost:3000';

async function main() {
  const crypto = require('crypto');
  const bcrypt = require('bcryptjs');
  const adminId = crypto.randomUUID();
  const username = 'source_backup_test_' + Date.now();
  const password = 'TempPass123!';
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(`INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, 'admin')`, [adminId, username, hash]);
    const loginRes = await fetch(BASE + '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password }) });
    const cookie = loginRes.headers.get('set-cookie');

    const res = await fetch(BASE + '/api/backup/source', { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie } });
    const data = await res.json().catch(() => ({}));
    console.log('Status:', res.status, 'Body:', JSON.stringify(data));
  } finally {
    await pool.query('DELETE FROM users WHERE id=$1', [adminId]).catch(()=>{});
    await pool.end();
  }
}
main().catch(e => { console.error('FAILED:', e); process.exit(1); });
