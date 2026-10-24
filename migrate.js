// Applies SQL migration files (001_init.sql, 002_*.sql, ...) once each, in order.
// Works with a flat project (SQL next to this file) or a ./migrations folder.
// Every file runs in its own transaction; any error stops startup and is reported (nothing is skipped silently).
const fs = require('fs'), path = require('path');

function findMigrations() {
  const dirs = [path.join(__dirname, 'migrations'), __dirname].filter(d => fs.existsSync(d) && fs.statSync(d).isDirectory());
  for (const dir of dirs) {
    const files = fs.readdirSync(dir).filter(f => /^\d{3}_.+\.sql$/.test(f)).sort();
    if (files.length) return { dir, files };
  }
  throw new Error('No migration files (like 001_init.sql) found in ' + dirs.join(' or ') + '. Commit 001_init.sql next to migrate.js.');
}

async function migrate(pool) {
  const { dir, files } = findMigrations();
  console.log(`Migrations: ${files.length} file(s) found in ${dir}`);
  const c = await pool.connect();
  try {
    await c.query('SELECT pg_advisory_lock(727274)');            // only one instance migrates at a time
    await c.query('CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())');
    for (const f of files) {
      if ((await c.query('SELECT 1 FROM schema_migrations WHERE name=$1', [f])).rowCount) { console.log('already applied:', f); continue; }
      try {
        await c.query('BEGIN');
        await c.query(fs.readFileSync(path.join(dir, f), 'utf8'));
        await c.query('INSERT INTO schema_migrations(name) VALUES ($1)', [f]);
        await c.query('COMMIT');
        console.log('applied:', f);
      } catch (e) {
        await c.query('ROLLBACK');
        throw new Error(`Migration ${f} failed: ${e.message}`);
      }
    }
  } finally {
    try { await c.query('SELECT pg_advisory_unlock(727274)'); } catch {}
    c.release();
  }
}
module.exports = { migrate, findMigrations };

if (require.main === module) {
  if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is not set'); process.exit(1); }
  const { Pool } = require('pg');
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === 'off' ? false : { rejectUnauthorized: false } });
  migrate(pool).then(() => pool.end()).catch(e => { console.error(e.message); process.exit(1); });
}