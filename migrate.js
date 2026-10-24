// Runs every migrations/*.sql file once, in order, inside a transaction.
const fs = require('fs'), path = require('path'), { Pool } = require('pg');
async function migrate(pool) {
  await pool.query('CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())');
  const dir = path.join(__dirname, 'migrations');
  for (const f of fs.readdirSync(dir).filter(x => x.endsWith('.sql')).sort()) {
    if ((await pool.query('SELECT 1 FROM schema_migrations WHERE name=$1', [f])).rowCount) continue;
    const c = await pool.connect();
    try {
      await c.query('BEGIN'); await c.query(fs.readFileSync(path.join(dir, f), 'utf8'));
      await c.query('INSERT INTO schema_migrations(name) VALUES ($1)', [f]); await c.query('COMMIT');
      console.log('applied', f);
    } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
  }
}
module.exports = { migrate };
if (require.main === module) {
  if (!process.env.DATABASE_URL) { console.error('DATABASE_URL is not set'); process.exit(1); }
  const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === 'off' ? false : { rejectUnauthorized: false } });
  migrate(pool).then(() => pool.end()).catch(e => { console.error(e.message); process.exit(1); });
}
