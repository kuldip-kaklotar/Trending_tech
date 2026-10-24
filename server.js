// VoltTrack API - customers first. Credentials come only from environment variables.
const express = require('express'), cors = require('cors'), helmet = require('helmet');
const rateLimit = require('express-rate-limit'), jwt = require('jsonwebtoken'), bcrypt = require('bcryptjs');
const { Pool } = require('pg'), { migrate } = require('./migrate');

const { DATABASE_URL, JWT_SECRET, FRONTEND_ORIGIN, ADMIN_EMAIL, ADMIN_PASSWORD, PORT = 3000 } = process.env;
for (const [k, v] of Object.entries({ DATABASE_URL, JWT_SECRET, FRONTEND_ORIGIN })) if (!v) { console.error(`Missing env var ${k}`); process.exit(1); }
if (JWT_SECRET.length < 32) { console.error('JWT_SECRET must be at least 32 characters'); process.exit(1); }

const pool = new Pool({ connectionString: DATABASE_URL, ssl: process.env.PGSSL === 'off' ? false : { rejectUnauthorized: false } });
const app = express();
app.set('trust proxy', 1);
app.use(helmet());
const origins = FRONTEND_ORIGIN.split(',').map(s => s.trim().replace(/\/$/, ''));
app.use(cors({ origin: (o, cb) => cb(null, !o || origins.includes(o)), methods: ['GET', 'POST', 'PUT', 'DELETE'], allowedHeaders: ['Content-Type', 'Authorization'] }));
app.set('etag', false);
app.use('/api', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });   // never let a phone/proxy cache API data
app.use(express.json({ limit: '1mb' }));

// ---------- helpers ----------
const COLS = `customer_code AS id, name, mobile, alt_mobile AS alt, email, address, city, state, pin, reg_no AS reg,
  bike_brand AS brand, bike_model AS model, chassis, archived, to_char(created_at,'YYYY-MM-DD') AS created,
  to_char(archived_at,'YYYY-MM-DD') AS "archivedOn"`;
function normMobile(s) {
  let d = String(s || '').replace(/[\s\-().]/g, '');
  if (d.startsWith('+91')) d = d.slice(3); else if (/^91\d{10}$/.test(d)) d = d.slice(2); else if (/^0\d{10}$/.test(d)) d = d.slice(1);
  return /^[6-9]\d{9}$/.test(d) && !/^(\d)\1{9}$/.test(d) ? d : '';
}
function validate(b, { partialOk = false } = {}) {
  const t = k => String(b[k] ?? '').trim(), errors = {}, v = {};
  v.name = t('name'); if (!v.name || v.name.length > 120) errors.name = 'Full name is required (max 120 characters)';
  v.mobile = normMobile(b.mobile); if (!v.mobile) errors.mobile = 'Enter a valid 10-digit Indian mobile number';
  v.alt = t('alt') ? normMobile(b.alt) : ''; if (t('alt') && !v.alt) errors.alt = 'Alternate mobile is invalid';
  v.email = t('email'); if (v.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v.email)) errors.email = 'Invalid email address';
  v.pin = t('pin'); if (v.pin && !/^\d{6}$/.test(v.pin)) errors.pin = 'PIN code must be 6 digits';
  v.reg = t('reg').toUpperCase().replace(/[\s-]/g, ''); if (!v.reg || v.reg.length > 20) errors.reg = 'Bike registration number is required';
  for (const k of ['address', 'city', 'state', 'brand', 'model', 'chassis']) { v[k] = t(k); if (v[k].length > 250) errors[k] = 'Too long'; }
  return { v, errors, ok: !Object.keys(errors).length };
}
const wrap = fn => (req, res) => fn(req, res).catch(e => {
  if (e.code === '23505') return res.status(409).json({ error: 'Duplicate', errors: { reg: 'This registration number already belongs to another customer' } });
  console.error('ERR', e.code || '', e.message);           // never log request bodies or credentials
  res.status(500).json({ error: 'Server error' });
});

// ---------- public ----------
app.get('/api/health', wrap(async (_req, res) => { await pool.query('SELECT 1'); res.json({ status: 'ok', db: 'up', time: new Date().toISOString() }); }));
app.post('/api/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false }), wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
  const u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
  const ok = await bcrypt.compare(pw, u ? u.password_hash : '$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvali');
  if (!u || !ok) return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ token: jwt.sign({ sub: u.id, role: u.role, email: u.email }, JWT_SECRET, { expiresIn: '12h' }), role: u.role, email: u.email });
}));

// ---------- protected ----------
const auth = (req, res, next) => {
  const h = req.headers.authorization || '';
  try { req.user = jwt.verify(h.startsWith('Bearer ') ? h.slice(7) : '', JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Login required' }); }
};
const adminOnly = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admin access required' });
app.use('/api/customers', auth, rateLimit({ windowMs: 60 * 1000, max: 240, standardHeaders: true, legacyHeaders: false }));
app.get('/api/auth/me', auth, (req, res) => res.json({ email: req.user.email, role: req.user.role }));

app.get('/api/customers', wrap(async (req, res) => {
  const archived = req.query.archived === 'true', q = String(req.query.q || '').trim();
  const limit = Math.min(Math.max(+req.query.limit || 500, 1), 1000), offset = Math.max(+req.query.offset || 0, 0);
  const fp = [archived]; let where = 'archived = $1';
  if (q) { fp.push('%' + q.replace(/[%_\\]/g, '\\$&') + '%'); where += ' AND (name ILIKE $2 OR mobile ILIKE $2 OR reg_no ILIKE $2)'; }
  const [rows, tot] = await Promise.all([
    pool.query(`SELECT ${COLS} FROM customers WHERE ${where} ORDER BY id LIMIT $${fp.length + 1} OFFSET $${fp.length + 2}`, [...fp, limit, offset]),
    pool.query(`SELECT count(*)::int AS n FROM customers WHERE ${where}`, fp)]);
  res.json({ customers: rows.rows, total: tot.rows[0].n, limit, offset });   // total = ALL matching rows, not just this page
}));
app.get('/api/customers/:code', wrap(async (req, res) => {
  const r = await pool.query(`SELECT ${COLS} FROM customers WHERE customer_code=$1`, [req.params.code]);
  r.rowCount ? res.json(r.rows[0]) : res.status(404).json({ error: 'Not found' });
}));
app.post('/api/customers', wrap(async (req, res) => {
  const { v, errors, ok } = validate(req.body); if (!ok) return res.status(400).json({ error: 'Validation failed', errors });
  const r = await pool.query(`INSERT INTO customers (name,mobile,alt_mobile,email,address,city,state,pin,reg_no,bike_brand,bike_model,chassis)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING ${COLS}`,
    [v.name, v.mobile, v.alt, v.email, v.address, v.city, v.state, v.pin, v.reg, v.brand, v.model, v.chassis]);
  res.status(201).json(r.rows[0]);
}));
app.put('/api/customers/:code', wrap(async (req, res) => {
  const { v, errors, ok } = validate(req.body); if (!ok) return res.status(400).json({ error: 'Validation failed', errors });
  const r = await pool.query(`UPDATE customers SET name=$2,mobile=$3,alt_mobile=$4,email=$5,address=$6,city=$7,state=$8,pin=$9,reg_no=$10,
    bike_brand=$11,bike_model=$12,chassis=$13,updated_at=now() WHERE customer_code=$1 AND NOT archived RETURNING ${COLS}`,
    [req.params.code, v.name, v.mobile, v.alt, v.email, v.address, v.city, v.state, v.pin, v.reg, v.brand, v.model, v.chassis]);
  r.rowCount ? res.json(r.rows[0]) : res.status(404).json({ error: 'Not found' });
}));
// Default = archive (keeps history safe). ?permanent=true removes the row (admin only).
app.delete('/api/customers/:code', adminOnly, wrap(async (req, res) => {
  const r = req.query.permanent === 'true'
    ? await pool.query('DELETE FROM customers WHERE customer_code=$1', [req.params.code])
    : await pool.query('UPDATE customers SET archived=true, archived_at=now(), updated_at=now() WHERE customer_code=$1 AND NOT archived', [req.params.code]);
  r.rowCount ? res.json({ ok: true }) : res.status(404).json({ error: 'Not found' });
}));
app.post('/api/customers/:code/restore', adminOnly, wrap(async (req, res) => {
  const r = await pool.query(`UPDATE customers SET archived=false, archived_at=NULL, updated_at=now() WHERE customer_code=$1 AND archived RETURNING ${COLS}`, [req.params.code]);
  r.rowCount ? res.json(r.rows[0]) : res.status(404).json({ error: 'Not found' });
}));
// One-time, repeatable import of customers from the browser's old localStorage data. Never creates duplicates.
// Repeatable import of a browser's old localStorage customers. Never duplicates a bike (registration no.) and never
// drops a person: if an old ID is already used by someone else, the record gets a new ID. Returns map = [{from,to}]
// so the browser can re-point its local purchases at the right server customer.
app.post('/api/customers/import', adminOnly, wrap(async (req, res) => {
  const list = Array.isArray(req.body.customers) ? req.body.customers.slice(0, 5000) : [];
  const out = { imported: 0, skipped: [], invalid: [], map: [] }, c = await pool.connect();
  try {
    await c.query('BEGIN');
    for (const raw of list) {
      const { v, errors, ok } = validate(raw), from = String(raw.id || '');
      if (!ok) { out.invalid.push({ id: from, errors }); continue; }
      let code = /^C-\d{1,9}$/.test(from) ? from : null;
      const same = code && await c.query('SELECT customer_code FROM customers WHERE customer_code=$1 AND reg_no=$2', [code, v.reg]);
      if (same && same.rowCount) { out.skipped.push(from); out.map.push({ from, to: code }); continue; }       // already imported
      const archived = !!raw.archivedOn;
      if (!archived) {
        const dup = await c.query('SELECT customer_code FROM customers WHERE reg_no=$1 AND NOT archived', [v.reg]);
        if (dup.rowCount) { out.skipped.push(from || v.reg); if (from) out.map.push({ from, to: dup.rows[0].customer_code }); continue; }
      }
      if (code && (await c.query('SELECT 1 FROM customers WHERE customer_code=$1', [code])).rowCount) code = null;  // ID used by another person
      const r = await c.query(`INSERT INTO customers (customer_code,name,mobile,alt_mobile,email,address,city,state,pin,reg_no,bike_brand,bike_model,chassis,archived,archived_at)
        VALUES (COALESCE($1,'C-'||nextval('customer_code_seq')),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,CASE WHEN $14 THEN now() END) RETURNING customer_code`,
        [code, v.name, v.mobile, v.alt, v.email, v.address, v.city, v.state, v.pin, v.reg, v.brand, v.model, v.chassis, archived]);
      out.imported++; if (from) out.map.push({ from, to: r.rows[0].customer_code });
    }
    await c.query(`SELECT setval('customer_code_seq', GREATEST(1000, (SELECT COALESCE(MAX(substring(customer_code from 3)::bigint),0) FROM customers), (SELECT last_value FROM customer_code_seq)))`);
    await c.query('COMMIT'); res.json(out);
  } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
}));

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

(async () => {
  await migrate(pool);
  const adminEmail = (ADMIN_EMAIL || '').trim().toLowerCase(), adminPw = (ADMIN_PASSWORD || '').trim();
  if (adminEmail && adminPw) {
    if (adminPw.length < 10) { console.error('ADMIN_PASSWORD must be at least 10 characters'); process.exit(1); }
    const hash = await bcrypt.hash(adminPw, 12);
    if ((process.env.ADMIN_RESET || '').trim() === 'true') {          // one-time password reset: set ADMIN_RESET=true, deploy, sign in, then delete the variable
      await pool.query(`INSERT INTO users (email,password_hash,role) VALUES ($1,$2,'admin') ON CONFLICT (email) DO UPDATE SET password_hash=EXCLUDED.password_hash, role='admin'`, [adminEmail, hash]);
      console.log('Admin password RESET for ' + adminEmail + ' - now delete the ADMIN_RESET variable');
    } else {
      const r = await pool.query(`INSERT INTO users (email,password_hash,role) VALUES ($1,$2,'admin') ON CONFLICT (email) DO NOTHING`, [adminEmail, hash]);
      console.log(r.rowCount ? 'Admin user created: ' + adminEmail : 'Admin user already exists: ' + adminEmail + ' (password unchanged; use ADMIN_RESET=true to change it)');
    }
  } else console.log('ADMIN_EMAIL / ADMIN_PASSWORD are not set - no admin user is created');
  console.log('Users in database: ' + (await pool.query('SELECT count(*)::int AS n FROM users')).rows[0].n);
  app.listen(PORT, () => console.log('VoltTrack API listening on ' + PORT));
})().catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
