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
  const limit = Math.min(+req.query.limit || 1000, 5000), offset = Math.max(+req.query.offset || 0, 0);
  const p = [archived, limit, offset]; let where = 'archived = $1';
  if (q) { p.push('%' + q.replace(/[%_\\]/g, '\\$&') + '%'); where += ` AND (name ILIKE $4 OR mobile ILIKE $4 OR reg_no ILIKE $4)`; }
  const r = await pool.query(`SELECT ${COLS} FROM customers WHERE ${where} ORDER BY id LIMIT $2 OFFSET $3`, p);
  res.json({ customers: r.rows });
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
app.post('/api/customers/import', adminOnly, wrap(async (req, res) => {
  const list = Array.isArray(req.body.customers) ? req.body.customers.slice(0, 5000) : [];
  const out = { imported: 0, skipped: [], invalid: [] }, c = await pool.connect();
  try {
    await c.query('BEGIN');
    for (const raw of list) {
      const code = /^C-\d{1,9}$/.test(String(raw.id || '')) ? raw.id : null, { v, errors, ok } = validate(raw);
      if (!ok) { out.invalid.push({ id: raw.id, errors }); continue; }
      const r = await c.query(`INSERT INTO customers (customer_code,name,mobile,alt_mobile,email,address,city,state,pin,reg_no,bike_brand,bike_model,chassis,archived,archived_at)
        VALUES (COALESCE($1,'C-'||nextval('customer_code_seq')),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,CASE WHEN $14 THEN now() END)
        ON CONFLICT DO NOTHING RETURNING id`, [code, v.name, v.mobile, v.alt, v.email, v.address, v.city, v.state, v.pin, v.reg, v.brand, v.model, v.chassis, !!raw.archivedOn]);
      r.rowCount ? out.imported++ : out.skipped.push(raw.id || v.reg);
    }
    await c.query(`SELECT setval('customer_code_seq', GREATEST(1000, (SELECT COALESCE(MAX(substring(customer_code from 3)::bigint),0) FROM customers), (SELECT last_value FROM customer_code_seq)))`);
    await c.query('COMMIT'); res.json(out);
  } catch (e) { await c.query('ROLLBACK'); throw e; } finally { c.release(); }
}));

app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

(async () => {
  await migrate(pool);
  if (ADMIN_EMAIL && ADMIN_PASSWORD) {                       // first admin from env; never overwritten afterwards
    if (ADMIN_PASSWORD.length < 10) { console.error('ADMIN_PASSWORD must be at least 10 characters'); process.exit(1); }
    await pool.query(`INSERT INTO users (email,password_hash,role) VALUES ($1,$2,'admin') ON CONFLICT (email) DO NOTHING`, [ADMIN_EMAIL.toLowerCase(), await bcrypt.hash(ADMIN_PASSWORD, 12)]);
  }
  app.listen(PORT, () => console.log('VoltTrack API listening on ' + PORT));
})().catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
