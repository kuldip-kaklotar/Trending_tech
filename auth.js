// Authentication, authorization and user management.
// Roles live in PostgreSQL. The token carries only the user id; role and active state are read from the database
// on every request, so a role change or deactivation takes effect immediately and a client can never choose its role.
const ROLES = ['admin', 'staff'];                       // 'staff' is shown as "Normal User" in the app
const PERMS = {
  admin: ['*'],
  staff: ['customers:read', 'customers:create', 'customers:update'],
};
const can = (role, perm) => (PERMS[role] || []).some(p => p === '*' || p === perm);
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

module.exports = function setup({ app, pool, bcrypt, jwt, JWT_SECRET, rateLimit, wrap }) {
  const pub = u => ({ id: u.id, email: u.email, name: u.name, role: u.role, active: u.active, lastLogin: u.last_login, created: u.created_at });
  const sign = u => jwt.sign({ sub: u.id, tv: u.token_version }, JWT_SECRET, { expiresIn: '12h' });
  const pwError = p => (typeof p !== 'string' || p.length < 10 ? 'Password must be at least 10 characters' : p.length > 200 ? 'Password is too long' : '');

  const auth = async (req, res, next) => {
    try {
      const h = req.headers.authorization || '';
      const t = jwt.verify(h.startsWith('Bearer ') ? h.slice(7) : '', JWT_SECRET);
      const u = (await pool.query('SELECT * FROM users WHERE id=$1', [t.sub])).rows[0];
      if (!u || !u.active || u.token_version !== t.tv) return res.status(401).json({ error: 'Login required' });
      req.user = u; next();
    } catch { res.status(401).json({ error: 'Login required' }); }
  };
  const need = perm => (req, res, next) =>
    can(req.user.role, perm) ? next() : res.status(403).json({ error: 'You do not have permission for this action' });

  // ----- sign in (no public sign-up exists: accounts are created only by an admin) -----
  app.post('/api/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false }), wrap(async (req, res) => {
    const email = String(req.body.email || '').trim().toLowerCase(), pw = String(req.body.password || '');
    const u = (await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows[0];
    const ok = await bcrypt.compare(pw, u ? u.password_hash : '$2a$10$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvali');
    if (!u || !ok || !u.active) return res.status(401).json({ error: 'Invalid email or password' });   // same message: no account probing
    await pool.query('UPDATE users SET last_login=now() WHERE id=$1', [u.id]);
    res.json({ token: sign(u), role: u.role, email: u.email, name: u.name });                            // role comes from the database
  }));

  // ----- own profile (role and email can never be changed here) -----
  app.get('/api/auth/me', auth, (req, res) => res.json(pub(req.user)));
  app.put('/api/auth/me', auth, wrap(async (req, res) => {
    const name = String(req.body.name || '').trim();
    if (!name || name.length > 120) return res.status(400).json({ error: 'Validation failed', errors: { name: 'Name is required (max 120 characters)' } });
    const r = await pool.query('UPDATE users SET name=$2, updated_at=now() WHERE id=$1 RETURNING *', [req.user.id, name]);
    res.json(pub(r.rows[0]));
  }));
  app.post('/api/auth/change-password', auth, rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false }), wrap(async (req, res) => {
    const cur = String(req.body.current || ''), next = req.body.next;
    if (!(await bcrypt.compare(cur, req.user.password_hash))) return res.status(400).json({ error: 'Validation failed', errors: { current: 'Current password is wrong' } });
    const pe = pwError(next); if (pe) return res.status(400).json({ error: 'Validation failed', errors: { next: pe } });
    if (next === cur) return res.status(400).json({ error: 'Validation failed', errors: { next: 'New password must be different' } });
    const r = await pool.query('UPDATE users SET password_hash=$2, token_version=token_version+1, updated_at=now() WHERE id=$1 RETURNING *', [req.user.id, await bcrypt.hash(next, 12)]);
    res.json({ ok: true, token: sign(r.rows[0]) });           // other sessions are signed out, this one continues
  }));

  // ----- user management: admin only (permission users:manage) -----
  const manage = [auth, need('users:manage')];
  const lastAdmin = async id => (await pool.query("SELECT count(*)::int AS n FROM users WHERE role='admin' AND active AND id<>$1", [id])).rows[0].n === 0;
  app.get('/api/users', ...manage, wrap(async (_req, res) => {
    res.json({ users: (await pool.query('SELECT * FROM users ORDER BY id')).rows.map(pub) });
  }));
  app.post('/api/users', ...manage, wrap(async (req, res) => {
    const b = req.body, errors = {}, name = String(b.name || '').trim(), email = String(b.email || '').trim().toLowerCase();
    if (!name || name.length > 120) errors.name = 'Name is required (max 120 characters)';
    if (!EMAIL.test(email) || email.length > 200) errors.email = 'Enter a valid email address';
    if (!ROLES.includes(b.role)) errors.role = 'Role must be admin or staff';
    const pe = pwError(b.password); if (pe) errors.password = pe;
    if (Object.keys(errors).length) return res.status(400).json({ error: 'Validation failed', errors });
    if ((await pool.query('SELECT * FROM users WHERE email=$1', [email])).rows.length) return res.status(409).json({ error: 'Duplicate', errors: { email: 'A user with this email already exists' } });
    const r = await pool.query('INSERT INTO users (email,password_hash,role,name) VALUES ($1,$2,$3,$4) RETURNING *', [email, await bcrypt.hash(b.password, 12), b.role, name]);
    res.status(201).json(pub(r.rows[0]));
  }));
  app.put('/api/users/:id', ...manage, wrap(async (req, res) => {
    const t = (await pool.query('SELECT * FROM users WHERE id=$1', [+req.params.id || 0])).rows[0];
    if (!t) return res.status(404).json({ error: 'Not found' });
    const b = req.body, errors = {}, name = b.name === undefined ? t.name : String(b.name).trim(), role = b.role === undefined ? t.role : b.role, active = b.active === undefined ? t.active : !!b.active;
    if (!name || name.length > 120) errors.name = 'Name is required (max 120 characters)';
    if (!ROLES.includes(role)) errors.role = 'Role must be admin or staff';
    if (Object.keys(errors).length) return res.status(400).json({ error: 'Validation failed', errors });
    const changed = role !== t.role || active !== t.active;
    if (t.id === req.user.id && changed) return res.status(400).json({ error: 'You cannot change your own role or deactivate yourself' });
    if (t.role === 'admin' && t.active && (role !== 'admin' || !active) && await lastAdmin(t.id)) return res.status(400).json({ error: 'At least one active admin is required' });
    const r = await pool.query('UPDATE users SET name=$2, role=$3, active=$4, token_version=$5, updated_at=now() WHERE id=$1 RETURNING *', [t.id, name, role, active, t.token_version + (changed ? 1 : 0)]);
    res.json(pub(r.rows[0]));
  }));
  app.post('/api/users/:id/reset-password', ...manage, wrap(async (req, res) => {
    const pe = pwError(req.body.password); if (pe) return res.status(400).json({ error: 'Validation failed', errors: { password: pe } });
    const t = (await pool.query('SELECT * FROM users WHERE id=$1', [+req.params.id || 0])).rows[0];
    if (!t) return res.status(404).json({ error: 'Not found' });
    await pool.query('UPDATE users SET password_hash=$2, token_version=token_version+1, updated_at=now() WHERE id=$1 RETURNING *', [t.id, await bcrypt.hash(req.body.password, 12)]);
    res.json({ ok: true });
  }));

  return { auth, need, can };
};
module.exports.can = can; module.exports.PERMS = PERMS;
