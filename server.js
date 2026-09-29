const path = require('path');
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');
const { scan } = require('./scanner');

const SECRET = process.env.JWT_SECRET || 'dev-only-secret';
if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET is required in production');
}

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10kb' }));

const api = express.Router();
const limit = (windowMs, max) => rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests. Try again shortly.' } });
const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);
const sign = (u) => jwt.sign({ id: u.id, email: u.email }, SECRET, { expiresIn: '7d' });
const auth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET); next(); }
  catch { res.status(401).json({ error: 'Sign in required' }); }
};

api.use(limit(60 * 1000, 120));
api.get('/health', (req, res) => res.json({ ok: true }));

api.post('/auth/register', limit(15 * 60 * 1000, 20), wrap(async (req, res) => {
  const { email, password } = req.body || {};
  if (!/^\S+@\S+\.\S+$/.test(email || '') || (password || '').length < 8)
    return res.status(400).json({ error: 'Enter a valid email and a password of 8+ characters' });
  try {
    const r = await db.query('INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id,email',
      [email.toLowerCase(), await bcrypt.hash(password, 10)]);
    res.status(201).json({ token: sign(r.rows[0]), user: r.rows[0] });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'This email is already registered' });
    throw e;
  }
}));

api.post('/auth/login', limit(15 * 60 * 1000, 20), wrap(async (req, res) => {
  const { email, password } = req.body || {};
  const r = await db.query('SELECT * FROM users WHERE email=$1', [(email || '').toLowerCase()]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(password || '', u.password_hash)))
    return res.status(401).json({ error: 'Incorrect email or password' });
  res.json({ token: sign(u), user: { id: u.id, email: u.email } });
}));

api.get('/me', auth, wrap(async (req, res) => {
  const r = await db.query('SELECT id,email FROM users WHERE id=$1', [req.user.id]);
  if (!r.rows[0]) return res.status(401).json({ error: 'Sign in required' });
  res.json(r.rows[0]);
}));

api.post('/scan', auth, limit(60 * 1000, 15), wrap(async (req, res) => {
  const result = await scan((req.body || {}).url || '');
  const r = await db.query('INSERT INTO scans(user_id,url,host,score,status,result) VALUES($1,$2,$3,$4,$5,$6) RETURNING id,created_at',
    [req.user.id, result.url, result.host, result.score, result.status, result]);
  res.status(201).json({ ...result, id: r.rows[0].id, created_at: r.rows[0].created_at });
}));

api.get('/scans', auth, wrap(async (req, res) => {
  const r = await db.query('SELECT id,url,host,score,status,created_at FROM scans WHERE user_id=$1 ORDER BY created_at DESC LIMIT 50', [req.user.id]);
  res.json(r.rows);
}));

api.delete('/scans/:id', auth, wrap(async (req, res) => {
  await db.query('DELETE FROM scans WHERE id=$1 AND user_id=$2', [parseInt(req.params.id, 10) || 0, req.user.id]);
  res.status(204).end();
}));

api.get('/stats', auth, wrap(async (req, res) => {
  const s = await db.query(`SELECT count(DISTINCT host)::int sites,
    count(*) FILTER (WHERE created_at>=date_trunc('day',now()))::int today,
    count(*) FILTER (WHERE status='threat')::int threats,
    COALESCE(round(avg(score)),0)::int avg FROM scans WHERE user_id=$1`, [req.user.id]);
  const d = await db.query(`SELECT to_char(d,'Dy') day, count(s.id)::int n
    FROM generate_series(current_date-6,current_date,'1 day') d
    LEFT JOIN scans s ON s.user_id=$1 AND s.created_at::date=d::date GROUP BY d ORDER BY d`, [req.user.id]);
  res.json({ ...s.rows[0], series: d.rows });
}));

api.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use('/api', api);
app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));
app.use((err, req, res, next) => {
  if (err.status) return res.status(err.status).json({ error: err.message });
  console.error(err);
  res.status(500).json({ error: 'Something went wrong on our side' });
});

if (require.main === module) {
  db.init().then(() => {
    const port = process.env.PORT || 3000;
    const srv = app.listen(port, () => console.log('WebGuard on :' + port));
    process.on('SIGTERM', () => srv.close(() => db.pool.end()));
  }).catch((e) => { console.error('DB init failed', e); process.exit(1); });
}
module.exports = app;
