'use strict';
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const PORT = parseInt(process.env.PORT || '3000', 10);
const DATA_DIR = process.env.DATA_DIR || '/data';
const ALLOW_REGISTRATION = (process.env.ALLOW_REGISTRATION || 'true').toLowerCase() === 'true';
const TOKEN_DAYS = 30;

fs.mkdirSync(DATA_DIR, { recursive: true });

// JWT secret: da env, altrimenti generato e persistito nel volume
function loadSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  const file = path.join(DATA_DIR, '.jwt_secret');
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
  const s = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(file, s, { mode: 0o600 });
  return s;
}
const JWT_SECRET = loadSecret();

// ---------- DB ----------
const db = new Database(path.join(DATA_DIR, 'ore.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS entries (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  date TEXT NOT NULL,
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, date)
);
CREATE TABLE IF NOT EXISTS settings (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  data TEXT NOT NULL,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  userById: db.prepare('SELECT id, username FROM users WHERE id = ?'),
  insertUser: db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)'),
  countUsers: db.prepare('SELECT COUNT(*) AS n FROM users'),
  entries: db.prepare('SELECT date, data FROM entries WHERE user_id = ?'),
  delEntries: db.prepare('DELETE FROM entries WHERE user_id = ?'),
  upsertEntry: db.prepare(`INSERT INTO entries (user_id, date, data) VALUES (?, ?, ?)
    ON CONFLICT(user_id, date) DO UPDATE SET data = excluded.data, updated_at = datetime('now')`),
  settings: db.prepare('SELECT data FROM settings WHERE user_id = ?'),
  upsertSettings: db.prepare(`INSERT INTO settings (user_id, data) VALUES (?, ?)
    ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = datetime('now')`)
};

// Utente admin iniziale (solo se il DB è vuoto)
if (process.env.ADMIN_USER && process.env.ADMIN_PASSWORD && q.countUsers.get().n === 0) {
  q.insertUser.run(process.env.ADMIN_USER.toLowerCase(), bcrypt.hashSync(process.env.ADMIN_PASSWORD, 12));
  console.log(`Utente iniziale "${process.env.ADMIN_USER}" creato`);
}

// ---------- App ----------
const app = express();
app.set('trust proxy', 1); // dietro Nginx Proxy Manager
app.disable('x-powered-by');
app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Troppi tentativi, riprova tra qualche minuto' }
});

function setSession(req, res, user) {
  const token = jwt.sign({ uid: user.id }, JWT_SECRET, { expiresIn: `${TOKEN_DAYS}d` });
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: req.secure,
    maxAge: TOKEN_DAYS * 24 * 3600 * 1000,
    path: '/'
  });
}

function requireAuth(req, res, next) {
  try {
    const { uid } = jwt.verify(req.cookies.token || '', JWT_SECRET);
    const user = q.userById.get(uid);
    if (!user) throw new Error('utente non trovato');
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Non autenticato', allowRegistration: ALLOW_REGISTRATION });
  }
}

const USERNAME_RE = /^[a-z0-9._-]{3,32}$/;

app.post('/api/register', authLimiter, (req, res) => {
  if (!ALLOW_REGISTRATION) return res.status(403).json({ error: 'Registrazione disabilitata' });
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!USERNAME_RE.test(username)) return res.status(400).json({ error: 'Username: 3-32 caratteri (lettere, numeri, . _ -)' });
  if (password.length < 8 || password.length > 200) return res.status(400).json({ error: 'La password deve avere almeno 8 caratteri' });
  if (q.userByName.get(username)) return res.status(409).json({ error: 'Username già in uso' });
  const info = q.insertUser.run(username, bcrypt.hashSync(password, 12));
  const user = { id: info.lastInsertRowid, username };
  setSession(req, res, user);
  res.json({ user: { username } });
});

app.post('/api/login', authLimiter, (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const row = q.userByName.get(username);
  // confronto anche se l'utente non esiste, per non rivelare quali username esistono
  const hash = row ? row.password_hash : '$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvali';
  const ok = bcrypt.compareSync(password, hash) && !!row;
  if (!ok) return res.status(401).json({ error: 'Credenziali non valide', allowRegistration: ALLOW_REGISTRATION });
  setSession(req, res, row);
  res.json({ user: { username: row.username } });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token', { path: '/' });
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ user: { username: req.user.username }, allowRegistration: ALLOW_REGISTRATION });
});

app.get('/api/data', requireAuth, (req, res) => {
  const data = {};
  for (const r of q.entries.all(req.user.id)) {
    try { data[r.date] = JSON.parse(r.data); } catch { /* riga corrotta, ignorata */ }
  }
  const s = q.settings.get(req.user.id);
  res.json({ data, settings: s ? JSON.parse(s.data) : null });
});

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const saveAll = db.transaction((uid, data) => {
  q.delEntries.run(uid);
  for (const [date, val] of Object.entries(data)) q.upsertEntry.run(uid, date, JSON.stringify(val));
});

app.put('/api/data', requireAuth, (req, res) => {
  const data = req.body && req.body.data;
  if (!data || typeof data !== 'object' || Array.isArray(data)) return res.status(400).json({ error: 'Formato non valido' });
  for (const [date, val] of Object.entries(data)) {
    if (!DATE_RE.test(date) || !val || typeof val !== 'object') return res.status(400).json({ error: `Voce non valida: ${date}` });
  }
  saveAll(req.user.id, data);
  res.json({ ok: true });
});

app.put('/api/settings', requireAuth, (req, res) => {
  const s = req.body && req.body.settings;
  if (!s || typeof s !== 'object' || Array.isArray(s)) return res.status(400).json({ error: 'Formato non valido' });
  q.upsertSettings.run(req.user.id, JSON.stringify(s));
  res.json({ ok: true });
});

app.get('/healthz', (req, res) => res.json({ ok: true }));

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: 0 }));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.status ? 'Richiesta non valida' : 'Errore interno' });
});

app.listen(PORT, () => console.log(`ore in ascolto sulla porta ${PORT}`));
