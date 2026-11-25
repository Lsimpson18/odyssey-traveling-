'use strict';
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const COOKIE = 'odyssey_token';
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

// ---------- storage (a simple JSON file, fine for local development) ----------
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
fs.mkdirSync(DATA_DIR, { recursive: true });

function loadSecret() {
  if (process.env.JWT_SECRET) return process.env.JWT_SECRET;
  const file = path.join(DATA_DIR, '.jwt-secret');
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
  const secret = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(file, secret, { mode: 0o600 });
  return secret;
}
const SECRET = loadSecret();

let users = fs.existsSync(USERS_FILE) ? JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')) : [];
function saveUsers() {
  const tmp = USERS_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(users, null, 2));
  fs.renameSync(tmp, USERS_FILE);
}

// ---------- helpers ----------
const DUMMY_HASH = bcrypt.hashSync('odyssey-dummy-password', 10);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email });

function getCookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}

function setSession(res, user) {
  const token = jwt.sign({ sub: user.id }, SECRET, { expiresIn: '7d' });
  res.cookie(COOKIE, token, { httpOnly: true, sameSite: 'lax', secure: IS_PROD, maxAge: WEEK_MS });
}

// small in-memory rate limiter to slow down password guessing
const hits = new Map();
setInterval(() => hits.clear(), 15 * 60 * 1000).unref();
function limit(max) {
  return (req, res, next) => {
    const key = req.ip + req.path;
    const count = (hits.get(key) || 0) + 1;
    hits.set(key, count);
    if (count > max) {
      return res.status(429).json({ error: 'Too many attempts. Please wait a few minutes and try again.' });
    }
    next();
  };
}

function requireAuth(req, res, next) {
  try {
    const token = getCookie(req, COOKIE);
    if (!token) throw new Error('no token');
    const payload = jwt.verify(token, SECRET);
    const user = users.find((u) => u.id === payload.sub);
    if (!user) throw new Error('no user');
    req.user = user;
    next();
  } catch {
    res.status(401).json({ error: 'Please sign in to continue.' });
  }
}

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

const auth = express.Router();

auth.post('/register', limit(10), async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (name.length < 2 || name.length > 60) return res.status(400).json({ error: 'Enter your full name (2 to 60 characters).' });
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Enter a valid email address, like name@example.com.' });
  if (password.length < 8) return res.status(400).json({ error: 'Your password needs at least 8 characters.' });
  if (users.some((u) => u.email === email)) {
    return res.status(409).json({ error: 'An account with this email already exists. Try signing in instead.' });
  }

  const user = {
    id: crypto.randomUUID(),
    name,
    email,
    passwordHash: await bcrypt.hash(password, 12),
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  saveUsers();
  setSession(res, user);
  res.status(201).json({ user: publicUser(user) });
});

auth.post('/login', limit(15), async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!email || !password) return res.status(400).json({ error: 'Enter your email and password.' });

  const user = users.find((u) => u.email === email);
  const ok = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);
  if (!user || !ok) return res.status(401).json({ error: 'Email or password is incorrect.' });

  setSession(res, user);
  res.json({ user: publicUser(user) });
});

auth.post('/forgot-password', limit(5), (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Enter a valid email address, like name@example.com.' });

  // Same reply whether or not the account exists, so nobody can probe for emails.
  if (users.some((u) => u.email === email)) {
    // TODO: send a real reset email here (Nodemailer, Resend, SendGrid, etc.)
    console.log(`[dev] Password reset requested for ${email}`);
  }
  res.json({ message: 'If an account exists for that email, a reset link is on its way.' });
});

auth.get('/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

auth.post('/logout', (req, res) => {
  res.clearCookie(COOKIE, { httpOnly: true, sameSite: 'lax', secure: IS_PROD });
  res.json({ ok: true });
});

app.use('/api/auth', auth);
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => res.status(400).json({ error: 'That request could not be read.' }));

app.listen(PORT, () => console.log(`Odyssey Travel Co is running at http://localhost:${PORT}`));
