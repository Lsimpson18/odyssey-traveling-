'use strict';
require('dotenv').config();
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { MongoClient } = require('mongodb');

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const COOKIE = 'odyssey_token';
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

// ---------- config ----------
const SECRET = process.env.JWT_SECRET || (IS_PROD ? null : 'dev-only-secret-change-me');
if (!SECRET) throw new Error('JWT_SECRET is not set. Add it in your Vercel project settings.');

// ---------- database (MongoDB Atlas) ----------
let colPromise;
function usersCol() {
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is not set.');
  if (!colPromise) {
    colPromise = (async () => {
      const client = await new MongoClient(process.env.MONGODB_URI).connect();
      const col = client.db('odyssey').collection('users');
      await col.createIndex({ email: 1 }, { unique: true });
      return col;
    })().catch((err) => {
      colPromise = null; // try again on the next request
      throw err;
    });
  }
  return colPromise;
}

// ---------- helpers ----------
const DUMMY_HASH = bcrypt.hashSync('odyssey-dummy-password', 10);
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email });

const wrap = (fn) => (req, res) =>
  Promise.resolve(fn(req, res)).catch((err) => {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong on our side. Please try again.' });
  });

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

// Basic rate limiter. On serverless it only counts per warm instance,
// so treat it as a speed bump, not a full defence.
const hits = new Map();
setInterval(() => hits.clear(), 15 * 60 * 1000).unref();
function limit(max) {
  return (req, res, next) => {
    const key = req.ip + req.path;
    const count = (hits.get(key) || 0) + 1;
    hits.set(key, count);
    if (count > max) return res.status(429).json({ error: 'Too many attempts. Please wait a few minutes and try again.' });
    next();
  };
}

async function requireAuth(req, res, next) {
  try {
    const token = getCookie(req, COOKIE);
    if (!token) return res.status(401).json({ error: 'Please sign in to continue.' });
    const payload = jwt.verify(token, SECRET);
    const user = await (await usersCol()).findOne({ id: payload.sub });
    if (!user) return res.status(401).json({ error: 'Please sign in to continue.' });
    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Please sign in to continue.' });
    }
    console.error(err);
    res.status(500).json({ error: 'Something went wrong on our side. Please try again.' });
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

auth.post('/register', limit(10), wrap(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (name.length < 2 || name.length > 60) return res.status(400).json({ error: 'Enter your full name (2 to 60 characters).' });
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Enter a valid email address, like name@example.com.' });
  if (password.length < 8) return res.status(400).json({ error: 'Your password needs at least 8 characters.' });

  const user = {
    id: crypto.randomUUID(),
    name,
    email,
    passwordHash: await bcrypt.hash(password, 12),
    createdAt: new Date().toISOString(),
  };
  try {
    await (await usersCol()).insertOne({ ...user });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'An account with this email already exists. Try signing in instead.' });
    }
    throw err;
  }
  setSession(res, user);
  res.status(201).json({ user: publicUser(user) });
}));

auth.post('/login', limit(15), wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!email || !password) return res.status(400).json({ error: 'Enter your email and password.' });

  const user = await (await usersCol()).findOne({ email });
  const ok = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);
  if (!user || !ok) return res.status(401).json({ error: 'Email or password is incorrect.' });

  setSession(res, user);
  res.json({ user: publicUser(user) });
}));

auth.post('/forgot-password', limit(5), wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Enter a valid email address, like name@example.com.' });

  // Same reply whether or not the account exists, so nobody can probe for emails.
  const user = await (await usersCol()).findOne({ email });
  if (user) {
    // TODO: send a real reset email here (Resend, SendGrid, Nodemailer, etc.)
    console.log('Password reset requested for an existing account');
  }
  res.json({ message: 'If an account exists for that email, a reset link is on its way.' });
}));

auth.get('/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

auth.post('/logout', (req, res) => {
  res.clearCookie(COOKIE, { httpOnly: true, sameSite: 'lax', secure: IS_PROD });
  res.json({ ok: true });
});

app.use('/api/auth', auth);
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((err, req, res, next) => res.status(400).json({ error: 'That request could not be read.' }));

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => console.log(`Odyssey Travel Co is running at http://localhost:${PORT}`));
}
