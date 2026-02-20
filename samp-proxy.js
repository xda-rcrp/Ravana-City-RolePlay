const express = require('express');
const sampQuery = require('samp-query');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(cors());
app.use(express.json());

const DB_FILE = path.join(__dirname, 'admin.db.json');
let db = { users: {}, tokens: {}, override: null };
try {
  if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
} catch (e) { console.error('Failed to load DB', e); }

function saveDB() {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
  catch (e) { console.error('Failed to save DB', e); }
}

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash: derived };
}

function verifyPassword(password, salt, hash) {
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return derived === hash;
}

// GET /status?ip=...&port=...
app.get('/status', (req, res) => {
  const ip = req.query.ip;
  const port = parseInt(req.query.port, 10) || 7777;
  if (!ip) return res.status(400).json({ error: 'ip required' });

  // If admin override exists, return that
  if (db.override && db.override.state) {
    if (db.override.state === 'on') {
      return res.json({ online: true, players: db.override.players || 0, maxplayers: db.override.maxplayers || 0, override: true });
    }
    if (db.override.state === 'off') {
      return res.json({ online: false, players: 0, maxplayers: 0, override: true });
    }
  }

  sampQuery({ host: ip, port }, (err, info) => {
    if (err) return res.json({ online: false, players: 0, maxplayers: 0, error: err.message });
    const players = Array.isArray(info.players) ? info.players.length : (info.players || 0);
    const maxplayers = info.maxplayers || 0;
    res.json({ online: true, players, maxplayers, raw: info });
  });
});

// Admin register (requires admin code)
app.post('/admin/register', (req, res) => {
  const { username, password, code } = req.body || {};
  if (!username || !password || !code) return res.status(400).json({ error: 'missing fields' });
  if (code !== 'TEAM999@#') return res.status(403).json({ error: 'invalid admin code' });
  if (db.users[username]) return res.status(400).json({ error: 'user exists' });
  const { salt, hash } = hashPassword(password);
  db.users[username] = { salt, hash, isAdmin: true };
  saveDB();
  res.json({ ok: true });
});

// Admin login
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing' });
  const user = db.users[username];
  if (!user) return res.status(401).json({ error: 'invalid' });
  if (!verifyPassword(password, user.salt, user.hash)) return res.status(401).json({ error: 'invalid' });
  const token = crypto.randomBytes(24).toString('hex');
  db.tokens[token] = { username, isAdmin: !!user.isAdmin };
  saveDB();
  res.json({ token });
});

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const parts = h.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'no auth' });
  const token = parts[1];
  const info = db.tokens[token];
  if (!info) return res.status(401).json({ error: 'invalid token' });
  req.user = info;
  next();
}

// Set override state (on/off/clear)
app.post('/admin/override', auth, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  const { state, players, maxplayers } = req.body || {};
  if (state === 'on') {
    db.override = { state: 'on', players: Number(players) || 0, maxplayers: Number(maxplayers) || 0 };
    saveDB();
    return res.json({ ok: true, override: db.override });
  }
  if (state === 'off') {
    db.override = { state: 'off' };
    saveDB();
    return res.json({ ok: true, override: db.override });
  }
  if (state === 'clear' || state == null) {
    db.override = null;
    saveDB();
    return res.json({ ok: true, override: db.override });
  }
  res.status(400).json({ error: 'invalid state' });
});

app.get('/admin/status', auth, (req, res) => {
  if (!req.user.isAdmin) return res.status(403).json({ error: 'admin only' });
  res.json({ override: db.override || null });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`SAMP proxy running on http://localhost:${PORT}`));
