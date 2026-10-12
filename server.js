require('dotenv').config?.();
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');
const Database = require('better-sqlite3');
const { nanoid } = require('nanoid');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// ---------- CONFIG ----------
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme123';
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';

// ---------- APP ----------
const app = express();
app.set('trust proxy', 1);   // ← REQUIRED on Render/Heroku for secure session cookies
const server = http.createServer(app);
const io = new Server(server, {
  cors: IS_PROD ? { origin: false } : { origin: true }
});

app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ---------- SESSIONS ----------
app.use(session({
  name: 'demo.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: IS_PROD,
    maxAge: 1000 * 60 * 60 * 12 // 12 hours
  }
}));

// ---------- DATABASE ----------
const db = new Database('data.db');
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT,
    category TEXT,
    subject TEXT,
    description TEXT,
    attachment TEXT,
    status TEXT DEFAULT 'open',
    created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    name TEXT,
    created_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id TEXT,
    sender TEXT,
    body TEXT,
    created_at INTEGER
  );
`);

// ---------- UPLOADS ----------
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir);
const upload = multer({
  storage: multer.diskStorage({
    destination: uploadsDir,
    filename: (_, file, cb) => {
      const safe = file.originalname.replace(/[^\w.\-]+/g, '_').slice(0, 80);
      cb(null, Date.now() + '-' + safe);
    }
  }),
  limits: { fileSize: 5 * 1024 * 1024 } // 5 MB
});

// ---------- HELPERS ----------
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const clean = (s, max = 500) => String(s || '').trim().slice(0, max);
const requestBuckets = new Map();

function rateLimit({ max = 5, windowMs = 60_000 } = {}) {
  return (req, res, next) => {
    const key = req.ip;
    const now = Date.now();
    const b = requestBuckets.get(key) || { count: 0, reset: now + windowMs };
    if (now > b.reset) { b.count = 0; b.reset = now + windowMs; }
    b.count++;
    requestBuckets.set(key, b);
    if (b.count > max) {
      return res.status(429).json({ error: 'Too many requests. Please slow down.' });
    }
    next();
  };
}

function requireAdmin(req, res, next) {
  if (req.session?.isAdmin) return next();
  const pwd = req.headers['x-admin-password'] || req.body?.password;
  if (pwd && pwd === ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    return next();
  }
  return res.status(401).json({ error: 'unauthorized' });
}

// ---------- STATIC ----------
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadsDir));

// ---------- HEALTH ----------
app.get('/healthz', (_, res) => res.json({ ok: true, ts: Date.now() }));

// ---------- LOGIN ----------
app.post('/api/admin/login', rateLimit({ max: 10, windowMs: 60_000 }), (req, res) => {
  const { password } = req.body || {};
  if (password === ADMIN_PASSWORD) {
    req.session.isAdmin = true;
    return res.json({ ok: true });
  }
  return res.status(401).json({ error: 'Wrong password' });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/admin/me', (req, res) => {
  res.json({ isAdmin: !!req.session?.isAdmin });
});

// ---------- SUBMIT A REQUEST ----------
app.post('/api/requests',
  rateLimit({ max: 5, windowMs: 60_000 }),
  upload.single('attachment'),
  (req, res) => {
    // Honeypot — bots fill every field, humans skip the hidden one
    if (req.body.website) {
      return res.json({ ok: true, ticketId: 'DEMO-00000' }); // pretend success
    }

    const name = clean(req.body.name, 100);
    const email = clean(req.body.email, 200);
    const category = clean(req.body.category, 100);
    const subject = clean(req.body.subject, 200);
    const description = clean(req.body.description, 5000);

    if (!EMAIL_RE.test(email)) return res.status(400).json({ error: 'Please enter a valid email address.' });
    if (subject.length < 3)     return res.status(400).json({ error: 'Subject must be at least 3 characters.' });
    if (description.length < 10)return res.status(400).json({ error: 'Description must be at least 10 characters.' });

    const attachment = req.file ? req.file.filename : null;
    const info = db.prepare(`
      INSERT INTO requests (name, email, category, subject, description, attachment, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(name, email, category, subject, description, attachment, Date.now());

    const ticketId = 'DEMO-' + String(info.lastInsertRowid).padStart(5, '0');
    io.to('admins').emit('admin:new-request', { ticketId, subject, email });
    res.json({ ok: true, ticketId });
  }
);

// ---------- ADMIN: REQUESTS ----------
app.get('/api/admin/requests', requireAdmin, (req, res) => {
  const { q = '', status = 'all' } = req.query;
  let sql = 'SELECT * FROM requests WHERE 1=1';
  const params = [];
  if (status !== 'all') { sql += ' AND status = ?'; params.push(status); }
  if (q) {
    sql += ' AND (subject LIKE ? OR email LIKE ? OR name LIKE ? OR description LIKE ?)';
    const like = `%${q}%`;
    params.push(like, like, like, like);
  }
  sql += ' ORDER BY created_at DESC';
  res.json(db.prepare(sql).all(...params));
});

app.post('/api/admin/requests/:id/status', requireAdmin, (req, res) => {
  const { status } = req.body;
  if (!['open', 'resolved', 'spam'].includes(status)) return res.status(400).json({ error: 'bad status' });
  db.prepare('UPDATE requests SET status = ? WHERE id = ?').run(status, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/requests/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM requests WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/requests/export.csv', requireAdmin, (_, res) => {
  const rows = db.prepare('SELECT * FROM requests ORDER BY created_at DESC').all();
  const cols = ['id', 'name', 'email', 'category', 'subject', 'description', 'status', 'created_at'];
  const esc = v => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const csv = [cols.join(','), ...rows.map(r => cols.map(c => esc(r[c])).join(','))].join('\n');
  res.header('Content-Type', 'text/csv');
  res.attachment('requests.csv');
  res.send(csv);
});

// ---------- CHAT ----------
app.post('/api/chat/start', rateLimit({ max: 10, windowMs: 60_000 }), (req, res) => {
  const { name, conversationId } = req.body || {};
  if (conversationId) {
    const existing = db.prepare('SELECT * FROM conversations WHERE id = ?').get(conversationId);
    if (existing) return res.json(existing);
  }
  const id = nanoid(10);
  db.prepare('INSERT INTO conversations (id, name, created_at) VALUES (?, ?, ?)')
    .run(id, clean(name || 'Guest', 50), Date.now());
  res.json({ id, name: clean(name || 'Guest', 50) });
});

app.get('/api/chat/messages/:conversationId', (req, res) => {
  const rows = db.prepare(
    'SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC'
  ).all(req.params.conversationId);
  res.json(rows);
});

app.get('/api/admin/conversations', requireAdmin, (_, res) => {
  const rows = db.prepare(`
    SELECT c.*,
      (SELECT body FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) as last_message,
      (SELECT created_at FROM messages WHERE conversation_id = c.id ORDER BY created_at DESC LIMIT 1) as last_at
    FROM conversations c
    ORDER BY last_at DESC NULLS LAST, created_at DESC
  `).all();
  res.json(rows);
});

// ---------- SOCKETS ----------
io.on('connection', (socket) => {
  socket.on('join', ({ conversationId, role }) => {
    if (conversationId) socket.join(conversationId);
    if (role === 'admin') socket.join('admins');
  });

  socket.on('typing', ({ conversationId, role }) => {
    if (!conversationId) return;
    socket.to(conversationId).emit('typing', { role });
  });

  socket.on('message', ({ conversationId, sender, body }) => {
    if (!conversationId || !body) return;
    const text = String(body).slice(0, 2000);
    db.prepare(
      'INSERT INTO messages (conversation_id, sender, body, created_at) VALUES (?, ?, ?, ?)'
    ).run(conversationId, sender, text, Date.now());
    const msg = { conversationId, sender, body: text, created_at: Date.now() };
    io.to(conversationId).emit('message', msg);
    io.to('admins').emit('admin:notify', msg);
  });
});

// ---------- SHUTDOWN ----------
process.on('SIGTERM', () => {
  console.log('SIGTERM received, closing...');
  server.close(() => { db.close(); process.exit(0); });
});

server.listen(PORT, () => console.log(`✅ http://localhost:${PORT} | Admin: /admin.html`));