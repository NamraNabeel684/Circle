require('dotenv').config();
const express = require('express'), http = require('http'), path = require('path'), fs = require('fs');
const mysql = require('mysql2/promise'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), multer = require('multer');
const { WebSocketServer } = require('ws');

const SECRET = process.env.JWT_SECRET || 'change-me';
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost', user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '', database: process.env.DB_NAME || 'social_network',
  waitForConnections: true, connectionLimit: 10, dateStrings: false
});

fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
const upload = multer({
  storage: multer.diskStorage({
    destination: path.join(__dirname, 'uploads'),
    filename: (req, f, cb) => cb(null, Date.now() + '-' + Math.round(Math.random() * 1e6) + path.extname(f.originalname).toLowerCase())
  }),
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (req, f, cb) => cb(null, /^(image|video)\//.test(f.mimetype))
});

const app = express();
const server = http.createServer(app);
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- WebSockets (real-time) ----------
const clients = new Map(); // userId -> Set<ws>
const wss = new WebSocketServer({ server });
wss.on('connection', (ws, req) => {
  try {
    const token = new URL(req.url, 'http://x').searchParams.get('token');
    const { id } = jwt.verify(token, SECRET);
    if (!clients.has(id)) clients.set(id, new Set());
    clients.get(id).add(ws);
    ws.on('close', () => { clients.get(id)?.delete(ws); if (!clients.get(id)?.size) clients.delete(id); });
  } catch { ws.close(); }
});
const sendTo = (uid, msg) => clients.get(uid)?.forEach(ws => ws.readyState === 1 && ws.send(JSON.stringify(msg)));
const broadcast = msg => clients.forEach((_, uid) => sendTo(uid, msg));

async function notify(userId, actorId, type, postId = null) {
  if (userId === actorId) return;
  await db.query('INSERT INTO notifications (user_id, actor_id, type, post_id) VALUES (?,?,?,?)', [userId, actorId, type, postId]);
  sendTo(userId, { type: 'notification' });
}
async function counts(postId) {
  const [[r]] = await db.query(
    'SELECT (SELECT COUNT(*) FROM likes WHERE post_id=?) likes, (SELECT COUNT(*) FROM comments WHERE post_id=?) comments', [postId, postId]);
  return r;
}

// ---------- helpers ----------
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });
const auth = (req, res, next) => {
  try { req.user = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET); next(); }
  catch { res.status(401).json({ error: 'Please log in' }); }
};
const sign = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: '7d' });
const publicUser = u => ({ id: u.id, username: u.username, email: u.email, bio: u.bio, avatar: u.avatar, is_private: !!u.is_private });

async function relation(me, other) {
  const [r] = await db.query(
    'SELECT * FROM friendships WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)', [me, other, other, me]);
  if (!r[0]) return 'none';
  if (r[0].status === 'accepted') return 'friends';
  return r[0].requester_id === me ? 'sent' : 'received';
}

// Posts a viewer may see: own, from public profiles, or from friends
const POST_SQL = `
  SELECT p.*, u.username, u.avatar,
    (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) likes,
    (SELECT COUNT(*) FROM comments c WHERE c.post_id=p.id) comments,
    EXISTS(SELECT 1 FROM likes l WHERE l.post_id=p.id AND l.user_id=?) liked
  FROM posts p JOIN users u ON u.id=p.user_id
  WHERE (p.user_id=? OR u.is_private=0 OR EXISTS(
    SELECT 1 FROM friendships f WHERE f.status='accepted' AND
    ((f.requester_id=? AND f.addressee_id=p.user_id) OR (f.addressee_id=? AND f.requester_id=p.user_id))))`;
const fixPost = p => ({ ...p, liked: !!p.liked });

// ---------- auth ----------
app.post('/api/register', wrap(async (req, res) => {
  const { username, email, password } = req.body;
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username || '')) return res.status(400).json({ error: 'Username must be 3-20 letters, numbers or underscores' });
  if (!/^\S+@\S+\.\S+$/.test(email || '')) return res.status(400).json({ error: 'Enter a valid email' });
  if ((password || '').length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(password, 10);
    const [r] = await db.query('INSERT INTO users (username, email, password_hash) VALUES (?,?,?)', [username, email, hash]);
    const [[u]] = await db.query('SELECT * FROM users WHERE id=?', [r.insertId]);
    res.json({ token: sign(u), user: publicUser(u) });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Username or email is already taken' });
    throw e;
  }
}));

app.post('/api/login', wrap(async (req, res) => {
  const { username, password } = req.body;
  const [[u]] = await db.query('SELECT * FROM users WHERE username=? OR email=?', [username, username]);
  if (!u || !(await bcrypt.compare(password || '', u.password_hash))) return res.status(401).json({ error: 'Wrong username or password' });
  res.json({ token: sign(u), user: publicUser(u) });
}));

app.get('/api/me', auth, wrap(async (req, res) => {
  const [[u]] = await db.query('SELECT * FROM users WHERE id=?', [req.user.id]);
  if (!u) return res.status(401).json({ error: 'Please log in' });
  const [[n]] = await db.query('SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0', [u.id]);
  res.json({ ...publicUser(u), unread: n.c });
}));

// profile + privacy settings (bio, private toggle, avatar)
app.put('/api/me', auth, upload.single('avatar'), wrap(async (req, res) => {
  const bio = (req.body.bio || '').slice(0, 300);
  const priv = req.body.is_private === 'true' || req.body.is_private === '1' ? 1 : 0;
  if (req.file) await db.query('UPDATE users SET avatar=? WHERE id=?', ['/uploads/' + req.file.filename, req.user.id]);
  await db.query('UPDATE users SET bio=?, is_private=? WHERE id=?', [bio, priv, req.user.id]);
  const [[u]] = await db.query('SELECT * FROM users WHERE id=?', [req.user.id]);
  res.json(publicUser(u));
}));

// ---------- users & profiles ----------
app.get('/api/users', auth, wrap(async (req, res) => {
  const [rows] = await db.query('SELECT id, username, avatar, bio FROM users WHERE username LIKE ? AND id<>? ORDER BY username LIMIT 20',
    ['%' + (req.query.q || '') + '%', req.user.id]);
  for (const u of rows) u.relation = await relation(req.user.id, u.id);
  res.json(rows);
}));

app.get('/api/users/:id', auth, wrap(async (req, res) => {
  const id = +req.params.id, me = req.user.id;
  const [[u]] = await db.query('SELECT id, username, avatar, bio, is_private, created_at FROM users WHERE id=?', [id]);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const rel = id === me ? 'self' : await relation(me, id);
  const locked = !!u.is_private && rel !== 'friends' && rel !== 'self';
  let posts = [];
  if (!locked) [posts] = await db.query(POST_SQL + ' AND p.user_id=? ORDER BY p.created_at DESC LIMIT 50', [me, me, me, me, id]);
  res.json({ user: { ...u, is_private: !!u.is_private }, relation: rel, locked, posts: posts.map(fixPost) });
}));

// ---------- posts ----------
app.get('/api/feed', auth, wrap(async (req, res) => {
  const me = req.user.id;
  const [rows] = await db.query(POST_SQL + ' ORDER BY p.created_at DESC LIMIT 50', [me, me, me, me]);
  res.json(rows.map(fixPost));
}));

app.post('/api/posts', auth, upload.single('media'), wrap(async (req, res) => {
  const content = (req.body.content || '').trim().slice(0, 2000);
  if (!content && !req.file) return res.status(400).json({ error: 'Write something or attach a photo or video' });
  const media = req.file ? '/uploads/' + req.file.filename : null;
  const type = req.file ? (req.file.mimetype.startsWith('video') ? 'video' : 'image') : null;
  const [r] = await db.query('INSERT INTO posts (user_id, content, media, media_type) VALUES (?,?,?,?)', [req.user.id, content, media, type]);
  broadcast({ type: 'new_post', userId: req.user.id });
  res.json({ id: r.insertId });
}));

app.delete('/api/posts/:id', auth, wrap(async (req, res) => {
  await db.query('DELETE FROM posts WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
  broadcast({ type: 'post_deleted', postId: +req.params.id });
  res.json({ ok: true });
}));

app.post('/api/posts/:id/like', auth, wrap(async (req, res) => {
  const pid = +req.params.id, me = req.user.id;
  const [[post]] = await db.query('SELECT user_id FROM posts WHERE id=?', [pid]);
  if (!post) return res.status(404).json({ error: 'Post not found' });
  const [del] = await db.query('DELETE FROM likes WHERE user_id=? AND post_id=?', [me, pid]);
  let liked = false;
  if (!del.affectedRows) { await db.query('INSERT INTO likes (user_id, post_id) VALUES (?,?)', [me, pid]); liked = true; await notify(post.user_id, me, 'like', pid); }
  const c = await counts(pid);
  broadcast({ type: 'post_update', postId: pid, ...c });
  res.json({ liked, ...c });
}));

app.get('/api/posts/:id/comments', auth, wrap(async (req, res) => {
  const [rows] = await db.query(
    'SELECT c.id, c.content, c.created_at, c.user_id, u.username, u.avatar FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.created_at', [req.params.id]);
  res.json(rows);
}));

app.post('/api/posts/:id/comments', auth, wrap(async (req, res) => {
  const pid = +req.params.id, content = (req.body.content || '').trim().slice(0, 500);
  if (!content) return res.status(400).json({ error: 'Comment cannot be empty' });
  const [[post]] = await db.query('SELECT user_id FROM posts WHERE id=?', [pid]);
  if (!post) return res.status(404).json({ error: 'Post not found' });
  await db.query('INSERT INTO comments (post_id, user_id, content) VALUES (?,?,?)', [pid, req.user.id, content]);
  await notify(post.user_id, req.user.id, 'comment', pid);
  broadcast({ type: 'post_update', postId: pid, ...(await counts(pid)), commentAdded: true });
  res.json({ ok: true });
}));

// ---------- friends ----------
app.post('/api/friends/request/:id', auth, wrap(async (req, res) => {
  const to = +req.params.id, me = req.user.id;
  if (to === me) return res.status(400).json({ error: "You can't add yourself" });
  if ((await relation(me, to)) !== 'none') return res.status(400).json({ error: 'Request already exists' });
  await db.query('INSERT INTO friendships (requester_id, addressee_id) VALUES (?,?)', [me, to]);
  await notify(to, me, 'friend_request');
  res.json({ ok: true });
}));

app.post('/api/friends/respond/:id', auth, wrap(async (req, res) => {
  const from = +req.params.id, me = req.user.id;
  if (req.body.accept) {
    const [r] = await db.query("UPDATE friendships SET status='accepted' WHERE requester_id=? AND addressee_id=? AND status='pending'", [from, me]);
    if (r.affectedRows) await notify(from, me, 'friend_accept');
  } else await db.query("DELETE FROM friendships WHERE requester_id=? AND addressee_id=? AND status='pending'", [from, me]);
  res.json({ ok: true });
}));

app.delete('/api/friends/:id', auth, wrap(async (req, res) => {
  const o = +req.params.id, me = req.user.id;
  await db.query('DELETE FROM friendships WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)', [me, o, o, me]);
  res.json({ ok: true });
}));

app.get('/api/friends', auth, wrap(async (req, res) => {
  const me = req.user.id;
  const [friends] = await db.query(
    `SELECT u.id, u.username, u.avatar FROM friendships f JOIN users u ON u.id = IF(f.requester_id=?, f.addressee_id, f.requester_id)
     WHERE f.status='accepted' AND (f.requester_id=? OR f.addressee_id=?)`, [me, me, me]);
  const [requests] = await db.query(
    "SELECT u.id, u.username, u.avatar FROM friendships f JOIN users u ON u.id=f.requester_id WHERE f.addressee_id=? AND f.status='pending'", [me]);
  res.json({ friends, requests });
}));

// ---------- notifications ----------
app.get('/api/notifications', auth, wrap(async (req, res) => {
  const [rows] = await db.query(
    `SELECT n.id, n.type, n.post_id, n.is_read, n.created_at, n.actor_id, u.username, u.avatar
     FROM notifications n JOIN users u ON u.id=n.actor_id WHERE n.user_id=? ORDER BY n.created_at DESC LIMIT 50`, [req.user.id]);
  res.json(rows);
}));
app.post('/api/notifications/read', auth, wrap(async (req, res) => {
  await db.query('UPDATE notifications SET is_read=1 WHERE user_id=?', [req.user.id]);
  res.json({ ok: true });
}));

server.listen(process.env.PORT || 3000, () => console.log('Running on http://localhost:' + (process.env.PORT || 3000)));
