import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { randomBytes, scrypt as derive, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const scrypt = promisify(derive);
const hashToken = value => createHash('sha256').update(value).digest('hex');
const lifetime = 7 * 24 * 60 * 60;
export function createApp({ database = 'data/lk.sqlite', secure = process.env.NODE_ENV === 'production' } = {}) {
  if (database !== ':memory:') mkdirSync(dirname(database), { recursive: true });
  const db = new DatabaseSync(database);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);`);
  const page = readFileSync(new URL('./public/index.html', import.meta.url));
  const attempts = new Map();
  const server = http.createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    const json = (status, body) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(body)); };
    const cookie = (value, age) => res.setHeader('Set-Cookie', `session=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${secure ? '; Secure' : ''}`);
    const token = /(?:^|;\s*)session=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie || '')?.[1];
    const session = token && db.prepare('SELECT users.id, users.email, users.created_at FROM sessions JOIN users ON users.id=sessions.user_id WHERE token=? AND expires>?').get(hashToken(token), Date.now());
    try {
      if (req.method === 'GET' && req.url === '/') { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(page); }
      if (req.method === 'GET' && req.url === '/api/me') return json(session ? 200 : 401, session ? { user: session } : { error: 'Требуется вход' });
      if (req.method !== 'POST' || !['/api/register', '/api/login', '/api/logout'].includes(req.url)) return json(404, { error: 'Не найдено' });
      // Browsers must submit JSON from this origin; cross-site form submissions are rejected.
      if (req.headers.origin && req.headers.origin !== `${secure ? 'https' : 'http'}://${req.headers.host}`) return json(403, { error: 'Недопустимый источник запроса' });
      if (req.headers['content-type']?.split(';')[0] !== 'application/json') return json(415, { error: 'Ожидается JSON' });
      if (req.url === '/api/logout') {
        if (token) db.prepare('DELETE FROM sessions WHERE token=?').run(hashToken(token));
        cookie('', 0); return json(200, { ok: true });
      }
      const now = Date.now();
      for (const [key, value] of attempts) if (value.until < now) attempts.delete(key);
      const key = req.socket.remoteAddress;
      const limit = attempts.get(key) || { count: 0, until: now + 60000 };
      attempts.set(key, limit);
      if (++limit.count > 20) return json(429, { error: 'Слишком много попыток. Повторите через минуту.' });
      let raw = '';
      for await (const chunk of req) { raw += chunk; if (Buffer.byteLength(raw) > 8192) return json(413, { error: 'Слишком большой запрос' }); }
      let body;
      try { body = JSON.parse(raw); } catch { return json(400, { error: 'Некорректный JSON' }); }
      const email = typeof body?.email === 'string' ? body.email.trim().toLowerCase() : '';
      const password = typeof body?.password === 'string' ? body.password : '';
      if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 12 || password.length > 128) return json(400, { error: 'Укажите корректный e-mail и пароль от 12 до 128 символов.' });
      if (req.url === '/api/register') {
        const salt = randomBytes(16).toString('hex');
        const digest = (await scrypt(password, salt, 64)).toString('hex');
        try { db.prepare('INSERT INTO users(email,password) VALUES (?,?)').run(email, `${salt}:${digest}`); }
        catch (error) { if (error.code?.startsWith('ERR_SQLITE') && db.prepare('SELECT id FROM users WHERE email=?').get(email)) return json(409, { error: 'Этот e-mail уже зарегистрирован.' }); throw error; }
        return json(201, { ok: true });
      }
      const user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
      const [salt, stored] = user ? user.password.split(':') : ['00000000000000000000000000000000', '00'.repeat(64)];
      const digest = await scrypt(password, salt, 64);
      if (!timingSafeEqual(digest, Buffer.from(stored, 'hex')) || !user) return json(401, { error: 'Неверный e-mail или пароль.' });
      db.prepare('DELETE FROM sessions WHERE expires<=?').run(Date.now());
      if (token) db.prepare('DELETE FROM sessions WHERE token=?').run(hashToken(token));
      const next = randomBytes(32).toString('hex');
      db.prepare('INSERT INTO sessions VALUES (?,?,?)').run(hashToken(next), user.id, Date.now() + lifetime * 1000);
      cookie(next, lifetime); return json(200, { user: { id: user.id, email: user.email, created_at: user.created_at } });
    } catch (error) { console.error(error.message); if (!res.headersSent) json(500, { error: 'Внутренняя ошибка сервера' }); else res.end(); }
  });
  server.on('close', () => db.close());
  return server;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 3000);
  createApp({ database: process.env.DATABASE_PATH || 'data/lk.sqlite' }).listen(port, process.env.HOST || '127.0.0.1', () => console.log(`LK listening on port ${port}`));
}
