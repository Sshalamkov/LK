import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp } from '../server.js';

test('registration, login, persistent sessions, logout and request protection', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'lk-test-'));
  const database = join(dir, 'test.sqlite');
  let server;
  let base;
  async function start() { server = createApp({ database }); server.listen(0, '127.0.0.1'); await once(server, 'listening'); base = `http://127.0.0.1:${server.address().port}`; }
  async function stop() { await new Promise(resolve => server.close(resolve)); }
  const post = (route, body, headers = {}) => fetch(base + route, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
  const credentials = { email: ' User@Example.com ', password: 'a-long-secret-password' };
  try {
    await start();
    assert.equal((await fetch(base)).status, 200);
    assert.equal((await fetch(base + '/api/me')).status, 401);
    assert.equal((await post('/api/register', { email: 'bad', password: 'short' })).status, 400);
    assert.equal((await post('/api/register', credentials, { Origin: 'https://evil.example' })).status, 403);
    assert.equal((await post('/api/register', credentials)).status, 201);
    assert.equal((await post('/api/register', credentials)).status, 409);
    assert.equal((await post('/api/login', { ...credentials, password: 'incorrect-password' })).status, 401);
    const login = await post('/api/login', credentials);
    assert.equal(login.status, 200);
    const cookie = login.headers.get('set-cookie');
    assert.match(cookie, /HttpOnly/); assert.match(cookie, /SameSite=Lax/);
    const headers = { Cookie: cookie.split(';')[0] };
    assert.equal((await (await fetch(base + '/api/me', { headers })).json()).user.email, 'user@example.com');
    await stop(); await start();
    assert.equal((await fetch(base + '/api/me', { headers })).status, 200);
    assert.equal((await post('/api/logout', {}, headers)).status, 200);
    assert.equal((await fetch(base + '/api/me', { headers })).status, 401);
    assert.equal((await post('/api/login', null)).status, 400);
    const malformed = await fetch(base + '/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{' });
    assert.equal(malformed.status, 400);
    let last;
    for (let i = 0; i < 21; i++) last = await post('/api/login', {});
    assert.equal(last.status, 429);
  } finally { if (server?.listening) await stop(); rmSync(dir, { recursive: true, force: true }); }
});
