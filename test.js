'use strict';
// Run: npm test      (BIG=1 npm test  adds a 2 GB memory/stress test)
const { test, before, after } = require('node:test');
const { spawnSync } = require('node:child_process');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const CH = 8 * 2 ** 20;
const KEY = 'correct horse battery staple';
const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

function startServer(extraEnv = {}) {
  return new Promise((resolve, reject) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-test-'));
    const port = 20000 + Math.floor(Math.random() * 20000);
    const p = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', path.join(__dirname, 'server.js')],
      { env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dir, TRUST_PROXY: '1', MASTER_SECRET: 'test-master-secret-1234567890abc', ...extraEnv } });
    let out = '';
    p.stdout.on('data', (d) => { out += d; const m = /SETUP CODE: (\w+)/.exec(out); if (/listening/.test(out)) resolve({ p, dir: extraEnv.DATA_DIR || dir, port, base: `http://127.0.0.1:${port}`, code: m && m[1] }); });
    p.stderr.on('data', (d) => { if (/Fatal|Error/.test(String(d))) reject(new Error(String(d))); });
    setTimeout(() => reject(new Error('server did not start')), 8000);
  });
}
function client(srv, ip = '10.0.0.1') {
  const jar = { cookie: '' };
  const call = async (method, url, body, headers = {}) => {
    const h = { 'x-vault': '1', 'x-forwarded-for': ip, ...headers };
    if (jar.cookie) h.cookie = jar.cookie;
    let payload = body;
    if (body !== undefined && !Buffer.isBuffer(body)) { payload = JSON.stringify(body); h['content-type'] = 'application/json'; }
    const r = await fetch(srv.base + url, { method, headers: h, body: payload });
    const sc = r.headers.get('set-cookie'); if (sc) jar.cookie = sc.split(';')[0].endsWith('=') ? '' : sc.split(';')[0];
    const buf = Buffer.from(await r.arrayBuffer());
    let json = null; try { json = JSON.parse(buf.toString()); } catch {}
    return { status: r.status, json, buf, headers: r.headers };
  };
  return { call, jar };
}
async function uploadFile(c, name, data, { folder = null, order, fingerprint, chunkHash = true } = {}) {
  const { json: up, status } = await c.call('POST', '/api/uploads', { name, size: data.length, folder, fingerprint });
  assert.equal(status, 200, JSON.stringify(up));
  const total = up.total, idxs = order || [...Array(total).keys()];
  await Promise.all(idxs.map(async (n) => {
    const part = data.subarray(n * CH, Math.min(data.length, (n + 1) * CH));
    const r = await c.call('PUT', `/api/uploads/${up.id}/chunks/${n}`, part, chunkHash ? { 'x-chunk-sha256': sha(part) } : {});
    assert.equal(r.status, 200, JSON.stringify(r.json));
  }));
  return up;
}

let S, C; // server, authed client
before(async () => {
  S = await startServer();
  C = client(S, '10.0.0.1');
});
after(() => { S.p.kill(); fs.rmSync(S.dir, { recursive: true, force: true }); });

test('fresh vault: nothing leaks, API is locked, setup needs the console code', async () => {
  const anon = client(S, '10.0.0.2');
  let r = await anon.call('GET', '/api/state'); assert.deepEqual([r.json.setup, r.json.authed], [false, false]);
  for (const u of ['/api/list', '/api/stats', '/api/uploads', '/api/audit', '/api/sessions']) assert.equal((await anon.call('GET', u)).status, 401, u);
  r = await anon.call('POST', '/api/setup', { code: 'WRONG', key: KEY }); assert.equal(r.status, 403);
  r = await anon.call('POST', '/api/setup', { code: S.code, key: 'short' }); assert.equal(r.status, 400);
  r = await anon.call('POST', '/api/setup', { code: S.code, key: 'aaaaaaaaaaaaaaaa' }); assert.equal(r.status, 400, 'repetitive key rejected');
  r = await C.call('POST', '/api/setup', { code: S.code, key: KEY }); assert.equal(r.status, 200);
  assert.match(r.headers.get('set-cookie'), /HttpOnly.*SameSite=Strict/);
  r = await anon.call('POST', '/api/setup', { code: S.code, key: KEY }); assert.equal(r.status, 409, 'setup only works once');
  assert.equal((await C.call('GET', '/api/state')).json.authed, true);
});

test('login: wrong key, lockout with Retry-After, right key still blocked while locked, other IPs unaffected', async () => {
  const a = client(S, '10.9.9.9');
  for (let i = 0; i < 5; i++) assert.equal((await a.call('POST', '/api/login', { key: 'wrong key wrong' + i })).status, 401);
  const locked = await a.call('POST', '/api/login', { key: KEY });
  assert.equal(locked.status, 429); assert.ok(+locked.headers.get('retry-after') > 0);
  assert.equal((await client(S, '10.9.9.10').call('POST', '/api/login', { key: KEY })).status, 200);
});

test('security headers + CSRF + static', async () => {
  const r = await fetch(S.base + '/'); const h = r.headers;
  assert.equal(h.get('x-content-type-options'), 'nosniff'); assert.equal(h.get('x-frame-options'), 'DENY');
  assert.match(h.get('content-security-policy'), /default-src 'none'/); assert.doesNotMatch(h.get('content-security-policy'), /script-src[^;]*unsafe-inline/);
  assert.equal(h.get('referrer-policy'), 'no-referrer');
  assert.equal((await fetch(S.base + '/..%2fserver.js')).status, 404);
  assert.equal((await fetch(S.base + '/server.js')).status, 404, 'source is not served');
  let x = await fetch(S.base + '/api/folders', { method: 'POST', headers: { cookie: C.jar.cookie, 'content-type': 'application/json' }, body: '{"name":"x"}' });
  assert.equal(x.status, 403, 'no custom header → blocked');
  x = await fetch(S.base + '/api/folders', { method: 'POST', headers: { cookie: C.jar.cookie, 'x-vault': '1', origin: 'https://evil.example', 'content-type': 'application/json' }, body: '{"name":"x"}' });
  assert.equal(x.status, 403, 'foreign origin → blocked');
});

test('upload 3 chunks out of order + parallel, verify, download, ranges', async () => {
  const data = crypto.randomBytes(2 * CH + 123457);
  const up = await uploadFile(C, 'My Photo ü.bin', data, { order: [2, 0, 1] });
  let r = await C.call('GET', `/api/uploads/${up.id}`); assert.deepEqual(r.json.received, [0, 1, 2]);
  r = await C.call('POST', `/api/uploads/${up.id}/complete`, { sha256: sha(data) }); assert.equal(r.status, 200, JSON.stringify(r.json));
  const f = r.json.file; assert.equal(f.size, data.length); assert.equal(f.sha256, sha(data)); assert.equal(f.ext, 'bin');
  // stored encrypted, under a random uuid, plaintext never on disk
  const stored = fs.readFileSync(path.join(S.dir, 'files', f.id));
  assert.equal(stored.length, Math.floor(data.length / 1048576) * (1048576 + 28) + (data.length % 1048576) + 28);
  assert.equal(stored.indexOf(data.subarray(1000, 1064)), -1, 'plaintext must not appear on disk');
  assert.equal(fs.readdirSync(path.join(S.dir, 'files')).includes('My Photo ü.bin'), false);
  // full download
  r = await C.call('GET', `/api/files/${f.id}/download`); assert.equal(r.status, 200); assert.equal(sha(r.buf), sha(data));
  assert.match(r.headers.get('content-disposition'), /^attachment; filename=/);
  // ranges
  const rng = async (h) => C.call('GET', `/api/files/${f.id}/download`, undefined, { range: h });
  r = await rng('bytes=0-9'); assert.equal(r.status, 206); assert.ok(r.buf.equals(data.subarray(0, 10)));
  r = await rng('bytes=1048570-1048590'); assert.ok(r.buf.equals(data.subarray(1048570, 1048591)), 'across segment boundary');
  r = await rng(`bytes=${CH - 5}-${CH + 5}`); assert.ok(r.buf.equals(data.subarray(CH - 5, CH + 6)), 'across chunk boundary');
  r = await rng('bytes=-100'); assert.ok(r.buf.equals(data.subarray(data.length - 100)), 'suffix range');
  r = await rng(`bytes=${data.length - 3}-`); assert.ok(r.buf.equals(data.subarray(data.length - 3)), 'open-ended');
  assert.equal((await rng(`bytes=${data.length}-`)).status, 416);
  assert.equal((await rng('bytes=5-2')).status, 416);
  // download counter + listing shows metadata
  r = await C.call('GET', '/api/list'); const row = r.json.files.find((x) => x.id === f.id);
  assert.equal(row.name, 'My Photo ü.bin'); assert.ok(row.downloads >= 1); assert.ok(row.created > 0);
});

test('resume: fingerprint returns same upload, missing parts reported, complete refused until done', async () => {
  const data = crypto.randomBytes(CH + 5000), fp = 'resume.bin|' + data.length + '|123';
  const up = await uploadFile(C, 'resume.bin', data, { order: [0], fingerprint: fp });
  let r = await C.call('POST', '/api/uploads', { name: 'resume.bin', size: data.length, fingerprint: fp });
  assert.equal(r.json.id, up.id); assert.equal(r.json.resumed, true); assert.deepEqual(r.json.received, [0]);
  r = await C.call('POST', `/api/uploads/${up.id}/complete`, {}); assert.equal(r.status, 409); assert.deepEqual(r.json.missing, [1]);
  r = await C.call('PUT', `/api/uploads/${up.id}/chunks/1`, data.subarray(CH)); assert.equal(r.status, 200);
  r = await C.call('PUT', `/api/uploads/${up.id}/chunks/1`, data.subarray(CH)); assert.equal(r.status, 200, 'retrying a chunk is harmless');
  r = await C.call('POST', `/api/uploads/${up.id}/complete`, {}); assert.equal(r.status, 200);
  assert.equal(sha((await C.call('GET', `/api/files/${r.json.file.id}/download`)).buf), sha(data));
});

test('resume still works if the file is re-picked from a different folder (folder follows latest choice)', async () => {
  const data = crypto.randomBytes(CH + 10), fp = 'moved.bin|' + data.length + '|99';
  const f1 = (await C.call('POST', '/api/folders', { name: 'ResumeA' })).json.id;
  const up = await uploadFile(C, 'moved.bin', data, { order: [0], folder: f1, fingerprint: fp });
  const again = (await C.call('POST', '/api/uploads', { name: 'moved.bin', size: data.length, folder: null, fingerprint: fp })).json;
  assert.equal(again.id, up.id); assert.equal(again.resumed, true); assert.deepEqual(again.received, [0]); assert.equal(again.folder_id, null);
  await C.call('PUT', `/api/uploads/${up.id}/chunks/1`, data.subarray(CH));
  const f = (await C.call('POST', `/api/uploads/${up.id}/complete`, {})).json.file; assert.equal(f.folder_id, null, 'lands in the newly chosen folder');
  assert.equal((await C.call('GET', '/api/uploads')).json.uploads.filter((u) => u.id === up.id).length, 0, 'no orphan left behind');
});

test('upload validation: bad size/chunk length/corrupt chunk/checksum mismatch/cancel', async () => {
  let r = await C.call('POST', '/api/uploads', { name: 'a', size: -1 }); assert.equal(r.status, 400);
  r = await C.call('POST', '/api/uploads', { name: 'a', size: 1.5 }); assert.equal(r.status, 400);
  r = await C.call('POST', '/api/uploads', { name: '', size: 5 }); assert.equal(r.status, 400);
  r = await C.call('POST', '/api/uploads', { name: 'a', size: 2 ** 50 }); assert.equal(r.status, 413);
  const up = (await C.call('POST', '/api/uploads', { name: 'v.bin', size: 100 })).json;
  r = await C.call('PUT', `/api/uploads/${up.id}/chunks/0`, Buffer.alloc(99)); assert.equal(r.status, 400);
  r = await C.call('PUT', `/api/uploads/${up.id}/chunks/1`, Buffer.alloc(100)); assert.equal(r.status, 400);
  r = await C.call('PUT', `/api/uploads/${up.id}/chunks/0`, Buffer.alloc(100, 7), { 'x-chunk-sha256': 'deadbeef' }); assert.equal(r.status, 422);
  r = await C.call('PUT', `/api/uploads/${up.id}/chunks/0`, Buffer.alloc(100, 7)); assert.equal(r.status, 200);
  r = await C.call('POST', `/api/uploads/${up.id}/complete`, { sha256: sha('nope') }); assert.equal(r.status, 422);
  assert.equal((await C.call('GET', `/api/uploads/${up.id}`)).status, 404, 'corrupt upload is discarded');
  const up2 = (await C.call('POST', '/api/uploads', { name: 'c.bin', size: 10 })).json;
  assert.equal((await C.call('DELETE', `/api/uploads/${up2.id}`)).status, 200);
  assert.equal((await C.call('PUT', `/api/uploads/${up2.id}/chunks/0`, Buffer.alloc(10))).status, 404);
  assert.equal(fs.readdirSync(path.join(S.dir, 'uploads')).length, fs.readdirSync(path.join(S.dir, 'uploads')).filter((n) => n.endsWith('.part')).length);
});

test('empty file, tiny file, odd names, path traversal names, duplicates', async () => {
  let up = await uploadFile(C, 'empty.txt', Buffer.alloc(0));
  let r = await C.call('POST', `/api/uploads/${up.id}/complete`, {}); assert.equal(r.status, 200); assert.equal(r.json.file.size, 0);
  r = await C.call('GET', `/api/files/${r.json.file.id}/download`); assert.equal(r.status, 200); assert.equal(r.buf.length, 0);
  const evil = crypto.randomBytes(10);
  up = await uploadFile(C, '../../etc/passwd', evil); r = await C.call('POST', `/api/uploads/${up.id}/complete`, {});
  assert.equal(r.json.file.name, '.._.._etc_passwd'); assert.ok(!fs.existsSync('/etc/passwd.bin'));
  up = await uploadFile(C, 'dup.txt', evil); const a = (await C.call('POST', `/api/uploads/${up.id}/complete`, {})).json.file;
  up = await uploadFile(C, 'dup.txt', evil); const b = (await C.call('POST', `/api/uploads/${up.id}/complete`, {})).json.file;
  assert.equal(a.name, 'dup.txt'); assert.equal(b.name, 'dup (1).txt');
  up = await uploadFile(C, 'dup.txt', evil); r = await C.call('POST', `/api/uploads/${up.id}/complete`, { onDuplicate: 'skip' });
  assert.equal(r.json.duplicate, true);
});

test('folders, rename, move, search/sort/filter, cycle protection, recursive delete removes files from disk', async () => {
  let r = await C.call('POST', '/api/folders', { name: 'Work' }); const work = r.json.id;
  r = await C.call('POST', '/api/folders', { name: 'work' }); assert.equal(r.status, 409, 'case-insensitive duplicate');
  r = await C.call('POST', '/api/folders', { name: 'Sub', parent: work }); const sub = r.json.id;
  assert.equal((await C.call('PATCH', `/api/folders/${work}`, { parent: sub })).status, 400, 'cannot move into own child');
  const d1 = crypto.randomBytes(1000), d2 = crypto.randomBytes(5000);
  let up = await uploadFile(C, 'report.pdf', d1, { folder: sub }); const f1 = (await C.call('POST', `/api/uploads/${up.id}/complete`, {})).json.file;
  up = await uploadFile(C, 'holiday.jpg', d2, { folder: work }); const f2 = (await C.call('POST', `/api/uploads/${up.id}/complete`, {})).json.file;
  r = await C.call('GET', `/api/list?folder=${sub}`); assert.deepEqual(r.json.breadcrumbs.map((x) => x.name), ['Work', 'Sub']); assert.equal(r.json.files.length, 1);
  r = await C.call('GET', '/api/list?q=holi'); assert.equal(r.json.files[0].id, f2.id);
  r = await C.call('GET', '/api/list?q=100%25'); assert.equal(r.json.files.length, 0, '% is escaped, not a wildcard');
  r = await C.call('GET', `/api/list?folder=${work}&type=image`); assert.equal(r.json.files.length, 1);
  r = await C.call('GET', `/api/list?folder=${work}&type=document`); assert.equal(r.json.files.length, 0);
  r = await C.call('GET', '/api/list?sort=size&dir=asc'); const sizes = r.json.files.map((x) => x.size); assert.deepEqual(sizes, [...sizes].sort((p, q) => p - q));
  assert.equal((await C.call('PATCH', `/api/files/${f2.id}`, { name: 'beach.jpg' })).status, 200);
  assert.equal((await C.call('PATCH', `/api/files/${f2.id}`, { folder: sub })).status, 200);
  r = await C.call('GET', `/api/list?folder=${sub}`); assert.deepEqual(r.json.files.map((x) => x.name).sort(), ['beach.jpg', 'report.pdf']);
  assert.equal((await C.call('PATCH', `/api/files/${f2.id}`, { name: 'report.pdf' })).status, 409);
  r = await C.call('POST', '/api/delete', { files: [f1.id] }); assert.equal(r.json.files, 1);
  assert.equal((await C.call('GET', `/api/files/${f1.id}/download`)).status, 404); assert.ok(!fs.existsSync(path.join(S.dir, 'files', f1.id)));
  r = await C.call('POST', '/api/delete', { folders: [work] }); assert.equal(r.json.folders, 2); assert.equal(r.json.files, 1);
  assert.ok(!fs.existsSync(path.join(S.dir, 'files', f2.id)), 'file bytes erased with folder');
  assert.equal((await C.call('GET', `/api/list?folder=${sub}`)).status, 404);
});

test('inline preview: only safe types inline; html/svg forced to download; sandbox CSP', async () => {
  const mk = async (name, body) => { const up = await uploadFile(C, name, Buffer.from(body)); return (await C.call('POST', `/api/uploads/${up.id}/complete`, {})).json.file; };
  const html = await mk('evil.html', '<script>alert(1)</script>'), svg = await mk('x.svg', '<svg onload=alert(1)>'), png = await mk('p.png', 'notreallyapng'), txt = await mk('n.txt', 'hello');
  for (const f of [html, svg]) { const r = await C.call('GET', `/api/files/${f.id}/download?inline=1`); assert.match(r.headers.get('content-disposition'), /^attachment/); assert.equal(r.headers.get('content-type'), 'application/octet-stream'); }
  let r = await C.call('GET', `/api/files/${png.id}/download?inline=1`); assert.match(r.headers.get('content-disposition'), /^inline/); assert.equal(r.headers.get('content-type'), 'image/png'); assert.match(r.headers.get('content-security-policy'), /sandbox/);
  r = await C.call('GET', `/api/files/${txt.id}/download?inline=1`); assert.equal(r.buf.toString(), 'hello'); assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
});

test('tampering with stored bytes is detected (GCM), and segments cannot be swapped', async () => {
  const data = crypto.randomBytes(3 * 1048576 + 10);
  const up = await uploadFile(C, 'tamper.bin', data); const f = (await C.call('POST', `/api/uploads/${up.id}/complete`, {})).json.file;
  const p = path.join(S.dir, 'files', f.id), orig = fs.readFileSync(p);
  const bad = Buffer.from(orig); bad[5000] ^= 1; fs.writeFileSync(p, bad);
  const drain = async () => { let got = 0; try { const r = await fetch(S.base + `/api/files/${f.id}/download`, { headers: { cookie: C.jar.cookie } }); for await (const ch of r.body) got += ch.length; } catch {} return got; };
  assert.ok((await drain()) < data.length, 'download aborts instead of serving tampered data');
  const sw = Buffer.from(orig), seg = 1048576 + 28; orig.copy(sw, 0, seg, 2 * seg); orig.copy(sw, seg, 0, seg); fs.writeFileSync(p, sw);
  assert.ok((await drain()) < data.length, 'swapped segments are rejected');
  fs.writeFileSync(p, orig);
});

test('sessions: logout kills cookie, change-key, logout-all, audit log, no secrets in audit', async () => {
  const k = client(S, '10.5.5.5'); assert.equal((await k.call('POST', '/api/login', { key: KEY })).status, 200);
  assert.equal((await k.call('GET', '/api/list')).status, 200);
  const old = k.jar.cookie; await k.call('POST', '/api/logout'); k.jar.cookie = old;
  assert.equal((await k.call('GET', '/api/list')).status, 401, 'old cookie is dead after logout');
  const r = await C.call('GET', '/api/sessions'); assert.ok(r.json.sessions.some((s) => s.current));
  assert.equal((await C.call('POST', '/api/change-key', { current: 'nope nope nope nope', next: 'a brand new passphrase 99' })).status, 401);
  const other = client(S, '10.6.6.6'); await other.call('POST', '/api/login', { key: KEY });
  assert.equal((await C.call('POST', '/api/change-key', { current: KEY, next: 'a brand new passphrase 99' })).status, 200);
  assert.equal((await other.call('GET', '/api/list')).status, 401, 'other sessions are killed on key change');
  assert.equal((await C.call('GET', '/api/list')).status, 200, 'current session survives');
  assert.equal((await client(S, '10.6.6.7').call('POST', '/api/login', { key: KEY })).status, 401, 'old key is dead');
  assert.equal((await client(S, '10.6.6.8').call('POST', '/api/login', { key: 'a brand new passphrase 99' })).status, 200);
  const au = (await C.call('GET', '/api/audit')).json.events; assert.ok(au.some((e) => e.ev === 'login_fail') && au.some((e) => e.ev === 'upload'));
  assert.ok(!JSON.stringify(au).includes('passphrase') && !JSON.stringify(au).includes(KEY));
  assert.equal((await C.call('POST', '/api/logout-all')).status, 200); assert.equal((await C.call('GET', '/api/list')).status, 401);
});

test('idle timeout expires the session', async () => {
  const s2 = await startServer({ IDLE_MINUTES: '0.01' }); // 600 ms
  try {
    const c = client(s2); assert.equal((await c.call('POST', '/api/setup', { code: s2.code, key: KEY })).status, 200);
    assert.equal((await c.call('GET', '/api/list')).status, 200);
    await new Promise((r) => setTimeout(r, 900)); assert.equal((await c.call('GET', '/api/list')).status, 401);
  } finally { s2.p.kill(); fs.rmSync(s2.dir, { recursive: true, force: true }); }
});

test('data survives a server restart (same MASTER_SECRET)', async () => {
  const s3 = await startServer(); const c = client(s3);
  await c.call('POST', '/api/setup', { code: s3.code, key: KEY });
  const data = crypto.randomBytes(300000); const up = await uploadFile(c, 'persist.bin', data); const f = (await c.call('POST', `/api/uploads/${up.id}/complete`, {})).json.file;
  s3.p.kill(); await new Promise((r) => s3.p.on('exit', r));
  const port = s3.port; const p = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', path.join(__dirname, 'server.js')],
    { env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: s3.dir, TRUST_PROXY: '1', MASTER_SECRET: 'test-master-secret-1234567890abc' } });
  await new Promise((r) => p.stdout.on('data', (d) => /listening/.test(d) && r()));
  try {
    const c2 = client(s3); assert.equal((await c2.call('GET', '/api/state')).json.setup, true);
    assert.equal((await c2.call('POST', '/api/login', { key: KEY })).status, 200);
    assert.equal(sha((await c2.call('GET', `/api/files/${f.id}/download`)).buf), sha(data));
  } finally { p.kill(); fs.rmSync(s3.dir, { recursive: true, force: true }); }
});

test('wrong MASTER_SECRET cannot decrypt', async () => {
  const s4 = await startServer(); const c = client(s4); await c.call('POST', '/api/setup', { code: s4.code, key: KEY });
  const up = await uploadFile(c, 'x.bin', crypto.randomBytes(5000)); const f = (await c.call('POST', `/api/uploads/${up.id}/complete`, {})).json.file;
  s4.p.kill(); await new Promise((r) => s4.p.on('exit', r));
  const p = spawn(process.execPath, ['--disable-warning=ExperimentalWarning', path.join(__dirname, 'server.js')],
    { env: { ...process.env, PORT: String(s4.port), HOST: '127.0.0.1', DATA_DIR: s4.dir, TRUST_PROXY: '1', MASTER_SECRET: 'a-totally-different-secret-value-xyz' } });
  await new Promise((r) => p.stdout.on('data', (d) => /listening/.test(d) && r()));
  try {
    const c2 = client(s4); await c2.call('POST', '/api/login', { key: KEY });
    const r = await fetch(s4.base + `/api/files/${f.id}/download`, { headers: { cookie: c2.jar.cookie } });
    assert.ok(r.status === 500 || r.status === 200 && (await r.arrayBuffer().then(() => false).catch(() => true)), 'cannot read data with the wrong master secret');
  } finally { p.kill(); fs.rmSync(s4.dir, { recursive: true, force: true }); }
});

// ---------- Phase 3 features (each on its own throwaway server) ----------
async function fresh(extra) { const s = await startServer(extra), c = client(s); assert.equal((await c.call('POST', '/api/setup', { code: s.code, key: KEY })).status, 200); return { s, c, stop: () => { s.p.kill(); fs.rmSync(s.dir, { recursive: true, force: true }); } }; }
const b32dec = (str) => { let bits = ''; for (const ch of str) bits += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(ch).toString(2).padStart(5, '0'); const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); };
const totpAt = (secret, counter) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(counter)); const h = crypto.createHmac('sha1', secret).update(b).digest(), o = h[19] & 15; return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0'); };
const finish = async (c, up, extra = {}) => (await c.call('POST', `/api/uploads/${up.id}/complete`, extra)).json.file;

test('two-step login: setup, required at login, wrong/replayed code rejected, backup codes single-use, disable', async () => {
  const { s, c, stop } = await fresh();
  try {
    assert.equal((await c.call('POST', '/api/2fa/start', { key: 'not my key at all' })).status, 401);
    const st = (await c.call('POST', '/api/2fa/start', { key: KEY })).json; const secret = b32dec(st.secret), now = Math.floor(Date.now() / 30000);
    assert.match(st.uri, /^otpauth:\/\/totp\//);
    assert.equal((await c.call('POST', '/api/2fa/enable', { code: '000000' })).status, 400);
    const en = await c.call('POST', '/api/2fa/enable', { code: totpAt(secret, now) }); assert.equal(en.status, 200); assert.equal(en.json.backupCodes.length, 8);
    const other = client(s, '10.1.1.1');
    let r = await other.call('POST', '/api/login', { key: KEY }); assert.equal(r.status, 401); assert.equal(r.json.need2fa, true);
    assert.equal((await other.call('GET', '/api/list')).status, 401, 'right key alone does not open the vault');
    r = await other.call('POST', '/api/login', { key: KEY, code: '123456' }); assert.equal(r.status, 401);
    r = await other.call('POST', '/api/login', { key: KEY, code: totpAt(secret, now) }); assert.equal(r.status, 401, 'the code used at setup cannot be replayed');
    r = await other.call('POST', '/api/login', { key: KEY, code: totpAt(secret, now + 1) }); assert.equal(r.status, 200, JSON.stringify(r.json));
    assert.equal((await other.call('GET', '/api/list')).status, 200);
    r = await other.call('POST', '/api/login', { key: KEY, code: totpAt(secret, now + 1) }); assert.equal(r.status, 401, 'same code twice is refused');
    const bc = en.json.backupCodes; const third = client(s, '10.1.1.2');
    assert.equal((await third.call('POST', '/api/login', { key: KEY, code: bc[0] })).status, 200, 'backup code works');
    assert.equal((await client(s, '10.1.1.3').call('POST', '/api/login', { key: KEY, code: bc[0] })).status, 401, 'backup code works only once');
    assert.equal((await c.call('POST', '/api/2fa/disable', { key: KEY, code: '111111' })).status, 401);
    assert.equal((await c.call('POST', '/api/2fa/disable', { key: KEY, code: bc[1] })).status, 200);
    assert.equal((await client(s, '10.1.1.4').call('POST', '/api/login', { key: KEY })).status, 200, 'after disabling, key alone works');
  } finally { stop(); }
});

test('share links: works without login, download limit, expiry, revoke, file delete kills link, token never stored in clear', async () => {
  const { s, c, stop } = await fresh();
  try {
    const data = crypto.randomBytes(300000), up = await uploadFile(c, 'Gift Photo.jpg', data), f = await finish(c, up);
    assert.equal((await c.call('POST', `/api/files/${f.id}/share`, { hours: 0 })).status, 400);
    assert.equal((await c.call('POST', `/api/files/${f.id}/share`, { hours: 721 })).status, 400);
    const sh = (await c.call('POST', `/api/files/${f.id}/share`, { hours: 2, max: 2 })).json; const token = sh.url.split('/s/')[1];
    assert.ok(token.length >= 40);
    const anon = client(s, '10.2.2.2'); const get = (t = token, h = {}) => anon.call('GET', '/s/' + t, undefined, h);
    let r = await get(); assert.equal(r.status, 200); assert.equal(sha(r.buf), sha(data)); assert.match(r.headers.get('content-disposition'), /^attachment; filename="Gift Photo.jpg"/);
    assert.equal(anon.jar.cookie, '', 'no session needed or created');
    assert.equal((await anon.call('GET', '/api/list')).status, 401, 'a share link opens one file, never the vault');
    r = await get(); assert.equal(r.status, 200);
    assert.equal((await get()).status, 404, 'third download refused (limit 2)');
    assert.equal((await get('A'.repeat(43))).status, 404); assert.equal((await get('../../etc/passwd')).status, 404);
    // never stored in clear
    for (const n of fs.readdirSync(s.dir).filter((x) => x.startsWith('vault.db'))) assert.equal(fs.readFileSync(path.join(s.dir, n)).indexOf(token), -1, n);
    // expiry (rewind the clock inside the DB)
    const sh2 = (await c.call('POST', `/api/files/${f.id}/share`, { hours: 1 })).json, t2 = sh2.url.split('/s/')[1];
    assert.equal((await get(t2)).status, 200);
    const { DatabaseSync } = require('node:sqlite'); const d = new DatabaseSync(path.join(s.dir, 'vault.db')); d.exec(`UPDATE shares SET expires=1 WHERE id='${sh2.id}'`); d.close();
    assert.equal((await get(t2)).status, 404, 'expired link is dead');
    // revoke + list
    const sh3 = (await c.call('POST', `/api/files/${f.id}/share`, {})).json, t3 = sh3.url.split('/s/')[1];
    assert.equal((await c.call('GET', '/api/shares')).json.shares.some((x) => x.id === sh3.id && x.name === 'Gift Photo.jpg'), true);
    assert.equal((await c.call('DELETE', `/api/shares/${sh3.id}`)).status, 200); assert.equal((await get(t3)).status, 404, 'revoked link is dead');
    // deleting the file kills links
    const sh4 = (await c.call('POST', `/api/files/${f.id}/share`, {})).json, t4 = sh4.url.split('/s/')[1]; assert.equal((await get(t4)).status, 200);
    await c.call('POST', '/api/delete', { files: [f.id] }); assert.equal((await get(t4)).status, 404);
    // brute-force guard
    for (let i = 0; i < 31; i++) await get('x'.repeat(30) + i);
    assert.equal((await get('y'.repeat(43))).status, 429);
  } finally { stop(); }
});

test('ZIP: nested folders, empty folder, unicode names, name clashes, valid for standard unzip tools', async () => {
  const { c, stop } = await fresh();
  try {
    const mkf = async (name, parent) => (await c.call('POST', '/api/folders', { name, parent })).json.id;
    const A = await mkf('Trip ✈️'), B = await mkf('sub', A); await mkf('empty', A);
    const files = { top: crypto.randomBytes(3 * 2 ** 20 + 17), a: crypto.randomBytes(1000), b: crypto.randomBytes(70000), z: Buffer.alloc(0), top2: crypto.randomBytes(500) };
    const put = async (name, buf, folder) => finish(c, await uploadFile(c, name, buf, { folder }));
    const ftop = await put('big.bin', files.top, null), fa = await put('é résumé.txt', files.a, A), fb = await put('data.bin', files.b, B), fz = await put('empty.txt', files.z, A);
    const fclash = await put('big.bin', files.top2, A); // different folder, same name as top-level
    const r = await c.call('GET', `/api/zip?files=${ftop.id},${fclash.id}&folders=${A}`); assert.equal(r.status, 200); assert.equal(r.headers.get('content-type'), 'application/zip');
    const zp = path.join(S.dir, 'out.zip'); fs.writeFileSync(zp, r.buf);
    const py = spawnSync('python3', ['-c', 'import zipfile,hashlib,json,sys;z=zipfile.ZipFile(sys.argv[1]);print(json.dumps({"bad":z.testzip(),"names":sorted(z.namelist()),"sha":{n:hashlib.sha256(z.read(n)).hexdigest() for n in z.namelist() if not n.endswith("/")}}))', zp]);
    assert.equal(py.status, 0, String(py.stderr)); const z = JSON.parse(py.stdout);
    assert.equal(z.bad, null, 'every CRC valid');
    assert.deepEqual(z.names, ['Trip ✈️/', 'Trip ✈️/big.bin', 'Trip ✈️/empty.txt', 'Trip ✈️/empty/', 'Trip ✈️/sub/', 'Trip ✈️/sub/data.bin', 'Trip ✈️/é résumé.txt', 'big (1).bin', 'big.bin'].sort());
    assert.equal(z.sha['big.bin'], sha(files.top)); assert.equal(z.sha['big (1).bin'], sha(files.top2)); assert.equal(z.sha['Trip ✈️/sub/data.bin'], sha(files.b));
    assert.equal(z.sha['Trip ✈️/é résumé.txt'], sha(files.a)); assert.equal(z.sha['Trip ✈️/empty.txt'], sha(files.z)); assert.equal(z.sha['Trip ✈️/big.bin'], sha(files.top2));
    const un = spawnSync('unzip', ['-tq', zp]); if (!un.error) assert.equal(un.status, 0, 'Info-ZIP unzip accepts it: ' + un.stdout + un.stderr);
    assert.equal((await c.call('GET', '/api/zip?files=nope')).status, 404);
    assert.equal((await client(S).call('GET', `/api/zip?folders=${A}`)).status, 401, 'needs login');
  } finally { stop(); }
});

test('backup CLI + restore: snapshot restores into a working vault with the same master secret', async () => {
  const { s, c, stop } = await fresh();
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-bk-'));
  try {
    const data = crypto.randomBytes(2 * 2 ** 20 + 5), f = await finish(c, await uploadFile(c, 'precious.bin', data));
    const run = () => spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', path.join(__dirname, 'server.js'), 'backup', dest], { env: { ...process.env, DATA_DIR: s.dir, MASTER_SECRET: 'test-master-secret-1234567890abc' }, encoding: 'utf8' });
    let b = run(); assert.equal(b.status, 0, b.stderr + b.stdout); assert.match(b.stdout, /1 new\/changed file/);
    b = run(); assert.match(b.stdout, /0 new\/changed file/, 'second backup is incremental');
    const s2 = await startServer({ DATA_DIR: dest }); // "restore" = start from the backup folder
    try {
      const c2 = client(s2); assert.equal((await c2.call('POST', '/api/login', { key: KEY })).status, 200);
      assert.equal(sha((await c2.call('GET', `/api/files/${f.id}/download`)).buf), sha(data), 'restored file decrypts correctly');
    } finally { s2.p.kill(); }
  } finally { stop(); fs.rmSync(dest, { recursive: true, force: true }); }
});

test('reset-key CLI: forgotten key can be replaced with server access; files survive', async () => {
  const { s, c, stop } = await fresh();
  try {
    const data = crypto.randomBytes(4000), f = await finish(c, await uploadFile(c, 'keep.bin', data));
    s.p.kill(); await new Promise((r) => s.p.on('exit', r));
    const r = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', path.join(__dirname, 'server.js'), 'reset-key'], { env: { ...process.env, DATA_DIR: s.dir, MASTER_SECRET: 'test-master-secret-1234567890abc' }, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr); assert.match(r.stdout, /removed/);
    const s2 = await startServer({ DATA_DIR: s.dir }); const c2 = client(s2);
    try {
      assert.equal((await c2.call('GET', '/api/state')).json.setup, false); assert.ok(s2.code, 'new setup code printed');
      assert.equal((await c2.call('POST', '/api/setup', { code: s2.code, key: 'a completely new passphrase' })).status, 200);
      assert.equal(sha((await c2.call('GET', `/api/files/${f.id}/download`)).buf), sha(data), 'old files still decrypt');
    } finally { s2.p.kill(); }
  } finally { stop(); }
});

test('BIG: 2 GB upload keeps server memory flat', { skip: !process.env.BIG, timeout: 900000 }, async () => {
  const s5 = await startServer(); const c = client(s5); await c.call('POST', '/api/setup', { code: s5.code, key: KEY });
  const size = 2 * 2 ** 30, buf = crypto.randomBytes(CH), total = Math.ceil(size / CH);
  const up = (await c.call('POST', '/api/uploads', { name: 'big.bin', size })).json; let peak = 0;
  const rss = () => +/VmRSS:\s+(\d+)/.exec(fs.readFileSync(`/proc/${s5.p.pid}/status`, 'utf8'))[1] / 1024;
  let next = 0; const t0 = Date.now();
  await Promise.all([0, 1, 2].map(async () => { while (next < total) { const n = next++; const r = await c.call('PUT', `/api/uploads/${up.id}/chunks/${n}`, buf); assert.equal(r.status, 200); peak = Math.max(peak, rss()); } }));
  const t1 = Date.now(); const r = await c.call('POST', `/api/uploads/${up.id}/complete`, {}); assert.equal(r.status, 200);
  peak = Math.max(peak, rss());
  console.log(`  2 GB uploaded in ${((t1 - t0) / 1000).toFixed(1)}s, verified in ${((Date.now() - t1) / 1000).toFixed(1)}s, peak server RSS ${peak.toFixed(0)} MB`);
  const tail = await c.call('GET', `/api/files/${r.json.file.id}/download`, undefined, { range: `bytes=${size - CH}-` }); assert.ok(tail.buf.equals(buf));
  assert.ok(peak < 450, 'peak RSS ' + peak);
  s5.p.kill(); fs.rmSync(s5.dir, { recursive: true, force: true });
});
