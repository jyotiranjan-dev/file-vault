'use strict';
/**
 * VaultDrop — private encrypted file vault. ONE backend file, ZERO dependencies.
 * Needs Node >= 22.13 (uses built-in node:sqlite, crypto, http).
 *
 * Sections (search for the "=== " markers):
 *   CONFIG · DATABASE · CRYPTO · AUTH · HTTP CORE · ROUTES: auth · files · folders · uploads · download · MAINTENANCE
 */
const http = require('node:http');
const fs = require('node:fs');
const fsp = fs.promises;
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { Readable } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const { DatabaseSync } = require('node:sqlite');

// === CONFIG ================================================================
const env = process.env;
const CFG = {
  port: +env.PORT || 3000,
  host: env.HOST || '0.0.0.0',
  dataDir: path.resolve(env.DATA_DIR || path.join(__dirname, 'data')),
  maxFileSize: +env.MAX_FILE_SIZE || 200 * 2 ** 30, // per file
  quota: +env.STORAGE_QUOTA || 0, // total bytes, 0 = only limited by disk
  chunkSize: 8 * 2 ** 20, // upload chunk (must be a multiple of SEG)
  idleMs: (+env.IDLE_MINUTES || 15) * 60e3, // auto-logout when unused
  absMs: (+env.SESSION_HOURS || 12) * 3600e3, // hard session limit
  trustProxy: env.TRUST_PROXY === '1',
  ipHeader: (env.CLIENT_IP_HEADER || '').toLowerCase(), // optional: name of a header your host sets to the real visitor IP // set to 1 when behind Caddy/nginx
  staleUploadMs: 24 * 3600e3, // abandoned partial uploads are deleted
};
const SEG = 1024 * 1024; // plaintext bytes per encrypted segment
const OVER = 28; // 12-byte nonce + 16-byte GCM tag per segment
const SPC = CFG.chunkSize / SEG; // segments per upload chunk

fs.mkdirSync(path.join(CFG.dataDir, 'files'), { recursive: true, mode: 0o700 });
fs.mkdirSync(path.join(CFG.dataDir, 'uploads'), { recursive: true, mode: 0o700 });
const filePath = (id) => path.join(CFG.dataDir, 'files', id);
const partPath = (id) => path.join(CFG.dataDir, 'uploads', id + '.part');
// Cloud hosts wipe a container's own disk on every restart. Detect "data folder is NOT on a separate mounted disk" inside a container.
const EPHEMERAL = (() => {
  try {
    if (!(fs.existsSync('/.dockerenv') || env.RENDER || env.RAILWAY_PROJECT_ID || env.FLY_APP_NAME || env.KUBERNETES_SERVICE_HOST)) return false;
    let best = '/';
    for (const l of fs.readFileSync('/proc/self/mountinfo', 'utf8').split('\n')) { const mp = l.split(' ')[4]; if (mp && mp.length > best.length && (CFG.dataDir === mp || CFG.dataDir.startsWith(mp.endsWith('/') ? mp : mp + '/'))) best = mp; }
    return best === '/';
  } catch { return false; }
})();

// === DATABASE ==============================================================
const db = new DatabaseSync(path.join(CFG.dataDir, 'vault.db'));
db.exec(`
PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS folders(id TEXT PRIMARY KEY, name TEXT NOT NULL, parent_id TEXT, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, name TEXT NOT NULL, ext TEXT NOT NULL, size INTEGER NOT NULL,
  sha256 TEXT NOT NULL, folder_id TEXT, wrapped_key TEXT NOT NULL, created INTEGER NOT NULL, downloads INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS files_folder ON files(folder_id);
CREATE TABLE IF NOT EXISTS uploads(id TEXT PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL, folder_id TEXT,
  chunk_size INTEGER NOT NULL, wrapped_key TEXT NOT NULL, fingerprint TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS upload_chunks(upload_id TEXT NOT NULL, n INTEGER NOT NULL, PRIMARY KEY(upload_id, n)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, created INTEGER NOT NULL, last_seen INTEGER NOT NULL, ip TEXT, ua TEXT);
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, ev TEXT NOT NULL, ip TEXT, ua TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS shares(id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, file_id TEXT NOT NULL, expires INTEGER NOT NULL, max_downloads INTEGER, downloads INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS share_items(share_id TEXT NOT NULL, file_id TEXT NOT NULL, PRIMARY KEY(share_id, file_id)) WITHOUT ROWID;
INSERT OR IGNORE INTO share_items SELECT id, file_id FROM shares;
`);
try { fs.chmodSync(path.join(CFG.dataDir, 'vault.db'), 0o600); } catch {}
// CLI:  node server.js reset-key   → forgot the vault key? (needs shell access to the server) removes key + 2FA; restart prints a new setup code. Files stay intact.
if (process.argv[2] === 'reset-key') {
  db.exec("DELETE FROM settings WHERE k IN ('key_hash','totp','backup_codes','totp_last'); DELETE FROM sessions;");
  console.log('Vault key and two-step login removed; all sessions ended. Restart the server: it will print a new setup code. Your files are untouched (they stay encrypted with MASTER_SECRET).');
  process.exit(0);
}
// CLI:  node server.js backup <folder>   → consistent DB snapshot + incremental copy of the (immutable) encrypted files
if (process.argv[2] === 'backup') {
  const dest = path.resolve(process.argv[3] || './vault-backup'), src = path.join(CFG.dataDir, 'files');
  fs.mkdirSync(path.join(dest, 'files'), { recursive: true, mode: 0o700 });
  const snap = path.join(dest, 'vault.db'); try { fs.unlinkSync(snap); } catch {}
  db.exec(`VACUUM INTO '${snap.replace(/'/g, "''")}'`);
  let copied = 0;
  for (const n of fs.readdirSync(src)) { const a = path.join(src, n), b = path.join(dest, 'files', n); if (!fs.existsSync(b) || fs.statSync(b).size !== fs.statSync(a).size) { fs.copyFileSync(a, b); copied++; } }
  console.log(`Backup OK → ${dest}  (database snapshot + ${copied} new/changed file(s)). The master key (MASTER_SECRET) is NOT in the backup: keep it somewhere else safe.`);
  process.exit(0);
}
const stmts = new Map();
const Q = (sql) => { let p = stmts.get(sql); if (!p) { p = db.prepare(sql); stmts.set(sql, p); } return p; };
const tx = (fn) => { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };
const getSetting = (k) => Q('SELECT v FROM settings WHERE k=?').get(k)?.v ?? null;
const setSetting = (k, v) => Q('INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v').run(k, v);

// === CRYPTO ================================================================
// Every file gets its own random 256-bit key. That key is wrapped (AES-256-GCM) by the master key (KEK)
// and stored in the DB. File bytes are stored as independent 1 MiB AES-256-GCM segments with random nonces,
// so any byte range can be decrypted without reading the whole file (fast resume + seek).
const KEK = (() => {
  if (env.MASTER_SECRET) {
    if (env.MASTER_SECRET.length < 24) { console.error('MASTER_SECRET must be at least 24 characters.'); process.exit(1); }
    return Buffer.from(crypto.hkdfSync('sha256', env.MASTER_SECRET, 'vaultdrop-salt-v1', 'vaultdrop-kek', 32));
  }
  const kf = path.join(CFG.dataDir, 'kek.key');
  if (!fs.existsSync(kf)) fs.writeFileSync(kf, crypto.randomBytes(32), { mode: 0o600 });
  console.warn('! Using key file ' + kf + ' as master key. For stronger protection set MASTER_SECRET in the environment instead\n  (then a stolen disk/backup alone cannot decrypt anything).');
  return fs.readFileSync(kf);
})();
const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');
const aadIdx = (i) => { const a = Buffer.alloc(8); a.writeBigUInt64BE(BigInt(i)); return a; };
function wrapKey(key, aad) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEK, iv);
  c.setAAD(Buffer.from(aad));
  return Buffer.concat([iv, c.update(key), c.final(), c.getAuthTag()]).toString('base64');
}
function unwrapKey(b64, aad) {
  const b = Buffer.from(b64, 'base64'), d = crypto.createDecipheriv('aes-256-gcm', KEK, b.subarray(0, 12));
  d.setAAD(Buffer.from(aad)); d.setAuthTag(b.subarray(b.length - 16));
  return Buffer.concat([d.update(b.subarray(12, b.length - 16)), d.final()]);
}
function encSeg(key, buf, idx) {
  const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(aadIdx(idx)); // binds the segment to its position: segments can't be swapped/reordered
  return Buffer.concat([iv, c.update(buf), c.final(), c.getAuthTag()]);
}
function decSeg(key, blob, idx) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, blob.subarray(0, 12));
  d.setAAD(aadIdx(idx)); d.setAuthTag(blob.subarray(blob.length - 16));
  return Buffer.concat([d.update(blob.subarray(12, blob.length - 16)), d.final()]);
}
const cipherSize = (size) => { const full = Math.floor(size / SEG), rem = size % SEG; return full * (SEG + OVER) + (rem ? rem + OVER : 0); };
/** Stream decrypted bytes [start..end] (inclusive) of a stored file. */
async function* readPlain(file, size, key, start, end) {
  if (size === 0 || end < start) return;
  const fd = await fsp.open(file, 'r');
  try {
    const first = Math.floor(start / SEG), last = Math.floor(end / SEG);
    for (let s = first; s <= last;) {
      const cnt = Math.min(8, last - s + 1);
      const buf = Buffer.allocUnsafe(cnt * (SEG + OVER));
      const { bytesRead } = await fd.read(buf, 0, buf.length, s * (SEG + OVER));
      let off = 0;
      for (let i = 0; i < cnt; i++) {
        const idx = s + i, plainLen = Math.min(SEG, size - idx * SEG), blobLen = plainLen + OVER;
        if (off + blobLen > bytesRead) throw new Error('stored file is truncated');
        const p = decSeg(key, buf.subarray(off, off + blobLen), idx);
        off += blobLen;
        yield p.subarray(idx === first ? start - idx * SEG : 0, idx === last ? end - idx * SEG + 1 : p.length);
      }
      s += cnt;
    }
  } finally { await fd.close(); }
}

// === AUTH ==================================================================
const SCRYPT = { N: 2 ** 15, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };
async function hashKey(key) {
  const salt = crypto.randomBytes(16);
  const h = await new Promise((res, rej) => crypto.scrypt(key.normalize('NFKC'), salt, 32, SCRYPT, (e, d) => (e ? rej(e) : res(d))));
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString('base64')}$${h.toString('base64')}`;
}
async function verifyKey(key, stored) {
  const [, N, r, p, salt, hash] = stored.split('$');
  const want = Buffer.from(hash, 'base64');
  const got = await new Promise((res, rej) => crypto.scrypt(key.normalize('NFKC'), Buffer.from(salt, 'base64'), want.length,
    { N: +N, r: +r, p: +p, maxmem: SCRYPT.maxmem }, (e, d) => (e ? rej(e) : res(d))));
  return crypto.timingSafeEqual(got, want);
}
// first-run setup code (printed to the server console) stops a stranger claiming a fresh, unconfigured vault
let setupCode = null;
if (!getSetting('key_hash')) {
  setupCode = crypto.randomBytes(5).toString('hex').toUpperCase();
  console.log(`\n  FIRST-RUN SETUP CODE: ${setupCode}\n  (enter it on the setup page together with your new vault key)\n`);
}
// brute-force protection: per-IP escalating lockout + a global ceiling
const fails = new Map(); let globalFails = [];
const lockLeft = (ip) => { const f = fails.get(ip); return f && f.until > Date.now() ? Math.ceil((f.until - Date.now()) / 1000) : 0; };
function noteFail(ip) {
  const f = fails.get(ip) || { n: 0, until: 0, last: 0 };
  f.n++; f.last = Date.now();
  if (f.n >= 5) f.until = Date.now() + Math.min(3600e3, 60e3 * 2 ** (f.n - 5)); // 1m, 2m, 4m ... max 1h
  fails.set(ip, f); globalFails.push(Date.now());
}
const globalLocked = () => { const cut = Date.now() - 3600e3; globalFails = globalFails.filter((t) => t > cut); return globalFails.length > 100; };
const parseCookies = (req) => Object.fromEntries((req.headers.cookie || '').split(';').map((s) => s.trim().split(/=(.*)/s).slice(0, 2)).filter((a) => a[0] && a[1] !== undefined));
function getSession(req) {
  const t = parseCookies(req).vault_sid;
  if (!t || t.length > 100) return null;
  const id = sha256(t), s = Q('SELECT * FROM sessions WHERE id=?').get(id), now = Date.now();
  if (!s) return null;
  if (now - s.last_seen > CFG.idleMs || now - s.created > CFG.absMs) { Q('DELETE FROM sessions WHERE id=?').run(id); return null; }
  if (now - s.last_seen > 15e3) { Q('UPDATE sessions SET last_seen=? WHERE id=?').run(now, id); s.last_seen = now; }
  return s;
}
function audit(ev, c, detail) {
  Q('INSERT INTO audit(ts,ev,ip,ua,detail) VALUES(?,?,?,?,?)').run(Date.now(), ev, c.ip ?? null, String(c.req.headers['user-agent'] || '').slice(0, 200), detail ? String(detail).slice(0, 300) : null);
}

// === HTTP CORE =============================================================
class HttpError extends Error { constructor(status, message, extra) { super(message); this.status = status; this.extra = extra; } }
const isHttps = (req) => !!req.socket.encrypted || (CFG.trustProxy && req.headers['x-forwarded-proto'] === 'https');
function clientIp(req) {
  if (CFG.ipHeader && req.headers[CFG.ipHeader]) return String(req.headers[CFG.ipHeader]).split(',')[0].trim();
  if (CFG.trustProxy && req.headers['x-forwarded-for']) { const p = String(req.headers['x-forwarded-for']).split(',').map((s) => s.trim()); return p[p.length - 1]; }
  return req.socket.remoteAddress || '?';
}
function send(res, status, obj, headers) {
  if (res.headersSent || res.destroyed) return;
  const b = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': b.length, ...headers });
  res.end(b);
}
function readExact(req, max) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on('data', (c) => { n += c.length; if (n > max) { req.destroy(); reject(new HttpError(413, 'Body too large')); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks, n)));
    req.on('error', reject); req.on('close', () => reject(new HttpError(499, 'Client closed connection')));
  });
}
function secHeaders(res, req) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  if (isHttps(req)) res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
}
// Static files from ./public. Inline <script>/<style> are allowed via SHA-256 hashes (no 'unsafe-inline' for scripts).
const MIME = { html: 'text/html; charset=utf-8', js: 'text/javascript; charset=utf-8', css: 'text/css; charset=utf-8', svg: 'image/svg+xml', png: 'image/png', webmanifest: 'application/manifest+json', ico: 'image/x-icon' };
const staticCache = new Map();
function loadStatic(name) {
  const p = path.join(__dirname, 'public', name);
  let st; try { st = fs.statSync(p); } catch { return null; }
  if (!st.isFile()) return null;
  const hit = staticCache.get(name);
  if (hit && hit.mtime === st.mtimeMs) return hit;
  const body = fs.readFileSync(p); let csp = null;
  if (name.endsWith('.html')) {
    const html = body.toString('utf8'), hs = (re) => [...html.matchAll(re)].map((m) => `'sha256-${crypto.createHash('sha256').update(m[1]).digest('base64')}'`).join(' ');
    csp = ["default-src 'none'", `script-src 'self' ${hs(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/g)}`, `style-src 'self' ${hs(/<style[^>]*>([\s\S]*?)<\/style>/g)}`,
      "style-src-attr 'unsafe-inline'", "img-src 'self' data: blob:", "media-src 'self' blob:", "connect-src 'self'", "frame-src 'self'", "worker-src 'self'", "manifest-src 'self'",
      "base-uri 'none'", "form-action 'self'", "frame-ancestors 'none'"].join('; ');
  }
  const v = { mtime: st.mtimeMs, body, csp, type: MIME[path.extname(name).slice(1)] || 'application/octet-stream' };
  staticCache.set(name, v); return v;
}
function sendStatic(req, res, name) {
  const f = /^[\w.-]+$/.test(name) ? loadStatic(name) : null;
  if (!f) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('Not found'); }
  const h = { 'Content-Type': f.type, 'Content-Length': f.body.length, 'Cache-Control': name.endsWith('.html') ? 'no-cache' : 'public, max-age=3600' };
  if (f.csp) h['Content-Security-Policy'] = f.csp;
  res.writeHead(200, h); res.end(req.method === 'HEAD' ? undefined : f.body);
}
const routes = [];
const route = (method, pattern, handler, opts = {}) =>
  routes.push({ method, re: new RegExp('^' + pattern.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), handler, ...opts });

async function handle(req, res) {
  const url = new URL(req.url, 'http://x');
  secHeaders(res, req);
  const ip = clientIp(req);
  if (!url.pathname.startsWith('/api/') && !url.pathname.startsWith('/s/')) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'Method not allowed' });
    return sendStatic(req, res, url.pathname === '/' ? 'index.html' : path.basename(url.pathname));
  }
  res.setHeader('Cache-Control', 'no-store');
  let params = null, r = null;
  for (const x of routes) { if (x.method !== req.method) continue; const m = x.re.exec(url.pathname); if (m) { r = x; params = m.groups || {}; break; } }
  if (!r) return send(res, 404, { error: 'Not found' });
  // CSRF: state-changing calls must carry a custom header (forces a CORS preflight we never grant) and a same-origin Origin
  if (req.method !== 'GET') {
    if (req.headers['x-vault'] !== '1') return send(res, 403, { error: 'Missing request header' });
    const o = req.headers.origin;
    if (o) { try { if (new URL(o).host !== req.headers.host) return send(res, 403, { error: 'Cross-origin request blocked' }); } catch { return send(res, 403, { error: 'Bad origin' }); } }
  }
  const c = { req, res, ip, params, query: url.searchParams, session: null };
  c.json = async () => { const b = await readExact(req, 65536); try { return JSON.parse(b.toString() || '{}'); } catch { throw new HttpError(400, 'Invalid JSON'); } };
  try {
    c.session = getSession(req);
    if (!r.public && !c.session) throw new HttpError(401, 'Locked');
    await r.handler(c);
  } catch (e) {
    if (res.headersSent) { if (!(e instanceof HttpError)) console.error('Error after headers sent:', e.message); return res.destroy(); }
    if (e instanceof HttpError) {
      const h = e.extra?.retryAfter ? { 'Retry-After': e.extra.retryAfter } : {};
      if (e.status === 499) return;
      send(res, e.status, { error: e.message, ...e.extra }, h);
    } else if (e?.code === 'ENOENT') send(res, 404, { error: 'Not found' });
    else { console.error('Internal error:', e); send(res, 500, { error: 'Internal error' }); }
  }
}

// === HELPERS (names, types) ================================================
function cleanName(s) {
  s = String(s ?? '').normalize('NFC').replace(/[\u0000-\u001f\u007f/\\]/g, '_').trim();
  if (s === '' || s === '.' || s === '..') s = '_';
  while (Buffer.byteLength(s) > 255) s = s.slice(0, -1);
  return s;
}
const extOf = (n) => { const m = /\.([A-Za-z0-9]{1,16})$/.exec(n); return m ? m[1].toLowerCase() : ''; };
const TYPES = {
  image: 'png jpg jpeg gif webp avif bmp ico svg heic tiff', video: 'mp4 mkv mov avi webm m4v wmv flv', audio: 'mp3 wav flac m4a ogg aac opus wma',
  document: 'pdf doc docx xls xlsx ppt pptx txt md rtf odt ods csv json xml html', archive: 'zip rar 7z tar gz bz2 xz iso',
};
for (const k of Object.keys(TYPES)) TYPES[k] = TYPES[k].split(' ');
const MIMES = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', avif: 'image/avif', bmp: 'image/bmp', svg: 'image/svg+xml', ico: 'image/x-icon',
  mp4: 'video/mp4', m4v: 'video/mp4', webm: 'video/webm', mov: 'video/quicktime', mkv: 'video/x-matroska', mp3: 'audio/mpeg', wav: 'audio/wav', flac: 'audio/flac', m4a: 'audio/mp4', ogg: 'audio/ogg', opus: 'audio/ogg', aac: 'audio/aac',
  pdf: 'application/pdf', txt: 'text/plain', md: 'text/plain', csv: 'text/csv', json: 'application/json', zip: 'application/zip', html: 'text/html', xml: 'application/xml' };
const mimeOf = (ext) => MIMES[ext] || 'application/octet-stream';
const INLINE_OK = new Set(['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/avif', 'image/bmp', 'video/mp4', 'video/webm', 'audio/mpeg', 'audio/wav', 'audio/flac', 'audio/mp4', 'audio/ogg', 'audio/aac', 'application/pdf', 'text/plain']);
const fileOut = (f) => ({ id: f.id, name: f.name, ext: f.ext, mime: mimeOf(f.ext), size: f.size, sha256: f.sha256, folder_id: f.folder_id, created: f.created, downloads: f.downloads });
const getFolder = (id) => (id ? Q('SELECT * FROM folders WHERE id=?').get(id) : null);
function uniqueName(folderId, name, table = 'files') {
  const col = table === 'files' ? 'folder_id' : 'parent_id';
  const exists = (n) => !!Q(`SELECT 1 FROM ${table} WHERE ${col} IS ? AND name=? COLLATE NOCASE`).get(folderId, n);
  if (!exists(name)) return name;
  const dot = name.lastIndexOf('.'), base = dot > 0 ? name.slice(0, dot) : name, ext = dot > 0 ? name.slice(dot) : '';
  for (let i = 1; i < 1000; i++) { const n = `${base} (${i})${ext}`; if (!exists(n)) return n; }
  return `${base} (${crypto.randomUUID().slice(0, 8)})${ext}`;
}
const descendants = (id) => Q('WITH RECURSIVE d(id) AS (SELECT ? UNION ALL SELECT f.id FROM folders f JOIN d ON f.parent_id=d.id) SELECT id FROM d').all(id).map((r) => r.id);
function removeFileNow(id) { try { fs.unlinkSync(filePath(id)); } catch (e) { if (e.code !== 'ENOENT') throw e; } Q('DELETE FROM files WHERE id=?').run(id); Q('DELETE FROM share_items WHERE file_id=?').run(id); Q('DELETE FROM shares WHERE id NOT IN (SELECT share_id FROM share_items)').run(); }
function diskFree() { try { const s = fs.statfsSync(CFG.dataDir); return s.bavail * s.bsize; } catch { return Infinity; } }
const usedBytes = () => (Q('SELECT COALESCE(SUM(size),0) s FROM files').get().s) + (Q('SELECT COALESCE(SUM(size),0) s FROM uploads').get().s);
const needStr = (v, what) => { if (typeof v !== 'string' || !v.trim()) throw new HttpError(400, `${what} is required`); return v; };

// === ROUTES: auth ==========================================================
const cookieHeader = (req, token, maxAge) => `vault_sid=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${isHttps(req) ? '; Secure' : ''}`;
function startSession(c) {
  const token = crypto.randomBytes(32).toString('base64url'), now = Date.now();
  Q('INSERT INTO sessions(id,created,last_seen,ip,ua) VALUES(?,?,?,?,?)').run(sha256(token), now, now, c.ip, String(c.req.headers['user-agent'] || '').slice(0, 200));
  c.res.setHeader('Set-Cookie', cookieHeader(c.req, token, Math.floor(CFG.absMs / 1000)));
}
const checkNewKey = (k) => {
  if (typeof k !== 'string' || k.length < 12) throw new HttpError(400, 'Vault key must be at least 12 characters (a long passphrase is best).');
  if (k.length > 256) throw new HttpError(400, 'Vault key is too long.');
  if (new Set(k).size < 5) throw new HttpError(400, 'Vault key is too repetitive.');
};
route('GET', '/api/state', (c) => send(c.res, 200, { setup: !!getSetting('key_hash'), authed: !!c.session, idleSeconds: CFG.idleMs / 1000, chunkSize: CFG.chunkSize }), { public: true });
route('POST', '/api/setup', async (c) => {
  if (getSetting('key_hash')) throw new HttpError(409, 'Already set up');
  const b = await c.json();
  if (lockLeft(c.ip)) throw new HttpError(429, 'Too many attempts', { retryAfter: lockLeft(c.ip) });
  const given = Buffer.from(String(b.code || '').trim().toUpperCase()), want = Buffer.from(setupCode);
  if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) { noteFail(c.ip); throw new HttpError(403, 'Wrong setup code (see the server console / docker logs)'); }
  checkNewKey(b.key);
  setSetting('key_hash', await hashKey(b.key)); setupCode = null;
  audit('setup', c); startSession(c); send(c.res, 200, { ok: true });
}, { public: true });
route('POST', '/api/login', async (c) => {
  const wait = lockLeft(c.ip);
  if (wait) throw new HttpError(429, `Too many wrong attempts. Try again in ${wait}s.`, { retryAfter: wait });
  if (globalLocked()) throw new HttpError(429, 'Vault is temporarily locked after repeated failed logins.', { retryAfter: 600 });
  const stored = getSetting('key_hash'); if (!stored) throw new HttpError(400, 'Vault is not set up yet');
  const b = await c.json();
  const ok = typeof b.key === 'string' && b.key.length <= 256 && (await verifyKey(b.key, stored));
  if (!ok) { noteFail(c.ip); audit('login_fail', c); await new Promise((r) => setTimeout(r, 250 + Math.random() * 250)); throw new HttpError(401, 'Wrong key'); }
  const tsec = getSetting('totp');
  if (tsec) { // second factor
    if (!b.code) throw new HttpError(401, 'Enter the 6-digit code from your authenticator app (or a backup code).', { need2fa: true });
    if (!(totpOk(unwrapKey(tsec, 'totp'), b.code) || useBackupCode(b.code))) { noteFail(c.ip); audit('login_fail_2fa', c); await new Promise((r) => setTimeout(r, 250 + Math.random() * 250)); throw new HttpError(401, 'Wrong code', { need2fa: true }); }
  }
  fails.delete(c.ip); audit('login', c); startSession(c); send(c.res, 200, { ok: true });
}, { public: true });
route('POST', '/api/logout', (c) => {
  if (c.session) Q('DELETE FROM sessions WHERE id=?').run(c.session.id);
  c.res.setHeader('Set-Cookie', cookieHeader(c.req, '', 0)); send(c.res, 200, { ok: true });
}, { public: true });
route('POST', '/api/logout-all', (c) => { Q('DELETE FROM sessions').run(); audit('logout_all', c); c.res.setHeader('Set-Cookie', cookieHeader(c.req, '', 0)); send(c.res, 200, { ok: true }); });
route('POST', '/api/change-key', async (c) => {
  const b = await c.json();
  if (lockLeft(c.ip)) throw new HttpError(429, 'Too many attempts', { retryAfter: lockLeft(c.ip) });
  if (!(await verifyKey(String(b.current || ''), getSetting('key_hash')))) { noteFail(c.ip); throw new HttpError(401, 'Current key is wrong'); }
  checkNewKey(b.next);
  setSetting('key_hash', await hashKey(b.next));
  Q('DELETE FROM sessions WHERE id<>?').run(c.session.id); audit('change_key', c); send(c.res, 200, { ok: true });
});
route('GET', '/api/sessions', (c) => send(c.res, 200, { sessions: Q('SELECT id,created,last_seen,ip,ua FROM sessions ORDER BY last_seen DESC').all().map((s) => ({ handle: s.id.slice(0, 12), current: s.id === c.session.id, created: s.created, last_seen: s.last_seen, ip: s.ip, ua: s.ua })) }));
route('DELETE', '/api/sessions/:h', (c) => {
  if (!/^[0-9a-f]{12}$/.test(c.params.h)) throw new HttpError(400, 'Bad handle');
  Q("DELETE FROM sessions WHERE substr(id,1,12)=?").run(c.params.h); audit('session_revoked', c); send(c.res, 200, { ok: true });
});
route('GET', '/api/audit', (c) => send(c.res, 200, { events: Q('SELECT ts,ev,ip,ua,detail FROM audit ORDER BY id DESC LIMIT ?').all(Math.min(+c.query.get('limit') || 200, 1000)) }));

// === ROUTES: listing, files, folders =======================================
route('GET', '/api/stats', (c) => {
  const s = Q('SELECT COUNT(*) n, COALESCE(SUM(size),0) bytes FROM files').get();
  send(c.res, 200, { files: s.n, bytes: s.bytes, quota: CFG.quota, diskFree: diskFree() === Infinity ? null : diskFree(), maxFileSize: CFG.maxFileSize, pendingUploads: Q('SELECT COUNT(*) n FROM uploads').get().n, ephemeral: EPHEMERAL });
});
route('GET', '/api/list', (c) => {
  const folder = c.query.get('folder') || null;
  if (folder && !getFolder(folder)) throw new HttpError(404, 'Folder not found');
  const q = (c.query.get('q') || '').trim().slice(0, 100);
  const col = { name: 'name COLLATE NOCASE', size: 'size', date: 'created', ext: 'ext', downloads: 'downloads' }[c.query.get('sort')] || 'created';
  const dir = c.query.get('dir') === 'asc' ? 'ASC' : 'DESC';
  const where = [], args = [];
  if (q) { where.push("name LIKE ? ESCAPE '\\'"); args.push('%' + q.replace(/[\\%_]/g, '\\$&') + '%'); } else { where.push('folder_id IS ?'); args.push(folder); }
  const type = c.query.get('type');
  if (type && TYPES[type]) { where.push(`ext IN (${TYPES[type].map(() => '?').join(',')})`); args.push(...TYPES[type]); }
  else if (type === 'other') { const all = Object.values(TYPES).flat(); where.push(`ext NOT IN (${all.map(() => '?').join(',')})`); args.push(...all); }
  if (+c.query.get('from')) { where.push('created >= ?'); args.push(+c.query.get('from')); }
  if (+c.query.get('to')) { where.push('created <= ?'); args.push(+c.query.get('to')); }
  const files = db.prepare(`SELECT * FROM files WHERE ${where.join(' AND ')} ORDER BY ${col} ${dir}, id LIMIT 5000`).all(...args).map(fileOut);
  const folders = (q ? Q("SELECT * FROM folders WHERE name LIKE ? ESCAPE '\\' ORDER BY name COLLATE NOCASE LIMIT 500").all('%' + q.replace(/[\\%_]/g, '\\$&') + '%')
    : Q('SELECT * FROM folders WHERE parent_id IS ? ORDER BY name COLLATE NOCASE').all(folder)).map((f) => ({ id: f.id, name: f.name, parent_id: f.parent_id, created: f.created,
    items: Q('SELECT (SELECT COUNT(*) FROM files WHERE folder_id=?) + (SELECT COUNT(*) FROM folders WHERE parent_id=?) n').get(f.id, f.id).n }));
  const crumbs = []; for (let id = folder, i = 0; id && i < 100; i++) { const f = getFolder(id); if (!f) break; crumbs.unshift({ id: f.id, name: f.name }); id = f.parent_id; }
  send(c.res, 200, { folder, breadcrumbs: crumbs, folders, files, search: q || null });
});
route('POST', '/api/folders', async (c) => {
  const b = await c.json(), parent = b.parent || null;
  if (parent && !getFolder(parent)) throw new HttpError(404, 'Parent folder not found');
  const name = cleanName(needStr(b.name, 'Name'));
  if (Q('SELECT 1 FROM folders WHERE parent_id IS ? AND name=? COLLATE NOCASE').get(parent, name)) throw new HttpError(409, 'A folder with this name already exists');
  const id = crypto.randomUUID(); Q('INSERT INTO folders(id,name,parent_id,created) VALUES(?,?,?,?)').run(id, name, parent, Date.now());
  audit('folder_create', c, name); send(c.res, 200, { id, name });
});
route('PATCH', '/api/folders/:id', async (c) => {
  const f = getFolder(c.params.id); if (!f) throw new HttpError(404, 'Folder not found');
  const b = await c.json(); let name = f.name, parent = f.parent_id;
  if (b.name !== undefined) name = cleanName(needStr(b.name, 'Name'));
  if (b.parent !== undefined) {
    parent = b.parent || null;
    if (parent && (!getFolder(parent) || descendants(f.id).includes(parent))) throw new HttpError(400, 'Cannot move a folder into itself');
  }
  if (Q('SELECT 1 FROM folders WHERE parent_id IS ? AND name=? COLLATE NOCASE AND id<>?').get(parent, name, f.id)) throw new HttpError(409, 'A folder with this name already exists there');
  Q('UPDATE folders SET name=?, parent_id=? WHERE id=?').run(name, parent, f.id); audit('folder_update', c, name); send(c.res, 200, { ok: true });
});
route('PATCH', '/api/files/:id', async (c) => {
  const f = Q('SELECT * FROM files WHERE id=?').get(c.params.id); if (!f) throw new HttpError(404, 'File not found');
  const b = await c.json(); let name = f.name, folder = f.folder_id;
  if (b.folder !== undefined) { folder = b.folder || null; if (folder && !getFolder(folder)) throw new HttpError(404, 'Folder not found'); }
  if (b.name !== undefined) {
    name = cleanName(needStr(b.name, 'Name'));
    if (Q('SELECT 1 FROM files WHERE folder_id IS ? AND name=? COLLATE NOCASE AND id<>?').get(folder, name, f.id)) throw new HttpError(409, 'A file with this name already exists here');
  } else if (folder !== f.folder_id) name = uniqueName(folder, f.name);
  Q('UPDATE files SET name=?, ext=?, folder_id=? WHERE id=?').run(name, extOf(name), folder, f.id); audit('file_update', c, name); send(c.res, 200, { ok: true, name });
});
route('POST', '/api/delete', async (c) => {
  const b = await c.json(), fileIds = Array.isArray(b.files) ? b.files.slice(0, 5000) : [], folderIds = Array.isArray(b.folders) ? b.folders.slice(0, 500) : [];
  let nFiles = 0, nFolders = 0;
  for (const id of fileIds) if (typeof id === 'string' && Q('SELECT 1 FROM files WHERE id=?').get(id)) { removeFileNow(id); nFiles++; }
  for (const id of folderIds) {
    if (typeof id !== 'string' || !getFolder(id)) continue;
    const ids = descendants(id);
    for (const fid of ids) { for (const f of Q('SELECT id FROM files WHERE folder_id=?').all(fid)) { removeFileNow(f.id); nFiles++; } }
    tx(() => { for (const fid of ids) Q('DELETE FROM folders WHERE id=?').run(fid); }); nFolders += ids.length;
  }
  audit('delete', c, `${nFiles} files, ${nFolders} folders`); send(c.res, 200, { ok: true, files: nFiles, folders: nFolders });
});

// === ROUTES: resumable chunked uploads =====================================
// Flow: POST /api/uploads → PUT /api/uploads/:id/chunks/:n (any order, parallel, retry-safe) → POST /api/uploads/:id/complete
const completing = new Set();
const uploadInfo = (u) => ({ id: u.id, name: u.name, size: u.size, chunkSize: u.chunk_size, total: Math.ceil(u.size / u.chunk_size), folder_id: u.folder_id,
  received: Q('SELECT n FROM upload_chunks WHERE upload_id=? ORDER BY n').all(u.id).map((r) => r.n), updated: u.updated });
const getUpload = (id) => { const u = Q('SELECT * FROM uploads WHERE id=?').get(id); if (!u) throw new HttpError(404, 'Upload not found (it may have expired). Start it again.'); return u; };
function dropUpload(id) { try { fs.unlinkSync(partPath(id)); } catch {} Q('DELETE FROM upload_chunks WHERE upload_id=?').run(id); Q('DELETE FROM uploads WHERE id=?').run(id); }
route('GET', '/api/uploads', (c) => send(c.res, 200, { uploads: Q('SELECT * FROM uploads ORDER BY created DESC').all().map(uploadInfo) }));
route('POST', '/api/uploads', async (c) => {
  const b = await c.json(), size = b.size, folder = b.folder || null;
  if (!Number.isSafeInteger(size) || size < 0) throw new HttpError(400, 'Invalid file size');
  if (size > CFG.maxFileSize) throw new HttpError(413, `File is larger than the allowed maximum (${CFG.maxFileSize} bytes)`);
  if (folder && !getFolder(folder)) throw new HttpError(404, 'Folder not found');
  const name = cleanName(needStr(b.name, 'File name')), fp = typeof b.fingerprint === 'string' ? b.fingerprint.slice(0, 300) : null;
  if (fp) { // same file picked again after a refresh/crash → resume the existing upload
    const ex = Q('SELECT * FROM uploads WHERE fingerprint=? AND size=?').get(fp, size);
    if (ex && fs.existsSync(partPath(ex.id))) { // resume follows the FILE; the folder follows the user's latest choice
      if (ex.folder_id !== folder) { Q('UPDATE uploads SET folder_id=? WHERE id=?').run(folder, ex.id); ex.folder_id = folder; }
      return send(c.res, 200, { ...uploadInfo(ex), resumed: true });
    }
    if (ex) dropUpload(ex.id);
  }
  if (diskFree() < size + 64 * 2 ** 20) throw new HttpError(507, 'Not enough free disk space on the server for this file');
  if (CFG.quota && usedBytes() + size > CFG.quota) throw new HttpError(507, 'Storage quota would be exceeded');
  const id = crypto.randomUUID(), now = Date.now();
  fs.closeSync(fs.openSync(partPath(id), 'w', 0o600));
  Q('INSERT INTO uploads(id,name,size,folder_id,chunk_size,wrapped_key,fingerprint,created,updated) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(id, name, size, folder, CFG.chunkSize, wrapKey(crypto.randomBytes(32), id), fp, now, now);
  send(c.res, 200, { ...uploadInfo(getUpload(id)), resumed: false });
});
route('GET', '/api/uploads/:id', (c) => send(c.res, 200, uploadInfo(getUpload(c.params.id))));
route('PUT', '/api/uploads/:id/chunks/:n', async (c) => {
  const u = getUpload(c.params.id), n = Number(c.params.n), total = Math.ceil(u.size / u.chunk_size);
  if (!Number.isInteger(n) || n < 0 || n >= total) throw new HttpError(400, 'Bad chunk number');
  const expect = Math.min(u.chunk_size, u.size - n * u.chunk_size);
  if (Number(c.req.headers['content-length']) !== expect) throw new HttpError(400, `Chunk must be exactly ${expect} bytes`);
  const body = await readExact(c.req, expect);
  if (body.length !== expect) throw new HttpError(400, 'Incomplete chunk');
  const want = c.req.headers['x-chunk-sha256'];
  if (want && sha256(body) !== String(want).toLowerCase()) throw new HttpError(422, 'Chunk was corrupted in transit — retrying');
  const key = unwrapKey(u.wrapped_key, u.id), parts = [];
  for (let off = 0, i = 0; off < body.length; off += SEG, i++) parts.push(encSeg(key, body.subarray(off, off + SEG), n * SPC + i));
  const out = Buffer.concat(parts), fd = await fsp.open(partPath(u.id), 'r+');
  try { await fd.write(out, 0, out.length, n * SPC * (SEG + OVER)); } finally { await fd.close(); }
  Q('INSERT OR IGNORE INTO upload_chunks(upload_id,n) VALUES(?,?)').run(u.id, n);
  Q('UPDATE uploads SET updated=? WHERE id=?').run(Date.now(), u.id);
  send(c.res, 200, { ok: true, received: Q('SELECT COUNT(*) c FROM upload_chunks WHERE upload_id=?').get(u.id).c, total });
});
route('POST', '/api/uploads/:id/complete', async (c) => {
  const u = getUpload(c.params.id), b = await c.json(), total = Math.ceil(u.size / u.chunk_size);
  if (completing.has(u.id)) throw new HttpError(409, 'Already finishing this upload');
  const have = new Set(Q('SELECT n FROM upload_chunks WHERE upload_id=?').all(u.id).map((r) => r.n)), missing = [];
  for (let i = 0; i < total && missing.length < 1000; i++) if (!have.has(i)) missing.push(i);
  if (missing.length) throw new HttpError(409, 'Some parts are missing', { missing });
  if ((await fsp.stat(partPath(u.id))).size !== cipherSize(u.size)) throw new HttpError(409, 'Stored data has the wrong size; please re-upload', { missing: [...have].length ? undefined : [] });
  completing.add(u.id);
  try {
    // verify: decrypt the whole file once (checks every GCM tag) and compute its SHA-256
    const key = unwrapKey(u.wrapped_key, u.id), h = crypto.createHash('sha256');
    try { for await (const p of readPlain(partPath(u.id), u.size, key, 0, u.size - 1)) h.update(p); }
    catch (e) { dropUpload(u.id); throw new HttpError(422, 'Stored data failed integrity check; please upload again'); }
    const digest = h.digest('hex');
    if (typeof b.sha256 === 'string' && b.sha256.toLowerCase() !== digest) { dropUpload(u.id); throw new HttpError(422, 'Checksum mismatch — the file was altered or damaged; upload again'); }
    if (b.onDuplicate === 'skip') {
      const dup = Q('SELECT * FROM files WHERE sha256=? AND size=?').get(digest, u.size);
      if (dup) { dropUpload(u.id); return send(c.res, 200, { duplicate: true, file: fileOut(dup) }); }
    }
    const folder = u.folder_id && getFolder(u.folder_id) ? u.folder_id : null, id = u.id, now = Date.now();
    fs.renameSync(partPath(id), filePath(id)); // atomic: the file appears fully-written or not at all
    const name = tx(() => {
      const nm = uniqueName(folder, u.name);
      Q('INSERT INTO files(id,name,ext,size,sha256,folder_id,wrapped_key,created) VALUES(?,?,?,?,?,?,?,?)').run(id, nm, extOf(nm), u.size, digest, folder, u.wrapped_key, now);
      Q('DELETE FROM upload_chunks WHERE upload_id=?').run(id); Q('DELETE FROM uploads WHERE id=?').run(id); return nm;
    });
    audit('upload', c, `${name} (${u.size} bytes)`);
    send(c.res, 200, { duplicate: false, file: fileOut(Q('SELECT * FROM files WHERE id=?').get(id)) });
  } finally { completing.delete(u.id); }
});
route('DELETE', '/api/uploads/:id', (c) => { getUpload(c.params.id); dropUpload(c.params.id); send(c.res, 200, { ok: true }); });

// === ROUTES: download / preview (Range-capable, streamed, decrypted on the fly) ===
const dispo = (type, name) => `${type}; filename="${name.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_')}"; filename*=UTF-8''${encodeURIComponent(name).replace(/['()*]/g, (ch) => '%' + ch.charCodeAt(0).toString(16).toUpperCase())}`;
function parseRange(h, size) {
  const m = /^bytes=(\d*)-(\d*)$/.exec(h || ''); if (!m || (m[1] === '' && m[2] === '')) return null;
  let start, end;
  if (m[1] === '') { const n = +m[2]; if (!n) return 'bad'; start = Math.max(0, size - n); end = size - 1; } else { start = +m[1]; end = m[2] === '' ? size - 1 : Math.min(+m[2], size - 1); }
  return start > end || start >= size ? 'bad' : { start, end };
}
route('GET', '/api/files/:id/download', async (c) => {
  const f = Q('SELECT * FROM files WHERE id=?').get(c.params.id); if (!f) throw new HttpError(404, 'File not found');
  await serveFile(c, f, { inline: c.query.get('inline') === '1' });
});
async function serveFile(c, f, { inline: wantInline, onStart }) {
  const mime = mimeOf(f.ext), inline = wantInline && INLINE_OK.has(mime);
  const h = { 'Accept-Ranges': 'bytes', 'Content-Type': inline ? mime : 'application/octet-stream', 'Content-Disposition': dispo(inline ? 'inline' : 'attachment', f.name), 'Cache-Control': 'private, no-store' };
  if (inline) { h['X-Frame-Options'] = 'SAMEORIGIN'; h['Content-Security-Policy'] = mime === 'application/pdf' ? "default-src 'none'; frame-ancestors 'self'" : "default-src 'none'; style-src 'unsafe-inline'; sandbox; frame-ancestors 'self'"; }
  let start = 0, end = f.size - 1, status = 200;
  if (c.req.headers.range && f.size > 0) {
    const r = parseRange(c.req.headers.range, f.size);
    if (r === 'bad') { c.res.writeHead(416, { 'Content-Range': `bytes */${f.size}` }); return c.res.end(); }
    if (r) { start = r.start; end = r.end; status = 206; h['Content-Range'] = `bytes ${start}-${end}/${f.size}`; }
  }
  h['Content-Length'] = f.size === 0 ? 0 : end - start + 1;
  const key = f.size === 0 ? null : unwrapKey(f.wrapped_key, f.id); // fail BEFORE headers go out if the master key is wrong
  if (onStart && !onStart(start)) throw new HttpError(404, 'This link does not exist or has expired.');
  if (!inline && start === 0) { Q('UPDATE files SET downloads=downloads+1 WHERE id=?').run(f.id); audit('download', c, f.name); }
  c.res.writeHead(status, h);
  if (f.size === 0) return c.res.end();
  await pipeline(Readable.from(readPlain(filePath(f.id), f.size, key, start, end), { objectMode: false }), c.res).catch(() => {});
}

// === ROUTES: two-step login (TOTP, RFC 6238 — works with Google Authenticator, Authy, 1Password, ...) ===
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const b32 = (buf) => { let bits = '', out = ''; for (const x of buf) bits += x.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; };
function totp(secret, counter) {
  const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac('sha1', secret).update(b).digest(), o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0');
}
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
function totpOk(secret, code) { // each code works once (replay-proof) and ±30 s clock drift is tolerated
  code = String(code || '').replace(/\s/g, ''); if (!/^\d{6}$/.test(code)) return false;
  const now = Math.floor(Date.now() / 30000), last = +(getSetting('totp_last') || 0);
  for (const d of [-1, 0, 1]) { const ctr = now + d; if (ctr > last && safeEq(totp(secret, ctr), code)) { setSetting('totp_last', String(ctr)); return true; } }
  return false;
}
function useBackupCode(code) {
  const h = sha256(String(code || '').toLowerCase().replace(/[^a-z0-9]/g, '')), list = JSON.parse(getSetting('backup_codes') || '[]');
  if (!list.includes(h)) return false;
  setSetting('backup_codes', JSON.stringify(list.filter((x) => x !== h))); return true;
}
let pending2fa = null;
const needKey = async (c, key) => {
  if (lockLeft(c.ip)) throw new HttpError(429, 'Too many attempts', { retryAfter: lockLeft(c.ip) });
  if (typeof key !== 'string' || !(await verifyKey(key, getSetting('key_hash')))) { noteFail(c.ip); throw new HttpError(401, 'Vault key is wrong'); }
};
route('GET', '/api/2fa', (c) => send(c.res, 200, { enabled: !!getSetting('totp'), backupCodesLeft: JSON.parse(getSetting('backup_codes') || '[]').length }));
route('POST', '/api/2fa/start', async (c) => {
  await needKey(c, (await c.json()).key);
  if (getSetting('totp')) throw new HttpError(409, 'Two-step login is already on');
  const secret = crypto.randomBytes(20); pending2fa = { secret, exp: Date.now() + 10 * 60e3 };
  const s32 = b32(secret);
  send(c.res, 200, { secret: s32, uri: `otpauth://totp/Vault?secret=${s32}&issuer=Vault&period=30&digits=6` });
});
route('POST', '/api/2fa/enable', async (c) => {
  const b = await c.json();
  if (!pending2fa || pending2fa.exp < Date.now()) throw new HttpError(400, 'Start again: the setup timed out');
  if (!totpOk(pending2fa.secret, b.code)) throw new HttpError(400, 'That code is not right. Check the time on your phone and try the next code.');
  const codes = Array.from({ length: 8 }, () => { const x = crypto.randomBytes(5).toString('hex'); return x.slice(0, 5) + '-' + x.slice(5); });
  setSetting('totp', wrapKey(pending2fa.secret, 'totp')); setSetting('backup_codes', JSON.stringify(codes.map((x) => sha256(x.replace('-', ''))))); pending2fa = null;
  Q('DELETE FROM sessions WHERE id<>?').run(c.session.id); audit('2fa_enabled', c); send(c.res, 200, { ok: true, backupCodes: codes });
});
route('POST', '/api/2fa/disable', async (c) => {
  const b = await c.json(); await needKey(c, b.key);
  if (!getSetting('totp')) throw new HttpError(409, 'Two-step login is not on');
  if (!(totpOk(unwrapKey(getSetting('totp'), 'totp'), b.code) || useBackupCode(b.code))) { noteFail(c.ip); throw new HttpError(401, 'Wrong code'); }
  Q("DELETE FROM settings WHERE k IN ('totp','backup_codes','totp_last')").run(); audit('2fa_disabled', c); send(c.res, 200, { ok: true });
});

// === ROUTES: share links — one or many files, no vault access, expiring, revocable; only a hash of the token is stored ===
function createShare(c, fileIds, b) {
  const files = [...new Set(fileIds)].filter((id) => typeof id === 'string').slice(0, 200).map((id) => Q('SELECT id,name FROM files WHERE id=?').get(id)).filter(Boolean);
  if (!files.length) throw new HttpError(404, 'File not found');
  const hours = b.hours === undefined ? 24 : Number(b.hours);
  if (!Number.isInteger(hours) || hours < 1 || hours > 720) throw new HttpError(400, 'Link lifetime must be a whole number of hours from 1 to 720');
  let max = null; if (b.max != null && b.max !== '') { max = Number(b.max); if (!Number.isInteger(max) || max < 1 || max > 10000) throw new HttpError(400, 'Download limit must be 1 to 10000'); }
  const token = crypto.randomBytes(32).toString('base64url'), id = crypto.randomUUID(), exp = Date.now() + hours * 3600e3;
  tx(() => {
    Q('INSERT INTO shares(id,token_hash,file_id,expires,max_downloads,created) VALUES(?,?,?,?,?,?)').run(id, sha256(token), files[0].id, exp, max, Date.now());
    for (const f of files) Q('INSERT OR IGNORE INTO share_items(share_id,file_id) VALUES(?,?)').run(id, f.id);
  });
  audit('share_create', c, files.length === 1 ? files[0].name : `${files.length} files`);
  return { id, expires: exp, count: files.length, url: `${isHttps(c.req) ? 'https' : 'http'}://${c.req.headers.host}/s/${token}` };
}
route('POST', '/api/shares', async (c) => { const b = await c.json(); send(c.res, 200, createShare(c, Array.isArray(b.files) ? b.files : [], b)); });
route('POST', '/api/files/:id/share', async (c) => send(c.res, 200, createShare(c, [c.params.id], await c.json())));
route('GET', '/api/shares', (c) => send(c.res, 200, { shares: Q('SELECT * FROM shares WHERE expires>? ORDER BY created DESC').all(Date.now()).map((s) => ({ id: s.id, expires: s.expires, max_downloads: s.max_downloads, downloads: s.downloads,
  names: Q('SELECT f.name FROM share_items i JOIN files f ON f.id=i.file_id WHERE i.share_id=? ORDER BY f.name COLLATE NOCASE').all(s.id).map((r) => r.name) })) }));
route('DELETE', '/api/shares/:id', (c) => { Q('DELETE FROM share_items WHERE share_id=?').run(c.params.id); Q('DELETE FROM shares WHERE id=?').run(c.params.id); audit('share_revoke', c); send(c.res, 200, { ok: true }); });
const shareFails = new Map();
function shareFind(c) {
  const bad = shareFails.get(c.ip) || { n: 0, t: 0 }; if (Date.now() - bad.t > 600e3) bad.n = 0;
  if (bad.n >= 30) throw new HttpError(429, 'Too many attempts. Try again later.');
  const row = /^[\w-]{20,64}$/.test(c.params.token) ? Q('SELECT * FROM shares WHERE token_hash=?').get(sha256(c.params.token)) : null;
  const files = row && row.expires > Date.now() ? Q('SELECT f.* FROM share_items i JOIN files f ON f.id=i.file_id WHERE i.share_id=? ORDER BY f.name COLLATE NOCASE').all(row.id) : [];
  if (!files.length) { bad.n++; bad.t = Date.now(); shareFails.set(c.ip, bad); throw new HttpError(404, 'This link does not exist or has expired.'); }
  return { row, files };
}
// a download "starts" at byte 0 and is counted atomically against the limit; resumed (Range) requests may continue once started
const shareCount = (row, start) => start === 0
  ? Q('UPDATE shares SET downloads=downloads+1 WHERE id=? AND (max_downloads IS NULL OR downloads<max_downloads)').run(row.id).changes === 1
  : (Q('SELECT downloads FROM shares WHERE id=?').get(row.id)?.downloads || 0) > 0;
route('GET', '/s/:token', (c) => { c.res.setHeader('X-Robots-Tag', 'noindex'); sendStatic(c.req, c.res, 'share.html'); }, { public: true });
route('GET', '/s/:token/info', (c) => {
  const { row, files } = shareFind(c);
  send(c.res, 200, { expires: row.expires, remaining: row.max_downloads ? Math.max(0, row.max_downloads - row.downloads) : null, files: files.map((f) => ({ id: f.id, name: f.name, size: f.size, ext: f.ext })) });
}, { public: true });
route('GET', '/s/:token/f/:fid', async (c) => {
  const { row, files } = shareFind(c), f = files.find((x) => x.id === c.params.fid);
  if (!f) throw new HttpError(404, 'This file is not part of that link.');
  await serveFile(c, f, { inline: false, onStart: (start) => shareCount(row, start) });
}, { public: true });
route('GET', '/s/:token/zip', async (c) => {
  const { row, files } = shareFind(c); if (!shareCount(row, 0)) throw new HttpError(404, 'This link does not exist or has expired.');
  const seen = new Set(), entries = files.map((f) => { const dot = f.name.lastIndexOf('.'), base = dot > 0 ? f.name.slice(0, dot) : f.name, ext = dot > 0 ? f.name.slice(dot) : ''; let n = f.name, i = 0; while (seen.has(n.toLowerCase())) n = `${base} (${++i})${ext}`; seen.add(n.toLowerCase()); return { path: n, f }; });
  await sendZip(c, entries, 'shared-files');
}, { public: true });

// === ROUTES: streamed ZIP of many files/folders (stored, not compressed; entries up to 4 GB each) ===
async function* zipStream(entries) {
  const cd = []; let off = 0;
  for (const e of entries) {
    const name = Buffer.from(e.path, 'utf8'), d = new Date(e.dir ? Date.now() : e.f.created), flags = e.dir ? 0x0800 : 0x0808;
    const dosT = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1), dosD = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
    const lh = Buffer.alloc(30 + name.length);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(flags, 6); lh.writeUInt16LE(dosT, 10); lh.writeUInt16LE(dosD, 12); lh.writeUInt16LE(name.length, 26); name.copy(lh, 30);
    const start = off; yield lh; off += lh.length;
    let crc = 0, size = 0;
    if (!e.dir && e.f.size > 0) for await (const p of readPlain(filePath(e.f.id), e.f.size, unwrapKey(e.f.wrapped_key, e.f.id), 0, e.f.size - 1)) { crc = zlib.crc32(p, crc); size += p.length; off += p.length; yield p; }
    if (!e.dir) { const dd = Buffer.alloc(16); dd.writeUInt32LE(0x08074b50, 0); dd.writeUInt32LE(crc >>> 0, 4); dd.writeUInt32LE(size, 8); dd.writeUInt32LE(size, 12); yield dd; off += 16; }
    cd.push({ name, flags, dosT, dosD, crc: crc >>> 0, size, start, dir: e.dir });
  }
  const cdStart = off; let cdLen = 0;
  for (const r of cd) {
    const b = Buffer.alloc(46 + r.name.length);
    b.writeUInt32LE(0x02014b50, 0); b.writeUInt16LE(0x0314, 4); b.writeUInt16LE(20, 6); b.writeUInt16LE(r.flags, 8); b.writeUInt16LE(r.dosT, 12); b.writeUInt16LE(r.dosD, 14);
    b.writeUInt32LE(r.crc, 16); b.writeUInt32LE(r.size, 20); b.writeUInt32LE(r.size, 24); b.writeUInt16LE(r.name.length, 28);
    b.writeUInt32LE(((r.dir ? 0o40755 : 0o100644) << 16 | (r.dir ? 0x10 : 0)) >>> 0, 38); b.writeUInt32LE(r.start, 42); r.name.copy(b, 46);
    yield b; cdLen += b.length;
  }
  const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(cd.length, 8); end.writeUInt16LE(cd.length, 10); end.writeUInt32LE(cdLen, 12); end.writeUInt32LE(cdStart, 16);
  yield end;
}
route('GET', '/api/zip', async (c) => {
  const ids = (k) => (c.query.get(k) || '').split(',').filter(Boolean).slice(0, 500), entries = [], top = new Set();
  const topName = (n, isFile) => { const dot = isFile ? n.lastIndexOf('.') : -1, base = dot > 0 ? n.slice(0, dot) : n, ext = dot > 0 ? n.slice(dot) : ''; let x = n, i = 0; while (top.has(x.toLowerCase())) x = `${base} (${++i})${ext}`; top.add(x.toLowerCase()); return x; };
  const walk = (folder, prefix) => {
    entries.push({ path: prefix + '/', dir: true });
    for (const f of Q('SELECT * FROM files WHERE folder_id=? ORDER BY name').all(folder)) entries.push({ path: `${prefix}/${f.name}`, f });
    for (const s of Q('SELECT * FROM folders WHERE parent_id=? ORDER BY name').all(folder)) walk(s.id, `${prefix}/${s.name}`);
  };
  for (const id of ids('files')) { const f = Q('SELECT * FROM files WHERE id=?').get(id); if (f) entries.push({ path: topName(f.name, true), f }); }
  for (const id of ids('folders')) { const fo = getFolder(id); if (fo) walk(fo.id, topName(fo.name)); }
  await sendZip(c, entries, 'vault');
});
async function sendZip(c, entries, base) {
  if (!entries.length) throw new HttpError(404, 'Nothing to download');
  const files = entries.filter((e) => !e.dir), total = files.reduce((a, e) => a + e.f.size, 0) + entries.reduce((a, e) => a + 150 + 2 * Buffer.byteLength(e.path), 0);
  if (entries.length > 20000 || files.some((e) => e.f.size >= 0xffffffff) || total >= 0xfffffff0) throw new HttpError(413, 'Too large for one ZIP (limit 4 GB total, 4 GB per file). Download the big files one by one.');
  for (const e of files) Q('UPDATE files SET downloads=downloads+1 WHERE id=?').run(e.f.id);
  audit('zip', c, `${files.length} files`);
  c.res.writeHead(200, { 'Content-Type': 'application/zip', 'Content-Disposition': dispo('attachment', `${base}-${new Date().toISOString().slice(0, 10)}.zip`), 'Cache-Control': 'private, no-store' });
  await pipeline(Readable.from(zipStream(entries), { objectMode: false }), c.res).catch(() => {});
}

// === ROUTES: move & copy (cut / copy / paste) ===
const idList = (v, n) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string').slice(0, n) : []);
route('POST', '/api/move', async (c) => {
  const b = await c.json(), to = b.to || null; if (to && !getFolder(to)) throw new HttpError(404, 'Destination folder not found');
  let moved = 0;
  tx(() => {
    for (const id of idList(b.folders, 500)) {
      const fo = getFolder(id); if (!fo) continue;
      if (fo.id === to || (to && descendants(fo.id).includes(to))) throw new HttpError(400, 'A folder cannot be moved into itself');
      if (fo.parent_id === to) continue;
      Q('UPDATE folders SET parent_id=?, name=? WHERE id=?').run(to, uniqueName(to, fo.name, 'folders'), fo.id); moved++;
    }
    for (const id of idList(b.files, 5000)) {
      const f = Q('SELECT * FROM files WHERE id=?').get(id); if (!f || f.folder_id === to) continue;
      const nm = uniqueName(to, f.name); Q('UPDATE files SET name=?, ext=?, folder_id=? WHERE id=?').run(nm, extOf(nm), to, f.id); moved++;
    }
  });
  audit('move', c, `${moved} items`); send(c.res, 200, { ok: true, moved });
});
route('POST', '/api/copy', async (c) => {
  const b = await c.json(), to = b.to || null; if (to && !getFolder(to)) throw new HttpError(404, 'Destination folder not found');
  const srcFolders = idList(b.folders, 200).map(getFolder).filter(Boolean), plan = [];
  for (const fo of srcFolders) if (fo.id === to || (to && descendants(fo.id).includes(to))) throw new HttpError(400, 'A folder cannot be copied into itself');
  for (const id of idList(b.files, 2000)) { const f = Q('SELECT * FROM files WHERE id=?').get(id); if (f) plan.push({ f, parent: to, top: true }); }
  const walk = (fo, parent, top) => {
    const nid = crypto.randomUUID(); plan.push({ folder: fo, nid, parent, top });
    for (const f of Q('SELECT * FROM files WHERE folder_id=?').all(fo.id)) plan.push({ f, parent: nid });
    for (const sub of Q('SELECT * FROM folders WHERE parent_id=?').all(fo.id)) walk(sub, nid, false);
  };
  for (const fo of srcFolders) walk(fo, to, true);
  const nFiles = plan.filter((p) => p.f).length, total = plan.reduce((a, p) => a + (p.f ? p.f.size : 0), 0);
  if (nFiles > 5000) throw new HttpError(413, 'Too many files in one copy (limit 5000)');
  if (diskFree() < total + 64 * 2 ** 20) throw new HttpError(507, 'Not enough free disk space to copy this');
  if (CFG.quota && usedBytes() + total > CFG.quota) throw new HttpError(507, 'Storage quota would be exceeded');
  const madeFiles = [], madeFolders = [];
  try {
    for (const p of plan) {
      if (p.folder) {
        const name = p.top ? uniqueName(p.parent, p.folder.name, 'folders') : p.folder.name;
        Q('INSERT INTO folders(id,name,parent_id,created) VALUES(?,?,?,?)').run(p.nid, name, p.parent, Date.now()); madeFolders.push(p.nid);
      } else {
        const f = p.f, nid = crypto.randomUUID(); madeFiles.push(nid);
        await fsp.copyFile(filePath(f.id), filePath(nid), fs.constants.COPYFILE_FICLONE); // same encrypted bytes; the copy gets its own record
        const nm = p.top ? uniqueName(p.parent, f.name) : f.name;
        Q('INSERT INTO files(id,name,ext,size,sha256,folder_id,wrapped_key,created) VALUES(?,?,?,?,?,?,?,?)').run(nid, nm, extOf(nm), f.size, f.sha256, p.parent, wrapKey(unwrapKey(f.wrapped_key, f.id), nid), Date.now());
      }
    }
  } catch (e) { // undo a half-finished copy
    for (const id of madeFiles) { try { removeFileNow(id); } catch {} try { fs.unlinkSync(filePath(id)); } catch {} }
    for (const id of madeFolders) Q('DELETE FROM folders WHERE id=?').run(id);
    throw e;
  }
  audit('copy', c, `${nFiles} files`); send(c.res, 200, { ok: true, files: nFiles, folders: madeFolders.length });
});

// === MAINTENANCE ===========================================================
function maintenance() {
  const now = Date.now();
  Q('DELETE FROM sessions WHERE last_seen<? OR created<?').run(now - CFG.idleMs, now - CFG.absMs);
  Q('DELETE FROM shares WHERE expires<?').run(now); Q('DELETE FROM share_items WHERE share_id NOT IN (SELECT id FROM shares)').run();
  for (const u of Q('SELECT id FROM uploads WHERE updated<?').all(now - CFG.staleUploadMs)) dropUpload(u.id);
  for (const [ip, f] of fails) if (now - f.last > 24 * 3600e3) fails.delete(ip);
  Q('DELETE FROM audit WHERE ts<? OR id<(SELECT COALESCE(MAX(id),0)-20000 FROM audit)').run(now - 180 * 86400e3);
}
function consistencyCheck() {
  const ids = new Set(Q('SELECT id FROM files').all().map((r) => r.id));
  const orphans = fs.readdirSync(path.join(CFG.dataDir, 'files')).filter((n) => !ids.has(n)), missing = [...ids].filter((i) => !fs.existsSync(filePath(i)));
  const live = new Set(Q('SELECT id FROM uploads').all().map((r) => r.id + '.part'));
  for (const n of fs.readdirSync(path.join(CFG.dataDir, 'uploads'))) if (!live.has(n)) try { fs.unlinkSync(path.join(CFG.dataDir, 'uploads', n)); } catch {}
  if (orphans.length) console.warn(`! ${orphans.length} stored file(s) have no database record (left untouched).`);
  if (missing.length) console.warn(`! ${missing.length} database record(s) point to missing files: ${missing.slice(0, 5).join(', ')}`);
}
if (EPHEMERAL) console.warn('\n!!! WARNING: the data folder (' + CFG.dataDir + ') is NOT on a persistent disk. On a cloud host, everything you upload will be DELETED when the service restarts.\n!!! Attach a persistent disk and point DATA_DIR at its mount path.\n');
consistencyCheck(); maintenance(); setInterval(maintenance, 3600e3).unref();

const server = http.createServer((req, res) => { handle(req, res).catch((e) => { console.error(e); try { res.destroy(); } catch {} }); });
server.requestTimeout = 30 * 60e3; server.headersTimeout = 30e3; server.keepAliveTimeout = 65e3;
server.listen(CFG.port, CFG.host, () => console.log(`VaultDrop listening on http://${CFG.host}:${CFG.port}  (data: ${CFG.dataDir})`));
const shutdown = () => { console.log('Shutting down…'); server.close(() => { try { db.close(); } catch {} process.exit(0); }); setTimeout(() => process.exit(0), 5000).unref(); };
process.on('SIGTERM', shutdown); process.on('SIGINT', shutdown);
process.on('uncaughtException', (e) => { console.error('Fatal:', e); process.exit(1); });
