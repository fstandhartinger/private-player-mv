'use strict';
// Private video player behind secret path prefixes. Media live only as AES-256-GCM blobs in enc/.
// Env: V_KEY (64 hex), V_PATHS="/v/<secret>/=a,...", PORT.
const crypto = require('node:crypto'), fs = require('node:fs'), fsp = require('node:fs/promises');
const http = require('node:http'), os = require('node:os'), path = require('node:path');
const ROOT = __dirname, ENC = path.join(ROOT, 'enc'), PLAIN = path.join(os.tmpdir(), 'private-player');
const PORT = Number(process.env.PORT || '8080');
const HDR = { 'X-Robots-Tag': 'noindex, nofollow, noarchive', 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' };

function key() {
  let v = process.env.V_KEY;
  if (!v) { try { v = fs.readFileSync(path.join(os.homedir(), '.config', 'private-player', 'bundle.key'), 'utf8'); } catch { throw new Error('V_KEY required'); } }
  v = String(v).trim(); if (!/^[a-f0-9]{64}$/i.test(v)) throw new Error('V_KEY must be 64 hex chars'); return Buffer.from(v, 'hex');
}
function paths() {
  const m = new Map();
  for (const part of String(process.env.V_PATHS || '').split(',').filter(Boolean)) {
    const [p, dir] = part.split('=');
    if (!/^\/v\/[A-Za-z0-9_-]{16,}\/$/.test(p) || !/^[a-z]$/.test(dir || '')) throw new Error('bad V_PATHS entry');
    m.set(p, dir);
  }
  if (!m.size) throw new Error('V_PATHS required'); return m;
}
function decrypt(b, k) { const d = crypto.createDecipheriv('aes-256-gcm', k, b.subarray(0, 12)); d.setAuthTag(b.subarray(12, 28)); return Buffer.concat([d.update(b.subarray(28)), d.final()]); }
const okName = n => typeof n === 'string' && /^[a-z]\/[A-Za-z0-9._-]+$/.test(n);
async function unpack(k) {
  await fsp.rm(PLAIN, { recursive: true, force: true }); await fsp.mkdir(PLAIN, { recursive: true, mode: 0o700 });
  const man = JSON.parse(decrypt(await fsp.readFile(path.join(ENC, 'manifest.bin')), k).toString('utf8'));
  for (const [name, it] of Object.entries(man)) {
    if (!okName(name) || !Array.isArray(it.blobs) || !it.blobs.every(b => /^[a-f0-9]{12}\.bin$/.test(b)) || !/^[a-f0-9]{64}$/.test(it.sha256)) throw new Error('bad manifest entry');
    const target = path.join(PLAIN, name); await fsp.mkdir(path.dirname(target), { recursive: true, mode: 0o700 });
    const h = crypto.createHash('sha256'); const fd = await fsp.open(target, 'w', 0o600); let size = 0;
    for (const b of it.blobs) { const plain = decrypt(await fsp.readFile(path.join(ENC, b)), k); h.update(plain); size += plain.length; await fd.write(plain); }
    await fd.close();
    if (size !== it.size || h.digest('hex') !== it.sha256) throw new Error('integrity check failed for ' + name);
  }
}
const MIME = { '.html': 'text/html; charset=utf-8', '.mp4': 'video/mp4', '.jpg': 'image/jpeg', '.png': 'image/png', '.svg': 'image/svg+xml', '.css': 'text/css; charset=utf-8', '.woff2': 'font/woff2', '.vtt': 'text/vtt; charset=utf-8' };
function text(res, code, body, extra = {}) { const b = Buffer.from(body); res.writeHead(code, { ...HDR, 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': b.length, 'Cache-Control': 'no-store', ...extra }); res.end(b); }
function range(v, size) {
  if (!v) return null; const m = /^bytes=(\d*)-(\d*)$/.exec(v.trim()); if (!m || (!m[1] && !m[2])) return false;
  let s, e; if (!m[1]) { const n = Number(m[2]); if (!(n > 0)) return false; s = Math.max(0, size - n); e = size - 1; }
  else { s = Number(m[1]); e = m[2] ? Number(m[2]) : size - 1; if (s > e || s >= size) return false; e = Math.min(e, size - 1); }
  return { s, e };
}
async function serve(req, res, file) {
  let st; try { st = await fsp.stat(file); } catch { return text(res, 404, 'not found'); } if (!st.isFile()) return text(res, 404, 'not found');
  const type = MIME[path.extname(file)] || 'application/octet-stream';
  const h = { ...HDR, 'Content-Type': type, 'Cache-Control': type === 'video/mp4' ? 'private, max-age=3600' : 'no-cache', 'Accept-Ranges': type === 'video/mp4' ? 'bytes' : 'none' };
  if (type.startsWith('text/html')) h['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; media-src 'self'; img-src 'self' data:; frame-ancestors 'none'";
  const r = type === 'video/mp4' && req.method === 'GET' ? range(req.headers.range, st.size) : null;
  if (r === false) return text(res, 416, 'range not satisfiable', { 'Content-Range': 'bytes */' + st.size });
  if (r) { h['Content-Length'] = r.e - r.s + 1; h['Content-Range'] = `bytes ${r.s}-${r.e}/${st.size}`; res.writeHead(206, h); return fs.createReadStream(file, { start: r.s, end: r.e }).pipe(res); }
  h['Content-Length'] = st.size; res.writeHead(200, h); if (req.method === 'HEAD') return res.end(); fs.createReadStream(file).pipe(res);
}
(async () => {
  const k = key(), P = paths(); await unpack(k);
  http.createServer(async (req, res) => {
    try {
      if (req.method !== 'GET' && req.method !== 'HEAD') return text(res, 404, 'not found');
      const p = new URL(req.url, 'http://x').pathname;
      if (p === '/healthz') return text(res, 200, 'ok');
      if (p === '/robots.txt') return text(res, 200, 'User-agent: *\nDisallow: /\n');
      for (const [prefix, dir] of P) {
        if (p === prefix.slice(0, -1)) { res.writeHead(301, { ...HDR, Location: prefix }); return res.end(); }
        if (!p.startsWith(prefix)) continue;
        let rel = decodeURIComponent(p.slice(prefix.length)) || 'index.html';
        if (!/^[A-Za-z0-9._-]+$/.test(rel)) return text(res, 404, 'not found');
        return serve(req, res, path.join(PLAIN, dir, rel));
      }
      return text(res, 404, 'not found');
    } catch (e) { if (!res.headersSent) text(res, 500, 'error'); }
  }).listen(PORT, () => console.log('listening on', PORT));
})().catch(e => { console.error('startup failed:', e.message); process.exit(1); });
