'use strict';
// Encrypt site/<dir>/* into enc/ (AES-256-GCM, chunks <= 80 MB, deterministic blob names per content). Key: V_KEY or ~/.config/private-player/bundle.key (created 0600).
const crypto = require('node:crypto'), fs = require('node:fs'), os = require('node:os'), path = require('node:path');
const SRC = process.argv[2] || path.join(__dirname, 'site'), ENC = path.join(__dirname, 'enc'), CHUNK = 80 * 1024 * 1024;
const kp = path.join(os.homedir(), '.config', 'private-player', 'bundle.key');
let k = process.env.V_KEY; if (!k) { if (!fs.existsSync(kp)) { fs.mkdirSync(path.dirname(kp), { recursive: true, mode: 0o700 }); fs.writeFileSync(kp, crypto.randomBytes(32).toString('hex'), { mode: 0o600 }); } k = fs.readFileSync(kp, 'utf8').trim(); }
const key = Buffer.from(k, 'hex');
const enc = b => { const iv = crypto.randomBytes(12); const c = crypto.createCipheriv('aes-256-gcm', key, iv); const ct = Buffer.concat([c.update(b), c.final()]); return Buffer.concat([iv, c.getAuthTag(), ct]); };
fs.rmSync(ENC, { recursive: true, force: true }); fs.mkdirSync(ENC);
const man = {};
for (const dir of fs.readdirSync(SRC)) for (const f of fs.readdirSync(path.join(SRC, dir))) {
  const buf = fs.readFileSync(path.join(SRC, dir, f)); const sha = crypto.createHash('sha256').update(buf).digest('hex'); const blobs = [];
  for (let o = 0, i = 0; o < buf.length || i === 0; o += CHUNK, i++) { const name = crypto.createHash('sha256').update(sha + ':' + i).digest('hex').slice(0, 12) + '.bin'; fs.writeFileSync(path.join(ENC, name), enc(buf.subarray(o, o + CHUNK))); blobs.push(name); }
  man[`${dir}/${f}`] = { blobs, size: buf.length, sha256: sha };
}
fs.writeFileSync(path.join(ENC, 'manifest.bin'), enc(Buffer.from(JSON.stringify(man))));
console.log('packed', Object.keys(man).length, 'files');
