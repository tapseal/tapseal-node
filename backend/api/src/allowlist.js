// Allowlist (whitelist) store and pass signer.
// The list lives in a JSON file that only the server command (scripts/allowlist.js) writes.
// Passes are signed on request with WL_SIGNING_KEY, the key named in the token's on-chain `allowlist` op.
// The key can only authorise allowlist mints within the reserve; it cannot move tokens, the treasury or authority.
const fs = require('fs');
const path = require('path');
const ts = require('./tapseal');

function store(file) {
  let cache = { mtime: -1, data: { version: 1, tokens: {} } };
  const read = () => {
    try {
      const st = fs.statSync(file);
      if (st.mtimeMs !== cache.mtime) cache = { mtime: st.mtimeMs, data: JSON.parse(fs.readFileSync(file, 'utf8')) };
    } catch (e) {
      if (e.code !== 'ENOENT') throw new Error('Allowlist file is unreadable: ' + e.message);
      cache = { mtime: -1, data: { version: 1, tokens: {} } };
    }
    return cache.data;
  };
  const write = (data) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o640 });
    fs.renameSync(tmp, file);
    cache.mtime = -1;
  };
  return {
    file,
    list: (tick) => read().tokens[tick] || { entries: {} },
    entry: (tick, ownerHex) => (read().tokens[tick]?.entries || {})[ownerHex] || null,
    count: (tick) => Object.keys(read().tokens[tick]?.entries || {}).length,
    put(tick, rows, replace = false) {
      const data = read();
      const t = data.tokens[tick] = replace ? { entries: {} } : data.tokens[tick] || { entries: {} };
      for (const r of rows) t.entries[r.owner] = { address: r.address, max: String(r.max), expiry: Number(r.expiry) };
      t.updated_at = Math.floor(Date.now() / 1000);
      write(data);
      return Object.keys(t.entries).length;
    },
    remove(tick, owners) {
      const data = read();
      const t = data.tokens[tick];
      if (!t) return 0;
      let n = 0;
      for (const o of owners) if (t.entries[o]) { delete t.entries[o]; n++; }
      t.updated_at = Math.floor(Date.now() / 1000);
      write(data);
      return n;
    },
  };
}

function signer(keyHex) {
  const key = String(keyHex || '').trim().toLowerCase();
  if (!key) return null;
  if (!/^[0-9a-f]{64}$/.test(key)) throw new Error('WL_SIGNING_KEY must be 64 hex characters.');
  const pub = ts.xonlyOf(key);
  return { pub, sign: (tick, ownerHex, max, expiry) => ts.signPass(key, tick, ownerHex, BigInt(max), Number(expiry)) };
}

module.exports = { store, signer };
