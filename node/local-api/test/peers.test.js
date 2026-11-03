// Peer agreement between real API instances over HTTP, and a light node's read-only behaviour.
const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const Database = require('better-sqlite3');
const { createRouter } = require('../src/router');

const FIX = path.join(__dirname, 'fixture.py');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tapseal-peers-'));
const base = path.join(tmp, 'base.sqlite');
execFileSync('python3', [FIX, 'make11', base, '1f'.repeat(32)]);
const copy = (name) => { const f = path.join(tmp, name); fs.copyFileSync(base, f); return f; };

const servers = [];
async function node(dbPath, extra = {}) {
  const app = express(); app.use(express.json());
  app.use('/api/tapseal', createRouter({ peerFetchImpl: fetch, dbPath, network: extra.network || 'mainnet', mempoolApi: 'http://127.0.0.1:9', minServerUtxo: 10000, publicLaunch: true,
    ownerAddresses: [], platformFee: { sats: 0 }, rpc: {}, previewRequireRpc: false, peerCheck: false, ...extra }));
  const s = app.listen(0); await new Promise((r) => s.once('listening', r)); servers.push(s);
  return `http://127.0.0.1:${s.address().port}`;
}
test.after(() => servers.forEach((s) => s.close()));

test('nodes with the same state agree; a changed root, another network and a dead peer are reported', async () => {
  const a = await node(copy('a.sqlite'));
  const b = await node(copy('b.sqlite'));
  const badDb = copy('bad.sqlite');
  const d = new Database(badDb); d.prepare("update blocks set root = 'ff' || substr(root, 3) where height = (select max(height) from blocks)").run(); d.close();
  const bad = await node(badDb);
  const other = await node(copy('o.sqlite'), { network: 'signet' });
  const me = await node(copy('me.sqlite'), { peers: [a, b + '/api/tapseal', bad, other, 'http://127.0.0.1:9'], peerCheck: true, peerIntervalMs: 3_600_000 });
  let p;
  for (let i = 0; i < 40; i++) { p = await (await fetch(me + '/api/tapseal/peers')).json(); if (p.summary.checked_at) break; await new Promise((r) => setTimeout(r, 50)); }
  const by = Object.fromEntries(p.peers.map((x) => [x.url.replace('/api/tapseal', ''), x]));
  assert.strictEqual(by[a].state, 'agree'); assert.strictEqual(by[b].state, 'agree');
  assert.strictEqual(by[bad].state, 'disagree'); assert.match(by[bad].reason, /state root differs/);
  assert.strictEqual(by[other].state, 'other-network');
  assert.strictEqual(by['http://127.0.0.1:9'].state, 'unreachable');
  assert.deepStrictEqual({ peers: p.summary.peers, agree: p.summary.agree, disagree: p.summary.disagree, state: p.summary.state }, { peers: 5, agree: 2, disagree: 1, state: 'disagree' });
  const st = await (await fetch(me + '/api/tapseal/status')).json();
  assert.strictEqual(st.consensus.agree, 2); assert.strictEqual(st.mode, 'full');
});

test('roots are served per block', async () => {
  const a = await node(copy('r.sqlite'));
  const r = await (await fetch(a + '/api/tapseal/root/101')).json();
  assert.ok(r.ok); assert.strictEqual(r.height, 101); assert.match(r.root, /^[0-9a-f]{64}$/);
  assert.strictEqual((await fetch(a + '/api/tapseal/root/5')).status, 404);
});

test('a light node serves reads and refuses every write', async () => {
  const l = await node(copy('l.sqlite'), { mode: 'light' });
  const st = await (await fetch(l + '/api/tapseal/status')).json();
  assert.strictEqual(st.mode, 'light'); assert.strictEqual(st.read_only, true);
  assert.ok((await (await fetch(l + '/api/tapseal/tokens')).json()).tokens.length >= 2);
  for (const p of ['/psbt/mint', '/psbt/transfer', '/transactions/simulate', '/broadcast']) {
    const res = await fetch(l + '/api/tapseal' + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    assert.strictEqual(res.status, 503); assert.match((await res.json()).error, /Node-only API/);
  }
});
