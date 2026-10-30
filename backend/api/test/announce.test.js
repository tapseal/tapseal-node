// Home nodes (not reachable from outside) check in with their peers. The peer verifies the reported root, lists the
// node for a while, and shows it on its network map. Fake reports are flagged; the table is bounded.
const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const Database = require('better-sqlite3');
const { createRouter } = require('../src/router');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tapseal-announce-'));
const base = path.join(tmp, 'base.sqlite');
execFileSync('python3', [path.join(__dirname, 'fixture.py'), 'make11', base, '1f'.repeat(32)]);
const servers = [];
test.after(() => servers.forEach((s) => s.close()));
async function node(name, extra = {}) {
  const db = path.join(tmp, `${name}.sqlite`); fs.copyFileSync(base, db);
  const app = express(); app.set('trust proxy', true); app.use(express.json());
  app.use('/api/tapseal', createRouter({ peerFetchImpl: fetch, dbPath: db, network: 'mainnet', mempoolApi: 'http://127.0.0.1:9', minServerUtxo: 10000, publicLaunch: true, ownerAddresses: [],
    platformFee: { sats: 0 }, rpc: {}, previewRequireRpc: false, peerIntervalMs: 200, mapCacheMs: 0, ...extra }));
  const s = app.listen(0); await new Promise((r) => s.once('listening', r)); servers.push(s);
  return { url: `http://127.0.0.1:${s.address().port}`, db };
}
const post = (url, body, ip = '10.0.0.1') => fetch(url + '/api/tapseal/announce', { method: 'POST', headers: { 'content-type': 'application/json', 'x-forwarded-for': ip }, body: JSON.stringify(body) });
const tipOf = (db) => { const d = new Database(db, { readonly: true }); const r = d.prepare('select height, hash, root from blocks order by height desc limit 1').get(); d.close(); return r; };

test('a home node checks in, is verified and appears on the seed\'s map', async () => {
  const seed = await node('seed', { nodeId: 'aaaaaaaaaaaaaaaa', mode: 'light' });
  const home = await node('home', { nodeId: 'bbbbbbbbbbbbbbbb', peers: [seed.url], mode: 'light' });
  let p;
  for (let i = 0; i < 40; i++) { p = await (await fetch(seed.url + '/api/tapseal/peers')).json(); if (p.announced.length) break; await new Promise((r) => setTimeout(r, 50)); }
  assert.strictEqual(p.announced.length, 1);
  assert.deepStrictEqual({ id: p.announced[0].id, matches: p.announced[0].matches, mode: p.announced[0].mode }, { id: 'bbbbbbbbbbbbbbbb', matches: true, mode: 'light' });
  assert.ok(!('ip' in p.announced[0]), 'addresses are never published');
  const hp = await (await fetch(home.url + '/api/tapseal/peers')).json();
  assert.strictEqual(Object.values(hp.checkins)[0].ok, true);
  const map = await (await fetch(seed.url + '/api/tapseal/network?refresh=1')).json();
  const h = map.nodes.find((n) => n.id === 'bbbbbbbbbbbbbbbb');
  assert.ok(h && h.outbound && h.matches === true);
  assert.ok(map.edges.some((e) => e.from === 'bbbbbbbbbbbbbbbb' && e.to === 'aaaaaaaaaaaaaaaa' && e.state === 'agree'));
  assert.strictEqual(map.summary.home, 1);
});

test('a report with the wrong root is flagged; bad input and floods are refused', async () => {
  const seed = await node('seed2', { nodeId: 'cccccccccccccccc' });
  const t = tipOf(seed.db);
  const fake = await (await post(seed.url, { node_id: 'dddddddddddddddd', network: 'mainnet', height: t.height, hash: t.hash, root: 'ab'.repeat(32) })).json();
  assert.strictEqual(fake.matches, false);
  const map = await (await fetch(seed.url + '/api/tapseal/network?refresh=1')).json();
  assert.strictEqual(map.nodes.find((n) => n.id === 'dddddddddddddddd').matches, false);
  assert.strictEqual((await post(seed.url, { node_id: 'eeeeeeeeeeeeeeee', network: 'signet', height: 1, hash: 'a'.repeat(64), root: 'b'.repeat(64) })).status, 409);
  assert.strictEqual((await post(seed.url, { node_id: 'not-hex', network: 'mainnet', height: 1, hash: 'a'.repeat(64), root: 'b'.repeat(64) })).status, 400);
  const codes = [];
  for (const id of ['1111111111111111', '2222222222222222', '3333333333333333', '4444444444444444', '5555555555555555'])
    codes.push((await post(seed.url, { node_id: id, network: 'mainnet', height: t.height, hash: t.hash, root: t.root }, '10.9.9.9')).status);
  assert.deepStrictEqual(codes, [200, 200, 200, 200, 429]);
});
