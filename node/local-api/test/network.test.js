// Network map: a mesh of real API instances, each checking its own peers; the map crawled from one node shows them
// all, the links between them, and which ones disagree, with node IDs merging duplicate URLs.
const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const express = require('express');
const Database = require('better-sqlite3');
const { createRouter } = require('../src/router');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tapseal-map-'));
const base = path.join(tmp, 'base.sqlite');
execFileSync('python3', [path.join(__dirname, 'fixture.py'), 'make11', base, '1f'.repeat(32)]);
const servers = [];
test.after(() => servers.forEach((s) => s.close()));

// Listen first (so every node knows the others' URLs), mount the router afterwards.
async function slot() {
  const app = express(); app.use(express.json());
  const s = http.createServer(app); await new Promise((r) => s.listen(0, '127.0.0.1', r)); servers.push(s);
  return { app, url: `http://127.0.0.1:${s.address().port}` };
}
function mount(n, id, peers, opts = {}) {
  const db = path.join(tmp, `${id}.sqlite`); fs.copyFileSync(base, db);
  if (opts.badRoot) { const d = new Database(db); d.prepare("update blocks set root = 'ee' || substr(root, 3)").run(); d.close(); }
  n.app.use('/api/tapseal', createRouter({ peerFetchImpl: fetch, dbPath: db, network: 'mainnet', mempoolApi: 'http://127.0.0.1:9', minServerUtxo: 10000, publicLaunch: true, ownerAddresses: [],
    platformFee: { sats: 0 }, rpc: {}, previewRequireRpc: false, peers, peerIntervalMs: 200, nodeId: id, publicUrl: n.url, mode: opts.mode, mapCacheMs: 0 }));
}

test('map of a mesh: every node, every link, agreement and a node that differs', async () => {
  const [A, B, C, D, E] = await Promise.all([slot(), slot(), slot(), slot(), slot()]);
  mount(A, 'node-a', [B.url, C.url]);
  mount(B, 'node-b', [A.url, D.url, B.url + '/']);          // lists itself under another spelling: ignored
  mount(C, 'node-c', [A.url, D.url, 'http://127.0.0.1:9']);  // one dead peer
  mount(D, 'node-d', [E.url], { mode: 'light' });
  mount(E, 'node-e', [], { badRoot: true });                // computes a different state
  await new Promise((r) => setTimeout(r, 900));              // let every node check its peers once
  const map = await (await fetch(A.url + '/api/tapseal/network?refresh=1')).json();
  const ids = map.nodes.map((n) => n.id).sort();
  assert.deepStrictEqual(ids.filter((i) => !i.startsWith('url:')), ['node-a', 'node-b', 'node-c', 'node-d', 'node-e']);
  assert.ok(ids.some((i) => i === 'url:http://127.0.0.1:9/api/tapseal'), 'dead peer shown as unreachable');
  const by = Object.fromEntries(map.nodes.map((n) => [n.id, n]));
  assert.strictEqual(by['node-a'].self, true);
  assert.strictEqual(by['node-d'].mode, 'light');
  assert.strictEqual(by['node-b'].matches, true); assert.strictEqual(by['node-d'].matches, true);
  assert.strictEqual(by['node-e'].matches, false);
  const link = (f, t) => map.edges.find((e) => e.from === f && e.to === t);
  assert.ok(link('node-a', 'node-b') && link('node-b', 'node-a') && link('node-b', 'node-d') && link('node-c', 'node-d'));
  assert.strictEqual(link('node-d', 'node-e').state, 'disagree');
  assert.strictEqual(link('node-a', 'node-c').state, 'agree');
  assert.ok(!map.edges.some((e) => e.from === e.to), 'no self loops');
  assert.deepStrictEqual({ differing: map.summary.differing, nodes: map.summary.nodes }, { differing: 1, nodes: 6 });
  const st = await (await fetch(D.url + '/api/tapseal/status')).json();
  assert.strictEqual(st.node_id, 'node-d'); assert.strictEqual(st.public_url, D.url);
});

test('the crawl is bounded', async () => {
  const nodes = await Promise.all(Array.from({ length: 6 }, slot));
  nodes.forEach((n, i) => mount(n, `chain-${i}`, i + 1 < nodes.length ? [nodes[i + 1].url] : []));
  await new Promise((r) => setTimeout(r, 600));
  const map = await (await fetch(nodes[0].url + '/api/tapseal/network?refresh=1')).json();
  assert.ok(map.nodes.length <= 5, `depth limit 4 from the start node, got ${map.nodes.length}`);
});
