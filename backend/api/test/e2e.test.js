// End to end: indexed chain (Python) -> API builds PSBTs -> signed like UniSat -> replayed by the reference rules.
const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const express = require('express');
const { ECPairFactory } = require('ecpair');
const ts = require('../src/tapseal');
const { createRouter } = require('../src/router');

const { bitcoin, ecc } = ts;
const ECPair = ECPairFactory(ecc);
const NET = bitcoin.networks.bitcoin;
const FIX = path.join(__dirname, 'fixture.py');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tapseal-'));
const DB = path.join(tmp, 'tapseal.sqlite');

// The user's wallet, the way UniSat holds it: one BIP86 Taproot key.
const SK = Buffer.from('1f'.repeat(32), 'hex');
const user = ECPair.fromPrivateKey(SK, { network: NET });
const xOnly = user.publicKey.subarray(1);
const address = bitcoin.payments.p2tr({ internalPubkey: xOnly, network: NET }).address;
const tweaked = user.tweak(bitcoin.crypto.taggedHash('TapTweak', xOnly)); // what UniSat signs with for Taproot
const other = bitcoin.payments.p2tr({ internalPubkey: ECPair.makeRandom().publicKey.subarray(1), network: NET }).address;

const py = (...args) => JSON.parse(execFileSync('python3', ['-I', FIX, ...args], { encoding: 'utf8' }));
const fakeUtxos = (n = 1, value = 300000) => Array.from({ length: n }, (_, i) => ({ txid: (i + 1).toString(16).padStart(64, 'a'), vout: i, value }));

let base, rpcCalls = [], server, rpcServer;
test.before(async () => {
  const made = py('make', DB, SK.toString('hex'));
  assert.strictEqual(made.owner, tweaked.publicKey.subarray(1).toString('hex'), 'fixture owner = UniSat output key');
  rpcServer = http.createServer((req, res) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => {
    const j = JSON.parse(b); rpcCalls.push(j); const txid = bitcoin.Transaction.fromHex(j.params[0]).getId();
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ result: txid, error: null, id: j.id })); }); });
  await new Promise((r) => rpcServer.listen(0, r));
  const app = express(); app.use(express.json());
  app.use('/api/tapseal', createRouter({ dbPath: DB, network: 'mainnet', mempoolApi: 'http://127.0.0.1:9', minServerUtxo: 10000,
    publicLaunch: false, ownerAddresses: [address], featured: 'STONK', platformFee: { sats: 0 },
    rpc: { url: `http://127.0.0.1:${rpcServer.address().port}`, user: 'u', password: 'p' } }));
  server = app.listen(0); await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}/api/tapseal`;
});
test.after(() => { server.close(); rpcServer.close(); });

const get = (p) => fetch(base + p).then((r) => r.json());
const post = (p, body) => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json());

/** Sign exactly what UniSat would: every listed input with the tweaked Taproot key (key path or script path). */
function signLikeUniSat(built) {
  const psbt = bitcoin.Psbt.fromHex(built.psbt_hex, { network: NET });
  for (const { index, address: a } of built.sign_inputs) { assert.strictEqual(a, address); psbt.signInput(index, tweaked); }
  assert.ok(psbt.validateSignaturesOfAllInputs((pk, msg, sig) => ecc.verifySchnorr(msg, pk, sig)), 'schnorr signatures valid');
  psbt.finalizeAllInputs();
  return psbt;
}
function replay(psbt) {
  const tx = psbt.extractTransaction();
  const j = { txid: tx.getId(), vin: tx.ins.map((i) => ({ prevout: `${Buffer.from(i.hash).reverse().toString('hex')}:${i.index}`, witness: i.witness.map((w) => w.toString('hex')) })),
    vout: tx.outs.map((o) => ({ value: o.value, spk: o.script.toString('hex') })) };
  const f = path.join(tmp, `${j.txid}.json`); fs.writeFileSync(f, JSON.stringify(j));
  return { tx, out: py('apply', DB, f) };
}

test('read endpoints reflect the indexed chain', async () => {
  const st = await get('/status');
  assert.strictEqual(st.tip.height, 103); assert.strictEqual(st.node.lag, 0); assert.strictEqual(st.node.fees['1'], 5);
  const tk = await get('/tokens');
  const stonk = tk.tokens.find((t) => t.tick === 'STONK');
  assert.strictEqual(stonk.minted, String(50000n * 50000000n)); assert.strictEqual(stonk.state, 'live'); assert.strictEqual(stonk.price_sats, 2);
  const seals = await get(`/seals?address=${address}`);
  assert.deepStrictEqual(seals.seals.map((s) => [s.amt, s.lock]).sort((x, y) => x[1] - y[1]), [[String(40000n * 50000000n), 0], [String(10000n * 50000000n), 102]]);
  const q = await get('/tokens/STONK/quote?sats=200000');
  assert.strictEqual(q.atoms, String(150000n * 50000000n)); assert.strictEqual(q.capped, true);
});

test('mint: built by the API, signed like UniSat, counted exactly as quoted', async () => {
  const built = await post('/psbt/mint', { tick: 'STONK', address, public_key: user.publicKey.toString('hex'), pay_sats: 25000, fee_rate: 3, utxos: fakeUtxos() });
  assert.ok(built.ok, built.error);
  const { tx, out } = replay(signLikeUniSat(built));
  const mint = out.events.find((e) => e.kind === 'mint');
  assert.strictEqual(mint.amt, built.atoms);
  assert.deepStrictEqual(out.new_seals.map((s) => s.amt), [built.atoms]);
  const fee = 300000 - tx.outs.reduce((s, o) => s + o.value, 0);
  assert.strictEqual(fee, built.fee_sats);
  assert.ok(fee / tx.virtualSize() >= 2.9 && fee / tx.virtualSize() < 3.6, `fee rate ${fee / tx.virtualSize()}`);
});

test('fair mint and locked mint', async () => {
  const b1 = await post('/psbt/mint', { tick: 'FREE', address, public_key: user.publicKey.toString('hex'), fee_rate: 2, utxos: fakeUtxos() });
  assert.strictEqual(replay(signLikeUniSat(b1)).out.events[0].amt, '1000');
  const b2 = await post('/psbt/mint', { tick: 'STONK', address, public_key: user.publicKey.toString('hex'), pay_sats: 5000, lock: 200, fee_rate: 2, utxos: fakeUtxos() });
  assert.deepStrictEqual(replay(signLikeUniSat(b2)).out.new_seals.map((s) => s.lock), [200]);
});

test('transfer: spends seals by script path (incl. a locked one), nothing lost, balance conserved', async () => {
  const before = String(50000n * 50000000n);
  const built = await post('/psbt/transfer', { tick: 'STONK', address, public_key: user.publicKey.toString('hex'), fee_rate: 2, utxos: fakeUtxos(),
    recipients: [{ address: other, atoms: String(45000n * 50000000n) }, { address: other, atoms: '7', lock: 500 }] });
  assert.ok(built.ok, built.error);
  assert.strictEqual(built.seals_in.length, 2, 'needs the locked seal too');
  const psbt = signLikeUniSat(built);
  assert.strictEqual(psbt.locktime, 102);
  const { out } = replay(psbt);
  assert.deepStrictEqual(out.events.map((e) => e.kind), ['transfer', 'transfer', 'change']);
  assert.strictEqual(out.balance.STONK, before); assert.strictEqual(out.lost.STONK, '0');
  assert.deepStrictEqual(out.new_seals.map((s) => [s.amt, s.lock]), [[String(45000n * 50000000n), 0], ['7', 500], [built.change_atoms, 0]]);
});

test('burn', async () => {
  const built = await post('/psbt/burn', { tick: 'STONK', address, public_key: user.publicKey.toString('hex'), atoms: '123', fee_rate: 2, utxos: fakeUtxos() });
  const { out } = replay(signLikeUniSat(built));
  assert.deepStrictEqual(out.events.map((e) => [e.kind, e.amt]), [['burn', '123'], ['change', built.change_atoms]]);
});

test('deploy is owner-gated, then indexes as a valid deploy', async () => {
  const form = { tick: 'ORBIT', dec: 8, max_atoms: String(21000000n * 100000000n), mode: 'curve', p0: 500, p1: 3000, cap: 100000, start: 110, end: 2000, fee_rate: 2, utxos: fakeUtxos() };
  const denied = await post('/psbt/deploy', { ...form, address: other, public_key: '02' + '11'.repeat(32) });
  assert.match(denied.error, /owner wallet/);
  const built = await post('/psbt/deploy', { ...form, address, public_key: user.publicKey.toString('hex') });
  const { out } = replay(signLikeUniSat(built));
  assert.strictEqual(out.events[0].kind, 'deploy'); assert.ok(out.tokens.includes('ORBIT'));
});

test('errors are readable', async () => {
  const pk = user.publicKey.toString('hex');
  assert.match((await post('/psbt/mint', { tick: 'STONK', address, public_key: pk, pay_sats: 1e9, fee_rate: 2, utxos: fakeUtxos(1, 20000) })).error, /Reduce payment/);
  assert.match((await post('/psbt/mint', { tick: 'NOPE', address, public_key: pk, pay_sats: 1000, utxos: fakeUtxos() })).error, /Unknown ticker/);
  assert.match((await post('/psbt/transfer', { tick: 'STONK', address, public_key: pk, utxos: fakeUtxos(), recipients: [{ address: other, atoms: '1' + '0'.repeat(20) }] })).error, /Not enough unlocked STONK/);
  assert.match((await post('/psbt/mint', { tick: 'STONK', address, public_key: '02' + '22'.repeat(32), pay_sats: 1000, utxos: fakeUtxos() })).error, /does not match/);
});

test('broadcast finalizes, sends to the node, and shows up in the mempool view', async () => {
  const built = await post('/psbt/mint', { tick: 'STONK', address, public_key: user.publicKey.toString('hex'), pay_sats: 1000, fee_rate: 2, utxos: fakeUtxos() });
  const psbt = bitcoin.Psbt.fromHex(built.psbt_hex, { network: NET });
  for (const { index } of built.sign_inputs) psbt.signInput(index, tweaked); // not finalized: the API must finalize
  const res = await post('/broadcast', { psbt: psbt.toHex() });
  assert.ok(res.ok, res.error);
  assert.strictEqual(rpcCalls.at(-1).method, 'sendrawtransaction');
  const mp = await get('/mempool');
  assert.ok(mp.ops.some((o) => o.txid === res.txid && o.kind === 'mint' && o.tick === 'STONK'));
});


test('pending mint readout reports detected demand and partial coverage', async () => {
  const q = await get('/tokens/STONK/pending?sats=1000');
  assert.strictEqual(q.ok, true);
  assert.strictEqual(q.coverage, 'partial');
  assert.ok(q.pending_mints >= 1);
  assert.ok(BigInt(q.pending_requested_atoms) > 0n);
  assert.strictEqual(BigInt(q.remaining_atoms) - BigInt(q.pending_requested_atoms), BigInt(q.estimated_available_atoms));
  const bad = await get('/tokens/STONK/pending?sats=-1');
  assert.strictEqual(bad.ok, false);
});
