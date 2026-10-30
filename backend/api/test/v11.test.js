// Protocol 1.1 through the API: allowlist settings, allowlist passes, wallet limits and token IDs.
// Every transaction is built by the API, signed the way UniSat signs, then counted by the Python reference rules.
const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const express = require('express');
const { ECPairFactory } = require('ecpair');
const ts = require('../src/tapseal');
const { createRouter } = require('../src/router');
const allow = require('../src/allowlist');

const { bitcoin, ecc } = ts;
const ECPair = ECPairFactory(ecc);
const NET = bitcoin.networks.bitcoin;
const FIX = path.join(__dirname, 'fixture.py');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tapseal-v11-'));
const DB = path.join(tmp, 'tapseal.sqlite');
const LIST = path.join(tmp, 'allowlist.json');
const WL_KEY = 'ab'.repeat(32);
const SK = Buffer.from('1f'.repeat(32), 'hex');
const user = ECPair.fromPrivateKey(SK, { network: NET });
const xOnly = user.publicKey.subarray(1);
const address = bitcoin.payments.p2tr({ internalPubkey: xOnly, network: NET }).address;
const tweaked = user.tweak(bitcoin.crypto.taggedHash('TapTweak', xOnly));
const py = (...args) => JSON.parse(execFileSync('python3', [FIX, ...args], { encoding: 'utf8' }));
const utxos = () => [{ txid: 'c'.repeat(64), vout: 0, value: 500000 }];
const pk = user.publicKey.toString('hex');

let base, server;
test.before(async () => {
  py('make11', DB, SK.toString('hex'));
  const app = express(); app.use(express.json());
  app.use('/api/tapseal', createRouter({ dbPath: DB, network: 'mainnet', mempoolApi: 'http://127.0.0.1:9', minServerUtxo: 10000,
    publicLaunch: true, ownerAddresses: [], featured: 'WLT', platformFee: { sats: 0 }, rpc: {}, allowlistFile: LIST, wlSigningKey: WL_KEY, previewRequireRpc: false }));
  server = app.listen(0); await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}/api/tapseal`;
});
test.after(() => server.close());
const get = (p) => fetch(base + p).then((r) => r.json());
const post = (p, body) => fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json());
function sign(built) {
  assert.ok(built.ok, built.error);
  const psbt = bitcoin.Psbt.fromHex(built.psbt_hex, { network: NET });
  for (const { index } of built.sign_inputs) psbt.signInput(index, tweaked);
  psbt.finalizeAllInputs();
  const tx = psbt.extractTransaction();
  const j = { txid: tx.getId(), vin: tx.ins.map((i) => ({ prevout: `${Buffer.from(i.hash).reverse().toString('hex')}:${i.index}`, witness: i.witness.map((w) => w.toString('hex')) })),
    vout: tx.outs.map((o) => ({ value: o.value, spk: o.script.toString('hex') })) };
  const f = path.join(tmp, `${j.txid}.json`); fs.writeFileSync(f, JSON.stringify(j));
  return { f, tx };
}
const apply = (f) => py('apply', DB, f);
const confirm = (f) => py('confirm', DB, f);

test('token IDs and wallet limit appear in the token view', async () => {
  const t = await get('/tokens/CAPPED');
  assert.strictEqual(t.token.id, '101:0');
  assert.strictEqual(t.token.wallet_cap, '30');
  const byId = await get('/tokens/id/100/0');
  assert.strictEqual(byId.token.tick, 'WLT');
});

test('wallet limit: two mints fit, the third is refused before signing', async () => {
  for (let i = 0; i < 3; i++) {
    const w = await get(`/allowlist/CAPPED/${address}`);
    assert.strictEqual(w.wallet_left, String(30 - 10 * i));
    const built = await post('/psbt/mint', { tick: 'CAPPED', address, public_key: pk, fee_rate: 2, utxos: utxos() });
    assert.ok(built.ok && built.owner_named, built.error);
    const { f } = sign(built);
    const ev = confirm(f).events;
    assert.deepStrictEqual(ev.map((e) => [e.kind, e.amt]), [['mint', '10']]);
  }
  const refused = await post('/psbt/mint', { tick: 'CAPPED', address, public_key: pk, fee_rate: 2, utxos: utxos() });
  assert.strictEqual(refused.ok, false);
  assert.match(refused.error, /mint limit/);
});

test('allowlist settings: built by the API, spends and re-creates the authority seal', async () => {
  const st = await get('/allowlist/WLT');
  assert.strictEqual(st.signer_key, ts.xonlyOf(WL_KEY));
  const built = await post('/psbt/allowlist', { tick: 'WLT', address, public_key: pk, fee_rate: 2, utxos: utxos(), price: 2, reserve: 400000, end: 200 });
  const { f } = sign(built);
  const out = apply(f);
  assert.deepStrictEqual(out.events.map((e) => e.kind), ['allowlist']);
  assert.ok(out.new_seals.some((s) => s.auth), 'authority seal re-created');
  assert.strictEqual(out.wl.WLT.end, 200);
  confirm(f);
  const t = (await get('/tokens/WLT')).token;
  assert.strictEqual(t.allowlist.active, true);
  assert.strictEqual(t.allowlist.reserve_left, '400000');
  assert.strictEqual(t.public_left, '600000');
});

test('allowlist pass: listed wallet mints at the lower price; public mints stop at the reserve', async () => {
  const notListed = await get(`/allowlist/WLT/${address}`);
  assert.strictEqual(notListed.allowlist.listed, false);
  allow.store(LIST).put('WLT', [{ owner: ts.ownerOfAddress(address, 'mainnet').toString('hex'), address, max: 50000n, expiry: 190 }]);
  const w = await get(`/allowlist/WLT/${address}`);
  assert.deepStrictEqual([w.allowlist.listed, w.allowlist.active, w.allowlist.left], [true, true, '50000']);
  const q = await get(`/tokens/WLT/quote?sats=10000&address=${address}`);
  assert.deepStrictEqual([q.atoms, q.allowlist], ['20000', true]);
  const built = await post('/psbt/mint', { tick: 'WLT', address, public_key: pk, pay_sats: 10000, fee_rate: 2, utxos: utxos(), allowlist: true });
  assert.ok(built.allowlist);
  const { f, tx } = sign(built);
  assert.ok(tx.outs[0].script.length > 80, 'pass mint payload is larger than 80 bytes');
  const ev = confirm(f).events;
  assert.deepStrictEqual(ev.map((e) => [e.kind, e.amt]), [['mint', '20000']]);
  const after = await get(`/allowlist/WLT/${address}`);
  assert.strictEqual(after.allowlist.used, '20000');
  const tooMuch = await post('/psbt/mint', { tick: 'WLT', address, public_key: pk, pay_sats: 20000, fee_rate: 2, utxos: utxos(), allowlist: true });
  assert.match(tooMuch.error, /allowlist allowance/);
  const pub = await post('/psbt/mint', { tick: 'WLT', address, public_key: pk, pay_sats: 700000, fee_rate: 2, utxos: [{ txid: 'd'.repeat(64), vout: 0, value: 900000 }], allowlist: false });
  assert.match(pub.error, /reserved for the allowlist/);
});

test('protocol preview accepts a pass mint only when the request says it uses the allowlist', async () => {
  const built = await post('/psbt/mint', { tick: 'WLT', address, public_key: pk, pay_sats: 5000, fee_rate: 2, utxos: utxos(), allowlist: true });
  assert.ok(built.ok, built.error);
  const expected = { tick: 'WLT', pay_sats: 5000, op: 'mint', atoms: built.atoms, allowlist: true };
  const ok = await post('/transactions/simulate', { psbt: built.psbt_hex, owners: [address], expected });
  assert.strictEqual(ok.valid, true, JSON.stringify(ok.errors));
  assert.strictEqual(ok.effects.created[0].atoms, '10000');
  const sneaky = await post('/transactions/simulate', { psbt: built.psbt_hex, owners: [address], expected: { ...expected, allowlist: false } });
  assert.strictEqual(sneaky.valid, false);
});
