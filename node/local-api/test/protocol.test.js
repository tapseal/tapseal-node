const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const ts = require('../src/tapseal');

const vec = require(path.join(__dirname, '../../protocol/vectors.json'));

const revive = (op) => JSON.parse(JSON.stringify(op), (k, v) => (['max', 'amt', 'rate', 'lim'].includes(k) && typeof v === 'number' ? BigInt(v) : v));

test('payload vectors match the Python reference byte for byte', () => {
  for (const p of vec.payloads) assert.strictEqual(ts.encode(revive(p.op)).toString('hex'), p.hex, p.op.op);
});

test('commitments and seal output keys match the vectors', () => {
  assert.strictEqual(ts.tokenCommitment('STONK').toString('hex'), vec.token_commitment_STONK);
  assert.strictEqual(ts.authCommitment('STONK').toString('hex'), vec.auth_commitment_STONK);
  for (const s of vec.seal) {
    const out = ts.seal('STONK', Buffer.from(vec.owner_xonly, 'hex'), { lock: s.lock });
    assert.strictEqual(out.leaf.toString('hex'), s.leaf);
    assert.strictEqual(out.script.subarray(2).toString('hex'), s.output_key);
  }
});

test('curve math matches the vector', () => {
  const c = vec.curve;
  assert.strictEqual(ts.curveAtoms(c.paid_sats, c.minted, BigInt(c.max), c.dec, c.p0, c.p1).toString(), String(c.atoms));
});

test('quoteMint caps and partially fills like the indexer', () => {
  const tok = { mode: 'fixed', dec: 8, max: 15000n, minted: 10000n, params: { rate: '10', cap: '300' } };
  const q0 = ts.quoteMint(tok, 1000);
  assert.deepStrictEqual([q0.atoms, q0.counted, q0.capped, q0.partial], [3000n, 300n, true, false]);
  const q = ts.quoteMint({ ...tok, minted: 14000n }, 200);
  assert.strictEqual(q.atoms, 1000n); assert.strictEqual(q.partial, true);
});

test('ownerOfAddress rejects non-Taproot and wrong-network addresses', () => {
  assert.throws(() => ts.ownerOfAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'mainnet'), /Taproot/);
  assert.throws(() => ts.ownerOfAddress('bc1przuh246ssla42m36k6nq7v7va8r9c73awh5el07sh2d7mf6cv40q5qjg69', 'testnet'), /not on testnet/);
  assert.strictEqual(ts.ownerOfAddress('bc1przuh246ssla42m36k6nq7v7va8r9c73awh5el07sh2d7mf6cv40q5qjg69', 'mainnet').length, 32);
});

test('vectors: every payload, including 1.1 extensions, encodes byte for byte', () => {
  for (const p of vec.payloads) {
    const op = JSON.parse(JSON.stringify(p.op));
    for (const k of ['max', 'rate', 'cap', 'amt', 'lim', 'wallet_cap', 'reserve']) if (op[k] != null) op[k] = BigInt(op[k]);
    if (op.pass) op.pass.max = BigInt(op.pass.max);
    if (op.edicts) op.edicts = op.edicts.map((e) => ({ ...e, amt: BigInt(e.amt) }));
    assert.strictEqual(ts.encode(op).toString('hex'), p.hex, p.op.op);
  }
});

test('allowlist passes: historical allowlist signature verifies and rejects altered allocation', () => {
  const a = vec.allowlist;
  assert.strictEqual(ts.passMessage(a.tick, a.owner, BigInt(a.max), a.expiry).toString('hex'), a.message);
  assert.ok(ts.verifyPass(a.signer_xonly, a.tick, a.owner, BigInt(a.max), a.expiry, a.sig));
  assert.ok(!ts.verifyPass(a.signer_xonly, a.tick, a.owner, BigInt(a.max) + 1n, a.expiry, a.sig));
});

test('quoteMint mirrors the 1.1 rules: reserve, allowlist price, pass and wallet limits', () => {
  const tok = { mode: 'fixed', dec: 0, max: 1000n, minted: 0n, params: { rate: '1', cap: '0' }, wallet_cap: 0n,
    wl: { key: 'k', price: 2n, reserve: 400n, end: 200 }, wl_minted: 0n };
  let q = ts.quoteMint(tok, 900, { height: 150 });
  assert.deepStrictEqual([q.atoms, q.limited_by], [600n, 'reserve']);
  q = ts.quoteMint(tok, 100, { height: 150, allowlist: { max: 300n, used: 0n } });
  assert.deepStrictEqual([q.atoms, q.limited_by], [200n, null]);
  q = ts.quoteMint(tok, 500, { height: 150, allowlist: { max: 300n, used: 250n } });
  assert.deepStrictEqual([q.atoms, q.limited_by], [50n, 'pass']);
  q = ts.quoteMint(tok, 900, { height: 201 });
  assert.deepStrictEqual([q.atoms, q.limited_by], [900n, null]);
  q = ts.quoteMint({ ...tok, wl: null, wallet_cap: 30n }, 100, { height: 150, walletUsed: 20n });
  assert.deepStrictEqual([q.atoms, q.limited_by], [10n, 'wallet']);
  const curve = { mode: 'curve', dec: 8, max: 10n ** 15n, minted: 0n, params: { p0: '500', p1: '3000', cap: '0' }, wl: { price: 2000n, reserve: 10n ** 14n, end: 300 }, wl_minted: 0n };
  q = ts.quoteMint(curve, 80000, { height: 150, allowlist: { max: 10n ** 14n, used: 0n } });
  assert.strictEqual(q.atoms, ts.curveAtoms(100000, 0n, 10n ** 15n, 8, 500, 3000));
});
