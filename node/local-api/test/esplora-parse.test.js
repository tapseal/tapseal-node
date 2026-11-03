// Light mode reads raw blocks. Blocks built here with bitcoinjs (an independent implementation) must parse in
// indexer/esplora.py to the same txids, inputs, witnesses and outputs, with merkle and witness commitments checked.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { execFileSync } = require('child_process');
const crypto = require('crypto');
const { bitcoin } = require('../src/tapseal');

const PY = `
import sys, json
sys.path.insert(0, ${JSON.stringify(path.join(__dirname, '../../indexer'))})
from esplora import parse_block
try:
    b = parse_block(bytes.fromhex(sys.stdin.read().strip()), 7)
    print(json.dumps({"hash": b["hash"], "prev": b["previousblockhash"], "tx": [{"txid": t["txid"], "vin": [[v.get("txid"), v.get("vout"), v.get("txinwitness", [])] for v in t["vin"] if "txid" in v], "vout": [[o["sats"], o["scriptPubKey"]["hex"]] for o in t["vout"]]} for t in b["tx"]]}))
except ValueError as e:
    print(json.dumps({"error": str(e)}))
`;
const parse = (hex) => JSON.parse(execFileSync('python3', ['-c', PY], { input: hex, encoding: 'utf8' }));
const rnd = (n) => crypto.randomBytes(n);

function makeBlock({ withWitness = true } = {}) {
  const cb = new bitcoin.Transaction();
  cb.addInput(Buffer.alloc(32), 0xffffffff, 0xffffffff, Buffer.from('03070000', 'hex'));
  cb.addOutput(Buffer.concat([Buffer.from([0x51, 0x20]), rnd(32)]), 625000000);
  const txs = [cb];
  for (let i = 0; i < 6; i++) {
    const tx = new bitcoin.Transaction();
    tx.version = 2;
    tx.addInput(rnd(32), i, 0xfffffffd);
    if (i % 2) tx.addInput(rnd(32), 3, 0xffffffff, Buffer.from('47304402', 'hex'));     // legacy-looking scriptSig
    tx.addOutput(Buffer.concat([Buffer.from([0x6a, 0x08]), Buffer.from('TSL1'), rnd(4)]), 0);
    tx.addOutput(Buffer.concat([Buffer.from([0x51, 0x20]), rnd(32)]), 330 + i);
    tx.addOutput(Buffer.concat([Buffer.from([0x00, 0x14]), rnd(20)]), 123456789 * (i + 1));
    if (withWitness && i !== 2) tx.ins[0].witness = [rnd(64), rnd(40 + i), Buffer.concat([Buffer.from([0xc0]), rnd(32)])];
    txs.push(tx);
  }
  if (txs.some((t) => t.hasWitnesses())) {
    cb.ins[0].witness = [Buffer.alloc(32)];
    const commit = bitcoin.Block.calculateMerkleRoot(txs, true);
    cb.addOutput(Buffer.concat([Buffer.from('6a24aa21a9ed', 'hex'), commit]), 0);
  }
  const b = new bitcoin.Block();
  b.version = 0x20000000; b.prevHash = rnd(32); b.timestamp = 1700000000; b.bits = 0x207fffff; b.transactions = txs;
  b.merkleRoot = bitcoin.Block.calculateMerkleRoot(txs);
  for (b.nonce = 0; !b.checkProofOfWork(); b.nonce++);
  return b;
}

test('raw blocks built by bitcoinjs parse to the same transactions', () => {
  for (const withWitness of [true, false]) {
    const b = makeBlock({ withWitness });
    const got = parse(b.toHex());
    assert.ok(!got.error, got.error);
    assert.strictEqual(got.hash, b.getId());
    assert.strictEqual(got.prev, Buffer.from(b.prevHash).reverse().toString('hex'));
    assert.strictEqual(got.tx.length, b.transactions.length);
    b.transactions.forEach((tx, i) => {
      const g = got.tx[i];
      assert.strictEqual(g.txid, tx.getId());
      const ins = i === 0 ? [] : tx.ins.map((x) => [Buffer.from(x.hash).reverse().toString('hex'), x.index, x.witness.map((w) => w.toString('hex'))]);
      assert.deepStrictEqual(g.vin, ins);
      assert.deepStrictEqual(g.vout, tx.outs.map((o) => [o.value, o.script.toString('hex')]));
    });
  }
});

test('a changed witness or a changed payload is rejected', () => {
  const b = makeBlock();
  b.transactions[2].ins[0].witness[1] = rnd(41);                       // header and txids still match
  assert.match(parse(b.toHex()).error, /witness commitment/);
  const c = makeBlock();
  c.transactions[4].outs[0].script = Buffer.concat([Buffer.from([0x6a, 0x08]), Buffer.from('TSL1'), rnd(4)]);
  assert.match(parse(c.toHex()).error, /merkle/);
});
