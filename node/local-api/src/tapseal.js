// TAPSEAL protocol helpers for Node: wire encoder, seal scripts/addresses, pricing.
// Mirrors protocol/tapseal.py; test/protocol.test.js checks it against protocol/vectors.json.
const crypto = require('crypto');
const bitcoin = require('bitcoinjs-lib');
const ecc = require('@bitcoinerlab/secp256k1');

bitcoin.initEccLib(ecc);

const MAGIC = Buffer.from('TSL1', 'ascii');
const OPS = { deploy: 1, mint: 2, transfer: 3, burn: 4, meta: 5, allowlist: 6, operator: 7 };
const BPS = 10000n;
const MODES = { fixed: 0, curve: 1, fair: 2, lots: 3 };
const NUMS = Buffer.from('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0', 'hex');
const LEAF_VERSION = 0xc0;
const TICK_RE = /^[A-Z0-9]{1,8}$/;
const SEAL_SATS = 330;

const B = (v) => BigInt(v);

function varint(n) {
  n = B(n);
  if (n < 0n) throw new Error('negative varint');
  const out = [];
  do { const b = Number(n & 0x7fn); n >>= 7n; out.push(n ? b | 0x80 : b); } while (n);
  return out;
}
function tickBytes(t) {
  if (!TICK_RE.test(t)) throw new Error('Ticker must be 1-8 characters A-Z or 0-9');
  return [t.length, ...Buffer.from(t, 'ascii')];
}
const opt = (v) => varint(v == null ? 0 : B(v) + 1n);
function x32(k) { const b = Buffer.isBuffer(k) ? k : Buffer.from(String(k), 'hex'); if (b.length !== 32) throw new Error('Expected a 32-byte x-only key'); return [...b]; }

function encode(op) {
  const o = [...MAGIC, OPS[op.op]];
  if (!OPS[op.op]) throw new Error(`unknown op ${op.op}`);
  if (op.op === 'deploy') {
    const win = !!(op.start || op.end), auth = op.auth_vout != null, wcap = !!(op.wallet_cap && B(op.wallet_cap) > 0n);
    o.push((auth ? 1 : 0) | (win ? 2 : 0) | (wcap ? 4 : 0) | (op.pow ? 8 : 0), ...tickBytes(op.tick), op.dec, ...varint(op.max), MODES[op.mode]);
    if (op.mode === 'fixed') o.push(...varint(op.rate), ...varint(op.cap || 0), ...varint(op.treasury_vout));
    else if (op.mode === 'curve') o.push(...varint(op.p0), ...varint(op.p1), ...varint(op.cap || 0), ...varint(op.treasury_vout));
    else if(op.mode==='lots'){if(op.profile!==undefined&&op.profile!==1)throw Error('Unsupported lot profile');o.push(1,...varint(op.treasury_vout));}
    else o.push(...varint(op.lim));
    if (win) o.push(...varint(op.start || 0), ...varint(op.end || 0));
    if (auth) o.push(...varint(op.auth_vout));
    if (wcap) o.push(...varint(op.wallet_cap));
    if(op.pow){const c=require('./pow').config(op.pow);o.push(2,c.bits,...varint(c.max_age));}
  } else if (op.op === 'mint') {
    o.push(...tickBytes(op.tick), ...varint(op.vout), ...varint(op.lock || 0));
    if ((op.pass||op.proof||op.operator) && !op.owner) throw new Error('An allowlist pass needs the owner key');
    if (op.owner) {
      o.push(1|(op.pass?2:0)|(op.proof?4:0)|(op.operator?8:0), ...x32(op.owner));
      if (op.pass) {
        const sig = Buffer.from(op.pass.sig, 'hex');
        if (sig.length !== 64) throw new Error('Pass signature must be 64 bytes');
        o.push(...varint(op.pass.max), ...varint(op.pass.expiry), ...sig);
      }
    }
    if(op.proof)o.push(...varint(op.proof.height),...require('./pow').u64(op.proof.nonce));
  } else if (op.op === 'operator') {
    o.push(...tickBytes(op.tick),...opt(op.next_auth),...x32(op.owner),...varint(op.max),...varint(op.expiry));
  } else if (op.op === 'allowlist') {
    o.push(...tickBytes(op.tick), ...opt(op.next_auth), ...x32(op.key), ...varint(op.price), ...varint(op.reserve), ...varint(op.end));
  } else if (op.op === 'transfer') {
    o.push(op.ticks.length);
    for (const t of op.ticks) o.push(...tickBytes(t.tick), ...opt(t.change));
    o.push(...varint(op.edicts.length));
    for (const e of op.edicts) o.push(e.t, ...varint(e.amt), ...varint(e.vout), ...varint(e.lock || 0));
  } else if (op.op === 'burn') {
    o.push(...tickBytes(op.tick), ...varint(op.amt), ...opt(op.change));
  } else if (op.op === 'meta') {
    o.push(...tickBytes(op.tick), ...opt(op.next_auth));
    for (const [type, val] of op.fields || []) { const v = Buffer.from(val); o.push(type, ...varint(v.length), ...v); }
  }
  if(op.proof&&op.pass)throw Error('Compact work uses on-chain operator approval, not signed passes');
  if(op.operator&&!op.proof)throw Error('Operator mint requires work');
  if((op.pow||op.proof||op.op==='operator'||op.mode==='lots')&&o.length>80)throw Error('Compact payload exceeds 80 bytes');
  return Buffer.from(o);
}

function opReturnScript(payload) {
  return bitcoin.script.compile([bitcoin.opcodes.OP_RETURN, payload]);
}

const sha = (b) => crypto.createHash('sha256').update(b).digest();
function taggedHash(tag, msg) { const t = sha(Buffer.from(tag)); return sha(Buffer.concat([t, t, msg])); }
const tokenCommitment = (tick) => taggedHash('TAPSEAL/token', Buffer.from(tick, 'ascii'));
const authCommitment = (tick) => taggedHash('TAPSEAL/auth', Buffer.from(tick, 'ascii'));

function pushNum(n) {
  if (n >= 1 && n <= 16) return Buffer.from([0x50 + n]);
  const out = [];
  while (n) { out.push(n & 0xff); n = Math.floor(n / 256); }
  if (out[out.length - 1] & 0x80) out.push(0);
  return Buffer.from([out.length, ...out]);
}
function sealLeaf(commitment, ownerX, lock = 0) {
  if (lock) return Buffer.concat([Buffer.from([0x20]), commitment, Buffer.from([0x75]), pushNum(lock), Buffer.from([0xb1, 0x75, 0x20]), ownerX, Buffer.from([0xac])]);
  return Buffer.concat([Buffer.from([0x20]), commitment, Buffer.from([0x75, 0x20]), ownerX, Buffer.from([0xac])]);
}

function networkOf(name) {
  return name === 'mainnet' || name === 'bitcoin' ? bitcoin.networks.bitcoin : name === 'regtest' ? bitcoin.networks.regtest : bitcoin.networks.testnet;
}

/** Seal output for an owner: { script, leaf, controlBlock, address }. */
function seal(tick, ownerX, { lock = 0, auth = false, network = 'mainnet' } = {}) {
  const leaf = sealLeaf(auth ? authCommitment(tick) : tokenCommitment(tick), ownerX, lock);
  const p = bitcoin.payments.p2tr({ internalPubkey: NUMS, scriptTree: { output: leaf }, redeem: { output: leaf, redeemVersion: LEAF_VERSION }, network: networkOf(network) });
  return { script: p.output, leaf, controlBlock: p.witness[p.witness.length - 1], address: p.address };
}

/** x-only owner key for a Taproot address: the output key inside the address (what UniSat signs with). */
function ownerOfAddress(address, network) {
  let d;
  try { d = bitcoin.address.fromBech32(address); } catch (e) { throw new Error('Use a Taproot (bc1p / tb1p) address'); }
  if (d.version !== 1 || d.data.length !== 32) throw new Error('Use a Taproot (bc1p / tb1p) address');
  if (d.prefix !== networkOf(network).bech32) throw new Error(`Address is not on ${network}`);
  return Buffer.from(d.data);
}

// ── pricing ────────────────────────────────────────────────────────────────
function isqrt(n) { if (n < 2n) return n; let x = n, y = (x + 1n) >> 1n; while (y < x) { x = y; y = (x + n / x) >> 1n; } return x; }
function curveAtoms(paid, minted, max, dec, p0, p1) {
  paid = B(paid); if (paid <= 0n) return 0n;
  const c = paid * 1000n * 10n ** B(dec), d = B(p1) - B(p0), b = B(p0) * B(max) + d * B(minted);
  if (d === 0n) return c / B(p0);
  return (isqrt(b * b + 2n * d * B(max) * c) - b) / d;
}

const wlActive = (token, height) => !!token.wl && height <= Number(token.wl.end);
const reserveLeft = (token, height) => {
  if (!wlActive(token, height)) return 0n;
  const r = B(token.wl.reserve) - B(token.wl_minted || 0);
  return r > 0n ? r : 0n;
};

/** Atoms for `paid` sats at the public price or the allowlist price, before clipping (tapseal.py mint_amount). */
function mintAmount(token, paid, allowlist = false) {
  if(token.mode==='lots'){const price=allowlist?450n:700n,p=B(paid);return p%price===0n&&p/price>=1n&&p/price<=10n?p/price*100000000000n:0n;}
  if (token.mode === 'fair') return B(token.params.lim);
  const cap = token.params.cap ? B(token.params.cap) : 0n;
  let counted = cap && B(paid) > cap ? cap : B(paid);
  if (token.mode === 'fixed') return counted * B(allowlist ? token.wl.price : token.params.rate);
  if (allowlist) counted = (counted * BPS) / (BPS - B(token.wl.price));
  return curveAtoms(counted, token.minted, token.max, token.dec, token.params.p0, token.params.p1);
}

/**
 * Quote a mint exactly as the indexer will count it. token uses BigInt fields.
 * opts: { height (the block it would confirm in), allowlist: {max, used} for a pass mint, walletUsed (public atoms already minted by this key) }
 */
function quoteMint(token, paySats, opts = {}) {
  const height = opts.height ?? Number.MAX_SAFE_INTEGER;
  const supplyLeft = token.max - token.minted;
  const cap = token.params.cap ? B(token.params.cap) : 0n;
  const paid = B(paySats || 0);
  if(token.mode==='lots'){
    const pass=opts.allowlist||null,price=pass?450n:700n,raw=mintAmount(token,paid,!!pass),left=token.max-token.minted,passLeft=pass?B(pass.max)-B(pass.used||0):left;
    const invalid=raw<=0n,limited=invalid?'lot':raw>left?'supply':raw>passLeft?'pass':null;
    return{atoms:limited?0n:raw,counted:paid,capped:paid>price*10n,partial:limited==='supply',limited_by:limited,clipped:!!limited,left,reserve_left:0n,allowlist:!!pass,lot_count:raw/100000000000n};
  }
  const counted = cap && paid > cap ? cap : paid;
  const reserve = opts.height == null ? 0n : reserveLeft(token, height);
  const pass = opts.allowlist || null;
  const raw = mintAmount(token, paid, !!pass);
  let limit, limitedBy = null;
  if (pass) {
    const passLeft = B(pass.max) - B(pass.used || 0);
    limit = [[passLeft, 'pass'], [reserve, 'reserve'], [supplyLeft, 'supply']].reduce((a, b) => (b[0] < a[0] ? b : a));
  } else {
    const available = supplyLeft - reserve;
    const opts2 = [[available, available < supplyLeft ? 'reserve' : 'supply']];
    if (token.wallet_cap && B(token.wallet_cap) > 0n) opts2.push([B(token.wallet_cap) - B(opts.walletUsed || 0), 'wallet']);
    limit = opts2.reduce((a, b) => (b[0] < a[0] ? b : a));
  }
  let atoms = raw;
  if (raw > limit[0]) { atoms = limit[0] < 0n ? 0n : limit[0]; limitedBy = limit[1]; }
  return { atoms, counted, capped: !!(cap && paid > cap), partial: limitedBy === 'supply', limited_by: limitedBy, clipped: limitedBy !== null,
    left: supplyLeft, reserve_left: reserve, allowlist: !!pass };
}

const passMessage = (tick, ownerX, max, expiry) =>
  taggedHash('TAPSEAL/pass', Buffer.from([...tickBytes(tick), ...x32(ownerX), ...varint(max), ...varint(expiry)]));
function verifyPass(keyHex, tick, ownerX, max, expiry, sigHex) {
  try { return ecc.verifySchnorr(passMessage(tick, ownerX, max, expiry), Buffer.from(keyHex, 'hex'), Buffer.from(sigHex, 'hex')); } catch (e) { return false; }
}

/** Find the payload in a transaction and decode the op name/tick (enough for the mempool view). */
function sniffPayload(tx) {
  for (const o of tx.outs) {
    const chunks = bitcoin.script.decompile(o.script);
    if (!chunks || chunks[0] !== bitcoin.opcodes.OP_RETURN || chunks.length !== 2 || !Buffer.isBuffer(chunks[1])) continue;
    const p = chunks[1];
    if (!p.subarray(0, 4).equals(MAGIC)) continue;
    const kind = Object.keys(OPS).find((k) => OPS[k] === p[4]) || 'cenotaph';
    let tick = null;
    const at = kind === 'deploy' || kind === 'transfer' ? 6 : 5;
    const len = p[at];
    if (len >= 1 && len <= 8) tick = p.subarray(at + 1, at + 1 + len).toString('ascii');
    return { kind, tick, bytes: p.length };
  }
  return null;
}

module.exports = {
  MAGIC, NUMS, LEAF_VERSION, SEAL_SATS, TICK_RE, encode, opReturnScript, tokenCommitment, authCommitment,
  sealLeaf, seal, ownerOfAddress, networkOf, curveAtoms, quoteMint, mintAmount, wlActive, reserveLeft, sniffPayload, bitcoin, ecc,
  passMessage, verifyPass, taggedHash,
};
