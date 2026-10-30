// PSBT builders for UniSat. Every builder returns an unsigned PSBT plus the input indexes the wallet must sign.
// Seals are owned by the x-only key inside the user's Taproot address, which is the key UniSat signs with,
// so the same wallet signs both funding inputs (key path) and seal inputs (script path).
const ts = require('./tapseal');

const { bitcoin } = ts;
const DUST = 546;
const outVb = (script) => 8 + 1 + script.length;
const SEAL_IN_VB = (lock) => 41 + (1 + 65 + 1 + (lock ? 72 : 68) + 1 + 33) / 4;

/** Describe how to spend the user's own coins (Taproot, native SegWit or nested SegWit). */
function payer(address, publicKeyHex, network) {
  const net = ts.networkOf(network);
  const script = bitcoin.address.toOutputScript(address, net);
  const pk = Buffer.from(String(publicKeyHex || ''), 'hex');
  if (pk.length === 33) {
    const w = bitcoin.payments.p2wpkh({ pubkey: pk, network: net });
    if (w.address === address) return { address, script, vb: 68, input: (u) => ({ witnessUtxo: { script, value: u.value } }) };
    if (bitcoin.payments.p2sh({ redeem: w, network: net }).address === address) {
      return { address, script, vb: 91, input: (u) => ({ witnessUtxo: { script, value: u.value }, redeemScript: w.output }) };
    }
  }
  const x = pk.length === 33 ? pk.subarray(1) : pk;
  if (x.length === 32 && bitcoin.payments.p2tr({ internalPubkey: x, network: net }).address === address) {
    return { address, script, vb: 57.5, taproot: true, input: (u) => ({ witnessUtxo: { script, value: u.value }, tapInternalKey: x }) };
  }
  throw new Error('Wallet public key does not match the address. Reconnect UniSat.');
}

/** Add funding inputs and change. Throws a readable error when there isn't enough BTC. */
function fund(psbt, { from, utxos, fixedOut, haveIn = 0, baseVb, feeRate }) {
  const fee = (n, change) => Math.ceil((baseVb + n * from.vb + (change ? outVb(from.script) : 0)) * feeRate);
  const pool = [...utxos].sort((a, b) => b.value - a.value);
  const picked = [];
  let total = haveIn;
  for (const u of pool) {
    if (total >= fixedOut + fee(picked.length, true) + DUST) break;
    picked.push(u); total += u.value;
  }
  let feeSats = fee(picked.length, true);
  let change = total - fixedOut - feeSats;
  if (change < DUST) {
    feeSats = fee(picked.length, false);
    if (total - fixedOut - feeSats < 0) throw new Error(`Not enough BTC in ${from.address}: about ${fixedOut + feeSats - total} more sats needed.`);
    feeSats = total - fixedOut; change = 0;
  }
  const first = psbt.inputCount;
  for (const u of picked) psbt.addInput({ hash: u.txid, index: u.vout, ...from.input(u) });
  return { picked, feeSats, change, signInputs: picked.map((_, i) => ({ index: first + i, address: from.address })) };
}

function finish(psbt, f, from, extra) {
  if (f.change) psbt.addOutput({ script: from.script, value: f.change });
  const vsize = Math.ceil(f.feeSats / extra.feeRate);
  return { psbt_hex: psbt.toHex(), psbt_base64: psbt.toBase64(), sign_inputs: f.signInputs, fee_sats: f.feeSats, vsize_est: vsize, change_sats: f.change, ...extra.summary };
}

function cleanUtxos(utxos, minValue) {
  return (utxos || []).map((u) => ({ txid: String(u.txid), vout: Number(u.vout), value: Number(u.value ?? u.satoshis ?? u.satoshi) }))
    .filter((u) => /^[0-9a-f]{64}$/.test(u.txid) && Number.isInteger(u.vout) && u.value >= minValue);
}

// ── mint ───────────────────────────────────────────────────────────────────
/**
 * pass: { max, expiry, sig, used } when the wallet mints with an allowlist pass.
 * walletUsed: public atoms this owner key already minted (for tokens with a wallet limit).
 */
function buildMint({ token, tip, address, publicKey, paySats, feeRate, lock = 0, utxos, network, platformFee, pass = null, walletUsed = 0n }) {
  const from = payer(address, publicKey, network);
  const owner = ts.ownerOfAddress(address, network);
  const next = tip + 1;
  if (token.start && next < token.start) throw new Error(`${token.tick} opens at block ${token.start}.`);
  if (token.end && next > token.end) throw new Error(`${token.tick} closed at block ${token.end}.`);
  if (token.minted >= token.max) throw new Error(`${token.tick} is sold out.`);
  if (lock && (lock <= next || lock >= 500000000)) throw new Error('Lock must be a future block height.');
  const pay = token.mode === 'fair' ? 0 : Math.floor(Number(paySats));
  if (token.mode !== 'fair' && !(pay >= DUST)) throw new Error(`Pay at least ${DUST} sats.`);
  const wlOn = ts.wlActive(token, next);
  if (pass && !wlOn) throw new Error(`${token.tick} has no active allowlist phase.`);
  if (pass && next > Number(pass.expiry)) throw new Error('Your allowlist pass has expired.');
  const quote = ts.quoteMint(token, pay, { height: next, allowlist: pass ? { max: BigInt(pass.max), used: BigInt(pass.used || 0) } : null, walletUsed: BigInt(walletUsed || 0) });
  if (quote.atoms <= 0n) {
    if (quote.limited_by === 'wallet') throw new Error(`This wallet has reached the ${token.tick} mint limit.`);
    if (quote.limited_by === 'pass') throw new Error('Your allowlist allowance is used up.');
    if (quote.limited_by === 'reserve') throw new Error(pass ? 'The allowlist reserve is used up.' : `The rest of ${token.tick} is reserved for the allowlist until block ${token.wl.end}.`);
    throw new Error('That amount buys zero tokens.');
  }
  const named = !!pass || (token.wallet_cap && BigInt(token.wallet_cap) > 0n);

  if (pay && from.script.toString('hex') === token.treasury_spk) throw new Error('This wallet is the treasury. Mint from a different address so change is not counted as payment.');
  const payload = ts.encode({ op: 'mint', tick: token.tick, vout: 1, lock, ...(named ? { owner } : {}),
    ...(pass ? { pass: { max: BigInt(pass.max), expiry: Number(pass.expiry), sig: pass.sig } } : {}) });
  const sealOut = ts.seal(token.tick, owner, { lock, network });
  const outs = [{ script: ts.opReturnScript(payload), value: 0 }, { script: sealOut.script, value: ts.SEAL_SATS }];
  if (pay) outs.push({ script: Buffer.from(token.treasury_spk, 'hex'), value: pay });
  if (platformFee && platformFee.sats > 0) outs.push({ script: bitcoin.address.toOutputScript(platformFee.address, ts.networkOf(network)), value: platformFee.sats });

  const psbt = new bitcoin.Psbt({ network: ts.networkOf(network) });
  const f = fund(psbt, { from, utxos, fixedOut: outs.reduce((s, o) => s + o.value, 0), baseVb: 10.5 + outs.reduce((s, o) => s + outVb(o.script), 0), feeRate });
  for (const o of outs) psbt.addOutput(o);
  return finish(psbt, f, from, { feeRate, summary: {
    op: 'mint', tick: token.tick, payload_hex: payload.toString('hex'), seal_address: sealOut.address, seal_vout: 1, lock,
    pay_sats: pay, atoms: quote.atoms.toString(), capped: quote.capped, partial: quote.partial, clipped: quote.clipped, limited_by: quote.limited_by,
    allowlist: !!pass, owner_named: named,
  } });
}

// ── transfer / burn (spend seals by script path) ────────────────────────────
function addSealInputs(psbt, seals, owner, network) {
  let lockTime = 0;
  const signInputs = [];
  for (const s of seals) {
    const sp = ts.seal(s.tick, owner, { lock: s.lock, auth: !!s.auth, network });
    if (sp.script.toString('hex') !== s.spk) throw new Error(`Seal ${s.outpoint} is not owned by this address.`);
    const [txid, vout] = s.outpoint.split(':');
    psbt.addInput({
      hash: txid, index: Number(vout), sequence: s.lock ? 0xfffffffe : 0xffffffff,
      witnessUtxo: { script: sp.script, value: ts.SEAL_SATS },
      tapLeafScript: [{ leafVersion: ts.LEAF_VERSION, script: sp.leaf, controlBlock: sp.controlBlock }],
    });
    signInputs.push({ index: psbt.inputCount - 1 });
    lockTime = Math.max(lockTime, s.lock || 0);
  }
  if (lockTime) psbt.setLocktime(lockTime);
  return signInputs;
}

function pickSeals(seals, tick, need, tip) {
  const usable = seals.filter((s) => s.tick === tick && !s.auth && BigInt(s.amt) > 0n && (!s.lock || s.lock <= tip))
    .sort((a, b) => (BigInt(b.amt) > BigInt(a.amt) ? 1 : -1));
  const out = []; let have = 0n;
  for (const s of usable) { if (have >= need) break; out.push(s); have += BigInt(s.amt); }
  if (have < need) throw new Error(`Not enough unlocked ${tick}: have ${have} atoms, need ${need}.`);
  return { picked: out, have };
}

function buildTransfer({ tick, tip, seals, address, publicKey, recipients, feeRate, utxos, network }) {
  const from = payer(address, publicKey, network);
  const owner = ts.ownerOfAddress(address, network);
  if (!recipients.length) throw new Error('Add at least one recipient.');
  const rec = recipients.map((r) => {
    const amt = BigInt(r.atoms);
    if (amt <= 0n) throw new Error('Every amount must be above zero.');
    const lock = Number(r.lock || 0);
    if (lock && (lock <= tip + 1 || lock >= 500000000)) throw new Error('Locks must be future block heights.');
    return { owner: ts.ownerOfAddress(r.address, network), amt, lock };
  });
  const need = rec.reduce((s, r) => s + r.amt, 0n);
  const { picked, have } = pickSeals(seals, tick, need, tip);
  const changeAtoms = have - need;
  const changeVout = rec.length + 1;

  const op = { op: 'transfer', ticks: [{ tick, change: changeAtoms > 0n ? changeVout : null }], edicts: rec.map((r, i) => ({ t: 0, amt: r.amt, vout: i + 1, lock: r.lock })) };
  const payload = ts.encode(op);
  const outs = [{ script: ts.opReturnScript(payload), value: 0 }, ...rec.map((r) => ({ script: ts.seal(tick, r.owner, { lock: r.lock, network }).script, value: ts.SEAL_SATS }))];
  if (changeAtoms > 0n) outs.push({ script: ts.seal(tick, owner, { network }).script, value: ts.SEAL_SATS });

  const psbt = new bitcoin.Psbt({ network: ts.networkOf(network) });
  const sealSign = addSealInputs(psbt, picked, owner, network);
  const sealVb = picked.reduce((s, x) => s + SEAL_IN_VB(x.lock), 0);
  const f = fund(psbt, { from, utxos, fixedOut: outs.reduce((s, o) => s + o.value, 0), haveIn: picked.length * ts.SEAL_SATS,
    baseVb: 10.5 + sealVb + outs.reduce((s, o) => s + outVb(o.script), 0), feeRate });
  for (const o of outs) psbt.addOutput(o);
  f.signInputs = [...sealSign.map((s) => ({ ...s, address })), ...f.signInputs];
  return finish(psbt, f, from, { feeRate, summary: {
    op: 'transfer', tick, payload_hex: payload.toString('hex'), seals_in: picked.map((s) => s.outpoint),
    sent_atoms: need.toString(), change_atoms: changeAtoms.toString(), recipients: rec.length,
  } });
}

function buildBurn({ tick, tip, seals, address, publicKey, atoms, feeRate, utxos, network }) {
  const from = payer(address, publicKey, network);
  const owner = ts.ownerOfAddress(address, network);
  const need = BigInt(atoms);
  if (need <= 0n) throw new Error('Burn amount must be above zero.');
  const { picked, have } = pickSeals(seals, tick, need, tip);
  const changeAtoms = have - need;
  const payload = ts.encode({ op: 'burn', tick, amt: need, change: changeAtoms > 0n ? 1 : null });
  const outs = [{ script: ts.opReturnScript(payload), value: 0 }];
  if (changeAtoms > 0n) outs.push({ script: ts.seal(tick, owner, { network }).script, value: ts.SEAL_SATS });
  const psbt = new bitcoin.Psbt({ network: ts.networkOf(network) });
  const sealSign = addSealInputs(psbt, picked, owner, network);
  const f = fund(psbt, { from, utxos, fixedOut: outs.reduce((s, o) => s + o.value, 0), haveIn: picked.length * ts.SEAL_SATS,
    baseVb: 10.5 + picked.reduce((s, x) => s + SEAL_IN_VB(x.lock), 0) + outs.reduce((s, o) => s + outVb(o.script), 0), feeRate });
  for (const o of outs) psbt.addOutput(o);
  f.signInputs = [...sealSign.map((s) => ({ ...s, address })), ...f.signInputs];
  return finish(psbt, f, from, { feeRate, summary: { op: 'burn', tick, payload_hex: payload.toString('hex'), burned_atoms: need.toString(), change_atoms: changeAtoms.toString() } });
}

// ── allowlist settings (spends the authority seal, re-creates it at vout 1) ──
function buildAllowlist({ token, tip, seals, address, publicKey, form, feeRate, utxos, network }) {
  const from = payer(address, publicKey, network);
  const owner = ts.ownerOfAddress(address, network);
  const auth = seals.find((s) => s.tick === token.tick && s.auth && s.outpoint === token.auth_outpoint);
  if (!auth) throw new Error(`This wallet does not hold the ${token.tick} authority seal.`);
  const end = Number(form.end || 0);
  const op = { op: 'allowlist', tick: token.tick, next_auth: 1, key: String(form.key || ''), price: BigInt(form.price || 0), reserve: BigInt(form.reserve || 0), end };
  if (end) {
    if (end <= tip + 1) throw new Error('The allowlist must end at a future block.');
    if (!/^[0-9a-f]{64}$/.test(op.key)) throw new Error('Signer key must be a 64-character x-only public key.');
    if (token.mode === 'fixed' && op.price <= BigInt(token.params.rate)) throw new Error('The allowlist price must be lower than the public price.');
    if (token.mode === 'curve' && !(op.price > 0n && op.price < 10000n)) throw new Error('The discount must be between 0.01% and 99.99%.');
    if (token.mode === 'fair' && op.price !== 0n) throw new Error('Fair launches have no allowlist price.');
    if (op.reserve > token.max - token.minted + BigInt(token.wl_minted || 0)) throw new Error('The reserve is larger than the unminted supply.');
  } else op.key = '00'.repeat(32);
  const payload = ts.encode(op);
  const outs = [{ script: ts.opReturnScript(payload), value: 0 }, { script: ts.seal(token.tick, owner, { auth: true, network }).script, value: ts.SEAL_SATS }];
  const psbt = new bitcoin.Psbt({ network: ts.networkOf(network) });
  const sealSign = addSealInputs(psbt, [auth], owner, network);
  const f = fund(psbt, { from, utxos, fixedOut: outs.reduce((s2, o) => s2 + o.value, 0), haveIn: ts.SEAL_SATS,
    baseVb: 10.5 + SEAL_IN_VB(0) + outs.reduce((s2, o) => s2 + outVb(o.script), 0), feeRate });
  for (const o of outs) psbt.addOutput(o);
  f.signInputs = [...sealSign.map((x) => ({ ...x, address })), ...f.signInputs];
  return finish(psbt, f, from, { feeRate, summary: { op: 'allowlist', tick: token.tick, payload_hex: payload.toString('hex'), authority_input: auth.outpoint,
    key: op.key, price: op.price.toString(), reserve: op.reserve.toString(), end } });
}

// ── deploy ─────────────────────────────────────────────────────────────────
function buildDeploy({ form, address, publicKey, feeRate, utxos, network }) {
  const from = payer(address, publicKey, network);
  const owner = ts.ownerOfAddress(address, network);
  const tick = String(form.tick || '').toUpperCase();
  const dec = Number(form.dec);
  if (!ts.TICK_RE.test(tick)) throw new Error('Ticker must be 1-8 characters A-Z or 0-9.');
  if (!(Number.isInteger(dec) && dec >= 0 && dec <= 18)) throw new Error('Decimals must be 0-18.');
  const max = BigInt(form.max_atoms);
  if (max <= 0n) throw new Error('Max supply must be above zero.');
  const op = { op: 'deploy', tick, dec, max, mode: form.mode };
  const paid = form.mode === 'fixed' || form.mode === 'curve';
  if (form.mode === 'fixed') { op.rate = BigInt(form.rate); op.cap = BigInt(form.cap || 0); if (op.rate <= 0n) throw new Error('Rate must be above zero.'); }
  else if (form.mode === 'curve') { op.p0 = BigInt(form.p0); op.p1 = BigInt(form.p1); op.cap = BigInt(form.cap || 0); if (!(op.p0 > 0n && op.p1 >= op.p0)) throw new Error('Curve needs 0 < start price <= end price.'); }
  else if (form.mode === 'fair') { op.lim = BigInt(form.lim_atoms); if (!(op.lim > 0n && op.lim <= max)) throw new Error('Per-mint amount must be between 1 atom and the max supply.'); }
  else throw new Error('Mode must be fixed, curve or fair.');
  if (form.start || form.end) { op.start = Number(form.start || 0); op.end = Number(form.end || 0); if (op.end && op.end < op.start) throw new Error('The window closes before it opens.'); }
  if (form.wallet_cap_atoms && BigInt(form.wallet_cap_atoms) > 0n) { op.wallet_cap = BigInt(form.wallet_cap_atoms); if (op.wallet_cap > max) throw new Error('The per-wallet limit cannot exceed the max supply.'); }
  const outs = [{ script: null, value: 0 }];
  if (paid) { op.treasury_vout = outs.length; outs.push({ script: bitcoin.address.toOutputScript(form.treasury_address || address, ts.networkOf(network)), value: DUST }); }
  let authAddress = null;
  if (form.auth !== false) { op.auth_vout = outs.length; const a = ts.seal(tick, owner, { auth: true, network }); authAddress = a.address; outs.push({ script: a.script, value: ts.SEAL_SATS }); }
  const payload = ts.encode(op);
  outs[0].script = ts.opReturnScript(payload);
  const psbt = new bitcoin.Psbt({ network: ts.networkOf(network) });
  const f = fund(psbt, { from, utxos, fixedOut: outs.reduce((s, o) => s + o.value, 0), baseVb: 10.5 + outs.reduce((s, o) => s + outVb(o.script), 0), feeRate });
  for (const o of outs) psbt.addOutput(o);
  return finish(psbt, f, from, { feeRate, summary: { op: 'deploy', tick, payload_hex: payload.toString('hex'), authority_seal: authAddress, treasury: paid ? (form.treasury_address || address) : null } });
}

/** Turn whatever the wallet returned into a raw transaction. */
function extract(psbtOrHex, network) {
  const s = String(psbtOrHex || '').trim();
  if (/^[0-9a-f]+$/i.test(s) && !s.startsWith('70736274')) return bitcoin.Transaction.fromHex(s);
  const psbt = /^[0-9a-f]+$/i.test(s) ? bitcoin.Psbt.fromHex(s, { network: ts.networkOf(network) }) : bitcoin.Psbt.fromBase64(s, { network: ts.networkOf(network) });
  try { psbt.finalizeAllInputs(); } catch (e) { /* already finalized by the wallet */ }
  return psbt.extractTransaction();
}

module.exports = { payer, fund, buildMint, buildTransfer, buildBurn, buildDeploy, buildAllowlist, extract, cleanUtxos, DUST };
