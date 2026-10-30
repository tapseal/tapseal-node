// Browser end to end for the 1.1 React site, against the real API, the real Python preview and the real indexer rules.
// A fake Bitcoin node answers gettxout / getblockchaininfo / testmempoolaccept / sendrawtransaction; UniSat is mocked
// in the page but signs with a real key in Node. Every broadcast is then mined into the indexer database.
//
// Run: SITE_DIR=../../web/out node test/web.e2e.js      (needs Playwright + Chromium; not part of `npm test`)
// Optional SHOTS=/some/dir writes screenshots of the live pages.
const { chromium } = require('playwright');
const { execFileSync } = require('child_process');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const express = require('express');
const Database = require('better-sqlite3');
const { ECPairFactory } = require('ecpair');
const ts = require('../src/tapseal');
const { createRouter } = require('../src/router');
const allow = require('../src/allowlist');

const { bitcoin, ecc } = ts;
const ECPair = ECPairFactory(ecc);
const NET = bitcoin.networks.bitcoin;
const FIX = path.join(__dirname, 'fixture.py');
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tapseal-web-'));
const DB = path.join(tmp, 'tapseal.sqlite');
const LIST = path.join(tmp, 'allowlist.json');
const WL_KEY = 'ab'.repeat(32);
const SK = Buffer.from('1f'.repeat(32), 'hex');
const user = ECPair.fromPrivateKey(SK, { network: NET });
const xOnly = user.publicKey.subarray(1);
const pay = bitcoin.payments.p2tr({ internalPubkey: xOnly, network: NET });
const address = pay.address;
const tweaked = user.tweak(bitcoin.crypto.taggedHash('TapTweak', xOnly));
const other = bitcoin.payments.p2tr({ internalPubkey: ECPair.makeRandom().publicKey.subarray(1), network: NET }).address;
const py = (...a) => JSON.parse(execFileSync('python3', [FIX, ...a], { encoding: 'utf8' }));
const SHOTS = process.env.SHOTS;
const step = (m) => console.log('·', m);

(async () => {
  py('make11', DB, SK.toString('hex'));
  // ── fake node ──
  const coins = new Map();          // outpoint -> { value, spk } for wallet coins handed to the mocked UniSat
  const sent = [];
  let n = 0;
  const freshCoins = () => [1, 2].map(() => {
    const txid = require('crypto').createHash('sha256').update('coin' + n++).digest('hex');
    coins.set(`${txid}:0`, { value: 300000, spk: pay.output.toString('hex') });
    return { txid, vout: 0, satoshis: 300000 };
  });
  const tip = () => { const d = new Database(DB, { readonly: true }); const r = d.prepare('select height,hash from blocks order by height desc limit 1').get(); d.close(); return r; };
  const seal = (op) => { const d = new Database(DB, { readonly: true }); const r = d.prepare('select spk from seals where outpoint=?').get(op); d.close(); return r; };
  const rpcSrv = http.createServer((req, res) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => {
    const j = JSON.parse(b); let result = null;
    if (j.method === 'gettxout') {
      const op = `${j.params[0]}:${j.params[1]}`, c = coins.get(op), s = c ? null : seal(op);
      result = c ? { value: c.value / 1e8, scriptPubKey: { hex: c.spk } } : s ? { value: ts.SEAL_SATS / 1e8, scriptPubKey: { hex: s.spk } } : null;
    }
    if (j.method === 'getblockchaininfo') { const t = tip(); result = { chain: 'main', blocks: t.height, bestblockhash: t.hash, initialblockdownload: false }; }
    if (j.method === 'testmempoolaccept') result = [{ allowed: true }];
    if (j.method === 'sendrawtransaction') { const tx = bitcoin.Transaction.fromHex(j.params[0]); sent.push(tx); result = tx.getId(); }
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ result, error: null, id: j.id }));
  }); });
  await new Promise((r) => rpcSrv.listen(0, '127.0.0.1', r));
  const mine = () => {
    const tx = sent.shift(); assert.ok(tx, 'nothing was broadcast');
    const j = { txid: tx.getId(), vin: tx.ins.map((i) => ({ prevout: `${Buffer.from(i.hash).reverse().toString('hex')}:${i.index}`, witness: i.witness.map((w) => w.toString('hex')) })),
      vout: tx.outs.map((o) => ({ value: o.value, spk: o.script.toString('hex') })) };
    const f = path.join(tmp, j.txid + '.json'); fs.writeFileSync(f, JSON.stringify(j));
    return py('confirm', DB, f);
  };

  const app = express(); app.use(express.json());
  app.use('/api/tapseal', createRouter({ dbPath: DB, network: 'mainnet', mempoolApi: 'http://127.0.0.1:9', minServerUtxo: 10000, publicLaunch: true,
    ownerAddresses: [], featured: 'WLT', platformFee: { sats: 0 }, rpc: { url: `http://127.0.0.1:${rpcSrv.address().port}` },
    allowlistFile: LIST, wlSigningKey: WL_KEY, previewRequireRpc: true }));
  app.use('/', express.static(process.env.SITE_DIR || path.join(__dirname, '../../../web/out')));
  const server = app.listen(0); await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const api = (p) => fetch(base + '/api/tapseal' + p).then((r) => r.json());

  const b = await chromium.launch();
  const errors = [];
  const ctx = await b.newContext({ viewport: { width: 1440, height: 1000 } });
  let signCalls = 0;
  await ctx.exposeFunction('__nodeSign', (hex, optsJson) => {
    signCalls++;
    const opts = JSON.parse(optsJson), psbt = bitcoin.Psbt.fromHex(hex, { network: NET });
    for (const i of opts.toSignInputs) {
      assert.strictEqual(i.address, address);
      psbt.signInput(i.index, tweaked);   // seals are owned by the Taproot output key, the same key UniSat signs with
    }
    if (opts.autoFinalized) psbt.finalizeAllInputs();
    return psbt.toHex();
  });
  await ctx.exposeFunction('__coins', () => freshCoins());
  await ctx.addInitScript(({ address, pubkey }) => {
    window.unisat = {
      requestAccounts: async () => { localStorage.setItem('mockAuth', '1'); return [address]; }, getAccounts: async () => (localStorage.getItem('mockAuth') ? [address] : []),
      getPublicKey: async () => pubkey, getChain: async () => ({ enum: 'BITCOIN_MAINNET' }),
      getBitcoinUtxos: () => window.__coins(), signPsbt: (hex, opts) => window.__nodeSign(hex, JSON.stringify(opts)), on: () => {}, removeListener: () => {},
    };
  }, { address, pubkey: user.publicKey.toString('hex') });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(e.message));
  const shot = async (name) => { if (SHOTS) await page.screenshot({ path: path.join(SHOTS, name + '.png'), fullPage: true }); };
  const runSheet = async (expectRows) => {
    await page.waitForSelector('#confirmTx', { timeout: 20000 }).catch(async () => { throw new Error('No review: ' + (await page.textContent('.sheet'))); });
    const text = await page.textContent('.sheet');
    for (const r of expectRows) assert.ok(text.includes(r), `review is missing "${r}":\n${text}`);
    await page.click('#confirmTx');
    await page.waitForSelector('.result', { timeout: 20000 });
    const res = await page.textContent('.result');
    assert.match(res, /Broadcast/, res);
    await page.click('.sheet-f .btn:last-child');
    return mine();
  };

  // 1. live site, connect
  await page.goto(base + '/');
  await page.waitForSelector('#siteSync[data-state="ok"]');
  assert.match(await page.textContent('#siteSync'), /Mainnet · block 103/);
  await page.click('#walletBtn');
  await page.waitForFunction(() => document.querySelector('#walletBtn').classList.contains('connected'));
  await shot('live-home');
  step('home live, UniSat connected');

  // shell prompt: typing "mint wlt" opens the mint page for WLT
  await page.click('#omnibox'); await page.fill('#omnibox', 'mint wlt'); await page.keyboard.press('Enter');
  await page.waitForURL(/\/mint\/\?t=WLT/);
  await page.waitForFunction(() => document.querySelector('.tm-ps1 .p')?.textContent === '~/mint/WLT');
  assert.match(await page.textContent('.tm-ps1 .u'), /^bc1p.+@tapseal$/);
  assert.match(await page.textContent('.tm-ps1 .g'), /mainnet ●/);
  // shell-style command and prefix completion
  await page.fill('#omnibox', 'cd ~/create#manage'); await page.keyboard.press('Enter');
  await page.waitForURL(/\/create\/#manage$/);
  step('shell prompt navigation (mint wlt, cd ~/create#manage)');

  // 2. creator opens the allowlist phase for WLT (fixed, 1 token per sat → allowlist 2 per sat)
  await page.goto(base + '/create/#manage');
  await page.waitForSelector('#wlRes');
  await page.fill('#wlRes', '400000'); await page.fill('#wlPrice', '0.5'); await page.fill('#wlEnd', '300');
  await shot('live-manage');
  await page.click('#wlSubmit');
  let mined = await runSheet(['Reserved for allowlist', '400,000 WLT', 'block 300']);
  assert.deepStrictEqual(mined.events.map((e) => e.kind), ['allowlist']);
  let wlt = (await api('/tokens/WLT')).token;
  assert.strictEqual(wlt.allowlist.active, true); assert.strictEqual(String(wlt.allowlist.reserve), '400000');
  step('allowlist opened on chain through the Manage tab');

  // 3. operator lists the wallet (server command does the same), user mints with the pass at the allowlist rate
  allow.store(LIST).put('WLT', [{ owner: ts.ownerOfAddress(address, 'mainnet').toString('hex'), address, max: 50000n, expiry: 300 }]);
  await page.goto(base + '/mint/?t=WLT');
  await page.waitForSelector('#passBox[data-state="ok"]');
  await page.fill('#paySats', '10000');
  await page.waitForFunction(() => document.querySelector('#mintOut')?.textContent.startsWith('20,000'));
  await shot('live-mint-pass');
  await page.click('#mintBtn');
  mined = await runSheet(['Allowlist pass', '20,000 WLT', '10,000 sats']);
  assert.deepStrictEqual(mined.events.map((e) => [e.kind, e.amt]), [['mint', '20000']]);
  wlt = (await api('/tokens/WLT')).token;
  assert.strictEqual(String(wlt.allowlist.minted), '20000');
  step('allowlist mint: 10,000 sats → 20,000 WLT, counted against the reserve');

  // 4. pass above the allowance is refused in the page before anything is built
  await page.goto(base + '/mint/?t=WLT');
  await page.waitForSelector('#passBox[data-state="ok"]');
  await page.fill('#paySats', '20000');
  await page.waitForSelector('#mintProblem');
  assert.match(await page.textContent('#mintProblem'), /more than your allowance/);
  assert.ok(await page.isDisabled('#mintBtn'));
  step('over-allowance mint blocked in the page');

  // 5. fair mint with a per-wallet limit (10 per mint, 30 per wallet)
  for (let i = 0; i < 3; i++) {
    await page.goto(base + '/mint/?t=CAPPED');
    await page.waitForSelector('#mintBtn:not([disabled])');
    await page.click('#mintBtn');
    mined = await runSheet(['10 CAPPED', 'Owner key on chain']);
    assert.deepStrictEqual(mined.events.map((e) => [e.kind, e.amt]), [['mint', '10']]);
  }
  await page.goto(base + '/mint/?t=CAPPED');
  await page.waitForSelector('#mintProblem');
  assert.match(await page.textContent('#mintProblem'), /reached the CAPPED mint limit/);
  await shot('live-mint-capped');
  step('wallet limit: three fair mints, then the page refuses the fourth');

  // 6. send WLT to another address with a lock
  await page.goto(base + '/send/?t=WLT');
  await page.waitForSelector('#ra0');
  await page.fill('#ra0', other); await page.fill('#rm0', '5000'); await page.fill('#rl0', '500');
  await page.click('#sendBtn');
  mined = await runSheet(['5,000 WLT', 'locked to 500']);
  assert.ok(mined.events.some((e) => e.kind === 'transfer'));
  step('send with time lock');

  // 7. deploy a new token with a wallet limit
  await page.goto(base + '/create/');
  await page.fill('#dTick', 'NEWT'); await page.fill('#dDec', '0'); await page.fill('#dMax', '1000000'); await page.fill('#dPrice', '1'); await page.fill('#dWcap', '5000');
  await page.click('#deployBtn');
  mined = await runSheet(['NEWT', 'Per-wallet limit', '5,000']);
  assert.deepStrictEqual(mined.events.map((e) => e.kind), ['deploy']);
  const newt = (await api('/tokens/NEWT')).token;
  assert.strictEqual(String(newt.wallet_cap), '5000'); assert.ok(/^\d+:0$/.test(newt.id));
  step(`deploy NEWT with ID ${newt.id}`);

  // 8. portfolio and token page show indexed state
  await page.goto(base + '/wallet/');
  await page.waitForSelector('.tbl.responsive tbody tr');
  const wtext = await page.textContent('.tbl.responsive');
  assert.ok(wtext.includes('15,000'), wtext);   // 20,000 − 5,000 WLT
  assert.ok(wtext.includes('CAPPED') && wtext.includes('30'), wtext);
  await shot('live-wallet');
  await page.goto(base + `/token/?id=${newt.id}`);
  await page.waitForSelector('h1');
  assert.strictEqual(await page.textContent('h1'), 'NEWT');
  await page.goto(base + '/token/?t=WLT');
  await page.waitForSelector('text=Allowlist phase');
  await shot('live-token');
  step('portfolio balances and token lookup by ID');

  // 9. close the allowlist
  await page.goto(base + '/create/#manage');
  await page.waitForSelector('#wlSubmit');
  await page.click('aside button:has-text("WLT")');
  await page.click('text=Close now');
  mined = await runSheet(['Closed now']);
  wlt = (await api('/tokens/WLT')).token;
  assert.ok(!wlt.allowlist || !wlt.allowlist.active, 'allowlist still active');
  step('allowlist closed');

  assert.deepStrictEqual(errors, []);
  console.log(`ok: ${signCalls} UniSat signatures, every one previewed, admitted and mined`);
  await b.close(); server.close(); rpcSrv.close();
})().catch((e) => { console.error(e); process.exit(1); });
