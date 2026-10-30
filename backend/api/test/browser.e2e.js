// Browser end to end: console page -> API -> mocked UniSat (signs with a real key in Node) -> broadcast -> "mined" -> confirmed.
// Run: node test/browser.e2e.js   (needs Playwright + Chromium installed; not part of `npm test`)
const { chromium } = require('playwright');
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
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tapseal-ui-'));
const DB = path.join(tmp, 'tapseal.sqlite');
const SK = Buffer.from('1f'.repeat(32), 'hex');
const user = ECPair.fromPrivateKey(SK, { network: NET });
const xOnly = user.publicKey.subarray(1);
const address = bitcoin.payments.p2tr({ internalPubkey: xOnly, network: NET }).address;
const tweaked = user.tweak(bitcoin.crypto.taggedHash('TapTweak', xOnly));
const other = bitcoin.payments.p2tr({ internalPubkey: ECPair.makeRandom().publicKey.subarray(1), network: NET }).address;
const py = (...a) => JSON.parse(execFileSync('python3', ['-I', FIX, ...a], { encoding: 'utf8' }));
const txJson = (tx) => ({ txid: tx.getId(), vin: tx.ins.map((i) => ({ prevout: `${Buffer.from(i.hash).reverse().toString('hex')}:${i.index}`, witness: i.witness.map((w) => w.toString('hex')) })), vout: tx.outs.map((o) => ({ value: o.value, spk: o.script.toString('hex') })) });

(async () => {
  py('make', DB, SK.toString('hex'));
  const broadcasts = [];
  const rpc = http.createServer((req, res) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => {
    const j = JSON.parse(b); const tx = bitcoin.Transaction.fromHex(j.params[0]); broadcasts.push(tx);
    res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ result: tx.getId(), error: null, id: j.id })); }); });
  await new Promise((r) => rpc.listen(0, r));
  const app = express(); app.use(express.json());
  app.use('/api/tapseal', createRouter({ dbPath: DB, network: 'mainnet', mempoolApi: 'http://127.0.0.1:9', minServerUtxo: 10000, publicLaunch: false,
    ownerAddresses: [address], featured: 'STONK', platformFee: { sats: 0 }, rpc: { url: `http://127.0.0.1:${rpc.address().port}` } }));
  app.use('/console', express.static(path.resolve(__dirname, '../../console')));
  const server = app.listen(0); await new Promise((r) => server.once('listening', r));
  const url = `http://127.0.0.1:${server.address().port}/console/index.html`;

  const b = await chromium.launch({ args: ['--use-gl=swiftshader', '--enable-webgl', '--ignore-gpu-blocklist'] });
  const page = await b.newPage({ viewport: { width: 1440, height: 900 } });
  const errors = []; page.on('pageerror', (e) => errors.push(e.message));
  let signCalls = 0;
  await page.exposeFunction('__nodeSign', (hex, optsJson) => {
    signCalls++;
    const opts = JSON.parse(optsJson);
    const psbt = bitcoin.Psbt.fromHex(hex, { network: NET });
    for (const i of opts.toSignInputs) psbt.signInput(i.index, tweaked);
    if (opts.autoFinalized) psbt.finalizeAllInputs();
    return psbt.toHex();
  });
  await page.addInitScript(({ address, pubkey }) => {
    window.unisat = {
      requestAccounts: async () => [address], getPublicKey: async () => pubkey, getChain: async () => ({ enum: 'BITCOIN_MAINNET' }),
      getBitcoinUtxos: async () => [{ txid: 'ab'.repeat(32), vout: 0, satoshis: 400000 }, { txid: 'cd'.repeat(32), vout: 1, satoshis: 50000 }],
      signPsbt: (hex, opts) => window.__nodeSign(hex, JSON.stringify(opts)), on: () => {},
    };
  }, { address, pubkey: user.publicKey.toString('hex') });

  const step = async (name, fn) => { await fn(); console.log('ok  ', name); };
  const shots = process.argv[2] || tmp;
  await page.goto(url); await page.waitForTimeout(1500);

  await step('switches to live mode from the API', async () => {
    const pill = await page.textContent('#modePill'); if (pill !== 'Live') throw new Error(`pill=${pill}`);
    const rows = await page.$$eval('[data-mint]', (r) => r.map((x) => x.dataset.mint)); if (rows.join() !== 'FREE,STONK') throw new Error(rows.join());
  });
  await step('connects UniSat and shows the vault seals', async () => {
    await page.click('#walletBtn'); await page.waitForTimeout(400);
    await page.click('[data-go="vault"]'); await page.waitForTimeout(300);
    const n = await page.$$eval('#work tbody tr', (r) => r.length); if (n !== 2) throw new Error(`seals=${n}`);
    await page.screenshot({ path: path.join(shots, 'live-vault.png') });
  });
  let mintTx;
  await step('mints STONK: server PSBT, UniSat signs, broadcast', async () => {
    await page.click('[data-go="mint"]'); await page.waitForTimeout(200);
    await page.fill('#mSats', '25000'); await page.waitForTimeout(100);
    await page.click('#mGo'); await page.waitForSelector('#dYes');
    await page.screenshot({ path: path.join(shots, 'live-confirm.png') });
    await page.click('#dYes'); await page.waitForTimeout(800);
    if (signCalls !== 1 || broadcasts.length !== 1) throw new Error(`sign=${signCalls} bc=${broadcasts.length}`);
    mintTx = broadcasts[0];
    const log = await page.textContent('#log'); if (!/broadcast mint/.test(log)) throw new Error('no broadcast log');
  });
  await step('the mint is valid under the reference rules', async () => {
    const f = path.join(tmp, 'mint.json'); fs.writeFileSync(f, JSON.stringify(txJson(mintTx)));
    const out = py('apply', DB, f); const m = out.events.find((e) => e.kind === 'mint');
    if (!m || m.amt !== String(25000n * 50000000n)) throw new Error(JSON.stringify(out.events));
  });
  await step('after it is mined, the console confirms it and the vault grows', async () => {
    const f = path.join(tmp, 'mint.json'); py('confirm', DB, f);
    await page.waitForFunction(() => /confirmed mint/.test(document.querySelector('#log').textContent), null, { timeout: 15000 });
    await page.click('[data-go="vault"]'); await page.waitForTimeout(300);
    const n = await page.$$eval('#work tbody tr', (r) => r.length); if (n !== 3) throw new Error(`seals=${n}`);
  });
  await step('sends STONK to another address (spends seals by script path)', async () => {
    await page.click('[data-go="send"]'); await page.waitForTimeout(200);
    await page.fill('#r0to', other); await page.fill('#r0amt', '1000'); await page.waitForTimeout(100);
    await page.click('#sGo'); await page.waitForSelector('#dYes'); await page.click('#dYes'); await page.waitForTimeout(800);
    const tx = broadcasts[1]; if (!tx) throw new Error('no transfer broadcast');
    const f = path.join(tmp, 'send.json'); fs.writeFileSync(f, JSON.stringify(txJson(tx)));
    const out = py('apply', DB, f);
    if (out.lost.STONK !== '0' || !out.events.some((e) => e.kind === 'transfer' && e.amt === String(1000n * 100000000n))) throw new Error(JSON.stringify(out));
    await page.screenshot({ path: path.join(shots, 'live-after.png') });
  });
  console.log(errors.length ? `page errors: ${errors.join(' | ')}` : 'no page errors');
  await b.close(); server.close(); rpc.close();
})().catch((e) => { console.error('FAIL', e); process.exit(1); });
