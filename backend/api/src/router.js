// /api/tapseal routes. Mount with: app.use('/api/tapseal', createRouter(config))
const express = require('express');
const {boundedFetch}=require('./bounded-fetch');
const ts = require('./tapseal');
const builders = require('./psbt');
const dbm = require('./db');
const allow = require('./allowlist');
const { createPeers } = require('./peers');
const { createNetwork } = require('./network');
const { createAnnouncements } = require('./announce');

function createRouter(cfg) {
  const db = dbm.open(cfg.dbPath);
  if(db.node().network && db.node().network!==cfg.network){db.raw.close();throw new Error('Database network does not match API configuration.');}
  const wlStore = allow.store(cfg.allowlistFile || process.env.ALLOWLIST_FILE || '/var/lib/tapseal/allowlist.json');
  const wlSigner = allow.signer(cfg.wlSigningKey ?? process.env.WL_SIGNING_KEY);
  const operatorSigner = allow.signer(cfg.operatorSigningKey ?? process.env.OPERATOR_SIGNING_KEY);
  const signerFor = t => t.pow ? operatorSigner : wlSigner;
  const r = express.Router();
  const net = cfg.network;
  const hits = new Map();

  const big = (v) => (typeof v === 'bigint' ? v.toString() : v);
  const send = (res, body) => res.type('json').send(JSON.stringify(body, (k, v) => big(v)));
  const fail = (res, code, msg) => res.status(code).json({ ok: false, error: msg });
  const tipHeight = () => (db.tip() || { height: 0 }).height;
  // Light nodes index from a public block API and have no Bitcoin node to check or broadcast transactions,
  // so every write route is refused there. They still serve every read route and take part in peer agreement.
  const readOnly = cfg.mode === 'light' || cfg.homeNode === true;
  const nodeIdEarly = cfg.nodeId || require('crypto').createHash('sha256').update(`${require('os').hostname()}|${cfg.dbPath}`).digest('hex').slice(0, 16);
  const peers = cfg.peersInstance || createPeers({ peers: cfg.peers || [], db, network: net, intervalMs: cfg.peerIntervalMs, fetchImpl: cfg.peerFetchImpl,
    announce: cfg.announce === false ? null : { id: nodeIdEarly, mode: cfg.mode || 'full', url: cfg.publicUrl || null, version: cfg.version || '1.4.0-lots-rc.1' } });
  const announcements = createAnnouncements({ db, network: net });
  if (cfg.peerCheck !== false) peers.start();
  const rootAt = db.raw.prepare('select height, hash, root from blocks where height = ?');
  // Stable identity for the network map: NODE_ID from the node's config, else derived from this machine and database.
  const nodeId = nodeIdEarly;
  const network = cfg.networkInstance || createNetwork({ db, peers, announcements, self: { id: nodeId, url: cfg.publicUrl || null, mode: cfg.mode || 'full', network: net },
    fetchImpl: cfg.peerFetchImpl, maxNodes: cfg.mapMaxNodes, maxDepth: cfg.mapMaxDepth, cacheMs: cfg.mapCacheMs });
  r.use((req, res, next) => {
    if (readOnly && req.method === 'POST' && req.path !== '/announce') return fail(res, 503, 'This home/light node is read-only for transactions. Use the public claim page to review, sign and broadcast through a full node.');
    return next();
  });
  const limit = (req, res, next) => { // 60 builder calls per minute per IP
    const k = req.ip, now = Date.now(), w = (hits.get(k) || []).filter((t) => now - t < 60000);
    if (w.length >= 60) return fail(res, 429, 'Too many requests, wait a minute.');
    if (hits.size>=4096 && !hits.has(k)) { for(const [ip,times] of hits)if(!times.some(t=>now-t<60000))hits.delete(ip); if(hits.size>=4096)return fail(res,429,'Request limiter full; retry later.'); }
    w.push(now); hits.set(k, w); return next();
  };

  function tokenView(t, tip, holders, pending) {
    const next = tip + 1;
    const state = t.minted >= t.max ? 'sold_out' : t.start && next < t.start ? 'soon' : t.end && next > t.end ? 'closed' : 'live';
    let price = null;
    if(t.mode==='lots')price=0.7;
    if (t.mode === 'fixed') price = 10 ** t.dec / Number(t.params.rate);
    if (t.mode === 'curve') price = (Number(t.params.p0) + (Number(t.params.p1) - Number(t.params.p0)) * Number(t.minted) / Number(t.max)) / 1000;
    let treasury = null;
    try { treasury = t.treasury_spk ? ts.bitcoin.address.fromOutputScript(Buffer.from(t.treasury_spk, 'hex'), ts.networkOf(net)) : null; } catch (e) { treasury = t.treasury_spk; }
    let wl = null;
    if (t.wl) {
      const active = ts.wlActive(t, next);
      let wlPrice = null;
      if (t.mode === 'fixed') wlPrice = 10 ** t.dec / Number(t.wl.price);
      if (t.mode === 'curve' && price != null) wlPrice = price * (1 - Number(t.wl.price) / 10000);
      wl = { key: t.wl.key, price: t.wl.price, reserve: t.wl.reserve, end: t.wl.end, minted: t.wl_minted, active,
        reserve_left: ts.reserveLeft(t, next), price_sats: wlPrice, discount_bps: t.mode === 'curve' ? Number(t.wl.price) : t.mode === 'fixed' ? Math.round((1 - Number(t.params.rate) / Number(t.wl.price)) * 10000) : 0,
        wallets: t.pow ? db.raw.prepare("select count(*) n from usage where tick=? and kind='op-max' and cast(atoms as integer)>0").get(t.tick).n : wlStore.count(t.tick), signer_ready: t.pow ? true : !!signerFor(t) && signerFor(t).pub === t.wl.key };
    }
    const publicLeft = t.max - t.minted - (wl ? wl.reserve_left : 0n);
    return { tick: t.tick, id: t.id, dec: t.dec, mode: t.mode, params: t.params, max: t.max, minted: t.minted, burned: t.burned, lost: t.lost,
      lot_terms:t.mode==='lots'?{supply_tokens:21000000,tokens_per_lot:1000,min_lots:1,max_lots:10,public_sats_per_lot:700,operator_sats_per_lot:450}:null,pow: t.pow || null, start: t.start, end: t.end, deploy_txid: t.deploy_txid, height: t.height, meta: t.meta, auth_outpoint: t.auth_outpoint,
      treasury_address: treasury, state, price_sats: price, holders: holders?.n || 0, seals: holders?.seals || 0, pending_mints: pending || 0,
      wallet_cap: t.wallet_cap, allowlist: wl, public_left: publicLeft > 0n ? publicLeft : 0n };
  }

  async function utxosFor(req, address) {
    const given = builders.cleanUtxos(req.body.utxos, builders.DUST + 1);
    if (given.length) return { utxos: given, source: 'wallet' };
    const res = await boundedFetch(`${cfg.mempoolApi}/address/${encodeURIComponent(address)}/utxo`,{maxBytes:2*1024*1024});
    if (!res.ok) throw new Error(`Could not load UTXOs (${res.status}).`);
    // Without wallet-supplied UTXOs we can't see inscriptions/runes, so skip small coins that may carry them.
    return { utxos: builders.cleanUtxos(await res.json(), cfg.minServerUtxo), source: 'mempool.space' };
  }


  // PENDING_MINT_READOUT_V1
  function pendingView(token, sats, opts = {}) {
    const rows = db.raw.prepare("select paid,op from mempool where kind='mint' and tick=?").all(token.tick);
    let demand = 0n, unknown = 0;
    for (const row of rows) {
      if (row.paid == null && token.mode !== 'fair') { unknown++; continue; }
      // Independent quotes at confirmed state: potential demand, not a reservation.
      let pendingOptions={};
      let operation;try{operation=JSON.parse(row.op||'null')}catch{}
      if(token.pow&&operation?.operator){const key=operation.owner,next=tipHeight()+1,max=db.usage(token.tick,'op-max',key),used=db.usage(token.tick,'wl',key),expiry=Number(db.usage(token.tick,'op-expiry',key));if((token.mode!=='lots'&&!ts.wlActive(token,next))||expiry<next||max<=used)continue;pendingOptions={height:next,allowlist:{max,used}};}
      demand += ts.quoteMint(token, Number(row.paid || 0),pendingOptions).atoms;
    }
    const left = token.max > token.minted ? token.max - token.minted : 0n;
    const available = demand >= left ? 0n : left - demand;
    const quote = ts.quoteMint(token, sats, { height: tipHeight() + 1, ...opts });
    return { tick: token.tick, dec: token.dec, max_atoms: token.max,
      confirmed_atoms: token.minted, remaining_atoms: left,
      pending_mints: rows.length, pending_requested_atoms: demand,
      unknown_amount_mints: unknown, estimated_available_atoms: available,
      requested_atoms: quote.atoms, partial: quote.partial, capped: quote.capped, limited_by: quote.limited_by, clipped: quote.clipped,
      exceeds_estimate: quote.atoms > available,
      coverage: 'partial',
      note: 'Detected node transactions only. Estimates do not reserve supply; missing, replaced or reordered transactions can change the outcome.' };
  }
  r.get('/tokens/:tick/pending', (req, res) => {
    try {
      const token = db.token(String(req.params.tick).toUpperCase());
      if (!token) return fail(res, 404, 'Unknown ticker.');
      const sats = Number(req.query.sats || 0);
      if (!Number.isSafeInteger(sats) || sats < 0) return fail(res, 400, 'Invalid sats.');
      // With ?address= the pre-check uses the same pass and wallet usage the builder will use.
      let opts = {};
      if (req.query.address) {
        const { wallet, pass } = passFor(token, String(req.query.address));
        const usePass = !!pass && req.query.allowlist !== '0';
        opts = { allowlist: usePass ? { max: pass.max, used: pass.used } : null, walletUsed: wallet.wallet_used };
      }
      send(res, { ok: true, ...pendingView(token, sats, opts) });
    } catch (e) { fail(res, 400, e.message); }
  });

  // ── read ──────────────────────────────────────────────────────────────────
  r.get('/status', (req, res) => {
    const tip = db.tip();
    const node = db.node();
    send(res, { ok: true, api_version:'1.4.0-lots-rc.1', protocol_version:'1.2.0-compact-draft.2', root_scope:'seal-outputs-v1', validation:cfg.mode==='light'?'external-api-integrity-checks':'configured-bitcoin-rpc', network: net, tip, node, node_id: nodeId, public_url: cfg.publicUrl || null, mode: cfg.mode || node.mode || 'full', read_only: readOnly, consensus: peers.summary(),
      pow_activation:node.pow_activation??null, lot_activation:node.lot_activation??null,supported_extensions:['pow-v2','lot-v1'], activation: node.activation ?? null, mempool_ops: db.mempoolCount(), public_launch: false, launch_policy: require('./operator-policy').launchPolicy(cfg),
      owners: cfg.ownerAddresses, featured: cfg.featured, platform_fee_sats: cfg.platformFee.sats || 0 });
  });
  r.get('/node-incentives',(req,res)=>send(res,{ok:true,network:net,...require('./operator-policy').incentivesPolicy()}));
  // State root after a block: what peers compare.
  r.get('/root/:height', (req, res) => {
    const h = Number(req.params.height);
    if (!Number.isSafeInteger(h) || h < 0) return fail(res, 400, 'Invalid height.');
    const row = rootAt.get(h);
    if (!row) return fail(res, 404, 'This node has not indexed that block.');
    send(res, { ok: true, height: row.height, hash: row.hash, root: row.root, root_scope:'seal-outputs-v1' });
  });
  // Every node reachable from here and who checks whom (cached; ?refresh=1 recrawls at most every 15 s).
  r.get('/network', async (req, res) => {
    try {
      const cur = await network.get(false);
      const fresh = req.query.refresh === '1' && Date.now() - cur.crawled_at > 15_000 ? await network.get(true) : cur;
      send(res, fresh);
    } catch (e) { fail(res, 500, String(e.message || e)); }
  });
  r.get('/peers', (req, res) => {
    const tip = db.tip();
    send(res, { ok: true, self: { network: net, mode: cfg.mode || 'full', height: tip ? tip.height : null, root: tip ? tip.root : null },
      summary: peers.summary(), peers: peers.results(), announced: announcements.list(), checkins: peers.announced() });
  });
  // A node that others can't reach checks in here; its root is verified against ours and listed for 15 minutes.
  r.post('/announce', limit, (req, res) => {
    const out = announcements.accept(req.body, req.ip);
    if (!out.ok) return fail(res, out.code, out.error);
    send(res, out);
  });
  r.get('/tokens', (req, res) => {
    const tip = tipHeight(), h = db.holders(), p = db.pendingMints();
    send(res, { ok: true, tip, tokens: db.tokens().map((t) => tokenView(t, tip, h[t.tick], p[t.tick])) });
  });
  /** What one wallet may do on one token right now: wallet limit left and allowlist pass. */
  function walletView(t, address) {
    const owner = ts.ownerOfAddress(address, net).toString('hex');
    const next = tipHeight() + 1;
    const out = { address, owner, wallet_cap: t.wallet_cap, wallet_used: t.wallet_cap > 0n ? db.usage(t.tick, 'pub', owner) : 0n, allowlist: null };
    if (t.wallet_cap > 0n) out.wallet_left = t.wallet_cap > out.wallet_used ? t.wallet_cap - out.wallet_used : 0n;
    const entry = t.pow ? (db.usage(t.tick,'op-max',owner)>0n?{max:String(db.usage(t.tick,'op-max',owner)),expiry:Number(db.usage(t.tick,'op-expiry',owner))}:null) : wlStore.entry(t.tick, owner);
    if (entry) {
      const used = db.usage(t.tick, 'wl', owner);
      const max = BigInt(entry.max);
      const expiry = Math.min(Number(entry.expiry), t.wl ? t.wl.end : Number(entry.expiry));
      const active = (t.mode==='lots'||ts.wlActive(t,next))&&next<=expiry;
      const ready = t.pow ? (t.mode==='lots'||!!t.wl) : !!signerFor(t) && !!t.wl && signerFor(t).pub === t.wl.key;
      out.allowlist = { listed: true, max, used, left: max > used ? max - used : 0n, expiry, active, signer_ready: ready,
        reason: !t.wl && t.mode!=='lots' ? 'The allowlist phase has not been opened on chain yet.' : !ready ? 'The allowlist signer is not configured on this server.' : !active ? 'The allowlist phase is over.' : max <= used ? 'Allowance used.' : null };
    } else out.allowlist = { listed: false };
    return out;
  }
  function passFor(t, address) {
    const w = walletView(t, address);
    const a = w.allowlist;
    if (!a.listed || a.reason) return { wallet: w, pass: null };
    return { wallet: w, pass: { max: a.max, expiry: a.expiry, used: a.used, ...(t.pow?{registered:true}:{sig:signerFor(t).sign(t.tick,w.owner,a.max,a.expiry)}) } };
  }
  r.get('/tokens/id/:height/:index', (req, res) => {
    const t = db.tokenById(`${Number(req.params.height)}:${Number(req.params.index)}`);
    if (!t) return fail(res, 404, 'Unknown token ID.');
    return send(res, { ok: true, token: tokenView(t, tipHeight(), db.holders()[t.tick], db.pendingMints()[t.tick]) });
  });
  r.get('/allowlist/:tick', (req, res) => {
    const t = db.token(String(req.params.tick).toUpperCase());
    if (!t) return fail(res, 404, 'Unknown ticker.');
    send(res, { ok: true, tick: t.tick, allowlist: tokenView(t, tipHeight()).allowlist, signer_key: signerFor(t)?.pub||null, wallets: tokenView(t,tipHeight()).allowlist?.wallets||0 });
  });
  r.get('/allowlist/:tick/:address', (req, res) => {
    try {
      const t = db.token(String(req.params.tick).toUpperCase());
      if (!t) return fail(res, 404, 'Unknown ticker.');
      send(res, { ok: true, tick: t.tick, ...walletView(t, String(req.params.address)) });
    } catch (e) { fail(res, 400, e.message); }
  });
  r.get('/operator-policy',(req,res)=>send(res,{ok:true,network:net,signer_key:operatorSigner?.pub||null,legacy_discount_bps:1000,lot_profile:{public_sats_per_1000:700,approved_work_sats_per_1000:450,min_tokens:1000,max_tokens:10000},automatic_eligibility:false,note:'Public on-chain operator approvals. The main lot profile has immutable 700/450-sat prices and needs confirmed wallet quotas; legacy tokens may use price phases; no check-in or hash proves independent node service.'}));
  r.get('/pow/job',limit,(req,res)=>{try{
    const token=db.token(String(req.query.tick||'').toUpperCase()),node=db.node(),tip=db.tip();
    if(!token?.pow)throw Error('Token does not use PoW minting');
    if(!tip||node.pow_activation==null||tip.height+1<node.pow_activation)throw Error('PoW extension is not activated');
    if(!node.updated_at||Date.now()/1000-node.updated_at>180||node.lag!==0)throw Error('Indexer is stale or not synchronized');
    if(token.start&&tip.height+1<token.start||token.end&&tip.height+1>token.end||token.minted>=token.max)throw Error('Mint window unavailable or sold out');
    const owner=ts.ownerOfAddress(String(req.query.address||''),net).toString('hex'),paid=token.mode==='fair'?0:Number(req.query.pay_sats),lock=Number(req.query.lock||0),config=require('./pow').config(token.pow);
    if(token.mode==='lots'){const needed=ts.mintAmount(token,paid,true),maximum=db.usage(token.tick,'op-max',owner),used=db.usage(token.tick,'wl',owner),expiry=db.usage(token.tick,'op-expiry',owner);if(node.lot_activation==null||tip.height+1<node.lot_activation||needed<=0n||maximum-used<needed||expiry<BigInt(tip.height+1))throw Error('Approved work requires 1..10 lots at 450 sats each and a live on-chain wallet allowance');}
    if(token.mode!=='fair'&&token.mode!=='lots'&&(paid<546||paid>Number(token.params.cap)))throw Error('PoW payment must be at least 546 sats and no more than this token mint cap');
    const context={network:net,token,owner,height:tip.height,hash:tip.hash,paid,lock};
    return send(res,{ok:true,version:2,network:net,tick:token.tick,deploy_txid:token.deploy_txid,owner,paid,lock,height:tip.height,hash:tip.hash,bits:config.bits,expires_height:tip.height+config.max_age,prefix_hex:require('./pow').prefix(context).toString('hex'),note:'Hash work controls issuance; it is not BTC mining or proof of node eligibility.'});
  }catch(e){return fail(res,400,e.message)}});
  r.get('/tokens/:tick', (req, res) => {
    const t = db.token(String(req.params.tick).toUpperCase());
    if (!t) return fail(res, 404, 'Unknown ticker.');
    const tip = tipHeight();
    return send(res, { ok: true, token: tokenView(t, tip, db.holders()[t.tick], db.pendingMints()[t.tick]) });
  });
  r.get('/tokens/:tick/quote', (req, res) => {
    const t = db.token(String(req.params.tick).toUpperCase());
    if (!t) return fail(res, 404, 'Unknown ticker.');
    const sats = Math.max(0, Math.floor(Number(req.query.sats || 0)));
    try {
      let w = null, p = null;
      if (req.query.address) ({ wallet: w, pass: p } = passFor(t, String(req.query.address)));
      const usePass = !!p && req.query.allowlist !== '0';
      const q = ts.quoteMint(t, sats, { height: tipHeight() + 1, allowlist: usePass ? { max: p.max, used: p.used } : null, walletUsed: w ? w.wallet_used : 0n });
      return send(res, { ok: true, tick: t.tick, ...q, wallet: w, pending_mints: db.pendingMints()[t.tick] || 0 });
    } catch (e) { return fail(res, 400, e.message); }
  });
  r.get('/seals', (req, res) => {
    try {
      const owner = ts.ownerOfAddress(String(req.query.address || ''), net);
      send(res, { ok: true, owner: owner.toString('hex'), tip: tipHeight(), seals: db.sealsOf(owner, net) });
    } catch (e) { fail(res, 400, e.message); }
  });
  r.get('/events', (req, res) => {
    const lim = Math.min(200, Math.max(1, Number(req.query.limit || 50)));
    send(res, { ok: true, events: db.events({ tick: req.query.tick ? String(req.query.tick).toUpperCase() : null, before: req.query.before ? Number(req.query.before) : null, limit: lim }) });
  });
  r.get('/blocks', (req, res) => {
    const lim = Math.min(20, Math.max(1, Number(req.query.limit || 8)));
    send(res, { ok: true, blocks: db.blocks(lim).map((b) => ({ ...b, ops: db.opsAt(b.height) })) });
  });
  r.get('/mempool', (req, res) => {
    const lim = Math.min(500, Math.max(1, Number(req.query.limit || 200)));
    const node = db.node();
    send(res, { ok: true, tip: db.tip(), ops: db.mempool(lim), stats: node.mempool_enabled === false ? null : node.mempool || null, scanner: require('./scanner-status').scannerStatus(db), fees: node.fees || null });
  });

  // ── PSBT builders ─────────────────────────────────────────────────────────
  const common = (req) => {
    const address = String(req.body.address || '').trim();
    const publicKey = String(req.body.public_key || '').trim();
    const feeRate = Math.max(1, Math.min(1000, Number(req.body.fee_rate || 2)));
    if (!address) throw new Error('Connect a wallet first.');
    return { address, publicKey, feeRate, network: net };
  };
  const wrap = (fn) => async (req, res) => {
    try { send(res, { ok: true, ...(await fn(req)) }); } catch (e) { fail(res, 400, String(e.message || e)); }
  };

  // PERSISTENT_INDEXING_V2 scanner status
  r.get('/scanner-status', (req, res) => {
    res.set('Cache-Control', 'no-store');
    send(res, require('./scanner-status').scannerStatus(db));
  });

  // SAFETY_PREVIEW_V1
  let activePreviews=0;
  r.post('/transactions/simulate', limit, wrap(async (req) => {
    if(activePreviews>=2)throw new Error('Preview capacity reached. Retry shortly.');
    activePreviews++;
    try{return await require('./preview').simulate({ ...cfg, previewRequireRpc: cfg.previewRequireRpc !== false }, req.body);}
    finally{activePreviews--;}
  }));

  r.post('/psbt/mint', limit, wrap(async (req) => {
    const c = common(req);
    const token = db.token(String(req.body.tick || '').toUpperCase());
    if (!token) throw new Error('Unknown ticker.');
    if(token.pow&&(token.mode!=='lots'||req.body.allowlist===true)){const tip=db.tip(),node=db.node();if(node.pow_activation==null||tip.height+1<node.pow_activation)throw Error('PoW extension not activated');
      const proof=req.body.proof;if(!proof)throw Error('Find a PoW proof before building this mint');
      const block=db.raw.prepare('select hash from blocks where height=?').get(proof.height);if(!block||block.hash!==proof.hash)throw Error('PoW anchor is not canonical');
      const digest=require('./pow').check({token,owner:ts.ownerOfAddress(c.address,net).toString('hex'),network:net,tip,proof,paid:token.mode==='fair'?0:Number(req.body.pay_sats),lock:Number(req.body.lock||0)});
      if(db.usage(token.tick,'pow',digest)>0n)throw Error('PoW proof already used');
    }
    const { wallet, pass: found } = passFor(token, c.address);
    const pass = req.body.allowlist === false || (token.mode==='lots'&&req.body.allowlist!==true) ? null : found;
    if (req.body.allowlist === true && !pass) throw new Error(wallet.allowlist.listed ? wallet.allowlist.reason || 'No allowlist pass available.' : 'This wallet is not on the allowlist.');
    if(token.mode==='lots'){const q=ts.quoteMint(token,Number(req.body.pay_sats),{allowlist:pass?{max:pass.max,used:pass.used}:null});if(q.clipped)throw Error('Choose 1..10 whole 1,000-token lots within your allowance and remaining supply');}
    const pending = pendingView(token, Math.max(0, Math.floor(Number(req.body.pay_sats || 0))),
      { allowlist: pass ? { max: pass.max, used: pass.used } : null, walletUsed: wallet.wallet_used });
    if (pending.requested_atoms <= 0n) throw new Error(pending.limited_by === 'wallet' ? `This wallet has reached the ${token.tick} mint limit.` : pending.limited_by === 'pass' ? 'Your allowlist allowance is used up.' : pending.limited_by === 'reserve' ? `The rest of ${token.tick} is reserved for the allowlist until block ${token.wl.end}.` : `${token.tick} is sold out.`);
    // A clipped paid mint would lose the extra BTC, so refuse it. A clipped fair mint costs nothing extra.
    if (pending.capped || ((pending.partial || pending.clipped) && token.mode !== 'fair')) throw new Error(pending.limited_by === 'wallet' ? 'Reduce payment: it is more than this wallet may still mint.' : pending.limited_by === 'pass' ? 'Reduce payment: it is more than your allowlist allowance.' : pending.limited_by === 'reserve' ? 'Reduce payment: the rest of the supply is reserved for the allowlist.' : 'Reduce payment: this request exceeds the mint cap or confirmed remaining supply.');
    if (pending.exceeds_estimate) throw new Error('Detected pending mints leave insufficient estimated supply. Wait for confirmation or reduce your mint.');
    const { utxos, source } = await utxosFor(req, c.address);
    return { utxo_source: source, ...builders.buildMint({ ...c, proof:req.body.proof || null, token, tip: tipHeight(), paySats: req.body.pay_sats, lock: Number(req.body.lock || 0), utxos, platformFee: cfg.platformFee, pass, walletUsed: wallet.wallet_used }) };
  }));
  r.post('/psbt/transfer', limit, wrap(async (req) => {
    const c = common(req);
    const tick = String(req.body.tick || '').toUpperCase();
    const seals = db.sealsOf(ts.ownerOfAddress(c.address, net), net);
    const { utxos, source } = await utxosFor(req, c.address);
    return { utxo_source: source, ...builders.buildTransfer({ ...c, tick, tip: tipHeight(), seals, recipients: req.body.recipients || [], utxos }) };
  }));
  r.post('/psbt/burn', limit, wrap(async (req) => {
    const c = common(req);
    const tick = String(req.body.tick || '').toUpperCase();
    const seals = db.sealsOf(ts.ownerOfAddress(c.address, net), net);
    const { utxos, source } = await utxosFor(req, c.address);
    return { utxo_source: source, ...builders.buildBurn({ ...c, tick, tip: tipHeight(), seals, atoms: req.body.atoms, utxos }) };
  }));
  r.post('/psbt/deploy', limit, wrap(async (req) => {
    const c = common(req);
    require('./operator-policy').assertOwnerLaunch(cfg,c.address);
    if(req.body.mode==='lots'){const n=db.node(),tip=db.tip();if(n.lot_activation==null||!tip||tip.height+1<n.lot_activation)throw Error('Lot profile is not activated on Mainnet yet');}
    if(req.body.pow){const n=db.node(),tip=db.tip();if(n.pow_activation==null||!tip||tip.height+1<n.pow_activation)throw Error('PoW extension is not activated on this network');require('./pow').config(req.body.pow);}
    const tick = String(req.body.tick || '').toUpperCase();
    if (db.token(tick)) throw new Error(`${tick} is already deployed.`);
    const { utxos, source } = await utxosFor(req, c.address);
    return { utxo_source: source, ...builders.buildDeploy({ ...c, form: req.body, utxos }) };
  }));

  r.post('/psbt/operator',limit,wrap(async(req)=>{const c=common(req),token=db.token(String(req.body.tick||'').toUpperCase());if(!token?.pow)throw Error('Unknown compact PoW token');const seals=db.sealsOf(ts.ownerOfAddress(c.address,net),net),{utxos,source}=await utxosFor(req,c.address);return{utxo_source:source,...builders.buildOperator({...c,token,tip:tipHeight(),seals,form:req.body,utxos})};}));
  r.post('/psbt/allowlist', limit, wrap(async (req) => {
    const c = common(req);
    const token = db.token(String(req.body.tick || '').toUpperCase());
    if (!token) throw new Error('Unknown ticker.');
    const seals = db.sealsOf(ts.ownerOfAddress(c.address, net), net);
    const { utxos, source } = await utxosFor(req, c.address);
    const selectedSigner = signerFor(token);
    const form = { ...req.body, key: req.body.key || selectedSigner?.pub || '' };
    if (Number(form.end || 0) && selectedSigner && form.key !== selectedSigner.pub) throw new Error('That signer key is not the one this server signs passes with.');
    return { utxo_source: source, ...builders.buildAllowlist({ ...c, token, tip: tipHeight(), seals, form, utxos }) };
  }));

  // ── broadcast ─────────────────────────────────────────────────────────────
  let activeBroadcasts=0;
  r.post('/broadcast', limit, wrap(async (req) => {
    if(activeBroadcasts>=4)throw new Error('Broadcast capacity reached. Retry shortly.');
    activeBroadcasts++;
    try{
    const tx = builders.extract(req.body.psbt || req.body.rawtx, net);
    if(ts.sniffPayload(tx)?.kind==='deploy')await require('./operator-policy').assertOwnerDeploymentRelay(cfg,tx,net,async(method,params)=>{
      const auth=cfg.rpc.bearer?`Bearer ${cfg.rpc.bearer}`:cfg.rpc.user?`Basic ${Buffer.from(`${cfg.rpc.user}:${cfg.rpc.password}`).toString('base64')}`:undefined;
      const response=await boundedFetch(cfg.rpc.url,{method:'POST',timeoutMs:8000,headers:{'content-type':'application/json',...(auth?{authorization:auth}:{})},body:JSON.stringify({jsonrpc:'1.0',id:'owner-deploy',method,params})});
      const result=await response.json();if(!response.ok||result.error)throw Error('Owner funding input verification unavailable.');return result.result;
    });
    const powMint=ts.sniffPayload(tx);
    if(powMint?.kind==='operator'){
      if(!req.body.psbt||!req.body.owner_address||req.body.expected?.op!=='operator'||req.body.expected.tick!==powMint.tick)throw Error('Operator updates require a reviewed PSBT and exact approval expectation');
      const checked=await require('./preview').simulate({...cfg,previewRequireRpc:true},{psbt:req.body.psbt,owners:[req.body.owner_address],expected:req.body.expected});
      if(!checked.valid)throw Error('Operator relay refused: '+checked.errors.join('; '));
    }
    if(powMint?.kind==='mint'&&db.token(powMint.tick)?.pow){
      if(!req.body.psbt||!req.body.owner_address)throw Error('PoW claims require a reviewed PSBT and owner_address');
      const checked=await require('./preview').simulate({...cfg,previewRequireRpc:true},{psbt:req.body.psbt,owners:[req.body.owner_address],expected:{op:'mint',tick:powMint.tick,allowlist:req.body.allowlist===true}});
      if(!checked.valid)throw Error('PoW relay refused: '+checked.errors.join('; '));
    }
    const hex = tx.toHex();
    let txid;
    if (cfg.rpc.url) {
      const auth = cfg.rpc.bearer ? `Bearer ${cfg.rpc.bearer}` : cfg.rpc.user ? `Basic ${Buffer.from(`${cfg.rpc.user}:${cfg.rpc.password}`).toString('base64')}` : undefined;
      const expectedChain={mainnet:'main',testnet3:'test',testnet:'testnet4',testnet4:'testnet4',signet:'signet',regtest:'regtest'}[net];
      const chainReply=await boundedFetch(cfg.rpc.url,{method:'POST',headers:{'content-type':'application/json',...(auth?{authorization:auth}:{})},body:JSON.stringify({jsonrpc:'1.0',id:'network-check',method:'getblockchaininfo',params:[]})});
      const chain=await chainReply.json();
      if(!chainReply.ok||chain.error||chain.result?.chain!==expectedChain||chain.result?.initialblockdownload)throw new Error('RPC network mismatch or node still synchronizing; broadcast refused.');
      const reply = await boundedFetch(cfg.rpc.url, { method: 'POST', headers: { 'content-type': 'application/json', ...(auth ? { authorization: auth } : {}) },
        body: JSON.stringify({ jsonrpc: '1.0', id: 'tapseal', method: 'sendrawtransaction', params: [hex] }) });
      const out=await reply.json();
      if (out.error) throw new Error('Bitcoin RPC rejected transaction ('+String(out.error.code??'unknown')+').');
      if(!reply.ok)throw new Error('Bitcoin RPC relay unavailable.');
      txid = out.result;
    } else {
      const out = await boundedFetch(`${cfg.mempoolApi}/tx`, { method: 'POST', body: hex });
      if (!out.ok) throw new Error('Transaction relay rejected the request ('+out.status+').');
      txid = (await out.text()).trim();
    }
    if(typeof txid!=='string'||txid!==tx.getId())throw new Error('Relay returned a different transaction ID; verify the transaction before retrying.');
    const sniff = ts.sniffPayload(tx);
    if (sniff) {
      const tok = sniff.tick ? db.token(sniff.tick) : null;
      const paid = sniff.kind === 'mint' && tok && tok.treasury_spk ? tx.outs.filter((o, i) => i !== 1 && o.script.toString('hex') === tok.treasury_spk).reduce((s2, o) => s2 + o.value, 0) : null;
      const feeIn = Number(req.body.fee_sats || 0);
      db.insertMempool({ txid, seen: Math.floor(Date.now() / 1000), kind: sniff.kind, tick: sniff.tick, op: null, error: null,
        fee_rate: feeIn ? Math.round((feeIn / tx.virtualSize()) * 100) / 100 : null, vsize: tx.virtualSize(), bytes: sniff.bytes, source: 'api', paid });
    }
    return { txid, vsize: tx.virtualSize() };
    }finally{activeBroadcasts--;}
  }));

  return r;
}

module.exports = { createRouter };
