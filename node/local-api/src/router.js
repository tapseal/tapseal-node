// Node-only read API. No transaction builders, signing services or relay handlers.
const express=require('express'),ts=require('./tapseal'),dbm=require('./db');
const {createPeers}=require('./peers'),{createNetwork}=require('./network'),{createAnnouncements}=require('./announce');
function createRouter(cfg){
 const db=dbm.open(cfg.dbPath),net=cfg.network,r=express.Router();
 if(db.node().network&&db.node().network!==net){db.raw.close();throw Error('Database network does not match API configuration.')}
 const send=(res,body)=>res.type('json').send(JSON.stringify(body,(_,v)=>typeof v==='bigint'?v.toString():v));
 const fail=(res,code,error)=>res.status(code).json({ok:false,error}),tipHeight=()=>db.tip()?.height??0;
 const nodeId=cfg.nodeId||require('crypto').createHash('sha256').update(`${require('os').hostname()}|${cfg.dbPath}`).digest('hex').slice(0,16);
 const peers=cfg.peersInstance||createPeers({peers:cfg.peers||[],db,network:net,intervalMs:cfg.peerIntervalMs,fetchImpl:cfg.peerFetchImpl,announce:cfg.announce===false?null:{id:nodeId,mode:cfg.mode||'full',url:cfg.publicUrl||null,version:'1.4.1-node-only.1'}});
 const announcements=createAnnouncements({db,network:net});
 const network=cfg.networkInstance||createNetwork({db,peers,announcements,self:{id:nodeId,url:cfg.publicUrl||null,mode:cfg.mode||'full',network:net},fetchImpl:cfg.peerFetchImpl,maxNodes:cfg.mapMaxNodes,maxDepth:cfg.mapMaxDepth,cacheMs:cfg.mapCacheMs});
 if(cfg.peerCheck!==false)peers.start();
 const rootAt=db.raw.prepare('select height,hash,root from blocks where height=?');
 const hits=new Map();
 const limit=(req,res,next)=>{const now=Date.now(),key=req.ip,rows=(hits.get(key)||[]).filter(t=>now-t<60000);if(rows.length>=60)return fail(res,429,'Too many requests; retry later.');if(hits.size>=4096&&!hits.has(key)){for(const [k,v] of hits)if(!v.some(t=>now-t<60000))hits.delete(k);if(hits.size>=4096)return fail(res,429,'Request limiter full.')}rows.push(now);hits.set(key,rows);next()};
 // This boundary is unconditional, including full/RPC indexing and HOME_NODE=false.
 r.use((req,res,next)=>{if(!['GET','HEAD'].includes(req.method)&&!(req.method==='POST'&&req.path==='/announce'))return fail(res,503,'Node-only API: transaction creation, owner management, signing and broadcast are not installed.');next()});
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
        wallets: t.pow ? db.raw.prepare("select count(*) n from usage where tick=? and kind='op-max' and cast(atoms as integer)>0").get(t.tick).n : null, signer_ready: t.pow ? true : false };
    }
    const publicLeft = t.max - t.minted - (wl ? wl.reserve_left : 0n);
    return { tick: t.tick, id: t.id, dec: t.dec, mode: t.mode, params: t.params, max: t.max, minted: t.minted, burned: t.burned, lost: t.lost,
      lot_terms:t.mode==='lots'?{supply_tokens:21000000,tokens_per_lot:1000,min_lots:1,max_lots:10,public_sats_per_lot:700,operator_sats_per_lot:450}:null,pow: t.pow || null, start: t.start, end: t.end, deploy_txid: t.deploy_txid, height: t.height, meta: t.meta, auth_outpoint: t.auth_outpoint,
      treasury_address: treasury, state, price_sats: price, holders: holders?.n || 0, seals: holders?.seals || 0, pending_mints: pending || 0,
      wallet_cap: t.wallet_cap, allowlist: wl, public_left: publicLeft > 0n ? publicLeft : 0n };
  }

 r.get('/status',(req,res)=>{const node=db.node();send(res,{ok:true,api_version:'1.4.1-node-only.1',distribution:'node-only',protocol_version:'1.2.0-compact-draft.2',network:net,mode:cfg.mode||node.mode||'full',read_only:true,tip:db.tip(),node,node_id:nodeId,public_url:cfg.publicUrl||null,root_scope:'seal-outputs-v1',validation:cfg.mode==='light'?'external-api-integrity-checks':'configured-bitcoin-rpc',consensus:peers.summary(),activation:node.activation??null,pow_activation:node.pow_activation??null,lot_activation:node.lot_activation??null,supported_extensions:['pow-v2','lot-v1'],mempool_ops:db.mempoolCount()})});
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
  r.get('/tokens/id/:height/:index', (req, res) => {
    const t = db.tokenById(`${Number(req.params.height)}:${Number(req.params.index)}`);
    if (!t) return fail(res, 404, 'Unknown token ID.');
    return send(res, { ok: true, token: tokenView(t, tipHeight(), db.holders()[t.tick], db.pendingMints()[t.tick]) });
  });
  r.get('/tokens/:tick', (req, res) => {
    const t = db.token(String(req.params.tick).toUpperCase());
    if (!t) return fail(res, 404, 'Unknown ticker.');
    const tip = tipHeight();
    return send(res, { ok: true, token: tokenView(t, tip, db.holders()[t.tick], db.pendingMints()[t.tick]) });
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

 r.get('/pow/job',limit,(req,res)=>{try{
 const tick=String(req.query.tick||'').toUpperCase(),address=String(req.query.address||''),pay=Number(req.query.pay_sats||0);
 require('./miner-policy').validateStart(db,net,{tick,address,pay_sats:pay});
 const token=db.token(tick),tip=db.tip(),owner=ts.ownerOfAddress(address,net).toString('hex'),work=require('./pow'),config=work.config(token.pow);
 if(req.query.lock&&Number(req.query.lock)!==0)throw Error('The local worker searches unlocked receiving seals only');
 const paid=token.mode==='fair'?0:pay,context={network:net,token,owner,height:tip.height,hash:tip.hash,paid,lock:0};
 send(res,{ok:true,version:2,network:net,tick,deploy_txid:token.deploy_txid,owner,paid,lock:0,height:tip.height,hash:tip.hash,bits:config.bits,expires_height:tip.height+config.max_age,prefix_hex:work.prefix(context).toString('hex'),note:'Unsigned owner-bound proof search only. No payment or transaction is created.'});
 }catch(e){fail(res,400,e.message)}});
 r.get('/scanner-status',(req,res)=>send(res,require('./scanner-status').scannerStatus(db)));
 r.use((req,res)=>fail(res,404,'Route not included in the node-only distribution.'));
 return r;
}
module.exports={createRouter};
