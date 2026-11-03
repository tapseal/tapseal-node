// Watch-only local state. Snapshots are consistent DB reads; failed saves/scans retain
// the last committed in-memory/file state. No wallet secrets or external wallet lookups.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const ts=require('./tapseal');const MAX_BYTES=8*1024*1024,MAX_WALLETS=10,MAX_SEALS=2000;
function validate(state,network){
 if(!state||state.version!==1||state.network!==network||!Array.isArray(state.wallets)||state.wallets.length>MAX_WALLETS||!Array.isArray(state.alerts)||state.alerts.length>100)throw Error('Invalid or wrong-network wallet monitor file');
 const addresses=new Set();
 for(const w of state.wallets){
  if(!w||typeof w.address!=='string'||w.address.length>120||addresses.has(w.address)||typeof w.baseline!=='boolean'||!Array.isArray(w.seals)||w.seals.length>MAX_SEALS)throw Error('Invalid wallet snapshot');
  ts.ownerOfAddress(w.address,network);addresses.add(w.address);
  if(w.baseline&&(!Number.isSafeInteger(w.height)||w.height<0||typeof w.hash!=='string'||w.hash.length>64||!Number.isFinite(w.checked_at)))throw Error('Invalid wallet snapshot tip');
  const outputs=new Set();for(const s of w.seals){if(!s||typeof s.outpoint!=='string'||s.outpoint.length>80||outputs.has(s.outpoint)||!(/^[A-Z0-9]{1,8}$/).test(s.tick)||typeof s.amt!=='string'||!(/^\d{1,80}$/).test(s.amt)||![0,1].includes(s.auth)||!Number.isSafeInteger(s.height)||s.height<0||!Number.isSafeInteger(s.lock)||s.lock<0)throw Error('Invalid stored seal');outputs.add(s.outpoint);}
 }
 for(const a of state.alerts)if(!a||!addresses.has(a.address)||!['seal_added','seal_removed'].includes(a.kind)||typeof a.outpoint!=='string'||a.outpoint.length>80||!(/^[A-Z0-9]{1,8}$/).test(a.tick)||!Number.isFinite(a.time)||!Number.isSafeInteger(a.at_height))throw Error('Invalid stored alert');
}
function createMonitor({db,network,file,now=Date.now}){
 let state={version:1,network,wallets:[],alerts:[]},error=null;
 if(fs.existsSync(file)){
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try{const st=fs.fstatSync(fd);if(!st.isFile()||st.size>MAX_BYTES||st.uid!==process.getuid())throw Error('Unsafe monitor state file');const raw=Buffer.alloc(st.size+1);const count=fs.readSync(fd,raw,0,raw.length,0);if(count!==st.size)throw Error('Monitor state changed during read');state=JSON.parse(raw.subarray(0,count));validate(state,network);fs.fchmodSync(fd,0o600);}finally{fs.closeSync(fd)}
 }
 function commit(next){
  validate(next,network);const bytes=JSON.stringify(next);if(Buffer.byteLength(bytes)>MAX_BYTES)throw Error('Monitor state exceeds limit');
  fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});const tmp=file+'.'+crypto.randomBytes(8).toString('hex')+'.tmp';let fd;
  try{fd=fs.openSync(tmp,'wx',0o600);fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;fs.renameSync(tmp,file);state=next;}finally{if(fd!==undefined)fs.closeSync(fd);if(fs.existsSync(tmp))fs.unlinkSync(tmp)}
 }
 function scan(){try{
  const next=structuredClone(state);
  function snapshot(){const tip=db.tip();if(!tip)throw Error('Indexer has no block history yet');for(const w of next.wallets){const rows=db.sealsOf(ts.ownerOfAddress(w.address,network),network);if(rows.length>MAX_SEALS)throw Error('Wallet exceeds 2000-seal monitoring limit');const seals=rows.map(r=>({outpoint:r.outpoint,tick:r.tick,amt:String(r.amt),lock:r.lock,auth:r.auth,height:r.height}));const old=new Map(w.seals.map(r=>[r.outpoint,r])),current=new Set(seals.map(r=>r.outpoint));
   if(w.baseline){for(const r of seals)if(!old.has(r.outpoint))next.alerts.unshift({time:now(),address:w.address,kind:'seal_added',outpoint:r.outpoint,tick:r.tick,at_height:tip.height});for(const r of old.values())if(!current.has(r.outpoint))next.alerts.unshift({time:now(),address:w.address,kind:'seal_removed',outpoint:r.outpoint,tick:r.tick,at_height:tip.height});}
   w.seals=seals;w.baseline=true;w.height=tip.height;w.hash=tip.hash;w.checked_at=now();}}
  if(db.raw)db.raw.transaction(snapshot)();else snapshot();
  next.alerts=next.alerts.slice(0,100);if(next.wallets.length)commit(next);error=null;
 }catch(e){error=String(e.message||e)}}
 function view(){const n=db.node(),tip=db.tip();return{ok:true,network,served_at:now(),error,tip,telemetry_updated_at:n.updated_at??null,lag:n.lag??null,poll_seconds:30,limitations:'Confirmed TAPSEAL seals within indexed history only. No pending spend detection or full Bitcoin validation. Removal may mean spend, reorg or replay.',wallets:state.wallets.map(w=>{const balances=new Map();for(const r of w.seals)if(!r.auth)balances.set(r.tick,(balances.get(r.tick)||0n)+BigInt(r.amt));return{...w,balances:[...balances].map(([tick,atoms])=>({tick,atoms:atoms.toString()}))}}),alerts:state.alerts}}
 function add(address){address=String(address||'').trim();if(address.length>120)throw Error('Address too long');ts.ownerOfAddress(address,network);if(state.wallets.some(w=>w.address===address))return view();if(state.wallets.length>=MAX_WALLETS)throw Error('Maximum 10 watched addresses');const next=structuredClone(state);next.wallets.push({address,seals:[],baseline:false});commit(next);scan();return view()}
 function remove(address){const next=structuredClone(state);next.wallets=next.wallets.filter(w=>w.address!==address);next.alerts=next.alerts.filter(a=>a.address!==address);commit(next);return view()}
 scan();const timer=setInterval(scan,30000);timer.unref?.();return{view,add,remove,scan,stop:()=>clearInterval(timer)};
}
function localOnly(req,res,next){const remote=req.socket?.remoteAddress;if(!['127.0.0.1','::1','::ffff:127.0.0.1'].includes(remote))return res.status(403).json({ok:false,error:'Loopback connection required'});const host=String(req.headers.host||'');if(!/^(127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$/.test(host))return res.status(403).json({ok:false,error:'Local node host required'});if(req.headers['x-tapseal-monitor']!=='1'||(req.headers.origin&&req.headers.origin!==`http://${host}`))return res.status(403).json({ok:false,error:'Local monitor request required'});next()}
module.exports={createMonitor,localOnly};
