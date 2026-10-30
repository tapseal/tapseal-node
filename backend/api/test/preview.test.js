const test=require('node:test');
const assert=require('node:assert/strict');
const {execFileSync}=require('child_process');
const path=require('path');
const fs=require('fs');
const os=require('os');
const http=require('http');
const Database=require('better-sqlite3');
const ts=require('../src/tapseal');
const build=require('../src/psbt');
const {simulate}=require('../src/preview');
const {ECPairFactory}=require('ecpair');
const ECPair=ECPairFactory(ts.ecc),bitcoin=ts.bitcoin;
const sk=Buffer.from('1f'.repeat(32),'hex'),user=ECPair.fromPrivateKey(sk);
const x=user.publicKey.subarray(1);
const address=bitcoin.payments.p2tr({internalPubkey:x}).address;
const tweaked=user.tweak(bitcoin.crypto.taggedHash('TapTweak',x));
const other=bitcoin.payments.p2tr({internalPubkey:ECPair.fromPrivateKey(Buffer.from('2f'.repeat(32),'hex')).publicKey.subarray(1)}).address;
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'tapseal-preview-'));
const dbPath=path.join(tmp,'state.sqlite');
const cfg={dbPath,network:'mainnet',previewRequireRpc:false};
const utxos=[{txid:'ab'.repeat(32),vout:0,value:300000}];
const common={address,publicKey:user.publicKey.toString('hex'),feeRate:2,utxos,network:'mainnet',tip:103};
let token,seals;
test.before(()=>{
 execFileSync('python3',['-I',path.join(__dirname,'fixture.py'),'make',dbPath,sk.toString('hex')]);
 const db=require('../src/db').open(dbPath);token=db.token('STONK');seals=db.sealsOf(ts.ownerOfAddress(address,'mainnet'),'mainnet');db.raw.close();
});
test.after(()=>fs.rmSync(tmp,{recursive:true,force:true}));
const mint=()=>build.buildMint({...common,token,paySats:25000});
const request=(made,expected={})=>({psbt:made.psbt_hex,owners:[address,other],expected:{op:made.op,tick:made.tick,atoms:made.atoms,pay_sats:made.pay_sats,...expected}});
test('preview reports exact mint effects and fee without modifying the ledger',async()=>{
 const made=mint(),db=new Database(dbPath),before=db.prepare('select json from tokens order by tick').all();db.close();
 const q=await simulate(cfg,request(made));assert.equal(q.valid,true,JSON.stringify(q));assert.equal(q.inputs_verified,false);assert.equal(q.btc_fee_sats,made.fee_sats);assert.equal(q.effects.created[0].atoms,made.atoms);assert.equal(q.pending.complete,false);
 const afterDb=new Database(dbPath);assert.deepEqual(afterDb.prepare('select json from tokens order by tick').all(),before);afterDb.close();
});
test('preview refuses receiving seals owned by an unexpected key',async()=>{
 const made=build.buildMint({...common,address:other,publicKey:ECPair.fromPrivateKey(Buffer.from('2f'.repeat(32),'hex')).publicKey.toString('hex'),token,paySats:25000});
 const q=await simulate(cfg,{...request(made),owners:[address]});assert.equal(q.valid,false);assert.match(q.errors.join(' '),/expected wallet/);
});
test('preview rejects a changed minimum mint allocation',async()=>{
 const made=mint();const q=await simulate(cfg,request(made,{atoms:(BigInt(made.atoms)+1n).toString()}));assert.equal(q.valid,false);assert.match(q.errors.join(' '),/allocation changed/);
});
test('preview handles a locked transfer and checks recipient amount/address',async()=>{
 const recipients=[{address:other,atoms:'100000',lock:110}];
 const made=build.buildTransfer({...common,tick:'STONK',seals,recipients});
 const q=await simulate(cfg,request(made,{recipients}));assert.equal(q.valid,true,JSON.stringify(q));assert.equal(q.effects.created.find(s=>s.outpoint.endsWith(':1')).lock,110);
 const wrong=await simulate(cfg,request(made,{recipients:[{...recipients[0],atoms:'100001'}]}));assert.equal(wrong.valid,false);assert.match(wrong.errors.join(' '),/Recipient allocation/);
});
test('preview detects seal loss when a transfer is replaced by a mint',async()=>{
 const made=build.buildTransfer({...common,tick:'STONK',seals,recipients:[{address:other,atoms:'100000'}]});
 // Rebuild an unsigned PSBT with the same inputs and a different operation.
 const p=bitcoin.Psbt.fromHex(made.psbt_hex),raw=bitcoin.Transaction.fromBuffer(p.data.globalMap.unsignedTx.toBuffer()),changed=new bitcoin.Psbt();
 raw.ins.forEach((i,n)=>changed.addInput({hash:i.hash,index:i.index,sequence:i.sequence,...p.data.inputs[n]}));
 raw.outs.forEach((o,n)=>changed.addOutput(n===0?{script:ts.opReturnScript(ts.encode({op:'mint',tick:'STONK',vout:1,lock:0})),value:0}:o));
 const q=await simulate(cfg,{...request(made),psbt:changed.toHex()});assert.equal(q.valid,false);assert.ok(q.effects.events.some(e=>e.kind==='lost'));
});
test('preview rejects stale indexer state',async()=>{
 const db=new Database(dbPath),prior=db.prepare("select value from node where key='updated_at'").get();db.prepare("update node set value='1' where key='updated_at'").run();db.close();
 try{const q=await simulate(cfg,request(mint()));assert.equal(q.valid,false);assert.match(q.errors.join(' '),/stale/);}finally{const d=new Database(dbPath);d.prepare("update node set value=? where key='updated_at'").run(prior.value);d.close();}
});
test('live preview verifies UTXOs and checks finalized transaction admission',async()=>{
 const made=mint(),p=bitcoin.Psbt.fromHex(made.psbt_hex),calls=[];
 const tipDb=new Database(dbPath);const tip=tipDb.prepare('select height,hash from blocks order by height desc limit 1').get();tipDb.close();
 let rejectTx=false,chainName='main',chainHash=tip.hash,spent=false;
 const server=http.createServer((req,res)=>{let body='';req.on('data',d=>body+=d);req.on('end',()=>{const j=JSON.parse(body);calls.push(j.method);let result;
  if(j.method==='gettxout')result=spent?null:{value:0.003,scriptPubKey:{hex:p.data.inputs[0].witnessUtxo.script.toString('hex')}};
  if(j.method==='getblockchaininfo')result={chain:chainName,blocks:tip.height,bestblockhash:chainHash,initialblockdownload:false};
  if(j.method==='testmempoolaccept')result=[{allowed:!rejectTx,'reject-reason':rejectTx?'test rejection':undefined}];
  res.setHeader('content-type','application/json');res.end(JSON.stringify({result,error:null}));
 });});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{
  const live={...cfg,previewRequireRpc:true,rpc:{url:'http://127.0.0.1:'+server.address().port}};
  let q=await simulate(live,request(made));assert.equal(q.valid,true);assert.equal(q.inputs_verified,true);assert.equal(q.node_admission,'not_checked_unsigned');
  p.signAllInputs(tweaked);p.finalizeAllInputs();q=await simulate(live,{...request(made),psbt:p.toHex()});assert.equal(q.valid,true);assert.equal(q.node_admission,'accepted');assert.ok(calls.includes('testmempoolaccept'));
  chainHash='ff'.repeat(32);await assert.rejects(simulate(live,request(made)),/canonical node tip/);chainHash=tip.hash;
  chainName='test';await assert.rejects(simulate(live,request(made)),/network/);chainName='main';
  rejectTx=true;q=await simulate(live,{...request(made),psbt:p.toHex()});assert.equal(q.valid,false);assert.match(q.errors.join(' '),/node rejected/);
  spent=true;await assert.rejects(simulate(live,request(made)),/spent or unavailable/);
 }finally{await new Promise(r=>server.close(r));}
});
test('preview validates deployment metadata-authority ownership',async()=>{
 const made=build.buildDeploy({...common,form:{tick:'NEWTEST',dec:0,max_atoms:'10000',mode:'fair',lim_atoms:'100',auth:true}});
 const q=await simulate(cfg,request(made,{max_atoms:'10000',dec:0,mode:'fair',lim_atoms:'100'}));assert.equal(q.valid,true,JSON.stringify(q));assert.equal(q.effects.created[0].authority,true);
});

test('pending demand is checked from the current snapshot before a fair mint',async()=>{
 const db=new Database(dbPath),original=db.prepare("select json from tokens where tick='FREE'").get().json;
 const token=JSON.parse(original);token.minted=String(BigInt(token.max)-1000n);
 db.prepare("update tokens set json=? where tick='FREE'").run(JSON.stringify(token));
 db.prepare("insert into mempool(txid,seen,kind,tick,source) values(?,?,'mint','FREE','api')").run('cd'.repeat(32),Math.floor(Date.now()/1000));db.close();
 try{
  const d=require('../src/db').open(dbPath),free=d.token('FREE');d.raw.close();
  const made=build.buildMint({...common,token:free,paySats:0});
  const q=await simulate(cfg,request(made));assert.equal(q.valid,false);assert.equal(q.pending.known_pending_mints,1);assert.equal(q.pending.remaining_atoms_estimate,'0');assert.match(q.errors.join(' '),/pending demand/);
 }finally{const d=new Database(dbPath);d.prepare("update tokens set json=? where tick='FREE'").run(original);d.prepare('delete from mempool where txid=?').run('cd'.repeat(32));d.close();}
});

test('preview runs the selected Python executable even when its path contains spaces',async()=>{const wrapper=path.join(tmp,'python wrapper'),marker=path.join(tmp,'selected-python-marker');const script='#!/usr/bin/env python3\nimport os,sys\nopen('+JSON.stringify(marker)+',"w").write("selected")\nos.execv(sys.executable,[sys.executable,*sys.argv[1:]])\n';fs.writeFileSync(wrapper,script,{mode:0o755});const prior=process.env.PYTHON_BIN;process.env.PYTHON_BIN=wrapper;try{const result=await simulate(cfg,request(mint()));assert.equal(result.valid,true,JSON.stringify(result));assert.equal(fs.readFileSync(marker,'utf8'),'selected')}finally{if(prior===undefined)delete process.env.PYTHON_BIN;else process.env.PYTHON_BIN=prior}});
