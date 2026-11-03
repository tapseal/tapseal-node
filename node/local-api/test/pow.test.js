const test=require('node:test'),assert=require('node:assert/strict'),{execFileSync}=require('node:child_process'),path=require('node:path'),fs=require('node:fs'),os=require('node:os');
const pow=require('../src/pow'),ts=require('../src/tapseal');
const context={network:'mainnet',token:{tick:'WORK',deploy_txid:'01'.repeat(32),height:100,pow:{version:2,bits:8,max_age:144}},owner:'02'.repeat(32),height:100,hash:'ab'.repeat(32),paid:600,lock:0};
test('PoW prefix and digest match Python on Mainnet, Testnet3 and regtest, including uint64 boundary',()=>{
 for(const network of ['mainnet','testnet3','regtest'])for(const nonce of ['0','18446744073709551615']){
 const c={...context,network};const script="import sys,json;sys.path.insert(0,sys.argv[1]);import tapseal as T;from types import SimpleNamespace;c=json.loads(sys.argv[2]);t=SimpleNamespace(**c['token']);p={'height':c['height'],'hash':c['hash'],'nonce':sys.argv[3]};print(json.dumps([T.pow_prefix(c['network'],t,bytes.fromhex(c['owner']),c['height'],c['hash'],c['paid'],c['lock']).hex(),T.pow_digest(c['network'],t,bytes.fromhex(c['owner']),p,c['paid'],c['lock']).hex()]))";
 const result=JSON.parse(execFileSync(process.env.PYTHON_BIN||'python3',['-I','-c',script,path.resolve(__dirname,'../../protocol'),JSON.stringify(c),nonce],{encoding:'utf8'}));assert.deepEqual([pow.prefix(c).toString('hex'),pow.digest(c,nonce).toString('hex')],result);
 }
});
test('PoW rejects invalid target, nonce, expired and future proofs',()=>{
 for(const bits of [0,7,29])assert.throws(()=>pow.config({bits}));
 assert.throws(()=>pow.u64('18446744073709551616'));assert.throws(()=>pow.u64(Number.MAX_SAFE_INTEGER+1));
 for(const height of [99,101])assert.throws(()=>pow.check({...context,token:context.token,tip:{height:100},proof:{height,hash:context.hash,nonce:'0'}}));
 assert.throws(()=>pow.check({...context,tip:{height:245},proof:{height:100,hash:context.hash,nonce:'0'}}));
});
test('local miner is opt-in, persists only public work data and rejects unsafe files',()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'tapseal-work-'));try{
 const {controls,store}=require('../src/local-miner'),token={tick:'WORK',mode:'fair',max:10000n,minted:0n,params:{lim:10},pow:{version:2},wallet_cap:0n},db={node:()=>({network:'mainnet',lag:0,updated_at:Date.now()/1000,pow_rules:'pow-v2',pow_activation:100}),tip:()=>({height:100}),tokens:()=>[token],token:()=>token,usage:()=>0n},c=controls({dir,network:'mainnet',db}),s=store(dir);assert.equal(c.view().config,null);
 const address=ts.bitcoin.payments.p2tr({internalPubkey:Buffer.from('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798','hex')}).address;
 assert.throws(()=>c.set({enabled:true,tick:'WORK',address,pay_sats:0,cpu_percent:100}));
 assert.equal(c.set({enabled:true,tick:'WORK',address,pay_sats:0,cpu_percent:10}).config.enabled,true);
 assert.equal(fs.statSync(path.join(dir,'config.json')).mode&0o777,0o600);assert.equal(c.set({enabled:false}).config.enabled,false);
 const outside=path.join(dir,'outside');fs.writeFileSync(outside,'{}');fs.symlinkSync(outside,path.join(dir,'proof.json'));assert.throws(()=>s.read('proof'),/Unsafe/);
 }finally{fs.rmSync(dir,{recursive:true,force:true})}
});
test('compact Python/JS wire parity and 80-byte bound at maximum supported mint/registration values',()=>{
 const owner='79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',cases=[{op:'mint',tick:'ABCDEFGH',vout:1,lock:499999999,owner,operator:true,proof:{height:4294967295,hash:'ab'.repeat(32),nonce:'18446744073709551615'}},{op:'operator',tick:'ABCDEFGH',next_auth:1,owner,max:'340282366920938463463374607431768211455',expiry:4294967295}];
 for(const op of cases){const encoded=ts.encode(op);assert.ok(encoded.length<=80);const script="import sys,json;sys.path.insert(0,sys.argv[1]);import tapseal as T;o=json.loads(sys.argv[2]);o.update({k:int(o[k]) for k in ('max',) if k in o});print(T.encode(o).hex())";const result=execFileSync(process.env.PYTHON_BIN||'python3',['-I','-c',script,path.resolve(__dirname,'../../protocol'),JSON.stringify(op)],{encoding:'utf8'}).trim();assert.equal(encoded.toString('hex'),result);assert.ok(ts.opReturnScript(encoded).length<=83)}
 const bad={...cases[0],vout:2n**128n-1n,lock:2n**128n-1n,proof:{...cases[0].proof,height:2n**128n-1n}};assert.throws(()=>ts.encode(bad),/80 bytes/);
});
