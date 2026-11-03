const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),http=require('node:http'),{execFileSync}=require('node:child_process');
const root=path.resolve(__dirname,'../../..');
for(const mode of ['light','full'])test(mode+': node-only server cannot enable transaction services through environment',async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'node-only-'));let server;
 try{
 const db=path.join(dir,'state.sqlite');execFileSync(process.env.PYTHON_BIN||'python3',[path.join(__dirname,'fixture.py'),'make11',db,'1f'.repeat(32)]);
 Object.assign(process.env,{TAPSEAL_DB:db,NETWORK:'mainnet',NODE_MODE:mode,HOME_NODE:'false',PUBLIC_LAUNCH:'true',SERVE_STATIC:'true',MAINNET_PROXY_ENABLED:'true',SITE_DIR:path.join(root,'softnode/node-ui'),PEERS:''});
 delete require.cache[require.resolve('../server')];const {app}=require('../server');server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));const url='http://127.0.0.1:'+server.address().port;
 const status=await fetch(url+'/api/tapseal/status').then(r=>r.json());assert.equal(status.distribution,'node-only');assert.equal(status.read_only,true);assert.equal(status.mode,mode);assert.equal(Object.hasOwn(status,'owners'),false);
 for(const route of ['/psbt/deploy','/psbt/operator','/psbt/allowlist','/psbt/mint','/psbt/transfer','/psbt/burn','/transactions/simulate','/broadcast']){
  const r=await fetch(url+'/api/tapseal'+route,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});assert.equal(r.status,503,route);
 }
 for(const route of ['/operator-policy','/allowlist/STONK','/tokens/STONK/quote'])assert.equal((await fetch(url+'/api/tapseal'+route)).status,404,route);
 assert.equal((await fetch(url+'/mainnet/api/tapseal/status')).status,200);
 assert.equal((await fetch(url+'/api/tapseal/status',{headers:{origin:'https://evil.example'}})).status,403);
 const host=await new Promise((resolve,reject)=>http.get(url+'/healthz',{headers:{host:'evil.example'}},r=>{r.resume();resolve(r.statusCode)}).on('error',reject));assert.equal(host,421);
 assert.equal((await fetch(url+'/api/tapseal/tokens').then(r=>r.json())).tokens.length>0,true);
 const reader=require('../src/db').open(db);assert.throws(()=>reader.raw.exec("delete from tokens"),/readonly/i);assert.equal(Object.hasOwn(reader,'insertMempool'),false);reader.raw.close();
 for(const name of ['psbt.js','preview.js','allowlist.js','operator-policy.js','network-gateway.js'])assert.equal(fs.existsSync(path.join(__dirname,'../src',name)),false);
 }finally{if(server)await new Promise(r=>server.close(r));fs.rmSync(dir,{recursive:true,force:true})}
});
