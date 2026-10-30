// TAPSEAL read-only protocol preview; no keys or database writes.
const { spawn } = require('child_process');
const path = require('path');
const ts = require('./tapseal');
function pythonPreview(dbPath, request, timeoutMs=20000) {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.env.PYTHON_BIN || '/usr/bin/python3', [path.resolve(__dirname, '../..', 'protocol/preview.py'), dbPath], {stdio:['pipe','pipe','pipe']});
    let text='', bytes=0, ended=false;
    const timer=setTimeout(()=>{ proc.kill(); reject(new Error('Protocol preview timed out.')); },timeoutMs);
    proc.on('error', e=>{clearTimeout(timer);reject(e);});
    proc.stderr.resume(); proc.stdin.on('error',()=>{});
    proc.stdout.on('data', d=>{bytes+=d.length; if(bytes>2_000_000){proc.kill();return;} text+=d;});
    proc.on('close',code=>{clearTimeout(timer);if(ended)return;ended=true;try{if(code!==0)throw new Error('Protocol preview failed.');resolve(JSON.parse(text));}catch(e){reject(e);}});
    proc.stdin.end(JSON.stringify(request));
  });
}
async function rpc(cfg, method, params, timeoutMs=15000) {
  if(!cfg.rpc?.url) throw new Error('Bitcoin RPC is required for live input verification.');
  const auth=cfg.rpc.bearer?'Bearer '+cfg.rpc.bearer:cfg.rpc.user?'Basic '+Buffer.from(cfg.rpc.user+':'+cfg.rpc.password).toString('base64'):null;
  const response=await fetch(cfg.rpc.url,{method:'POST',headers:{'content-type':'application/json',...(auth?{authorization:auth}:{})},body:JSON.stringify({jsonrpc:'1.0',id:'preview',method,params}),signal:AbortSignal.timeout(timeoutMs)});
  if(!response.ok)throw new Error('Bitcoin RPC verification unavailable.');
  const data=await response.json(); if(data.error)throw new Error('Bitcoin RPC rejected '+method+'.');return data.result;
}
// Retry transient tip races by replaying the entire preview against a new DB snapshot.
// Never accept an old height/hash, another network, or a node in initial sync.
async function canonicalPreview({preview,chainInfo,expectedChain,waitMs=8000,sleep=ms=>new Promise(r=>setTimeout(r,ms))}) {
  const deadline=Date.now()+Math.max(1,Math.min(8000,waitMs));let result,chain;
  const remaining=()=>Math.max(1,deadline-Date.now());
  for(let attempt=0;attempt<6;attempt++){
    result=await preview(remaining());
    if(Date.now()>=deadline)break;
    chain=await chainInfo(remaining());
    if(!expectedChain||chain.chain!==expectedChain)throw new Error('Bitcoin RPC network does not match the website network.');
    if(chain.initialblockdownload)throw new Error('Bitcoin RPC node is still synchronizing. Wait for its initial block download to finish.');
    if(result.indexed_height===chain.blocks&&result.indexed_hash===chain.bestblockhash)return result;
    if(attempt===5||remaining()<=750)break;
    await sleep(750);
  }
  throw new Error('Indexer is not at the current canonical node tip after bounded retries. Indexed '+(result?.indexed_height??'unknown')+', RPC '+(chain?.blocks??'unknown')+'. Wait for synchronization and rebuild.');
}
function decodeWitness(buf) {
  let i=0;
  function read(){if(i>=buf.length)throw new Error('Truncated witness.');const n=buf[i++];if(n<253)return n;if(n===253){const v=buf.readUInt16LE(i);i+=2;return v;}if(n===254){const v=buf.readUInt32LE(i);i+=4;return v;}throw new Error('Oversized witness.');}
  const n=read();if(n>100)throw new Error('Oversized witness.');const out=[];
  for(let j=0;j<n;j++){const len=read();if(i+len>buf.length)throw new Error('Truncated witness.');out.push(buf.subarray(i,i+len).toString('hex'));i+=len;}
  if(i!==buf.length)throw new Error('Trailing witness bytes.');return out;
}
async function simulate(cfg, body) {
  if(typeof body.psbt!=='string'||body.psbt.length>400000)throw new Error('Provide a bounded PSBT.');
  const psbt=/^[a-f0-9]+$/i.test(body.psbt)?ts.bitcoin.Psbt.fromHex(body.psbt):ts.bitcoin.Psbt.fromBase64(body.psbt);
  const tx=ts.bitcoin.Transaction.fromBuffer(psbt.data.globalMap.unsignedTx.toBuffer());
  if(!tx.ins.length||tx.ins.length>32||tx.outs.length>128)throw new Error('Preview supports up to 32 inputs and 128 outputs.');
  const owners=[...new Set((body.owners||[]).map(a=>ts.ownerOfAddress(a,cfg.network).toString('hex')))];
  if(!owners.length||owners.length>64)throw new Error('Expected owner addresses are required.');
  const expected={...(body.expected||{})};
  if(expected.recipients)expected.recipients=expected.recipients.map(r=>({...r,owner:ts.ownerOfAddress(r.address,cfg.network).toString('hex')}));
  const seen=new Set();let inputSats=0;
  const vin=tx.ins.map((input,index)=>{
    const pin=psbt.data.inputs[index],prevout=Buffer.from(input.hash).reverse().toString('hex')+':'+input.index;
    if(seen.has(prevout))throw new Error('Duplicate transaction input.');seen.add(prevout);
    if(!pin.witnessUtxo)throw new Error('Every input needs its witness UTXO.');
    inputSats+=pin.witnessUtxo.value;
    const witness=pin.finalScriptWitness?decodeWitness(pin.finalScriptWitness):pin.tapLeafScript?.length?['00'.repeat(64),pin.tapLeafScript[0].script.toString('hex'),pin.tapLeafScript[0].controlBlock.toString('hex')]:[];
    return {prevout,witness,sequence:input.sequence};
  });
  async function verifyInputs(timeoutMs=15000){
    const deadline=Date.now()+timeoutMs;
    // Bound concurrency to four RPC requests; do not scan the full mempool.
    for(let i=0;i<vin.length;i+=4)await Promise.all(vin.slice(i,i+4).map(async(v,j)=>{
      const [id,n]=v.prevout.split(':'),actual=await rpc(cfg,'gettxout',[id,Number(n),true],Math.max(1,deadline-Date.now())),claimed=psbt.data.inputs[i+j].witnessUtxo;
      if(!actual)throw new Error('A transaction input is spent or unavailable. Rebuild the transaction.');
      if(actual.scriptPubKey.hex!==claimed.script.toString('hex')||Math.round(actual.value*1e8)!==claimed.value)throw new Error('PSBT input differs from the node UTXO.');
    }));
  }
  if(cfg.previewRequireRpc)await verifyInputs();
  const outputs=tx.outs.map((o,index)=>{let address=null;try{address=ts.bitcoin.address.fromOutputScript(o.script,ts.networkOf(cfg.network));}catch(_){}return {index,sats:o.value,script:o.script.toString('hex'),address};});
  const fee=inputSats-tx.outs.reduce((sum,o)=>sum+o.value,0);if(!Number.isSafeInteger(fee)||fee<0)throw new Error('Invalid BTC input/output accounting.');
  const previewRequest={owners,expected,tx:{txid:tx.getId(),locktime:tx.locktime,vin,vout:tx.outs.map(o=>({value:o.value,spk:o.script.toString('hex')}))}};
  const expectedChain={mainnet:'main',bitcoin:'main',testnet3:'test',testnet:'testnet4',testnet4:'testnet4',signet:'signet',regtest:'regtest'}[cfg.network];
  let previewAttempts=0;
  const result=cfg.previewRequireRpc?await canonicalPreview({
    preview:async ms=>{const end=Date.now()+ms;if(previewAttempts++>0)await verifyInputs(ms);return pythonPreview(cfg.dbPath,previewRequest,Math.max(1,end-Date.now()));},
    chainInfo:ms=>rpc(cfg,'getblockchaininfo',[],ms),expectedChain
  }):await pythonPreview(cfg.dbPath,previewRequest);
  let admission='not_checked_unsigned';
  const finalized=psbt.data.inputs.every(i=>i.finalScriptWitness||i.finalScriptSig);
  if(result.valid&&cfg.previewRequireRpc&&finalized){
    const raw=psbt.extractTransaction().toHex(),answer=await rpc(cfg,'testmempoolaccept',[[raw]]);
    if(!Array.isArray(answer)||!answer.length)throw new Error('Node returned no transaction admission verdict.');
    admission=answer[0].allowed?'accepted':'rejected';
    if(!answer[0].allowed){result.valid=false;result.errors.push('Bitcoin node rejected transaction: '+(answer[0]['reject-reason']||'unknown'));}
  }
  return {...result,network:cfg.network,btc_fee_sats:fee,outputs,inputs_verified:!!cfg.previewRequireRpc,node_admission:admission};
}
module.exports={simulate,decodeWitness,canonicalPreview};
