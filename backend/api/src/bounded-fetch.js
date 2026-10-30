// Bounded upstream transport. Configured RPC/provider URLs are trusted configuration,
// but their redirects and responses must not extend authority or consume unbounded memory.
async function boundedFetch(url,{maxBytes=128*1024,timeoutMs=15000,...options}={}){
 const deadline=AbortSignal.timeout(Math.max(1,Math.min(15000,timeoutMs)));
 const signal=options.signal?AbortSignal.any([options.signal,deadline]):deadline;
 let response;
 try{response=await fetch(url,{...options,redirect:'error',signal});}catch{throw Error('Upstream request failed or timed out.');}
 if(Number(response.headers.get('content-length'))>maxBytes){await response.body?.cancel();throw Error('Upstream response exceeds size limit.');}
 const reader=response.body?.getReader();let bytes=0;const chunks=[];
 if(reader){try{for(;;){const {done,value}=await reader.read();if(done)break;bytes+=value.byteLength;if(bytes>maxBytes){await reader.cancel();throw Error('Upstream response exceeds size limit.');}chunks.push(Buffer.from(value));}}catch(e){if(signal.aborted)throw Error('Upstream request failed or timed out.');throw e;}finally{reader.releaseLock();}}
 const text=Buffer.concat(chunks).toString('utf8');return{ok:response.ok,status:response.status,headers:response.headers,text:async()=>text,json:async()=>{try{return JSON.parse(text)}catch{throw Error('Upstream returned invalid JSON.')}}};
}
module.exports={boundedFetch};
