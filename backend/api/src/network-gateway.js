// Fixed loopback proxy: no user-supplied target, credentials or cross-network fallback.
const http=require('node:http');
function mainnetGateway({port=8091,maxActive=32}={}){
 let active=0;
 return(req,res)=>{
  if(active>=maxActive)return res.status(503).json({ok:false,error:'Mainnet gateway busy'});
  if(Number(req.headers['content-length'])>256*1024)return res.status(413).json({ok:false,error:'Request too large'});
  active++;let ended=false,bytes=0;const finish=()=>{if(ended)return;ended=true;active--};
  const headers={accept:'application/json','content-type':req.headers['content-type']||'application/json','x-forwarded-for':req.ip};
  const upstream=http.request({hostname:'127.0.0.1',port,method:req.method,path:'/api/tapseal'+(req.url==='/'?'':req.url),headers},answer=>{
   res.status(answer.statusCode);res.setHeader('content-type',answer.headers['content-type']||'application/json');res.setHeader('cache-control','no-store');answer.pipe(res);answer.on('error',()=>res.destroy());answer.on('end',finish);
  });
  const timer=setTimeout(()=>upstream.destroy(new Error('timeout')),30000);
  upstream.on('error',()=>{if(!res.headersSent)res.status(503).json({ok:false,error:'Mainnet API unavailable; Testnet3 was not used as fallback.'});else res.destroy();finish()});
  res.on('close',()=>{clearTimeout(timer);upstream.destroy();finish()});
  req.on('data',chunk=>{bytes+=chunk.length;if(bytes>256*1024){upstream.destroy();if(!res.headersSent)res.status(413).json({ok:false,error:'Request too large'});} });req.on('error',()=>upstream.destroy());req.pipe(upstream);
 };
}
module.exports={mainnetGateway};
