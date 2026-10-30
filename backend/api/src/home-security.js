// Home-console protections. Public server deployments retain their separate origin policy.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
function homeGuard({siteDir,publicUrl=''}){
 let publicHost=null,publicOrigin=null;
 if(publicUrl){const u=new URL(publicUrl);if(u.protocol!=='https:'||u.username||u.password||u.search||u.hash)throw Error('Public node URL must use HTTPS without credentials/query/fragment');publicHost=u.host;publicOrigin=u.origin;}
 const hashes=[];
 if(siteDir){const file=path.join(siteDir,'index.html');if(fs.existsSync(file)){if(fs.statSync(file).size>256*1024)throw Error('Home dashboard exceeds size limit');const html=fs.readFileSync(file,'utf8');for(const m of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi))hashes.push("'sha256-"+crypto.createHash('sha256').update(m[1]).digest('base64')+"'");}}
 const csp="default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self'; script-src "+(hashes.join(' ')||"'none'");
 return(req,res,next)=>{
  const host=String(req.headers.host||'').toLowerCase();
  if(!/^(localhost|127\.0\.0\.1|\[::1\])(?::\d{1,5})?$/.test(host)&&host!==publicHost)return res.status(421).json({ok:false,error:'Unrecognized home-node host'});
  const origin=req.headers.origin;
  if((origin&&origin!==`http://${host}`&&!(host===publicHost&&origin===publicOrigin))||req.headers['sec-fetch-site']==='cross-site')return res.status(403).json({ok:false,error:'Cross-site home-node requests are refused'});
  res.setHeader('Content-Security-Policy',csp);res.setHeader('X-Frame-Options','DENY');res.setHeader('Cross-Origin-Resource-Policy','same-origin');res.setHeader('Cache-Control','no-store');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');next();
 };
}
module.exports={homeGuard};
