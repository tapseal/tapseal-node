// Untrusted peers are not general-purpose URL fetch targets. Resolve, validate and pin
// a public address for each HTTPS connection; never follow redirects or use a proxy.
const dns = require('node:dns').promises;
const https = require('node:https');
const ipaddr = require('ipaddr.js');
const MAX_BYTES = 128 * 1024;
function publicAddress(value) {
  try { return ipaddr.process(String(value)).range() === 'unicast'; } catch { return false; }
}
function parseUrl(value) {
  const u = new URL(String(value));
  if (u.protocol !== 'https:' || (u.port && u.port !== '443') || u.username || u.password || u.hash) throw new Error('Peers require public HTTPS on port 443 without credentials or fragments.');
  if (u.href.length > 512) throw new Error('Peer URL is too long.');
  return u;
}
async function publicLookup(hostname, lookup = dns.lookup) {
  const host = hostname.replace(/^\[|\]$/g, '');
  const records = ipaddr.isValid(host) ? [{ address: host, family: ipaddr.parse(host).kind() === 'ipv4' ? 4 : 6 }] : await lookup(host, { all: true, verbatim: true });
  if (!records.length || records.length > 32 || records.some(r => !publicAddress(r.address))) throw new Error('Peer DNS must contain only public unicast addresses.');
  return records;
}
function abortable(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(new Error('Peer request aborted.'));
  return new Promise((resolve, reject) => {
    const stop = () => reject(new Error('Peer request aborted.'));
    signal.addEventListener('abort', stop, { once: true });
    promise.then(resolve,reject).finally(() => signal.removeEventListener('abort', stop));
  });
}
async function peerFetch(input, options = {}) {
  const u = parseUrl(input), signal = options.signal || AbortSignal.timeout(8000);
  const records = await abortable(publicLookup(u.hostname), signal);
  if (signal.aborted) throw new Error('Peer request aborted.');
  return new Promise((resolve, reject) => {
    const pinned = records.find(r=>r.family===4) || records[0]; let completed = false;
    const finish = (err,value) => { if(completed)return;completed=true;signal.removeEventListener('abort',stop);err?reject(err):resolve(value); };
    const req = https.request(u, { agent:false, method:options.method || 'GET', headers:options.headers,
      lookup: (_host, opts, callback) => opts.all ? callback(null,[pinned]) : callback(null,pinned.address,pinned.family),
    }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400) { res.destroy();return finish(new Error('Peer redirects are refused.')); }
      if (Number(res.headers['content-length']) > MAX_BYTES) { res.destroy();return finish(new Error('Peer response exceeds limit.')); }
      const chunks=[];let bytes=0;
      res.on('data',chunk=>{bytes+=chunk.length;if(bytes>MAX_BYTES){res.destroy();finish(new Error('Peer response exceeds limit.'));}else chunks.push(chunk);});
      res.on('error',e=>finish(e));
      res.on('end',()=>{const body=Buffer.concat(chunks).toString('utf8');finish(null,{ok:res.statusCode>=200&&res.statusCode<300,status:res.statusCode,json:async()=>JSON.parse(body)});});
    });
    const stop=()=>{req.destroy();finish(new Error('Peer request aborted.'));};
    signal.addEventListener('abort',stop,{once:true});
    req.on('error',e=>finish(e));
    if (options.body) { if(Buffer.byteLength(options.body)>16*1024)return stop();req.write(options.body); }
    req.end();
  });
}
module.exports={peerFetch,publicAddress,publicLookup,parseUrl,MAX_BYTES};
