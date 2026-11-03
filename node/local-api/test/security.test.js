const test=require('node:test');const assert=require('node:assert/strict');const https=require('node:https');const {EventEmitter}=require('node:events');
const {peerFetch,publicAddress,publicLookup,parseUrl,MAX_BYTES}=require('../src/peer-http');
test('private, local, mapped and reserved peer addresses are refused',async()=>{
 for(const ip of ['127.0.0.1','10.0.0.1','172.16.0.1','192.168.1.1','169.254.169.254','100.64.0.1','0.0.0.0','::1','fc00::1','fe80::1','::ffff:127.0.0.1','2001:db8::1'])assert.equal(publicAddress(ip),false,ip);
 assert.equal(publicAddress('8.8.8.8'),true);assert.equal(publicAddress('2606:4700:4700::1111'),true);
 await assert.rejects(peerFetch('https://127.0.0.1/status'),/public unicast/);
 await assert.rejects(publicLookup('mixed.example',async()=>[{address:'8.8.8.8',family:4},{address:'127.0.0.1',family:4}]),/public unicast/);
});
test('HTTPS peer transport rejects credentials, HTTP and alternate ports',()=>{
 for(const url of ['http://8.8.8.8','https://user:secret@8.8.8.8','https://8.8.8.8:8443','https://8.8.8.8/#fragment'])assert.throws(()=>parseUrl(url));
 assert.equal(parseUrl('https://example.org/api/tapseal').protocol,'https:');
});
async function response(t,status,chunks,headers={}){
 let opts;
 t.mock.method(https,'request',(_url,o,cb)=>{opts=o;const req=new EventEmitter();req.write=()=>{};req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{const res=new EventEmitter();res.statusCode=status;res.headers=headers;res.destroy=()=>{};cb(res);for(const c of chunks)res.emit('data',c);res.emit('end');});return req;});
 const result=peerFetch('https://8.8.8.8/api/tapseal/status');return {result,options:()=>opts};
}
test('HTTP redirects are never followed',async t=>{const x=await response(t,302,[],{location:'http://169.254.169.254'});await assert.rejects(x.result,/redirect/);});
test('oversized peer responses are bounded',async t=>{const x=await response(t,200,[Buffer.alloc(MAX_BYTES+1)]);await assert.rejects(x.result,/exceeds limit/);});
test('connections pin the prevalidated DNS result and disable pooling',async t=>{const x=await response(t,200,[Buffer.from('{"ok":true}')]);assert.equal((await (await x.result).json()).ok,true);const opts=x.options();assert.equal(opts.agent,false);let pinned;opts.lookup('changed-dns.example',{},(_err,address,family)=>pinned=[address,family]);assert.deepEqual(pinned,['8.8.8.8',4]);});
test('announcement IDs cannot be taken over from a different source address',()=>{
 const {createAnnouncements}=require('../src/announce');let at=1;const row={hash:'a'.repeat(64),root:'b'.repeat(64)};
 const a=createAnnouncements({network:'testnet3',now:()=>at,db:{raw:{prepare:()=>({get:()=>row})}}});
 const body={node_id:'0123456789abcdef',network:'testnet3',height:1,...row};assert.equal(a.accept(body,'first').ok,true);at+=30000;
 assert.equal(a.accept(body,'second').code,409);assert.equal(a.list()[0].authenticated,false);assert.equal('ip' in a.list()[0],false);
});
