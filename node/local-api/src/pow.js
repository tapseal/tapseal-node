'use strict';
const crypto=require('node:crypto');
const networks=new Set(['mainnet','testnet3','regtest','signet','testnet4']);
function integer(v,min,max,name){if(!Number.isSafeInteger(v)||v<min||v>max)throw Error('Invalid '+name);return v}
function config(c){if(c.version!==undefined&&c.version!==2)throw Error('Unsupported PoW version');return{version:2,bits:integer(c.bits,8,28,'PoW bits'),max_age:integer(c.max_age??144,6,144,'PoW max_age')}}
function bytes32(v){if(typeof v!=='string'||!(/^[a-fA-F0-9]{64}$/).test(v))throw Error('Expected 32-byte hex');return Buffer.from(v,'hex')}
function u32(v,name){const b=Buffer.alloc(4);b.writeUInt32LE(integer(v,0,0xffffffff,name));return b}
function u64(v){if(typeof v==='string'&&!/^\d{1,20}$/.test(v))throw Error('Invalid uint64');if(typeof v==='number'&&!Number.isSafeInteger(v))throw Error('Unsafe uint64');const n=BigInt(v);if(n<0n||n>0xffffffffffffffffn)throw Error('Invalid uint64');const b=Buffer.alloc(8);b.writeBigUInt64LE(n);return b}
function prefix({network,token,owner,height,hash,paid,lock=0}){if(!networks.has(network))throw Error('PoW network unavailable');if(!/^[A-Z0-9]{1,8}$/.test(token.tick))throw Error('Invalid ticker');integer(paid,0,21000000*1e8,'PoW payment');integer(lock,0,499999999,'PoW lock');return Buffer.concat([Buffer.from('TAPSEAL/POW/v2\0'+network+'\0'),bytes32(token.deploy_txid),Buffer.from([token.tick.length]),Buffer.from(token.tick),bytes32(owner),u32(height,'anchor height'),bytes32(hash),u64(paid),u32(lock,'lock')])}
function digest(context,nonce){return crypto.createHash('sha256').update(prefix(context)).update(u64(nonce)).digest()}
function meets(hash,bits){integer(bits,8,28,'PoW bits');return BigInt('0x'+Buffer.from(hash).toString('hex'))<(1n<<BigInt(256-bits))}
function check({token,owner,network,tip,proof,paid,lock=0}){const c=config(token.pow);if(!proof||!Number.isSafeInteger(proof.height)||proof.height<token.height||proof.height>=tip.height+1||tip.height+1>proof.height+c.max_age)throw Error('PoW proof is missing, expired or not an ancestor');const context={network,token,owner,height:proof.height,hash:proof.hash,paid,lock};const h=digest(context,proof.nonce);if(!meets(h,c.bits))throw Error('PoW hash does not meet target');return h.toString('hex')}
module.exports={config,prefix,digest,meets,check,u64,bytes32};
