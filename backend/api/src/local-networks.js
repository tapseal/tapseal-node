const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
function localNetworks({directory,requestFile,network}){
 const read=net=>{if(!['mainnet','testnet3'].includes(net))throw Error('Unknown network');const file=path.join(directory,net+'.json');const stat=fs.lstatSync(file);if(!stat.isFile()||stat.isSymbolicLink()||stat.size>128*1024)throw Error('Unsafe profile');const cfg=JSON.parse(fs.readFileSync(file));if(cfg.network!==net||!Number.isSafeInteger(cfg.start)||cfg.start<0)throw Error('Invalid profile');return cfg};
 return{list:()=>({ok:true,active:network,profiles:['mainnet','testnet3'].map(net=>{try{const c=read(net);return{network:net,configured:true,activation:c.start,mode:c.mode}}catch{return{network:net,configured:false}}})}),use:net=>{read(net);const tmp=requestFile+'.'+crypto.randomBytes(8).toString('hex')+'.tmp';try{fs.writeFileSync(tmp,JSON.stringify({network:net,created_at:Date.now()}),{mode:0o600,flag:'wx'});fs.renameSync(tmp,requestFile)}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp)}return{ok:true,switching:true,network:net}}};
}
module.exports={localNetworks};
