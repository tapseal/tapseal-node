// Owner-only launch service policy. This is not a Bitcoin consensus rule.
function owners(cfg){return Array.isArray(cfg.ownerAddresses)?cfg.ownerAddresses.filter(a=>typeof a==='string'&&a):[];}
function assertOwnerLaunch(cfg,address){if(!owners(cfg).includes(address))throw Error('Public launches are closed. Only the configured owner wallet can deploy through this service.');}
function launchPolicy(cfg){return {mode:'owner-only',public_creation:false,owner_configured:owners(cfg).length>0,public_directory_network:'mainnet',scope:'this-api-service'};}
function incentivesPolicy(){return {status:'planned',rewards_active:false,payouts_active:false,eligibility:'not-implemented',earned_sats:null,services:['independent indexing','data availability','API service'],funding:'A future opt-in infrastructure fee may fund service payments. No fee allocation or reward rate is enabled.',limitations:'Peer check-ins and matching seal roots are observations, not proof of eligibility or full-ledger validity.'};}
async function assertOwnerDeploymentRelay(cfg,tx,network,callRpc){
 if(!cfg.rpc?.url)throw Error('Owner deployment relay requires the configured Bitcoin RPC backend.');
 const first=tx.ins[0];if(!first)throw Error('Owner deployment requires an owner funding input.');
 const prevout=await callRpc('gettxout',[Buffer.from(first.hash).reverse().toString('hex'),first.index,true]);
 const ts=require('./tapseal');const expected=owners(cfg).map(address=>{try{return ts.bitcoin.address.toOutputScript(address,ts.networkOf(network)).toString('hex')}catch{return null}}).filter(Boolean);
 if(!prevout?.scriptPubKey?.hex||!expected.includes(prevout.scriptPubKey.hex))throw Error('Owner deployment relay refused: first funding input does not belong to the configured owner.');
}
module.exports={assertOwnerLaunch,assertOwnerDeploymentRelay,launchPolicy,incentivesPolicy};
