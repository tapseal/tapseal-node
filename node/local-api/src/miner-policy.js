'use strict';
const ts=require('./tapseal');
function catalog(db,network,now=Date.now()/1000){
 const node=db.node(),tip=db.tip(),tokens=db.tokens();let reason=null;
 if(node.network!==network)reason='The local database is on a different network.';
 else if(!tip||!Number.isSafeInteger(tip.height))reason='Your node is starting. Wait for its first indexed block.';
 else if(node.lag!==0||!Number.isFinite(node.updated_at)||now-node.updated_at>180||node.updated_at>now+60)reason='Your node is catching up. Work becomes available when synchronization is current.';
 else if(node.pow_rules!=='pow-v2'||!Number.isSafeInteger(node.pow_activation))reason='This node has not loaded the published work rules.';
 else if(tip.height+1<node.pow_activation)reason='Work opens at block '+node.pow_activation+'. Current block: '+tip.height+'.';
 const height=tip?.height??0;
 const items=tokens.map(t=>{let why=null;if(t.pow?.version!==2)why='This token uses ordinary minting, not proof searches.';else if(t.mode==='lots'&&(node.lot_activation==null||height+1<node.lot_activation))why='The main-token launch rules are not activated yet.';else if(BigInt(t.minted)>=BigInt(t.max))why='All tokens have been minted.';else if(t.start&&height+1<t.start)why='Minting opens at block '+t.start+'.';else if(t.end&&height+1>t.end)why='The minting window has closed.';return{tick:t.tick,mode:t.mode,dec:t.dec,cap_sats:t.mode==='lots'?4500:t.mode==='fair'?0:Number(t.params.cap),min_sats:t.mode==='lots'?450:t.mode==='fair'?0:546,step_sats:t.mode==='lots'?450:1,remaining_atoms:String(BigInt(t.max)-BigInt(t.minted)),eligible:!why,reason:why};}).sort((a,b)=>a.tick.localeCompare(b.tick));
 return{network,ready:!reason,reason,indexed_height:tip?.height??null,activation:node.pow_activation??null,indexed_tokens:items.length,tokens:items};
}
function validateStart(db,network,body){
 const state=catalog(db,network);if(!state.ready)throw Error(state.reason);
 const item=state.tokens.find(t=>t.tick===body.tick);if(!item)throw Error('Choose an existing token from the list.');if(!item.eligible)throw Error(item.reason);
 const token=db.token(body.tick),height=db.tip().height+1,pay=Number(body.pay_sats),owner=ts.ownerOfAddress(body.address,network).toString('hex');
 if(token.mode==='fair'&&pay!==0)throw Error('This token has no token payment. Use 0 sats.');
 if(token.mode!=='fair'&&ts.bitcoin.address.toOutputScript(body.address,ts.networkOf(network)).toString('hex')===token.treasury_spk)throw Error('Use a different wallet: the treasury address cannot fund this claim.');
 if(token.mode==='lots'){const max=db.usage(token.tick,'op-max',owner),used=db.usage(token.tick,'wl',owner),expiry=db.usage(token.tick,'op-expiry',owner),q=ts.quoteMint(token,pay,{allowlist:{max,used}});if(expiry<BigInt(height)||q.atoms<=0n||q.clipped)throw Error('Your wallet needs a live on-chain approval. Choose 1..10 lots at 450 sats each.');return state;}
 if(token.mode!=='fair'&&(pay<546||pay>Number(token.params.cap)))throw Error('Choose a payment from 546 to '+token.params.cap+' sats. Nothing is charged while searching.');
 const quotes=[ts.quoteMint(token,pay,{height,walletUsed:db.usage(token.tick,'pub',owner)})];
 const max=db.usage(token.tick,'op-max',owner),used=db.usage(token.tick,'wl',owner),expiry=db.usage(token.tick,'op-expiry',owner);
 if(ts.wlActive(token,height)&&max>used&&expiry>=BigInt(height))quotes.push(ts.quoteMint(token,pay,{height,allowlist:{max,used}}));
 if(!quotes.some(q=>q.atoms>0n&&!q.capped&&(token.mode==='fair'||!q.clipped)))throw Error('This payment does not fit your available mint allocation. Check the claim page or reduce it.');
 return state;
}
module.exports={catalog,validateStart};
