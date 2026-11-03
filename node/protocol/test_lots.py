import copy,unittest
import tapseal as T
from test_tapseal import spend
OWNER=T._mul(11)[0].to_bytes(32,'big');TREASURY=b'\x51\x20'+T._mul(99)[0].to_bytes(32,'big');AUTH=T._mul(44)[0].to_bytes(32,'big');HASH='ab'*32;LOT=1000*10**8

def transaction(n,op,outputs,vin=None):return {'txid':f'{n:064x}','vin':vin or [],'vout':[{'value':0,'spk':T.op_return_script(T.encode(op))}]+[{'value':v,'spk':s} for v,s in outputs]}
def setup(net='mainnet',activation=100):
 st=T.State(network=net,pow_activation=90,lot_activation=activation,pow_anchors={100:HASH});op={'op':'deploy','tick':'TAPSEAL','dec':8,'max':21000000*10**8,'mode':'lots','profile':1,'treasury_vout':1,'auth_vout':2,'pow':{'version':2,'bits':8,'max_age':144}};tx=transaction(1,op,[(546,TREASURY),(330,T.seal_spk('TAPSEAL',AUTH,auth=True))]);return st,op,tx

def proof(st,paid):
 tok=st.tokens['TAPSEAL'];p={'height':100,'hash':HASH,'nonce':'0'}
 for n in range(100000):
  p['nonce']=str(n)
  if int.from_bytes(T.pow_digest(st.network,tok,OWNER,p,paid),'big')<1<<248:return p
 raise AssertionError('fixture search exhausted')
def mint(st,n,count,discount=False,paid=None):
 paid=(450 if discount else 700)*count if paid is None else paid
 op={'op':'mint','tick':'TAPSEAL','vout':1,'owner':OWNER.hex()}
 if discount:op.update(operator=True,proof=proof(st,paid))
 return transaction(n,op,[(330,T.seal_spk('TAPSEAL',OWNER)),(paid,TREASURY)])
class Lots(unittest.TestCase):
 def test_exact_prices_all_ten_quantities_and_networks(self):
  for net in ['mainnet','testnet3','regtest']:
   for discount in [False,True]:
    for count in range(1,11):
     st,op,tx=setup(net);self.assertEqual(T.apply_tx(st,tx,100)[-1]['kind'],'deploy');st.add_usage('TAPSEAL','op-max',OWNER.hex(),LOT*100);st.add_usage('TAPSEAL','op-expiry',OWNER.hex(),200)
     ev=T.apply_tx(st,mint(st,2,count,discount),101);self.assertEqual(ev[-1]['kind'],'mint');self.assertEqual(st.tokens['TAPSEAL'].minted,count*LOT);self.assertEqual(st.used('TAPSEAL','wl',OWNER.hex()),count*LOT if discount else 0)
 def test_bounds_steps_and_no_partial_fills(self):
  st,op,tx=setup();T.apply_tx(st,tx,100)
  for paid in [0,450,699,701,750,7001,7700]:self.assertEqual(T.apply_tx(copy.deepcopy(st),mint(st,2,1,paid=paid),101)[-1]['kind'],'invalid')
  st.tokens['TAPSEAL'].minted=st.tokens['TAPSEAL'].max-LOT
  self.assertEqual(T.apply_tx(st,mint(st,3,2),101)[-1]['kind'],'invalid');self.assertEqual(st.tokens['TAPSEAL'].minted,st.tokens['TAPSEAL'].max-LOT)
  self.assertEqual(T.apply_tx(st,mint(st,4,1),101)[-1]['kind'],'mint')
 def test_activation_supply_decimals_treasury_and_authority(self):
  st,op,tx=setup(activation=101);self.assertEqual(T.apply_tx(st,tx,100)[-1]['kind'],'cenotaph')
  for changes in [{'max':21000001*10**8},{'dec':0},{'wallet_cap':LOT}]:
   st,op,_=setup();op.update(changes);self.assertEqual(T.apply_tx(st,transaction(1,op,[(546,TREASURY),(330,T.seal_spk('TAPSEAL',AUTH,auth=True))]),100)[-1]['kind'],'invalid')
  st,op,_=setup();self.assertEqual(T.apply_tx(st,transaction(1,op,[(546,b'\x00\x14'+b'\x11'*20),(330,T.seal_spk('TAPSEAL',AUTH,auth=True))]),100)[-1]['kind'],'invalid')
 def test_discount_approval_expiry_work_and_replay(self):
  st,op,tx=setup();T.apply_tx(st,tx,100);t=mint(st,2,1,True)
  self.assertEqual(T.apply_tx(st,t,101)[-1]['kind'],'invalid');st.add_usage('TAPSEAL','op-max',OWNER.hex(),LOT);st.add_usage('TAPSEAL','op-expiry',OWNER.hex(),101)
  self.assertEqual(T.apply_tx(st,t,102)[-1]['kind'],'invalid');self.assertEqual(T.apply_tx(st,t,101)[-1]['kind'],'mint');self.assertEqual(T.apply_tx(st,t,101)[-1]['kind'],'invalid')
 def test_immutable_phase_and_lot_quota(self):
  st,op,tx=setup();T.apply_tx(st,tx,100);tok=st.tokens['TAPSEAL'];before=dict(tok.params)
  op={'op':'allowlist','tick':'TAPSEAL','next_auth':1,'key':OWNER.hex(),'price':999,'reserve':LOT,'end':200};t=transaction(2,op,[(330,T.seal_spk('TAPSEAL',AUTH,auth=True))],[spend(tok.auth_outpoint,'TAPSEAL',AUTH,auth=True)])
  self.assertEqual(T.apply_tx(st,t,101)[-1]['kind'],'invalid');self.assertEqual(tok.params,before)
  op={'op':'operator','tick':'TAPSEAL','next_auth':1,'owner':OWNER.hex(),'max':LOT+1,'expiry':200};t=transaction(3,op,[(330,T.seal_spk('TAPSEAL',AUTH,auth=True))],[spend(tok.auth_outpoint,'TAPSEAL',AUTH,auth=True)])
  self.assertEqual(T.apply_tx(st,t,102)[-1]['kind'],'invalid');self.assertEqual(st.used('TAPSEAL','op-max',OWNER.hex()),0)
 def test_compact_encoding(self):
  st,op,tx=setup();T.apply_tx(st,tx,100);self.assertLessEqual(len(T.encode(op)),80);self.assertEqual(T.decode(T.encode(op))['profile'],1)
  for discount in [False,True]:self.assertLessEqual(len(T.payload_from_script(mint(st,2,10,discount)['vout'][0]['spk'])),80)
if __name__=='__main__':unittest.main()
