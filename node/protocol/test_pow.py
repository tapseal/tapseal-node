import copy,hashlib,json,unittest
import tapseal as T
OWNER=T._mul(11)[0].to_bytes(32,'big');OTHER=T._mul(22)[0].to_bytes(32,'big');ANCHOR='ab'*32

def tx(n,op,outputs):return {'txid':f'{n:064x}','vin':[],'vout':[{'value':0,'spk':T.op_return_script(T.encode(op))}]+outputs}
def out(value,spk):return {'value':value,'spk':spk}
def setup(net='mainnet',paid=True):
 st=T.State(network=net,pow_activation=100,pow_anchors={100:ANCHOR})
 op={'op':'deploy','tick':'WORK','dec':0,'max':1000000,'mode':'fixed' if paid else 'fair','rate':1,'cap':900,'treasury_vout':1,'lim':10,'pow':{'version':2,'bits':8,'max_age':144}}
 T.apply_tx(st,tx(1,op,[out(546,b'\x51\x20'+OTHER)]),100)
 return st,op

def proof(st,owner=OWNER,paid=600,height=100,hash_=ANCHOR,lock=0):
 p={'height':height,'hash':hash_,'nonce':'0'}
 for n in range(100000):
  p['nonce']=str(n)
  if int.from_bytes(T.pow_digest(st.network,st.tokens['WORK'],owner,p,paid,lock),'big')<1<<248:return p
 raise AssertionError('fixture search exhausted')
def mint(n,p,paid=600,owner=OWNER):
 return tx(n,{'op':'mint','tick':'WORK','vout':1,'owner':owner.hex(),'proof':p},[out(330,T.seal_spk('WORK',owner)),out(paid,b'\x51\x20'+OTHER)])
class PowTests(unittest.TestCase):
 def test_two_networks_and_regtest_accept_work_and_reject_replay(self):
  for net in ['mainnet','testnet3','regtest']:
   st,_=setup(net);p=proof(st);events=T.apply_tx(st,mint(2,p),101);self.assertEqual(events[-1]['kind'],'mint');self.assertEqual(st.tokens['WORK'].minted,600)
   ev=T.apply_tx(st,mint(3,p),102);self.assertIn('already used',ev[-1]['detail']);self.assertEqual(st.tokens['WORK'].minted,600)
 def test_network_owner_payment_and_lock_binding(self):
  st,_=setup();p=proof(st)
  for net,owner,paid,lock in [('testnet3',OWNER,600,0),('mainnet',OTHER,600,0),('mainnet',OWNER,601,0),('mainnet',OWNER,600,200)]:
   h=T.pow_digest(net,st.tokens['WORK'],owner,p,paid,lock);self.assertNotEqual(h,T.pow_digest('mainnet',st.tokens['WORK'],OWNER,p,600,0))
 def test_expired_unknown_and_future_anchor(self):
  st,_=setup();p=proof(st)
  for height,p2 in [(245,p),(100,p),(101,{**p,'height':99})]:
   ev=T.apply_tx(copy.deepcopy(st),mint(2,p2),height);self.assertEqual(ev[-1]['kind'],'invalid')
 def test_missing_work_and_disabled_activation(self):
  st,_=setup();m=mint(2,proof(st));op=T.decode(T.payload_from_script(m['vout'][0]['spk']));op.pop('proof');m['vout'][0]['spk']=T.op_return_script(T.encode(op));self.assertIn('requires',T.apply_tx(st,m,101)[-1]['detail'])
  st,op=setup();st.pow_activation=None;st.tokens.clear();ev=T.apply_tx(st,tx(1,op,[out(546,b'\x51\x20'+OTHER)]),100);self.assertEqual(ev[-1]['kind'],'cenotaph');self.assertFalse(st.tokens)
 def test_discount_requires_confirmed_operator_quota(self):
  st,_=setup();tok=st.tokens['WORK'];tok.wl={'key':OWNER.hex(),'price':2,'reserve':2000,'end':200};p=proof(st)
  op={'op':'mint','tick':'WORK','vout':1,'owner':OWNER.hex(),'proof':p,'operator':True}
  t=tx(2,op,[out(330,T.seal_spk('WORK',OWNER)),out(600,b'\x51\x20'+OTHER)])
  self.assertIn('not approved',T.apply_tx(st,t,101)[-1]['detail'])
  st.add_usage('WORK','op-max',OWNER.hex(),1000);st.add_usage('WORK','op-expiry',OWNER.hex(),200)
  ev=T.apply_tx(st,t,101);self.assertEqual(ev[-1]['kind'],'mint');self.assertEqual(tok.minted,1000);self.assertEqual(tok.wl_minted,1000)
 def test_roundtrip_and_malformed_limits(self):
  st,op=setup();self.assertEqual(T.decode(T.encode(op))['pow'],op['pow']);p=proof(st);m={'op':'mint','tick':'WORK','vout':1,'owner':OWNER.hex(),'proof':p};self.assertEqual(T.decode(T.encode(m))['proof'],{k:v for k,v in p.items() if k!='hash'})
  for bits in [0,7,29,256]:
   with self.assertRaises(ValueError):T.encode({**op,'pow':{'bits':bits,'max_age':144}})
  with self.assertRaises(ValueError):T.encode({**m,'proof':{**p,'nonce':str(2**64)}})
if __name__=='__main__':unittest.main()
