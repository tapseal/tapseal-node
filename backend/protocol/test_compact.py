import copy,unittest
import tapseal as T
from test_pow import setup,proof,mint,tx,out,OWNER,OTHER
from test_tapseal import spend

def with_authority(net='mainnet'):
 st,op=setup(net);st.tokens.clear();op['auth_vout']=2
 T.apply_tx(st,tx(1,op,[out(546,b'\x51\x20'+OTHER),out(330,T.seal_spk('WORK',OWNER,auth=True))]),100)
 st.tokens['WORK'].wl={'key':OWNER.hex(),'price':2,'reserve':100000,'end':250}
 return st

def approval(st,n,max_=1000,expiry=200,owner=OWNER,authorised=True):
 op={'op':'operator','tick':'WORK','next_auth':1,'owner':owner.hex(),'max':max_,'expiry':expiry}
 t=tx(n,op,[out(330,T.seal_spk('WORK',OWNER,auth=True))])
 if authorised:t['vin']=[spend(st.tokens['WORK'].auth_outpoint,'WORK',OWNER,auth=True)]
 return t
class CompactTests(unittest.TestCase):
 def test_approval_requires_authority_and_confirmed_quota(self):
  for net in ['mainnet','testnet3']:
   st=with_authority(net);ev=T.apply_tx(st,approval(st,2,authorised=False),101);self.assertEqual(ev[-1]['kind'],'invalid');self.assertEqual(st.used('WORK','op-max',OWNER.hex()),0)
   self.assertEqual(T.apply_tx(st,approval(st,3),101)[-1]['kind'],'operator');self.assertEqual(st.used('WORK','op-max',OWNER.hex()),1000)
   p=proof(st);op={'op':'mint','tick':'WORK','vout':1,'owner':OWNER.hex(),'proof':p,'operator':True};t=tx(4,op,[out(330,T.seal_spk('WORK',OWNER)),out(600,b'\x51\x20'+OTHER)])
   self.assertEqual(T.apply_tx(st,t,102)[-1]['kind'],'mint');self.assertEqual(st.tokens['WORK'].minted,1000)
   self.assertEqual(T.apply_tx(st,approval(st,5,max_=0),103)[-1]['kind'],'operator')
   st2=copy.deepcopy(st);p2=proof(st2,paid=601);op['proof']=p2;t2=tx(6,op,[out(330,T.seal_spk('WORK',OWNER)),out(601,b'\x51\x20'+OTHER)])
   self.assertIn('not approved',T.apply_tx(st,t2,104)[-1]['detail']);self.assertEqual(st.tokens['WORK'].minted,1000)
 def test_revocation_does_not_reset_used_allowance(self):
  st=with_authority();T.apply_tx(st,approval(st,2),101);st.add_usage('WORK','wl',OWNER.hex(),1000);T.apply_tx(st,approval(st,3,max_=0),102);T.apply_tx(st,approval(st,4,max_=1000),103)
  self.assertEqual(st.used('WORK','wl',OWNER.hex()),1000)
 def test_expiry_and_anchor_reorg(self):
  st=with_authority();T.apply_tx(st,approval(st,2,expiry=101),101);p=proof(st);op={'op':'mint','tick':'WORK','vout':1,'owner':OWNER.hex(),'proof':p,'operator':True};t=tx(3,op,[out(330,T.seal_spk('WORK',OWNER)),out(600,b'\x51\x20'+OTHER)])
  self.assertIn('expired',T.apply_tx(st,t,102)[-1]['detail']);st.pow_anchors[100]='cd'*32
  self.assertEqual(T.apply_tx(st,mint(4,p),102)[-1]['kind'],'invalid')
 def test_bounded_wire_and_no_duplicated_hash(self):
  maximum=(1<<128)-1
  for tick in ['A','ABCDEFGH']:
   for lock in [0,499999999]:
    for operator in [False,True]:
     op={'op':'mint','tick':tick,'vout':1,'lock':lock,'owner':OWNER.hex(),'proof':{'height':2**32-1,'hash':'ab'*32,'nonce':str(2**64-1)},'operator':operator}
     payload=T.encode(op);self.assertLessEqual(len(payload),80);self.assertNotIn(b'\xab'*32,payload);decoded=T.decode(payload);self.assertEqual(decoded['proof']['nonce'],str(2**64-1))
   payload=T.encode({'op':'operator','tick':tick,'next_auth':1,'owner':OWNER.hex(),'max':maximum,'expiry':2**32-1});self.assertLessEqual(len(payload),80)
  with self.assertRaises(ValueError):T.encode({'op':'mint','tick':'ABCDEFGH','vout':maximum,'lock':maximum,'owner':OWNER.hex(),'proof':{'height':maximum,'nonce':'0'}})
 def test_invalid_registry_bounds_preserve_authority_without_grant(self):
  st=with_authority()
  for n,maximum,expiry in [(2,st.tokens['WORK'].max+1,200),(3,0,2**32)]:
   self.assertEqual(T.apply_tx(st,approval(st,n,max_=maximum,expiry=expiry),101)[-1]['kind'],'invalid');self.assertEqual(st.used('WORK','op-max',OWNER.hex()),0);self.assertEqual(st.tokens['WORK'].auth_outpoint,f'{n:064x}:1')
 def test_large_signed_passes_cannot_enter_compact_work(self):
  st=with_authority();p=proof(st)
  with self.assertRaises(ValueError):T.encode({'op':'mint','tick':'WORK','vout':1,'owner':OWNER.hex(),'proof':p,'pass':{'max':1000,'expiry':200,'sig':'00'*64}})
if __name__=='__main__':unittest.main()
