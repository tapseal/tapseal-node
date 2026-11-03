import sys,tempfile,unittest
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parent.parent/'protocol')]
import tapseal as T
import tapseal_indexer as I
from test_lots import setup,mint,transaction,OWNER,AUTH,LOT,HASH
from test_tapseal import spend

def rpc(t):return {**t,'vin':[{'txid':v['prevout'].split(':')[0],'vout':int(v['prevout'].split(':')[1]),'txinwitness':[w.hex() for w in v['witness']]} for v in t['vin']],'vout':[{'value':v['value']/1e8,'scriptPubKey':{'hex':v['spk'].hex()}} for v in t['vout']]}
def block(h,hash_,prev,t):return {'height':h,'hash':hash_,'previousblockhash':prev,'time':h,'tx':[rpc(t)]}
class PersistentLots(unittest.TestCase):
 def test_restart_and_discount_rollback(self):
  with tempfile.TemporaryDirectory() as d:
   file=Path(d)/'chain.sqlite';store=I.Store(file);store.put_node(network='mainnet',activation=100,pow_rules='pow-v2',pow_activation=90,lot_rules='lot-v1',lot_activation=100);state=store.load_state();_,_,deploy=setup();store.apply_block(state,block(100,HASH,'00'*32,deploy));store.apply_block(state,block(101,'cd'*32,HASH,mint(state,2,10)))
   approval=transaction(3,{'op':'operator','tick':'TAPSEAL','next_auth':1,'owner':OWNER.hex(),'max':100*LOT,'expiry':200},[(330,T.seal_spk('TAPSEAL',AUTH,auth=True))],[spend(state.tokens['TAPSEAL'].auth_outpoint,'TAPSEAL',AUTH,auth=True)]);store.apply_block(state,block(102,'de'*32,'cd'*32,approval));discounted=mint(state,4,10,True);store.apply_block(state,block(103,'ef'*32,'de'*32,discounted));store.db.close()
   store=I.Store(file);state=store.load_state();self.assertEqual(state.lot_activation,100);self.assertEqual(state.tokens['TAPSEAL'].minted,20*LOT);self.assertEqual(state.used('TAPSEAL','wl',OWNER.hex()),10*LOT);self.assertEqual(state.tokens['TAPSEAL'].params['operator_price'],450)
   store.rollback_tip(state);self.assertEqual(state.tokens['TAPSEAL'].minted,10*LOT);self.assertEqual(state.used('TAPSEAL','wl',OWNER.hex()),0);store.apply_block(state,block(103,'f0'*32,'de'*32,discounted));self.assertEqual(state.tokens['TAPSEAL'].minted,20*LOT);store.db.close()
if __name__=='__main__':unittest.main()
