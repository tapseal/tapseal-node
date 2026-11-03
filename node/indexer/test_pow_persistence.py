import sys,tempfile,unittest,json
from pathlib import Path
sys.path[:0]=[str(Path(__file__).resolve().parent),str(Path(__file__).resolve().parent.parent/'protocol')]
import tapseal as T
import tapseal_indexer as I
from test_pow import setup,proof,mint,tx,out,OTHER,ANCHOR
def rpc(tx):
 return {**tx,"vout":[{"value":v["value"]/1e8,"scriptPubKey":{"hex":v["spk"].hex()}} for v in tx["vout"]]}
class PersistentPow(unittest.TestCase):
 def test_restart_replay_and_reorg(self):
  for net in ['mainnet','testnet3']:
   with tempfile.TemporaryDirectory() as d:
    path=Path(d)/'chain.sqlite';s=I.Store(path);s.put_node(network=net,pow_activation=100);state=s.load_state();_,op=setup(net)
    dep=tx(1,op,[out(546,b'\x51\x20'+OTHER)])
    s.apply_block(state,{'height':100,'hash':ANCHOR,'previousblockhash':'00'*32,'time':1,'tx':[rpc(dep)]})
    p=proof(state);digest=T.pow_digest(net,state.tokens['WORK'],__import__('test_pow').OWNER,p,600).hex()
    s.apply_block(state,{'height':101,'hash':'cd'*32,'previousblockhash':ANCHOR,'time':2,'tx':[rpc(mint(2,p))]});s.db.close()
    s=I.Store(path);state=s.load_state();self.assertEqual(state.network,net);self.assertEqual(state.pow_activation,100);self.assertEqual(state.used('WORK','pow',digest),1);self.assertEqual(state.tokens['WORK'].minted,600)
    self.assertIn('already used',T.apply_tx(state,mint(3,p),102)[-1]['detail']);s.rollback_tip(state);self.assertEqual(state.used('WORK','pow',digest),0);self.assertEqual(state.tokens['WORK'].minted,0);self.assertNotIn(101,state.pow_anchors)
    s.apply_block(state,{'height':101,'hash':'ef'*32,'previousblockhash':ANCHOR,'time':3,'tx':[rpc(mint(4,p))]});self.assertEqual(state.tokens['WORK'].minted,600);s.db.close()
if __name__=='__main__':unittest.main()

class OperatorPersistence(unittest.TestCase):
 def test_operator_approval_restart_and_reorg(self):
  from test_compact import approval
  from test_pow import OWNER
  def converted(t):
   return {**rpc(t),'vin':[{'txid':v['prevout'].split(':')[0],'vout':int(v['prevout'].split(':')[1]),'txinwitness':[w.hex() for w in v['witness']]} for v in t['vin']]}
  for net in ['mainnet','testnet3']:
   with tempfile.TemporaryDirectory() as d:
    path=Path(d)/'chain.sqlite';s=I.Store(path);s.put_node(network=net,pow_activation=100,pow_rules='pow-v2');state=s.load_state();_,op=setup(net);op['auth_vout']=2
    dep=tx(1,op,[out(546,b'\x51\x20'+OTHER),out(330,T.seal_spk('WORK',OWNER,auth=True))]);s.apply_block(state,{'height':100,'hash':ANCHOR,'previousblockhash':'00'*32,'time':1,'tx':[converted(dep)]})
    s.apply_block(state,{'height':101,'hash':'cd'*32,'previousblockhash':ANCHOR,'time':2,'tx':[converted(approval(state,2))]});s.db.close()
    s=I.Store(path);state=s.load_state();self.assertEqual(state.used('WORK','op-max',OWNER.hex()),1000);self.assertEqual(state.used('WORK','op-expiry',OWNER.hex()),200)
    s.apply_block(state,{'height':102,'hash':'ef'*32,'previousblockhash':'cd'*32,'time':3,'tx':[converted(approval(state,3,max_=0))]});self.assertEqual(state.used('WORK','op-max',OWNER.hex()),0)
    s.rollback_tip(state);self.assertEqual(state.used('WORK','op-max',OWNER.hex()),1000);s.rollback_tip(state);self.assertEqual(state.used('WORK','op-max',OWNER.hex()),0);self.assertEqual(state.tokens['WORK'].auth_outpoint,dep['txid']+':2');s.db.close()
