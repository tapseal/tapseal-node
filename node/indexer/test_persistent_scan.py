#!/usr/bin/env python3
import json,sys,tempfile,unittest
from pathlib import Path
from collections import Counter
from unittest.mock import patch
sys.path[:0]=[str(Path(__file__).parent),str(Path(__file__).parent.parent/'protocol')]
import tapseal_indexer as IX
from persistent_scan import scan,initialize_scan
from persistent_rpc import RpcLimit
from test_indexer import FakeRpc,rpc_tx,opret,h,chain,TREASURY

class CountingRpc(FakeRpc):
    def __init__(self):super().__init__();self.calls=Counter();self.fail=set();self.interrupt_at=None;self.snapshot_fail=False;self.rate_limit=None
    def call(self,method,*params):
        if method=='getblockchaininfo':return {'chain':getattr(self,'chain_name','test'),'initialblockdownload':False}
        self.calls[method]+=1
        if method=='getrawmempool' and self.snapshot_fail:raise RuntimeError('offline')
        if method=='getrawtransaction':
            if self.interrupt_at==self.calls[method]:raise KeyboardInterrupt()
            if params[0]==self.rate_limit:raise RpcLimit('limited',code=429,retry_after=30)
            if params[0] in self.fail:raise RuntimeError('temporary failure')
        return super().call(method,*params)

def plain(n):return rpc_tx(f'{n:064x}',[],[(1000,TREASURY)])
def mint(n=999):return rpc_tx(f'{n:064x}',[],[opret({'op':'mint','tick':'STONK','vout':1,'lock':0}),(330,TREASURY),(1000,TREASURY)])

class PersistentScan(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.file=str(Path(self.tmp.name)/'ledger.sqlite');self.store=IX.Store(self.file);self.rpc=CountingRpc()
    def tearDown(self):self.store.db.close();self.tmp.cleanup()
    def pool(self,n):self.rpc.mempool={t['txid']:t for t in [plain(i) for i in range(1,n+1)]}
    def test_restart_does_not_repeat_successful_raw_lookups(self):
        self.pool(6);a=scan(self.rpc,self.store,set(),3);self.assertEqual(a['scanned'],3)
        self.store.db.close();self.store=IX.Store(self.file)
        b=scan(self.rpc,self.store,set(),3);self.assertEqual(b['backlog'],0);self.assertEqual(self.rpc.calls['getrawtransaction'],6)
        c=scan(self.rpc,self.store,set(),3);self.assertEqual(c['scanned'],0);self.assertEqual(self.rpc.calls['getrawtransaction'],6)
    def test_resume_in_a_separate_python_process(self):
        import subprocess
        self.pool(5);scan(self.rpc,self.store,set(),2);self.store.db.close()
        code="import sys,json;sys.path.insert(0,sys.argv[2]);import tapseal_indexer as IX;from persistent_scan import scan;from test_persistent_scan import CountingRpc,plain;r=CountingRpc();r.mempool={t['txid']:t for t in [plain(i) for i in range(1,6)]};s=IX.Store(sys.argv[1]);out=scan(r,s,set(),10);print(json.dumps({'raw':r.calls['getrawtransaction'],'backlog':out['backlog']}));s.db.close()"
        try:
            result=json.loads(subprocess.check_output([sys.executable,'-c',code,self.file,str(Path(__file__).parent)],text=True))
            self.assertEqual(result,{'raw':3,'backlog':0})
        finally:self.store=IX.Store(self.file)
    def test_large_eviction_prunes_in_bounded_sql_chunks(self):
        self.pool(1200);a=scan(self.rpc,self.store,set(),1200,max_rpc=1300,max_seconds=10)
        self.assertEqual(a['backlog'],0)
        self.rpc.mempool={};scan(self.rpc,self.store,set(),10)
        self.assertEqual(self.store.db.execute('select count(*) from mempool_scan_cache').fetchone()[0],0)
    def test_failed_fetch_is_not_marked_inspected_and_retries(self):
        self.pool(2);first=f'{1:064x}';self.rpc.fail.add(first)
        a=scan(self.rpc,self.store,set(),2);self.assertEqual(a['scanned'],1);self.assertEqual(a['backlog'],1)
        row=self.store.db.execute('select checked_at,failures,next_retry from mempool_scan_cache where txid=?',(first,)).fetchone()
        self.assertIsNone(row[0]);self.assertEqual(row[1],1);self.assertGreater(row[2],0)
        before=self.rpc.calls['getrawtransaction'];scan(self.rpc,self.store,set(),2);self.assertEqual(self.rpc.calls['getrawtransaction'],before)
        self.rpc.fail.clear();self.store.db.execute('update mempool_scan_cache set next_retry=0')
        b=scan(self.rpc,self.store,set(),2);self.assertEqual(b['backlog'],0)
    def test_eviction_prunes_cache_and_pending_rows(self):
        tx=mint();self.rpc.mempool={tx['txid']:tx};scan(self.rpc,self.store,set(),10)
        self.assertEqual(self.store.db.execute('select count(*) from mempool').fetchone()[0],1)
        self.rpc.mempool={};scan(self.rpc,self.store,set(),10)
        self.assertEqual(self.store.db.execute('select count(*) from mempool_scan_cache').fetchone()[0],0)
        self.assertEqual(self.store.db.execute('select count(*) from mempool').fetchone()[0],0)
    def test_reorg_or_missing_pending_row_rehydrates_from_raw_cache(self):
        tx=mint();self.rpc.mempool={tx['txid']:tx};scan(self.rpc,self.store,set(),10)
        self.store.db.execute('delete from mempool');scan(self.rpc,self.store,set(),10)
        self.assertEqual(self.store.db.execute('select count(*) from mempool').fetchone()[0],1)
        self.assertEqual(self.rpc.calls['getrawtransaction'],1)
    def test_request_budget_includes_snapshot_and_fee_requests(self):
        self.pool(10);a=scan(self.rpc,self.store,set(),100,max_rpc=5)
        self.assertLessEqual(sum(self.rpc.calls.values()),5);self.assertEqual(a['scanned'],3);self.assertEqual(a['backlog'],7)
    def test_checkpoint_survives_interruption(self):
        self.pool(3);self.rpc.interrupt_at=2
        with self.assertRaises(KeyboardInterrupt):scan(self.rpc,self.store,set(),10)
        self.assertEqual(self.store.db.execute('select count(*) from mempool_scan_cache where checked_at is not null').fetchone()[0],1)
        self.store.db.close();self.store=IX.Store(self.file);self.rpc.interrupt_at=None
        a=scan(self.rpc,self.store,set(),10);self.assertEqual(a['scanned'],2);self.assertEqual(a['backlog'],0)
    def test_snapshot_failure_retains_previous_cache(self):
        self.pool(2);scan(self.rpc,self.store,set(),2);self.rpc.snapshot_fail=True
        with self.assertRaises(RuntimeError):scan(self.rpc,self.store,set(),2)
        self.assertEqual(self.store.db.execute('select count(*) from mempool_scan_cache').fetchone()[0],2)
        node={k:json.loads(v) for k,v in self.store.db.execute('select key,value from node')}
        self.assertEqual(node['scanner']['status'],'error')
    def test_rate_limit_pauses_and_keeps_failed_item_uninspected(self):
        self.pool(3);self.rpc.rate_limit=f'{1:064x}'
        a=scan(self.rpc,self.store,set(),10);self.assertEqual(a['scanned'],0);self.assertEqual(a['backlog'],3)
        node={k:json.loads(v) for k,v in self.store.db.execute('select key,value from node')}
        self.assertEqual(node['scanner']['status'],'rate_limited');self.assertGreaterEqual(node['scanner']['retry_after_seconds'],30)
    def test_disabled_initialization_keeps_progress(self):
        self.pool(2);scan(self.rpc,self.store,set(),2);initialize_scan(self.store,False)
        self.assertEqual(self.store.db.execute('select count(*) from mempool_scan_cache where checked_at is not null').fetchone()[0],2)
        self.assertEqual(json.loads(self.store.db.execute("select value from node where key='mempool_enabled'").fetchone()[0]),False)
    def test_cached_mint_payment_refreshes_after_token_discovery(self):
        tx=mint();self.rpc.mempool={tx['txid']:tx};scan(self.rpc,self.store,set(),10)
        self.assertIsNone(self.store.db.execute('select paid from mempool').fetchone()[0])
        self.rpc.blocks,_=chain();state=self.store.load_state();IX.sync(self.rpc,self.store,state,100,log=lambda _:None)
        scan(self.rpc,self.store,set(),10,state)
        self.assertEqual(self.store.db.execute('select paid from mempool').fetchone()[0],1000)
        self.assertEqual(self.rpc.calls['getrawtransaction'],1)
    def test_transaction_budget_counts_failures_without_starving_next_items(self):
        self.pool(5);self.rpc.fail.add(f'{1:064x}');a=scan(self.rpc,self.store,set(),2)
        self.assertEqual(self.rpc.calls['getrawtransaction'],2);self.assertEqual(a['scanned'],1);self.assertEqual(a['backlog'],4)
    def follow_args(self,budget,once=True):
        from types import SimpleNamespace
        return SimpleNamespace(rpc_url='https://fake.invalid',rpc_user='',rpc_password='',rpc_bearer='',rps=10,db=self.file,network='testnet3',start=100,mempool_budget=budget,mempool_interval=60,mempool_scan_seconds=10,mempool_rpc_budget=100,poll=10,once=once)
    def test_wrong_rpc_network_stops_before_replaying_blocks(self):
        self.rpc.chain_name='main';self.rpc.blocks,_=chain()
        with patch.object(IX,'Rpc',return_value=self.rpc):
            with self.assertRaisesRegex(RuntimeError,'network mismatch'):IX.follow(self.follow_args(0))
        self.assertIsNone(self.store.tip())
    def test_disabled_follow_makes_no_mempool_snapshot_requests(self):
        self.rpc.blocks,_=chain()
        with patch.object(IX,'Rpc',return_value=self.rpc):IX.follow(self.follow_args(0))
        self.assertEqual(self.rpc.calls['getrawmempool'],0)
        node={k:json.loads(v) for k,v in self.store.db.execute('select key,value from node')}
        self.assertFalse(node['mempool_enabled']);self.assertEqual(node['scanner']['status'],'disabled')
    def test_scan_interval_does_not_scan_on_every_block_poll(self):
        self.rpc.blocks,_=chain();self.pool(2)
        with patch.object(IX,'Rpc',return_value=self.rpc),patch.object(IX.time,'monotonic',return_value=100),patch.object(IX.time,'sleep',side_effect=[None,KeyboardInterrupt()]):
            with self.assertRaises(KeyboardInterrupt):IX.follow(self.follow_args(2,False))
        self.assertEqual(self.rpc.calls['getrawmempool'],1)
    def test_identical_snapshot_costs_only_snapshot_queries(self):
        self.pool(2);scan(self.rpc,self.store,set(),2);self.rpc.calls.clear();scan(self.rpc,self.store,set(),2)
        self.assertEqual(dict(self.rpc.calls),{'getrawmempool':1,'getmempoolinfo':1})

if __name__=='__main__':unittest.main()
