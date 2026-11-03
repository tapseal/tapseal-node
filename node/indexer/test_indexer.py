#!/usr/bin/env python3
"""Run: python3 test_indexer.py   (no network; uses an in-memory fake RPC)"""
import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "protocol"))
import tapseal as T  # noqa: E402
import tapseal_indexer as IX  # noqa: E402


def xonly(k):
    return T._mul(k)[0].to_bytes(32, "big")


OWNER, DEV = xonly(11), xonly(44)
TREASURY = b"\x51\x20" + xonly(99)


def rpc_tx(txid, vin, vout):
    return {"txid": txid,
            "vin": [{"txid": p.split(":")[0], "vout": int(p.split(":")[1]), "txinwitness": [w.hex() for w in wit]} for p, wit in vin],
            "vout": [{"n": i, "value": v / 1e8, "scriptPubKey": {"hex": spk.hex()}} for i, (v, spk) in enumerate(vout)]}


def opret(op):
    return (0, T.op_return_script(T.encode(op)))


def h(s):
    return hashlib.sha256(s.encode()).hexdigest()


class FakeRpc:
    def __init__(self):
        self.blocks, self.mempool, self.lat = [], {}, []

    def call(self, method, *p):
        if method == "getblockcount":
            return self.blocks[-1]["height"]
        if method == "getblockhash":
            return next(b["hash"] for b in self.blocks if b["height"] == p[0])
        if method == "getblock":
            return next(b for b in self.blocks if b["hash"] == p[0])
        if method == "getmempoolinfo":
            return {"size": len(self.mempool), "bytes": 1000, "usage": 2000, "mempoolminfee": 0.00001}
        if method == "getrawmempool":
            return list(self.mempool)
        if method == "getrawtransaction":
            return self.mempool[p[0]]
        if method == "getmempoolentry":
            return {"fees": {"base": 0.00002}, "vsize": 200}
        if method == "estimatesmartfee":
            return {"feerate": 0.00005}
        if method == "getconnectioncount":
            raise RuntimeError("method not allowed")
        raise RuntimeError(method)

    def latency_ms(self):
        return 1.0


def chain(variant="a"):
    """Blocks 100..103. Variant b replaces 103 and adds 104."""
    dep = rpc_tx(h("dep"), [], [opret({"op": "deploy", "tick": "STONK", "dec": 8, "max": 21_000_000 * 10**8, "mode": "fixed",
                                       "rate": 10_000, "cap": 0, "treasury_vout": 1, "auth_vout": 2}),
                                (330, TREASURY), (330, T.seal_spk("STONK", DEV, auth=True))])
    mint = rpc_tx(h("mint"), [], [opret({"op": "mint", "tick": "STONK", "vout": 1}), (330, T.seal_spk("STONK", OWNER)), (5000, TREASURY)])
    leaf = T.seal_leaf(T.token_commitment("STONK"), OWNER)
    send = rpc_tx(h("send" + variant), [(f"{h('mint')}:1", [b"\x01" * 64, leaf, b"\xc0" + T.NUMS_X])],
                  [opret({"op": "transfer", "ticks": [{"tick": "STONK", "change": 2}], "edicts": [{"t": 0, "amt": 1000 if variant == "a" else 7, "vout": 1, "lock": 0}]}),
                   (330, T.seal_spk("STONK", DEV)), (330, T.seal_spk("STONK", OWNER))])
    blocks, prev = [], "00" * 32
    for height, txs in [(100, [dep]), (101, [mint]), (102, []), (103, [send])] + ([(104, [])] if variant == "b" else []):
        bh = h(f"{variant if height >= 103 else ''}{height}")
        blocks.append({"height": height, "hash": bh, "previousblockhash": prev, "time": 1700000000 + height, "tx": txs})
        prev = bh
    return blocks, send


class Indexer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def db(self, name):
        return os.path.join(self.tmp, name)

    def test_same_height_reorg_replays_without_waiting_for_next_block(self):
        rpc=FakeRpc();rpc.blocks,_=chain("a")
        store=IX.Store(self.db("same.sqlite"));st=store.load_state()
        IX.sync(rpc,store,st,100,log=lambda m:None)
        rpc.blocks,_=chain("b");rpc.blocks=rpc.blocks[:-1]
        IX.sync(rpc,store,st,100,log=lambda m:None)
        fresh_store=IX.Store(self.db("same-fresh.sqlite"));fresh=fresh_store.load_state()
        IX.sync(rpc,fresh_store,fresh,100,log=lambda m:None)
        self.assertEqual(st.root(),fresh.root());self.assertEqual(store.tip()[1],rpc.blocks[-1]["hash"])

    def test_wrong_block_height_or_hash_is_not_applied(self):
        rpc=FakeRpc();rpc.blocks,_=chain("a")
        original=rpc.call
        def bad(method,*params):
            answer=original(method,*params)
            return {**answer,"height":999} if method=="getblock" else answer
        rpc.call=bad
        store=IX.Store(self.db("wrong.sqlite"));st=store.load_state()
        with self.assertRaisesRegex(RuntimeError,"inconsistent block"):IX.sync(rpc,store,st,100,log=lambda m:None)
        self.assertIsNone(store.tip())

    def test_replay_persist_and_reload(self):
        rpc = FakeRpc(); rpc.blocks, _ = chain("a")
        store = IX.Store(self.db("a.sqlite")); st = store.load_state()
        IX.sync(rpc, store, st, 100, log=lambda m: None)
        self.assertEqual(store.tip()[0], 103)
        self.assertEqual(st.balance("STONK"), 5000 * 10_000)
        reloaded = IX.Store(self.db("a.sqlite")).load_state()
        self.assertEqual(reloaded.root(), st.root())
        self.assertEqual(reloaded.tokens["STONK"].minted, st.tokens["STONK"].minted)
        root = store.db.execute("select root from blocks where height=103").fetchone()[0]
        self.assertEqual(root, st.root())

    def test_reorg_matches_fresh_replay(self):
        rpc = FakeRpc(); rpc.blocks, _ = chain("a")
        store = IX.Store(self.db("r.sqlite")); st = store.load_state()
        IX.sync(rpc, store, st, 100, log=lambda m: None)
        rpc.blocks, _ = chain("b")                         # 103 replaced, 104 added
        IX.sync(rpc, store, st, 100, log=lambda m: None)
        fresh_store = IX.Store(self.db("fresh.sqlite")); fresh = fresh_store.load_state()
        IX.sync(rpc, fresh_store, fresh, 100, log=lambda m: None)
        self.assertEqual(st.root(), fresh.root())
        self.assertEqual(IX.Store(self.db("r.sqlite")).load_state().root(), fresh.root())
        self.assertEqual(store.tip()[1], rpc.blocks[-1]["hash"])
        amts = sorted(s.amt for s in st.seals.values() if not s.auth)
        self.assertEqual(amts, [7, 5000 * 10_000 - 7])

    def test_mempool_scan_then_confirm(self):
        rpc = FakeRpc(); blocks, send = chain("a")
        rpc.blocks = blocks[:3]
        store = IX.Store(self.db("m.sqlite")); st = store.load_state()
        IX.sync(rpc, store, st, 100, log=lambda m: None)
        rpc.mempool = {send["txid"]: send, h("plain"): rpc_tx(h("plain"), [], [(1000, TREASURY)])}
        info = IX.mempool_scan(rpc, store, set(), 10)
        self.assertEqual(info["found"], 1)
        row = store.db.execute("select kind, tick, fee_rate from mempool").fetchone()
        self.assertEqual(row, ("transfer", "STONK", 10.0))
        rpc.blocks = blocks; rpc.mempool = {}
        IX.sync(rpc, store, st, 100, log=lambda m: None)
        self.assertEqual(store.db.execute("select count(*) from mempool").fetchone()[0], 0)
        IX.telemetry(rpc, store, 103, 0, info, IX.fee_estimates(rpc))
        node = dict(store.db.execute("select key, value from node"))
        self.assertEqual(node["lag"], "0")
        self.assertEqual(node["fees"], '{"1": 5.0, "3": 5.0, "6": 5.0, "144": 5.0}')

    def test_v11_ids_usage_and_reorg(self):
        """Token ID from block position; per-wallet usage persists, reloads and rolls back with a reorg."""
        dep = rpc_tx(h("capdep"), [], [opret({"op": "deploy", "tick": "CAP", "dec": 0, "max": 1000, "mode": "fair", "lim": 10,
                                              "wallet_cap": 30, "auth_vout": 1}), (330, T.seal_spk("CAP", DEV, auth=True))])
        def m(tag):
            return rpc_tx(h(tag), [], [opret({"op": "mint", "tick": "CAP", "vout": 1, "owner": OWNER.hex()}), (330, T.seal_spk("CAP", OWNER))])
        filler = rpc_tx(h("filler"), [], [(1000, TREASURY)])
        def blocks(variant):
            out, prev = [], "00" * 32
            plan = [(200, [filler, dep]), (201, [m("m1"), m("m2")])] + ([(202, [m("m3")])] if variant == "a" else [(202, []), (203, [])])
            for height, txs in plan:
                bh = h(f"cap{variant if height >= 202 else ''}{height}")
                out.append({"height": height, "hash": bh, "previousblockhash": prev, "time": 1, "tx": txs}); prev = bh
            return out
        rpc = FakeRpc(); rpc.blocks = blocks("a")
        store = IX.Store(self.db("v11.sqlite")); st = store.load_state()
        IX.sync(rpc, store, st, 200, log=lambda m: None)
        self.assertEqual(st.tokens["CAP"].id, "200:1")
        self.assertEqual(st.used("CAP", "pub", OWNER.hex()), 30)
        again = IX.Store(self.db("v11.sqlite")).load_state()
        self.assertEqual(again.used("CAP", "pub", OWNER.hex()), 30)
        self.assertEqual(again.tokens["CAP"].wallet_cap, 30)
        rpc.blocks = blocks("b")                                  # block 202 (the third mint) is reorged away
        IX.sync(rpc, store, st, 200, log=lambda m: None)
        self.assertEqual(st.used("CAP", "pub", OWNER.hex()), 20)
        self.assertEqual(IX.Store(self.db("v11.sqlite")).load_state().used("CAP", "pub", OWNER.hex()), 20)
        self.assertEqual(st.tokens["CAP"].minted, 20)

    def test_backfill_ids(self):
        rpc = FakeRpc(); rpc.blocks, _ = chain("a")
        store = IX.Store(self.db("bf.sqlite")); st = store.load_state()
        IX.sync(rpc, store, st, 100, log=lambda m: None)
        st.tokens["STONK"].id = ""
        orig = rpc.call
        def call(method, *p):
            if method == "getrawtransaction":
                return {"blockhash": rpc.blocks[0]["hash"]}
            if method == "getblock" and len(p) > 1 and p[1] == 1:
                b = next(x for x in rpc.blocks if x["hash"] == p[0])
                return {"height": b["height"], "tx": [t["txid"] for t in b["tx"]]}
            return orig(method, *p)
        rpc.call = call
        IX.backfill_token_ids(rpc, store, st, log=lambda m: None)
        self.assertEqual(IX.Store(self.db("bf.sqlite")).load_state().tokens["STONK"].id, "100:0")


if __name__ == "__main__":
    unittest.main(verbosity=1)
