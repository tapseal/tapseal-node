#!/usr/bin/env python3
"""Test helper for the API.
  fixture.py make <db> <user_sk_hex>        build an indexed chain where the user owns STONK seals
  fixture.py apply <db> <tx.json>           apply a tx (JSON from the JS test) at tip+1, print events + balances
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "protocol"))
sys.path.insert(0, str(ROOT / "indexer"))
import tapseal as T  # noqa: E402
import tapseal_indexer as IX  # noqa: E402
from test_indexer import FakeRpc, rpc_tx, opret, h  # noqa: E402


def xonly(k):
    return T._mul(k)[0].to_bytes(32, "big")


def bip86_output_key(sk: int) -> bytes:
    """The x-only key inside a BIP86 Taproot address (what UniSat signs with)."""
    px = xonly(sk)
    t = int.from_bytes(T.tagged_hash("TapTweak", px), "big")
    q = T._add(T._lift_x(px), T._mul(t))
    return q[0].to_bytes(32, "big")


def make(db, sk_hex):
    owner = bip86_output_key(int(sk_hex, 16))
    treasury = b"\x51\x20" + xonly(99)
    dev = xonly(44)
    dep = rpc_tx(h("dep"), [], [opret({"op": "deploy", "tick": "STONK", "dec": 8, "max": 21_000_000 * 10**8, "mode": "fixed",
                                       "rate": 50_000_000, "cap": 150_000, "treasury_vout": 1, "auth_vout": 2}),
                                (330, treasury), (330, T.seal_spk("STONK", dev, auth=True))])
    fair = rpc_tx(h("fair"), [], [opret({"op": "deploy", "tick": "FREE", "dec": 0, "max": 1_000_000, "mode": "fair", "lim": 1000})])
    m1 = rpc_tx(h("m1"), [], [opret({"op": "mint", "tick": "STONK", "vout": 1}), (330, T.seal_spk("STONK", owner)), (40_000, treasury)])
    m2 = rpc_tx(h("m2"), [], [opret({"op": "mint", "tick": "STONK", "vout": 1, "lock": 102}), (330, T.seal_spk("STONK", owner, 102)), (10_000, treasury)])
    rpc = FakeRpc()
    prev = "00" * 32
    for height, txs in [(100, [dep, fair]), (101, [m1, m2]), (102, []), (103, [])]:
        bh = h(f"blk{height}")
        rpc.blocks.append({"height": height, "hash": bh, "previousblockhash": prev, "time": 1700000000 + height, "tx": txs})
        prev = bh
    store = IX.Store(db)
    st = store.load_state()
    IX.sync(rpc, store, st, 100, log=lambda m: None)
    IX.telemetry(rpc, store, 103, 0, {"size": 10, "bytes": 2000}, IX.fee_estimates(rpc))
    print(json.dumps({"owner": owner.hex(), "seals": len(st.seals), "root": st.root()}))


def make11(db, sk_hex):
    """Chain for protocol 1.1: WLT (fixed, user holds authority) and CAPPED (fair, 30 per wallet)."""
    owner = bip86_output_key(int(sk_hex, 16))
    treasury = b"\x51\x20" + xonly(99)
    wlt = rpc_tx(h("wlt"), [], [opret({"op": "deploy", "tick": "WLT", "dec": 0, "max": 1_000_000, "mode": "fixed",
                                       "rate": 1, "cap": 0, "treasury_vout": 1, "auth_vout": 2}),
                                (330, treasury), (330, T.seal_spk("WLT", owner, auth=True))])
    cap = rpc_tx(h("capped"), [], [opret({"op": "deploy", "tick": "CAPPED", "dec": 0, "max": 1_000_000, "mode": "fair", "lim": 10, "wallet_cap": 30})])
    rpc = FakeRpc()
    prev = "00" * 32
    for height, txs in [(100, [wlt]), (101, [cap]), (102, []), (103, [])]:
        bh = h(f"v11blk{height}")
        rpc.blocks.append({"height": height, "hash": bh, "previousblockhash": prev, "time": 1700000000 + height, "tx": txs})
        prev = bh
    store = IX.Store(db)
    st = store.load_state()
    IX.sync(rpc, store, st, 100, log=lambda m: None)
    IX.telemetry(rpc, store, 103, 0, {"size": 10, "bytes": 2000}, IX.fee_estimates(rpc))
    print(json.dumps({"owner": owner.hex(), "ids": {t: st.tokens[t].id for t in st.tokens}}))


def apply(db, txfile):
    store = IX.Store(db)
    st = store.load_state()
    tip = store.tip()[0]
    j = json.loads(Path(txfile).read_text())
    tx = {"txid": j["txid"], "vin": [{"prevout": v["prevout"], "witness": [bytes.fromhex(w) for w in v["witness"]]} for v in j["vin"]],
          "vout": [{"value": o["value"], "spk": bytes.fromhex(o["spk"])} for o in j["vout"]]}
    events = T.apply_tx(st, tx, tip + 1)
    bal = {t: str(st.balance(t)) for t in st.tokens}
    wl = {t: ({**st.tokens[t].wl, "reserve": str(st.tokens[t].wl["reserve"]), "price": str(st.tokens[t].wl["price"])} if st.tokens[t].wl else None) for t in st.tokens}
    lost = {t: str(st.tokens[t].lost) for t in st.tokens}
    new = [{"outpoint": s.outpoint, "tick": s.tick, "amt": str(s.amt), "lock": s.lock, "auth": s.auth} for s in st.seals.values() if s.outpoint.startswith(j["txid"])]
    print(json.dumps({"events": [{**e, "amt": str(e["amt"])} for e in events], "balance": bal, "lost": lost, "new_seals": new, "tokens": sorted(st.tokens), "wl": wl}))


def confirm(db, txfile):
    """Mine the tx (JSON from the JS side) into a new block at tip+1, like the live indexer would."""
    store = IX.Store(db)
    st = store.load_state()
    tip_h, tip_hash = store.tip()
    j = json.loads(Path(txfile).read_text())
    tx = {"txid": j["txid"],
          "vin": [{"txid": v["prevout"].split(":")[0], "vout": int(v["prevout"].split(":")[1]), "txinwitness": v["witness"]} for v in j["vin"]],
          "vout": [{"n": i, "value": o["value"] / 1e8, "scriptPubKey": {"hex": o["spk"]}} for i, o in enumerate(j["vout"])]}
    block = {"height": tip_h + 1, "hash": h(f"confirm{j['txid']}"), "previousblockhash": tip_hash, "time": 1700000000 + tip_h + 1, "tx": [tx]}
    events = store.apply_block(st, block)
    print(json.dumps({"height": tip_h + 1, "events": [{**e, "amt": str(e["amt"])} for e in events]}))


if __name__ == "__main__":
    {"make": make, "make11": make11, "apply": apply, "confirm": confirm}[sys.argv[1]](*sys.argv[2:])
