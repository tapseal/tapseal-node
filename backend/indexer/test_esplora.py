"""Light mode: raw blocks from an Esplora API must index to exactly the state an RPC node gives."""
import hashlib
import http.server
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "protocol"))
import tapseal as T  # noqa: E402
import tapseal_indexer as IX  # noqa: E402
from esplora import Esplora, parse_block  # noqa: E402
from test_indexer import FakeRpc, DEV, OWNER, TREASURY  # noqa: E402


def dsha(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def vi(n):
    return bytes([n]) if n < 0xFD else b"\xfd" + n.to_bytes(2, "little") if n <= 0xFFFF else b"\xfe" + n.to_bytes(4, "little")


class Tx:
    """A transaction built for the test: knows its own raw bytes and its getblock-2 JSON."""

    def __init__(self, vin, vout, coinbase=False):
        self.vin, self.vout, self.coinbase = vin, vout, coinbase   # vin: [(txid, n, witness[])], vout: [(sats, spk)]

    def _ins(self):
        out = vi(len(self.vin))
        for txid, n, _ in self.vin:
            out += bytes.fromhex(txid)[::-1] + n.to_bytes(4, "little") + (b"\x03\x01\x02\x03" if self.coinbase else b"\x00") + b"\xff\xff\xff\xff"
        out += vi(len(self.vout))
        for sats, spk in self.vout:
            out += sats.to_bytes(8, "little") + vi(len(spk)) + spk
        return out

    def raw(self):
        wit = any(w for _, _, w in self.vin)
        body = self._ins()
        if not wit:
            return b"\x02\x00\x00\x00" + body + b"\x00\x00\x00\x00"
        ws = b"".join(vi(len(w)) + b"".join(vi(len(x)) + x for x in w) for _, _, w in self.vin)
        return b"\x02\x00\x00\x00\x00\x01" + body + ws + b"\x00\x00\x00\x00"

    @property
    def wtxid(self):
        return dsha(self.raw())[::-1].hex() if any(w for _, _, w in self.vin) else self.txid

    @property
    def txid(self):
        return dsha(b"\x02\x00\x00\x00" + self._ins() + b"\x00\x00\x00\x00")[::-1].hex()

    def rpc(self):
        vin = [{"coinbase": "010203"} if self.coinbase else {"txid": t, "vout": n, "txinwitness": [x.hex() for x in w]} for t, n, w in self.vin]
        return {"txid": self.txid, "vin": vin,
                "vout": [{"n": i, "value": s / 1e8, "scriptPubKey": {"hex": spk.hex()}} for i, (s, spk) in enumerate(self.vout)]}


def merkle(txids):
    level = [bytes.fromhex(t)[::-1] for t in txids]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [dsha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def mine(prev, txs, t, bits=0x207FFFFF):
    """Header with regtest-easy proof of work."""
    root = merkle([x.txid for x in txs])
    for nonce in range(1 << 20):
        hdr = (0x20000000).to_bytes(4, "little") + bytes.fromhex(prev)[::-1] + root + t.to_bytes(4, "little") + bits.to_bytes(4, "little") + nonce.to_bytes(4, "little")
        hh = dsha(hdr)[::-1]
        target = (bits & 0xFFFFFF) << (8 * ((bits >> 24) - 3))
        if int.from_bytes(hh, "big") <= target:
            return hdr, hh.hex()
    raise RuntimeError("no nonce")


def coinbase(height, body):
    """Coinbase with the BIP141 witness commitment over the block's other transactions."""
    root = merkle(["00" * 32] + [x.wtxid for x in body])
    commit = dsha(root + bytes(32))
    return Tx([("00" * 32, 0xFFFFFFFF, [bytes(32)])],
              [(50_0000_0000 + height, b"\x51\x20" + bytes(32)), (0, bytes.fromhex("6a24aa21a9ed") + commit)], coinbase=True)


def coin(tag):
    return (hashlib.sha256(tag.encode()).hexdigest(), 0, [b"\x02" * 64])


def build_chain(variant="a"):
    """Blocks 100..103 (+104 for b): deploy, mint, empty, transfer. Same story as test_indexer.chain, real txids."""
    op = lambda o: (0, T.op_return_script(T.encode(o)))  # noqa: E731
    dep = Tx([coin("fund-dep")], [op({"op": "deploy", "tick": "STONK", "dec": 8, "max": 21_000_000 * 10**8, "mode": "fixed",
                                      "rate": 10_000, "cap": 0, "treasury_vout": 1, "auth_vout": 2}),
                                  (330, TREASURY), (330, T.seal_spk("STONK", DEV, auth=True))])
    mint = Tx([coin("fund-mint")], [op({"op": "mint", "tick": "STONK", "vout": 1}), (330, T.seal_spk("STONK", OWNER)), (5000, TREASURY)])
    other = Tx([coin("unrelated")], [(12345, b"\x00\x14" + bytes(20))])
    legacy = Tx([(hashlib.sha256(b"legacy").hexdigest(), 1, [])], [(999, b"\x76\xa9\x14" + bytes(20) + b"\x88\xac")])
    leaf = T.seal_leaf(T.token_commitment("STONK"), OWNER)
    send = Tx([(mint.txid, 1, [b"\x01" * 64, leaf, b"\xc0" + T.NUMS_X]), coin("fee" + variant)],
              [op({"op": "transfer", "ticks": [{"tick": "STONK", "change": 2}], "edicts": [{"t": 0, "amt": 1000 if variant == "a" else 7, "vout": 1, "lock": 0}]}),
               (330, T.seal_spk("STONK", DEV)), (330, T.seal_spk("STONK", OWNER))])
    plan = [(100, [dep, legacy]), (101, [mint, other]), (102, []), (103, [send])] + ([(104, [])] if variant == "b" else [])
    blocks, prev = [], "00" * 32
    for height, body in plan:
        txs = [coinbase(height + (1000 if variant == "b" and height >= 103 else 0), body)] + body
        hdr, bh = mine(prev, txs, 1_700_000_000 + height)
        raw = hdr + vi(len(txs)) + b"".join(x.raw() for x in txs)
        blocks.append({"height": height, "hash": bh, "prev": prev, "raw": raw,
                       "rpc": {"height": height, "hash": bh, "previousblockhash": prev, "time": 1_700_000_000 + height, "tx": [x.rpc() for x in txs]}})
        prev = bh
    return blocks


class FakeEsplora(http.server.BaseHTTPRequestHandler):
    chain: list = []
    hits: list = []

    def log_message(self, *a):
        pass

    def _send(self, body, ctype="text/plain"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(200); self.send_header("content-type", ctype); self.send_header("content-length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        FakeEsplora.hits.append(self.path)
        c = FakeEsplora.chain
        p = self.path
        if p == "/blocks/tip/height":
            return self._send(str(c[-1]["height"]))
        if p.startswith("/block-height/"):
            h = int(p.rsplit("/", 1)[1])
            b = next((x for x in c if x["height"] == h), None)
            return self._send(b["hash"]) if b else self.send_error(404)
        if p.startswith("/block/"):
            parts = p.split("/")
            b = next((x for x in c if x["hash"] == parts[2]), None)
            if not b:
                return self.send_error(404)
            if len(parts) == 4 and parts[3] == "raw":
                return self._send(b["raw"], "application/octet-stream")
            if len(parts) == 4 and parts[3] == "txids":
                return self._send(json.dumps([t["txid"] for t in b["rpc"]["tx"]]), "application/json")
            return self._send(json.dumps({"id": b["hash"], "height": b["height"], "timestamp": b["rpc"]["time"], "previousblockhash": b["prev"]}), "application/json")
        if p == "/fee-estimates":
            return self._send(json.dumps({"1": 7.5, "3": 5.0, "6": 3.1, "144": 1.0}), "application/json")
        self.send_error(404)


class LightMode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeEsplora)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def store(self):
        d = tempfile.mkdtemp()
        s = IX.Store(os.path.join(d, "t.sqlite"))
        return s, s.load_state()

    def roots(self, s):
        return [tuple(r) for r in s.db.execute("select height, hash, root from blocks order by height")]

    def test_parse_matches_built_transactions(self):
        for b in build_chain():
            got = parse_block(b["raw"], b["height"])
            self.assertEqual(got["hash"], b["hash"])
            self.assertEqual(got["previousblockhash"], b["prev"])
            for g, want in zip(got["tx"], b["rpc"]["tx"]):
                self.assertEqual(T.tx_from_rpc(g), T.tx_from_rpc(want))

    def test_light_sync_equals_rpc_sync(self):
        chain = build_chain()
        FakeEsplora.chain = chain
        rpc = FakeRpc(); rpc.blocks = [b["rpc"] for b in chain]
        a, sa = self.store(); b, sb = self.store()
        IX.sync(rpc, a, sa, 100, log=lambda m: None)
        IX.sync(Esplora(self.url, rps=1000), b, sb, 100, log=lambda m: None)
        self.assertEqual(self.roots(a), self.roots(b))
        self.assertEqual(sa.root(), sb.root())
        self.assertEqual(sb.tokens["STONK"].id, "100:1")          # coinbase is index 0
        self.assertEqual(sb.balance("STONK"), sa.balance("STONK"))
        self.assertTrue(any(e[0] == "transfer" for e in b.db.execute("select kind from events")))

    def test_light_reorg_matches_rpc(self):
        FakeEsplora.chain = build_chain("a")
        b, sb = self.store()
        es = Esplora(self.url, rps=1000)
        IX.sync(es, b, sb, 100, log=lambda m: None)
        chain_b = build_chain("b")
        FakeEsplora.chain = chain_b
        IX.sync(es, b, sb, 100, log=lambda m: None)
        rpc = FakeRpc(); rpc.blocks = [x["rpc"] for x in chain_b]
        a, sa = self.store()
        IX.sync(rpc, a, sa, 100, log=lambda m: None)
        self.assertEqual(self.roots(a), self.roots(b))

    def test_rejects_tampered_blocks(self):
        good = build_chain()[3]["raw"]
        bad = bytearray(good); bad[-30] ^= 1                       # change a witness byte (the seal's control block)
        with self.assertRaisesRegex(ValueError, "witness commitment"):
            parse_block(bytes(bad))
        i = good.index(T.op_return_script(T.encode({"op": "transfer", "ticks": [{"tick": "STONK", "change": 2}], "edicts": [{"t": 0, "amt": 1000, "vout": 1, "lock": 0}]})))
        bad2 = bytearray(good); bad2[i + 10] ^= 1                  # change the TAPSEAL payload
        with self.assertRaisesRegex(ValueError, "merkle"):
            parse_block(bytes(bad2))
        hard = bytearray(good); hard[72:76] = (0x1D00FFFF).to_bytes(4, "little")   # mainnet-hard target, same header
        with self.assertRaisesRegex(ValueError, "proof of work"):
            parse_block(bytes(hard))

    def test_network_minimum_and_second_source(self):
        chain = build_chain()
        with self.assertRaisesRegex(ValueError, "below this network"):
            parse_block(chain[0]["raw"], 100, pow_limit=0x1D00FFFF)       # regtest-easy header on mainnet
        self.assertEqual(parse_block(chain[0]["raw"], 100, pow_limit=0x207FFFFF)["hash"], chain[0]["hash"])
        FakeEsplora.chain = chain
        b, sb = self.store()
        IX.sync(Esplora(f"{self.url},{self.url}", rps=1000, network="regtest"), b, sb, 100, log=lambda m: None)   # both agree
        self.assertEqual(b.tip()[0], 103)
        other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("Liar", (FakeEsplora,), {"do_GET": lambda s: s._send("ab" * 32)}))
        threading.Thread(target=other.serve_forever, daemon=True).start()
        c, sc = self.store()
        with self.assertRaisesRegex(RuntimeError, "disagree"):
            IX.sync(Esplora(f"{self.url},http://127.0.0.1:{other.server_address[1]}", rps=1000), c, sc, 100, log=lambda m: None)
        other.shutdown()
        self.assertIsNone(c.tip())

    def test_one_request_for_the_block_body(self):
        FakeEsplora.chain = build_chain(); FakeEsplora.hits = []
        b, sb = self.store()
        IX.sync(Esplora(self.url, rps=1000), b, sb, 100, log=lambda m: None)
        raws = [p for p in FakeEsplora.hits if p.endswith("/raw")]
        self.assertEqual(len(raws), 4)
        self.assertLessEqual(len(FakeEsplora.hits), 4 * 3 + 1)   # tip height + per block: hash, info, raw


if __name__ == "__main__":
    unittest.main()

class ParserSecurity(unittest.TestCase):
    def test_compact_target_edge_cases_and_truncation(self):
        from esplora import _target,_Reader
        self.assertEqual(_target(0x02010000),256)
        for bits in [0,0x1d80ffff,0x23000001]:
            with self.assertRaises(ValueError):_target(bits)
        with self.assertRaises(ValueError):_Reader(b'\xfd\x01\x00').varint()
        for raw in [b'',b'\x00'*80,b'\x00'*4_000_001]:
            with self.assertRaises(ValueError):parse_block(raw)
    def test_commitment_is_checked_even_without_other_witnesses(self):
        from esplora import _check_witness_commitment
        coinbase={'vin':[{'coinbase':'01','txinwitness':['00'*32,'00']}], 'vout':[{'scriptPubKey':{'hex':'6a24aa21a9ed'+'00'*32}}]}
        with self.assertRaises(ValueError):_check_witness_commitment([coinbase])
