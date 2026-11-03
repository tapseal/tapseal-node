"""
Light mode: read confirmed blocks from a public Esplora API (mempool.space, blockstream.info) instead of a
Bitcoin node. One request per block (`/block/:hash/raw`), parsed here into the same shape as
`getblock <hash> 2`, so the indexer and the protocol rules run unchanged and reach the same state root.

`Esplora` offers the `call(method, *params)` interface of `Rpc` for the calls the indexer makes:
getblockcount, getblockhash, getblock (verbosity 1 and 2), getrawtransaction (verbose), estimatesmartfee.
A light node trusts the Esplora server for block data. It still checks every block links to the previous one,
and peers compare state roots, so a server serving a different chain shows up as a disagreement.
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.request
from collections import deque

# Primary block API first; the others only confirm each block hash (one small request per block each).
ESPLORA = {
    "mainnet": "https://mempool.space/api,https://blockstream.info/api",
    "testnet3": "https://mempool.space/testnet/api,https://blockstream.info/testnet/api",
    "testnet": "https://mempool.space/testnet4/api",
    "testnet4": "https://mempool.space/testnet4/api",
    "signet": "https://mempool.space/signet/api,https://blockstream.info/signet/api",
}
# Easiest target each network allows (consensus powLimit, as compact bits). A header claiming an easier target is fake.
POW_LIMIT = {"mainnet": 0x1D00FFFF, "testnet3": 0x1D00FFFF, "testnet": 0x1D00FFFF, "testnet4": 0x1D00FFFF,
             "signet": 0x1E0377AE, "regtest": 0x207FFFFF}


def _target(bits: int) -> int:
    size=bits >> 24;word=bits & 0x7fffff
    if bits & 0x800000 or word == 0 or size > 34: raise ValueError("invalid compact proof-of-work target")
    target=(word >> (8*(3-size))) if size<=3 else (word << (8*(size-3)))
    if not 0<target<(1<<256):raise ValueError("invalid proof-of-work target")
    return target


def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


class _Reader:
    __slots__ = ("b", "i")

    def __init__(self, b: bytes):
        self.b, self.i = b, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.b):
            raise ValueError("truncated block")
        out = self.b[self.i:self.i + n]
        self.i += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "little")

    def varint(self) -> int:
        n = self.u8()
        if n < 0xFD:
            return n
        value=int.from_bytes(self.take({0xFD: 2, 0xFE: 4, 0xFF: 8}[n]), "little")
        if value < {0xFD:253,0xFE:65536,0xFF:4294967296}[n]:raise ValueError("non-canonical CompactSize")
        if value>4_000_000:raise ValueError("oversized block vector")
        return value


def _tx(r: _Reader) -> dict:
    """One transaction (BIP144 aware) in getblock-2 shape; txid from the non-witness serialization."""
    start = r.i
    version = r.take(4)
    if r.i+2>len(r.b):raise ValueError("truncated transaction")
    segwit = r.b[r.i] == 0 and r.b[r.i + 1] == 1
    if segwit:
        r.take(2)
    ins_start = r.i
    vin = []
    for _ in range(r.varint()):
        prev = r.take(32)[::-1].hex()
        n = r.u32()
        script = r.take(r.varint())
        seq = r.u32()
        coinbase = prev == "00" * 32 and n == 0xFFFFFFFF
        vin.append({"coinbase": script.hex(), "sequence": seq} if coinbase else {"txid": prev, "vout": n, "sequence": seq})
    vout = []
    for k in range(r.varint()):
        sats = r.u64()
        spk = r.take(r.varint())
        vout.append({"n": k, "value": sats / 100_000_000, "sats": sats, "scriptPubKey": {"hex": spk.hex()}})
    ins_end = r.i
    if segwit:
        for v in vin:
            items = [r.take(r.varint()).hex() for _ in range(r.varint())]
            if items:
                v["txinwitness"] = items
    locktime = r.take(4)
    stripped = version + r.b[ins_start:ins_end] + locktime
    txid = sha256d(stripped)[::-1].hex()
    return {"txid": txid, "hash": sha256d(r.b[start:r.i])[::-1].hex() if segwit else txid,
            "version": int.from_bytes(version, "little"), "locktime": int.from_bytes(locktime, "little"), "vin": vin, "vout": vout}


def parse_block(raw: bytes, height: int | None = None, pow_limit: int | None = None) -> dict:
    """Raw block bytes → getblock-2 dict (hash, previousblockhash, time, height, tx).
    Checks proof of work (against the network's limit when given), the merkle root and the witness commitment."""
    if not 81<=len(raw)<=4_000_000:raise ValueError("block size outside parser limits")
    r = _Reader(raw)
    header = r.take(80)
    count=r.varint()
    if not 0<count<=30000:raise ValueError("invalid transaction count")
    txs = [_tx(r) for _ in range(count)]
    if len({t["txid"] for t in txs})!=len(txs):raise ValueError("duplicate transaction in block")
    if r.i != len(raw):
        raise ValueError("trailing bytes after block")
    bhash = sha256d(header)[::-1]
    bits = int.from_bytes(header[72:76], "little")
    target = _target(bits)
    if pow_limit is not None and target > _target(pow_limit):
        raise ValueError("block header claims a difficulty below this network's minimum")
    if int.from_bytes(bhash, "big") > target:
        raise ValueError("block header has insufficient proof of work")
    merkle = header[36:68][::-1].hex()
    if _merkle_root([t["txid"] for t in txs]) != merkle:
        raise ValueError("merkle root does not match the transactions")
    _check_witness_commitment(txs)
    return {"hash": bhash.hex(), "previousblockhash": header[4:36][::-1].hex(),
            "time": int.from_bytes(header[68:72], "little"), "height": height, "tx": txs}


WITNESS_TAG = "6a24aa21a9ed"


def _check_witness_commitment(txs: list[dict]) -> None:
    """BIP141: witnesses are not covered by the txid merkle root but by a commitment in the coinbase.
    Seal spends depend on witness data, so a light node must check it."""
    if not txs or len(txs[0]["vin"])!=1 or "coinbase" not in txs[0]["vin"][0]:raise ValueError("first transaction is not coinbase")
    if any("coinbase" in v for t in txs[1:] for v in t["vin"]):raise ValueError("multiple coinbase transactions")
    has_witness=any(any("txinwitness" in v for v in t["vin"]) for t in txs[1:])
    outs = [o["scriptPubKey"]["hex"] for o in txs[0]["vout"] if o["scriptPubKey"]["hex"].startswith(WITNESS_TAG)]
    if not outs and not has_witness:return
    witness=txs[0]["vin"][0].get("txinwitness") or []
    reserved=witness[0] if len(witness)==1 else ""
    if not outs or len(outs[-1])<76 or len(reserved) != 64:
        raise ValueError("block has witness data but no witness commitment")
    root = _merkle_root(["00" * 32] + [t["hash"] for t in txs[1:]])
    if sha256d(bytes.fromhex(root)[::-1] + bytes.fromhex(reserved)).hex() != outs[-1][12:76]:
        raise ValueError("witness commitment does not match the witness data")


def _merkle_root(txids: list[str]) -> str:
    level = [bytes.fromhex(t)[::-1] for t in txids]
    if not level:
        return "00" * 32
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256d(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0][::-1].hex()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):return None

class Esplora:
    """Esplora HTTP API with the indexer's Rpc.call interface. Polite: rate limited, retries with backoff."""

    def __init__(self, base: str, rps: float = 4, timeout: float = 60, network: str | None = None):
        urls = [u.strip().rstrip("/") for u in base.split(",") if u.strip()]
        if not urls:raise ValueError("at least one block API is required")
        self.base, self.confirm = urls[0], urls[1:3]
        self.pow_limit = POW_LIMIT.get(network) if network else None
        self.delay, self.timeout, self.last = 1.0 / max(0.5, float(rps)), timeout, 0.0
        self.lat = deque(maxlen=50)
        self.headers = {"User-Agent": "tapseal-node/1 (light)"}

    def _get(self, path: str, binary=False, base: str | None = None):
        wait = self.delay - (time.time() - self.last)
        if wait > 0:
            time.sleep(wait)
        self.last = time.time()
        t0 = time.time()
        for attempt in range(5):
            try:
                with urllib.request.build_opener(_NoRedirect).open(urllib.request.Request((base or self.base) + path, headers=self.headers), timeout=self.timeout) as res:
                    limit=4_000_000;chunks=[];size=0;deadline=time.monotonic()+self.timeout
                    while True:
                        if time.monotonic()>deadline:raise RuntimeError("Esplora response deadline exceeded")
                        chunk=res.read1(min(65536,limit+1-size))
                        if not chunk:break
                        size+=len(chunk)
                        if size>limit:raise RuntimeError("Esplora response exceeds parser limit")
                        chunks.append(chunk)
                    body=b"".join(chunks)
                break
            except urllib.error.HTTPError as exc:
                if exc.code in (429, 500, 502, 503, 504) and attempt < 4:
                    time.sleep(min(30, 2 ** attempt * (3 if exc.code == 429 else 1)))
                    continue
                raise RuntimeError(f"Esplora HTTP {exc.code} for {path}") from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt < 4:
                    time.sleep(2 ** attempt)
                    continue
                raise RuntimeError(f"Esplora unreachable: {exc}") from exc
        self.lat.append((time.time() - t0) * 1000)
        return body if binary else body.decode()

    def call(self, method: str, *params):
        if method == "getblockcount":
            return int(self._get("/blocks/tip/height"))
        if method == "getblockhash":
            return self._get(f"/block-height/{int(params[0])}").strip()
        if method == "getbestblockhash":
            return self._get("/blocks/tip/hash").strip()
        if method == "getblock":
            bhash, verbosity = params[0], (params[1] if len(params) > 1 else 1)
            info = json.loads(self._get(f"/block/{bhash}"))
            if verbosity == 1:
                return {"hash": bhash, "height": info["height"], "time": info["timestamp"],
                        "previousblockhash": info.get("previousblockhash"), "tx": json.loads(self._get(f"/block/{bhash}/txids"))}
            try:
                block = parse_block(self._get(f"/block/{bhash}/raw", binary=True), info["height"], self.pow_limit)
            except ValueError as exc:
                raise RuntimeError(f"rejected block {bhash} from {self.base}: {exc}") from exc
            if block["hash"] != bhash:
                raise RuntimeError(f"Esplora served a different block for {bhash}")
            for other in self.confirm:            # a second, independent block API must report the same block
                theirs = self._get(f"/block-height/{info['height']}", base=other).strip()
                if theirs != bhash:
                    raise RuntimeError(f"block APIs disagree at {info['height']}: {self.base} {bhash[:16]}…, {other} {theirs[:16]}…")
            return block
        if method == "getrawtransaction":
            tx = json.loads(self._get(f"/tx/{params[0]}"))
            st = tx.get("status", {})
            return {"txid": tx["txid"], "blockhash": st.get("block_hash"), "confirmations": 1 if st.get("confirmed") else 0}
        if method == "estimatesmartfee":
            fees = json.loads(self._get("/fee-estimates"))
            v = fees.get(str(int(params[0])))
            return {"feerate": v / 1e5} if v else {"errors": ["no estimate"]}
        raise RuntimeError(f"{method} is not available on a light node")

    def latency_ms(self):
        return round(sum(self.lat) / len(self.lat), 1) if self.lat else None
