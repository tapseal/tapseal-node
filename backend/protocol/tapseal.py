#!/usr/bin/env python3
"""
TAPSEAL reference implementation (formerly TAPSEAL).

One file, standard library only. It contains:

  * the wire codec (encode / decode every op, canonical varints)
  * seal leaf scripts (plain + timelocked) and their Taproot output keys
  * launch-mode pricing (fixed, linear bonding curve, fair mint)
  * the replay state machine: apply_tx(state, tx, height) -> events

The Python here is the normative behaviour; SPEC.md describes it in prose.
If the two disagree, fix whichever is wrong, then regenerate vectors.json.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

# ─────────────────────────────────────────────────────────────── constants ──

MAGIC = b"TSL1"
OP_DEPLOY, OP_MINT, OP_TRANSFER, OP_BURN, OP_META, OP_ALLOWLIST = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06
OP_NAMES = {OP_DEPLOY: "deploy", OP_MINT: "mint", OP_TRANSFER: "transfer", OP_BURN: "burn", OP_META: "meta",
            OP_ALLOWLIST: "allowlist"}

MODE_FIXED, MODE_CURVE, MODE_FAIR = 0, 1, 2
MODE_NAMES = {MODE_FIXED: "fixed", MODE_CURVE: "curve", MODE_FAIR: "fair"}

FLAG_AUTH = 0x01      # deploy creates an authority seal
FLAG_WINDOW = 0x02    # deploy carries start/end block heights
FLAG_WALLET_CAP = 0x04  # deploy carries a per-wallet public mint limit (atoms)

MINT_OWNER = 0x01     # mint names the x-only key that owns the new seal
MINT_PASS = 0x02      # mint carries a signed allowlist pass (requires MINT_OWNER)
BPS = 10_000

META_NAME, META_IMAGE_SHA256, META_URL, META_DESC = 1, 2, 3, 4

TICK_RE = re.compile(r"^[A-Z0-9]{1,8}$")
MAX_DECIMALS = 18
MAX_TICKS_PER_TRANSFER = 8
LOCKTIME_THRESHOLD = 500_000_000   # CLTV: below = block height (only heights allowed)
P2TR_DUST = 330

# BIP-341 "nothing up my sleeve" point H: no one knows its private key, so a
# seal can only be spent through its script leaf. Same key CRC-20 v1 used.
NUMS_X = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
TAPLEAF_VERSION = 0xC0


class DecodeError(ValueError):
    """Payload is malformed. A tx carrying one is a 'cenotaph'."""


# ───────────────────────────────────────────────────────────────── varints ──

def enc_varint(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint must be unsigned")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


class Reader:
    def __init__(self, data: bytes):
        self.b, self.i = data, 0

    def u8(self) -> int:
        if self.i >= len(self.b):
            raise DecodeError("truncated")
        v = self.b[self.i]
        self.i += 1
        return v

    def raw(self, n: int) -> bytes:
        if self.i + n > len(self.b):
            raise DecodeError("truncated")
        v = self.b[self.i:self.i + n]
        self.i += n
        return v

    def varint(self) -> int:
        shift = result = 0
        for idx in range(19):  # 19 * 7 = 133 bits, enough for u128
            byte = self.u8()
            result |= (byte & 0x7F) << shift
            if not byte & 0x80:
                if byte == 0 and idx > 0:
                    raise DecodeError("non-minimal varint")
                if result >= 1 << 128:
                    raise DecodeError("varint overflow")
                return result
            shift += 7
        raise DecodeError("varint too long")

    def tick(self) -> str:
        n = self.u8()
        if not 1 <= n <= 8:
            raise DecodeError("bad tick length")
        try:
            t = self.raw(n).decode("ascii")
        except UnicodeDecodeError as exc:
            raise DecodeError("bad tick") from exc
        if not TICK_RE.match(t):
            raise DecodeError("bad tick")
        return t

    def done(self):
        if self.i != len(self.b):
            raise DecodeError("trailing bytes")


def enc_tick(t: str) -> bytes:
    if not TICK_RE.match(t):
        raise ValueError(f"bad tick {t!r}")
    return bytes([len(t)]) + t.encode("ascii")


# ─────────────────────────────────────────────────────────────── ops (wire) ──

def _b32(x) -> bytes:
    b = bytes.fromhex(x) if isinstance(x, str) else bytes(x)
    if len(b) != 32:
        raise ValueError("expected a 32-byte x-only key")
    return b


def encode(op: dict) -> bytes:
    """dict -> payload bytes (goes in a single OP_RETURN push)."""
    kind = op["op"]
    if kind == "deploy":
        flags = (FLAG_AUTH if op.get("auth_vout") is not None else 0) | (
            FLAG_WINDOW if op.get("start") or op.get("end") else 0) | (
            FLAG_WALLET_CAP if op.get("wallet_cap") else 0)
        out = MAGIC + bytes([OP_DEPLOY, flags]) + enc_tick(op["tick"]) + bytes([op["dec"]]) + enc_varint(op["max"])
        mode = {"fixed": MODE_FIXED, "curve": MODE_CURVE, "fair": MODE_FAIR}[op["mode"]]
        out += bytes([mode])
        if mode == MODE_FIXED:
            out += enc_varint(op["rate"]) + enc_varint(op.get("cap", 0)) + enc_varint(op["treasury_vout"])
        elif mode == MODE_CURVE:
            out += enc_varint(op["p0"]) + enc_varint(op["p1"]) + enc_varint(op.get("cap", 0)) + enc_varint(op["treasury_vout"])
        else:
            out += enc_varint(op["lim"])
        if flags & FLAG_WINDOW:
            out += enc_varint(op.get("start", 0)) + enc_varint(op.get("end", 0))
        if flags & FLAG_AUTH:
            out += enc_varint(op["auth_vout"])
        if flags & FLAG_WALLET_CAP:
            out += enc_varint(op["wallet_cap"])
        return out
    if kind == "mint":
        out = MAGIC + bytes([OP_MINT]) + enc_tick(op["tick"]) + enc_varint(op["vout"]) + enc_varint(op.get("lock", 0))
        ext = (MINT_OWNER if op.get("owner") is not None else 0) | (MINT_PASS if op.get("pass") is not None else 0)
        if ext & MINT_PASS and not ext & MINT_OWNER:
            raise ValueError("an allowlist pass needs the owner key")
        if ext:
            out += bytes([ext]) + _b32(op["owner"])
            if ext & MINT_PASS:
                ps = op["pass"]
                sig = bytes.fromhex(ps["sig"]) if isinstance(ps["sig"], str) else ps["sig"]
                if len(sig) != 64:
                    raise ValueError("pass signature must be 64 bytes")
                out += enc_varint(ps["max"]) + enc_varint(ps["expiry"]) + sig
        return out
    if kind == "allowlist":
        return (MAGIC + bytes([OP_ALLOWLIST]) + enc_tick(op["tick"])
                + enc_varint(0 if op.get("next_auth") is None else op["next_auth"] + 1)
                + _b32(op["key"]) + enc_varint(op["price"]) + enc_varint(op["reserve"]) + enc_varint(op["end"]))
    if kind == "transfer":
        ticks = op["ticks"]  # [{"tick":..., "change": vout|None}]
        out = MAGIC + bytes([OP_TRANSFER, len(ticks)])
        for t in ticks:
            out += enc_tick(t["tick"]) + enc_varint(0 if t.get("change") is None else t["change"] + 1)
        out += enc_varint(len(op["edicts"]))
        for e in op["edicts"]:
            out += bytes([e["t"]]) + enc_varint(e["amt"]) + enc_varint(e["vout"]) + enc_varint(e.get("lock", 0))
        return out
    if kind == "burn":
        return (MAGIC + bytes([OP_BURN]) + enc_tick(op["tick"]) + enc_varint(op["amt"])
                + enc_varint(0 if op.get("change") is None else op["change"] + 1))
    if kind == "meta":
        out = MAGIC + bytes([OP_META]) + enc_tick(op["tick"]) + enc_varint(
            0 if op.get("next_auth") is None else op["next_auth"] + 1)
        for typ, val in op.get("fields", []):
            out += bytes([typ]) + enc_varint(len(val)) + val
        return out
    raise ValueError(f"unknown op {kind}")


def decode(payload: bytes) -> dict:
    """payload bytes -> dict. Raises DecodeError for anything non-canonical."""
    if not payload.startswith(MAGIC):
        raise DecodeError("no magic")
    r = Reader(payload[len(MAGIC):])
    code = r.u8()
    if code == OP_DEPLOY:
        flags = r.u8()
        if flags & ~(FLAG_AUTH | FLAG_WINDOW | FLAG_WALLET_CAP):
            raise DecodeError("unknown deploy flags")
        op = {"op": "deploy", "tick": r.tick(), "dec": r.u8(), "max": r.varint()}
        if op["dec"] > MAX_DECIMALS:
            raise DecodeError("too many decimals")
        mode = r.u8()
        if mode not in MODE_NAMES:
            raise DecodeError("unknown mode")
        op["mode"] = MODE_NAMES[mode]
        if mode == MODE_FIXED:
            op.update(rate=r.varint(), cap=r.varint(), treasury_vout=r.varint())
        elif mode == MODE_CURVE:
            op.update(p0=r.varint(), p1=r.varint(), cap=r.varint(), treasury_vout=r.varint())
        else:
            op["lim"] = r.varint()
        if flags & FLAG_WINDOW:
            op.update(start=r.varint(), end=r.varint())
        if flags & FLAG_AUTH:
            op["auth_vout"] = r.varint()
        if flags & FLAG_WALLET_CAP:
            op["wallet_cap"] = r.varint()
            if op["wallet_cap"] == 0:
                raise DecodeError("wallet cap flag with zero cap")
    elif code == OP_MINT:
        op = {"op": "mint", "tick": r.tick(), "vout": r.varint(), "lock": r.varint()}
        if r.i < len(r.b):
            ext = r.u8()
            if ext == 0 or ext & ~(MINT_OWNER | MINT_PASS) or (ext & MINT_PASS and not ext & MINT_OWNER):
                raise DecodeError("bad mint extension")
            op["owner"] = r.raw(32).hex()
            if ext & MINT_PASS:
                op["pass"] = {"max": r.varint(), "expiry": r.varint(), "sig": r.raw(64).hex()}
    elif code == OP_TRANSFER:
        n = r.u8()
        if not 1 <= n <= MAX_TICKS_PER_TRANSFER:
            raise DecodeError("bad tick count")
        ticks = []
        for _ in range(n):
            t, ch = r.tick(), r.varint()
            ticks.append({"tick": t, "change": None if ch == 0 else ch - 1})
        if len({t["tick"] for t in ticks}) != n:
            raise DecodeError("duplicate tick")
        edicts = []
        for _ in range(r.varint()):
            e = {"t": r.u8(), "amt": r.varint(), "vout": r.varint(), "lock": r.varint()}
            if e["t"] >= n:
                raise DecodeError("edict tick index out of range")
            edicts.append(e)
        op = {"op": "transfer", "ticks": ticks, "edicts": edicts}
    elif code == OP_BURN:
        t, amt, ch = r.tick(), r.varint(), r.varint()
        op = {"op": "burn", "tick": t, "amt": amt, "change": None if ch == 0 else ch - 1}
    elif code == OP_META:
        t, na = r.tick(), r.varint()
        fields = []
        while r.i < len(r.b):
            typ = r.u8()
            fields.append((typ, r.raw(r.varint())))
        op = {"op": "meta", "tick": t, "next_auth": None if na == 0 else na - 1, "fields": fields}
    elif code == OP_ALLOWLIST:
        t, na = r.tick(), r.varint()
        op = {"op": "allowlist", "tick": t, "next_auth": None if na == 0 else na - 1, "key": r.raw(32).hex(),
              "price": r.varint(), "reserve": r.varint(), "end": r.varint()}
    else:
        raise DecodeError("unknown op")
    r.done()
    if op.get("lock", 0) >= LOCKTIME_THRESHOLD or any(e["lock"] >= LOCKTIME_THRESHOLD for e in op.get("edicts", [])):
        raise DecodeError("lock must be a block height")
    return op


def op_return_script(payload: bytes) -> bytes:
    n = len(payload)
    if n <= 75:
        return b"\x6a" + bytes([n]) + payload
    if n <= 255:
        return b"\x6a\x4c" + bytes([n]) + payload
    return b"\x6a\x4d" + n.to_bytes(2, "little") + payload


def payload_from_script(spk: bytes) -> bytes | None:
    """Return the payload if spk is OP_RETURN <single push> starting with MAGIC."""
    if not spk or spk[0] != 0x6A:
        return None
    try:
        r = Reader(spk[1:])
        n = r.u8()
        if n <= 75:
            data = r.raw(n)
        elif n == 0x4C:
            data = r.raw(r.u8())
        elif n == 0x4D:
            data = r.raw(int.from_bytes(r.raw(2), "little"))
        else:
            return None
        r.done()
    except DecodeError:
        return None
    return data if data.startswith(MAGIC) else None


# ───────────────────────────────────────────────── hashing + secp256k1 bits ──

def tagged_hash(tag: str, msg: bytes) -> bytes:
    th = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(th + th + msg).digest()


def token_commitment(tick: str) -> bytes:
    return tagged_hash("TAPSEAL/token", tick.encode("ascii"))


def auth_commitment(tick: str) -> bytes:
    return tagged_hash("TAPSEAL/auth", tick.encode("ascii"))


_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % _P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, _P) % _P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, _P) % _P
    x = (lam * lam - a[0] - b[0]) % _P
    return x, (lam * (a[0] - x) - a[1]) % _P


def _mul(k, pt=_G):
    acc = None
    while k:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def _lift_x(xb: bytes):
    x = int.from_bytes(xb, "big")
    if x >= _P:
        raise ValueError("x out of range")
    y = pow((pow(x, 3, _P) + 7) % _P, (_P + 1) // 4, _P)
    if (y * y - pow(x, 3, _P) - 7) % _P:
        raise ValueError("not on curve")
    return x, y if y % 2 == 0 else _P - y


def bip340_verify(pubkey: bytes, msg: bytes, sig: bytes) -> bool:
    """BIP-340 Schnorr verification (reference algorithm, no external libraries)."""
    if len(pubkey) != 32 or len(msg) != 32 or len(sig) != 64:
        return False
    try:
        p = _lift_x(pubkey)
    except ValueError:
        return False
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    if r >= _P or s >= _N:
        return False
    e = int.from_bytes(tagged_hash("BIP0340/challenge", sig[:32] + pubkey + msg), "big") % _N
    neg_e_p = _mul(e, p)
    if neg_e_p is not None:
        neg_e_p = (neg_e_p[0], (_P - neg_e_p[1]) % _P)
    rr = _add(_mul(s), neg_e_p)
    return rr is not None and rr[1] % 2 == 0 and rr[0] == r


def bip340_sign(seckey: bytes, msg: bytes, aux: bytes = bytes(32)) -> bytes:
    """BIP-340 signing, for tests and the allowlist signer's reference. Production signing uses libsecp256k1."""
    d0 = int.from_bytes(seckey, "big")
    if not 0 < d0 < _N:
        raise ValueError("bad secret key")
    pt = _mul(d0)
    d = d0 if pt[1] % 2 == 0 else _N - d0
    px = pt[0].to_bytes(32, "big")
    t = (d ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), "big")).to_bytes(32, "big")
    k0 = int.from_bytes(tagged_hash("BIP0340/nonce", t + px + msg), "big") % _N
    if k0 == 0:
        raise ValueError("bad nonce")
    rp = _mul(k0)
    k = k0 if rp[1] % 2 == 0 else _N - k0
    e = int.from_bytes(tagged_hash("BIP0340/challenge", rp[0].to_bytes(32, "big") + px + msg), "big") % _N
    return rp[0].to_bytes(32, "big") + ((k + e * d) % _N).to_bytes(32, "big")


def xonly_pubkey(seckey: bytes) -> bytes:
    return _mul(int.from_bytes(seckey, "big"))[0].to_bytes(32, "big")


def pass_message(tick: str, owner_x: bytes, max_atoms: int, expiry: int) -> bytes:
    """What an allowlist signer signs: one wallet, one token, an allowance and an expiry height."""
    return tagged_hash("TAPSEAL/pass", enc_tick(tick) + owner_x + enc_varint(max_atoms) + enc_varint(expiry))


def _push_num(n: int) -> bytes:
    """Minimal script push of a CScriptNum (used for CLTV heights)."""
    if n == 0:
        return b"\x00"
    if 1 <= n <= 16:
        return bytes([0x50 + n])
    out = bytearray()
    while n:
        out.append(n & 0xFF)
        n >>= 8
    if out[-1] & 0x80:
        out.append(0)
    return bytes([len(out)]) + bytes(out)


# ─────────────────────────────────────────────────────────────────── seals ──

def seal_leaf(commitment: bytes, owner_x: bytes, lock: int = 0) -> bytes:
    """
    plain : <C> OP_DROP <owner> OP_CHECKSIG                          (= CRC-20 v1 shape)
    locked: <C> OP_DROP <lock> OP_CHECKLOCKTIMEVERIFY OP_DROP <owner> OP_CHECKSIG
    """
    assert len(commitment) == 32 and len(owner_x) == 32
    if lock:
        return b"\x20" + commitment + b"\x75" + _push_num(lock) + b"\xb1\x75" + b"\x20" + owner_x + b"\xac"
    return b"\x20" + commitment + b"\x75\x20" + owner_x + b"\xac"


def parse_leaf(script: bytes) -> dict | None:
    if len(script) == 68 and script[0] == 0x20 and script[33:35] == b"\x75\x20" and script[-1] == 0xAC:
        return {"commitment": script[1:33], "owner": script[35:67], "lock": 0}
    if len(script) > 70 and script[0] == 0x20 and script[33] == 0x75 and script[-34] == 0x20 and script[-1] == 0xAC \
            and script[-36:-34] == b"\xb1\x75":
        push = script[34:-36]
        if not push:
            return None
        if 0x51 <= push[0] <= 0x60 and len(push) == 1:
            lock = push[0] - 0x50
        elif push[0] == len(push) - 1 and 1 <= push[0] <= 5:
            lock = int.from_bytes(push[1:], "little")
        else:
            return None
        if _push_num(lock) != push:
            return None  # non-minimal push
        return {"commitment": script[1:33], "owner": script[-33:-1], "lock": lock}
    return None


def tapleaf_hash(script: bytes) -> bytes:
    n = len(script)
    size = bytes([n]) if n < 0xFD else b"\xfd" + n.to_bytes(2, "little")
    return tagged_hash("TapLeaf", bytes([TAPLEAF_VERSION]) + size + script)


def seal_output_key(leaf: bytes) -> bytes:
    """x-only output key Q for a single-leaf tree under the NUMS internal key."""
    p = _lift_x(NUMS_X)
    t = int.from_bytes(tagged_hash("TapTweak", NUMS_X + tapleaf_hash(leaf)), "big")
    if t >= _N:
        raise ValueError("bad tweak")
    q = _add(p, _mul(t))
    return q[0].to_bytes(32, "big")


def seal_spk(tick: str, owner_x: bytes, lock: int = 0, auth: bool = False) -> bytes:
    c = auth_commitment(tick) if auth else token_commitment(tick)
    return b"\x51\x20" + seal_output_key(seal_leaf(c, owner_x, lock))


def is_p2tr(spk: bytes) -> bool:
    return len(spk) == 34 and spk[:2] == b"\x51\x20"


def revealed_leaf(witness: list[bytes]) -> bytes | None:
    w = list(witness)
    if len(w) >= 2 and w[-1][:1] == b"\x50":
        w = w[:-1]  # drop annex
    if len(w) < 2:
        return None  # key-path spend: nothing revealed
    return w[-2]


# ─────────────────────────────────────────────────────────────── pricing ──

def isqrt(n: int) -> int:
    import math
    return math.isqrt(n)


def curve_atoms(paid_sats: int, minted: int, max_supply: int, dec: int, p0: int, p1: int) -> int:
    """
    Linear bonding curve. Price per whole token rises from p0 to p1 millisats
    as supply goes 0 -> max. Returns atoms bought for paid_sats starting at
    `minted`, rounded down (never gives more than was paid for).
    """
    if paid_sats <= 0:
        return 0
    c = paid_sats * 1000 * 10**dec           # budget in msat·atoms/token units
    d = p1 - p0
    b = p0 * max_supply + d * minted
    if d == 0:
        return c // p0
    return (isqrt(b * b + 2 * d * max_supply * c) - b) // d


def curve_cost_sats(atoms: int, minted: int, max_supply: int, dec: int, p0: int, p1: int) -> int:
    """Inverse helper for UIs: sats needed to buy `atoms` from `minted`, rounded up."""
    d = p1 - p0
    num = 2 * p0 * max_supply * atoms + d * (2 * minted * atoms + atoms * atoms)   # msat·10^dec·2max
    den = 2 * max_supply * 10**dec * 1000
    return -(-num // den)


def wl_active(tok, height: int) -> bool:
    return bool(tok.wl) and height <= tok.wl["end"]


def wl_reserve_left(tok, height: int) -> int:
    return max(0, tok.wl["reserve"] - tok.wl_minted) if wl_active(tok, height) else 0


def mint_amount(tok, paid: int, allowlist: bool = False) -> int:
    """Atoms bought for `paid` sats at the public price, or at the allowlist price. Before any clipping."""
    if tok.mode == "fair":
        return tok.params["lim"]
    cap = tok.params.get("cap", 0)
    counted = min(paid, cap) if cap else paid
    if tok.mode == "fixed":
        return counted * (tok.wl["price"] if allowlist else tok.params["rate"])
    if allowlist:  # curve: the payment counts as if it were bigger by the discount
        counted = counted * BPS // (BPS - tok.wl["price"])
    return curve_atoms(counted, tok.minted, tok.max, tok.dec, tok.params["p0"], tok.params["p1"])


# ────────────────────────────────────────────────────────────── replay state ──

@dataclass
class Token:
    tick: str
    dec: int
    max: int
    mode: str
    params: dict
    treasury_spk: bytes | None
    start: int
    end: int
    deploy_txid: str
    height: int
    minted: int = 0
    burned: int = 0
    lost: int = 0
    meta: dict = field(default_factory=dict)
    auth_outpoint: str | None = None
    id: str = ""              # "height:index" of the deploy transaction (rune-style token ID)
    wallet_cap: int = 0       # public atoms one owner key may mint in total, 0 = no limit
    wl: dict | None = None    # allowlist: {"key": hex, "price": int, "reserve": int, "end": int}
    wl_minted: int = 0        # atoms minted with allowlist passes


@dataclass
class Seal:
    outpoint: str
    tick: str
    amt: int
    lock: int
    spk: bytes
    height: int
    auth: bool = False


@dataclass
class State:
    tokens: dict = field(default_factory=dict)   # tick -> Token
    seals: dict = field(default_factory=dict)    # outpoint -> Seal
    usage: dict = field(default_factory=dict)    # (tick, "pub"|"wl", owner hex) -> atoms minted
    usage_before: dict = field(default_factory=dict)  # first value seen per touched key (indexer undo log)

    def used(self, tick: str, kind: str, owner: str) -> int:
        return self.usage.get((tick, kind, owner), 0)

    def add_usage(self, tick: str, kind: str, owner: str, amt: int):
        k = (tick, kind, owner)
        self.usage_before.setdefault(k, self.usage.get(k))
        self.usage[k] = self.usage.get(k, 0) + amt

    def balance(self, tick: str) -> int:
        return sum(s.amt for s in self.seals.values() if s.tick == tick and not s.auth)

    def root(self) -> str:
        h = hashlib.sha256()
        for op in sorted(self.seals):
            s = self.seals[op]
            h.update(f"{op}|{s.tick}|{s.amt}|{s.lock}|{int(s.auth)}|{s.spk.hex()}\n".encode())
        return h.hexdigest()


def apply_tx(state: State, tx: dict, height: int, index: int = 0) -> list[dict]:
    """
    tx = {"txid": hex, "vin": [{"prevout": "txid:n", "witness": [bytes,...]}],
          "vout": [{"value": sats, "spk": bytes}]}
    Mutates state, returns a list of events for logging / the API.
    """
    txid, vouts = tx["txid"], tx["vout"]
    events: list[dict] = []

    # 1. Spent seals -> per-tick input pools (only if the reveal checks out).
    pools: dict[str, int] = {}
    auth_spent: set[str] = set()
    spent_any = False
    for vin in tx["vin"]:
        seal = state.seals.pop(vin["prevout"], None)
        if seal is None:
            continue
        spent_any = True
        leaf = revealed_leaf(vin.get("witness", []))
        info = parse_leaf(leaf) if leaf else None
        want = auth_commitment(seal.tick) if seal.auth else token_commitment(seal.tick)
        ok = info is not None and info["commitment"] == want and info["lock"] == seal.lock \
            and seal_output_key(leaf) == seal.spk[2:]
        if not ok:
            tok = state.tokens[seal.tick]
            if seal.auth:
                tok.auth_outpoint = None
                events.append(ev(txid, "lost-auth", seal.tick, 0, "authority seal spent without a valid reveal"))
            else:
                tok.lost += seal.amt
                events.append(ev(txid, "lost", seal.tick, seal.amt, "seal spent without a valid reveal"))
            continue
        if seal.auth:
            auth_spent.add(seal.tick)
        else:
            pools[seal.tick] = pools.get(seal.tick, 0) + seal.amt

    # 2. Find the payload: first OP_RETURN that starts with MAGIC.
    op_idx, op, err = None, None, None
    for i, o in enumerate(vouts):
        payload = payload_from_script(o["spk"])
        if payload is not None:
            op_idx = i
            try:
                op = decode(payload)
            except DecodeError as exc:
                err = str(exc)
            break

    taken: dict[int, tuple[str, int]] = {}   # vout -> (tick, lock) already assigned in this tx

    def new_seal(vout: int, tick: str, amt: int, lock: int, auth: bool = False) -> bool:
        if vout >= len(vouts) or vout == op_idx or not is_p2tr(vouts[vout]["spk"]):
            return False
        prev = taken.get(vout)
        if prev is not None and (prev != (tick, lock) or auth):
            return False
        key = f"{txid}:{vout}"
        if key in state.seals:
            state.seals[key].amt += amt
        else:
            state.seals[key] = Seal(key, tick, amt, lock, vouts[vout]["spk"], height, auth)
        taken[vout] = (tick, lock) if not auth else ("#auth", -1)
        return True

    def burn_pools(reason: str):
        for t, amt in pools.items():
            if amt:
                state.tokens[t].lost += amt
                events.append(ev(txid, "lost", t, amt, reason))
        for t in auth_spent:
            state.tokens[t].auth_outpoint = None
            events.append(ev(txid, "lost-auth", t, 0, reason))
        pools.clear()
        auth_spent.clear()

    if err is not None:
        events.append(ev(txid, "cenotaph", None, 0, err))
        burn_pools("cenotaph: " + err)
        return events
    if op is None:
        if spent_any:
            burn_pools("seal spent by a tx with no TAPSEAL payload")
        return events

    kind = op["op"]

    # 3. Ops.
    if kind == "deploy":
        burn_pools("seals spent into a deploy")
        t = op["tick"]
        why = None
        if t in state.tokens:
            why = "tick already deployed"
        elif op["max"] <= 0:
            why = "max must be > 0"
        elif op["mode"] == "fixed" and op["rate"] <= 0:
            why = "rate must be > 0"
        elif op["mode"] == "curve" and not (0 < op["p0"] <= op["p1"]):
            why = "curve needs 0 < p0 <= p1"
        elif op["mode"] == "fair" and not (0 < op["lim"] <= op["max"]):
            why = "lim must be in (0, max]"
        elif op.get("end") and op["end"] < op.get("start", 0):
            why = "end before start"
        tre = None
        if why is None and op["mode"] in ("fixed", "curve"):
            tv = op["treasury_vout"]
            if tv >= len(vouts) or tv == op_idx:
                why = "treasury vout missing"
            else:
                tre = vouts[tv]["spk"]
        if why is None and op.get("wallet_cap", 0) > op["max"]:
            why = "wallet cap above max supply"
        if why is None and "auth_vout" in op:
            av = op["auth_vout"]
            if av >= len(vouts) or av == op_idx or not is_p2tr(vouts[av]["spk"]) or (tre is not None and av == op["treasury_vout"]):
                why = "auth vout must be a separate P2TR output"
        if why:
            events.append(ev(txid, "invalid", t, 0, why, op="deploy"))
            return events
        params = {k: op[k] for k in ("rate", "cap", "p0", "p1", "lim") if k in op}
        tok = Token(t, op["dec"], op["max"], op["mode"], params, tre, op.get("start", 0), op.get("end", 0), txid, height,
                    id=f"{height}:{index}", wallet_cap=op.get("wallet_cap", 0))
        state.tokens[t] = tok
        if "auth_vout" in op:
            new_seal(op["auth_vout"], t, 0, 0, auth=True)
            tok.auth_outpoint = f"{txid}:{op['auth_vout']}"
        events.append(ev(txid, "deploy", t, 0, f"{op['mode']} mode, max {op['max']}"))
        return events

    if kind == "mint":
        burn_pools("seals spent into a mint")
        t = op["tick"]
        tok = state.tokens.get(t)
        why = None
        if tok is None:
            why = "unknown tick"
        elif tok.start and height < tok.start:
            why = f"mint window opens at {tok.start}"
        elif tok.end and height > tok.end:
            why = f"mint window closed at {tok.end}"
        elif tok.minted >= tok.max:
            why = "sold out"
        if why:
            events.append(ev(txid, "invalid", t, 0, why, op="mint"))
            return events
        def bad(reason):
            events.append(ev(txid, "invalid", t, 0, reason, op="mint"))
            return events
        owner, ps = op.get("owner"), op.get("pass")
        if owner is not None:
            # the named key must be the one inside the new seal, so limits and passes follow real ownership
            if op["vout"] >= len(vouts) or vouts[op["vout"]]["spk"] != seal_spk(t, bytes.fromhex(owner), op["lock"]):
                return bad("seal does not belong to the named owner key")
        paid = 0 if tok.mode == "fair" else sum(
            o["value"] for i, o in enumerate(vouts) if o["spk"] == tok.treasury_spk and i != op["vout"])
        reserve_left = wl_reserve_left(tok, height)
        kind_used = None
        if ps is not None:
            if not wl_active(tok, height):
                return bad("allowlist phase is not active")
            if height > ps["expiry"]:
                return bad(f"allowlist pass expired at {ps['expiry']}")
            if not bip340_verify(bytes.fromhex(tok.wl["key"]), pass_message(t, bytes.fromhex(owner), ps["max"], ps["expiry"]),
                                 bytes.fromhex(ps["sig"])):
                return bad("allowlist pass signature is not valid")
            pass_left = ps["max"] - state.used(t, "wl", owner)
            if pass_left <= 0:
                return bad("allowlist allowance already used")
            amt = min(mint_amount(tok, paid, allowlist=True), pass_left, reserve_left, tok.max - tok.minted)
            if reserve_left <= 0:
                return bad("allowlist reserve is used up")
            kind_used = "wl"
        else:
            if tok.wallet_cap and owner is None:
                return bad("this token limits mints per wallet, so the mint must name its owner key")
            available = tok.max - tok.minted - reserve_left
            if available <= 0:
                return bad(f"remaining supply is reserved for the allowlist until block {tok.wl['end']}")
            amt = min(mint_amount(tok, paid), available)
            if tok.wallet_cap:
                left = tok.wallet_cap - state.used(t, "pub", owner)
                if left <= 0:
                    return bad("wallet mint limit reached")
                amt = min(amt, left)
                kind_used = "pub"
        if amt <= 0:
            return bad("nothing paid to treasury" if not paid and tok.mode != "fair" else "amount rounds to zero")
        if op["vout"] < len(vouts) and vouts[op["vout"]]["spk"] == tok.treasury_spk:
            return bad("seal cannot be the treasury output")
        if not new_seal(op["vout"], t, amt, op["lock"]):
            return bad("seal vout must be a P2TR output")
        tok.minted += amt
        if kind_used:
            state.add_usage(t, kind_used, owner, amt)
        if kind_used == "wl":
            tok.wl_minted += amt
        events.append(ev(txid, "mint", t, amt, f"paid {paid} sats" + (" with an allowlist pass" if ps else "")
                         + (f", locked to {op['lock']}" if op["lock"] else "")))
        return events

    if kind == "transfer":
        # auth seals can't ride along in a transfer
        for t in list(auth_spent):
            state.tokens[t].auth_outpoint = None
            events.append(ev(txid, "lost-auth", t, 0, "authority seal spent into a transfer"))
        auth_spent.clear()
        ticks = [x["tick"] for x in op["ticks"]]
        for e in op["edicts"]:
            t = ticks[e["t"]]
            amt = min(e["amt"], pools.get(t, 0))
            if amt <= 0:
                continue
            if new_seal(e["vout"], t, amt, e["lock"]):
                pools[t] -= amt
                events.append(ev(txid, "transfer", t, amt, f"-> vout {e['vout']}" + (f" locked to {e['lock']}" if e["lock"] else "")))
        for x in op["ticks"]:
            t, left = x["tick"], pools.get(x["tick"], 0)
            if left and x["change"] is not None and new_seal(x["change"], t, left, 0):
                events.append(ev(txid, "change", t, left, f"-> vout {x['change']}"))
                pools[t] = 0
        burn_pools("unallocated balance")
        return events

    if kind == "burn":
        for t in list(auth_spent):
            state.tokens[t].auth_outpoint = None
            events.append(ev(txid, "lost-auth", t, 0, "authority seal spent into a burn"))
        auth_spent.clear()
        t = op["tick"]
        amt = min(op["amt"], pools.get(t, 0))
        if amt:
            state.tokens[t].burned += amt
            pools[t] -= amt
            events.append(ev(txid, "burn", t, amt, "burned"))
        left = pools.get(t, 0)
        if left and op["change"] is not None and new_seal(op["change"], t, left, 0):
            events.append(ev(txid, "change", t, left, f"-> vout {op['change']}"))
            pools[t] = 0
        burn_pools("unallocated balance")
        return events

    if kind == "meta":
        t = op["tick"]
        tok = state.tokens.get(t)
        if tok is None or t not in auth_spent:
            events.append(ev(txid, "invalid", t, 0, "meta must spend the token's authority seal", op="meta"))
            burn_pools("seals spent into an invalid meta")
            return events
        auth_spent.discard(t)
        burn_pools("seals spent into a meta")
        names = {META_NAME: "name", META_IMAGE_SHA256: "image_sha256", META_URL: "url", META_DESC: "desc"}
        for typ, val in op["fields"]:
            if typ in names:
                tok.meta[names[typ]] = val.hex() if typ == META_IMAGE_SHA256 else val.decode("utf-8", "replace")
        if op["next_auth"] is not None and new_seal(op["next_auth"], t, 0, 0, auth=True):
            tok.auth_outpoint = f"{txid}:{op['next_auth']}"
        else:
            tok.auth_outpoint = None
        events.append(ev(txid, "meta", t, 0, "authority renounced" if tok.auth_outpoint is None else "metadata updated"))
        return events

    if kind == "allowlist":
        t = op["tick"]
        tok = state.tokens.get(t)
        if tok is None or t not in auth_spent:
            events.append(ev(txid, "invalid", t, 0, "allowlist must spend the token's authority seal", op="allowlist"))
            burn_pools("seals spent into an invalid allowlist")
            return events
        auth_spent.discard(t)
        burn_pools("seals spent into an allowlist")
        why = None
        if op["end"] and op["end"] < height:
            why = "allowlist end is in the past"
        elif op["end"] and op["reserve"] > tok.max - tok.minted + tok.wl_minted:
            why = "reserve is larger than the unminted supply"
        elif op["end"] and tok.mode == "fixed" and op["price"] <= tok.params["rate"]:
            why = "allowlist price must give more tokens per sat than the public rate"
        elif op["end"] and tok.mode == "curve" and not 0 < op["price"] < BPS:
            why = "curve discount must be between 1 and 9999 basis points"
        elif op["end"] and tok.mode == "fair" and op["price"] != 0:
            why = "fair launches have no allowlist price"
        elif op["end"]:
            try:
                _lift_x(bytes.fromhex(op["key"]))
            except ValueError:
                why = "allowlist key is not a valid x-only public key"
        # authority always continues to next_auth, so a bad setting never costs the creator the authority seal
        if op["next_auth"] is not None and new_seal(op["next_auth"], t, 0, 0, auth=True):
            tok.auth_outpoint = f"{txid}:{op['next_auth']}"
        else:
            tok.auth_outpoint = None
        if why:
            events.append(ev(txid, "invalid", t, 0, why, op="allowlist"))
            return events
        if op["end"] == 0:
            tok.wl = None
            events.append(ev(txid, "allowlist", t, 0, "allowlist closed"))
        else:
            tok.wl = {"key": op["key"], "price": op["price"], "reserve": op["reserve"], "end": op["end"]}
            events.append(ev(txid, "allowlist", t, 0, f"allowlist until {op['end']}, reserve {op['reserve']}"))
        return events

    return events


def ev(txid, kind, tick, amt, detail, op=None):
    return {"txid": txid, "kind": kind, "tick": tick, "amt": amt, "detail": detail, **({"op": op} if op else {})}


# ───────────────────────────────────────────── bitcoind getblock adapter ──

def tx_from_rpc(t: dict) -> dict:
    """Convert a `getblock <hash> 2` transaction into apply_tx's shape."""
    return {
        "txid": t["txid"],
        "vin": [
            {"prevout": f"{v['txid']}:{v['vout']}", "witness": [bytes.fromhex(w) for w in v.get("txinwitness", [])]}
            for v in t.get("vin", []) if "txid" in v
        ],
        "vout": [
            {"value": int(round(float(o["value"]) * 100_000_000)), "spk": bytes.fromhex(o["scriptPubKey"]["hex"])}
            for o in t.get("vout", [])
        ],
    }


def apply_block(state: State, block: dict) -> list[dict]:
    out = []
    for i, t in enumerate(block.get("tx", [])):
        out += apply_tx(state, tx_from_rpc(t), block["height"], i)
    return out
