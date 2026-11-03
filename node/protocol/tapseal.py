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
OP_DEPLOY, OP_MINT, OP_TRANSFER, OP_BURN, OP_META, OP_ALLOWLIST, OP_OPERATOR = 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
OP_NAMES = {OP_DEPLOY: "deploy", OP_MINT: "mint", OP_TRANSFER: "transfer", OP_BURN: "burn", OP_META: "meta",
            OP_ALLOWLIST: "allowlist", OP_OPERATOR: "operator"}

MODE_FIXED, MODE_CURVE, MODE_FAIR, MODE_LOTS = 0, 1, 2, 3
MODE_NAMES = {MODE_FIXED: "fixed", MODE_CURVE: "curve", MODE_FAIR: "fair", MODE_LOTS: "lots"}

FLAG_AUTH = 0x01      # deploy creates an authority seal
FLAG_WINDOW = 0x02    # deploy carries start/end block heights
FLAG_POW = 0x08      # opt-in proof-of-work mint policy for new deployments
FLAG_WALLET_CAP = 0x04  # deploy carries a per-wallet public mint limit (atoms)

MINT_OPERATOR = 0x08
MINT_POW = 0x04      # anchor height/hash and uint64 nonce; requires owner
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
            FLAG_WALLET_CAP if op.get("wallet_cap") else 0) | (FLAG_POW if op.get("pow") is not None else 0)
        out = MAGIC + bytes([OP_DEPLOY, flags]) + enc_tick(op["tick"]) + bytes([op["dec"]]) + enc_varint(op["max"])
        mode = {"fixed": MODE_FIXED, "curve": MODE_CURVE, "fair": MODE_FAIR, "lots": MODE_LOTS}[op["mode"]]
        out += bytes([mode])
        if mode == MODE_FIXED:
            out += enc_varint(op["rate"]) + enc_varint(op.get("cap", 0)) + enc_varint(op["treasury_vout"])
        elif mode == MODE_CURVE:
            out += enc_varint(op["p0"]) + enc_varint(op["p1"]) + enc_varint(op.get("cap", 0)) + enc_varint(op["treasury_vout"])
        elif mode == MODE_LOTS:
            if op.get("profile",1)!=1: raise ValueError("unsupported lot profile")
            out += bytes([1]) + enc_varint(op["treasury_vout"])
        else:
            out += enc_varint(op["lim"])
        if flags & FLAG_WINDOW:
            out += enc_varint(op.get("start", 0)) + enc_varint(op.get("end", 0))
        if flags & FLAG_AUTH:
            out += enc_varint(op["auth_vout"])
        if flags & FLAG_WALLET_CAP:
            out += enc_varint(op["wallet_cap"])
        if flags & FLAG_POW:
            bits, age = pow_config(op["pow"])
            out += bytes([2, bits]) + enc_varint(age)
        return compact_payload(out) if op.get("pow") else out
    if kind == "mint":
        out = MAGIC + bytes([OP_MINT]) + enc_tick(op["tick"]) + enc_varint(op["vout"]) + enc_varint(op.get("lock", 0))
        ext = (MINT_OWNER if op.get("owner") is not None else 0) | (MINT_PASS if op.get("pass") is not None else 0) | (MINT_POW if op.get("proof") is not None else 0) | (MINT_OPERATOR if op.get("operator") else 0)
        if ext & (MINT_PASS | MINT_POW | MINT_OPERATOR) and not ext & MINT_OWNER:
            raise ValueError("an allowlist pass needs the owner key")
        if ext:
            out += bytes([ext]) + _b32(op["owner"])
            if ext & MINT_PASS:
                ps = op["pass"]
                sig = bytes.fromhex(ps["sig"]) if isinstance(ps["sig"], str) else ps["sig"]
                if len(sig) != 64:
                    raise ValueError("pass signature must be 64 bytes")
                out += enc_varint(ps["max"]) + enc_varint(ps["expiry"]) + sig
        if ext & MINT_POW:
            proof = op['proof']
            nonce = int(proof['nonce'])
            if not 0 <= nonce < 2**64: raise ValueError('PoW nonce exceeds uint64')
            out += enc_varint(proof['height']) + nonce.to_bytes(8,'little')
        if ext & MINT_POW:
            if ext & MINT_PASS: raise ValueError("compact work uses on-chain operator approval, not signed passes")
            return compact_payload(out)
        if ext & MINT_OPERATOR: raise ValueError("operator mint requires work")
        return out
    if kind == "operator":
        return compact_payload(MAGIC + bytes([OP_OPERATOR]) + enc_tick(op['tick']) + enc_varint(op['next_auth']+1) + _b32(op['owner']) + enc_varint(op['max']) + enc_varint(op['expiry']))
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
        if flags & ~(FLAG_AUTH | FLAG_WINDOW | FLAG_WALLET_CAP | FLAG_POW):
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
        elif mode == MODE_LOTS:
            op.update(profile=r.u8(),treasury_vout=r.varint())
            if op["profile"]!=1: raise DecodeError("unsupported lot profile")
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
        if flags & FLAG_POW:
            version, bits, age = r.u8(), r.u8(), r.varint()
            try: pow_config({'version':version,'bits':bits,'max_age':age})
            except ValueError as e: raise DecodeError(str(e)) from e
            op['pow'] = {'version':version,'bits':bits,'max_age':age}
    elif code == OP_MINT:
        op = {"op": "mint", "tick": r.tick(), "vout": r.varint(), "lock": r.varint()}
        if r.i < len(r.b):
            ext = r.u8()
            if ext == 0 or ext & ~(MINT_OWNER | MINT_PASS | MINT_POW | MINT_OPERATOR) or (ext & (MINT_PASS | MINT_POW | MINT_OPERATOR) and not ext & MINT_OWNER):
                raise DecodeError("bad mint extension")
            op["owner"] = r.raw(32).hex()
            if ext & MINT_PASS:
                op["pass"] = {"max": r.varint(), "expiry": r.varint(), "sig": r.raw(64).hex()}
            if ext & MINT_OPERATOR:
                if not ext & MINT_POW: raise DecodeError("operator mint requires work")
                op["operator"] = True
            if ext & MINT_POW:
                if ext & MINT_PASS: raise DecodeError("signed passes are not compact work")
                op['proof'] = {'height':r.varint(),'nonce':str(int.from_bytes(r.raw(8),'little'))}
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
    elif code == OP_OPERATOR:
        t, na = r.tick(), r.varint()
        if na == 0: raise DecodeError('operator update must retain authority')
        op = {'op':'operator','tick':t,'next_auth':na-1,'owner':r.raw(32).hex(),'max':r.varint(),'expiry':r.varint()}
    elif code == OP_ALLOWLIST:
        t, na = r.tick(), r.varint()
        op = {"op": "allowlist", "tick": t, "next_auth": None if na == 0 else na - 1, "key": r.raw(32).hex(),
              "price": r.varint(), "reserve": r.varint(), "end": r.varint()}
    else:
        raise DecodeError("unknown op")
    r.done()
    if ('pow' in op or 'proof' in op or op['op']=='operator' or op.get('mode')=='lots') and len(payload)>80: raise DecodeError('compact payload exceeds 80 bytes')
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


def lot_params():
    return {'profile':1,'lot':1000*10**8,'public_price':700,'operator_price':450,'min_lots':1,'max_lots':10,'cap':7000}

def lot_amount(paid,discount=False):
    price=450 if discount else 700
    if type(paid) is not int or paid%price or not 1<=paid//price<=10:return 0
    return paid//price*(1000*10**8)

def mint_amount(tok, paid: int, allowlist: bool = False) -> int:
    """Atoms bought for `paid` sats at the public price, or at the allowlist price. Before any clipping."""
    if tok.mode == "lots":return lot_amount(paid,allowlist)
    if tok.mode == "fair":
        return tok.params["lim"]
    cap = tok.params.get("cap", 0)
    counted = min(paid, cap) if cap else paid
    if tok.mode == "fixed":
        return counted * (tok.wl["price"] if allowlist else tok.params["rate"])
    if allowlist:  # curve: the payment counts as if it were bigger by the discount
        counted = counted * BPS // (BPS - tok.wl["price"])
    return curve_atoms(counted, tok.minted, tok.max, tok.dec, tok.params["p0"], tok.params["p1"])


# PoW v1: an issuance predicate, not Bitcoin mining or proof of node operation.
def compact_payload(data):
    if len(data)>80: raise ValueError('compact payload exceeds 80 bytes')
    return data

def pow_config(cfg):
    if cfg.get('version',2) != 2: raise ValueError('unsupported PoW version')
    bits, age = cfg.get('bits'), cfg.get('max_age',144)
    if type(bits) is not int or not 8 <= bits <= 28: raise ValueError('PoW bits must be 8..28')
    if type(age) is not int or not 6 <= age <= 144: raise ValueError('PoW max_age must be 6..144 blocks')
    return bits, age

def pow_prefix(network, tok, owner, height, blockhash, paid, lock=0):
    if network not in ('mainnet','testnet3','regtest','signet','testnet4'): raise ValueError('PoW network is unavailable')
    if len(owner)!=32 or len(bytes.fromhex(blockhash))!=32: raise ValueError('bad PoW owner/anchor')
    if not 0 <= paid <= 21000000*100000000 or not 0 <= height < 2**32 or not 0 <= lock < 500000000: raise ValueError('bad PoW payment/height')
    return (b'TAPSEAL/POW/v2\x00'+network.encode()+b'\x00'+bytes.fromhex(tok.deploy_txid)+enc_tick(tok.tick)+owner+
            height.to_bytes(4,'little')+bytes.fromhex(blockhash)+paid.to_bytes(8,'little')+lock.to_bytes(4,'little'))

def pow_digest(network,tok,owner,proof,paid,lock=0):
    nonce=int(proof['nonce'])
    if not 0 <= nonce < 2**64: raise ValueError('bad PoW nonce')
    return hashlib.sha256(pow_prefix(network,tok,owner,proof['height'],proof['hash'],paid,lock)+nonce.to_bytes(8,'little')).digest()

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
    pow: dict | None = None   # immutable opt-in mint work policy
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
    network: str | None = None
    pow_activation: int | None = None
    pow_anchors: dict = field(default_factory=dict)
    lot_activation: int | None = None

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
                if op.get('mode')=='lots' and (state.lot_activation is None or height<state.lot_activation):raise DecodeError('Lot profile is not activated')
                if ('pow' in op or 'proof' in op or op.get('op')=='operator') and (state.pow_activation is None or height < state.pow_activation):
                    raise DecodeError('PoW extension is not activated on this network')
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
        if why is None and op.get('pow') and op['mode'] not in ('fair','lots') and not 546 <= op.get('cap',0) <= 21000000*100000000:
            why='paid PoW tokens require a per-mint payment cap of at least 546 sats'
        if why is None and op['mode']=='lots' and (op['dec']!=8 or op['max']!=21000000*10**8 or not op.get('pow') or op.get('wallet_cap',0) or 'auth_vout' not in op):
            why='lot profile 1 requires 21M tokens, 8 decimals, work settings and no custom wallet cap'
        tre = None
        if why is None and op["mode"] in ("fixed", "curve", "lots"):
            tv = op["treasury_vout"]
            if tv >= len(vouts) or tv == op_idx:
                why = "treasury vout missing"
            else:
                tre = vouts[tv]["spk"]
        if why is None and op['mode']=='lots' and not is_p2tr(tre):why='lot treasury must be Taproot'
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
        if op['mode']=='lots':params=lot_params()
        tok = Token(t, op["dec"], op["max"], op["mode"], params, tre, op.get("start", 0), op.get("end", 0), txid, height,
                    id=f"{height}:{index}", wallet_cap=op.get("wallet_cap", 0), pow=op.get("pow"))
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
        proof_key = None
        if tok.pow and (tok.mode!='lots' or op.get('operator')):
            if tok.mode!='fair' and paid>tok.params['cap']: return bad('PoW payment exceeds the per-mint cap')
            proof = op.get('proof')
            if owner is None or not proof: return bad('this mint requires an owner-bound PoW proof')
            try:
                bits, age = pow_config(tok.pow)
                if not tok.height <= proof['height'] < height <= proof['height']+age: return bad('PoW anchor expired or is not an ancestor')
                anchor = state.pow_anchors.get(proof['height'])
                if not anchor: return bad('PoW anchor is not a known canonical block')
                proof = {**proof, 'hash':anchor}
                digest = pow_digest(state.network,tok,bytes.fromhex(owner),proof,paid,op.get('lock',0))
                if int.from_bytes(digest,'big') >= 1 << (256-bits): return bad('PoW hash does not meet target')
                proof_key = digest.hex()
                if state.used(t,'pow',proof_key): return bad('PoW proof already used')
            except (ValueError,KeyError,OverflowError,TypeError): return bad('invalid PoW context')
        elif op.get('proof') is not None: return bad('legacy token does not accept PoW extensions')
        if tok.mode=='lots':
            if state.lot_activation is None or height<state.lot_activation:return bad('lot profile not activated')
            if owner is None:return bad('lot mint must name its receiving owner')
            if ps is not None:return bad('lot discounts require on-chain operator approval, not signed passes')
            discount=bool(op.get('operator'))
            amt=lot_amount(paid,discount)
            if not amt:return bad('pay exactly 700 sats per public lot or 450 per approved proof lot; choose 1..10 lots')
            if tok.minted+amt>tok.max:return bad('insufficient remaining whole lots; no partial fill')
            if discount:
                if state.used(t,'op-expiry',owner)<height or state.used(t,'op-max',owner)-state.used(t,'wl',owner)<amt:return bad('operator approval expired, missing or allowance insufficient')
            if op['vout']<len(vouts) and vouts[op['vout']]['spk']==tok.treasury_spk:return bad('seal cannot be treasury')
            if not new_seal(op['vout'],t,amt,op['lock']):return bad('seal vout must be P2TR')
            if proof_key:state.add_usage(t,'pow',proof_key,1)
            if discount:state.add_usage(t,'wl',owner,amt);tok.wl_minted+=amt
            tok.minted+=amt
            events.append(ev(txid,'mint',t,amt,f"paid {paid} sats"+(' with operator work' if discount else ' public lot mint')))
            return events
        if op.get('operator'):
            if not tok.pow: return bad('operator approval requires a compact work token')
            if ps is not None: return bad('operator approval cannot carry a signed pass')
            ps = {'max':state.used(t,'op-max',owner), 'expiry':state.used(t,'op-expiry',owner), 'registered':True}
            if ps['max'] <= 0: return bad('operator wallet is not approved on chain')
        reserve_left = wl_reserve_left(tok, height)
        kind_used = None
        if ps is not None:
            if not wl_active(tok, height):
                return bad("allowlist phase is not active")
            if height > ps["expiry"]:
                return bad(f"allowlist pass expired at {ps['expiry']}")
            if not ps.get("registered") and not bip340_verify(bytes.fromhex(tok.wl["key"]), pass_message(t, bytes.fromhex(owner), ps["max"], ps["expiry"]),
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
        if proof_key: state.add_usage(t,'pow',proof_key,1)
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

    if kind == "operator":
        t = op['tick']; tok = state.tokens.get(t)
        if tok is None or not tok.pow or t not in auth_spent:
            events.append(ev(txid,'invalid',t,0,'operator update must spend the compact token authority seal',op='operator'))
            burn_pools('seals spent into an invalid operator update'); return events
        auth_spent.discard(t); burn_pools('seals spent into an operator update')
        if not new_seal(op['next_auth'],t,0,0,auth=True):
            tok.auth_outpoint=None
            events.append(ev(txid,'invalid',t,0,'operator update must re-create authority',op='operator')); return events
        tok.auth_outpoint=f"{txid}:{op['next_auth']}"
        if (tok.mode=='lots' and op['max']%lot_params()['lot']) or op['max'] > tok.max or op['expiry'] >= 2**32 or (op['max'] > 0 and op['expiry'] < height):
            events.append(ev(txid,'invalid',t,0,'operator quota or expiry is invalid',op='operator')); return events
        try: _lift_x(bytes.fromhex(op['owner']))
        except ValueError:
            events.append(ev(txid,'invalid',t,0,'invalid operator owner key',op='operator')); return events
        for kind_,value in [('op-max',op['max']),('op-expiry',op['expiry'])]:
            state.add_usage(t,kind_,op['owner'],value-state.used(t,kind_,op['owner']))
        events.append(ev(txid,'operator',t,0,'operator quota updated on chain')); return events

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
        if tok.mode=="lots":
            why = "lot prices are immutable; use operator approvals without a price phase"
        elif tok.pow and len(payload)>80:
            why = "compact allowlist payload exceeds 80 bytes"
        elif op["end"] and op["end"] < height:
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
    if block.get('hash'): state.pow_anchors[block['height']] = block['hash']
    state.pow_anchors = {h:v for h,v in state.pow_anchors.items() if h >= block['height']-144}
    return out
