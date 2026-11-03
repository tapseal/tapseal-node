#!/usr/bin/env python3
"""Run: python3 test_tapseal.py   (writes vectors.json next to this file on success)"""
import json
import unittest
from pathlib import Path

import tapseal as c


def xonly(priv: int) -> bytes:
    return c._mul(priv)[0].to_bytes(32, "big")


ALICE, BOB, CAROL, DEV = xonly(11), xonly(22), xonly(33), xonly(44)
TREASURY_SPK = b"\x51\x20" + xonly(99)
_n = 0


def txid():
    global _n
    _n += 1
    return f"{_n:064x}"


def p2tr(x):  # plain wallet output, NOT a seal
    return b"\x51\x20" + x


def opret(op):
    return {"value": 0, "spk": c.op_return_script(c.encode(op))}


def spend(outpoint, tick, owner, lock=0, auth=False, sig=b"\x01" * 64):
    com = c.auth_commitment(tick) if auth else c.token_commitment(tick)
    return {"prevout": outpoint, "witness": [sig, c.seal_leaf(com, owner, lock), b"\xc0" + c.NUMS_X]}


def deploy_fixed(st, tick="STONK", h=100, **kw):
    t = txid()
    op = {"op": "deploy", "tick": tick, "dec": 8, "max": 21_000_000 * 10**8, "mode": "fixed",
          "rate": 10_000, "cap": 150_000, "treasury_vout": 1, "auth_vout": 2, **kw}
    c.apply_tx(st, {"txid": t, "vin": [], "vout": [opret(op), {"value": 330, "spk": TREASURY_SPK},
                                                   {"value": 330, "spk": c.seal_spk(tick, DEV, auth=True)}]}, h)
    return t


def mint(st, tick, owner, paid, h=101, lock=0):
    t = txid()
    ev = c.apply_tx(st, {"txid": t, "vin": [], "vout": [
        opret({"op": "mint", "tick": tick, "vout": 1, "lock": lock}),
        {"value": 330, "spk": c.seal_spk(tick, owner, lock)},
        {"value": paid, "spk": TREASURY_SPK}]}, h)
    return t, ev


class Codec(unittest.TestCase):
    def test_roundtrip_all_ops(self):
        ops = [
            {"op": "deploy", "tick": "STONK", "dec": 8, "max": 2_100_000_000_000_000, "mode": "fixed", "rate": 10000, "cap": 150000, "treasury_vout": 1, "auth_vout": 2},
            {"op": "deploy", "tick": "CURVE", "dec": 8, "max": 10**15, "mode": "curve", "p0": 500, "p1": 3000, "cap": 0, "treasury_vout": 1, "start": 900000, "end": 905000},
            {"op": "deploy", "tick": "FAIR", "dec": 0, "max": 1_000_000, "mode": "fair", "lim": 1000},
            {"op": "mint", "tick": "STONK", "vout": 1, "lock": 0},
            {"op": "mint", "tick": "STONK", "vout": 1, "lock": 950000},
            {"op": "transfer", "ticks": [{"tick": "STONK", "change": 4}], "edicts": [{"t": 0, "amt": 5 * 10**8, "vout": 1, "lock": 0}, {"t": 0, "amt": 7 * 10**8, "vout": 2, "lock": 0}, {"t": 0, "amt": 10**8, "vout": 3, "lock": 960000}]},
            {"op": "burn", "tick": "STONK", "amt": 10**8, "change": 1},
            {"op": "meta", "tick": "STONK", "next_auth": 1, "fields": [(1, b"Stonk"), (3, b"https://x.y")]},
        ]
        for op in ops:
            d = c.decode(c.encode(op))
            for k, v in op.items():
                self.assertEqual(d.get(k, v), v, (op["op"], k))

    def test_size_vs_v1(self):
        v1 = b'{"p":"crc-20","op":"mint","tick":"STONK","to":"' + b"a" * 64 + b'"}'
        v2 = c.encode({"op": "mint", "tick": "STONK", "vout": 1})
        self.assertLess(len(v2), 16)
        self.assertGreater(len(v1), 100)
        batch = c.encode({"op": "transfer", "ticks": [{"tick": "STONK", "change": 9}],
                          "edicts": [{"t": 0, "amt": 1000 * 10**8, "vout": i, "lock": 0} for i in range(1, 8)]})
        self.assertLessEqual(len(batch), 80, "7-recipient airdrop must fit the classic 80-byte OP_RETURN")

    def test_rejects_noncanonical(self):
        good = c.encode({"op": "mint", "tick": "STONK", "vout": 1})
        for bad in [good + b"\x00", good[:-1] + b"\x80\x00", b"TSL1\x09", b"TSL1\x02\x05stonk\x01\x00",
                    c.MAGIC + b"\x02\x05STONK\x01" + c.enc_varint(600_000_000)]:
            with self.assertRaises(c.DecodeError):
                c.decode(bad)

    def test_leaf_parse(self):
        com = c.token_commitment("STONK")
        for lock in (0, 5, 16, 17, 127, 128, 255, 256, 950000):
            leaf = c.seal_leaf(com, ALICE, lock)
            self.assertEqual(c.parse_leaf(leaf), {"commitment": com, "owner": ALICE, "lock": lock})
        self.assertEqual(len(c.seal_leaf(com, ALICE)), 68)  # v1-compatible shape


class Curve(unittest.TestCase):
    def test_monotonic_and_inverse(self):
        mx, dec, p0, p1 = 21_000_000 * 10**8, 8, 500, 3000
        a1 = c.curve_atoms(100_000, 0, mx, dec, p0, p1)
        a2 = c.curve_atoms(100_000, mx // 2, mx, dec, p0, p1)
        self.assertGreater(a1, a2)  # later buyers get less
        self.assertLess(a1, 100_000 * 1000 * 10**8 // p0)
        self.assertGreater(a1, 100_000 * 1000 * 10**8 // p1)
        cost = c.curve_cost_sats(a2, mx // 2, mx, dec, p0, p1)
        self.assertLessEqual(cost, 100_000)
        self.assertGreaterEqual(cost, 99_999)

    def test_flat_curve_equals_fixed(self):
        self.assertEqual(c.curve_atoms(1000, 0, 10**12, 8, 1000, 1000), 1000 * 10**8)


class Replay(unittest.TestCase):
    def test_fixed_mint_and_cap(self):
        st = c.State()
        deploy_fixed(st)
        _, ev = mint(st, "STONK", ALICE, 200_000)
        self.assertEqual(ev[-1]["kind"], "mint")
        self.assertEqual(st.balance("STONK"), 150_000 * 10_000)  # capped at 150k sats

    def test_duplicate_deploy_and_window(self):
        st = c.State()
        deploy_fixed(st, start=200, end=300)
        deploy_fixed(st)  # dup
        _, ev = mint(st, "STONK", ALICE, 1000, h=150)
        self.assertIn("opens", ev[-1]["detail"])
        _, ev = mint(st, "STONK", ALICE, 1000, h=301)
        self.assertIn("closed", ev[-1]["detail"])
        _, ev = mint(st, "STONK", ALICE, 1000, h=250)
        self.assertEqual(ev[-1]["kind"], "mint")

    def test_partial_fill_at_sellout(self):
        st = c.State()
        deploy_fixed(st, tick="TINY", max=15_000, rate=10, cap=0)
        mint(st, "TINY", ALICE, 1000)
        _, ev = mint(st, "TINY", BOB, 1000)
        self.assertEqual(ev[-1]["amt"], 5_000)
        self.assertEqual(st.tokens["TINY"].minted, 15_000)
        _, ev = mint(st, "TINY", BOB, 1000)
        self.assertEqual(ev[-1]["detail"], "sold out")

    def test_batch_transfer_with_change_and_lock(self):
        st = c.State()
        deploy_fixed(st)
        m, _ = mint(st, "STONK", ALICE, 100_000)
        total = st.balance("STONK")
        t = txid()
        ev = c.apply_tx(st, {"txid": t, "vin": [spend(f"{m}:1", "STONK", ALICE)], "vout": [
            opret({"op": "transfer", "ticks": [{"tick": "STONK", "change": 3}],
                   "edicts": [{"t": 0, "amt": 100, "vout": 1, "lock": 0},
                              {"t": 0, "amt": 200, "vout": 2, "lock": 500}]}),
            {"value": 330, "spk": c.seal_spk("STONK", BOB)},
            {"value": 330, "spk": c.seal_spk("STONK", CAROL, 500)},
            {"value": 330, "spk": c.seal_spk("STONK", ALICE)}]}, 110)
        self.assertEqual([e["kind"] for e in ev], ["transfer", "transfer", "change"])
        self.assertEqual(st.balance("STONK"), total)
        self.assertEqual(st.seals[f"{t}:2"].lock, 500)
        # Carol spends her locked seal revealing an UNLOCKED leaf -> lost
        e2 = c.apply_tx(st, {"txid": txid(), "vin": [spend(f"{t}:2", "STONK", CAROL)], "vout": [
            opret({"op": "transfer", "ticks": [{"tick": "STONK", "change": None}], "edicts": [{"t": 0, "amt": 200, "vout": 1, "lock": 0}]}),
            {"value": 330, "spk": c.seal_spk("STONK", CAROL)}]}, 600)
        self.assertEqual(e2[0]["kind"], "lost")
        # Bob spends correctly, sends everything to Carol
        e3 = c.apply_tx(st, {"txid": txid(), "vin": [spend(f"{t}:1", "STONK", BOB)], "vout": [
            opret({"op": "transfer", "ticks": [{"tick": "STONK", "change": None}], "edicts": [{"t": 0, "amt": 10**30, "vout": 1, "lock": 0}]}),
            {"value": 330, "spk": c.seal_spk("STONK", CAROL)}]}, 600)
        self.assertEqual(e3[0]["amt"], 100)  # overdraw is clamped

    def test_unallocated_is_lost_and_conservation(self):
        st = c.State()
        deploy_fixed(st)
        m, _ = mint(st, "STONK", ALICE, 1000)
        before = st.balance("STONK")
        c.apply_tx(st, {"txid": txid(), "vin": [spend(f"{m}:1", "STONK", ALICE)], "vout": [
            opret({"op": "transfer", "ticks": [{"tick": "STONK", "change": None}], "edicts": [{"t": 0, "amt": 1, "vout": 1, "lock": 0}]}),
            {"value": 330, "spk": c.seal_spk("STONK", BOB)}]}, 120)
        tok = st.tokens["STONK"]
        self.assertEqual(st.balance("STONK") + tok.lost + tok.burned, before)
        self.assertEqual(st.balance("STONK"), 1)

    def test_no_payload_or_keypath_spend_loses(self):
        st = c.State()
        deploy_fixed(st)
        m, _ = mint(st, "STONK", ALICE, 1000)
        ev = c.apply_tx(st, {"txid": txid(), "vin": [{"prevout": f"{m}:1", "witness": [b"\x01" * 64]}],
                             "vout": [{"value": 1000, "spk": p2tr(ALICE)}]}, 130)
        self.assertEqual(ev[0]["kind"], "lost")
        self.assertEqual(st.balance("STONK"), 0)

    def test_burn(self):
        st = c.State()
        deploy_fixed(st)
        m, _ = mint(st, "STONK", ALICE, 1000)
        bal = st.balance("STONK")
        c.apply_tx(st, {"txid": txid(), "vin": [spend(f"{m}:1", "STONK", ALICE)], "vout": [
            opret({"op": "burn", "tick": "STONK", "amt": 400, "change": 1}),
            {"value": 330, "spk": c.seal_spk("STONK", ALICE)}]}, 140)
        self.assertEqual(st.tokens["STONK"].burned, 400)
        self.assertEqual(st.balance("STONK"), bal - 400)

    def test_meta_requires_authority(self):
        st = c.State()
        d = deploy_fixed(st)
        ev = c.apply_tx(st, {"txid": txid(), "vin": [], "vout": [opret({"op": "meta", "tick": "STONK", "fields": [(1, b"fake")]})]}, 150)
        self.assertEqual(ev[0]["kind"], "invalid")
        t = txid()
        c.apply_tx(st, {"txid": t, "vin": [spend(f"{d}:2", "STONK", DEV, auth=True)], "vout": [
            opret({"op": "meta", "tick": "STONK", "next_auth": 1, "fields": [(1, b"Stonk Corp"), (3, b"https://stonk20.xyz")]}),
            {"value": 330, "spk": c.seal_spk("STONK", DEV, auth=True)}]}, 151)
        self.assertEqual(st.tokens["STONK"].meta["name"], "Stonk Corp")
        self.assertEqual(st.tokens["STONK"].auth_outpoint, f"{t}:1")
        c.apply_tx(st, {"txid": txid(), "vin": [spend(f"{t}:1", "STONK", DEV, auth=True)], "vout": [
            opret({"op": "meta", "tick": "STONK", "fields": []})]}, 152)
        self.assertIsNone(st.tokens["STONK"].auth_outpoint)  # renounced

    def test_fair_and_curve(self):
        st = c.State()
        c.apply_tx(st, {"txid": txid(), "vin": [], "vout": [opret({"op": "deploy", "tick": "FREE", "dec": 0, "max": 2500, "mode": "fair", "lim": 1000})]}, 100)
        for who in (ALICE, BOB, CAROL):
            c.apply_tx(st, {"txid": txid(), "vin": [], "vout": [opret({"op": "mint", "tick": "FREE", "vout": 1}), {"value": 330, "spk": c.seal_spk("FREE", who)}]}, 101)
        self.assertEqual(st.tokens["FREE"].minted, 2500)
        c.apply_tx(st, {"txid": txid(), "vin": [], "vout": [opret({"op": "deploy", "tick": "BOND", "dec": 8, "max": 10**15, "mode": "curve", "p0": 500, "p1": 3000, "treasury_vout": 1}), {"value": 330, "spk": TREASURY_SPK}]}, 100)
        _, e1 = mint(st, "BOND", ALICE, 50_000)
        _, e2 = mint(st, "BOND", BOB, 50_000)
        self.assertGreater(e1[-1]["amt"], e2[-1]["amt"])

    def test_cenotaph_burns_inputs(self):
        st = c.State()
        deploy_fixed(st)
        m, _ = mint(st, "STONK", ALICE, 1000)
        ev = c.apply_tx(st, {"txid": txid(), "vin": [spend(f"{m}:1", "STONK", ALICE)],
                             "vout": [{"value": 0, "spk": c.op_return_script(b"TSL1\x03\x00")}]}, 160)
        self.assertEqual([e["kind"] for e in ev], ["cenotaph", "lost"])


WL_SK = (77).to_bytes(32, "big")
WL_KEY = c.xonly_pubkey(WL_SK)


def owner_mint(st, tick, owner, paid, h=101, lock=0, ps=None, name=True, seal_owner=None):
    t = txid()
    op = {"op": "mint", "tick": tick, "vout": 1, "lock": lock}
    if name:
        op["owner"] = owner.hex()
    if ps:
        op["pass"] = ps
    ev = c.apply_tx(st, {"txid": t, "vin": [], "vout": [
        opret(op), {"value": 330, "spk": c.seal_spk(tick, seal_owner or owner, lock)},
        {"value": paid, "spk": TREASURY_SPK}]}, h)
    return t, ev


def make_pass(tick, owner, mx, expiry, sk=WL_SK):
    return {"max": mx, "expiry": expiry, "sig": c.bip340_sign(sk, c.pass_message(tick, owner, mx, expiry)).hex()}


def allowlist(st, tick, auth_outpoint, h=102, price=20_000, reserve=10**15, end=200, key=WL_KEY, owner=DEV):
    t = txid()
    op = {"op": "allowlist", "tick": tick, "next_auth": 1, "key": key.hex(), "price": price, "reserve": reserve, "end": end}
    ev = c.apply_tx(st, {"txid": t, "vin": [spend(auth_outpoint, tick, owner, auth=True)], "vout": [
        opret(op), {"value": 330, "spk": c.seal_spk(tick, owner, auth=True)}]}, h)
    return t, ev


class V11(unittest.TestCase):
    def test_schnorr_sign_verify(self):
        m = c.tagged_hash("x", b"msg")
        sig = c.bip340_sign(WL_SK, m)
        self.assertTrue(c.bip340_verify(WL_KEY, m, sig))
        self.assertFalse(c.bip340_verify(WL_KEY, c.tagged_hash("x", b"msh"), sig))
        self.assertFalse(c.bip340_verify(ALICE, m, sig))

    def test_codec_new_fields(self):
        ps = make_pass("STONK", ALICE, 5 * 10**12, 300)
        for op in [{"op": "deploy", "tick": "LIM", "dec": 0, "max": 1000, "mode": "fair", "lim": 10, "wallet_cap": 30},
                   {"op": "mint", "tick": "STONK", "vout": 1, "lock": 0, "owner": ALICE.hex()},
                   {"op": "mint", "tick": "STONK", "vout": 1, "lock": 0, "owner": ALICE.hex(), "pass": ps},
                   {"op": "allowlist", "tick": "STONK", "next_auth": 1, "key": WL_KEY.hex(), "price": 20000, "reserve": 10**15, "end": 900}]:
            self.assertEqual(c.decode(c.encode(op)), op)
        base = c.encode({"op": "mint", "tick": "STONK", "vout": 1, "lock": 0})
        for bad in (base + b"\x00", base + b"\x02" + ALICE + b"\x01\x01" + b"\x00" * 64, base + b"\x05" + ALICE, base + b"\x01" + ALICE[:31]):
            with self.assertRaises(c.DecodeError):
                c.decode(bad)
        self.assertLessEqual(len(c.encode({"op": "mint", "tick": "STONK", "vout": 1, "owner": ALICE.hex()})), 80)

    def test_token_id_from_block_position(self):
        st = c.State()
        t = txid()
        op = {"op": "deploy", "tick": "IDX", "dec": 0, "max": 100, "mode": "fair", "lim": 1}
        c.apply_tx(st, {"txid": t, "vin": [], "vout": [opret(op)]}, 871204, 12)
        self.assertEqual(st.tokens["IDX"].id, "871204:12")

    def test_wallet_cap(self):
        st = c.State()
        deploy_fixed(st, wallet_cap=15_000 * 10_000)   # 15,000 sats worth per wallet
        _, ev = mint(st, "STONK", ALICE, 1000)          # no owner named: rejected
        self.assertEqual(ev[-1]["kind"], "invalid")
        _, ev = owner_mint(st, "STONK", ALICE, 10_000)
        self.assertEqual(ev[-1]["amt"], 10_000 * 10_000)
        _, ev = owner_mint(st, "STONK", ALICE, 10_000)  # only 5,000 sats of allowance left
        self.assertEqual(ev[-1]["amt"], 5_000 * 10_000)
        _, ev = owner_mint(st, "STONK", ALICE, 10_000)
        self.assertEqual((ev[-1]["kind"], ev[-1]["detail"]), ("invalid", "wallet mint limit reached"))
        _, ev = owner_mint(st, "STONK", BOB, 1_000)    # another wallet is unaffected
        self.assertEqual(ev[-1]["kind"], "mint")
        _, ev = owner_mint(st, "STONK", CAROL, 1_000, seal_owner=BOB)  # named key must own the seal
        self.assertEqual(ev[-1]["detail"], "seal does not belong to the named owner key")

    def test_allowlist_phase(self):
        st = c.State()
        d = deploy_fixed(st, max=10**15, cap=0)
        tok = st.tokens["STONK"]
        reserve = 4 * 10**14
        _, ev = allowlist(st, "STONK", f"{d}:2", reserve=reserve, end=200)
        self.assertEqual(ev[-1]["kind"], "allowlist")
        self.assertEqual(tok.auth_outpoint.split(":")[1], "1")
        # public can only take the unreserved part
        _, ev = owner_mint(st, "STONK", BOB, 10**11)
        self.assertEqual(ev[-1]["amt"], 10**15 - reserve)
        _, ev = owner_mint(st, "STONK", BOB, 1000, name=False)
        self.assertIn("reserved for the allowlist", ev[-1]["detail"])
        # allowlist mint: cheaper price, allowance, reserve
        ps = make_pass("STONK", ALICE, 3 * 10**14, 190)
        _, ev = owner_mint(st, "STONK", ALICE, 10**10, ps=ps, h=150)
        self.assertEqual(ev[-1]["amt"], 10**10 * 20_000)              # wl price 20,000 atoms/sat vs 10,000
        _, ev = owner_mint(st, "STONK", ALICE, 10**10, ps=ps, h=150)
        self.assertEqual(ev[-1]["amt"], 3 * 10**14 - 2 * 10**14)       # clipped to the pass allowance
        _, ev = owner_mint(st, "STONK", ALICE, 1, ps=ps, h=150)
        self.assertEqual(ev[-1]["detail"], "allowlist allowance already used")
        # stolen pass: tokens could only go to ALICE's own seal
        _, ev = owner_mint(st, "STONK", ALICE, 1, ps=ps, h=150, seal_owner=CAROL)
        self.assertEqual(ev[-1]["kind"], "invalid")
        forged = make_pass("STONK", CAROL, 10**14, 190, sk=(5).to_bytes(32, "big"))
        _, ev = owner_mint(st, "STONK", CAROL, 1000, ps=forged, h=150)
        self.assertEqual(ev[-1]["detail"], "allowlist pass signature is not valid")
        late = make_pass("STONK", BOB, 10**14, 160)
        _, ev = owner_mint(st, "STONK", BOB, 1000, ps=late, h=170)
        self.assertIn("expired", ev[-1]["detail"])
        # after the phase ends the rest of the reserve opens to everyone
        _, ev = owner_mint(st, "STONK", BOB, 10**11, h=201)
        self.assertEqual(ev[-1]["amt"], reserve - 3 * 10**14)
        self.assertEqual(tok.minted, tok.max)

    def test_allowlist_needs_authority_and_valid_price(self):
        st = c.State()
        d = deploy_fixed(st)
        _, ev = allowlist(st, "STONK", f"{d}:2", price=5_000)          # worse than public: rejected, authority kept
        self.assertEqual(ev[-1]["kind"], "invalid")
        self.assertIsNone(st.tokens["STONK"].wl)
        self.assertIsNotNone(st.tokens["STONK"].auth_outpoint)
        t = txid()
        ev = c.apply_tx(st, {"txid": t, "vin": [], "vout": [opret({"op": "allowlist", "tick": "STONK", "next_auth": None,
                         "key": WL_KEY.hex(), "price": 20000, "reserve": 1, "end": 500})]}, 103)
        self.assertEqual(ev[-1]["detail"], "allowlist must spend the token's authority seal")

    def test_curve_discount(self):
        st = c.State()
        t = txid()
        op = {"op": "deploy", "tick": "BOND", "dec": 8, "max": 10**15, "mode": "curve", "p0": 500, "p1": 3000, "cap": 0,
              "treasury_vout": 1, "auth_vout": 2}
        c.apply_tx(st, {"txid": t, "vin": [], "vout": [opret(op), {"value": 330, "spk": TREASURY_SPK},
                                                       {"value": 330, "spk": c.seal_spk("BOND", DEV, auth=True)}]}, 100)
        allowlist(st, "BOND", f"{t}:2", price=2000, reserve=10**14, end=300)
        _, ev = owner_mint(st, "BOND", ALICE, 80_000, ps=make_pass("BOND", ALICE, 10**14, 300), h=150)
        self.assertEqual(ev[-1]["amt"], c.curve_atoms(100_000, 0, 10**15, 8, 500, 3000))  # 20% off: 80k pays like 100k


def write_vectors():
    com = c.token_commitment("STONK")
    vec = {
        "nums_internal_key": c.NUMS_X.hex(),
        "owner_xonly": ALICE.hex(),
        "token_commitment_STONK": com.hex(),
        "auth_commitment_STONK": c.auth_commitment("STONK").hex(),
        "seal": [], "payloads": [],
    }
    for lock in (0, 950000):
        leaf = c.seal_leaf(com, ALICE, lock)
        vec["seal"].append({"lock": lock, "leaf": leaf.hex(), "output_key": c.seal_output_key(leaf).hex()})
    for op in [
        {"op": "deploy", "tick": "STONK", "dec": 8, "max": 2_100_000_000_000_000, "mode": "fixed", "rate": 10000, "cap": 150000, "treasury_vout": 1, "auth_vout": 2},
        {"op": "deploy", "tick": "BOND", "dec": 8, "max": 10**15, "mode": "curve", "p0": 500, "p1": 3000, "cap": 0, "treasury_vout": 1, "start": 900000, "end": 905000},
        {"op": "deploy", "tick": "FREE", "dec": 0, "max": 1_000_000, "mode": "fair", "lim": 1000},
        {"op": "mint", "tick": "STONK", "vout": 1, "lock": 0},
        {"op": "mint", "tick": "STONK", "vout": 1, "lock": 950000},
        {"op": "transfer", "ticks": [{"tick": "STONK", "change": 4}], "edicts": [{"t": 0, "amt": 500000000, "vout": 1, "lock": 0}, {"t": 0, "amt": 700000000, "vout": 2, "lock": 0}, {"t": 0, "amt": 100000000, "vout": 3, "lock": 960000}]},
        {"op": "burn", "tick": "STONK", "amt": 100000000, "change": 1},
    ]:
        vec["payloads"].append({"op": op, "hex": c.encode(op).hex()})
    ps = {"max": 5 * 10**12, "expiry": 300, "sig": c.bip340_sign((77).to_bytes(32, "big"), c.pass_message("STONK", ALICE, 5 * 10**12, 300)).hex()}
    vec["allowlist"] = {"signer_secret": "00" * 31 + "4d", "signer_xonly": c.xonly_pubkey((77).to_bytes(32, "big")).hex(),
                        "tick": "STONK", "owner": ALICE.hex(), "max": ps["max"], "expiry": ps["expiry"],
                        "message": c.pass_message("STONK", ALICE, ps["max"], ps["expiry"]).hex(), "sig": ps["sig"]}
    for op in [
        {"op": "deploy", "tick": "LIM", "dec": 0, "max": 1_000_000, "mode": "fair", "lim": 100, "wallet_cap": 500},
        {"op": "mint", "tick": "STONK", "vout": 1, "lock": 0, "owner": ALICE.hex()},
        {"op": "mint", "tick": "STONK", "vout": 1, "lock": 0, "owner": ALICE.hex(), "pass": ps},
        {"op": "allowlist", "tick": "STONK", "next_auth": 1, "key": vec["allowlist"]["signer_xonly"], "price": 20000, "reserve": 10**15, "end": 900000},
    ]:
        vec["payloads"].append({"op": op, "hex": c.encode(op).hex()})
    vec["curve"] = {"paid_sats": 100000, "minted": 0, "max": 2_100_000_000_000_000, "dec": 8, "p0": 500, "p1": 3000,
                    "atoms": c.curve_atoms(100000, 0, 2_100_000_000_000_000, 8, 500, 3000)}
    Path(__file__).with_name("vectors.json").write_text(json.dumps(vec, indent=2) + "\n")


if __name__ == "__main__":
    res = unittest.main(exit=False, verbosity=1).result
    if res.wasSuccessful():
        write_vectors()
        print("vectors.json written")
