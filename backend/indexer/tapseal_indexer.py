#!/usr/bin/env python3
"""
TAPSEAL indexer.

Replays confirmed blocks from a Bitcoin JSON-RPC endpoint (Chainstack or your own node)
through the reference rules in ../protocol/tapseal.py and keeps the result in SQLite:

  tokens, seals, events, blocks   confirmed state (what balances are)
  undo                             per-block pre-images, so a reorg can be rolled back
  mempool                          unconfirmed TAPSEAL transactions (a separate view, never mixed in)
  node                             telemetry for the API and the console (sync, latency, fees, load)

Only this process writes confirmed state. The API reads the same file (WAL mode) and may insert
into `mempool` when it broadcasts a transaction, so the mempool view updates instantly.

Usage:
  export BITCOIN_RPC_URL=...  BITCOIN_RPC_USER=...  BITCOIN_RPC_PASSWORD=...   (or BITCOIN_RPC_BEARER)
  python3 tapseal_indexer.py --db tapseal.sqlite follow --start <activation height>
  python3 tapseal_indexer.py --db tapseal.sqlite status
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "protocol"))
import tapseal as T  # noqa: E402

UNDO_DEPTH = 24          # blocks of undo kept for reorgs (spec requires >= 6)
DEFAULT_MEMPOOL_BUDGET = 150   # getrawtransaction calls per mempool scan


# ───────────────────────────────────────────────────────────────── RPC ──

from persistent_rpc import Rpc  # bounded HTTP attempts and rate limiting

SCHEMA = """
pragma journal_mode=wal;
create table if not exists meta   (key text primary key, value text);
create table if not exists blocks (height integer primary key, hash text not null, prev text, time integer,
                                   ntx integer, nops integer, replay_ms integer, root text);
create table if not exists tokens (tick text primary key, json text not null);
create table if not exists seals  (outpoint text primary key, tick text not null, amt text not null, lock integer not null,
                                   auth integer not null, spk text not null, height integer not null);
create index if not exists seals_spk on seals(spk);
create index if not exists seals_tick on seals(tick);
create table if not exists events (id integer primary key autoincrement, height integer not null, txid text not null,
                                   kind text not null, tick text, amt text, detail text, op text);
create index if not exists events_height on events(height);
create index if not exists events_txid on events(txid);
create table if not exists undo   (height integer not null, kind text not null, key text not null, before text);
create index if not exists undo_height on undo(height);
create table if not exists mempool (txid text primary key, seen integer not null, kind text, tick text, op text,
                                    error text, fee_rate real, vsize integer, bytes integer, source text, paid integer);
create table if not exists node   (key text primary key, value text);
create table if not exists usage  (tick text not null, kind text not null, owner text not null, atoms text not null,
                                   primary key (tick, kind, owner));
"""


def jsonable(x):
    if isinstance(x, bytes):
        return x.hex()
    if isinstance(x, int) and not isinstance(x, bool) and abs(x) > 2 ** 53:
        return str(x)
    if isinstance(x, dict):
        return {k: jsonable(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [jsonable(v) for v in x]
    return x


def tok_json(t: T.Token) -> str:
    d = dataclasses.asdict(t)
    d["treasury_spk"] = t.treasury_spk.hex() if t.treasury_spk else None
    for k in ("max", "minted", "burned", "lost"):
        d[k] = str(d[k])
    d["params"] = {k: str(v) for k, v in t.params.items()}
    d["wallet_cap"] = str(t.wallet_cap)
    d["wl_minted"] = str(t.wl_minted)
    if t.wl:
        d["wl"] = {**t.wl, "price": str(t.wl["price"]), "reserve": str(t.wl["reserve"])}
    return json.dumps(d, sort_keys=True)


def tok_load(s: str) -> T.Token:
    d = json.loads(s)
    d["treasury_spk"] = bytes.fromhex(d["treasury_spk"]) if d["treasury_spk"] else None
    for k in ("max", "minted", "burned", "lost"):
        d[k] = int(d[k])
    d["params"] = {k: int(v) for k, v in d["params"].items()}
    d["wallet_cap"] = int(d.get("wallet_cap", 0))
    d["wl_minted"] = int(d.get("wl_minted", 0))
    if d.get("wl"):
        d["wl"] = {**d["wl"], "price": int(d["wl"]["price"]), "reserve": int(d["wl"]["reserve"]), "end": int(d["wl"]["end"])}
    return T.Token(**d)


def seal_json(s: T.Seal | None):
    if s is None:
        return None
    return json.dumps({"outpoint": s.outpoint, "tick": s.tick, "amt": str(s.amt), "lock": s.lock,
                       "spk": s.spk.hex(), "height": s.height, "auth": s.auth})


def seal_load(s: str) -> T.Seal:
    d = json.loads(s)
    return T.Seal(d["outpoint"], d["tick"], int(d["amt"]), d["lock"], bytes.fromhex(d["spk"]), d["height"], d["auth"])


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, timeout=30, isolation_level=None)
        self.db.executescript(SCHEMA)
        cols = {r[1] for r in self.db.execute("pragma table_info(mempool)")}
        if "paid" not in cols:  # databases from before the paid column
            self.db.execute("alter table mempool add column paid integer")

    # state ----------------------------------------------------------------
    def load_state(self) -> T.State:
        st = T.State()
        for (j,) in self.db.execute("select json from tokens"):
            t = tok_load(j)
            st.tokens[t.tick] = t
        for op, tick, amt, lock, auth, spk, h in self.db.execute("select outpoint,tick,amt,lock,auth,spk,height from seals"):
            st.seals[op] = T.Seal(op, tick, int(amt), lock, bytes.fromhex(spk), h, bool(auth))
        for tick, kind, owner, atoms in self.db.execute("select tick, kind, owner, atoms from usage"):
            st.usage[(tick, kind, owner)] = int(atoms)
        return st

    def _put_usage(self, key, atoms):
        if atoms is None:
            self.db.execute("delete from usage where tick=? and kind=? and owner=?", key)
        else:
            self.db.execute("insert or replace into usage values(?,?,?,?)", (*key, str(atoms)))

    def tip(self):
        return self.db.execute("select height, hash from blocks order by height desc limit 1").fetchone()

    def hash_at(self, h):
        r = self.db.execute("select hash from blocks where height=?", (h,)).fetchone()
        return r[0] if r else None

    def _put_seal(self, key, s: T.Seal | None):
        if s is None:
            self.db.execute("delete from seals where outpoint=?", (key,))
        else:
            self.db.execute("insert or replace into seals values(?,?,?,?,?,?,?)",
                            (key, s.tick, str(s.amt), s.lock, int(s.auth), s.spk.hex(), s.height))

    # apply / rollback --------------------------------------------------------
    def apply_block(self, st: T.State, block: dict) -> list[dict]:
        h = block["height"]
        txs = block.get("tx", [])
        before_seals = {}
        for t in txs:
            for v in t.get("vin", []):
                if "txid" in v:
                    k = f"{v['txid']}:{v['vout']}"
                    if k in st.seals:
                        before_seals[k] = dataclasses.replace(st.seals[k])
        created = [f"{t['txid']}:{i}" for t in txs for i in range(len(t.get("vout", [])))]
        before_tokens = {k: tok_json(v) for k, v in st.tokens.items()}

        t0 = time.time()
        st.usage_before.clear()
        events = T.apply_block(st, block)
        replay_ms = round((time.time() - t0) * 1000)

        db = self.db
        db.execute("begin immediate")
        try:
            for k, prev in before_seals.items():
                now = st.seals.get(k)
                self._put_seal(k, now)
                db.execute("insert into undo values(?,?,?,?)", (h, "seal", k, seal_json(prev)))
            for k in created:
                if k in st.seals and k not in before_seals:
                    self._put_seal(k, st.seals[k])
                    db.execute("insert into undo values(?,?,?,?)", (h, "seal", k, None))
            for tick, t in st.tokens.items():
                j = tok_json(t)
                if before_tokens.get(tick) != j:
                    db.execute("insert or replace into tokens values(?,?)", (tick, j))
                    db.execute("insert into undo values(?,?,?,?)", (h, "token", tick, before_tokens.get(tick)))
            for key, prev in st.usage_before.items():
                self._put_usage(key, st.usage.get(key))
                db.execute("insert into undo values(?,?,?,?)", (h, "usage", json.dumps(list(key)), None if prev is None else str(prev)))
            st.usage_before.clear()
            nops = 0
            for e in events:
                if e["kind"] in ("deploy", "mint", "transfer", "burn", "meta", "allowlist", "invalid", "cenotaph"):
                    nops += 1
                db.execute("insert into events(height,txid,kind,tick,amt,detail,op) values(?,?,?,?,?,?,?)",
                           (h, e["txid"], e["kind"], e.get("tick"), str(e.get("amt", 0)), e.get("detail"), e.get("op")))
            db.execute("insert or replace into blocks values(?,?,?,?,?,?,?,?)",
                       (h, block["hash"], block.get("previousblockhash"), block.get("time"), len(txs), nops, replay_ms, st.root()))
            confirmed = [t["txid"] for t in txs]
            for i in range(0, len(confirmed), 500):
                chunk = confirmed[i:i + 500]
                db.execute(f"delete from mempool where txid in ({','.join('?' * len(chunk))})", chunk)
            db.execute("delete from undo where height < ?", (h - UNDO_DEPTH,))
            db.execute("commit")
        except Exception:
            db.execute("rollback")
            raise
        return events

    def rollback_tip(self, st: T.State) -> int:
        """Undo the highest stored block. Returns the new tip height."""
        h, _ = self.tip()
        rows = self.db.execute("select kind, key, before from undo where height=? order by rowid desc", (h,)).fetchall()
        if not rows and self.db.execute("select count(*) from events where height=?", (h,)).fetchone()[0]:
            raise RuntimeError(f"no undo data for block {h}; reindex from an earlier height")
        db = self.db
        db.execute("begin immediate")
        try:
            for kind, key, before in rows:
                if kind == "usage":
                    k = tuple(json.loads(key))
                    self._put_usage(k, int(before) if before is not None else None)
                    if before is None:
                        st.usage.pop(k, None)
                    else:
                        st.usage[k] = int(before)
                    continue
                if kind == "seal":
                    s = seal_load(before) if before else None
                    self._put_seal(key, s)
                    if s:
                        st.seals[key] = s
                    else:
                        st.seals.pop(key, None)
                else:
                    if before:
                        restored = tok_load(before);current = st.tokens.get(key)
                        if not restored.id and current and current.deploy_txid == restored.deploy_txid:restored.id = current.id
                        st.tokens[key] = restored
                        db.execute("insert or replace into tokens values(?,?)", (key, tok_json(restored)))
                    else:
                        st.tokens.pop(key, None)
                        db.execute("delete from tokens where tick=?", (key,))
            db.execute("delete from undo where height=?", (h,))
            db.execute("delete from events where height=?", (h,))
            db.execute("delete from blocks where height=?", (h,))
            db.execute("commit")
        except Exception:
            db.execute("rollback")
            raise
        return h - 1

    # mempool + telemetry ---------------------------------------------------
    def put_node(self, **kv):
        self.db.execute("begin immediate")
        for k, v in kv.items():
            self.db.execute("insert or replace into node values(?,?)", (k, json.dumps(v)))
        self.db.execute("commit")


# ──────────────────────────────────────────────────────────── mempool ──

def mempool_scan(rpc, store, checked, budget, st=None, *, max_seconds=10, max_rpc=100, interval=60):
    from persistent_scan import scan
    return scan(rpc, store, checked, budget, st, max_seconds=max_seconds, max_rpc=max_rpc, interval=interval)


def fee_estimates(rpc: Rpc) -> dict:
    out = {}
    for n in (1, 3, 6, 144):
        try:
            r = rpc.call("estimatesmartfee", n)
            out[str(n)] = round(float(r["feerate"]) * 1e5, 2) if "feerate" in r else None
        except RuntimeError:
            out[str(n)] = None
    return out


# ──────────────────────────────────────────────────────────── follow ──

def sync(rpc: Rpc, store: Store, st: T.State, start: int, log=print) -> int:
    tip = rpc.call("getblockcount")
    cur = store.tip()
    # A same-height reorg must be recognized even if no new block arrives.
    while cur and (cur[0] > tip or cur[1] != rpc.call("getblockhash", cur[0])):
        log(f"canonical tip changed at {cur[0]}; rolling back stored block")
        store.rollback_tip(st)
        cur = store.tip()
    h = (cur[0] + 1) if cur else start
    processed = 0
    while h <= tip:
        bhash = rpc.call("getblockhash", h)
        block = rpc.call("getblock", bhash, 2)
        if block.get("hash") != bhash or block.get("height") != h:
            raise RuntimeError("RPC returned inconsistent block height/hash; block not applied.")
        prev = store.hash_at(h - 1)
        if prev is not None and block.get("previousblockhash") != prev:
            log(f"reorg at {h}: stored {prev[:16]}… != {block.get('previousblockhash', '')[:16]}…, rolling back {h - 1}")
            h = store.rollback_tip(st) + 1
            continue
        events = store.apply_block(st, block)
        processed += 1
        ops = sum(1 for e in events if e["kind"] in ("deploy", "mint", "transfer", "burn", "meta", "allowlist"))
        if ops or h % 50 == 0 or h == tip:
            log(json.dumps({"height": h, "ops": ops, "seals": len(st.seals), "root": st.root()[:16]}))
        h += 1
    return tip


def backfill_token_ids(rpc, store: Store, st: T.State, log=print):
    """Tokens deployed before protocol 1.1 have no ID yet. Look up each deploy's position once."""
    for tick, tok in st.tokens.items():
        if tok.id:
            continue
        try:
            row = store.db.execute("select hash from blocks where height=?", (tok.height,)).fetchone()
            block_hash = row[0] if row else rpc.call("getblockhash", tok.height)
            block = rpc.call("getblock", block_hash, 1)
            if block["height"] != tok.height:
                raise ValueError("deploy block height mismatch")
            tok.id = f"{block['height']}:{block['tx'].index(tok.deploy_txid)}"
        except (RuntimeError, KeyError, ValueError) as exc:
            log(f"warn: no ID for {tick} yet ({exc})")
            continue
        store.db.execute("insert or replace into tokens values(?,?)", (tick, tok_json(tok)))
        log(json.dumps({"token_id": tok.id, "tick": tick}))


def telemetry(rpc: Rpc, store: Store, tip: int, started: float, mem: dict | None, fees: dict | None):
    cur = store.tip()
    last = store.db.execute("select replay_ms from blocks order by height desc limit 1").fetchone()
    peers = None
    try:
        peers = rpc.call("getconnectioncount")
    except RuntimeError:
        pass  # many hosted RPCs don't expose it
    try:
        load = os.getloadavg()[0]
    except OSError:
        load = None
    try:
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    except Exception:  # noqa: BLE001 - optional metric
        rss = None
    kv = {"height": cur[0] if cur else None, "tip": tip, "lag": (tip - cur[0]) if cur else None,
          "replay_ms": last[0] if last else None, "rpc_ms": rpc.latency_ms(), "peers": peers,
          "load1": load, "rss_mb": round(rss, 1) if rss else None, "started_at": int(started), "updated_at": int(time.time())}
    if mem is not None:
        kv["mempool"] = mem
        kv["mempool_updated_at"] = mem.get("snapshot_at", int(time.time()))
    if fees is not None:
        kv["fees"] = fees
    store.put_node(**kv)


def follow(args):
    args.esplora = getattr(args, "esplora", "") or ""
    if args.esplora:
        # Light mode: blocks from a public Esplora API, no Bitcoin node and no mempool scanning.
        from esplora import Esplora
        rpc = Esplora(args.esplora, rps=min(args.rps, 4), network=args.network)
        args.mempool_budget = 0
    else:
        rpc = Rpc(args.rpc_url, args.rpc_user, args.rpc_password, args.rpc_bearer, args.rps)
    store = Store(args.db)
    st = store.load_state()
    store.put_node(network=args.network, activation=args.start, mempool_enabled=args.mempool_budget > 0,
                   mode="light" if args.esplora else "full", source=args.esplora or "bitcoin-rpc")
    from persistent_scan import initialize_scan
    initialize_scan(store, args.mempool_budget > 0, args.mempool_interval, args.mempool_scan_seconds, args.mempool_rpc_budget, args.mempool_budget)
    last_scan = -float('inf')
    started, checked, last_fee = time.time(), set(), 0.0
    print(f"TAPSEAL indexer: {len(st.tokens)} tokens, {len(st.seals)} live seals, tip={store.tip()}", flush=True)
    backfill_token_ids(rpc, store, st, log=lambda m: print(m, flush=True))
    while True:
        try:
            tip = sync(rpc, store, st, args.start, log=lambda m: print(m, flush=True))
            mem = None
            if args.mempool_budget > 0 and time.monotonic() - last_scan >= args.mempool_interval:
                last_scan = time.monotonic()
                mem = mempool_scan(rpc, store, checked, args.mempool_budget, st,
                    max_seconds=args.mempool_scan_seconds, max_rpc=args.mempool_rpc_budget, interval=args.mempool_interval)
            fees = None
            if time.time() - last_fee > 60:
                fees, last_fee = fee_estimates(rpc), time.time()
            telemetry(rpc, store, tip, started, mem, fees)
        except RuntimeError as exc:
            print(f"warn: {exc}", flush=True)
            store.put_node(last_error=str(exc), last_error_at=int(time.time()))
        if args.once:
            return
        time.sleep(args.poll)


def status(args):
    store = Store(args.db)
    st = store.load_state()
    tip = store.tip()
    print(json.dumps({"tip": tip, "tokens": len(st.tokens), "live_seals": len(st.seals), "root": st.root(),
                      "mempool": store.db.execute("select count(*) from mempool").fetchone()[0],
                      "node": {k: json.loads(v) for k, v in store.db.execute("select key, value from node")}}, indent=2))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default=os.getenv("TAPSEAL_DB", "tapseal.sqlite"))
    ap.add_argument("--rpc-url", default=os.getenv("BITCOIN_RPC_URL", ""))
    ap.add_argument("--rpc-user", default=os.getenv("BITCOIN_RPC_USER", ""))
    ap.add_argument("--rpc-password", default=os.getenv("BITCOIN_RPC_PASSWORD", ""))
    ap.add_argument("--rpc-bearer", default=os.getenv("BITCOIN_RPC_BEARER", ""))
    ap.add_argument("--rps", type=float, default=float(os.getenv("RPC_RPS", 20)))
    ap.add_argument("--esplora", default=os.getenv("ESPLORA_URL", ""), help="light mode: read blocks from this Esplora API instead of Bitcoin RPC")
    ap.add_argument("--light", action="store_true", default=os.getenv("NODE_MODE") == "light", help="light mode with the default Esplora for --network")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("follow", help="replay to tip, then keep following and scanning the mempool")
    f.add_argument("--start", type=int, default=int(os.getenv("TAPSEAL_ACTIVATION", 0) or 0), help="activation height (first block to index)")
    f.add_argument("--poll", type=float, default=10)
    f.add_argument("--mempool-budget", type=int, default=DEFAULT_MEMPOOL_BUDGET, help="getrawtransaction calls per scan, 0 disables")
    f.add_argument("--network", default=os.getenv("NETWORK", "mainnet"))
    f.add_argument("--once", action="store_true", help="one sync + scan pass, then exit")
    sub.add_parser("status", help="print stored state summary")
    f.add_argument('--mempool-interval', type=float, default=float(os.getenv('MEMPOOL_SCAN_INTERVAL', '60')))
    f.add_argument('--mempool-scan-seconds', type=float, default=float(os.getenv('MEMPOOL_SCAN_SECONDS', '10')))
    f.add_argument('--mempool-rpc-budget', type=int, default=int(os.getenv('MEMPOOL_RPC_BUDGET', '100')))
    args = ap.parse_args()
    if args.cmd == 'follow' and (args.mempool_budget < 0 or args.mempool_interval < 5 or not 1 <= args.mempool_scan_seconds <= 30 or args.mempool_rpc_budget < 2):
        ap.error('Invalid scanner limits: interval >=5s, scan duration 1..30s, RPC budget >=2, transaction budget >=0.')
    if args.cmd == "follow":
        if args.light and not args.esplora:
            from esplora import ESPLORA
            args.esplora = ESPLORA.get(args.network) or ap.error(f"No default Esplora for {args.network}; pass --esplora URL.")
        if not args.rpc_url and not args.esplora:
            raise SystemExit("Set BITCOIN_RPC_URL (full mode) or use --light / --esplora URL (light mode).")
        if not args.start and not Store(args.db).tip():
            raise SystemExit("First run needs --start <activation height> (or TAPSEAL_ACTIVATION).")
        follow(args)
    else:
        status(args)


if __name__ == "__main__":
    main()
