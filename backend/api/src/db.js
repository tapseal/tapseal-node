// Read access to the indexer's SQLite file (WAL). The only write is inserting broadcast txs into `mempool`.
const Database = require('better-sqlite3');
const ts = require('./tapseal');

function open(file) {
  const db = new Database(file, { fileMustExist: true });
  db.pragma('busy_timeout = 5000');
  const q = {
    tip: db.prepare('select height, hash, time, root from blocks order by height desc limit 1'),
    tokens: db.prepare('select json from tokens order by tick'),
    token: db.prepare('select json from tokens where tick = ?'),
    holders: db.prepare("select tick, count(distinct spk) n, count(*) seals from seals where auth = 0 and amt != '0' group by tick"),
    pendingMints: db.prepare("select tick, count(*) n from mempool where kind = 'mint' group by tick"),
    lockPairs: db.prepare('select distinct tick, lock from seals where lock > 0'),
    events: db.prepare('select id, height, txid, kind, tick, amt, detail from events where (? is null or tick = ?) and (? is null or id < ?) order by id desc limit ?'),
    blocks: db.prepare('select height, hash, time, ntx, nops, replay_ms, root from blocks order by height desc limit ?'),
    opsAt: db.prepare("select txid, kind, tick, amt from events where height = ? and kind in ('deploy','mint','transfer','burn','meta','allowlist','invalid','cenotaph')"),
    mempool: db.prepare('select txid, seen, kind, tick, op, error, fee_rate, vsize, bytes, source, paid from mempool order by seen desc limit ?'),
    mempoolCount: db.prepare('select count(*) n from mempool'),
    node: db.prepare('select key, value from node'),
    insertMempool: db.prepare('insert or ignore into mempool(txid, seen, kind, tick, op, error, fee_rate, vsize, bytes, source, paid) values (?,?,?,?,?,?,?,?,?,?,?)'),
  };

  const parseToken = (json) => {
    const t = JSON.parse(json);
    for (const k of ['max', 'minted', 'burned', 'lost']) t[k] = BigInt(t[k]);
    t.wallet_cap = BigInt(t.wallet_cap || 0);
    t.wl_minted = BigInt(t.wl_minted || 0);
    if (t.wl) t.wl = { ...t.wl, price: BigInt(t.wl.price), reserve: BigInt(t.wl.reserve), end: Number(t.wl.end) };
    t.id = t.id || null;
    return t;
  };
  // Databases from before protocol 1.1 have no usage table until the indexer runs once.
  let usageQ = null;
  const usage = (tick, kind, owner) => {
    try { usageQ = usageQ || db.prepare('select atoms from usage where tick = ? and kind = ? and owner = ?'); } catch (e) { return 0n; }
    const r = usageQ.get(tick, kind, owner);
    return r ? BigInt(r.atoms) : 0n;
  };

  return {
    raw: db,
    tip: () => q.tip.get() || null,
    tokens: () => q.tokens.all().map((r) => parseToken(r.json)),
    token: (tick) => { const r = q.token.get(tick); return r ? parseToken(r.json) : null; },
    tokenById: (id) => q.tokens.all().map((r) => parseToken(r.json)).find((t) => t.id === id) || null,
    usage,
    holders: () => Object.fromEntries(q.holders.all().map((r) => [r.tick, r])),
    pendingMints: () => Object.fromEntries(q.pendingMints.all().map((r) => [r.tick, r.n])),
    events: ({ tick = null, before = null, limit = 50 }) => q.events.all(tick, tick, before, before, limit),
    blocks: (limit) => q.blocks.all(limit),
    opsAt: (h) => q.opsAt.all(h),
    mempool: (limit) => q.mempool.all(limit).map((r) => ({ ...r, op: r.op ? JSON.parse(r.op) : null })),
    mempoolCount: () => q.mempoolCount.get().n,
    node: () => Object.fromEntries(q.node.all().map((r) => [r.key, JSON.parse(r.value)])),
    insertMempool: (row) => q.insertMempool.run(row.txid, row.seen, row.kind, row.tick, row.op, row.error, row.fee_rate, row.vsize, row.bytes, row.source, row.paid ?? null),

    /** Live seals owned by an x-only key: plain + authority for every tick, plus every lock height in use. */
    sealsOf(ownerX, network) {
      const tokens = q.tokens.all().map((r) => JSON.parse(r.json).tick);
      const want = new Map();
      for (const tick of tokens) {
        want.set(ts.seal(tick, ownerX, { network }).script.toString('hex'), null);
        want.set(ts.seal(tick, ownerX, { network, auth: true }).script.toString('hex'), null);
      }
      for (const { tick, lock } of q.lockPairs.all()) want.set(ts.seal(tick, ownerX, { network, lock }).script.toString('hex'), null);
      const spks = [...want.keys()];
      const rows = [];
      for (let i = 0; i < spks.length; i += 400) {
        const chunk = spks.slice(i, i + 400);
        rows.push(...db.prepare(`select outpoint, tick, amt, lock, auth, spk, height from seals where spk in (${chunk.map(() => '?').join(',')})`).all(...chunk));
      }
      return rows.sort((a, b) => b.height - a.height || a.outpoint.localeCompare(b.outpoint));
    },
  };
}

module.exports = { open };
