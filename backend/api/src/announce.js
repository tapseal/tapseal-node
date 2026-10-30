// Check-ins from nodes that others can't reach (a computer at home behind a router). Such a node POSTs its tip to
// its peers every minute; each peer checks the reported root against its own state at that block and lists the node
// for a while. The announcement is unauthenticated, so it's only ever shown as "reported", never trusted: the
// root is verified here, entries expire, and the table and the rate per address are bounded.

const {parseUrl,publicAddress}=require('./peer-http');
const net=require('node:net');
const TTL = 15 * 60_000;
const MAX = 256;
const PER_IP = 4;
const MIN_INTERVAL = 20_000;
const HEX64 = /^[0-9a-f]{64}$/;

function createAnnouncements({ db, network, now = Date.now }) {
  const rootAt = db.raw.prepare('select height, hash, root from blocks where height = ?');
  const table = new Map();             // node_id -> entry

  const prune = () => { const t = now(); for (const [k, v] of table) if (t - v.seen_at > TTL) table.delete(k); };

  function accept(body, ip) {
    prune();
    const b = body || {};
    const id = String(b.node_id || '');
    if (!/^[0-9a-f]{16}$/.test(id)) return { ok: false, code: 400, error: 'node_id must be 16 hex characters.' };
    if (b.network !== network) return { ok: false, code: 409, error: `This node is on ${network}.` };
    const height = Number(b.height);
    if (!Number.isSafeInteger(height) || height < 0 || !HEX64.test(String(b.hash)) || !HEX64.test(String(b.root))) return { ok: false, code: 400, error: 'Send height, hash and root.' };
    const prev = table.get(id);
    if(prev && prev.ip!==ip)return {ok:false,code:409,error:'An unauthenticated node ID cannot be moved to a different source address before expiry.'};
    if (prev && now() - prev.seen_at < MIN_INTERVAL) return { ok: true, matches: prev.matches, next_in_ms: MIN_INTERVAL };
    if (!prev) {
      if ([...table.values()].filter((v) => v.ip === ip).length >= PER_IP) return { ok: false, code: 429, error: 'Too many nodes from this address.' };
      if (table.size >= MAX) return { ok: false, code: 503, error: 'Check-in table full.' };
    }
    const ours = rootAt.get(height);
    const matches = ours ? ours.hash === b.hash && ours.root === b.root : null;
    let url=null;
    if(b.public_url){
      try{const u=parseUrl(b.public_url);const host=u.hostname.replace(/^\[|\]$/g,'');if(net.isIP(host)&&!publicAddress(host))throw Error();url=u.href.replace(/\/$/,'');}
      catch{return {ok:false,code:400,error:'public_url must be a public HTTPS URL.'};}
    }
    table.set(id, { authenticated:false, reported:true, id, ip, network, height, hash: b.hash, root: b.root, matches, mode: b.mode === 'full' ? 'full' : 'light',
      version: String(b.version || '').slice(0, 20), url, seen_at: now(), compared_at: ours ? height : null });
    return { ok: true, matches };
  }

  return {
    accept,
    list() { prune(); return [...table.values()].map(({ ip, ...e }) => e); },
  };
}

module.exports = { createAnnouncements, TTL };
