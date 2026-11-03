// Network map: start from this node, ask each peer for its peers, and so on (breadth first), to draw every node
// reachable from here and who checks whom. Bounded so a crawl can never run away: depth, node count, per-request
// timeout and a cache. Nodes are identified by their node ID, so one node reachable at two URLs appears once.

const { apiOf } = require('./peers');
const { peerFetch } = require('./peer-http');

async function getJson(fetchImpl, url, timeoutMs) {
  const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: 'application/json', 'user-agent': 'tapseal-node/1 (map)' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

function createNetwork({ db, self, peers, announcements = null, fetchImpl = peerFetch, maxNodes = 64, maxDepth = 4, timeoutMs = 6000, concurrency = 8, cacheMs = 120_000, now = Date.now }) {
  maxNodes=Math.max(1,Math.min(64,Number(maxNodes)||64));maxDepth=Math.max(0,Math.min(4,Number(maxDepth)||4));
  concurrency=Math.max(1,Math.min(8,Number(concurrency)||8));cacheMs=Math.max(15000,Math.min(300000,Number(cacheMs)||120000));
  const rootAt = db.raw.prepare('select height, hash, root from blocks where height = ?');
  const tipQ = db.raw.prepare('select height, hash, root from blocks order by height desc limit 1');
  let cache = null, inflight = null;

  async function crawl() {
    const deadline=now()+15000;
    const tip = tipQ.get();
    const me = { id: self.id, url: self.url || null, self: true, mode: self.mode, network: self.network, height: tip ? tip.height : null,
      root: tip ? tip.root : null, reachable: true, matches: true, depth: 0 };
    const nodes = new Map([[me.id, me]]);
    const byUrl = new Map();                         // api url -> node id
    if (self.url) byUrl.set(apiOf(self.url), me.id);
    const edges = new Map();                         // "from|to" -> state
    const addEdge = (from, to, state) => { if (edges.size < 512 && from && to && from !== to) edges.set(`${from}|${to}`, { from, to, state }); };

    for (const p of peers.results()) {               // our own checks are already fresh
      byUrl.has(p.url) || byUrl.set(p.url, `url:${p.url}`);
    }
    let frontier = peers.results().map((p) => ({ url: p.url, from: me.id, state: p.state, depth: 1 }));
    const seenUrl = new Set([...(self.url ? [apiOf(self.url)] : [])]);
    // Nodes that checked in (outbound only, e.g. at home): verified against our own roots, never crawled.
    const reported = [];
    const addReported = (e, to) => { if(reported.length<256)reported.push({ e, to }); };
    for (const e of announcements ? announcements.list() : []) addReported(e, me.id);

    while (frontier.length && nodes.size < maxNodes && now()<deadline) {
      const batch = [];
      for (const f of frontier) {
        if (!seenUrl.has(f.url)) { seenUrl.add(f.url); if(batch.length<maxNodes)batch.push(f); }
        else addEdge(f.from, byUrl.get(f.url) || `url:${f.url}`, f.state);   // already visited: keep the link, don't crawl again
      }
      frontier = [];
      for (let i = 0; i < batch.length && nodes.size < maxNodes && now()<deadline; i += concurrency) {
        await Promise.all(batch.slice(i, i + concurrency).map(async (f) => {
          let st, pe;
          try {
            [st, pe] = await Promise.all([getJson(fetchImpl, `${f.url}/status`, Math.min(timeoutMs,Math.max(1,deadline-now()))), getJson(fetchImpl, `${f.url}/peers`, Math.min(timeoutMs,Math.max(1,deadline-now()))).catch(() => null)]);
          } catch (e) {
            const id = `url:${f.url}`;
            if (!nodes.has(id) && nodes.size < maxNodes) nodes.set(id, { id, url: f.url, reachable: false, depth: f.depth, reason: String(e.message || e) });
            addEdge(f.from, id, f.state || 'unreachable');
            return;
          }
          if (!st || typeof st.network!=='string' || (st.tip && (!Number.isSafeInteger(st.tip.height) || st.tip.height<0))) { const id=`url:${f.url}`; if(nodes.size<maxNodes)nodes.set(id,{id,url:f.url,reachable:false,reason:'Malformed peer status',depth:f.depth}); addEdge(f.from,id,'unreachable'); return; }
          const id = typeof st.node_id==='string' && /^[a-zA-Z0-9-]{1,64}$/.test(st.node_id) ? st.node_id : `url:${f.url}`;
          if (id===self.id) return;
          const known = nodes.get(id);
          if (!known) {
            if (nodes.size >= maxNodes) return;
            const n = { id, url: st.public_url ? apiOf(st.public_url) : f.url, mode: st.mode || 'full', network: st.network, height: st.tip ? st.tip.height : null,
              root: st.tip ? st.tip.root : null, reachable: true, depth: f.depth, peers: pe ? pe.summary : null };
            // Does it agree with this node? Compare roots at the lower of the two heights.
            if (n.network !== self.network) n.matches = null, n.reason = `on ${n.network}`;
            else if (tip && n.height != null) {
              const h = Math.min(tip.height, n.height);
              try {
                const theirs = n.height === h ? { hash: st.tip.hash, root: st.tip.root } : await getJson(fetchImpl, `${f.url}/root/${h}`, Math.min(timeoutMs,Math.max(1,deadline-now())));
                const ours = rootAt.get(h);
                n.matches = ours ? theirs.hash === ours.hash && theirs.root === ours.root : null;
                n.compared_at = h;
              } catch { n.matches = null; }
            }
            nodes.set(id, n);
          }
          byUrl.set(f.url, id);
          addEdge(f.from, id, f.state || (known ? 'known' : 'checked'));
          for (const e of (Array.isArray(pe?.announced) ? pe.announced.slice(0,64) : [])) addReported(e, id);
          if (pe && f.depth < maxDepth) {
            for (const p of (Array.isArray(pe.peers) ? pe.peers.slice(0,32) : [])) {
              const u = apiOf(p.url);
              if (!u) continue;
              if(frontier.length<maxNodes)frontier.push({ url: u, from: id, state: p.state, depth: f.depth + 1 });
            }
          }
        }));
      }
    }
    for (const { e, to } of reported) {
      if (!e || !/^[0-9a-f]{16}$/.test(String(e.id)) || e.network !== self.network || e.id === self.id) continue;
      let n = nodes.get(e.id);
      if (!n) {
        if (nodes.size >= maxNodes) continue;
        const ours = rootAt.get(Number(e.height));
        n = { id: e.id, url: e.url ? apiOf(e.url) : null, mode: e.mode, network: e.network, height: e.height, root: e.root, reachable: true, outbound: true,
          matches: ours ? ours.hash === e.hash && ours.root === e.root : null, compared_at: ours ? e.height : undefined, depth: 1,
          reason: 'checks in from behind a router (not reachable from here)', seen_at: e.seen_at };
        nodes.set(e.id, n);
      }
      addEdge(e.id, to, e.matches === true ? 'agree' : e.matches === false ? 'disagree' : 'checked');
    }
    // Edges were recorded against URLs for nodes not yet identified: map them to node IDs.
    const out = [];
    for (const e of edges.values()) {
      const to = e.to.startsWith('url:') && byUrl.has(e.to.slice(4)) ? byUrl.get(e.to.slice(4)) : e.to;
      if (nodes.has(e.from) && nodes.has(to) && e.from !== to) out.push({ ...e, to });
    }
    const dedup = [...new Map(out.map((e) => [`${e.from}|${e.to}`, e])).values()];
    const list = [...nodes.values()];
    return { ok: true, root_scope: 'seal-outputs-v1', authenticated: false, crawled_at: now(), self: me.id, network: self.network,
      summary: { nodes: list.length, reachable: list.filter((n) => n.reachable).length, home: list.filter((n) => n.outbound).length, matching: list.filter((n) => n.matches === true).length,
        differing: list.filter((n) => n.matches === false).length, links: dedup.length, truncated: list.length >= maxNodes || now()>=deadline },
      nodes: list, edges: dedup };
  }

  return {
    async get(force = false) {
      if (!force && cache && now() - cache.crawled_at < cacheMs) return cache;
      if (!inflight) inflight = crawl().then((r) => { cache = r; return r; }).finally(() => { inflight = null; });
      return inflight;
    },
  };
}

module.exports = { createNetwork };
