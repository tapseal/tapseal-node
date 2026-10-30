// Peer agreement: every TAPSEAL node computes a state root per block (a legacy hash of live seal outputs, not all token state). Nodes that
// index the same Bitcoin blocks under the same rules get the same root. This module asks other nodes for their root
// at a height both have indexed and reports who agrees. A disagreement means one side has a bug, a different
// chain view, or was tampered with: it is shown, never resolved automatically.

const { peerFetch } = require('./peer-http');
const DEFAULT_INTERVAL = 60_000;

const apiOf = (url) => {
  try {
    const u = new URL(String(url).trim());
    if (!['https:', 'http:'].includes(u.protocol) || u.username || u.password || u.search || u.hash || u.href.length > 512) return null;
    const base = u.href.replace(/\/+$/, '');
    return /\/api\/tapseal$/.test(base) ? base : `${base}/api/tapseal`;
  } catch { return null; }
};

async function getJson(url, timeoutMs, fetchImpl) {
  const t0 = Date.now();
  const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs), headers: { accept: 'application/json', 'user-agent': 'tapseal-node/1' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const body = await res.json();
  return { body, ms: Date.now() - t0 };
}

function createPeers({ peers = [], db, network, intervalMs = DEFAULT_INTERVAL, timeoutMs = 8000, fetchImpl = peerFetch, now = Date.now, announce = null }) {
  const list = [...new Set(peers.map(apiOf).filter(Boolean))].slice(0, 32);
  const rootAt = db.raw.prepare('select height, hash, root from blocks where height = ?');
  const tipQ = db.raw.prepare('select height, hash, root from blocks order by height desc limit 1');
  let results = list.map((url) => ({ url, state: 'pending' }));
  let checkedAt = 0, timer = null, running = false;

  async function checkOne(url) {
    const out = { url, checked_at: now() };
    try {
      const { body: st, ms } = await getJson(`${url}/status`, timeoutMs, fetchImpl);
      out.latency_ms = ms;
      if(!st || !['mainnet','testnet3','testnet','testnet4','signet','regtest'].includes(st.network))throw new Error('Malformed peer network.');
      out.network = st.network;
      out.mode = st.mode==='light'?'light':'full';
      out.height = st.tip ? st.tip.height : null;
      if(out.height!==null && (!Number.isSafeInteger(out.height)||out.height<0))throw new Error('Malformed peer height.');
      if (st.network !== network) return { ...out, state: 'other-network', agree: null, reason: `peer is on ${st.network}` };
      const mine = tipQ.get();
      if (!mine || out.height == null) return { ...out, state: 'syncing', agree: null, reason: 'no indexed blocks yet' };
      const h = Math.min(mine.height, out.height);
      const ours = rootAt.get(h);
      if (!ours) return { ...out, state: 'not-comparable', agree: null, reason: `this node starts after block ${h}` };
      let theirs;
      if (st.tip.height === h && st.tip.root) theirs = { height: h, hash: st.tip.hash, root: st.tip.root };
      else theirs = (await getJson(`${url}/root/${h}`, timeoutMs, fetchImpl)).body;
      out.compared_at = h;
      if (theirs.hash !== ours.hash) return { ...out, state: 'other-chain', agree: false, reason: `different block ${h}: ${String(theirs.hash).slice(0, 12)}…` };
      if (theirs.root !== ours.root) return { ...out, state: 'disagree', agree: false, reason: `state root differs at block ${h}` };
      return { ...out, state: 'agree', agree: true, root: ours.root };
    } catch (e) {
      return { ...out, state: 'unreachable', agree: null, reason: String(e.message || e) };
    }
  }

  async function check() {
    if (running || !list.length) return results;
    running = true;
    try {
      results = await Promise.all(list.map(checkOne));
      checkedAt = now();
      if (announce) await announceAll();
    } finally { running = false; }
    return results;
  }

  // Check in with every peer: tells nodes that can't reach us (we may be at home behind a router) that we exist and
  // what state we computed. Each peer verifies the root itself; nothing here is trusted by anyone.
  let announced = {};
  async function announceAll() {
    const tip = tipQ.get();
    if (!tip) return;
    const body = JSON.stringify({ node_id: announce.id, network, mode: announce.mode, version: announce.version, public_url: announce.url || undefined,
      height: tip.height, hash: tip.hash, root: tip.root });
    await Promise.all(list.map(async (url) => {
      try {
        const res = await fetchImpl(`${url}/announce`, { method: 'POST', body, headers: { 'content-type': 'application/json', 'user-agent': 'tapseal-node/1' }, signal: AbortSignal.timeout(timeoutMs) });
        announced[url] = { ok: res.ok, status: res.status, at: now() };
      } catch (e) { announced[url] = { ok: false, error: String(e.message || e), at: now() }; }
    }));
  }

  function summary() {
    const agree = results.filter((p) => p.agree === true).length;
    const disagree = results.filter((p) => p.agree === false).length;
    const reachable = results.filter((p) => p.state && !['pending', 'unreachable'].includes(p.state)).length;
    return { peers: list.length, reachable, agree, disagree, checked_at: checkedAt || null,
      root_scope: 'seal-outputs-v1', authenticated: false, state: !list.length ? 'solo' : disagree ? 'disagree' : agree ? 'agree' : checkedAt ? 'no-peers-reachable' : 'pending' };
  }

  return {
    list, check, summary, announced: () => announced,
    results: () => results,
    start() { if (!timer && list.length) { check(); timer = setInterval(check, Math.max(15000, Number(intervalMs) || DEFAULT_INTERVAL)); timer.unref?.(); } return this; },
    stop() { clearInterval(timer); timer = null; },
  };
}

module.exports = { createPeers, apiOf };
