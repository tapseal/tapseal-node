// TAPSEAL API server. Run next to the indexer; point Netlify's /api/* redirect at it.
require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const { createRouter } = require('./src/router');

const env = process.env;
const config = {
  dbPath: env.TAPSEAL_DB || path.resolve(__dirname, '../indexer/tapseal.sqlite'),
  network: env.NETWORK || 'mainnet',
  mempoolApi: (env.MEMPOOL_API || (env.NETWORK && env.NETWORK !== 'mainnet' ? `https://mempool.space/${env.NETWORK === 'testnet' ? 'testnet4' : env.NETWORK}/api` : 'https://mempool.space/api')).replace(/\/$/, ''),
  minServerUtxo: Number(env.MIN_SERVER_UTXO_SATS || 10000),
  publicLaunch: env.PUBLIC_LAUNCH === 'true',
  ownerAddresses: String(env.OWNER_ADDRESSES || '').split(',').map((s) => s.trim()).filter(Boolean),
  featured: env.FEATURED_TICK || 'STONK',
  platformFee: { address: env.PLATFORM_FEE_ADDRESS || '', sats: env.PLATFORM_FEE_ADDRESS ? Number(env.PLATFORM_FEE_SATS || 0) : 0 },
  rpc: { url: env.BITCOIN_RPC_URL || '', user: env.BITCOIN_RPC_USER || '', password: env.BITCOIN_RPC_PASSWORD || '', bearer: env.BITCOIN_RPC_BEARER || '' },
  mode: env.NODE_MODE === 'light' ? 'light' : 'full',
  peers: String(env.PEERS || '').split(',').map((s) => s.trim()).filter(Boolean),
  peerIntervalMs: Number(env.PEER_INTERVAL_MS || 60000),
  nodeId: env.NODE_ID || '',
  publicUrl: env.PUBLIC_URL || '',
  mapCacheMs: Number(env.MAP_CACHE_MS || 120000),
};

config.previewRequireRpc = true; // Required for production input/admission checks.
const app = express();
app.set('trust proxy', 'loopback');
if(env.HOME_NODE === 'true')app.use(require('./src/home-security').homeGuard({siteDir:env.SITE_DIR,publicUrl:config.publicUrl}));
app.use(cors({ origin: env.HOME_NODE === 'true' ? false : env.CORS_ORIGIN ? env.CORS_ORIGIN.split(',') : true }));
app.disable('x-powered-by');
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');next();});
app.use(express.json({ limit: '256kb' }));
// Enabled only by the home CLI; not enabled on the public Vultr API.
if(env.WALLET_MONITOR_FILE){
  const {createMonitor,localOnly}=require('./src/wallet-monitor');
  const monitor=createMonitor({db:require('./src/db').open(config.dbPath),network:config.network,file:env.WALLET_MONITOR_FILE});
  app.use('/api/local-monitor',localOnly);
  app.get('/api/local-monitor',(req,res)=>res.json(monitor.view()));
  app.post('/api/local-monitor',(req,res)=>{try{res.json(monitor.add(req.body.address))}catch(e){res.status(400).json({ok:false,error:e.message})}});
  app.delete('/api/local-monitor',(req,res)=>{try{res.json(monitor.remove(String(req.body.address||'')))}catch(e){res.status(400).json({ok:false,error:e.message})}});
}
app.use('/api/tapseal', createRouter(config));
if (env.SERVE_STATIC === 'true') { // local testing: serve the console and mempool pages from the same origin
  app.use('/console', express.static(path.resolve(__dirname, '../console')));
  app.use('/mempool', express.static(path.resolve(__dirname, '../mempool')));
  app.use('/', express.static(path.resolve(__dirname, '../console')));
}
app.get('/healthz', (req, res) => res.json({ ok: true }));
// A soft node serves the TAPSEAL site itself (the Next.js static export), so anyone can host a front end.
if (env.SITE_DIR) {
  const site = path.resolve(env.SITE_DIR);
  app.use(express.static(site, { extensions: ['html'], redirect: true }));
  app.use((req, res, next) => (req.method === 'GET' && req.accepts('html') ? res.status(404).sendFile(path.join(site, '404.html')) : next()));
}

app.use((err,req,res,next)=>{if(res.headersSent)return next(err);res.status(err.status>=400&&err.status<500?err.status:500).json({ok:false,error:err.type==='entity.too.large'?'Request body too large.':'Invalid request.'});});

if (require.main === module) {
  const port = Number(env.PORT || 8090);
  const host = env.HOST || '127.0.0.1';
  const server = app.listen(port, host, () => console.log(`TAPSEAL ${config.mode} node on http://${host}:${port} (${config.network}, db ${config.dbPath}, ${config.peers.length} peers)`));
  server.headersTimeout=15000;server.requestTimeout=30000;server.keepAliveTimeout=5000;server.maxConnections=256;
}

module.exports = { app, config };
