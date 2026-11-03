// Node-only loopback API and dashboard. This server cannot create or relay transactions.
require('dotenv').config();
const path=require('path'),express=require('express');
const {createRouter}=require('./src/router'),env=process.env;
const config={dbPath:env.TAPSEAL_DB||path.resolve(__dirname,'../indexer/tapseal.sqlite'),network:env.NETWORK||'mainnet',homeNode:true,mode:env.NODE_MODE==='light'?'light':'full',peers:String(env.PEERS||'').split(',').map(s=>s.trim()).filter(Boolean),peerIntervalMs:Number(env.PEER_INTERVAL_MS||60000),nodeId:env.NODE_ID||'',publicUrl:env.PUBLIC_URL||'',mapCacheMs:Number(env.MAP_CACHE_MS||120000)};
const site=path.resolve(env.SITE_DIR||path.join(__dirname,'../../softnode/node-ui'));
const app=express();app.disable('x-powered-by');app.set('trust proxy',false);
app.use(require('./src/home-security').homeGuard({siteDir:site,publicUrl:config.publicUrl}));
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');next()});
app.use(express.json({limit:'256kb'}));
if(env.WALLET_MONITOR_FILE){
  const {createMonitor,localOnly}=require('./src/wallet-monitor');
  const monitor=createMonitor({db:require('./src/db').open(config.dbPath),network:config.network,file:env.WALLET_MONITOR_FILE});
  app.use('/api/local-monitor',localOnly);
  app.get('/api/local-monitor',(req,res)=>res.json(monitor.view()));
  app.post('/api/local-monitor',(req,res)=>{try{res.json(monitor.add(req.body.address))}catch(e){res.status(400).json({ok:false,error:e.message})}});
  app.delete('/api/local-monitor',(req,res)=>{try{res.json(monitor.remove(String(req.body.address||'')))}catch(e){res.status(400).json({ok:false,error:e.message})}});
}
if(env.NODE_PROFILES_DIR&&env.NETWORK_REQUEST_FILE){
 const {localOnly}=require('./src/wallet-monitor');
 const profiles=require('./src/local-networks').localNetworks({directory:env.NODE_PROFILES_DIR,requestFile:env.NETWORK_REQUEST_FILE,network:config.network});
 app.use('/api/local-networks',localOnly);
 app.get('/api/local-networks',(req,res)=>res.json(profiles.list()));
 app.post('/api/local-networks/use',(req,res)=>{try{res.json(profiles.use(req.body.network))}catch{res.status(400).json({ok:false,error:'Network profile unavailable or invalid'})}});
}
if(env.MINER_DIR){
 const {localOnly}=require('./src/wallet-monitor');const miner=require('./src/local-miner').controls({dir:env.MINER_DIR,network:config.network,db:require('./src/db').open(config.dbPath)});
 app.use('/api/local-miner',localOnly);app.get('/api/local-miner',(req,res)=>{try{res.json(miner.view())}catch{res.status(400).json({ok:false,error:'Miner state unavailable'})}});app.post('/api/local-miner',(req,res)=>{try{res.json(miner.set(req.body))}catch(e){res.status(400).json({ok:false,error:e.message})}});
}

const router=createRouter(config);app.use('/api/tapseal',router);app.use('/'+config.network+'/api/tapseal',router);
app.get('/healthz',(req,res)=>res.json({ok:true,distribution:'node-only'}));
app.use(express.static(site,{extensions:['html'],redirect:true}));
app.use((req,res)=>res.status(404).json({ok:false,error:'Node route not found.'}));
app.use((err,req,res,next)=>{if(res.headersSent)return next(err);res.status(err.status>=400&&err.status<500?err.status:500).json({ok:false,error:err.type==='entity.too.large'?'Request body too large.':'Invalid node request.'})});
if(require.main===module){const host=env.HOST||'127.0.0.1',port=Number(env.PORT||8090);const server=app.listen(port,host,()=>console.log(`TAPSEAL node-only ${config.mode} indexer console on http://${host}:${port} (${config.network})`));server.headersTimeout=15000;server.requestTimeout=30000;server.keepAliveTimeout=5000;server.maxConnections=256;}
module.exports={app,config};
