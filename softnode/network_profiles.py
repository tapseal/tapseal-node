"""Private network profiles and atomic active-config switching; no ledger deletion."""
import json,os,tempfile,sqlite3
from contextlib import closing
from pathlib import Path
NETWORKS=('mainnet','testnet3')
def write(path,data):
 path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 fd,tmp=tempfile.mkstemp(prefix='.profile-',dir=path.parent)
 try:
  os.fchmod(fd,0o600)
  with os.fdopen(fd,'w') as f:json.dump(data,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
  os.replace(tmp,path)
 finally:
  if os.path.exists(tmp):os.unlink(tmp)
def read(home,network):
 if network not in NETWORKS:raise ValueError('Choose mainnet or testnet3')
 p=home/'profiles'/(network+'.json')
 if p.is_symlink() or not p.is_file() or p.stat().st_size>128*1024:raise ValueError('Profile not configured; configure it from the matching public network API first')
 return validate(json.loads(p.read_text()),network)
def validate(cfg,network):
 if cfg.get('network')!=network or type(cfg.get('start')) is not int or cfg['start']<0 or cfg.get('mode') not in ('full','light'):raise ValueError('Invalid network profile')
 db=Path(cfg['db'])
 if not db.is_absolute():raise ValueError('Profile database must use an absolute path')
 if db.exists():
  with closing(sqlite3.connect(db.resolve().as_uri()+'?mode=ro',uri=True)) as c:
   row=c.execute("select value from node where key='network'").fetchone()
   if not row or json.loads(row[0])!=network:raise ValueError('Database network does not match profile; no configuration changed')
   row=c.execute("select value from node where key='activation'").fetchone()
   if row and json.loads(row[0])!=cfg['start']:raise ValueError('Database activation differs from profile')
 return cfg
def save(home,cfg):
 validate(cfg,cfg['network'])
 if cfg['network'] not in NETWORKS:raise ValueError('Only mainnet and testnet3 profiles are supported')
 other='testnet3' if cfg['network']=='mainnet' else 'mainnet';p=home/'profiles'/(other+'.json')
 if p.exists() and Path(json.loads(p.read_text())['db']).resolve()==Path(cfg['db']).resolve():raise ValueError('Different networks must not share a database')
 write(home/'profiles'/(cfg['network']+'.json'),cfg)
