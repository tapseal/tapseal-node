#!/usr/bin/env python3
"""Build the home runtime from this checkout, without the public website or network access."""
from pathlib import Path
import gzip,hashlib,io,json,os,re,shutil,tarfile,subprocess,sys
ROOT=Path(__file__).resolve().parent.parent
subprocess.run([sys.executable,str(ROOT/'scripts/check-source.py')],cwd=ROOT,check=True)
subprocess.run([sys.executable,str(ROOT/'scripts/check-node-only.py')],cwd=ROOT,check=True)
version=re.search(r'^VERSION = "([A-Za-z0-9.-]+)"',(ROOT/'softnode/tapseal-node').read_text(),re.M)[1]
name='tapseal-node-'+version;out=ROOT/'artifacts';out.mkdir(exist_ok=True);stage=out/name
if stage.exists():shutil.rmtree(stage)
(stage/'app/api').mkdir(parents=True);(stage/'app/bin').mkdir()
ignore=shutil.ignore_patterns('node_modules','__pycache__','*.pyc','*.sqlite*','.env*','test_*.py')
for folder in ['protocol','indexer']:shutil.copytree(ROOT/'node'/folder,stage/'app'/folder,ignore=ignore)
for folder in ['src','scripts']:shutil.copytree(ROOT/'node/local-api'/folder,stage/'app/api'/folder,ignore=ignore)
for file in ['server.js','package.json','package-lock.json']:shutil.copy2(ROOT/'node/local-api'/file,stage/'app/api'/file)
shutil.copytree(ROOT/'softnode/node-ui',stage/'app/site')
shutil.copy2(ROOT/'softnode/tapseal-node',stage/'app/bin/tapseal-node')
shutil.copy2(ROOT/'softnode/network_profiles.py',stage/'app/bin/network_profiles.py')
for file in ['install.sh','Dockerfile','docker-compose.yml']:shutil.copy2(ROOT/'softnode'/file,stage/file)
(stage/'docs').mkdir();shutil.copy2(ROOT/'docs/LOT-V1.md',stage/'docs/LOT-V1.md');shutil.copy2(ROOT/'docs/POW-COMPACT-V2.md',stage/'docs/POW-COMPACT-V2.md');shutil.copy2(ROOT/'docs/GUIDED-WORKER.md',stage/'docs/GUIDED-WORKER.md')
for file in ['QUICKSTART.md','UPDATING.md','TROUBLESHOOTING.md','SERVER.md','ARCHITECTURE.md','MINT-WORKER.md','RELEASE.md']:
 shutil.copy2(ROOT/'docs'/file,stage/'docs'/file)
for file in ['README.md','LICENSE','SECURITY.md','THIRD-PARTY.md']:shutil.copy2(ROOT/file,stage/file)
source_files={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(ROOT.rglob('*')) if p.is_file() and not any(part in {'node_modules','__pycache__','.git','artifacts'} for part in p.relative_to(ROOT).parts) and p.suffix!='.pyc'}
(stage/'SOURCE.json').write_text(json.dumps({'version':version,'files':source_files},sort_keys=True,indent=2)+'\n')
archive=out/(name+'.tar.gz')
epoch=int(os.environ.get('SOURCE_DATE_EPOCH','0'))
with archive.open('wb') as output,gzip.GzipFile(filename='',mode='wb',fileobj=output,mtime=epoch) as gz,tarfile.open(fileobj=gz,mode='w',format=tarfile.PAX_FORMAT) as tar:
 for p in [stage,*sorted(stage.rglob('*'))]:
  if p.is_symlink():raise RuntimeError('Symlinks are not allowed in release')
  info=tar.gettarinfo(str(p),arcname=str(p.relative_to(out)));info.uid=info.gid=0;info.uname=info.gname='';info.mtime=epoch;info.pax_headers={};info.mode=0o755 if p.is_dir() or p.name in {'install.sh','tapseal-node'} else 0o644
  if p.is_file():
   with p.open('rb') as f:tar.addfile(info,f)
  else:tar.addfile(info)
digest=hashlib.sha256(archive.read_bytes()).hexdigest();(out/(archive.name+'.sha256')).write_text(digest+'  '+archive.name+'\n')
(out/'install.sh').write_text((ROOT/'softnode/install.sh').read_text().replace('__PINNED_RELEASE_SHA256__',digest))
print(json.dumps({'archive':str(archive),'sha256':digest,'version':version}))
