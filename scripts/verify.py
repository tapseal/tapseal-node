#!/usr/bin/env python3
"""Run source guard and isolated test suites. Does not start/stop your home service."""
from pathlib import Path
import argparse,os,subprocess,sys
ROOT=Path(__file__).resolve().parent.parent
p=argparse.ArgumentParser();p.add_argument('--skip-install',action='store_true');args=p.parse_args()
def run(cmd,**kw):subprocess.run(cmd,check=True,cwd=kw.pop('cwd',ROOT),**kw)
if sys.version_info<(3,10):raise SystemExit('Python 3.10+ required')
version=subprocess.check_output(['node','-p','process.versions.node'],text=True).strip()
if int(version.split('.')[0])<22:raise SystemExit('Node 22+ required')
run([sys.executable,'scripts/check-source.py'])
run([sys.executable,'scripts/check-node-only.py'])
if not args.skip_install:run(['npm','ci'],cwd=ROOT/'node/local-api')
run(['npm','test'],cwd=ROOT/'node/local-api',env={**os.environ,'PYTHON_BIN':sys.executable})
run([sys.executable,'-m','unittest','discover','-s','node/protocol','-p','test_*.py'])
run([sys.executable,'-m','unittest','discover','-s','node/indexer','-p','test_*.py'],env={**os.environ,'PYTHONPATH':str(ROOT/'node/protocol')+os.pathsep+str(ROOT/'node/indexer')})
run([sys.executable,'-m','unittest','discover','-s','softnode','-p','test_*.py'])
print('Source guard and all isolated test suites passed. Live OS/browser validation remains separate.')
