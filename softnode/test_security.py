"""Offline security regressions: release extraction, installer rollback and private config."""
import hashlib,importlib.machinery,importlib.util,io,json,os,plistlib,shutil,subprocess,sys,tarfile,tempfile,types,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
class Security(unittest.TestCase):
 def test_archive_rejects_traversal_and_links(self):
  script=(ROOT/'softnode/install.sh').read_text().split("<<'PY'\n",1)[1].split('\nPY\n',1)[0]
  for name,link in [('tapseal-node-test/../../outside',False),('tapseal-node-test/link',True)]:
   with tempfile.TemporaryDirectory() as d:
    archive=Path(d)/'r.tgz'
    with tarfile.open(archive,'w:gz') as t:
     m=tarfile.TarInfo(name)
     if link:m.type=tarfile.SYMTYPE;m.linkname='/etc/passwd';t.addfile(m)
     else:m.size=1;t.addfile(m,io.BytesIO(b'x'))
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    result=subprocess.run([sys.executable,'-',str(archive),digest,d],input=script,text=True,capture_output=True)
    self.assertNotEqual(result.returncode,0);self.assertIn('unsafe archive',result.stderr)
 def test_dependency_failure_keeps_current_app_and_data(self):
  with tempfile.TemporaryDirectory() as d:
   base=Path(d);pkg=base/'release';home=base/'home';bin=base/'bin';bin.mkdir()
   (pkg/'app/api').mkdir(parents=True);(pkg/'app/bin').mkdir()
   (pkg/'app/api/server.js').write_text('// fixture');shutil.copy2(ROOT/'softnode/install.sh',pkg/'install.sh');shutil.copy2(ROOT/'softnode/tapseal-node',pkg/'app/bin/tapseal-node')
   (home/'app').mkdir(parents=True);(home/'app/old').write_text('keep');(home/'node.json').write_text('{"keep":true}')
   for command,body in [('node','#!/bin/sh\nprintf 22'),('npm','#!/bin/sh\nexit 37')]:
    p=bin/command;p.write_text(body);p.chmod(0o755)
   result=subprocess.run(['sh',str(pkg/'install.sh')],env={**os.environ,'PATH':str(bin)+os.pathsep+os.environ['PATH'],'TAPSEAL_HOME':str(home),'TAPSEAL_BIN':str(base/'commands'),'TAPSEAL_INSTALL_ALLOW_ROOT':'1'},capture_output=True,text=True)
   self.assertNotEqual(result.returncode,0);self.assertEqual((home/'app/old').read_text(),'keep');self.assertEqual((home/'node.json').read_text(),'{"keep":true}')
 def test_private_config_service_quoting_and_network_isolation(self):
  loader=importlib.machinery.SourceFileLoader('node_security',str(ROOT/'softnode/tapseal-node'));spec=importlib.util.spec_from_loader(loader.name,loader);module=importlib.util.module_from_spec(spec);loader.exec_module(module)
  with tempfile.TemporaryDirectory() as d:
   module.HOME=Path(d)/'home & space';module.CONFIG=module.HOME/'node.json';old=Path(d)/'old.sqlite';old.write_text('preserved')
   module.save({'network':'mainnet','start':100,'db':str(old),'node_id':'0123456789abcdef'})
   args=types.SimpleNamespace(from_url=None,network='testnet3',start=100,peer=[],force=True,full=False,esplora=None,rpc_url=None,rpc_user=None,rpc_password=None,rpc_bearer=None,public_url=None,port=8090,public=False,no_site=False)
   module.cmd_init(args);new=json.loads(module.CONFIG.read_text())
   self.assertIn('/testnet3/100/',new['db']);self.assertEqual(old.read_text(),'preserved');self.assertEqual(module.CONFIG.stat().st_mode&0o777,0o600)
   exe=str(module.HOME/'app/bin/tapseal-node');pl=plistlib.loads(next(iter(module.service_files('macos',exe).values())).encode());self.assertEqual(pl['ProgramArguments'][1],exe)
   self.assertIsInstance(module._windows_task_args(exe),list)
if __name__=='__main__':unittest.main()
