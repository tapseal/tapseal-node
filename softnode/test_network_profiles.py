import tempfile,unittest,json,sqlite3,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import network_profiles as P
class Profiles(unittest.TestCase):
 def test_networks_preserve_separate_db_paths_and_private_profiles(self):
  with tempfile.TemporaryDirectory() as t:
   h=Path(t)
   for net,start in [('mainnet',973408),('testnet3',5221529)]:
    cfg={'network':net,'start':start,'mode':'light','db':str(h/net/'tapseal.sqlite')}
    P.save(h,cfg);self.assertEqual(P.read(h,net),cfg);self.assertEqual((h/'profiles'/(net+'.json')).stat().st_mode&0o777,0o600)
   with self.assertRaises(ValueError):P.save(h,{'network':'mainnet','start':973408,'mode':'light','db':str(h/'testnet3/tapseal.sqlite')})
 def test_wrong_network_existing_db_is_refused(self):
  with tempfile.TemporaryDirectory() as t:
   h=Path(t);db=h/'x.sqlite'
   c=sqlite3.connect(db);c.execute('create table node(key text,value text)');c.execute('insert into node values(?,?)',('network',json.dumps('testnet3')));c.commit();c.close()
   with self.assertRaisesRegex(ValueError,'network'):P.save(h,{'network':'mainnet','start':973408,'mode':'light','db':str(db)})
   self.assertFalse((h/'profiles/mainnet.json').exists())
if __name__=='__main__':unittest.main()
