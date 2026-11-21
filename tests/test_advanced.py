import sys,pathlib,unittest,tempfile,zipfile,io,json,hashlib
from unittest.mock import patch
sys.path.insert(0,str(pathlib.Path(__file__).parents[1]/'src'/'engine'))
import advanced as a
class AdvancedTests(unittest.TestCase):
 def test_pci_ids_little_endian(self):
  rows=a.registry_rows([{'IORegistryEntryName':'WiFi','vendor-id':{'hex':'86800000'},'device-id':{'hex':'23270000'},'IORegistryEntryChildren':[{'BSD Name':'en1','IOClass':'ExampleDriver'}]}],'PCI')
  self.assertEqual(rows[0]['vendor'],'8086');self.assertEqual(rows[0]['interfaces'],['en1']);self.assertEqual(rows[0]['functional'],'manual-test-required')
 def test_bridge_does_not_claim_child_interface(self):
  rows=a.registry_rows([{'vendor-id':1,'IORegistryEntryID':1,'IORegistryEntryChildren':[{'vendor-id':2,'IORegistryEntryID':2,'IORegistryEntryChildren':[{'BSD Name':'en1'}]}]}],'PCI')
  self.assertFalse(rows[0]['interfaces']);self.assertEqual(rows[1]['interfaces'],['en1'])
 def test_recognized_not_active(self):
  r=a.network_rows('Hardware Port: Wi-Fi\nDevice: en1\nEthernet Address: private',{'en1':{'ifconfig':'status: inactive','radio':'off'}},'en0')[0]
  self.assertTrue(r['recognized']);self.assertEqual(r['link'],'inactive');self.assertFalse(r['default_route']);self.assertEqual(r['internet'],'not-tested')
 def test_connected_but_not_default(self):
  r=a.network_rows('Hardware Port: Wi-Fi\nDevice: en1\n',{'en1':{'ifconfig':'inet 192.0.2.1\nstatus: active'}},'en0')[0]
  self.assertTrue(r['has_ipv4']);self.assertEqual(r['link'],'active');self.assertFalse(r['default_route'])
 def test_efi_enumeration(self):
  tree={'AllDisksAndPartitions':[{'DeviceIdentifier':'disk0','Partitions':[{'Content':'EFI','DeviceIdentifier':'disk0s1','Size':200},{'Content':'Apple_APFS','DeviceIdentifier':'disk0s2'}]}]}
  rows=a.efi_partitions(tree,lambda x:{'Content':'EFI'})
  self.assertEqual(len(rows),1);self.assertFalse(rows[0]['mounted']);self.assertEqual(rows[0]['boot_source'],'unknown')
 def test_disk_id_injection_rejected(self):
  with self.assertRaises(ValueError):a.disk_info('disk0s1; echo bad')
 def test_repo_injection_rejected(self):
  with self.assertRaises(ValueError):a.repo_valid('user/repo/../../other')
 def test_redirect_rejected(self):
  for url in ['http://github.com/x','https://evil.example/x','https://github.com@evil.example/x']:
   with self.assertRaises(ValueError):a.check_download_url(url)
 def test_traversal_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   z=pathlib.Path(d)/'a.zip'
   with zipfile.ZipFile(z,'w') as f:f.writestr('../outside','bad')
   with self.assertRaises(ValueError):a.unpack_zip(z,pathlib.Path(d)/'out')
 def test_symlink_rejected(self):
  with tempfile.TemporaryDirectory() as d:
   z=pathlib.Path(d)/'a.zip';info=zipfile.ZipInfo('link');info.create_system=3;info.external_attr=0o120777<<16
   with zipfile.ZipFile(z,'w') as f:f.writestr(info,'/etc')
   with self.assertRaises(ValueError):a.unpack_zip(z,pathlib.Path(d)/'out')
 def test_safe_extract_lists_root_kext_only(self):
  with tempfile.TemporaryDirectory() as d:
   z=pathlib.Path(d)/'a.zip'
   with zipfile.ZipFile(z,'w') as f:
    f.writestr('Root.kext/Contents/Info.plist','fixture');f.writestr('Root.kext/Contents/PlugIns/Child.kext/Contents/Info.plist','fixture');f.writestr('Driver.efi','fixture')
   target=pathlib.Path(d)/'out';a.unpack_zip(z,target)
   self.assertEqual(len(a.downloadable_items(target)),2)
 def test_digest_mismatch_cleans_download(self):
  class Response(io.BytesIO):
   def geturl(self):return 'https://github.com/test/repo/releases/download/v1/a.zip'
  class Opener:
   def open(self,*args,**kwargs):return Response(b'bad')
  with tempfile.TemporaryDirectory() as d,patch.object(a,'cache_root',return_value=pathlib.Path(d)),patch.object(a,'api',return_value={'name':'a.zip','size':3,'browser_download_url':'https://github.com/test/repo/releases/download/v1/a.zip','digest':'sha256:'+'0'*64}),patch.object(a.urllib.request,'build_opener',return_value=Opener()):
   with self.assertRaises(ValueError):a.download('test/repo',123)
   self.assertFalse(list(pathlib.Path(d).iterdir()))
if __name__=='__main__':unittest.main()
