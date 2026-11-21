import importlib.util, json, pathlib, plistlib, tempfile, unittest, sys
ENGINE=pathlib.Path(__file__).parents[1]/'src'/'engine'
sys.path.insert(0,str(ENGINE))
spec=importlib.util.spec_from_file_location('probe',ENGINE/'probe.py')
p=importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
class EngineTests(unittest.TestCase):
 def test_kernel_range_is_only_a_config_filter(self):
  self.assertEqual(p.kernel_range_status('23.4.0','22.0.0','24.9.9'),'inside-range')
  self.assertEqual(p.kernel_range_status('25.0.0','22.0.0','24.9.9'),'outside-range')
  self.assertEqual(p.kernel_range_status('25.0.0','',''),'not-set')
  self.assertEqual(p.kernel_range_status('unknown','',''),'unknown')
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(); self.root=pathlib.Path(self.tmp.name).resolve(); self.oc=self.root/'EFI/OC'; self.oc.mkdir(parents=True)
  (self.oc/'OpenCore.efi').write_bytes(b'fixture')
  self.cfg={'Kernel':{'Add':[]},'NVRAM':{'Add':{p.GUID:{'boot-args':'-v alcid=7 keepsyms=1'}}}}
  self.save()
 def tearDown(self): self.tmp.cleanup()
 def save(self): (self.oc/'config.plist').write_bytes(plistlib.dumps(self.cfg))
 def codes(self): return [x['code'] for x in p.analyze({'probes':{}},self.oc)['findings']]
 def kext(self,name,exists=True):
  self.cfg['Kernel']['Add'].append({'BundlePath':name+'.kext','Enabled':True})
  if exists:
   d=self.oc/'Kexts'/(name+'.kext')/'Contents'; d.mkdir(parents=True)
   (d/'Info.plist').write_bytes(plistlib.dumps({'CFBundleVersion':'1.0','CFBundleIdentifier':'test.'+name}))
  self.save()
 def test_resolve(self): self.assertEqual(p.resolve_oc(self.root),self.oc)
 def test_conflict(self):
  self.kext('itlwm'); self.kext('AirportItlwm'); self.assertIn('NET-101',self.codes())
 def test_missing_dependency(self):
  self.kext('AppleALC'); self.assertIn('KEXT-201',self.codes())
 def test_order(self):
  self.kext('WhateverGreen'); self.kext('Lilu'); self.assertIn('KEXT-202',self.codes())
 def test_missing_bundle(self):
  self.kext('Lilu',False); self.assertIn('EFI-101',self.codes())
 def test_escape(self):
  with self.assertRaises(ValueError): p.safe_child(self.oc,'../../outside')
 def test_symlink_refused(self):
  (self.oc/'linked').symlink_to(self.root)
  with self.assertRaises(ValueError): p.workspace(self.oc,self.root/'work')
 def test_backup_and_patch(self):
  before=p.hashes(self.root/'EFI'); work=self.root/'work'; p.workspace(self.oc,work)
  result=p.patch_layout(work,18)
  self.assertEqual(result['after'],'-v keepsyms=1 alcid=18')
  self.assertEqual(p.hashes(work/'Backup'),before); self.assertEqual(p.hashes(self.root/'EFI'),before)
  config=plistlib.loads((work/'Candidate/OC/config.plist').read_bytes()); self.assertEqual(config['NVRAM']['Add'][p.GUID]['boot-args'],result['after'])
 def test_backup_tamper(self):
  work=self.root/'work'; p.workspace(self.oc,work); (work/'Backup/OC/OpenCore.efi').write_bytes(b'changed')
  with self.assertRaises(ValueError): p.patch_layout(work,18)
 def test_inside_source_refused(self):
  with self.assertRaises(ValueError): p.workspace(self.oc,self.oc/'work')
 def test_invalid_layout(self):
  with self.assertRaises(ValueError): p.patch_layout(self.root,0)
 def test_redaction(self):
  value=p.clean({'serial_number':'secret','uuid':'secret','safe':{'mac_address':'secret','value':b'abc'}})
  self.assertNotIn('secret',json.dumps(value)); self.assertEqual(value['safe']['value']['hex'],'616263')
 def test_probe_failure_visible(self):
  r=p.analyze({'probes':{'hardware':{'ok':False,'stderr':'denied'}}})
  self.assertIn('SYS-010',[f['code'] for f in r['findings']])
 def test_corrupt_plist(self):
  (self.oc/'config.plist').write_text('bad'); self.assertIn('EFI-002',self.codes())
 def test_no_success_from_empty_data(self):
  r=p.analyze({'probes':{}})
  self.assertTrue(any(f['confidence']=='manual' for f in r['findings']))
  self.assertFalse(any(f['severity']=='success' for f in r['findings']))
if __name__=='__main__': unittest.main()
