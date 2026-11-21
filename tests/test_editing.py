import test_engine
p = test_engine.p
import unittest
import json, pathlib, plistlib
class EditingTests(unittest.TestCase):
 setUp = test_engine.EngineTests.setUp
 tearDown = test_engine.EngineTests.tearDown
 save = test_engine.EngineTests.save
 def work(self):
  work=self.root/'work';p.workspace(self.oc,work);return work
 def source_kext(self,name='Demo',deps=None):
  d=self.root/(name+'.kext');(d/'Contents/MacOS').mkdir(parents=True)
  (d/'Contents/MacOS'/name).write_bytes(b'fake fixture executable, never boot')
  (d/'Contents/Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier':'test.'+name,'CFBundleVersion':'1.2.3','CFBundleExecutable':name,'OSBundleLibraries':deps or {}}))
  return d
 def test_import_kext_registers(self):
  src=self.source_kext();work=self.work();before=p.hashes(self.root/'EFI')
  result=p.import_item(work,src,'kext');self.assertEqual(result['registered'],['Demo.kext'])
  _,cfg,kexts=p.inspect_efi(work/'Candidate');self.assertTrue(kexts[0]['enabled']);self.assertTrue(kexts[0]['exists'])
  self.assertEqual(cfg['Kernel']['Add'][0]['ExecutablePath'],'Contents/MacOS/Demo');self.assertEqual(p.hashes(self.root/'EFI'),before)
 def test_import_aml_registers(self):
  src=self.root/'SSDT-Test.aml';src.write_bytes(b'fixture');work=self.work();p.import_item(work,src,'acpi')
  _,cfg,_=p.inspect_efi(work/'Candidate');self.assertEqual(cfg['ACPI']['Add'][0]['Path'],src.name)
 def test_import_driver_registers(self):
  src=self.root/'Demo.efi';src.write_bytes(b'fixture');work=self.work();p.import_item(work,src,'driver')
  _,cfg,_=p.inspect_efi(work/'Candidate');self.assertFalse(cfg['UEFI']['Drivers'][0]['LoadEarly'])
 def test_invalid_import_rolls_back(self):
  src=self.source_kext();(src/'Contents/MacOS/Demo').unlink();work=self.work();before=p.hashes(work/'Candidate')
  with self.assertRaises(ValueError):p.import_item(work,src,'kext')
  self.assertEqual(p.hashes(work/'Candidate'),before);self.assertFalse((work/'history.jsonl').exists())
 def test_overwrite_requires_flag(self):
  src=self.source_kext();work=self.work();p.import_item(work,src,'kext');before=p.hashes(work/'Candidate')
  with self.assertRaises(ValueError):p.import_item(work,src,'kext')
  self.assertEqual(p.hashes(work/'Candidate'),before)
  p.import_item(work,src,'kext',True)
 def test_toggle_history_restore(self):
  src=self.source_kext();work=self.work();p.import_item(work,src,'kext');p.set_kext_enabled(work,'Demo.kext',False)
  info=p.workspace_info(work);self.assertFalse(info['kexts'][0]['enabled']);self.assertEqual(len(info['history']),2)
  p.restore_history(work,info['history'][-1]['id']);self.assertTrue(p.workspace_info(work)['kexts'][0]['enabled'])
 def test_config_invalid_does_not_change(self):
  work=self.work();before=p.hashes(work/'Candidate');src=self.root/'bad.plist';src.write_text('bad')
  with self.assertRaises(Exception):p.save_config(work,src)
  self.assertEqual(p.hashes(work/'Candidate'),before)
 def test_config_edit_and_undo(self):
  work=self.work();src=self.root/'edited.plist';cfg=self.cfg.copy();cfg['Misc']={'Boot':{'Timeout':9}};src.write_bytes(plistlib.dumps(cfg));p.save_config(work,src)
  self.assertTrue(p.workspace_info(work)['changes']);h=p.workspace_info(work)['history'][0]['id'];p.restore_history(work,h)
  self.assertFalse(p.workspace_info(work)['changes'])
 def test_dependency_order(self):
  work=self.work();addon=self.source_kext('Addon',{'test.Base':'1.0'});base=self.source_kext('Base')
  p.import_item(work,addon,'kext');p.import_item(work,base,'kext')
  self.assertEqual([k['name'] for k in p.workspace_info(work)['kexts']],['Base','Addon'])
 def test_cycle_rejected(self):
  work=self.work();a=self.source_kext('A',{'test.B':'1'});b=self.source_kext('B',{'test.A':'1'})
  p.import_item(work,a,'kext');before=p.hashes(work/'Candidate')
  with self.assertRaises(ValueError):p.import_item(work,b,'kext')
  self.assertEqual(p.hashes(work/'Candidate'),before)
 def test_lock_rejected(self):
  work=self.work();(work/'.edit-lock').write_text('')
  with self.assertRaises(ValueError):p.set_kext_enabled(work,'A.kext',False)
 def test_tampered_history_rejected(self):
  work=self.work();src=self.source_kext();p.import_item(work,src,'kext');rev=p.workspace_info(work)['history'][0]['id']
  (work/'History'/rev/'OpenCore.efi').write_text('tamper')
  with self.assertRaises(ValueError):p.restore_history(work,rev)
 def test_workspace_source_import_rejected(self):
  work=self.work();src=self.source_kext();p.import_item(work,src,'kext')
  with self.assertRaises(ValueError):p.import_item(work,work/'Candidate/Kexts/Demo.kext','kext',True)
 def validator(self,version):
  tool=self.root/'ocvalidate';tool.write_text('#!/bin/sh\nif [ "$1" = "--version" ]; then echo "OpenCore '+version+'"; exit 0; fi\necho "No issues found"\n');tool.chmod(0o755);return tool
 def test_validator_version_match(self):
  work=self.work();tool=self.validator('1.0.4');before=p.hashes(work/'Candidate');r=p.validate_candidate(work,tool,'1.0.4')
  self.assertTrue(r['ok']);self.assertEqual(p.hashes(work/'Candidate'),before)
 def test_validator_version_mismatch(self):
  work=self.work();tool=self.validator('1.0.3')
  with self.assertRaises(ValueError):p.validate_candidate(work,tool,'1.0.4')

 def test_replace_refreshes_executable_reference(self):
  src=self.source_kext();work=self.work();p.import_item(work,src,'kext')
  info=plistlib.loads((src/'Contents/Info.plist').read_bytes());info['CFBundleExecutable']='DemoNew';(src/'Contents/Info.plist').write_bytes(plistlib.dumps(info));(src/'Contents/MacOS/DemoNew').write_bytes(b'fixture');(src/'Contents/MacOS/Demo').unlink()
  p.import_item(work,src,'kext',True)
  _,cfg,_=p.inspect_efi(work/'Candidate');self.assertEqual(cfg['Kernel']['Add'][0]['ExecutablePath'],'Contents/MacOS/DemoNew')
