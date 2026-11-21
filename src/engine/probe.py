#!/usr/bin/env python3
"""Noor Probe 1.0: read-only host collection and isolated EFI workspace operations."""
import argparse, base64, concurrent.futures, contextlib, datetime, difflib, hashlib, json, os, pathlib, platform, plistlib, re, shutil, subprocess, sys, tempfile, urllib.request, uuid
P = pathlib.Path
GUID = '7C436110-AB2A-4BBB-A880-FE41995C9F82'
SOURCES = {
 'guide':'https://dortania.github.io/OpenCore-Install-Guide/',
 'limits':'https://dortania.github.io/OpenCore-Install-Guide/macos-limits.html',
 'wifi':'https://openintelwireless.github.io/itlwm/Installation.html',
 'audio':'https://github.com/acidanthera/AppleALC/wiki/Installation-and-usage',
 'oc':'https://github.com/acidanthera/OpenCorePkg/releases'}
REPOS = {'Lilu':'acidanthera/Lilu','WhateverGreen':'acidanthera/WhateverGreen','AppleALC':'acidanthera/AppleALC','VirtualSMC':'acidanthera/VirtualSMC','itlwm':'OpenIntelWireless/itlwm','AirportItlwm':'OpenIntelWireless/itlwm','IntelBluetoothFirmware':'OpenIntelWireless/IntelBluetoothFirmware','VoodooPS2Controller':'acidanthera/VoodooPS2','VoodooI2C':'VoodooI2C/VoodooI2C'}
def clean(v):
    if isinstance(v, bytes): return {'hex':v.hex()}
    if isinstance(v, dict): return {k:clean(x) for k,x in v.items() if not re.search(r'serial|uuid|mlb|rom$|mac_address|ssid|bssid|user_name',k,re.I)}
    if isinstance(v, list): return [clean(x) for x in v]
    if isinstance(v, datetime.datetime): return v.isoformat()
    return v

def command(args, timeout=50):
    try:
        r = subprocess.run(args, capture_output=True, timeout=timeout, check=False)
        return {'ok':r.returncode==0,'exit':r.returncode,'stdout':r.stdout.decode(errors='replace'),'stderr':r.stderr.decode(errors='replace')[:1000]}
    except (OSError,subprocess.TimeoutExpired) as e: return {'ok':False,'exit':-1,'stdout':'','stderr':str(e)}

def collect():
    if platform.system()!='Darwin': raise ValueError('SYS-001: الفحص المباشر يحتاج macOS؛ استخدم ملف fixture للاختبارات.')
    result = {'os':platform.mac_ver()[0], 'kernel':platform.release(), 'arch':platform.machine(), 'probes':{}}
    groups = {'hardware':['SPHardwareDataType','SPMemoryDataType','SPDisplaysDataType','SPPCIDataType'], 'network':['SPAirPortDataType','SPBluetoothDataType','SPEthernetDataType'], 'devices':['SPAudioDataType','SPUSBDataType','SPNVMeDataType','SPSerialATADataType','SPPowerDataType','SPStorageDataType']}
    def read_profile(types):
        r=command(['/usr/sbin/system_profiler','-json','-detailLevel','basic',*types],90)
        try: r['data']=clean(json.loads(r.pop('stdout'))) if r['ok'] else {}; r.pop('stdout',None)
        except ValueError: r.update(ok=False,data={},stderr='Invalid system_profiler JSON'); r.pop('stdout',None)
        return r
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(groups)) as pool:
        futures={pool.submit(read_profile,types):name for name,types in groups.items()}
        for future in concurrent.futures.as_completed(futures):
            result['probes'][futures[future]]=future.result()
    extra={'kexts':['/usr/bin/kmutil','showloaded','--list-only'], 'pci':['/usr/sbin/ioreg','-a','-l','-r','-c','IOPCIDevice'], 'battery':['/usr/sbin/ioreg','-a','-r','-c','AppleSmartBattery'], 'power':['/usr/bin/pmset','-g','custom']}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(extra)) as pool:
        futures={pool.submit(command,args):name for name,args in extra.items()}
        for future in concurrent.futures.as_completed(futures):
            name=futures[future];r=future.result()
            if name in ('pci','battery'):
                try: r['data']=clean(plistlib.loads(r.pop('stdout').encode())) if r['ok'] else []; r.pop('stdout',None)
                except Exception: r.update(ok=False,data=[],stderr='IORegistry decoding failed'); r.pop('stdout',None)
            result['probes'][name]=r
    import advanced
    result["deep"]=advanced.deep_collect(result)
    return result

def resolve_oc(path):
    p=P(path).expanduser().resolve()
    for candidate in (p,p/'OC',p/'EFI'/'OC'):
        if (candidate/'config.plist').is_file(): return candidate
    raise ValueError('EFI-001: اختر مجلد EFI أو OC يحتوي config.plist')

def safe_child(root, relative):
    p=(root/relative).resolve()
    if not p.is_relative_to(root.resolve()): raise ValueError('EFI-009: مسار خارج EFI')
    return p

def inspect_efi(path):
    oc=resolve_oc(path)
    with (oc/'config.plist').open('rb') as f: config=plistlib.load(f)
    if not isinstance(config,dict): raise ValueError('EFI-002: config ليس قاموس plist')
    entries=config.get('Kernel',{}).get('Add',[])
    if not isinstance(entries,list): raise ValueError('EFI-002: Kernel/Add ليس قائمة')
    kexts=[]
    for entry in entries:
        if not isinstance(entry,dict): raise ValueError('EFI-002: مدخل Kernel/Add غير صالح')
        rel=entry.get('BundlePath','')
        p=safe_child(oc/'Kexts',rel)
        info={}
        try: info=plistlib.loads((p/'Contents/Info.plist').read_bytes())
        except (OSError,plistlib.InvalidFileException): pass
        kexts.append({'name':P(rel).name.removesuffix('.kext'),'path':rel,'enabled':entry.get('Enabled',False),'exists':p.is_dir(),'version':info.get('CFBundleVersion','unknown'),'id':info.get('CFBundleIdentifier',''),'min':entry.get('MinKernel',''),'max':entry.get('MaxKernel',''),'executable':entry.get('ExecutablePath',''),'plist':entry.get('PlistPath','')})
    return oc,config,kexts

def kernel_range_status(kernel,minimum,maximum):
    def version(value):
        match=re.fullmatch(r'(\d+)(?:\.(\d+))?(?:\.(\d+))?',str(value or ''))
        return tuple(int(x or 0) for x in match.groups()) if match else None
    current=version(kernel);low=version(minimum);high=version(maximum)
    if current is None or (minimum and low is None) or (maximum and high is None):return 'unknown'
    if (low is not None and current<low) or (high is not None and current>high):return 'outside-range'
    if low is not None or high is not None:return 'inside-range'
    return 'not-set'

def analyze(snapshot,efi=None,updates=False):
    findings=[]
    def add(code,category,severity,title,detail,action,source='guide',confidence='confirmed'):
        findings.append(dict(id=code+'-'+str(len(findings)),code=code,category=category,severity=severity,title=title,detail=detail,action=action,source=SOURCES[source],confidence=confidence))
    probes=snapshot.get('probes',{})
    for name,p in probes.items():
        if not p.get('ok'): add('SYS-010','النظام','warning','بيانات غير مكتملة',name+': '+p.get('stderr',''),'أعد الفحص؛ غياب البيانات لا يعني غياب الجهاز.')
    oc=None; config={}; kexts=[]
    if efi:
        try: oc,config,kexts=inspect_efi(efi)
        except Exception as e: add('EFI-002','EFI','error','تعذر تحليل EFI',str(e),'راجع صيغة config.plist والمسارات.')
    else: add('EFI-001','EFI','info','لم يتم اختيار EFI','يمكن فحص النظام لكن لا يمكن استنتاج إعدادات الإقلاع.','اختر مجلد EFI المركّب أو نسخة منه.')
    enabled=[k for k in kexts if k['enabled']]; names=[k['name'] for k in enabled]
    kernel=snapshot.get('kernel','')
    for k in kexts:
        k['host_kernel']=kernel
        k['host_kernel_range']=kernel_range_status(kernel,k.get('min'),k.get('max'))
        if k['enabled'] and k['host_kernel_range']=='outside-range':
            add('EFI-106','EFI','info','شرط الإقلاع يستبعد إصدار macOS الحالي',k['name']+' مفعّل في config لكن MinKernel/MaxKernel لا يشمل Darwin '+kernel+'. هذا يصف شرط OpenCore فقط، ولا يثبت عدم توافق التعريف مع نظام آخر.','إذا كانت هذه EFI مخصصة لهذا الجهاز، راجع مدى النواة مقابل النظام المستهدف. إذا كانت EFI لجهاز آخر، تجاهل مقارنة النظام الحالي.','oc')
    for k in enabled:
        if not k['exists']: add('EFI-101','EFI','error','Kext مفعّل وملفه مفقود',k['path'],'أصلح المرجع أو أضف النسخة المناسبة داخل مساحة العمل.')
        else:
            for field in ('executable','plist'):
                if k[field] and not safe_child(oc/'Kexts',k['path']+'/'+k[field]).is_file(): add('EFI-102','EFI','error','مسار داخلي مفقود',k['path']+'/'+k[field],'راجع ExecutablePath وPlistPath.')
    if len(names)!=len(set(names)): add('EFI-103','EFI','warning','تعريف مكرر','توجد أسماء kext مفعّلة أكثر من مرة.','راجع شروط MinKernel/MaxKernel؛ قد تكون بدائل مقصودة.')
    if 'itlwm' in names and 'AirportItlwm' in names: add('NET-101','الشبكة','error','تعارض تعريفي Intel Wi-Fi','itlwm وAirportItlwm مفعّلان معاً.','استخدم واحداً فقط بعد مطابقة إصدار macOS.','wifi')
    for dep in ('WhateverGreen','AppleALC'):
        if dep in names:
            if 'Lilu' not in names: add('KEXT-201','EFI','error','اعتماد Lilu مفقود',dep+' يحتاج Lilu.','أضف Lilu المتوافق وفعّله قبله.','audio' if dep=='AppleALC' else 'guide')
            elif names.index('Lilu')>names.index(dep): add('KEXT-202','EFI','warning','ترتيب اعتماد يحتاج مراجعة',dep+' يسبق Lilu.','رتّب Lilu قبل إضافاته داخل النسخة التجريبية.')
    if oc:
        for section,key,folder,pathkey in [('ACPI','Add','ACPI','Path'),('UEFI','Drivers','Drivers','Path')]:
            for item in config.get(section,{}).get(key,[]):
                rel=item if isinstance(item,str) else item.get(pathkey,''); active=True if isinstance(item,str) else item.get('Enabled',False)
                if active and rel and not safe_child(oc/folder,rel).is_file(): add('EFI-104','EFI','error','ملف إقلاع مفقود',folder+'/'+rel,'راجع المرجع في النسخة التجريبية.')
        if not (oc/'OpenCore.efi').is_file(): add('EFI-105','EFI','error','OpenCore.efi مفقود','المجلد المختار غير مكتمل.','اختر EFI كاملة؛ لا تستخدم هذه النسخة للإقلاع.')
        add('EFI-110','EFI','info','التحقق البنيوي لا يكفي','لم يتم تشغيل ocvalidate.','استخدم ocvalidate من نفس إصدار OpenCore؛ راجع Docs/TOOLS.md.','oc')
    hardware=json.dumps(probes.get('hardware',{}).get('data',{})).lower()
    if 'nvidia' in hardware: add('GPU-301','الشاشة','warning','كرت NVIDIA يحتاج تحديد الدعم','تم رصد NVIDIA؛ الموديل وإصدار macOS يحددان الدعم.','راجع التوصيلات الفعلية للمخارج. GTX 1650 في جهازك المعروف غير مدعوم؛ لا تفترض أن HDMI على Intel.','limits','likely')
    add('BIO-401','البصمة','info','حد توافق بصمة اللابتوب','قارئ بصمة أجهزة PC لا يتحول إلى Touch ID بتعريف kext. لم نثبت وجود القارئ من هذا الفحص.','استخدم كلمة المرور؛ لا تثبت تعريفاً يدّعي إضافة Touch ID.','limits')
    for cat,code,detail,action in [('الصوت','AUD-501','وجود جهاز صوت أو AppleALC لا يثبت عمل السماعات والمايك.','اختبر السماعة والمايك والمنفذ؛ طابق Codec وlayout-id قبل أي تعديل.'),('الشبكة','NET-502','ظهور بطاقة الشبكة لا يثبت الاتصال أو توافق AirportItlwm مع نظامك.','اختبر Wi-Fi وBluetooth منفصلين؛ itlwm يحتاج HeliPort.'),('الشاشة','GPU-503','كشف الشاشة لا يثبت التسريع أو السطوع أو توصيل HDMI.','اختبر التسريع والسطوع ومخرج USB-C/HDMI كل واحد منفصلاً.'),('الطاقة','PWR-601','السكون والبطارية وUSB واللمس تحتاج اختبارات فعلية.','اختبر السكون والاستيقاظ والبطارية ولوحة اللمس ومنافذ USB؛ لا تولّد ACPI عشوائياً.')]:
        add(code,cat,'info','اختبار وظيفي مطلوب',detail,action,'audio' if cat=='الصوت' else 'guide','manual')
    releases=[]
    if updates:
        requested={}
        for k in kexts:
            repo=REPOS.get(k['name'])
            if repo: requested.setdefault(repo,[]).append(k)
        def fetch_latest(repo):
            req=urllib.request.Request('https://api.github.com/repos/'+repo+'/releases/latest',headers={'User-Agent':'NoorProbe/2.0','Accept':'application/vnd.github+json'})
            with urllib.request.urlopen(req,timeout=6) as response:return json.load(response)
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4,max(1,len(requested)))) as pool:
            futures={pool.submit(fetch_latest,repo):repo for repo in requested}
            for future in concurrent.futures.as_completed(futures):
                repo=futures[future]
                try:
                    data=future.result();latest=data.get('tag_name','unknown')
                    for k in requested[repo]:releases.append({'name':k['name'],'installed':k['version'],'latest':latest,'url':data['html_url'],'note':'اختلاف الإصدار يحتاج مراجعة توافق؛ لا يعني أن التحديث مناسب.'})
                except Exception as e:
                    for k in requested[repo]:releases.append({'name':k['name'],'installed':k['version'],'latest':'unavailable','url':'https://github.com/'+repo+'/releases','note':str(e)[:150]})
    return dict(version='2.0.0-beta.3',created=datetime.datetime.now(datetime.timezone.utc).isoformat(),snapshot=clean(snapshot),kexts=kexts,findings=findings,releases=releases,scope='Read-only diagnosis. Unknown is not supported or unsupported. No automatic EFI installation.')

def hashes(root):
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(root.rglob('*')) if p.is_file()}

def workspace(source,destination):
    oc=resolve_oc(source); dest=P(destination).expanduser().resolve()
    src=oc.parent if oc.parent.name=='EFI' else oc
    if dest.exists() or dest.is_relative_to(src) or src.is_relative_to(dest): raise ValueError('SAFE-001: اختر مجلداً جديداً خارج المصدر')
    if any(p.is_symlink() for p in src.rglob('*')): raise ValueError('SAFE-002: الروابط الرمزية غير مسموحة في نسخة EFI')
    before=hashes(src)
    dest.mkdir(parents=True)
    try:
        shutil.copytree(src,dest/'Backup'); shutil.copytree(src,dest/'Candidate')
        if hashes(dest/'Backup')!=before or hashes(dest/'Candidate')!=before or hashes(src)!=before: raise ValueError('SAFE-003: فشل تطابق البصمات')
        (dest/'manifest.json').write_text(json.dumps({'source_hashes':before,'created':datetime.datetime.now(datetime.timezone.utc).isoformat()},indent=2))
    except Exception:
        # Preserve incomplete work for inspection. Never delete the original.
        raise
    return {'workspace':str(dest),'message':'نسخة احتياطية ونسخة مرشحة متطابقتان. المصدر لم يتغير.'}

def patch_layout(work,layout):
    if not 1<=layout<=255: raise ValueError('PATCH-001: layout-id بين 1 و255؛ القيمة الصحيحة تتطلب معرفة Codec')
    root=P(work).resolve()
    if not (root/'manifest.json').is_file(): raise ValueError('SAFE-004: مساحة عمل غير صالحة')
    oc=resolve_oc(root/'Candidate'); backup=resolve_oc(root/'Backup')
    manifest=json.loads((root/'manifest.json').read_text())
    if hashes(root/'Backup')!=manifest['source_hashes']: raise ValueError('SAFE-005: النسخة الاحتياطية تغيّرت')
    # Refuse symlink substitution after workspace creation.
    if any(p.is_symlink() for p in root.rglob('*')): raise ValueError('SAFE-002: روابط رمزية غير مسموحة')
    cfg=plistlib.loads((oc/'config.plist').read_bytes())
    nv=cfg.setdefault('NVRAM',{}).setdefault('Add',{}).setdefault(GUID,{})
    old=nv.get('boot-args','')
    if not isinstance(old,str): raise ValueError('PATCH-002: boot-args ليست نصاً')
    new=' '.join([x for x in old.split() if not x.startswith('alcid=')]+['alcid='+str(layout)])
    nv['boot-args']=new
    data=plistlib.dumps(cfg,sort_keys=False); plistlib.loads(data)
    target=oc/'config.plist'
    fd,tmp=tempfile.mkstemp(dir=str(oc),prefix='.noor-')
    try:
        with os.fdopen(fd,'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp,target)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    result={'before':old,'after':new,'target':'Candidate/config.plist','note':'لم يتم التثبيت. شغّل ocvalidate واختبر USB قبل اعتماد النسخة.'}
    (root/'last-change.json').write_text(json.dumps(result,ensure_ascii=False,indent=2))
    return result

# Editing is deliberately constrained to managed Candidate copies.
def checked_workspace(path):
    root=P(path).expanduser().resolve()
    if not (root/'manifest.json').is_file(): raise ValueError('SAFE-004: مساحة عمل غير صالحة')
    if any(p.is_symlink() for p in root.rglob('*')): raise ValueError('SAFE-002: الروابط الرمزية غير مسموحة')
    m=json.loads((root/'manifest.json').read_text())
    if hashes(root/'Backup')!=m['source_hashes']: raise ValueError('SAFE-005: النسخة الاحتياطية تغيرت')
    resolve_oc(root/'Candidate')
    return root

@contextlib.contextmanager
def edit_transaction(path,label):
    root=checked_workspace(path)
    lock=root/'.edit-lock'
    try: fd=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    except FileExistsError: raise ValueError('SAFE-006: عملية تعديل أخرى تعمل أو قفل قديم. أغلق التطبيق وراجع القفل.')
    os.close(fd)
    token=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid.uuid4().hex[:8]
    checkpoint=root/'History'/token
    copied=False
    try:
        size=sum(f.stat().st_size for f in (root/'Candidate').rglob('*') if f.is_file())
        if shutil.disk_usage(root).free < size*3+10*1024*1024: raise ValueError('SAFE-007: مساحة غير كافية لنقطة استعادة')
        shutil.copytree(root/'Candidate',checkpoint); copied=True
        yield root
        inspect_efi(root/'Candidate')
        record={'id':token,'label':label,'created':datetime.datetime.now(datetime.timezone.utc).isoformat(),'before':hashes(checkpoint),'after':hashes(root/'Candidate')}
        with (root/'history.jsonl').open('a') as f: f.write(json.dumps(record,ensure_ascii=False)+'\n')
    except Exception:
        if copied:
            shutil.rmtree(root/'Candidate')
            shutil.copytree(checkpoint,root/'Candidate')
        raise
    finally: lock.unlink(missing_ok=True)

def workspace_info(path):
    root=checked_workspace(path); base=hashes(root/'Backup'); current=hashes(root/'Candidate')
    changes=[]
    for rel in sorted(set(base)|set(current)):
        if base.get(rel)!=current.get(rel): changes.append({'path':rel,'change':'added' if rel not in base else 'removed' if rel not in current else 'modified'})
    oc,cfg,kexts=inspect_efi(root/'Candidate')
    records=[]
    if (root/'history.jsonl').exists(): records=[json.loads(x) for x in (root/'history.jsonl').read_text().splitlines() if x.strip()]
    return {'workspace':str(root),'changes':changes,'files':list(current),'kexts':kexts,'history':[{'id':r['id'],'label':r['label'],'created':r['created']} for r in records], 'config':plistlib.dumps(cfg,sort_keys=False).decode(),'candidate':str(root/'Candidate')}

def import_item(work,source,kind,replace=False):
    source_path=P(source).expanduser()
    if source_path.is_symlink(): raise ValueError('IMPORT-001: مصدر برابط رمزي غير مسموح')
    src=source_path.resolve()
    if not src.exists(): raise ValueError('IMPORT-001: المصدر غير موجود')
    folder={'kext':'Kexts','acpi':'ACPI','driver':'Drivers'}.get(kind)
    if not folder: raise ValueError('IMPORT-002: نوع ملف غير معروف')
    if kind=='kext':
        if src.suffix.lower()!='.kext' or not src.is_dir(): raise ValueError('IMPORT-003: اختر حزمة .kext مفكوكة وليست ZIP')
        if any(f.is_symlink() for f in src.rglob('*')): raise ValueError('IMPORT-001: روابط رمزية داخل الحزمة')
        plist=src/'Contents/Info.plist'
        info=plistlib.loads(plist.read_bytes())
        if not info.get('CFBundleIdentifier'): raise ValueError('IMPORT-004: معرف الحزمة مفقود')
    elif not src.is_file() or src.suffix.lower()!=('.aml' if kind=='acpi' else '.efi'):
        raise ValueError('IMPORT-005: امتداد الملف غير مطابق')
    # Reject recursive imports from the managed workspace.
    root=checked_workspace(work)
    if src.is_relative_to(root) or root.is_relative_to(src): raise ValueError('IMPORT-006: اختر مصدراً خارج مساحة العمل')
    with edit_transaction(work,'Import '+kind+': '+src.name) as root:
        oc,cfg,_=inspect_efi(root/'Candidate'); target=oc/folder/src.name
        if target.exists() and not replace: raise ValueError('IMPORT-007: الملف موجود. فعّل الاستبدال بعد مراجعة النسختين.')
        target.parent.mkdir(exist_ok=True)
        if target.is_dir(): shutil.rmtree(target)
        elif target.exists(): target.unlink()
        if src.is_dir(): shutil.copytree(src,target)
        else: shutil.copy2(src,target)
        registered=[]
        if kind=='kext':
            bundles=[target]+sorted(target.glob('Contents/PlugIns/*.kext'))
            entries=cfg.setdefault('Kernel',{}).setdefault('Add',[])
            for bundle in bundles:
                info=plistlib.loads((bundle/'Contents/Info.plist').read_bytes())
                rel=str(bundle.relative_to(oc/'Kexts')); binary=info.get('CFBundleExecutable','')
                executable='Contents/MacOS/'+binary if binary else ''
                if binary and not safe_child(bundle,executable).is_file(): raise ValueError('IMPORT-008: CFBundleExecutable مفقود: '+rel)
                existing=next((e for e in entries if e.get('BundlePath')==rel),None)
                if existing is None:
                    entries.append({'Arch':'Any','BundlePath':rel,'Comment':'Imported by Noor Probe — verify compatibility','Enabled':True,'ExecutablePath':executable,'MaxKernel':'','MinKernel':'','PlistPath':'Contents/Info.plist'})
                else:
                    existing.update(ExecutablePath=executable,PlistPath='Contents/Info.plist')
                registered.append(rel)
            if replace:
                entries[:]=[e for e in entries if not e.get('BundlePath','').startswith(src.name+'/Contents/PlugIns/') or e.get('BundlePath') in registered]
            # Stable topological ordering of available bundle dependencies. Missing dependencies are diagnostic findings, not invented files.
            metadata={}
            for entry in entries:
                try:
                    info=plistlib.loads(safe_child(oc/'Kexts',entry['BundlePath']+'/Contents/Info.plist').read_bytes())
                    metadata[entry['BundlePath']]=info
                except (OSError,KeyError,plistlib.InvalidFileException): pass
            ordered=[]; pending=entries[:]; present={m.get('CFBundleIdentifier') for m in metadata.values()}
            while pending:
                done={metadata.get(e['BundlePath'],{}).get('CFBundleIdentifier') for e in ordered}
                ready=[e for e in pending if set(metadata.get(e['BundlePath'],{}).get('OSBundleLibraries',{})) & present <= done]
                if not ready: raise ValueError('IMPORT-009: اعتماد دائري في التعريفات؛ لم يتم التعديل')
                for e in ready: ordered.append(e); pending.remove(e)
            cfg['Kernel']['Add']=ordered
        else:
            section,key=('ACPI','Add') if kind=='acpi' else ('UEFI','Drivers')
            entries=cfg.setdefault(section,{}).setdefault(key,[])
            if any(isinstance(e,str) for e in entries): raise ValueError('IMPORT-010: صيغة Drivers قديمة. حدّث البنية يدوياً في config قبل الاستيراد')
            if not any(e.get('Path')==src.name for e in entries):
                entry={'Comment':'Imported by Noor Probe — verify compatibility','Enabled':True,'Path':src.name}
                if kind=='driver': entry.update(Arguments='',LoadEarly=False)
                entries.append(entry)
            registered=[src.name]
        (oc/'config.plist').write_bytes(plistlib.dumps(cfg,sort_keys=False))
    return {'registered':registered,'message':'أُضيفت الملفات والمراجع إلى Candidate فقط. الترتيب يراعي الاعتمادات المتاحة؛ راجع التوافق وحدود Kernel وocvalidate قبل الإقلاع.'}

def set_kext_enabled(work,bundle,enabled):
    with edit_transaction(work,'Kext '+bundle+': '+str(enabled)) as root:
        oc,cfg,_=inspect_efi(root/'Candidate'); found=False
        for e in cfg.get('Kernel',{}).get('Add',[]):
            if e.get('BundlePath')==bundle: e['Enabled']=enabled; found=True
        if not found: raise ValueError('EDIT-001: المرجع غير موجود')
        (oc/'config.plist').write_bytes(plistlib.dumps(cfg,sort_keys=False))
    return {'message':'تم تحديث التفعيل داخل Candidate فقط.'}

def save_config(work,xmlfile):
    raw=P(xmlfile).read_bytes()
    if len(raw)>4*1024*1024: raise ValueError('EDIT-002: config أكبر من حد المحرر 4 MiB')
    config=plistlib.loads(raw)
    if not isinstance(config,dict): raise ValueError('EFI-002: plist يجب أن يكون قاموساً')
    for key in ('ACPI','Booter','DeviceProperties','Kernel','Misc','NVRAM','PlatformInfo','UEFI'):
        if key in config and not isinstance(config[key],dict): raise ValueError('EDIT-003: قسم غير صالح: '+key)
    if not isinstance(config.get('Kernel',{}).get('Add',[]),list): raise ValueError('EDIT-003: Kernel/Add يجب أن تكون قائمة')
    with edit_transaction(work,'Save config.plist XML') as root:
        oc=resolve_oc(root/'Candidate'); (oc/'config.plist').write_bytes(plistlib.dumps(config,sort_keys=False))
    return {'message':'تم حفظ config.plist في Candidate بعد تحليل plist. يلزم ocvalidate مطابق؛ صحة XML لا تعني صحة إعدادات OpenCore.'}

def restore_history(work,revision):
    root=checked_workspace(work)
    if not re.fullmatch(r'[0-9]{8}T[0-9]{6}-[0-9a-f]{8}',revision): raise ValueError('EDIT-004: معرف نقطة استعادة غير صالح')
    source=root/'History'/revision
    if not source.is_dir(): raise ValueError('EDIT-004: نقطة الاستعادة غير موجودة')
    records=[json.loads(x) for x in (root/'history.jsonl').read_text().splitlines() if x.strip()]
    record=next((r for r in records if r['id']==revision),None)
    if not record or hashes(source)!=record['before']: raise ValueError('SAFE-008: نقطة الاستعادة لا تطابق سجلها')
    with edit_transaction(work,'Restore before '+revision) as root:
        shutil.rmtree(root/'Candidate'); shutil.copytree(source,root/'Candidate')
    return {'message':'تمت استعادة Candidate إلى ما قبل العملية المختارة. الأصل وBackup لم يتغيرا.'}

def validate_candidate(work,tool,expected):
    root=checked_workspace(work)
    path=P(tool).expanduser().resolve()
    if path.name!='ocvalidate' or not path.is_file() or not os.access(path,os.X_OK): raise ValueError('VALIDATE-001: اختر ملف ocvalidate التنفيذي من الحزمة الرسمية')
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',expected): raise ValueError('VALIDATE-002: حدد إصدار OpenCore مثل 1.0.4 دون تخمين')
    version=command([str(path),'--version'],15)
    text=version['stdout']+'\n'+version['stderr']
    if not re.search(r'(?<![0-9.])'+re.escape(expected)+r'(?![0-9.])',text): raise ValueError('VALIDATE-003: إصدار الأداة لم يطابق الإصدار الذي حددته. Output: '+text[:1000])
    result=command([str(path),str(resolve_oc(root/'Candidate')/'config.plist')],45)
    record={'expected_version':expected,'version_output':text[:2000],'ok':result['ok'],'exit':result['exit'],'output':(result['stdout']+'\n'+result['stderr'])[:24000],'note':'مطابقة الإصدار هنا مع ما أدخلته أنت، وليست كشفاً آلياً لإصدار OpenCore. نجاح ocvalidate لا يثبت توافق العتاد أو الإقلاع.'}
    (root/'ocvalidate-result.json').write_text(json.dumps(record,ensure_ascii=False,indent=2))
    return record

def main():
    if sys.version_info < (3,9):
        print(json.dumps({'error':'SYS-002: Python 3.9+ required'})); sys.exit(1)
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest='cmd',required=True)
    s=sub.add_parser('scan'); s.add_argument('--efi'); s.add_argument('--fixture'); s.add_argument('--updates',action='store_true'); s.add_argument('--output')
    s=sub.add_parser('workspace'); s.add_argument('source'); s.add_argument('destination')
    s=sub.add_parser('layout'); s.add_argument('workspace'); s.add_argument('value',type=int)
    s=sub.add_parser('info'); s.add_argument('workspace')
    s=sub.add_parser('import'); s.add_argument('workspace'); s.add_argument('source'); s.add_argument('--kind',choices=['kext','acpi','driver'],required=True); s.add_argument('--replace',action='store_true')
    s=sub.add_parser('toggle'); s.add_argument('workspace'); s.add_argument('bundle'); s.add_argument('--enabled',choices=['yes','no'],required=True)
    s=sub.add_parser('config'); s.add_argument('workspace'); s.add_argument('xmlfile')
    s=sub.add_parser('restore'); s.add_argument('workspace'); s.add_argument('revision')
    s=sub.add_parser('validate'); s.add_argument('workspace'); s.add_argument('tool'); s.add_argument('version')
    a=p.parse_args()
    try:
        if a.cmd=='scan':
            snapshot=json.loads(P(a.fixture).read_text()) if a.fixture else collect()
            result=analyze(snapshot,a.efi,a.updates)
            if a.output: P(a.output).write_text(json.dumps(result,ensure_ascii=False,indent=2))
        elif a.cmd=='workspace': result=workspace(a.source,a.destination)
        elif a.cmd=='layout':
            with edit_transaction(a.workspace,'Change alcid to '+str(a.value)): result=patch_layout(a.workspace,a.value)
        elif a.cmd=='info': result=workspace_info(a.workspace)
        elif a.cmd=='import': result=import_item(a.workspace,a.source,a.kind,a.replace)
        elif a.cmd=='toggle': result=set_kext_enabled(a.workspace,a.bundle,a.enabled=='yes')
        elif a.cmd=='config': result=save_config(a.workspace,a.xmlfile)
        elif a.cmd=='restore': result=restore_history(a.workspace,a.revision)
        else: result=validate_candidate(a.workspace,a.tool,a.version)
        print(json.dumps(result,ensure_ascii=False))
    except Exception as e:
        print(json.dumps({'error':str(e)},ensure_ascii=False)); sys.exit(1)
if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='advanced':
        import advanced; advanced.main()
    else: main()
