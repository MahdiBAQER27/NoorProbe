"""Noor Probe 2.0.0 Beta 3: evidence layers, EFI discovery, opt-in release downloads."""
import argparse, hashlib, json, os, pathlib, platform, plistlib, re, shutil, stat, sys, tempfile, urllib.parse, urllib.request, uuid, zipfile
import probe as core
P=pathlib.Path
LIMIT=200*1024*1024
REPOS=sorted(set(core.REPOS.values())|{'acidanthera/OpenCorePkg','OpenIntelWireless/HeliPort','OpenIntelWireless/IntelBluetoothFirmware'})
def walk(nodes):
    for node in nodes:
        if not isinstance(node,dict): continue
        yield node
        yield from walk(node.get('IORegistryEntryChildren',[]))
def device_children(nodes,bus):
    for node in nodes:
        if not isinstance(node,dict):continue
        if bus=='PCI' and 'vendor-id' in node:continue
        if bus=='USB' and 'idVendor' in node:continue
        yield node
        yield from device_children(node.get('IORegistryEntryChildren',[]),bus)
def number(v):
    if isinstance(v,dict) and 'hex' in v:
        try:return int.from_bytes(bytes.fromhex(v['hex'])[:4],'little')
        except ValueError:return None
    if isinstance(v,bytes):return int.from_bytes(v[:4],'little')
    return v if isinstance(v,int) else None
def hexid(v):
    n=number(v);return f'{n:04x}' if n is not None else 'unknown'
def registry_rows(nodes,bus):
    rows=[];seen=set()
    for node in walk(nodes):
        if bus=='PCI' and 'vendor-id' not in node:continue
        if bus=='USB' and 'idVendor' not in node:continue
        key=str(node.get('IORegistryEntryID',node.get('IORegistryEntryName','')))
        if key in seen:continue
        seen.add(key)
        children=list(device_children(node.get('IORegistryEntryChildren',[]),bus))
        interfaces=sorted({x['BSD Name'] for x in children if isinstance(x.get('BSD Name'),str)})
        services=sorted({str(x.get('IOClass',x.get('IOObjectClass',''))) for x in children if x.get('IOClass') or x.get('IOObjectClass')})
        bundles=sorted({str(x['CFBundleIdentifier']) for x in children if x.get('CFBundleIdentifier')})
        rows.append({'bus':bus,'name':str(node.get('IORegistryEntryName','Unknown')),'vendor':hexid(node.get('vendor-id' if bus=='PCI' else 'idVendor')),'device':hexid(node.get('device-id' if bus=='PCI' else 'idProduct')),'present':'enumerated','recognized':'interface-created' if interfaces else 'unknown','driver_services':services[:30],'driver_bundle_candidates':bundles[:20],'interfaces':interfaces,'functional':'manual-test-required','note':'الخدمات الأبناء دليل فني للمراجعة، وليست إثباتاً قطعياً لتعريف مربوط بهذه القطعة أو لعملها.'})
    return rows

def network_rows(ports,states,default_interface):
    rows=[]
    for match in re.finditer(r'Hardware Port:\s*([^\n]+)\nDevice:\s*([a-zA-Z0-9]+)',ports):
        name,dev=match.groups();text=states.get(dev,{}).get('ifconfig','')
        rows.append({'name':name,'interface':dev,'recognized':True,'link':'active' if re.search(r'status:\s*active\b',text) else 'inactive' if re.search(r'status:\s*inactive\b',text) else 'unknown','has_ipv4':bool(re.search(r'\binet\s+(?!127\.)',text)),'default_route':dev==default_interface,'radio':states.get(dev,{}).get('radio','unknown'),'internet':'not-tested','note':'رابط نشط أو عنوان IP لا يثبت وصول الإنترنت. default_route يعني واجهة المسار الافتراضي IPv4، وليس كل حركة الجهاز.'})
    return rows

def deep_collect(snapshot):
    probes=snapshot.get('probes',{}); pci=probes.get('pci',{}).get('data',[])
    result={'devices':registry_rows(pci,'PCI'),'network':[],'coverage':['macOS-visible PCI/USB only; BIOS-disabled or ACPI-hidden devices may be absent'],'errors':[]}
    usb=core.command(['/usr/sbin/ioreg','-a','-l','-r','-c','IOUSBHostDevice'],60)
    try:
        if not usb['ok']:raise ValueError(usb['stderr'])
        result['devices']+=registry_rows(plistlib.loads(usb['stdout'].encode()),'USB')
    except Exception as e:result['errors'].append('USB: '+str(e)[:500])
    ports=core.command(['/usr/sbin/networksetup','-listallhardwareports'])
    route=core.command(['/sbin/route','-n','get','default'])
    default=re.search(r'interface:\s*(\w+)',route['stdout']);default=default.group(1) if default else ''
    states={}
    for name,dev in re.findall(r'Hardware Port:\s*([^\n]+)\nDevice:\s*([a-zA-Z0-9]+)',ports['stdout']):
        states[dev]={'ifconfig':core.command(['/sbin/ifconfig',dev])['stdout']}
        if 'wi-fi' in name.lower() or 'airport' in name.lower():
            r=core.command(['/usr/sbin/networksetup','-getairportpower',dev]);text=r['stdout']
            states[dev]['radio']='on' if re.search(r':\s*On\b',text) else 'off' if re.search(r':\s*Off\b',text) else 'unknown'
    result['network']=network_rows(ports['stdout'],states,default)
    if not ports['ok']:result['errors'].append('networksetup: '+ports['stderr'])
    for device in result['devices']:
        loaded=probes.get('kexts',{})
        device['loaded_bundle_candidates']=[b for b in device['driver_bundle_candidates'] if loaded.get('ok') and re.search(r'(?<![A-Za-z0-9_.-])'+re.escape(b)+r'(?![A-Za-z0-9_.-])',loaded.get('stdout',''))]
        device['loaded_check']='available' if loaded.get('ok') else 'unavailable'
        device['network_evidence']=[r for r in result['network'] if r['interface'] in device['interfaces']]
    return result

def disk_info(identifier):
    if not re.fullmatch(r'disk\d+s\d+',identifier):raise ValueError('EFI-201: معرف قسم غير صالح')
    r=core.command(['/usr/sbin/diskutil','info','-plist',identifier])
    if not r['ok']:raise ValueError('EFI-202: '+r['stderr'])
    d=plistlib.loads(r['stdout'].encode())
    if d.get('Content')!='EFI' and str(d.get('PartitionType','')).upper()!='C12A7328-F81F-11D2-BA4B-00A0C93EC93B':raise ValueError('EFI-203: القسم ليس EFI')
    return d

def efi_partitions(tree,info_lookup):
    out=[]
    for disk in tree.get('AllDisksAndPartitions',[]):
        for part in disk.get('Partitions',[]):
            if part.get('Content')!='EFI':continue
            ident=part['DeviceIdentifier']
            try:
                detail=info_lookup(ident);mount=detail.get('MountPoint','');root=P(mount) if mount else None
                configs=[]
                if root:
                    for cfg in (root/'EFI/OC/config.plist',root/'OC/config.plist'):
                        if cfg.is_file():configs.append(str(cfg.parent))
                out.append({'id':ident,'disk':disk.get('DeviceIdentifier',''),'name':detail.get('VolumeName','EFI'),'size':part.get('Size',0),'mounted':bool(mount),'mount':mount,'readonly':detail.get('ReadOnlyVolume'),'configs':configs,'boot_source':'unknown'})
            except Exception as e:out.append({'id':ident,'error':str(e)})
    return out

def list_efi():
    if platform.system()!='Darwin':raise ValueError('EFI-200: اكتشاف EFI يحتاج macOS')
    r=core.command(['/usr/sbin/diskutil','list','-plist'])
    if not r['ok']:raise ValueError('EFI-202: '+r['stderr'])
    return {'partitions':efi_partitions(plistlib.loads(r['stdout'].encode()),disk_info),'note':'عرض أقسام GPT EFI لا يثبت قسم الإقلاع الفعلي؛ قد يكون OpenCore على USB أو وحدة FAT عادية غير مصنفة EFI.'}

def mount_efi(identifier):
    disk_info(identifier)
    r=core.command(['/usr/sbin/diskutil','mount',identifier])
    if not r['ok']:raise ValueError('EFI-204: تعذر تركيب قسم EFI للقراءة والكتابة عبر macOS. جرّب زر صلاحية المسؤول. '+r['stdout']+r['stderr'])
    return list_efi()

def cache_root():return P.home()/'Library/Application Support/NoorProbe/Downloads'
def repo_valid(repo):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repo) or '..' in repo:raise ValueError('GH-001: اسم المستودع يجب أن يكون owner/repo')
    return repo

def api(path):
    req=urllib.request.Request('https://api.github.com/'+path,headers={'User-Agent':'NoorProbe/1.2','Accept':'application/vnd.github+json'})
    with urllib.request.urlopen(req,timeout=25) as r:
        data=r.read(5*1024*1024+1)
        if len(data)>5*1024*1024:raise ValueError('GH-002: بيانات المصدر أكبر من الحد')
        return json.loads(data)

def releases(repo):
    repo_valid(repo)
    data=api('repos/'+repo+'/releases?per_page=15')
    return {'repo':repo,'releases':[{'id':r['id'],'tag':r['tag_name'],'name':r.get('name',''),'prerelease':r.get('prerelease',False),'url':r['html_url'],'notes':r.get('body','')[:10000],'assets':[{'id':a['id'],'name':a['name'],'size':a['size'],'digest':a.get('digest'),'url':a['browser_download_url']} for a in r.get('assets',[])]} for r in data if not r.get('draft')],'catalog':REPOS}

class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        check_download_url(newurl)
        return super().redirect_request(req,fp,code,msg,headers,newurl)
def check_download_url(url):
    u=urllib.parse.urlsplit(url)
    if u.scheme!='https' or u.username or u.password or u.hostname not in ('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'):
        raise ValueError('GH-003: وجهة تنزيل غير مسموحة')

def unpack_zip(archive,target):
    total=0
    with zipfile.ZipFile(archive) as z:
        items=z.infolist()
        if len(items)>20000:raise ValueError('GH-004: عدد ملفات كبير')
        for item in items:
            mode=item.external_attr>>16
            if stat.S_ISLNK(mode) or '\\' in item.filename or P(item.filename).is_absolute() or '..' in P(item.filename).parts:raise ValueError('GH-004: مسار أو رابط غير آمن داخل ZIP')
            total+=item.file_size
            if total>512*1024*1024 or item.file_size>LIMIT:raise ValueError('GH-004: حجم فك الضغط أكبر من الحد')
            core.safe_child(target,item.filename)
        for item in items:
            dest=core.safe_child(target,item.filename)
            if item.is_dir():dest.mkdir(parents=True,exist_ok=True)
            else:
                dest.parent.mkdir(parents=True,exist_ok=True)
                with z.open(item) as source,dest.open('xb') as f:shutil.copyfileobj(source,f)
                dest.chmod(0o600) # Imported binaries are never executed by the downloader.

def downloadable_items(folder):
    out=[]
    for p in sorted(folder.rglob('*')):
        if '__MACOSX' in p.parts:continue
        # Root kext only; plugins are imported by core.import_item.
        if any(x.endswith('.kext') for x in p.relative_to(folder).parts[:-1]):continue
        kind='kext' if p.is_dir() and p.suffix.lower()=='.kext' else 'acpi' if p.is_file() and p.suffix.lower()=='.aml' else 'driver' if p.is_file() and p.suffix.lower()=='.efi' else None
        if kind:out.append({'path':str(p.relative_to(folder)),'kind':kind})
    return out

def download(repo,asset_id):
    repo_valid(repo)
    if not str(asset_id).isdigit():raise ValueError('GH-005: معرف ملف غير صالح')
    meta=api('repos/'+repo+'/releases/assets/'+str(asset_id));name=meta['name']
    if name!=P(name).name or not name.lower().endswith('.zip') or meta['size']>LIMIT:raise ValueError('GH-006: اختر أصل إصدار ZIP بحجم أقل من 200 MiB')
    url=meta['browser_download_url'];check_download_url(url)
    if not urllib.parse.urlsplit(url).path.startswith('/'+repo+'/releases/download/'):raise ValueError('GH-003: الملف لا يطابق المستودع المختار')
    root=cache_root();root.mkdir(parents=True,exist_ok=True)
    entry=root/uuid.uuid4().hex;entry.mkdir(mode=0o700)
    try:
        archive=entry/name;size=0;sha=hashlib.sha256()
        opener=urllib.request.build_opener(SafeRedirect())
        req=urllib.request.Request(url,headers={'User-Agent':'NoorProbe/1.2'})
        with opener.open(req,timeout=45) as r,archive.open('xb') as f:
            check_download_url(r.geturl())
            while True:
                chunk=r.read(1024*1024)
                if not chunk:break
                size+=len(chunk)
                if size>LIMIT:raise ValueError('GH-006: حجم التنزيل تجاوز الحد')
                sha.update(chunk);f.write(chunk)
        if size!=meta['size']:raise ValueError('GH-007: حجم الملف لا يطابق GitHub')
        digest=sha.hexdigest();expected=meta.get('digest')
        if expected and expected.startswith('sha256:') and expected!='sha256:'+digest:raise ValueError('GH-008: بصمة التنزيل لا تطابق بصمة المصدر')
        unpacked=entry/'Unpacked';unpacked.mkdir();unpack_zip(archive,unpacked)
        record={'id':entry.name,'repo':repo,'asset_id':int(asset_id),'name':name,'sha256':digest,'source_digest_verified':expected=='sha256:'+digest,'items':downloadable_items(unpacked),'note':'لا يثبت التنزيل أو تطابق البصمة توافق التعريف. لم يُطبّق أي ملف.'}
        (entry/'download.json').write_text(json.dumps(record,ensure_ascii=False,indent=2))
        return record
    except Exception:shutil.rmtree(entry);raise

def app_version_key(value):
    match=re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:-beta\.(\d+))?',str(value),re.I)
    if not match:return None
    major,minor,patch,beta=match.groups()
    return (int(major),int(minor),int(patch),0 if beta else 1,int(beta or 0))

def bundle_app_version(info):
    custom=str(info.get('NoorUpdateVersion',''))
    if app_version_key(custom):return custom.removeprefix('v')
    short=str(info.get('CFBundleShortVersionString',''))
    build=str(info.get('CFBundleVersion',''))
    beta=re.fullmatch(re.escape(short)+r'b(\d+)',build,re.I)
    if beta:return short+'-beta.'+beta.group(1)
    explicit=re.fullmatch(re.escape(short)+r'-beta\.(\d+)',build,re.I)
    if explicit:return short+'-beta.'+explicit.group(1)
    return short if app_version_key(short) else None

def latest_app_release(repo):
    releases=api('repos/'+repo+'/releases?per_page=50')
    candidates=[]
    for release in releases:
        if release.get('draft'):continue
        version=str(release.get('tag_name','')).removeprefix('v').lower()
        key=app_version_key(version)
        if not key:continue
        assets=[a for a in release.get('assets',[]) if 'noorprobe' in a.get('name','').lower() and a.get('name','').lower().endswith('.zip') and a.get('name')==P(a.get('name','')).name]
        if len(assets)==1:candidates.append((key,version,release,assets[0]))
    if not candidates:raise ValueError('UPD-003: لا يوجد إصدار منشور بملف ZIP واحد يتضمن NoorProbe في اسمه')
    return max(candidates,key=lambda item:item[0])

def app_update_check(repo,current):
    repo_valid(repo)
    installed=app_version_key(current)
    if installed is None:raise ValueError('UPD-001: إصدار التطبيق الحالي غير صالح')
    key,version,release,asset=latest_app_release(repo)
    if int(asset.get('size',0))<1 or int(asset['size'])>LIMIT:raise ValueError('UPD-004: حجم حزمة التحديث يجب أن يكون أقل من 200 MiB')
    return {'repo':repo,'current':current,'version':version,'name':release.get('name') or ('Noor Probe '+version),'notes':str(release.get('body') or '')[:6000],'release_url':release.get('html_url',''),'asset_id':int(asset['id']),'asset_name':asset['name'],'size':int(asset['size']),'digest':asset.get('digest'),'available':key>installed}

def download_app_update(repo,asset_id,version):
    repo_valid(repo)
    if not str(asset_id).isdigit() or not re.fullmatch(r'\d+\.\d+\.\d+',version):raise ValueError('UPD-005: بيانات الإصدار غير صالحة')
    _,latest,release,latest_asset=latest_app_release(repo)
    if latest!=version:raise ValueError('UPD-006: تغيّر الإصدار المنشور؛ افحص التحديثات مجدداً')
    asset=latest_asset if int(latest_asset['id'])==int(asset_id) else None
    if not asset or 'noorprobe' not in asset.get('name','').lower() or not asset['name'].lower().endswith('.zip') or asset['name']!=P(asset['name']).name:raise ValueError('UPD-007: ملف التحديث لا يطابق إصدار Noor Probe')
    if int(asset.get('size',0))<1 or int(asset['size'])>LIMIT:raise ValueError('UPD-004: حجم حزمة التحديث يجب أن يكون أقل من 200 MiB')
    expected=asset.get('digest')
    if not isinstance(expected,str) or not re.fullmatch(r'sha256:[0-9a-f]{64}',expected):raise ValueError('UPD-008: GitHub لم يوفّر بصمة SHA-256 لهذا الملف؛ لن نثبّت حزمة غير متحقّق منها')
    url=asset.get('browser_download_url','');check_download_url(url)
    if not urllib.parse.urlsplit(url).path.startswith('/'+repo+'/releases/download/'):raise ValueError('UPD-009: رابط الملف لا يطابق المستودع')
    base=cache_root().parent/'Updates';base.mkdir(parents=True,exist_ok=True)
    entry=base/(version+'-'+uuid.uuid4().hex[:12]);entry.mkdir(mode=0o700)
    try:
        archive=entry/asset['name'];sha=hashlib.sha256();size=0
        req=urllib.request.Request(url,headers={'User-Agent':'NoorProbe/1.3','Accept':'application/octet-stream'})
        opener=urllib.request.build_opener(SafeRedirect())
        with opener.open(req,timeout=45) as response,archive.open('xb') as out:
            check_download_url(response.geturl())
            while True:
                chunk=response.read(1024*1024)
                if not chunk:break
                size+=len(chunk)
                if size>LIMIT:raise ValueError('UPD-004: حجم التنزيل تجاوز الحد')
                sha.update(chunk);out.write(chunk)
        if size!=int(asset['size']) or 'sha256:'+sha.hexdigest()!=expected:raise ValueError('UPD-010: الحجم أو بصمة الملف لا تطابق بيانات GitHub')
        with zipfile.ZipFile(archive) as z:
            candidates=[];total=0
            for item in z.infolist():
                mode=item.external_attr>>16
                if stat.S_ISLNK(mode) or '\\' in item.filename or P(item.filename).is_absolute() or '..' in P(item.filename).parts:raise ValueError('UPD-011: مسار غير آمن داخل ملف التحديث')
                total+=item.file_size
                if total>512*1024*1024 or len(z.infolist())>20000:raise ValueError('UPD-012: حجم فك ضغط التحديث تجاوز الحد')
                parts=P(item.filename).parts
                for i,part in enumerate(parts):
                    if part.endswith('.app') and parts[i+1: i+3]==('Contents','Info.plist'):
                        info=plistlib.loads(z.read(item))
                        if info.get('CFBundleIdentifier')=='dev.noor.probe.app' and bundle_app_version(info)==version:candidates.append('/'.join(parts[:i+1]))
            if len(set(candidates))!=1:raise ValueError('UPD-013: الحزمة لا تحتوي تطبيق Noor Probe بالإصدار المطلوب')
            unpacked=entry/'Unpacked';unpacked.mkdir();unpack_zip(archive,unpacked)
        app_path=unpacked.joinpath(*P(candidates[0]).parts)
        exe=app_path/'Contents'/'MacOS'/'NoorProbe'
        if not exe.is_file():raise ValueError('UPD-014: ملف تشغيل التطبيق غير موجود')
        exe.chmod(0o755)
        return {'path':str(app_path),'version':version,'name':asset['name'],'sha256':sha.hexdigest(),'repo':repo}
    except Exception:
        shutil.rmtree(entry,ignore_errors=True);raise

def prepare_app_update(staged,target):
    staged=P(staged).expanduser().resolve();target=P(target).expanduser().resolve();root=(cache_root().parent/'Updates').resolve()
    if not staged.is_relative_to(root) or staged.name!='Noor Probe.app' or not (staged/'Contents'/'Info.plist').is_file():raise ValueError('UPD-015: مسار التحديث المؤقت غير صالح')
    if target.name!='Noor Probe.app' or not (target/'Contents'/'Info.plist').is_file():raise ValueError('UPD-016: لم يتم التعرّف على التطبيق المثبت')
    new=plistlib.loads((staged/'Contents'/'Info.plist').read_bytes());old=plistlib.loads((target/'Contents'/'Info.plist').read_bytes())
    if new.get('CFBundleIdentifier')!='dev.noor.probe.app' or old.get('CFBundleIdentifier')!='dev.noor.probe.app':raise ValueError('UPD-017: معرّف التطبيق غير مطابق')
    new_version=app_version_key(bundle_app_version(new));old_version=app_version_key(bundle_app_version(old))
    if new_version is None or old_version is None or new_version<=old_version:raise ValueError('UPD-018: الإصدار الموجود أحدث أو مساوٍ')
    if not os.access(target.parent,os.W_OK):raise ValueError('UPD-019: لا يمكن الكتابة إلى مجلد التطبيق. انقله إلى Applications بحسابك ثم أعد المحاولة.')
    helper=root/('install-'+uuid.uuid4().hex+'.py');log=root/'install.log';backups=root/'Backups'
    helper.write_text('''import os,pathlib,plistlib,shutil,subprocess,sys,time,uuid\nsrc=pathlib.Path(sys.argv[1]);dst=pathlib.Path(sys.argv[2]);parent=int(sys.argv[3]);backups=pathlib.Path(sys.argv[4]);log=pathlib.Path(sys.argv[5])\ndef write(s):\n with log.open("a") as f:f.write(s+"\\n")\ntry:\n deadline=time.time()+180\n while time.time()<deadline:\n  try:os.kill(parent,0)\n  except ProcessLookupError:break\n  time.sleep(.5)\n else:raise RuntimeError("The app did not close")\n backups.mkdir(parents=True,exist_ok=True)\n version=plistlib.loads((dst/"Contents"/"Info.plist").read_bytes())["CFBundleShortVersionString"]\n backup=backups/("Noor Probe "+version+" "+uuid.uuid4().hex[:8]+".app")\n subprocess.run(["/usr/bin/ditto",str(dst),str(backup)],check=True)\n fresh=dst.parent/(".Noor Probe update "+uuid.uuid4().hex+".app")\n subprocess.run(["/usr/bin/ditto",str(src),str(fresh)],check=True)\n (fresh/"Contents"/"MacOS"/"NoorProbe").chmod(0o755)\n old=dst.parent/(".Noor Probe previous "+uuid.uuid4().hex+".app")\n os.replace(dst,old)\n try:os.replace(fresh,dst)\n except Exception:\n  os.replace(old,dst);raise\n shutil.rmtree(old,ignore_errors=True)\n subprocess.Popen(["/usr/bin/open","-a",str(dst)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\n write("Installed "+version+" backup="+str(backup))\nexcept Exception as e:\n write("Update failed: "+repr(e))\n''',encoding='utf-8');helper.chmod(0o700)
    with log.open('a') as out:subprocess.Popen([sys.executable,str(helper),str(staged),str(target),str(os.getppid()),str(backups),str(log)],stdin=subprocess.DEVNULL,stdout=out,stderr=out,start_new_session=True,close_fds=True)
    return {'started':True,'message':'سيغلق التطبيق، ثم يثبت النسخة المتحقّق منها ويعيد فتحها. تُحفظ نسخة احتياطية في دعم التطبيق.'}

def downloaded():
    root=cache_root();out=[]
    if root.exists():
        for p in root.glob('*/download.json'):
            try:out.append(json.loads(p.read_text()))
            except Exception:pass
    return {'downloads':out,'catalog':REPOS}

def apply_download(work,download_id,relative,replace=False):
    if not re.fullmatch(r'[a-f0-9]{32}',download_id):raise ValueError('GH-009: معرف تنزيل غير صالح')
    folder=cache_root()/download_id;record=json.loads((folder/'download.json').read_text())
    item=next((x for x in record['items'] if x['path']==relative),None)
    if not item:raise ValueError('GH-009: اختر ملفاً من سجل التنزيل')
    source=core.safe_child(folder/'Unpacked',relative)
    if any(p.is_symlink() for p in (folder/'Unpacked').rglob('*')):raise ValueError('GH-004: رابط رمزي في ملفات التنزيل')
    return core.import_item(work,source,item['kind'],replace)

def compare_inventory(filename, devices):
    from collections import Counter
    path = P(filename)
    with path.open('rb') as stream:
        raw = stream.read(512 * 1024 + 1)
    if len(raw) > 512 * 1024:
        raise ValueError('HW-301: تقرير PCI أكبر من الحد')
    matches = re.findall(r'^([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7])\s+[0-9a-f]{4}:\s+([0-9a-f]{4}):([0-9a-f]{4})', raw.decode('utf-8', errors='replace'), re.I | re.M)
    unique = {slot.lower(): (vendor.lower(), device.lower()) for slot, vendor, device in matches}
    if not unique:
        raise ValueError('HW-302: اختر تقرير lspci -Dn')
    linux = Counter(unique.values())
    mac = Counter((d.get('vendor'), d.get('device')) for d in devices if d.get('bus') == 'PCI')
    return {'rows': [{'id': v + ':' + d, 'linux': count, 'macos': mac[v,d]} for (v,d), count in sorted(linux.items())]}


def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='cmd',required=True)
    sub.add_parser('efi');s=sub.add_parser('mount');s.add_argument('identifier')
    s=sub.add_parser('releases');s.add_argument('repo')
    s=sub.add_parser('download');s.add_argument('repo');s.add_argument('asset')
    s=sub.add_parser('update-check');s.add_argument('repo');s.add_argument('current')
    s=sub.add_parser('update-download');s.add_argument('repo');s.add_argument('asset');s.add_argument('version')
    s=sub.add_parser('update-install');s.add_argument('staged');s.add_argument('target')
    sub.add_parser('downloads')
    s=sub.add_parser('inventory');s.add_argument('path')
    s=sub.add_parser('apply');s.add_argument('workspace');s.add_argument('download');s.add_argument('relative');s.add_argument('--replace',action='store_true')
    a=p.parse_args(sys.argv[2:])
    try:
        if a.cmd=='efi':r=list_efi()
        elif a.cmd=='mount':r=mount_efi(a.identifier)
        elif a.cmd=='releases':r=releases(a.repo)
        elif a.cmd=='download':r=download(a.repo,a.asset)
        elif a.cmd=='update-check':r=app_update_check(a.repo,a.current)
        elif a.cmd=='update-download':r=download_app_update(a.repo,a.asset,a.version)
        elif a.cmd=='update-install':r=prepare_app_update(a.staged,a.target)
        elif a.cmd=='downloads':r=downloaded()
        elif a.cmd=='inventory':r=compare_inventory(a.path,json.loads(os.environ.pop('NOOR_INVENTORY_DEVICES')))
        else:r=apply_download(a.workspace,a.download,a.relative,a.replace)
        print(json.dumps(r,ensure_ascii=False))
    except Exception as e:print(json.dumps({'error':str(e)},ensure_ascii=False));sys.exit(1)
