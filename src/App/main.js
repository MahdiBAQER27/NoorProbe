/* JXA AppKit host. Executed by macOS /usr/bin/osascript, not a compiled Swift binary. */
ObjC.import('Cocoa');
ObjC.import('WebKit');
var app, win, web, bridge, resources, active = null;
var aiProfiles = {}, aiHistory = [];
var DEFAULT_UPDATE_REPO = 'MahdiBAQER27/NoorProbe';
var state = { efi: '', workspace: '', report: null, info: null, busy: false, status: 'جاهز • اختر EFI أو ابدأ فحص النظام', efiList: null, catalog: null, downloads: [], runtime: 'JXA / AppKit + WebKit • 2.0.0-beta.3', aiConfigured: {}, aiAnswers: [], aiQuestion: '', inventory: null, appUpdate: null, updatePath: '', updateRepo: '' };
function str(x) { return ObjC.unwrap(x); }
function read(path) { var v = $.NSString.stringWithContentsOfFileEncodingError($(path), $.NSUTF8StringEncoding, null); return v.isNil() ? '' : str(v); }
function exists(path) { return $.NSFileManager.defaultManager.fileExistsAtPath($(path)); }
function alertText(title, text) { var a = $.NSAlert.alloc.init; if (!a || a.isNil()) { state.status=String(title)+': '+String(text).slice(0,300); emit(); return; } a.messageText = $(title); a.informativeText = $(String(text).slice(0,12000)); a.addButtonWithTitle($('حسناً')); a.runModal; }
function confirm(title, text) { var a = $.NSAlert.alloc.init; if (!a || a.isNil()) return false; a.messageText = $(title); a.informativeText = $(text); a.addButtonWithTitle($('تأكيد')); a.addButtonWithTitle($('إلغاء')); return Number(a.runModal) === 1000; }
function emit() { if (web) web.evaluateJavaScriptCompletionHandler($('window.receiveState(' + JSON.stringify(state) + ')'), null); }
function chooseFolder(message) { var panel=$.NSOpenPanel.openPanel; panel.canChooseFiles=false; panel.canChooseDirectories=true; panel.canCreateDirectories=true; panel.message=$(message); if(Number(panel.runModal)===1) return str(panel.URL.path); return null; }
function chooseFile(message, directory) { var panel=$.NSOpenPanel.openPanel; panel.canChooseDirectories=!!directory; panel.canChooseFiles=!directory; panel.treatsFilePackagesAsDirectories=!!directory; panel.message=$(message); if(Number(panel.runModal)===1) return str(panel.URL.path); return null; }
function savePath(name,message) { var panel=$.NSSavePanel.savePanel; panel.nameFieldStringValue=$(name); panel.message=$(message); panel.canCreateDirectories=true; if(Number(panel.runModal)===1) return str(panel.URL.path); return null; }
function python() { var candidates=['/usr/local/bin/python3','/opt/homebrew/bin/python3','/usr/bin/python3']; for(var i=0;i<candidates.length;i++) if($.NSFileManager.defaultManager.isExecutableFileAtPath($(candidates[i]))) return candidates[i]; throw Error('SYS-002: Python 3.9+ مطلوب لمحرك الفحص والتعديل. ثبّته من python.org. الواجهة نفسها لا تحتاج Xcode.'); }
function start(args, callback, extraEnvironment, script) {
    if(state.busy) return;
    try {
        var path=python();
        var output=str($.NSTemporaryDirectory())+'noor-'+str($.NSUUID.UUID.UUIDString)+'.json';
        $.NSFileManager.defaultManager.createFileAtPathContentsAttributes($(output),$.NSData.data,null);
        var handle=$.NSFileHandle.fileHandleForWritingAtPath($(output));
        var task=$.NSTask.alloc.init;
        task.launchPath=$(path); task.arguments=$([resources+'/'+(script||'probe.py')].concat(args));
        if(extraEnvironment) task.environment=$(Object.assign(ObjC.deepUnwrap($.NSProcessInfo.processInfo.environment),extraEnvironment));
        task.standardOutput=handle; task.standardError=handle;
        active={task:task,handle:handle,path:output,callback:callback};
        $.NSNotificationCenter.defaultCenter.addObserverSelectorNameObject(bridge,'taskFinished:',$.NSTaskDidTerminateNotification,task);
        state.busy=true; state.status='جارٍ العمل… الفحص قد يستغرق عدة دقائق'; emit();
        task.launch;
    } catch(e) { state.busy=false; active=null; emit(); alertText('تعذر تشغيل المحرك',e.message); }
}
function finish() {
    if(!active) return;
    var job=active; active=null;
    $.NSNotificationCenter.defaultCenter.removeObserverNameObject(bridge,$.NSTaskDidTerminateNotification,job.task);
    job.handle.closeFile;
    var text=read(job.path);
    $.NSFileManager.defaultManager.removeItemAtPathError($(job.path),null);
    state.busy=false;
    try {
        if(Number(job.task.terminationStatus)!==0) throw Error(text || 'ENGINE-001: المحرك توقف دون تقرير.');
        var result=JSON.parse(text);
        state.status='اكتملت العملية • '+new Date().toLocaleTimeString();
        if(job.callback) job.callback(result);
    } catch(e) { state.status='تعذرت العملية • راجع رسالة الخطأ'; alertText('Noor Probe',e.message); }
    emit();
}
function refreshWorkspace() { if(state.workspace) start(['info',state.workspace],function(r){ state.info=r; }); }
function aiReport(){
    var report=state.report;
    if(!report)return null;
    var deep=report.snapshot.deep||{};
    function pick(rows,keys,limit){
        return (rows||[]).slice(0,limit).map(function(row){
            var selected={};
            keys.forEach(function(key){selected[key]=row[key];});
            return selected;
        });
    }
    return {snapshot:{os:report.snapshot.os,deep:{
        devices:pick(deep.devices,['bus','vendor','device','interfaces','loaded_bundle_candidates'],60),
        network:pick(deep.network,['interface','link','has_ipv4','default_route','radio'],15)
    }},kexts:pick(report.kexts,['name','version','enabled','exists'],40),
       findings:pick(report.findings,['code'],60),inventory:pick(state.inventory&&state.inventory.rows,['id','linux','macos'],60)};
}
function action(message) {
    if(state.busy && message.action!=='ready') return;
    switch(message.action) {
    case 'ready': state.updateRepo=str($.NSUserDefaults.standardUserDefaults.stringForKey($('noorUpdateRepo'))||DEFAULT_UPDATE_REPO); emit(); break;
    case 'aiProfile':
        if(['google','groq','router','cloudflare','hf'].indexOf(message.provider)<0)break;
        var provider=message.provider;
        if(message.remove){delete aiProfiles[provider];delete state.aiConfigured[provider];emit();break;}
        var panel=$.NSAlert.alloc.init;
        panel.messageText=$('API • '+provider);
        panel.informativeText=$('أدخل مفتاح حسابك المجاني. المفتاح يبقى في الذاكرة إلى أن تغلق التطبيق.');
        var keyField=$.NSSecureTextField.alloc.initWithFrame($.NSMakeRect(0,0,350,24));
        panel.accessoryView=keyField;panel.addButtonWithTitle($('حفظ'));panel.addButtonWithTitle($('إلغاء'));
        panel.window.initialFirstResponder=keyField;
        if(Number(panel.runModal)!==1000)break;
        var key=str(keyField.stringValue).trim();
        if(!key||!message.model||key.length>2048)break;
        aiProfiles[provider]={provider:provider,key:key,model:String(message.model).slice(0,200),account:String(message.account||'').slice(0,32)};
        state.aiConfigured[provider]=String(message.model);emit();break;
    case 'askAI':
        var profiles=Object.keys(aiProfiles).filter(function(p){return message.provider==='all'||p===message.provider;}).map(function(p){return aiProfiles[p];});
        if(!profiles.length || typeof message.question!=='string'||!message.question.trim())break;
        if(!confirm('إرسال السؤال إلى مزوّد الذكاء','المزوّدون: '+profiles.map(function(p){return p.provider;}).join(', ')+'\nيُرسل سؤالك وسياق المحادثة، ومع خيار إرفاق الفحص تُرسل خلاصة معرّفات القطع والشبكة والتعريفات وأكواد التشخيص. استخدم حسابات ونماذج مجانية عند المزوّد.'))break;
        var question=message.question.slice(0,4000);
        var history=aiHistory.filter(function(turn){return turn.scope===message.provider && turn.withReport===!!message.withReport;}).map(function(turn){return {role:turn.role,content:turn.content};});
        start([],function(r){
            state.aiAnswers=r.answers;state.aiQuestion=question;
            var replies=r.answers.filter(function(x){return typeof x.answer==='string'&&x.answer;}).map(function(x){return x.provider+': '+x.answer.slice(0,650);});
            if(replies.length){aiHistory.push({role:'user',content:question,scope:message.provider,withReport:!!message.withReport},{role:'assistant',content:replies.join('\n'),scope:message.provider,withReport:!!message.withReport});aiHistory=aiHistory.slice(-10);}
        },{NOOR_AI_REQUEST:JSON.stringify({profiles:profiles,question:question,history:history,report:message.withReport?aiReport():null})},'assistant_ai.py');
        break;
    case 'inventory':
        if(!state.report || !state.report.snapshot.deep || !state.report.snapshot.probes.pci.ok){alertText('فحص macOS مطلوب','أكمل فحص PCI بنجاح قبل المقارنة.');break;}
        var inventoryFile=chooseFile('اختر ملف lspci -Dn من Linux على نفس الجهاز',false);
        if(inventoryFile)start(['advanced','inventory',inventoryFile],function(r){state.inventory=r;},{NOOR_INVENTORY_DEVICES:JSON.stringify(state.report.snapshot.deep.devices.map(function(d){return {bus:d.bus,vendor:d.vendor,device:d.device};}))});
        break;
    case 'listEFI':
        start(['advanced','efi'],function(r){state.efiList=r;});break;
    case 'mountEFI':
        if(!state.efiList || !state.efiList.partitions.some(function(p){return p.id===message.id;}))break;
        if(!confirm('إظهار قسم EFI','سيتم طلب تركيب '+message.id+' لتظهر ملفاته في Finder. قد تحتاج صلاحية مسؤول. لا يكتب التطبيق على الملفات أثناء الفحص، لكن القسم قد يكون قابلاً للكتابة.'))break;
        start(['advanced','mount',message.id],function(r){state.efiList=r;});break;
    case 'mountAdmin':
        if(!/^disk[0-9]+s[0-9]+$/.test(message.id)||!state.efiList||!state.efiList.partitions.some(function(p){return p.id===message.id;}))break;
        if(!confirm('صلاحية مسؤول لتركيب EFI','سيطلب macOS صلاحية مسؤول لتركيب '+message.id+' عبر diskutil حتى تتمكن من تصفح الملفات. لا يحفظ التطبيق كلمة المرور. انتبه عند تعديل ملفات EFI يدوياً.'))break;
        var automation=Application.currentApplication();automation.includeStandardAdditions=true;
        automation.doShellScript('/usr/sbin/diskutil mount '+message.id,{administratorPrivileges:true});
        start(['advanced','efi'],function(r){state.efiList=r;});break;
    case 'selectEFISource':
        if(state.efiList && state.efiList.partitions.some(function(p){return (p.configs||[]).indexOf(message.path)>=0;})){state.efi=message.path;state.report=null;emit();}break;
    case 'showEFI':
        var part=state.efiList && state.efiList.partitions.find(function(p){return p.id===message.id;});
        if(part && part.mount)$.NSWorkspace.sharedWorkspace.openURL($.NSURL.fileURLWithPath($(part.mount)));break;
    case 'getReleases':
        if(typeof message.repo==='string')start(['advanced','releases',message.repo],function(r){state.catalog=r;});break;
    case 'checkAppUpdate':
        var updateRepo=String(message.repo||'').trim();
        var repoMatch=updateRepo.match(/^(?:https:\/\/)?(?:www\.)?github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)(?:\/releases(?:\/.*)?)?\/?$/i);
        if(repoMatch)updateRepo=repoMatch[1].replace(/\.git$/i,'');
        if(!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(updateRepo)){alertText('رابط المستودع','أدخل github.com/owner/repo أو owner/repo.');break;}
        $.NSUserDefaults.standardUserDefaults.setObjectForKey($(updateRepo),$('noorUpdateRepo'));state.updateRepo=updateRepo;
        state.updatePath='';state.appUpdate=null;
        var currentVersion=(state.runtime.match(/[0-9]+\.[0-9]+\.[0-9]+(?:-beta\.[0-9]+)?/i)||[])[0]||'2.0.0-beta.3';
        start(['advanced','update-check',updateRepo,currentVersion],function(r){state.appUpdate=r;});break;
    case 'downloadAppUpdate':
        if(!state.appUpdate||!state.appUpdate.available)break;
        if(!confirm('تنزيل تحديث Noor Probe',state.appUpdate.repo+'\nالإصدار '+state.appUpdate.version+' • '+state.appUpdate.asset_name+'\nسيُتحقق من بصمة SHA-256 التي ينشرها GitHub قبل التثبيت.'))break;
        start(['advanced','update-download',state.appUpdate.repo,String(state.appUpdate.asset_id),state.appUpdate.version],function(r){state.updatePath=r.path;alertText('اكتمل تنزيل التحديث','تم التحقق من البصمة. اختر تثبيت وإعادة التشغيل للمتابعة.');});break;
    case 'installAppUpdate':
        if(!state.appUpdate||!state.updatePath)break;
        if(!confirm('تثبيت تحديث Noor Probe','سيحفظ التطبيق نسخة احتياطية، ثم يستبدل نفسه بالإصدار '+state.appUpdate.version+' ويعيد فتحه.'))break;
        var targetApp=resources.replace(/\/Contents\/Resources\/?$/,'');
        start(['advanced','update-install',state.updatePath,targetApp],function(r){state.status=r.message||'جارٍ تثبيت التحديث…';emit();app.terminate(null);});break;
    case 'getDownloads':
        start(['advanced','downloads'],function(r){state.downloads=r.downloads;});break;
    case 'downloadAsset':
        if(!state.catalog)break;
        var asset=null;state.catalog.releases.forEach(function(r){r.assets.forEach(function(a){if(a.id===Number(message.id))asset=a;});});
        if(!asset)break;
        if(!confirm('تنزيل من GitHub فقط',state.catalog.repo+'\n'+asset.name+'\nالحجم: '+asset.size+' بايت. سيتم الحفظ وفك ZIP محلياً؛ لن يتم التطبيق على EFI أو تشغيل الملفات. راجع إصدار macOS وملاحظات الإصدار.'))break;
        start(['advanced','download',state.catalog.repo,String(asset.id)],function(r){alertText('تم التنزيل',r.note+'\nSHA-256: '+r.sha256);start(['advanced','downloads'],function(d){state.downloads=d.downloads;});});break;
    case 'applyDownload':
        if(!state.workspace){alertText('مساحة عمل مطلوبة','أنشئ أو افتح Workspace قبل التطبيق.');break;}
        if(!confirm('تطبيق ملف منزّل على Candidate',message.path+'\nسيُنسخ الملف ويُسجل في config مع نقطة استعادة. '+(message.replace?'سيُسمح بالاستبدال.':'سيُرفض إذا كان الملف موجوداً.')+' لا يثبت التنزيل توافقه ولا يعدّل EFI الأصلية.'))break;
        start(['advanced','apply',state.workspace,message.download,message.path].concat(message.replace?['--replace']:[]),function(r){alertText('التطبيق على Candidate',r.message);refreshWorkspace();});break;
    case 'chooseEFI':
        var source=chooseFolder('اختر EFI أو OC أو نسخة منهما. لن يتم تركيب الأقراص تلقائياً.');
        if(source) {state.efi=source; state.report=null; emit();} break;
    case 'scan':
        var args=['scan'];
        var efi=message.candidate && state.info ? state.info.candidate : state.efi;
        if(efi) args=args.concat(['--efi',efi]);
        if(message.updates) args.push('--updates');
        start(args,function(r){state.report=r;state.inventory=null;}); break;
    case 'createWorkspace':
        if(!state.efi) {alertText('EFI مطلوب','اختر EFI أولاً.'); break;}
        var dest=savePath('Noor-Workspace-'+Date.now(),'اختر اسم مجلد جديد؛ سيتم إنشاء Backup وCandidate دون تغيير المصدر.');
        if(dest) start(['workspace',state.efi,dest],function(r){state.workspace=r.workspace; state.info=null; refreshWorkspace();}); break;
    case 'openWorkspace':
        var folder=chooseFolder('اختر مساحة Noor سابقة تحتوي manifest.json وBackup وCandidate.');
        if(folder) start(['info',folder],function(r){state.workspace=folder;state.info=r;}); break;
    case 'refreshWorkspace': refreshWorkspace(); break;
    case 'revealWorkspace': if(state.workspace) $.NSWorkspace.sharedWorkspace.openURL($.NSURL.fileURLWithPath($(state.workspace))); break;
    case 'import':
        if(!state.workspace) break;
        var kind=message.kind;
        if(['kext','acpi','driver'].indexOf(kind)<0) break;
        var file=chooseFile(kind==='kext'?'اختر حزمة .kext مفكوكة':'اختر ملف '+(kind==='acpi'?'.aml':'.efi'),kind==='kext');
        if(!file) break;
        if(!confirm('مراجعة استيراد ملف','المصدر: '+file+'\nالوجهة: Candidate فقط.\nسيتم '+(message.replace?'استبدال الملف الموجود إن وجد':'رفض العملية إذا الملف موجود')+' وإضافة مرجعه إلى config.plist. هذه ليست شهادة توافق. راجع إصدار النظام والاعتمادات قبل الإقلاع.')) break;
        var ia=['import',state.workspace,file,'--kind',kind]; if(message.replace) ia.push('--replace');
        start(ia,function(r){alertText('اكتمل الاستيراد',r.message);refreshWorkspace();}); break;
    case 'toggle':
        if(!state.workspace || typeof message.bundle!=='string') break;
        if(!confirm('تغيير تفعيل kext','سيتم '+(message.enabled?'تفعيل ':'تعطيل ')+message.bundle+' في Candidate فقط مع نقطة استعادة. تعطيل تعريف أساسي قد يمنع إقلاع هذه النسخة.')) break;
        start(['toggle',state.workspace,message.bundle,'--enabled',message.enabled?'yes':'no'],function(r){refreshWorkspace();}); break;
    case 'saveConfig':
        if(!state.workspace || typeof message.xml!=='string' || message.xml.length>4*1024*1024) break;
        if(!confirm('حفظ config.plist','سيتم استبدال إعداد Candidate بالنص الموجود في المحرر بعد تحليل plist، مع نقطة استعادة. لا يتم تشغيل ocvalidate تلقائياً.')) break;
        var tmp=str($.NSTemporaryDirectory())+'noor-edit-'+str($.NSUUID.UUID.UUIDString)+'.plist';
        if(!$(message.xml).writeToFileAtomicallyEncodingError($(tmp),true,$.NSUTF8StringEncoding,null)) throw Error('EDIT-005: تعذر حفظ النص المؤقت.');
        start(['config',state.workspace,tmp],function(r){$.NSFileManager.defaultManager.removeItemAtPathError($(tmp),null); alertText('تم الحفظ',r.message);refreshWorkspace();}); break;
    case 'layout':
        if(!state.workspace || !Number.isInteger(Number(message.value)) || Number(message.value)<1 || Number(message.value)>255) break;
        if(!confirm('تعديل الصوت في Candidate','سيتم استبدال alcid الحالي بالقيمة '+message.value+' في boot-args. لا يختار التطبيق Codec أو layout-id بالنيابة عنك.')) break;
        start(['layout',state.workspace,String(message.value)],function(r){alertText('التغيير',JSON.stringify(r,null,2));refreshWorkspace();}); break;
    case 'restore':
        if(!state.workspace || typeof message.revision!=='string') break;
        if(!confirm('استعادة نسخة مرشحة سابقة','سترجع Candidate إلى ما قبل العملية المختارة. سيتم حفظ وضعها الحالي كنقطة استعادة أخرى.')) break;
        start(['restore',state.workspace,message.revision],function(r){refreshWorkspace();}); break;
    case 'validate':
        if(!state.workspace || typeof message.version!=='string' || !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(message.version)) {alertText('VALIDATE-002','أدخل إصدار OpenCore المستخدم بصيغة 1.0.4 مثلاً؛ لا تخمّن الإصدار.');break;}
        var validator=chooseFile('اختر ocvalidate من حزمة OpenCore الرسمية المطابقة لإصدارك.',false);
        if(!validator) break;
        if(!confirm('تشغيل أداة تحقق خارجية','سيتم تشغيل الملف الذي اخترته: '+validator+'\nعلى config.plist في Candidate. يجب أن تثق بمصدر الأداة. سيتحقق البرنامج من ناتج --version مقابل '+message.version+' قبل فحص الملف.'))break;
        start(['validate',state.workspace,validator,message.version],function(r){alertText(r.ok?'نجح التحقق البنيوي':'توجد ملاحظات تحقق',r.output+'\n'+r.note);});break;
    case 'export':
        if(!state.report) break;
        var out=savePath('Noor-Diagnostic.json','راجع التقرير قبل مشاركته. مرشّح الهوية ليس ضماناً لإخفاء كل البيانات.');
        if(out) $(JSON.stringify(state.report,null,2)).writeToFileAtomicallyEncodingError($(out),true,$.NSUTF8StringEncoding,null); break;
    case 'openLink':
        if(typeof message.url==='string' && /^https:\/\/(github\.com|dortania\.github\.io|openintelwireless\.github\.io|www\.python\.org)\//.test(message.url)) $.NSWorkspace.sharedWorkspace.openURL($.NSURL.URLWithString($(message.url))); break;
    }
}
// Keep bridge selectors dynamic: protocol registration can fail across macOS bridge versions.
ObjC.registerSubclass({name:'NoorBridge',superclass:'NSObject',methods:{
    'userContentController:didReceiveScriptMessage:': {types:['void',['id','id']],implementation:function(controller,message){try {if(!message.frameInfo.isMainFrame) return; action(ObjC.deepUnwrap(message.body));} catch(e){alertText('APP-001',e.message);}}},
    'taskFinished:': {types:['void',['id']],implementation:function(notification){finish();}},
    'windowShouldClose:': {types:['bool',['id']],implementation:function(sender){if(active){alertText('عملية جارية','انتظر اكتمال العملية قبل إغلاق التطبيق، خصوصاً أثناء تعديل Candidate.');return false;}return true;}},
    'applicationShouldTerminate:': {types:['long',['id']],implementation:function(sender){if(active){alertText('عملية جارية','انتظر اكتمال العملية قبل إنهاء التطبيق.');return 0;}return 1;}},
    'windowWillClose:': {types:['void',['id']],implementation:function(notification){if(active){active.task.terminate;} app.terminate(null);}}
}});
function run(argv) {
    resources=argv[0];
    if(!resources || !exists(resources+'/ui.html')) throw Error('APP-002: ملفات الحزمة ناقصة.');
    app=$.NSApplication.sharedApplication; app.setActivationPolicy($.NSApplicationActivationPolicyRegular);
    var mainMenu=$.NSMenu.alloc.init;
    var appItem=$.NSMenuItem.alloc.init; mainMenu.addItem(appItem);
    var appMenu=$.NSMenu.alloc.initWithTitle($('Noor Probe'));
    appMenu.addItem($.NSMenuItem.alloc.initWithTitleActionKeyEquivalent($('Quit Noor Probe'),'terminate:',$('q'))); appItem.submenu=appMenu;
    var editItem=$.NSMenuItem.alloc.init; mainMenu.addItem(editItem);
    var editMenu=$.NSMenu.alloc.initWithTitle($('Edit'));
    [['Undo','undo:','z'],['Cut','cut:','x'],['Copy','copy:','c'],['Paste','paste:','v'],['Select All','selectAll:','a']].forEach(function(v){editMenu.addItem($.NSMenuItem.alloc.initWithTitleActionKeyEquivalent($(v[0]),v[1],$(v[2])));}); editItem.submenu=editMenu; app.mainMenu=mainMenu;
    bridge=$.NoorBridge.alloc.init; app.delegate=bridge;
    var configuration=$.WKWebViewConfiguration.alloc.init;
    configuration.userContentController.addScriptMessageHandlerName(bridge,$('noor'));
    configuration.websiteDataStore=$.WKWebsiteDataStore.nonPersistentDataStore;
    win=$.NSWindow.alloc.initWithContentRectStyleMaskBackingDefer($.NSMakeRect(0,0,1180,800),$.NSWindowStyleMaskTitled|$.NSWindowStyleMaskClosable|$.NSWindowStyleMaskMiniaturizable|$.NSWindowStyleMaskResizable,$.NSBackingStoreBuffered,false);
    win.title=$('Noor Probe'); win.minSize=$.NSMakeSize(920,640); win.delegate=bridge;
    web=$.WKWebView.alloc.initWithFrameConfiguration($.NSMakeRect(0,0,1180,800),configuration);
    web.autoresizingMask=$.NSViewWidthSizable|$.NSViewHeightSizable;
    win.contentView=web;
    web.loadFileURLAllowingReadAccessToURL($.NSURL.fileURLWithPath($(resources+'/ui.html')),$.NSURL.fileURLWithPath($(resources)));
    win.center; win.makeKeyAndOrderFront(null); app.activateIgnoringOtherApps(true); app.run;
}
