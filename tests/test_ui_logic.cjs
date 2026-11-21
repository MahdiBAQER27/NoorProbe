// Logic-only test with minimal DOM stubs. Does not validate WebKit/AppKit rendering.
const fs=require('fs'),vm=require('vm'),assert=require('assert');
const elements=new Map(['nav','heading','status','spinner','content','issueList'].map(k=>[k,{innerHTML:'',textContent:'',hidden:false}]));
const handlers={},sent=[];
const context={document:{getElementById:k=>elements.get(k)||null,querySelectorAll:()=>[],addEventListener:(name,fn)=>handlers[name]=fn},window:{webkit:{messageHandlers:{noor:{postMessage:m=>sent.push(m)}}}},console};
vm.createContext(context);
const html=fs.readFileSync(__dirname+'/../App/ui.html','utf8');const script=html.match(/<script>([\s\S]*)<\/script>/)[1];vm.runInContext(script,context);
assert.equal(sent[0].action,'ready');
for(const key of ['overview','hardware','issues','drivers','workspace','about','deep','efiBrowser','catalog','ai']){vm.runInContext(`page=${JSON.stringify(key)};render()`,context);assert(elements.get('content').innerHTML.length>10);}
vm.runInContext(`receiveState({efi:'/EFI',workspace:'/work',busy:false,status:'test',report:null,info:{config:'<plist><dict/></plist>',changes:[],files:[],kexts:[],history:[]}});page='workspace';tab='editor';render()`,context);
assert(elements.get('content').innerHTML.includes('id="editor"'));
vm.runInContext(`editorDraft='<plist><dict/></plist>';`,context);
handlers.click({target:{closest:()=>({dataset:{action:'saveConfig'}})}});assert.equal(sent.at(-1).action,'saveConfig');assert.equal(sent.at(-1).xml,'<plist><dict/></plist>');
handlers.click({target:{closest:()=>({dataset:{action:'import',kind:'kext'}})}});assert.equal(sent.at(-1).kind,'kext');
assert.equal(vm.runInContext(`esc('<script>')`,context),'&lt;script&gt;');
console.log('UI logic passed: ten routes, workspace editor, save payload, import payload, HTML escaping. Rendering/native bridge untested.');
