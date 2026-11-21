"""Optional provider calls with a deliberately narrow hardware context."""
import concurrent.futures
import json
import os
import re
import urllib.error
import urllib.request

ENDPOINTS = {
    'google': 'https://generativelanguage.googleapis.com/v1beta/openai/chat/completions',
    'groq': 'https://api.groq.com/openai/v1/chat/completions',
    'router': 'https://openrouter.ai/api/v1/chat/completions',
    'hf': 'https://router.huggingface.co/v1/chat/completions',
    'cloudflare': 'https://api.cloudflare.com/client/v4/accounts/{account}/ai/v1/chat/completions',
}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None

def safe_context(report):
    snapshot = report.get('snapshot', {})
    deep = snapshot.get('deep', {})
    return {
        'macos': snapshot.get('os', ''),
        'linux_pci_comparison': report.get('inventory', [])[:60],
        'pci_usb': [{k: d.get(k) for k in ('bus', 'vendor', 'device', 'interfaces', 'loaded_bundle_candidates')} for d in deep.get('devices', [])[:80]],
        'network': [{k: n.get(k) for k in ('interface', 'link', 'has_ipv4', 'default_route', 'radio')} for n in deep.get('network', [])[:20]],
        'kexts': [{k: d.get(k) for k in ('name', 'version', 'enabled', 'exists')} for d in report.get('kexts', [])[:60]],
        'finding_codes': [d.get('code') for d in report.get('findings', [])[:80]],
    }

def ask_one(profile, messages):
    provider = profile['provider']
    model = profile['model'].strip()
    try:
        if provider == 'router' and model != 'openrouter/free' and not model.endswith(':free'):
            raise ValueError('اختر openrouter/free أو نموذجاً ينتهي بـ :free')
        url = ENDPOINTS[provider]
        if provider == 'cloudflare':
            account = profile.get('account', '')
            if not re.fullmatch(r'[0-9a-fA-F]{32}', account):
                raise ValueError('Cloudflare يحتاج Account ID')
            url = url.format(account=account)
        request = urllib.request.Request(url, json.dumps({'model': model, 'messages': messages, 'max_tokens': 1000}).encode(),
            headers={'Authorization': 'Bearer ' + profile['key'], 'Content-Type': 'application/json'})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            data = json.loads(response.read(2_000_000))
        return {'provider': provider, 'answer': data['choices'][0]['message']['content']}
    except urllib.error.HTTPError as error:
        return {'provider': provider, 'error': f'HTTP {error.code} — راجع النموذج والمفتاح وحدود الحساب'}
    except ValueError as error:
        return {'provider': provider, 'error': 'إعداد أو رد غير صالح'}
    except Exception:
        return {'provider': provider, 'error': 'تعذر الاتصال أو قراءة جواب المزود'}

def main():
    data = json.loads(os.environ.pop('NOOR_AI_REQUEST'))
    profiles = [p for p in data['profiles'] if p.get('provider') in ENDPOINTS and p.get('key') and p.get('model')][:5]
    messages = [{'role':'system', 'content':'أجب بالعربية. استخدم بيانات الفحص كأدلة فقط. لا تفترض أن عدم الرصد يعني غياب القطعة. اقترح خطوات قابلة للتحقق واذكر درجة الثقة. لا يمكنك تنفيذ أوامر أو تغيير EFI. السياق: '+json.dumps(safe_context(data.get('report') or {}), ensure_ascii=False)}]
    messages.extend({'role': t['role'], 'content': t['content'][:4000]} for t in data.get('history', [])[-8:] if t['role'] in ('user','assistant'))
    messages.append({'role':'user','content':data['question'][:4000]})
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        answers = list(pool.map(lambda p: ask_one(p, messages), profiles))
    print(json.dumps({'answers':answers}, ensure_ascii=False))

if __name__ == '__main__':
    main()
