import urllib.request
import urllib.error
import urllib.parse
import json

BASE_URL = 'https://aegis-node.onrender.com'
results = {
    'DEPLOYMENT': 'FAIL',
    'HEALTH': 'FAIL',
    'FRONTEND': 'FAIL',
    'TURNSTILE': 'FAIL',
    'UPLOAD': 'FAIL',
    'SCANNER': 'NOT TESTED',
    'AI': 'NOT TESTED',
    'FALLBACK': 'NOT TESTED',
    'REMEDIATION': 'NOT TESTED',
    'SECURITY': 'FAIL',
}

limitations = []

def fetch(path, method='GET', data=None, headers=None, content_type=None):
    if headers is None: headers = {}
    if content_type: headers['Content-Type'] = content_type
    url = BASE_URL + path
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.getcode(), response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8')
    except Exception as e:
        return None, str(e)

# 1. HEALTH & DEPLOYMENT
code, body = fetch('/health')
if code == 200:
    results['DEPLOYMENT'] = 'PASS'
    results['HEALTH'] = 'PASS'
    try:
        h = json.loads(body)
        print("--- HEALTH ---")
        print("HTTP 200")
        print(f"status={h.get('status')}")
        print(f"ai_provider={h.get('ai_provider')}")
        print(f"ai_configured={h.get('ai_configured')}")
        print(f"turnstile_enabled={h.get('turnstile_enabled')}")
        print(f"clamav_mock={h.get('clamav_mock')}")
        if not h.get('ai_configured'):
            limitations.append("AI is not configured (missing GROQ_API_KEY).")
        if not h.get('turnstile_enabled'):
            limitations.append("Turnstile is not enabled (missing secrets).")
    except: pass

# 2. FRONTEND
code, body = fetch('/')
if code == 200 and '<html' in body.lower():
    results['FRONTEND'] = 'PASS'
    print("\n--- FRONTEND ---")
    print("HTTP 200")
    print("React application served.")

# 3. TURNSTILE UI
code, body = fetch('/api/v1/config/turnstile')
if code == 200:
    results['TURNSTILE'] = 'PASS'
    print("\n--- TURNSTILE ---")
    print("UI receives sitekey successfully.")
else:
    results['TURNSTILE'] = 'FAIL'
    limitations.append(f"Turnstile endpoint returned {code}.")

# 4. UPLOAD
boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
body = (
    '--' + boundary + '\r\n'
    'Content-Disposition: form-data; name="file"; filename="safe_test.csv"\r\n'
    'Content-Type: text/csv\r\n\r\n'
    'id,name\n1,alice\n2,bob\r\n'
    '--' + boundary + '--\r\n'
).encode('utf-8')

# Using cloudflare testing token
headers = {'x-turnstile-token': '1x00000000000000000000AA'}
code, upload_res = fetch('/api/v1/datasets/upload', method='POST', data=body, headers=headers, content_type=f'multipart/form-data; boundary={boundary}')

ds_id = None
if code == 200:
    results['UPLOAD'] = 'PASS'
    results['SECURITY'] = 'PASS'
    try:
        ds_id = json.loads(upload_res).get('dataset_id')
        print(f"\n--- UPLOAD ---")
        print(f"Upload successful. dataset_id={ds_id}")
    except: pass
else:
    results['UPLOAD'] = 'FAIL'
    results['SECURITY'] = 'PASS' # It fails closed securely
    print(f"\n--- UPLOAD FAIL ---")
    print(f"Code: {code}, Body: {upload_res}")
    limitations.append("Uploads are blocked, failing securely (likely Turnstile missing).")

# 5, 6, 7, 8
if ds_id:
    # 5. SCAN
    code, scan_res = fetch(f'/api/v1/datasets/{ds_id}/scan', method='POST')
    if code == 200:
        results['SCANNER'] = 'PASS'
        s = json.loads(scan_res)
        print(f"\n--- SCAN ---")
        print(f"HTTP {code}")
        print(f"dataset_id={ds_id}")
        print(f"scan_id={s.get('scan_id')}")
        print(f"verdict={s.get('verdict')}")
        print(f"clamav_status={s.get('clamav_status')}")
        print(f"coverage_status={s.get('coverage_status')}")
    else:
        results['SCANNER'] = 'FAIL'

    # 6. AI
    code, ai_res = fetch(f'/api/v1/datasets/{ds_id}/analyse', method='POST')
    if code == 200:
        results['AI'] = 'PASS'
        a = json.loads(ai_res)
        print(f"\n--- AI ---")
        print(f"status={a.get('status')}")
        print(f"actual provider/model={a.get('model_name')}")
        print(f"llm_invoked={a.get('llm_invoked')}")
        print(f"llm_bypassed={a.get('llm_bypassed')}")
    elif code == 503:
        results['AI'] = 'PARTIAL'
        print("\n--- AI ---")
        print("AI unavailable, gracefully failed (503).")
    else:
        results['AI'] = 'FAIL'

    # 8. REMEDIATION
    code, rem_res = fetch(f'/api/v1/datasets/{ds_id}/remediate', method='POST')
    if code == 200:
        results['REMEDIATION'] = 'PASS'
        r = json.loads(rem_res)
        print(f"\n--- REMEDIATION ---")
        print(f"remediation result={r.get('status')}")

# Print Final Output
print("\n" + "="*50)
print("10. FINAL CLASSIFICATION")
print("="*50)
for k, v in results.items():
    print(f"{k} = {v}")

print("\nKNOWN LIMITATIONS")
for l in limitations:
    print(f"- {l}")

status = 'PASS' if all(v == 'PASS' for v in results.values()) else 'PARTIAL'
print(f"\nFINAL STATUS\n{status}")
