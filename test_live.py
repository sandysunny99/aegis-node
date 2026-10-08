import urllib.request
import urllib.error
import urllib.parse
import json

BASE_URL = 'https://aegis-node.onrender.com'

def fetch(path, method='GET', data=None, headers=None, content_type=None):
    if headers is None: headers = {}
    if content_type: headers['Content-Type'] = content_type
    url = BASE_URL + path
    req = urllib.request.Request(url, method=method, headers=headers, data=data)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.getcode(), response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8')
    except Exception as e:
        return None, str(e)

print('--- 1. UPLOAD SAFE FILE ---')
boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
body = (
    '--' + boundary + '\r\n'
    'Content-Disposition: form-data; name="file"; filename="safe_test.csv"\r\n'
    'Content-Type: text/csv\r\n\r\n'
    'id,name\n1,alice\n2,bob\r\n'
    '--' + boundary + '--\r\n'
).encode('utf-8')

code, upload_res = fetch('/api/v1/datasets/upload', method='POST', data=body, content_type=f'multipart/form-data; boundary={boundary}')
print('Upload:', code, upload_res)
ds_id = None
if code == 200:
    try:
        ds_id = json.loads(upload_res).get('dataset_id')
    except: pass

if ds_id:
    print('\n--- 2. SCAN SAFE FILE ---')
    code, scan_res = fetch(f'/api/v1/datasets/{ds_id}/scan', method='POST')
    print('Scan:', code, scan_res)

    print('\n--- 3. AI ANALYSIS (BENIGN) ---')
    code, ai_res = fetch(f'/api/v1/datasets/{ds_id}/analyse', method='POST')
    print('AI:', code, ai_res)

    print('\n--- 4. TEST REMEDIATION ---')
    code, rem_res = fetch(f'/api/v1/datasets/{ds_id}/remediate', method='POST')
    print('Remediation:', code, rem_res)

print('\n--- 5. ERROR HANDLING: INVALID EXTENSION ---')
body_err = (
    '--' + boundary + '\r\n'
    'Content-Disposition: form-data; name="file"; filename="test.exe"\r\n'
    'Content-Type: application/x-msdownload\r\n\r\n'
    'MZ...\r\n'
    '--' + boundary + '--\r\n'
).encode('utf-8')
code, err_res = fetch('/api/v1/datasets/upload', method='POST', data=body_err, content_type=f'multipart/form-data; boundary={boundary}')
print('Invalid Upload:', code, err_res)
