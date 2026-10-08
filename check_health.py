import urllib.request
import urllib.error
import json

try:
    with urllib.request.urlopen('https://aegis-node.onrender.com/health', timeout=10) as r:
        print(r.getcode())
        print(r.read().decode())
except Exception as e:
    print('Failed:', e)
