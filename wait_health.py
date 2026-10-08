import urllib.request
import urllib.error
import time
import sys

for _ in range(30):
    try:
        with urllib.request.urlopen('https://aegis-node.onrender.com/health', timeout=5) as r:
            if r.getcode() == 200:
                print("HEALTHY!")
                print(r.read().decode())
                sys.exit(0)
    except Exception as e:
        pass
    time.sleep(10)
print("Timeout waiting for health")
sys.exit(1)
