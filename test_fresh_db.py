import requests

BASE = "http://127.0.0.1:8000"

print("Uploading...")
r = requests.post(f"{BASE}/api/v1/datasets/upload", files={"file": ("test.csv", "col1\nval1")})
print("Upload status:", r.status_code)
assert r.status_code == 201
ds_id = r.json()["id"]

print("Scanning...")
r2 = requests.post(f"{BASE}/api/v1/datasets/{ds_id}/scan")
print("Scan status:", r2.status_code)
assert r2.status_code == 200

print("History...")
r3 = requests.get(f"{BASE}/api/v1/history?page=1&page_size=10")
print("History status:", r3.status_code)
assert r3.status_code == 200
assert len(r3.json()["items"]) > 0

print("All DB fresh start tasks passed.")
