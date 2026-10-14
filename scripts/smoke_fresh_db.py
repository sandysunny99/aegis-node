"""Manual smoke test against a running dev server: upload -> scan -> history.

Usage (from repo root, with `uvicorn main:app` running in backend/):
    python scripts/smoke_fresh_db.py
"""

import httpx

BASE = "http://127.0.0.1:8000"

print("Uploading...")
r = httpx.post(f"{BASE}/api/v1/datasets/upload", files={"file": ("test.csv", b"col1
val1
")})
print("Upload status:", r.status_code)
assert r.status_code == 201, r.text
ds_id = r.json()["dataset_id"]  # C8: the API returns dataset_id, not id

print("Scanning...")
r2 = httpx.post(f"{BASE}/api/v1/datasets/{ds_id}/scan", timeout=120)
print("Scan status:", r2.status_code)
assert r2.status_code == 200, r2.text

print("History...")
r3 = httpx.get(f"{BASE}/api/v1/history", params={"page": 1, "page_size": 10, "ids": ds_id})
print("History status:", r3.status_code)
assert r3.status_code == 200, r3.text
assert [item["dataset_id"] for item in r3.json()["items"]] == [ds_id]

print("All DB fresh start tasks passed.")
