import os
import hashlib
from config import settings
from services.storage import storage_backend

def run_smoke_test():
    if not settings.r2_enabled:
        print("R2 is not enabled in configuration. Smoke test BLOCKED.")
        return False

    print(f"Running R2 Smoke Test on bucket: {settings.r2_bucket}")

    test_content = b"AEGIS R2 SMOKE TEST PAYLOAD"
    test_scan_id = "smoke-test-uuid"
    test_filename = "aegis-r2-smoke-test.txt"

    try:
        # 1. Upload
        print("1. Uploading...")
        object_key, expected_sha256 = storage_backend.save_original(test_scan_id, test_filename, test_content)
        print(f"Uploaded to key: {object_key} with SHA256: {expected_sha256}")

        # 2. Retrieve
        print("2. Retrieving...")
        retrieved_content = storage_backend.get_object(object_key)

        # 3. Verify content
        if retrieved_content != test_content:
            print("Content mismatch!")
            return False
        print("Content verified.")

        # 4. Verify SHA-256
        actual_sha256 = hashlib.sha256(retrieved_content).hexdigest()
        if actual_sha256 != expected_sha256:
            print("SHA-256 mismatch!")
            return False
        print("SHA-256 verified.")

        # 5. Check metadata/exists
        if not storage_backend.exists(object_key):
            print("Object metadata 'exists' check failed!")
            return False
        print("Metadata/exists verified.")

        # 6. Delete
        print("6. Deleting...")
        storage_backend.delete_object(object_key)

        # 7. Confirm deletion
        if storage_backend.exists(object_key):
            print("Object still exists after deletion!")
            return False
        print("Deletion confirmed.")

        print("R2 live smoke test: PASS")
        return True

    except Exception as e:
        print(f"R2 live smoke test: FAIL ({e})")
        return False

if __name__ == "__main__":
    run_smoke_test()
