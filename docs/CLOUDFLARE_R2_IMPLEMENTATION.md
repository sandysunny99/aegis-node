# Cloudflare R2 Artifact Storage Implementation

This document describes the Phase 8B architectural enhancement implementing Cloudflare R2 object storage.

## Architecture & Data Flow

R2 has been introduced strictly as an **Artifact Storage Backend**. It manages persistence of dataset uploads, sanitized artifacts, and security reports without replacing the underlying analysis engines or the SQLite operational database.

**Data Flow:**
1. **Upload:** Files stream directly into a local ephemeral temporary file (to enforce size/magic byte validation without exhausting RAM).
2. **Storage:** The `R2ArtifactStorage` adapter immediately uploads the file to R2 via the `boto3` client, returning the `object_key` and verifying the `sha256` integrity hash.
3. **Scan Execution:** The scanner requires a local file to pass to `clamdscan` and YARA. If the file is still present locally (which it is immediately after upload), the local path is used. If a user triggers a manual re-scan and the container has rebooted (ephemeral disk wiped), `file_service.get_sample_path` automatically requests the file from R2 via its `object_key`, downloading it locally before scanning.
4. **Remediation:** Sanitized artifacts are generated locally and uploaded to R2.

## Configuration

R2 is disabled by default for backward compatibility with local development.

```env
R2_ENABLED=true
R2_ACCOUNT_ID=your_account_id
R2_BUCKET=aegis-node-artifacts
R2_ACCESS_KEY_ID=your_access_key
R2_SECRET_ACCESS_KEY=your_secret_key
# Automatically derived if empty, or can be explicitly overridden
R2_ENDPOINT_URL=https://<R2_ACCOUNT_ID>.r2.cloudflarestorage.com
R2_REGION=auto
```

## Security Model

1. **SHA-256 Verification:** `put_object` leverages `ChecksumSHA256` to ensure the uploaded payload identically matches the client-side hash.
2. **Path Traversal Protection:** User-supplied filenames are heavily sanitized. The `object_key` uses a strict directory hierarchy:
   - `originals/<scan_id>/<sanitized_filename>`
   - `sanitized/<scan_id>/<sanitized_filename>`
   - `reports/<scan_id>/security-report.json`
3. **Private Bucket & Pre-signed URLs:** The R2 bucket **must be configured as private**. Direct public URL access should not be allowed. If users require downloads, the existing FastAPI endpoints will stream the file securely using authorization checks.

## Failure Semantics

If R2 is unavailable, an explicit `StorageUnavailableError` or `StorageError` is raised. This raises an HTTP 500 or HTTP 400 response. The application **does not** silently convert storage failures into a "CLEAN" verdict, ensuring fail-closed semantics for critical storage.

## Local Mode & Tests

When `R2_ENABLED=false`, the system uses `LocalArtifactStorage`, writing files precisely to `data/samples/` and `data/sanitized/` as before.

The testing suite utilizes Python's `unittest.mock.patch` to intercept the `boto3.client` during `test_storage.py`, ensuring CI pipelines execute the R2 integration code paths perfectly without requiring actual remote Cloudflare credentials. 269 tests are passing.

## Rollback Procedure

Since `DatasetRecord` now logs both `object_key` and `storage_backend="R2"`, rolling back consists of setting `R2_ENABLED=false`. All new uploads will default to local storage. Previously uploaded R2 files would require manual fetching or an export script if the R2 bucket was detached permanently.
