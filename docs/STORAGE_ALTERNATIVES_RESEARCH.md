# Storage Alternatives Research

## 1. Current R2 Situation
Cloudflare R2 storage has been successfully implemented and unit-tested in the Aegis Node repository via the `R2ArtifactStorage` adapter using `boto3`. However, the live production validation is currently **BLOCKED**. The associated Cloudflare account requires activation and a valid payment method before the R2 service can be utilized, despite the existence of a free tier. The project is currently frozen to assess alternatives before making a billing or architectural decision.

## 2. Requirements for Aegis Artifact Storage
The Aegis artifact storage backend must strictly serve as a persistence layer. It must not interfere with the core security pipeline.

**Security & Functional Requirements:**
- Must store and retrieve opaque files (no execution, no shell invocation, no compilation).
- Must support private buckets/storage with no public exposure by default.
- Must support bucket-scoped credentials (server-side authentication only).
- Must support integrity verification (SHA-256 checksums).
- Must handle controlled deletion.
- Should ideally use an S3-compatible API to seamlessly fit the existing `boto3` integration.

## 3. Candidate Comparison

| Feature | R2 | Backblaze B2 | Supabase | MinIO | SeaweedFS | Tigris | AWS S3 | Local Storage |
|---------|----|--------------|----------|-------|-----------|--------|--------|---------------|
| **Type** | Managed | Managed | Managed | Self-hosted | Self-hosted | Managed | Managed | Local |
| **S3 Compatible** | Yes | Yes | Yes (API) | Yes | Yes | Yes | Native | No |
| **boto3 Support** | Yes | Yes | Yes | Yes | Yes | Yes | Yes | N/A |
| **Presigned URLs**| Yes | Yes | Yes | Yes | Yes | Yes | Yes | N/A |
| **Complexity** | Low | Low | Low | Medium | High | Low | Medium | Zero |

## 4. Cost / Free-Tier Comparison

- **Cloudflare R2**: 10 GB/month included, 1M Class A ops, 10M Class B ops, free egress. *Requires payment method/activation.*
- **Backblaze B2**: 10 GB always free. Free egress up to 3× stored data (then $0.01/GB). *No card required for free tier signups generally, highly attractive.*
- **Supabase Storage**: 1 GB free storage, 5 GB egress. *Projects pause after 1 week of inactivity on free tier.*
- **MinIO**: Free (open-source), but incurs infrastructure costs to host (VPS/server).
- **SeaweedFS**: Free (open-source), but incurs infrastructure costs.
- **Tigris**: Free tier exists, but generally targets edge/global databases.
- **AWS S3**: 5 GB storage free for 12 months (AWS Free Tier). *Requires payment method/activation.*
- **LocalArtifactStorage**: $0. No external requests. Relies on the host disk (ephemeral on Render).

## 5. Security Comparison

All managed candidates (R2, B2, AWS S3) and MinIO support:
- Private storage by default.
- Bucket-scoped access keys.
- Checksum/integrity verification during upload/download.
- Strong data exposure protections provided the bucket policy is kept private.
- Supabase storage uses RLS (Row Level Security) which maps slightly differently but achieves private storage.

## 6. Integration Comparison

Because Aegis Node uses `boto3`, switching between R2, B2, MinIO, Tigris, and AWS S3 requires exactly **zero** logic changes. 
The integration maps perfectly:
- `put_object` (upload)
- `get_object` (download)
- `delete_object` (delete)
- `head_object` (exists / metadata)
The only required change is updating the `endpoint_url` and credentials in `.env`.

## 7. Complexity Comparison

- **LOW**: LocalArtifactStorage, Backblaze B2, Cloudflare R2, Supabase, Tigris
- **MEDIUM**: AWS S3 (due to complex IAM policies), MinIO (requires setting up a Docker container or server)
- **HIGH**: SeaweedFS (distributed architecture overkill for this project)

## 8. Licensing (Open-Source Solutions)

- **MinIO**: AGPL v3.0. For an academic demo, this is fine to use internally, but distributing it commercially triggers copyleft clauses.
- **SeaweedFS**: Apache 2.0. Very permissive, but too complex to deploy.

## 9. Aegis Node Recommendation

**PRIMARY RECOMMENDATION: Continue with LocalArtifactStorage for the academic demo.**
It costs $0, requires 0 setup, and perfectly demonstrates the security pipeline without risking payment method issues.

**SECONDARY RECOMMENDATION: Backblaze B2.**
If persistent cloud storage is strictly required to survive Render reboots, B2 is the best drop-in replacement for R2. It offers 10 GB free, uses the exact same `boto3` S3-compatible API, and is highly cost-effective.

**DEFERRED OPTIONS:**
- Cloudflare R2 (Blocked by billing)
- AWS S3 (Unnecessary billing complexity)
- MinIO (Unnecessary infrastructure complexity)

## 10. Migration Impact

If switching from R2 to Backblaze B2:
1. Create a B2 bucket and Application Key.
2. Update `.env` to point `R2_ENDPOINT_URL` to the B2 S3 endpoint.
3. Rename the environment variables (e.g., `S3_ENDPOINT_URL`, `S3_ACCESS_KEY`) for semantic clarity, though technically leaving them named `R2_*` would still functionally work.
**No underlying python code logic in `file_service.py` or `storage.py` needs to change.**

## 11. Decision Matrix

| Option | Security (25%) | Simplicity (20%) | Cost (20%) | S3 API (15%) | Deployment (10%) | Academic (10%) | Weighted Total |
|--------|----------------|------------------|------------|--------------|------------------|----------------|----------------|
| Local  | 5              | 5                | 5          | 1            | 5                | 5              | **4.40**       |
| B2     | 5              | 4                | 5          | 5            | 4                | 5              | **4.70**       |
| R2     | 5              | 4                | 3          | 5            | 4                | 4              | **4.20**       |
| AWS S3 | 5              | 2                | 3          | 5            | 3                | 4              | **3.70**       |
| MinIO  | 4              | 2                | 4          | 5            | 2                | 4              | **3.55**       |

*Scoring: 1 (Poor) to 5 (Excellent). Cost score is lower for R2/AWS due to payment gates.*

## 12. Final Recommendation

**Should Aegis Node activate R2?**
No, not if it requires entering a payment method that the user is uncomfortable with for a student project. The project is fundamentally about AI/security dataset analysis, not cloud storage benchmarking.

**If not, what should replace/defer it?**
Aegis Node should simply use `LocalArtifactStorage`. It natively fulfills the requirement of storing the file temporarily for the scanner, returning it for remediation, and allowing end-to-end verification. The ephemeral nature of Render disks is perfectly acceptable for an academic demonstration.

If persistent storage is heavily desired, Backblaze B2 provides the cleanest, free S3-compatible path with zero code changes.
