# Final Re-Audit: API Matrix

| Endpoint | Method | Auth | File/Body | Side Effects | Security Boundary |
|----------|--------|------|-----------|--------------|-------------------|
| `/api/v1/datasets/upload` | POST | None | File | DB write, Disk | Arbitrary Binary Blocked |
| `/api/v1/datasets/{id}/scan` | POST | None | None | TI Calls, Scan | Lookup-only |
| `/api/v1/datasets/{id}/analyse`| POST | None | None | LLM Calls | Guardrails applied |
| `/api/v1/datasets/{id}/remediate`| POST | None | None | Disk write | Re-scan mandated |
