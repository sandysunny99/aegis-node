# VirusTotal Integration Security

## Privacy Guarantees
- **Hash-First**: We only perform GET /api/v3/files/{sha256} lookups.
- **No File Uploads**: We NEVER POST the dataset file to VirusTotal.
- **No Private Data**: Raw rows, text, emails, and dataset structure are strictly kept local.

## Reliability Guarantees
- **Timeout**: Enforced 10-second timeout.
- **Failure state**: If VT is rate-limited (429) or unavailable (5xx), the status returns 
ate_limited or unavailable.
- **Verdict Impact**: A failed or missing VT result (
ot_found, unavailable) does **NOT** equal CLEAN. It simply means no external evidence was added. Local scanning dictates the safety baseline.
