# Phase 9.4 TI Evidence Normalization + Fusion Report

## 1. Existing Provider Models
Prior to Phase 9.4, URLhaus and AbuseIPDB independently produced results using the `ThreatIntelResult` model and stored their outcomes as generic `ContentFinding` structures mapped into the `content_findings` list. They operated in isolated loops and generated independent metadata.

## 2. Normalized TI Schema
We introduced a generic and shared `NormalizedTIEvidence` model designed to decouple TI metadata from the final local scanning result.
Supported indicator types: `url`, `ipv4`.
Reputations: `malicious`, `suspicious`, `benign`, `unknown`.
Severity: `critical`, `high`, `medium`, `low`, `informational`.
This feeds into a central `TIFusionReport` that is ultimately exposed on the API.

## 3. URLhaus Normalization
URLhaus responses are translated seamlessly:
- `malicious` status maps to `malicious` / `critical`.
- `clean` or `not_found` maps to `benign` / `informational`.
- Errors (`timeout`, `rate_limited`, `unauthorized`) translate to an `unknown` reputation with `informational` severity, appending their specific error strings into `error_status`.

## 4. AbuseIPDB Normalization
AbuseIPDB translates gracefully:
- `malicious` -> `malicious` / `critical`.
- `suspicious` -> `suspicious` / `high`.
- `clean` -> `benign` / `informational`.
- Provider errors correctly populate `error_status` and fallback to `unknown`.

## 5. Fusion Rules
The deterministic fusion layer analyzes the list of `NormalizedTIEvidence` across checked providers and assigns an `EvidenceStrength`:
- **NONE**: No indicators were checked or no provider returned a verdict.
- **SINGLE_PROVIDER**: Exactly one provider returned actionable reputation intelligence.
- **CORROBORATED**: Multiple providers returned valid intelligence, and no logical contradiction exists.
- **CONFLICTED**: Direct contradiction detected between two valid TI responses (e.g. one `malicious` and one `benign`).
- **PROVIDER_UNAVAILABLE**: At least one indicator was checked, but the provider(s) failed with an error, preventing actionable evidence retrieval.

## 6. Conflict Semantics
If the local scanner engine marks a dataset as `clean_verified` or `clean_with_limitations`, but ANY threat intelligence provider reports a `malicious` indicator, the fusion layer triggers a `CONFLICT_TI_MALICIOUS` limitation warning.

## 7. Failure Semantics
Provider timeouts, rate limiting, and 400/500 errors gracefully fail into `error_status` states. This results in explicit limitations (e.g. `URLHAUS_UNAVAILABLE_TIMEOUT`) without throwing exceptions that would disrupt the deterministic scanner results. Unavailability is never misclassified as `benign`.

## 8. Local Verdict Authority
TI is treated strictly as enrichment evidence. No amount of `malicious` TI findings silently changes a `clean_verified` local verdict into `malicious`. The verdict explicitly reflects the output of the local `scanner.engine`. Discrepancies are highlighted through limitations.

## 9. Security Boundaries
- **No dataset-derived URL fetching:** URLs are merely queried against the URLhaus API.
- **No dataset-derived IP requesting:** IPs are merely queried against the AbuseIPDB API.
- **No reverse DNS/active probing:** Local validation checks only (`ipaddress.is_global`).
- **No secrets in logs:** Standard API key abstraction used across all providers.
- **No Remediation Execute:** TI evidence does not hook into automated file remediation/sanitization.

## 10. Test Results
- **307 / 307 Tests Passed**.
- Validation encompasses normalization mapping rules, explicit fusion strength boundaries, error resilience, and correct translation.
- `git diff --check` passed cleanly.
- `pip check` and `npm audit` verified clean environment.

## 11. Known Limitations
- TI only covers indicators extracted by the existing bounded extraction process (max 5 URLs, 5 IPs).
- Provider outages reduce enrichment coverage.
- Two providers (URLhaus, AbuseIPDB) do not constitute absolute ground truth.
- Fusion is deterministic evidence aggregation, not a probabilistic machine-learning malware classifier.
