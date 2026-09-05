# Threat Intelligence API Audit

## API Comparison
| API | Purpose | Free Availability | Limits | Decision |
|---|---|---|---|---|
| **VirusTotal** | Hash/File Reputation | Yes (API v3) | 500/day, 4/min | **ADOPT** (Hash lookup only) |
| **URLhaus** | Malware URL Reputation | Yes (Community) | Generous/Free | **ADOPT** (Malware URL lookup) |
| **AbuseIPDB** | IP Abuse/Reputation | Yes (Individual) | 1,000/day | **OPTIONAL** (Public IPs only) |
| **PhishTank** | Phishing URL Verification | Yes | Open API | **OPTIONAL** |
| **Have I Been Pwned** | Breach/Email Exposure | Paid (except passwords) | Sub-based | **REJECT** (Not dataset malware scanning) |
| **Shodan** | Exposed Service Intel | Paid/Limited Free | - | **DEFER** (Secondary to core focus) |
| **SecurityTrails**| DNS/Domain Intel | Paid/Limited Free | - | **REJECT** (Less direct value than URLhaus) |

## Final Recommendation
Target MVP: Local (ClamAV + YARA + Heuristics) -> IOC Extraction -> **VirusTotal (Hash) + URLhaus (URLs)** -> LLM -> Remediation. AbuseIPDB and PhishTank remain optional extensions if benchmarks require them.
