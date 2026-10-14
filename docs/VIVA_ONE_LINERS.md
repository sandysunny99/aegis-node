# Aegis Node: Viva One-Liners

**Why not LLM-only?**
"Because LLMs are probabilistic interpreters, while Aegis requires deterministic and independently verifiable security controls."

**Why threat intelligence?**
"TI provides external reputation evidence, but Aegis keeps it as enrichment rather than replacing local evidence."

**Why guardrails?**
"Because dataset content can contain instructions designed to manipulate the LLM."

**Why re-scan?**
"Because remediation is not trusted until the resulting artifact is independently verified."

**Why no dynamic sandbox?**
"Aegis intentionally focuses on safe dataset-centric static analysis without executing untrusted content."

## Security hardening, October 2026 audit

**Why can't someone download another user's cleaned file?**
"Datasets are addressed by random 128-bit ids, and the one-time download token is returned only once, to the uploader, never by a read endpoint."

**Why are threat-intel lookups off by default?**
"Sending indicators from a user's dataset to a third party is a privacy decision, so every provider is opt-in and only hashes, URLs and IPs ever leave the server."

**What stops an insecure production deployment?**
"The app fails closed: in production it refuses to start with wildcard CORS, Cloudflare's test Turnstile keys, or no protection on write endpoints."

**Why not put the API key in the frontend?**
"Anything in a browser bundle is public, so the key is for server-to-server use and the public UI relies on Turnstile, rate limits and unguessable ids."

**How do you stop guardrail bypasses?**
"Detection rules look at what the text does, not at magic phrases, so appending 'was found' no longer switches a signal off."

**Can a failed scan corrupt a dataset's state?**
"No: every step after the scan is transactional, and a failure rolls back to the last good status instead of leaving it stuck."

**How do you know the tests don't leak data or keys?**
"The suite runs in a throwaway data directory with every provider key blanked, and CI also runs a secret scan on every push."
