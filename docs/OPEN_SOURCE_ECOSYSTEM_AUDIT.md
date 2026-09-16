# Open-Source Ecosystem Audit

## 1. Executive Summary
This audit evaluates several open-source repositories for their suitability in the Aegis Node architecture. The core finding is that none of these repositories should be added to the Aegis production runtime. They are strictly classified as Antigravity development skills, reference materials, or rejected entirely due to architectural mismatch or licensing constraints.

## 2. Repository Reviews

### OpenViking
- **Purpose:** Context/memory database for agents (viking:// virtual filesystem, layered context loading).
- **License:** AGPL-3.0
- **Current Status:** Active
- **Aegis Relevance:** Low (Architectural mismatch). Aegis is a bounded security pipeline, not an autonomous agent.
- **Security Relevance:** Low.
- **Complexity:** High feature drift.
- **Runtime Decision:** **REJECTED** for runtime.
- **Antigravity Decision:** Reference only.

### agentmemory
- **Purpose:** Persistent memory for coding agents using hooks, MCP, and REST.
- **License:** Apache-2.0
- **Current Status:** Active
- **Aegis Relevance:** Low for runtime.
- **Security Relevance:** Low.
- **Complexity:** Moderate.
- **Runtime Decision:** **REJECTED** for runtime.
- **Antigravity Decision:** Optional developer skill (remembering architectural decisions and constraints).

### diagram-design
- **Purpose:** Agent Skill with editorial diagram patterns and HTML/SVG output.
- **License:** MIT
- **Current Status:** Active
- **Aegis Relevance:** High for presentation/documentation, zero for runtime.
- **Security Relevance:** Low.
- **Complexity:** Low.
- **Runtime Decision:** **REJECTED** for runtime.
- **Antigravity Decision:** **APPROVED** as selective presentation/design skill.

### scientific-agent-skills
- **Purpose:** 166 scientific/research skills compatible with Google Antigravity.
- **License:** MIT
- **Current Status:** Active
- **Aegis Relevance:** High for research planning, zero for runtime.
- **Security Relevance:** Low.
- **Complexity:** High if all skills used; low if selective.
- **Runtime Decision:** **REJECTED** for runtime.
- **Antigravity Decision:** **APPROVED** selectively (research planning, benchmark analysis, visualization).

### awesome-harness-engineering
- **Purpose:** Curated resource list for agent harness engineering.
- **License:** NOASSERTION (Ambiguous)
- **Current Status:** Active
- **Aegis Relevance:** High as a conceptual reference.
- **Security Relevance:** High conceptual relevance.
- **Complexity:** N/A.
- **Runtime Decision:** **REJECTED** for runtime.
- **Antigravity Decision:** Reference only.

### Anthropic-Cybersecurity-Skills
- **Purpose:** Cybersecurity skills mapped to ATT&CK, NIST CSF, ATLAS, etc. Contains offensive/dual-use workflows.
- **License:** Apache-2.0
- **Current Status:** Active
- **Aegis Relevance:** Moderate for defensive audit workflows.
- **Security Relevance:** High.
- **Complexity:** High.
- **Runtime Decision:** **REJECTED** for runtime.
- **Antigravity Decision:** **APPROVED** selectively for defensive workflows only. Offensive skills are strictly prohibited.

### public-apis
- **Purpose:** Curated directory of public APIs.
- **License:** MIT
- **Current Status:** Active
- **Aegis Relevance:** Low.
- **Security Relevance:** Low.
- **Complexity:** N/A.
- **Runtime Decision:** **REJECTED** for runtime.
- **Antigravity Decision:** Reference/discovery only.

## 3. Final Recommendations
- **Production Runtime Additions:** None.
- **Antigravity-Only Tools:** `diagram-design`, selective `scientific-agent-skills`, selective defensive `Anthropic-Cybersecurity-Skills`, optional `agentmemory`.
- **Reference-Only:** `awesome-harness-engineering`, `public-apis`, `OpenViking`.
- **Rejected:** `OpenViking`, NeMo, LiteLLM, LLM Guard, Guardrails AI (Unnecessary duplication for current Aegis scope).
