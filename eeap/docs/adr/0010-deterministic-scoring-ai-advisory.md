# ADR-0010: Deterministic scoring and correlation; LLMs advisory only

- Status: Accepted
- Date: 2026-10-12

## Context

The AI Engine must summarize, correlate, map to MITRE ATT&CK, analyze propagation, score
exposure and guide remediation. Risk scores drive prioritization and executive reporting,
so they must be reproducible, explainable and auditable. LLM output is non-deterministic
and sending infrastructure weakness data to third parties is a confidentiality risk.

## Decision

- **Authoritative logic is deterministic**: the risk score formula (doc 08), correlation
  rules (declarative YAML/JSON in `ai.correlation_rules`), MITRE mapping (static table) and
  remediation prioritization are rule-based and versioned.
- **LLMs are optional and advisory**: used only to produce natural-language summaries,
  executive narratives and remediation elaboration. `AI_LLM_PROVIDER=none` by default.
- When enabled: hostnames, usernames, IPs, domains are replaced with stable tokens before
  sending; no raw evidence is sent; prompts are not stored (only a hash); outputs are
  schema-validated, checked against a defensive-content policy, and labeled
  `generated_by=llm` in the UI and reports.
- Provider abstraction supports self-hosted models (Ollama/vLLM) for air-gapped customers.

## Consequences

- (+) Scores and scenarios are explainable and reproducible from stored factors.
- (+) Platform is fully functional with no LLM, including offline deployments.
- (−) Correlation coverage depends on rule authoring; rules are content shipped and
  versioned like controls.
