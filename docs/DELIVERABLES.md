# Design Deliverables — Index

Every deliverable from the platform brief, mapped to where it is **implemented**
(code) and **documented** (docs). AEGIS is a working platform, so each deliverable
is backed by runnable code, not just prose.

| # | Deliverable | Implementation | Documentation |
|---|-------------|----------------|---------------|
| 1 | **System architecture** | package layout under `aegis/` (layered, registries) | [ARCHITECTURE §1](ARCHITECTURE.md#1-system-architecture) |
| 2 | **Multi-agent interaction diagram** | `aegis/agents/` (25 agents), `aegis/core/events.py` (bus) | [ARCHITECTURE §2](ARCHITECTURE.md#2-multi-agent-interaction) |
| 3 | **LangGraph workflow** | `aegis/graph/workflow.py` (`to_langgraph`, built-in runner) | [WORKFLOW](WORKFLOW.md) |
| 4 | **MCP integration design** | `aegis/targets/surface.py` (`MCPTarget`), `agents/analysis.py` | [MCP_INTEGRATION](MCP_INTEGRATION.md) |
| 5 | **State machine** | `aegis/graph/workflow.py` (`Phase`, `AGENT_PHASE`) | [ARCHITECTURE §3](ARCHITECTURE.md#3-state-machine) |
| 6 | **Planner logic** | `aegis/agents/planning.py` (`Planner`, `TaskScheduler`, `PIPELINES`) | [ARCHITECTURE §4](ARCHITECTURE.md#4-planner-logic) |
| 7 | **Memory architecture** | `aegis/core/memory.py`, `storage/` (episodic/semantic/regression) | [ARCHITECTURE §5](ARCHITECTURE.md#5-memory-architecture) |
| 8 | **Explainability integration** | `aegis/explainability/` (behavioral + internals-optional) | [ARCHITECTURE §6](ARCHITECTURE.md#6-explainability-integration) |
| 9 | **Evaluation metrics** | `aegis/evaluation/metrics.py`, `core/confidence.py` | [ARCHITECTURE §7](ARCHITECTURE.md#7-evaluation-metrics) |
| 10 | **Logging & observability** | `aegis/observability/` (logging + OTel-optional tracing) | [ARCHITECTURE §8](ARCHITECTURE.md#8-logging--observability) |
| 11 | **Database schema** | `aegis/storage/schema.sql`, `storage/db.py` | [DATABASE](DATABASE.md) |
| 12 | **Dashboard design** | `reporting/renderer.py` (`render_html`), `agents` `DashboardAgent` | [ARCHITECTURE §9](ARCHITECTURE.md#9-dashboard-design) |
| 13 | **CI/CD integration** | `.github/workflows/ci.yml`, CLI `--fail-on` gate | [DEPLOYMENT](DEPLOYMENT.md#cicd-integration-deliverable-13) |
| 14 | **Continuous validation workflow** | `.github/workflows/continuous-validation.yml`, `Memory.check_regression` | [DEPLOYMENT](DEPLOYMENT.md#continuous-validation-deliverable-14) |
| 15 | **Deployment recommendations** | `Dockerfile`, `docker-compose.yml`, `Makefile` | [DEPLOYMENT](DEPLOYMENT.md#deployment-topologies) |

---

## Specification coverage

**Multi-agent architecture** — all 25 named agents implemented with declared
responsibilities/inputs/outputs/memory/communication/confidence/stopping
(`aegis/agents/`, `BaseAgent`).

**AI behavioural assessment** — instruction following, reasoning consistency,
multilingual behaviour, structured output, long-context retention, contradiction/
conflict surfacing, hallucination/grounding, confidence calibration, context
management, tool usage & retrieval grounding (RAG), response stability, robustness
to formatting (`aegis/evaluation/`).

**Prompt mutation framework** — 20 transforms: Unicode normalization, homoglyphs,
Cyrillic/mixed-script, bidi edge cases, nested documents, long-context references,
academic-review framing, fictional scenarios, taxonomy organization,
JSON/XML/YAML/Markdown, tables, OCR-like, mixed language, instruction-hierarchy,
ambiguity, multi-document, persona, style, conversation restarts
(`aegis/mutation/transforms.py`).

**Adaptive evaluation loop** — the full 12-step cycle (`aegis/evaluation/loop.py`).

**Long-context, RAG, explainability, web/API, cross-domain correlation, memory &
learning, reporting** — each has a dedicated module and is exercised end-to-end by
the multi-target test (`tests/test_agents_e2e.py`).

**Black/grey/white-box** — every `Finding` and `Observation` records the
`EvaluationMode` used; explainability degrades gracefully from white-box to
behavioural.

**Framework mapping** — OWASP LLM/API/Web Top 10, ASVS, MITRE ATLAS, NIST AI RMF
(`aegis/reporting/frameworks.py`).

**Accuracy benchmark** — offline, ground-truth benchmark measuring detection
precision/recall/F1 against self-contained fixtures (vulnerable + hardened-control
cases), with documented coverage gaps reported separately. Implemented in
`aegis/benchmark/`, queryable via `aegis benchmark`, documented in
`docs/BENCHMARK.md`, with a generated report under
`docs/proof-of-concept/benchmark/`.

**Testing methodologies** — machine-readable, framework-mapped methodologies for
Web Application & API pentesting (OWASP WSTG/PTES), Active Directory security
assessment (MITRE ATT&CK, assumed-breach), and AI/LLM/agentic red-teaming (OWASP
LLM & Agentic Top 10, ATLAS, NIST AI RMF). Defensive by construction — each
technique pairs objective with detection + mitigation. Implemented in
`aegis/methodology/`, queryable via `aegis methodology`, documented in
`docs/METHODOLOGY_WEBAPP.md`, `docs/METHODOLOGY_ACTIVE_DIRECTORY.md`, and
`docs/METHODOLOGY_AI_REDTEAM.md`, and appended to every report (§11).

**Mitigations & regression tests for every confirmed finding** — attached by the
Mitigation Recommendation agent from the framework knowledge base.

**Reporting** — Executive Summary, Scope/Authorization, Architecture, Attack
Surface Inventory, AI Findings, Web/API/MCP Findings, Risk Ratings, Security
Metrics, Coverage, Mitigation Roadmap, Regression Test Plan, Appendices with
reproducible artifacts (`aegis/reporting/`).
