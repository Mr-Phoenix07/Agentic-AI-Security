# AI / LLM / Agentic Red-Teaming Methodology

> **Authorized use only.** Assess only AI systems you **own or are explicitly
> authorized to evaluate**. AEGIS routes every provider request through the
> fail-closed authorization scope; the mutation framework produces
> *semantics-preserving re-encodings* to measure robustness and calibration —
> **not** to defeat safety controls. Companion to
> [`aegis/methodology/ai_redteam.py`](../aegis/methodology/ai_redteam.py) — run
> `aegis methodology ai-redteam` to query it.

This methodology integrates two community sources into AEGIS's defensive,
authorization-gated posture:

- **[AI Red-Teaming Guide](https://github.com/requie/AI-Red-Teaming-Guide)** —
  the four-phase model (Planning & Threat Modeling → Execution → Evaluation &
  Scoring → Reporting & Remediation), plus its alignment to OWASP GenAI/LLM, the
  OWASP Top 10 for Agentic Applications (ASI01–ASI10), MITRE ATLAS, and NIST AI RMF.
- **[redamon](https://github.com/samugit83/redamon)** — the *pipeline shape* of an
  autonomous engagement (reconnaissance → intelligence → execution →
  post-exploitation → triage → remediation). AEGIS adopts the **structure** of that
  lifecycle while keeping its own safe-by-construction model: declared inventory +
  controlled validation + the adaptive evaluation loop, rather than an autonomous
  exploit engine with live offensive tooling.

The result maps directly onto AEGIS's existing
[`FindingCategory`](../aegis/core/types.py) values and its 25-agent collective, so
this methodology is the human-readable companion to what the adaptive evaluation
loop already runs against the offline mock target and authorized providers.

## Phases & techniques

### Phase 1 — Planning & Threat Modeling  (NIST AI RMF: Govern, Map)
| ID | Technique | Objective |
|----|-----------|-----------|
| `AIRT-PLAN-01` | Threat modeling & scoping | Enumerate assets, trust boundaries, abuse cases; set measurable objectives and an authorized scope |

Map data flows (prompt, context, tools, memory, outputs), maintain an AI system
card, and record a signed scope with volume/time caps.

### Phase 2 — Reconnaissance & Attack-Surface Mapping  (redamon: Recon / AI-surface detection)
| ID | Technique | Objective | Frameworks |
|----|-----------|-----------|------------|
| `AIRT-MAP-01` | AI attack-surface detection | Identify inference endpoints, RAG retrieval, MCP tools, agent autonomy; flag unauthenticated/unbounded ones | LLM06, ASI02/ASI05 |

Handled by AEGIS's capability/boundary/recon and attack-surface agents.

### Phase 3 — Adversarial Execution
| ID | Technique | Objective | Frameworks |
|----|-----------|-----------|------------|
| `AIRT-EXE-01` | Prompt injection & instruction-hierarchy testing | Direct/indirect injection; system-vs-user-vs-tool override | LLM01, ATLAS AML.T0051/T0054, ASI01 |
| `AIRT-EXE-02` | Agentic / tool-abuse & excessive-agency testing | Tool misuse, goal hijacking, cross-tool escalation | LLM06, ASI02/ASI03/ASI05, ATLAS AML.T0053 |
| `AIRT-EXE-03` | RAG grounding & poisoning testing | Grounding rate, unsupported citations, retrieval/context poisoning | LLM08/LLM09, ATLAS AML.T0070 |
| `AIRT-EXE-04` | Robustness, calibration & sensitive-data-exposure testing | Output stability under benign re-encoding; calibration; prompt/secret leakage | LLM02/LLM09, ATLAS AML.T0043, NIST MEASURE 2.5/2.9 |

Execution uses **reproducible, semantics-preserving** mutation transforms
([`aegis/mutation/`](../aegis/mutation/)) and layered-instruction probes, scored
deterministically so adaptivity never compromises reproducibility.

### Phase 4 — Evaluation & Scoring  (NIST AI RMF: Measure)
| ID | Technique | Objective |
|----|-----------|-----------|
| `AIRT-SCORE-01` | Attack-success-rate & confidence scoring | Per-dimension rates with Wilson-interval confidence; severity = shortfall × confidence |

Backed by [`aegis/evaluation/metrics.py`](../aegis/evaluation/metrics.py) and
[`aegis/core/confidence.py`](../aegis/core/confidence.py); minimum sample sizes are
required before a rating is assigned.

### Phase 5 — Reporting & Remediation  (NIST AI RMF: Manage)
| ID | Technique | Objective |
|----|-----------|-----------|
| `AIRT-REM-01` | Remediation, regression & continuous validation | Bind each finding to a mitigation + regression test; re-run to confirm closure |

Continuous validation runs in CI via `.github/workflows/continuous-validation.yml`
and `Memory.check_regression`.

## Attack-vector coverage (from the AI Red-Teaming Guide)

The guide's vector catalogue maps onto AEGIS techniques and categories as follows:

| Vector (guide) | AEGIS technique | Category |
|----------------|-----------------|----------|
| Prompt injection (direct/indirect/cross-plugin) | `AIRT-EXE-01` | `prompt_injection` |
| Jailbreaking (role-play/encoding/multi-turn) | `AIRT-EXE-01` | `instruction_hierarchy` |
| Agentic attacks (goal hijack, tool misuse, priv-esc) | `AIRT-EXE-02` | `agent_autonomy` |
| MCP / tool-protocol security | `AIRT-MAP-01`, `AIRT-EXE-02` | `mcp_exposure` |
| RAG-based attacks / poisoning | `AIRT-EXE-03` | `rag_grounding` |
| Adversarial examples / robustness | `AIRT-EXE-04` | `robustness` |
| Sensitive-data / model-info disclosure | `AIRT-EXE-04` | `data_exposure` |
| Misinformation / overreliance (calibration) | `AIRT-EXE-04`, `AIRT-SCORE-01` | `confidence_calibration` |

## Framework alignment

- **OWASP Top 10 for LLM Applications 2025** — LLM01–LLM10.
- **OWASP Top 10 for Agentic Applications** — ASI01–ASI10.
- **MITRE ATLAS** — adversarial ML tactics/techniques.
- **NIST AI RMF 1.0** — Govern / Map / Measure / Manage.

## References

- requie — *AI Red-Teaming Guide* (methodology, phases, framework alignment)
- samugit83 — *redamon* (autonomous engagement pipeline shape)
- OWASP GenAI / LLM & Agentic Top 10 · MITRE ATLAS · NIST AI RMF
