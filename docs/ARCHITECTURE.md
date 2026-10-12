# AEGIS Architecture

This document covers the system architecture, the multi-agent interaction model,
the state machine, planner logic, memory architecture, explainability integration,
evaluation metrics, observability, and dashboard design. (Workflow/LangGraph, MCP,
database, and deployment have dedicated docs.)

---

## 1. System architecture

AEGIS is layered so that each concern is independently testable and swappable.
The **core is pure standard library** (offline, deterministic); every heavier
integration is optional and runtime-detected.

```mermaid
flowchart TB
    subgraph Interfaces
      CLI[CLI: run / demo / mutate / scope-check]
      SDK[Python SDK / CI]
    end
    subgraph Orchestration
      ORCH[Orchestrator + Phase State Machine]
      GRAPH[Graph / LangGraph-optional]
      STATE[(AssessmentState blackboard)]
    end
    subgraph Agents[24-agent collective + orchestrator]
      A1[Planning] --- A2[Mapping/Recon]
      A2 --- A3[Interaction/Evaluation]
      A3 --- A4[Analysis/Adjudication]
      A4 --- A5[Explain/Mitigate/Report]
    end
    subgraph Engine[Evaluation engine]
      MUT[Mutation engine + 20 transforms]
      LOOP[Adaptive loop]
      ANA[Analyzers: behavioral · long-context · RAG]
      MET[Metrics + confidence]
    end
    subgraph Targets[Vendor-independent targets]
      PROV[Providers: mock · OpenAI-compatible]
      TLLM[LLM] & TRAG[RAG] & TWEB[Web/API] & TMCP[MCP]
    end
    subgraph Platform[Cross-cutting]
      AUTH[[Authorization gate — fail-closed]]
      MEM[Memory: episodic · semantic · regression]
      DB[(SQLite store)]
      OBS[Observability: logging · tracing]
      REP[Reporting: frameworks · MD/HTML/JSON]
      XAI[Explainability]
    end

    Interfaces --> Orchestration --> Agents
    Agents <--> STATE
    Agents --> Engine --> Targets
    Targets --> AUTH
    Agents --> MEM & DB & OBS
    Agents --> REP & XAI
```

**Design principles in practice**

- *Modularity* — agents/analyzers/providers/transforms are registries; add one
  without touching the rest.
- *Reproducibility* — content-addressed probes + seeded RNG + SQLite record.
- *Observability* — structured logs + spans around every agent and probe.
- *Vendor independence* — the analyzers read only response text; any provider works.
- *Security by design* — the authorization gate is on the request path, fail-closed.

---

## 2. Multi-agent interaction

Agents collaborate two ways: **directly** via declared read/write keys on the
shared `AssessmentState` blackboard, and **indirectly** via typed `Message`
events on an in-process bus (audit trail + loose coupling).

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant P as Planner
    participant M as Mapping agents
    participant E as Adaptive Evaluation
    participant V as Verification→Vuln→Validation
    participant R as Risk→Mitigation→Reporting
    participant BB as AssessmentState
    participant BUS as MessageBus

    O->>P: run(state)
    P->>BB: write seeds, plan
    P-->>BUS: agent.planner.done
    O->>M: run(state)
    M->>BB: write capabilities, boundaries, attack_surface
    O->>E: run(state)
    loop adaptive rounds
      E->>E: mutate → execute → analyze → estimate confidence → find gaps
    end
    E->>BB: write observations, metrics, coverage, pairs
    E-->>BUS: eval.round.end {coverage}
    O->>V: run(state)
    V->>BB: verified_observations → candidates (with confidence)
    O->>R: run(state)
    R->>BB: findings (+frameworks, mitigations, regression tests)
    R->>BB: report_paths (md/html/json/dashboard)
```

### The 24 agents (+ orchestrator)

The collective is 24 specialized `BaseAgent` subclasses (the numbered rows below,
which match `aegis agents` and `WORKFLOW_ORDER`), coordinated by the Orchestrator
(row 0), which drives the phases but is not itself one of the collective. Rows 11
and 16 are **offensive** agents that stay gated off (via `should_run`) unless the
engagement sets `redteam.enabled` / `scan.active_exploit` respectively.

| # | Agent | Phase | Responsibility |
|---|-------|-------|----------------|
| 0 | Orchestrator | — | Coordinate the collective across phases; enforce ordering |
| 1 | Planner | plan | Objectives → seed bank, per-target pipeline, budget |
| 2 | Task Scheduler | plan | Dependency-ordered, per-target schedule |
| 3 | Capability Mapping | map | Responsiveness, instruction-following, structured output |
| 4 | Boundary Mapping | map | Empty/oversized input, format adherence |
| 5 | Web Recon | map | Enumerate/classify declared web/API surface |
| 6 | Attack-Surface Mapping | map | Consolidate cross-target surface inventory |
| 7 | Prompt Mutation | evaluate | Own the transform catalog + reproducible generation |
| 8 | Prompt Optimization | evaluate | Prioritize transforms via historical priors (bandit) |
| 9 | Conversation | evaluate | Multi-turn context-management probe |
| 10 | Adaptive Evaluation | evaluate | Closed-loop evaluator; persist probes/observations |
| 11 | Adversarial Red-Team ⚔️ | evaluate | **Gated.** Benign-canary prompt-injection / system-prompt-leak / RAG-injection susceptibility (OWASP LLM01/LLM07) |
| 12 | Long-Context | evaluate | Systematic recall-vs-distance sweep |
| 13 | RAG Analysis | evaluate | Grounding, citation, retrieval quality |
| 14 | Information Verification | analyze | Corroborate/aggregate; flag thin data |
| 15 | API Security | analyze | OWASP API Top 10 / excessive-agency surface checks |
| 16 | Web Exploit ⚔️ | analyze | **Gated.** Active, scope-gated confirmation of reflected XSS / path traversal / open redirect / SSRF |
| 17 | Vulnerability Assessment | analyze | Observations → candidate findings (thresholds) |
| 18 | Controlled Validation | analyze | Safe, authorized confirmatory re-test |
| 19 | Evidence Collection | analyze | Reproduction-grade evidence per finding |
| 20 | Risk Analysis | analyze | Finalize severity; cross-domain correlation |
| 21 | Explainability | remediate | Behavioral + white-box-optional explanations |
| 22 | Mitigation Recommendation | remediate | Frameworks + mitigations + regression tests |
| 23 | Reporting | report | Assemble + render MD/HTML/JSON; persist |
| 24 | Dashboard | report | Machine-readable coverage/metric time-series |

Each agent extends `BaseAgent`, whose lifecycle wraps `_run` with tracing,
logging, bus events, confidence estimation, and a `should_run` **stopping/gating
condition** (e.g. API Security only runs when a web/MCP surface exists).

---

## 3. State machine

The Orchestrator advances through six phases (plus a terminal `DONE`). Agents are
mapped to phases; the phase view drives progress reporting and the report's
methodology section.

```mermaid
stateDiagram-v2
    [*] --> PLAN
    PLAN --> MAP: seeds + plan ready
    MAP --> EVALUATE: surface + capabilities mapped
    EVALUATE --> ANALYZE: coverage/confidence targets met OR budget spent
    ANALYZE --> REMEDIATE: findings finalized
    REMEDIATE --> REPORT: explanations + mitigations attached
    REPORT --> DONE: artifacts written, assessment closed
    DONE --> [*]

    EVALUATE --> EVALUATE: adaptive round (gaps remain, budget left)
```

Within `EVALUATE`, the **Adaptive Evaluation** agent runs its own inner loop
(round → analyze → gaps → refine) until `LoopConfig` stopping conditions —
`min_rounds`, `coverage_target`, `confidence_target`, `max_rounds` — are met.

---

## 4. Planner logic

```mermaid
flowchart TD
    OBJ[Objectives / seeds] --> S1{seeds provided?}
    S1 -- no --> BANK[Load benign seed bank]
    S1 -- yes --> USE[Use provided seeds]
    BANK --> PIPE
    USE --> PIPE[Per-target pipeline by TargetKind]
    PIPE --> BUDGET[Attach loop budget: rounds, coverage & confidence targets]
    BUDGET --> SCHED[Task Scheduler: dependency-ordered per-target schedule]
```

The Planner is deterministic and transparent: it selects a **pipeline per target
kind** (e.g. LLM → capability→boundary→mutation→optimization→conversation→adaptive
→long-context→explainability; MCP → attack-surface→api-security) plus a shared
adjudication tail (verify→vuln→validate→evidence→risk→mitigate). The scheduler
materializes an explicit per-target schedule for the report.

---

## 5. Memory architecture

Three tiers, all SQLite-backed so they persist and keep runs reproducible:

```mermaid
flowchart LR
    subgraph Working[Working memory]
      BB[(AssessmentState blackboard — current run)]
    end
    subgraph Episodic[Episodic memory]
      OBSH[Observation & finding history]
      VS[Prompt-variant signal — which transforms were informative]
    end
    subgraph Semantic[Semantic / regression memory]
      BASE[(Baselines per target·dimension·metric + tolerance)]
    end
    BB --> OBSH
    OBSH --> VS
    VS -->|bandit priors| PLAN2[Prompt Optimization / loop refinement]
    BASE -->|drift check| REG[Regression detection]
```

- **Working** — the live blackboard for the current assessment.
- **Episodic** — what happened, and which prompt variants produced signal.
  `transform_priors()` returns Laplace-smoothed hit-rates that bias future
  transform selection (learning *which* probes to prioritize).
- **Semantic/regression** — accepted baselines per `(target_key, dimension,
  metric)` with a tolerance; `check_regression()` flags drift across runs. This is
  the backbone of continuous validation.

Priors change *which* probes run; they never change *how* a probe is scored — so
learning and reproducibility coexist.

---

## 6. Explainability integration

```mermaid
flowchart TD
    OBS[Observation + probe/result pairs] --> BEH[Behavioral tier — always]
    BEH --> ATTR[Transform attribution: which transforms drove divergence]
    BEH --> CURVE[Recall-vs-distance curve for long context]
    BEH --> DIFF[Contrastive token diff: baseline vs most-divergent variant]
    OBS --> WB{White-box access?}
    WB -- weights + libs --> INT[TransformerLens · SHAP · Captum · BertViz]
    INT --> TOK[Token attribution · attention · residual stream · logit lens]
    WB -- no --> DEG[Documented 'unavailable' — behavioral-only, stated in report]
```

The **behavioral tier is provider-agnostic** and always runs. The **internals
tier** activates only in genuine white-box engagements (weights local + libraries
installed); otherwise the report honestly records that internals were unavailable
and exactly what *would* have been produced with access.

---

## 7. Evaluation metrics

All metrics are pure functions (see [`aegis/evaluation/metrics.py`](../aegis/evaluation/metrics.py)).

| Metric | Meaning | Direction |
|--------|---------|-----------|
| `consistency` | mean pairwise cosine similarity across variant answers | higher better |
| `stability` (per family) | 1 − divergence-rate vs identity baseline | higher better |
| `anchor_recall_rate` | long-context / multi-turn recall of an injected token | higher better |
| `ece` / `brier` | calibration of stated confidence vs correctness | lower better |
| `grounding_rate` | fraction of RAG answers whose citations are all retrieved | higher better |
| `avg_top_retrieval_score` | mean top-1 retrieval relevance | higher better |
| `conflict_acknowledgement_rate` | surfacing of layered-instruction conflicts | higher better |
| coverage | fraction of **measurable** dimensions observed | higher better |

**Confidence is precision, not magnitude.** `measurement_confidence(value, n)` =
`1 − width(Wilson 95% CI)`, so a confidently-*poor* result (value 0.0 over many
trials) is *high* confidence. Severity = f(shortfall vs threshold) discounted when
the measurement itself is low-confidence.

---

## 8. Logging & observability

```mermaid
flowchart LR
    AG[Agents/loop] -->|BoundLogger| LOG[JSON structured logs]
    AG -->|tracer.span| TR[Trace tree: orchestrator→agent→probe]
    TR -->|if installed| OTEL[OpenTelemetry → Jaeger/Tempo/Phoenix]
    TR -->|always| MEMSP[In-memory span timeline → report appendix]
    LOG --> SINK[stderr / ELK / Loki]
    DB[(SQLite)] --> MET[metrics table → Grafana/MLflow]
```

Every log record can carry `assessment_id`/`agent`/`event` for correlation. Spans
wrap every agent and probe; with OpenTelemetry installed they export to a real
backend, otherwise an in-memory timeline is embedded in the report.

---

## 9. Dashboard design

Two complementary surfaces:

- **`report.html`** — a self-contained, theme-aware dashboard (risk cards,
  AI/web/MCP finding tables, metrics, coverage). No external assets; opens
  anywhere, shareable.
- **`dashboard.json`** — machine-readable coverage/confidence **time-series per
  round** and metric snapshot, for external dashboards (Grafana, Arize Phoenix).

```mermaid
flowchart LR
    RUN[Assessment] --> HTML[report.html — human]
    RUN --> JSON[dashboard.json — machines]
    JSON --> GRAF[Grafana / Phoenix panels]
    HTML --> STAKE[Stakeholder review]
```

Dashboard schema (`dashboard.json`): `{engagement, assessment_id, coverage,
metrics, rounds:{target:[{round,coverage,mean_confidence,probes,gaps}]},
finding_counts}`.
