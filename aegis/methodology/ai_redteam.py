"""AI / LLM / Agentic red-teaming methodology.

Integrates the phased model popularised by the community **AI Red-Teaming Guide**
(Planning & Threat Modeling → Execution → Evaluation & Scoring → Reporting &
Remediation) and the recon→intelligence→execution→post-exploitation→triage→
remediation *pipeline* shape used by autonomous frameworks such as **redamon**,
re-expressed inside AEGIS's defensive, authorization-gated posture.

It is aligned to **OWASP Top 10 for LLM Applications (2025)**, the **OWASP Top 10
for Agentic Applications (ASI01–ASI10)**, **MITRE ATLAS**, and the **NIST AI RMF**
(Govern/Map/Measure/Manage). Techniques map directly onto AEGIS
:class:`~aegis.core.types.FindingCategory` values and the existing agent
collective, so this methodology is the human-readable companion to what the
adaptive evaluation loop already executes against the (offline) mock target and
authorized providers.
"""

from __future__ import annotations

from ..core.types import FindingCategory as FC
from ..core.types import Severity as S
from .models import Methodology, Phase, Technique

_REFERENCES = {
    "owasp_llm": "OWASP Top 10 for LLM Applications 2025",
    "owasp_agentic": "OWASP Top 10 for Agentic Applications (ASI01–ASI10)",
    "mitre_atlas": "MITRE ATLAS",
    "nist_ai_rmf": "NIST AI Risk Management Framework 1.0",
    "guide": "AI Red-Teaming Guide (requie/AI-Red-Teaming-Guide)",
    "redamon": "redamon autonomous pipeline (samugit83/redamon) — pipeline shape only",
}


AI_REDTEAM = Methodology(
    id="ai-redteam",
    title="AI / LLM / Agentic Red-Teaming",
    domain="ai_red_team",
    summary=(
        "A phased methodology for adversarial evaluation of AI systems — LLMs, RAG "
        "pipelines, and agentic/MCP surfaces — spanning threat modeling, "
        "attack-surface mapping, adversarial execution (prompt injection, "
        "jailbreak, tool/agent abuse, RAG poisoning, multimodal), evidence-based "
        "scoring, and remediation. It is the human-readable companion to AEGIS's "
        "adaptive evaluation loop and 25-agent collective."
    ),
    authorization_note=(
        "Assess only AI systems you own or are explicitly authorized to evaluate. "
        "AEGIS routes every provider request through the fail-closed authorization "
        "scope; the mutation framework produces semantics-preserving re-encodings "
        "to measure robustness and calibration, not to defeat safety controls."
    ),
    references=_REFERENCES,
    phases=[
        Phase(
            id="plan",
            name="Planning & Threat Modeling",
            goal="Define scope, objectives, risk profile, and rules of engagement before probing.",
            techniques=[
                Technique(
                    id="AIRT-PLAN-01",
                    name="Threat modeling & scoping",
                    objective="Enumerate assets, trust boundaries, and abuse cases for the AI system; set measurable objectives and an authorized scope.",
                    approach="Map data flows (prompt, context, tools, memory, outputs), identify actors and boundaries, and record a signed scope with volume/time caps.",
                    signals=["Undocumented tool/data trust boundaries", "No defined abuse cases or success criteria"],
                    detection=["N/A (governance activity)"],
                    mitigations=["Maintain an AI system card and data-flow diagram", "Define acceptance thresholds per risk"],
                    frameworks={"nist_ai_rmf": ["GOVERN 1", "MAP 1", "MAP 5"], "guide": ["Phase 1: Planning & Threat Modeling"]},
                    category=FC.OTHER,
                    severity_hint=S.INFO,
                    tags=["threat-model", "scope", "govern"],
                ),
            ],
        ),
        Phase(
            id="map",
            name="Reconnaissance & Attack-Surface Mapping",
            goal="Discover and characterise the AI surface: models, RAG stores, tools, agents, and exposed endpoints.",
            techniques=[
                Technique(
                    id="AIRT-MAP-01",
                    name="AI attack-surface detection",
                    objective="Identify inference endpoints, RAG retrieval, MCP tools/resources, and agent autonomy, and flag those that are unauthenticated or unbounded.",
                    approach="Enumerate declared surface inventory and characterise capabilities/boundaries with benign probes (AEGIS capability/boundary/recon agents).",
                    signals=["Unauthenticated inference/MCP endpoints", "Dangerous tools callable without confirmation", "Excessive agent autonomy"],
                    detection=["Inventory and monitor AI endpoints and tool grants", "Alert on unauthenticated inference traffic"],
                    mitigations=["Authenticate and rate-limit AI endpoints", "Require confirmation for side-effecting tools", "Constrain agent scopes (least agency)"],
                    frameworks={"owasp_llm": ["LLM06:2025 Excessive Agency"], "owasp_agentic": ["ASI02 Tool Misuse", "ASI05 Privilege Compromise"], "redamon": ["Recon: AI Surface detection"]},
                    category=FC.MCP_EXPOSURE,
                    severity_hint=S.MEDIUM,
                    tags=["recon", "attack-surface", "mcp", "agentic"],
                ),
            ],
        ),
        Phase(
            id="execute",
            name="Adversarial Execution",
            goal="Probe model, RAG, and agent behaviour with reproducible, semantics-preserving adversarial inputs.",
            techniques=[
                Technique(
                    id="AIRT-EXE-01",
                    name="Prompt injection & instruction-hierarchy testing",
                    objective="Measure susceptibility to direct and indirect prompt injection and to instruction-hierarchy override (system vs. user vs. tool content).",
                    approach="Apply reproducible mutation transforms and layered-instruction probes; score whether untrusted content can override authoritative instructions.",
                    signals=["Injected content overrides system policy", "Indirect injection via retrieved/tool content", "Instruction hierarchy not enforced"],
                    detection=["Log and review tool/RAG content that alters behaviour", "Output/action policy checks with anomaly alerting"],
                    mitigations=["Strong instruction hierarchy and content provenance separation", "Input/output filtering; sandbox untrusted content", "Human-in-the-loop for high-impact actions"],
                    frameworks={"owasp_llm": ["LLM01:2025 Prompt Injection"], "mitre_atlas": ["AML.T0051 LLM Prompt Injection", "AML.T0054 LLM Jailbreak"], "owasp_agentic": ["ASI01 Agent Instruction Manipulation"]},
                    category=FC.PROMPT_INJECTION,
                    severity_hint=S.HIGH,
                    tags=["prompt-injection", "jailbreak", "instruction-hierarchy"],
                ),
                Technique(
                    id="AIRT-EXE-02",
                    name="Agentic / tool-abuse & excessive-agency testing",
                    objective="Determine whether an agent can be steered to misuse tools, exceed authority, or chain actions toward a harmful goal.",
                    approach="Exercise agent tool-use under authorized scenarios; check confirmation gates, scope enforcement, and goal-hijack resistance.",
                    signals=["Side-effecting tools invoked without confirmation", "Goal hijacking via injected sub-goals", "Cross-tool privilege escalation"],
                    detection=["Audit tool-call chains; alert on dangerous tool use", "Rate/scope monitoring per agent identity"],
                    mitigations=["Least-privilege tool scopes; confirmation gates", "Action allow-lists and spending/rate caps", "Provenance-aware planning; isolate memory"],
                    frameworks={"owasp_llm": ["LLM06:2025 Excessive Agency"], "owasp_agentic": ["ASI02 Tool Misuse", "ASI03 Goal Manipulation", "ASI05 Privilege Compromise"], "mitre_atlas": ["AML.T0053 LLM Plugin Compromise"]},
                    category=FC.AGENT_AUTONOMY,
                    severity_hint=S.HIGH,
                    tags=["agentic", "tool-abuse", "excessive-agency"],
                ),
                Technique(
                    id="AIRT-EXE-03",
                    name="RAG grounding & poisoning testing",
                    objective="Assess grounding rate, unsupported-citation behaviour, and susceptibility to retrieval/context poisoning.",
                    approach="Probe with queries whose ground truth is known; measure grounding, source attribution, and behaviour on adversarial/poisoned context.",
                    signals=["High unsupported-citation rate", "Retrieved malicious content changes output", "Weak source attribution"],
                    detection=["Track grounding/attribution metrics in production", "Content integrity checks on the vector store"],
                    mitigations=["Provenance and integrity controls on the corpus", "Grounding/citation verification; refusal on low support", "Sanitize retrieved content before use"],
                    frameworks={"owasp_llm": ["LLM08:2025 Vector & Embedding Weaknesses", "LLM09:2025 Misinformation"], "mitre_atlas": ["AML.T0070 RAG Poisoning"]},
                    category=FC.RAG_GROUNDING,
                    severity_hint=S.MEDIUM,
                    tags=["rag", "grounding", "poisoning"],
                ),
                Technique(
                    id="AIRT-EXE-04",
                    name="Robustness, calibration & sensitive-data-exposure testing",
                    objective="Measure output stability under benign re-encoding, confidence calibration, and resistance to training/system-data disclosure.",
                    approach="Apply semantics-preserving transforms (Unicode/encoding/format) and consistency/calibration probes; test for system-prompt or sensitive-data leakage.",
                    signals=["Inconsistent answers to equivalent inputs", "Overconfident wrong answers", "System prompt or secrets disclosed"],
                    detection=["Monitor answer variance and refusal patterns", "DLP on model outputs"],
                    mitigations=["Input normalization; consistency checks", "Calibration training and abstention", "Prompt/secret isolation; output DLP"],
                    frameworks={"owasp_llm": ["LLM02:2025 Sensitive Information Disclosure", "LLM09:2025 Misinformation"], "mitre_atlas": ["AML.T0043 Craft Adversarial Data"], "nist_ai_rmf": ["MEASURE 2.5", "MEASURE 2.9"]},
                    category=FC.ROBUSTNESS,
                    severity_hint=S.MEDIUM,
                    tags=["robustness", "calibration", "data-exposure"],
                ),
            ],
        ),
        Phase(
            id="score",
            name="Evaluation & Scoring",
            goal="Quantify results with reproducible, statistically grounded metrics.",
            techniques=[
                Technique(
                    id="AIRT-SCORE-01",
                    name="Attack-success-rate & confidence scoring",
                    objective="Compute per-dimension success/failure rates with calibrated confidence and derive severity from measured shortfall × confidence.",
                    approach="Aggregate probe outcomes into rates with Wilson-interval confidence (AEGIS metrics/confidence); require minimum sample sizes before rating.",
                    signals=["Findings without sample size/confidence", "Severity not tied to measured impact"],
                    detection=["N/A (measurement discipline)"],
                    mitigations=["Report confidence bands and sample sizes", "Set fail-on thresholds for CI gating"],
                    frameworks={"nist_ai_rmf": ["MEASURE 2.3", "MEASURE 2.7"], "guide": ["Phase 3: Evaluation & Scoring"]},
                    category=FC.CONFIDENCE_CALIBRATION,
                    severity_hint=S.INFO,
                    tags=["asr", "confidence", "scoring"],
                ),
            ],
        ),
        Phase(
            id="remediate",
            name="Reporting & Remediation",
            goal="Deliver standards-mapped findings, mitigations, and regression tests, then re-test.",
            techniques=[
                Technique(
                    id="AIRT-REM-01",
                    name="Remediation, regression & continuous validation",
                    objective="Attach mitigation guidance and a regression test to each finding, and re-run to confirm closure and prevent regression.",
                    approach="Map findings to frameworks, generate mitigations + regression probes, and schedule continuous re-evaluation (AEGIS memory/regression + CI).",
                    signals=["Findings without mitigations or regression tests", "No re-test after remediation"],
                    detection=["Track regression suite pass/fail over time"],
                    mitigations=["Bind every finding to a regression test", "Continuous validation in CI with severity gates"],
                    frameworks={"nist_ai_rmf": ["MANAGE 4.1"], "guide": ["Phase 4: Reporting & Remediation"], "redamon": ["Triage & Remediation"]},
                    category=FC.MONITORING,
                    severity_hint=S.INFO,
                    tags=["remediation", "regression", "continuous-validation"],
                ),
            ],
        ),
    ],
)
