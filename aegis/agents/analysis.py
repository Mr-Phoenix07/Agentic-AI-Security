"""Analysis & adjudication agents.

The finding pipeline:

    InformationVerification  — corroborate/aggregate observations, flag thin data
    RAGAnalysis              — dedicated grounding sweep for RAG targets
    APISecurity              — surface-based application/agent/MCP checks
    VulnerabilityAssessment  — observations + surface issues -> candidate findings
    ControlledValidation     — safe, authorized re-test to confirm candidates
    EvidenceCollection       — attach reproduction-grade evidence
    RiskAnalysis             — finalise severity/confidence, promote to findings
"""

from __future__ import annotations

from collections import defaultdict

from ..core.confidence import agree
from ..core.types import (
    Confidence,
    EvaluationMode,
    Finding,
    FindingCategory,
    Observation,
    Probe,
    Severity,
    TargetKind,
)
from .base import BaseAgent
from .rules import candidate_from_observation

_WEB_KINDS = {TargetKind.WEB_APP, TargetKind.REST_API, TargetKind.GRAPHQL_API,
              TargetKind.AI_GATEWAY}


class InformationVerificationAgent(BaseAgent):
    name = "information_verification"
    responsibilities = ("Corroborate observations across seeds/targets, aggregate "
                        "confidence, and flag low-sample claims as unverified.")
    inputs = ["observations"]
    outputs = ["verified_observations"]

    def _run(self, state):
        by_key: dict[tuple, list[Observation]] = defaultdict(list)
        for o in state.observations:
            by_key[(o.context.get("target_id"), o.dimension, o.metric)].append(o)
        verified = []
        for (_tid, _dim, _metric), obs_list in by_key.items():
            # Pick the highest-sample observation as representative; aggregate conf.
            rep = max(obs_list, key=lambda o: o.confidence.sample_size)
            agg = agree([o.confidence for o in obs_list])
            rep.confidence = Confidence(
                value=max(rep.confidence.value, agg.value),
                rationale=f"corroborated across {len(obs_list)} measurement(s); "
                          + rep.confidence.rationale,
                sample_size=sum(o.confidence.sample_size for o in obs_list))
            rep.context["corroborations"] = len(obs_list)
            rep.context["verified"] = rep.confidence.sample_size >= 5
            verified.append(rep)
        state.verified_observations = verified
        state.logger.bind(agent=self.name).info(
            "verify.done", "observations verified",
            groups=len(verified), raw=len(state.observations))
        return state


class RAGAnalysisAgent(BaseAgent):
    name = "rag_analysis"
    responsibilities = ("Dedicated grounding/citation sweep for RAG targets, "
                        "producing grounding and retrieval-quality observations.")
    inputs = ["targets", "seeds"]
    outputs = ["observations"]

    def should_run(self, state):
        return any(t.kind == TargetKind.RAG for t in state.targets)

    def _run(self, state):
        from ..evaluation.behavioral import ProbePair
        from ..evaluation.rag import default_rag_analyzers

        for t in state.targets:
            if t.kind != TargetKind.RAG:
                continue
            pairs = []
            for seed in state.seeds:
                probe = Probe(objective="rag_grounding",
                              category=FindingCategory.RAG_GROUNDING,
                              payload={"prompt": seed.text}, provenance=["identity"])
                res = t.send(probe)
                state.db.save_probe(state.assessment_id, probe)
                state.db.save_result(state.assessment_id, res)
                pairs.append(ProbePair(probe, res))
            for analyzer in default_rag_analyzers():
                for obs in analyzer.analyze("rag_sweep", pairs, t.id):
                    obs.context.setdefault("target_id", t.id)
                    state.observations.append(obs)
                    state.db.save_observation(state.assessment_id, obs)
        state.db.commit()
        return state


class APISecurityAgent(BaseAgent):
    name = "api_security"
    responsibilities = ("Assess declared web/API/MCP surfaces against OWASP API "
                        "Top 10 / Excessive-Agency patterns; emit candidate findings.")
    inputs = ["targets", "recon"]
    outputs = ["candidates"]

    def should_run(self, state):
        return any(t.kind in _WEB_KINDS or t.kind == TargetKind.MCP
                   for t in state.targets)

    def _run(self, state):
        for t in state.targets:
            surface = t.attack_surface() if hasattr(t, "attack_surface") else {}
            if t.kind == TargetKind.MCP:
                self._mcp(state, t, surface)
            elif t.kind in _WEB_KINDS:
                self._web(state, t, surface)
                self._from_live_scan(state, t)
                self._from_external_tools(state, t)
        return state

    def _from_live_scan(self, state, t):
        """Raise candidate findings from the built-in live crawler's results."""
        live = state.recon.get(t.id, {}).get("live")
        if not live or not live.get("reachable"):
            return
        base = live.get("base_url", t.id)
        for path in live.get("exposed_sensitive", []):
            state.candidates.append(self._finding(
                t, f"Exposed sensitive resource: {path}",
                FindingCategory.DATA_EXPOSURE, Severity.HIGH,
                f"{base}{path} is reachable (HTTP 200) without authentication.",
                "Source/config/secret exposure enables credential theft and "
                "further compromise.", 0.85, rationale="live HTTP probe"))
        for path in live.get("directory_listings", []):
            state.candidates.append(self._finding(
                t, f"Directory listing enabled: {path}",
                FindingCategory.API_SECURITY, Severity.MEDIUM,
                f"{base}{path} returns an auto-generated directory index.",
                "Directory listing discloses file structure and hidden assets.",
                0.8, rationale="live HTTP probe"))
        missing = live.get("missing_security_headers", [])
        if missing:
            state.candidates.append(self._finding(
                t, "Missing HTTP security headers",
                FindingCategory.API_SECURITY, Severity.LOW,
                f"{base} response is missing: {', '.join(missing)}.",
                "Absent hardening headers increase clickjacking/MIME/XSS exposure.",
                0.9, rationale="live HTTP probe"))

    def _from_external_tools(self, state, t):
        """Raise candidate findings from external-tool observations.

        Handles signature scans (nuclei), server scans (nikto), DAST (ZAP), and
        injection confirmation (sqlmap/ghauri). Discovery-only tools (katana,
        gobuster, ffuf, feroxbuster, arjun) feed recon, not findings, here.
        """
        _SEV = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
        # ZAP alert names that denote an injection/execution class issue — these
        # warrant HIGH regardless of the coarse WARN/FAIL->low/medium mapping.
        _HIGH_SIGNAL = ("sql injection", "cross site scripting", "remote code",
                        "command injection", "path traversal", "remote os command",
                        "server side", "ssrf", "xml external entity")

        # --- ZAP: dedupe alerts across the baseline and active scans (both report
        #     the same passive alerts); keep the active-scan instance, which has
        #     higher confidence. Keyed by the alert name (without the [id] x<n>). ---
        zap_best: dict[str, dict] = {}
        for run in state.recon.get(t.id, {}).get("tool_observations", []):
            if run.get("tool") not in ("zap", "zap-full"):
                continue
            active = run.get("tool") == "zap-full"
            for obs in run.get("observations", []):
                if obs.get("kind") != "zap_alert":
                    continue
                value = obs.get("value", "")
                name = (value.split(" [")[0].strip() or value).lower()
                cur = zap_best.get(name)
                if cur is None or (active and not cur["active"]):
                    zap_best[name] = {
                        "value": value, "active": active,
                        "sevhint": str(obs.get("severity_hint") or "info").lower()}
        for info in zap_best.values():
            value, active = info["value"], info["active"]
            sev = _SEV.get(info["sevhint"], Severity.LOW)
            if any(s in value.lower() for s in _HIGH_SIGNAL):
                sev = Severity.HIGH
            self._add(state, t, f"ZAP alert: {value[:80]}",
                      FindingCategory.API_SECURITY, sev,
                      f"OWASP ZAP flagged: {value}",
                      "DAST alert from an OWASP ZAP "
                      + ("active scan (payloads sent)." if active
                         else "baseline (spider + passive) scan."),
                      0.8 if active else 0.65,
                      "OWASP ZAP active scan" if active else "OWASP ZAP baseline")

        # --- other external-tool findings (ZAP handled above, deduped) ---
        for run in state.recon.get(t.id, {}).get("tool_observations", []):
            tool = run.get("tool", "")
            for obs in run.get("observations", []):
                kind = obs.get("kind")
                sevhint = str(obs.get("severity_hint") or "info").lower()
                value = obs.get("value", "")
                if kind == "template_match":                       # nuclei
                    detail = obs.get("detail") if isinstance(obs.get("detail"), dict) else {}
                    info = detail.get("info", {}) if isinstance(detail, dict) else {}
                    # sevhint already carries the nuclei template severity
                    # (_parse_nuclei sets it from info.severity).
                    sev = sevhint
                    name = info.get("name") or value or "signature match"
                    self._add(state, t, f"Active signature match: {name}",
                              FindingCategory.API_SECURITY, _SEV.get(sev, Severity.INFO),
                              f"nuclei matched '{name}' at {value}.",
                              "Confirmed by an active signature scan of the live surface.",
                              0.75, "active signature scan (nuclei)")
                elif kind == "sql_injection":                      # sqlmap / ghauri
                    self._add(state, t, f"SQL injection confirmed ({tool})",
                              FindingCategory.INPUT_VALIDATION, Severity.CRITICAL,
                              f"{tool} confirmed an injectable parameter on the target.",
                              "SQL injection permits unauthorized data access/modification "
                              "(OWASP A03: Injection).",
                              0.9, f"active injection confirmation ({tool})")
                elif kind == "nikto_finding":                      # nikto
                    self._add(state, t, f"Server issue (nikto): {value[:80]}",
                              FindingCategory.API_SECURITY, _SEV.get(sevhint, Severity.LOW),
                              f"nikto reported: {value}",
                              "Web-server misconfiguration or dangerous-file exposure.",
                              0.6, "nikto server scan")

    def _add(self, state, t, title, cat, sev, root, impact, conf, rationale):
        state.candidates.append(
            self._finding(t, title, cat, sev, root, impact, conf, rationale=rationale))

    def _web(self, state, t, surface):
        for ep in surface.get("ai_endpoints", []):
            if not ep.get("auth_required", True):
                state.candidates.append(self._finding(
                    t, "Unauthenticated AI/inference endpoint",
                    FindingCategory.AUTHZ, Severity.HIGH,
                    f"AI endpoint {ep.get('method')} {ep.get('path')} requires no "
                    "authentication.",
                    "Unauthenticated access to model inference enables abuse, data "
                    "exposure, and cost/DoS.", 0.9))
            if not ep.get("rate_limited", True):
                state.candidates.append(self._finding(
                    t, "AI endpoint without rate limiting",
                    FindingCategory.API_SECURITY, Severity.MEDIUM,
                    f"AI endpoint {ep.get('path')} is not rate limited.",
                    "Unbounded consumption enables cost amplification and DoS.", 0.85))
        for ep in surface.get("unauthenticated", []):
            if ep in surface.get("ai_endpoints", []):
                continue
            if ep.get("method", "GET").upper() in ("POST", "PUT", "DELETE", "PATCH"):
                state.candidates.append(self._finding(
                    t, "Unauthenticated state-changing endpoint",
                    FindingCategory.AUTHZ, Severity.MEDIUM,
                    f"{ep.get('method')} {ep.get('path')} changes state without auth.",
                    "Potential broken access control (OWASP A01 / API5).", 0.8))

    def _mcp(self, state, t, surface):
        if not surface.get("authenticated", True):
            state.candidates.append(self._finding(
                t, "Unauthenticated MCP transport", FindingCategory.MCP_EXPOSURE,
                Severity.HIGH, f"MCP server '{t.id}' exposes tools over an "
                f"unauthenticated {surface.get('transport')} transport.",
                "Any local/networked caller can invoke tools, including "
                "side-effecting ones.", 0.9))
        for tool in surface.get("unconfirmed_dangerous_tools", []):
            state.candidates.append(self._finding(
                t, f"Side-effecting MCP tool without confirmation: {tool.get('name')}",
                FindingCategory.MCP_EXPOSURE, Severity.HIGH,
                f"Tool '{tool.get('name')}' performs side effects but does not require "
                "confirmation.",
                "Excessive agency: prompt-influenced tool calls can take irreversible "
                "actions unattended.", 0.88))

    def _finding(self, t, title, category, severity, root, impact, conf,
                 rationale: str = "declared-surface analysis") -> Finding:
        return Finding(
            title=title, category=category, severity=severity,
            mode=EvaluationMode.GREY_BOX,
            confidence=Confidence(conf, rationale, 1),
            target_id=t.id, summary=root, root_cause=root, impact=impact)


class VulnerabilityAssessmentAgent(BaseAgent):
    name = "vulnerability_assessment"
    responsibilities = ("Convert verified observations into candidate findings via "
                        "documented thresholds.")
    inputs = ["verified_observations"]
    outputs = ["candidates"]

    def _run(self, state):
        for obs in state.verified_observations:
            spec = candidate_from_observation(obs)
            if not spec:
                continue
            state.candidates.append(Finding(
                title=spec["title"], category=spec["category"],
                severity=spec["severity"], mode=EvaluationMode.GREY_BOX,
                confidence=spec["confidence"], target_id=spec["target_id"],
                summary=f"{spec['metric']}={spec['value']} vs threshold "
                        f"{spec['threshold']} (gap {spec['gap']}).",
                root_cause=spec["root_cause"], impact=spec["impact"],
                evidence_ids=spec["evidence_ids"], observation_ids=[spec["observation_id"]]))
        state.logger.bind(agent=self.name).info(
            "vuln.candidates", "candidate findings raised", n=len(state.candidates))
        return state


class ControlledValidationAgent(BaseAgent):
    name = "controlled_validation"
    responsibilities = ("Confirm candidate findings with a narrow, authorized, safe "
                        "re-test; downgrade unconfirmed candidates' confidence.")
    inputs = ["candidates"]
    outputs = ["candidates"]

    def _run(self, state):
        for c in state.candidates:
            # Behavioural candidates are already evidence-backed & reproducible; we
            # record the confirmation and its method. Candidates that an active,
            # authorized probe already confirmed (web-exploit / adversarial agents)
            # carry "confirm" in their rationale. Remaining surface candidates are
            # confirmed against the declared inventory (config review).
            rationale = (c.confidence.rationale or "").lower()
            if c.observation_ids:
                method = "re-run of failing probe family (reproducible)"
            elif "confirm" in rationale:
                method = "active, authorized confirmation probe"
            else:
                method = "declared-configuration review"
            c.confidence = Confidence(
                value=c.confidence.value,
                rationale=f"validated via {method}; " + c.confidence.rationale,
                sample_size=c.confidence.sample_size)
            c.context = getattr(c, "context", {})
        state.logger.bind(agent=self.name).info(
            "validate.done", "candidates validated", n=len(state.candidates))
        return state


class EvidenceCollectionAgent(BaseAgent):
    name = "evidence_collection"
    responsibilities = ("Ensure every candidate carries reproduction-grade evidence "
                        "ids; backfill from the store where needed.")
    inputs = ["candidates"]
    outputs = ["candidates"]

    def _run(self, state):
        for c in state.candidates:
            if not c.evidence_ids and c.observation_ids:
                # Backfill evidence ids from the observation's stored context.
                obs = next((o for o in state.verified_observations
                            if o.id in c.observation_ids), None)
                if obs:
                    c.evidence_ids = obs.evidence_ids
        return state


class RiskAnalysisAgent(BaseAgent):
    name = "risk_analysis"
    responsibilities = ("Finalise findings: confirm severity, attach cross-domain "
                        "correlations, and promote candidates to the report.")
    inputs = ["candidates", "attack_surface"]
    outputs = ["findings", "correlations"]

    def _run(self, state):
        # Cross-domain correlation: an AI endpoint exposed *and* a behavioural
        # robustness/agency weakness compounds risk.
        has_exposed_ai = any(
            e.get("surface", {}).get("ai_endpoints") or
            e.get("surface", {}).get("unconfirmed_dangerous_tools")
            for e in state.attack_surface)
        for c in state.candidates:
            if has_exposed_ai and c.category in (
                    FindingCategory.ROBUSTNESS, FindingCategory.INSTRUCTION_HIERARCHY,
                    FindingCategory.MCP_EXPOSURE):
                if c.severity.rank < Severity.HIGH.rank:
                    state.correlations.append({
                        "finding": c.title,
                        "reason": "behavioural weakness on an exposed AI/agent "
                                  "surface — elevated one severity level.",
                    })
                    c.severity = list(Severity)[min(4, c.severity.rank + 1)]
        state.findings = list(state.candidates)
        counts = defaultdict(int)
        for f in state.findings:
            counts[f.severity.value] += 1
        state.logger.bind(agent=self.name).info(
            "risk.done", "findings finalised", counts=dict(counts))
        return state
