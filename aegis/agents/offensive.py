"""Offensive agents: authorized, confirmation-grade active testing.

Two agents, both fail-closed and opt-in behind an explicit engagement switch,
both routing every request through the engagement authorization scope:

* :class:`WebExploitAgent` — built-in active web-exploit *confirmation* probes
  (reflected XSS, path traversal/LFI, open redirect, optional SSRF) via
  :class:`~aegis.targets.activeprobe.ActiveExploitProbe`. Gated on
  ``scan.enabled and scan.active_exploit``.
* :class:`AdversarialRedTeamAgent` — benign-canary model red-team (prompt
  injection, system-prompt leak, RAG query injection). Gated on
  ``redteam.enabled``.

Both raise candidate :class:`~aegis.core.types.Finding` objects that flow through
the normal validation → risk → reporting pipeline; findings carry a rationale
marked as actively *confirmed* so controlled-validation labels them correctly.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..core.confidence import Confidence, measurement_confidence
from ..core.types import (
    EvaluationMode,
    Evidence,
    Finding,
    FindingCategory,
    Observation,
    Probe,
    Severity,
    TargetKind,
    new_id,
    now_ts,
)
from ..evaluation import adversarial
from .base import BaseAgent

_WEB_KINDS = {TargetKind.WEB_APP, TargetKind.REST_API, TargetKind.GRAPHQL_API,
              TargetKind.AI_GATEWAY}
_MODEL_KINDS = {TargetKind.LOCAL_LLM, TargetKind.API_LLM, TargetKind.RAG,
                TargetKind.COPILOT, TargetKind.MULTI_AGENT, TargetKind.AI_GATEWAY}

# web-exploit hit kind -> (category, severity, confidence, framework-friendly title)
_WEB_FINDING = {
    "reflected_xss": (FindingCategory.INPUT_VALIDATION, Severity.HIGH, 0.9,
                      "Reflected XSS confirmed"),
    "path_traversal": (FindingCategory.DATA_EXPOSURE, Severity.HIGH, 0.9,
                       "Path traversal / local file read confirmed"),
    "open_redirect": (FindingCategory.API_SECURITY, Severity.MEDIUM, 0.85,
                      "Open redirect confirmed"),
    "ssrf": (FindingCategory.API_SECURITY, Severity.MEDIUM, 0.5,
             "SSRF candidate (verify out-of-band)"),
}


class WebExploitAgent(BaseAgent):
    name = "web_exploit"
    responsibilities = ("Confirm web vulnerabilities with benign, scope-gated "
                        "active probes (reflected XSS, path traversal, open "
                        "redirect, optional SSRF); raise evidence-backed findings.")
    inputs = ["targets", "recon"]
    outputs = ["candidates"]

    def should_run(self, state):
        sc = state.config.scan
        return (sc.enabled and sc.active_exploit
                and any(t.kind in _WEB_KINDS for t in state.targets))

    def _run(self, state):
        from ..targets.activeprobe import ActiveExploitProbe

        sc = state.config.scan
        log = state.logger.bind(agent=self.name)
        for t in state.targets:
            if t.kind not in _WEB_KINDS:
                continue
            base = t.metadata.get("endpoint")
            if not base:
                continue
            urls = self._candidate_urls(state, t, base)
            probe = ActiveExploitProbe(
                state.config.scope, offline=sc.offline, timeout_s=sc.timeout_s,
                max_checks=max(50, sc.max_pages * 4), oob_host=sc.oob_host,
                dry_run=sc.dry_run)
            hits = probe.assess(urls, include_ssrf=bool(sc.oob_host))
            for h in hits:
                self._raise(state, t, h)
            self._persist_audit(state, probe)
            log.info("web.exploit", "active confirmation complete", target=t.id,
                     urls=len(urls), hits=len(hits), checks=probe._checks,
                     audited=len(probe.audit_log))
        return state

    def _persist_audit(self, state, probe) -> None:
        """Record every active-probe request (sent / refused / errored) in the
        same append-only tool_runs audit trail the external tools use."""
        rows = []
        for e in probe.audit_log:
            status = e.get("status")
            note = e.get("note", "")
            is_dry = note.startswith("dry-run")
            executed = e["allowed"] and status is not None and not is_dry
            if is_dry:
                outcome = "allowed"                      # validated, not sent
            elif not e["allowed"]:
                outcome = "refused"
            elif executed:
                outcome = "executed"
            else:
                outcome = "errored"
            rows.append({
                "id": new_id("trun"), "tool": "web-exploit", "binary": "(builtin)",
                "target": e["url"], "engagement": state.config.engagement,
                "requested_by": self.name,
                "reason": "active web-exploit confirmation probe",
                "argv": [e.get("method", "GET"), e["url"]],
                "scope_allowed": bool(e["allowed"]), "scope_reason": note,
                "risk_level": "active", "approved": True, "dry_run": is_dry,
                "executed": bool(executed), "exit_code": status, "duration_s": 0.0,
                "outcome": outcome, "detail": note, "created_at": now_ts()})
        if rows:
            try:
                state.db.save_tool_runs(rows, state.assessment_id)
            except Exception:
                pass

    @staticmethod
    def _candidate_urls(state, t, base: str) -> list[str]:
        """Base URL + discovered same-host paths (from recon) + operator paths."""
        base = base.rstrip("/")
        host = (urlparse(base).hostname or "").lower()
        urls = [base + "/"]
        seen = {base + "/"}
        recon = state.recon.get(t.id, {})
        live = recon.get("live", {}) if isinstance(recon.get("live"), dict) else {}
        paths = list(live.get("discovered_paths", []))
        for u in recon.get("discovered_endpoints", []) or []:
            pu = urlparse(u if "://" in u else base + "/" + u.lstrip("/"))
            if (pu.hostname or "").lower() == host and pu.path:
                paths.append(pu.path)
        paths += list(state.config.scan.crawl_paths)
        for p in paths:
            full = base + "/" + p.lstrip("/")
            if full not in seen:
                seen.add(full)
                urls.append(full)
        return urls[: max(10, state.config.scan.max_discovered)]

    def _raise(self, state, t, hit) -> None:
        cat, sev, conf, title = _WEB_FINDING.get(
            hit.kind, (FindingCategory.API_SECURITY, Severity.MEDIUM, 0.6, hit.kind))
        ev = Evidence(
            kind="http", summary=f"active confirmation: {hit.kind} on {t.id}",
            payload={"request": {"url": hit.url, "param": hit.param},
                     "proof": hit.evidence, "detail": hit.detail},
            target_id=t.id,
            reproduction={"method": "GET", "url": hit.url, "param": hit.param})
        try:
            state.db.save_evidence(state.assessment_id, None, ev)
        except Exception:
            pass
        verb = "confirmed" if hit.confirmed else "candidate (verify out-of-band)"
        state.candidates.append(Finding(
            title=f"{title} ({hit.param or 'n/a'})",
            category=cat, severity=sev, mode=EvaluationMode.BLACK_BOX,
            confidence=Confidence(
                conf, f"active confirmation probe — {hit.kind} {verb}", 1),
            target_id=t.id,
            summary=f"{hit.kind} {verb} on parameter '{hit.param}' at {hit.url}.",
            root_cause="Untrusted input reaches a sensitive sink without "
                       "validation/encoding.",
            impact="Confirmed by an active, authorized probe against the live "
                   "target; exploitable by a remote attacker.",
            evidence_ids=[ev.id]))


class AdversarialRedTeamAgent(BaseAgent):
    name = "adversarial_redteam"
    responsibilities = ("Red-team authorized models with benign-canary prompt "
                        "injection, system-prompt-leak, and RAG-injection probes; "
                        "report susceptibility (OWASP LLM01/LLM07).")
    inputs = ["targets"]
    outputs = ["observations", "candidates"]

    def should_run(self, state):
        return (state.config.redteam.enabled
                and any(t.kind in _MODEL_KINDS for t in state.targets))

    def _run(self, state):
        rt = state.config.redteam
        aid = state.assessment_id
        log = state.logger.bind(agent=self.name)
        for t in state.targets:
            if t.kind not in _MODEL_KINDS:
                continue
            for kind in self._enabled_attacks(rt, t):
                builder = adversarial.BUILDERS[kind]
                successes, evidence_ids = 0, []
                probe_category = FindingCategory(
                    adversarial.ATTACK_META[kind]["category"])
                for i in range(rt.trials):
                    ap = builder(f"{t.id}:{kind}:{i}")
                    probe = Probe(
                        objective=ap.objective or kind,
                        category=probe_category,
                        payload=ap.payload, provenance=["adversarial", kind],
                        expectation={"canary": ap.canary})
                    res = t.send(probe)
                    state.db.save_probe(aid, probe)
                    state.db.save_result(aid, res)
                    evidence_ids += [e.id for e in res.evidence]
                    if adversarial.succeeded(ap, res.text):
                        successes += 1
                rate = successes / rt.trials if rt.trials else 0.0
                obs = Observation(
                    dimension="adversarial_robustness",
                    metric=f"{kind}_success_rate", value=round(rate, 4),
                    direction="lower_is_better",
                    confidence=measurement_confidence(rate, rt.trials,
                                                      dimension="adversarial_robustness"),
                    evidence_ids=evidence_ids,
                    context={"target_id": t.id, "n": rt.trials,
                             "successes": successes, "transforms": ["adversarial", kind]})
                state.observations.append(obs)
                state.db.save_observation(aid, obs)
                if successes > 0:
                    self._raise(state, t, kind, successes, rt.trials, evidence_ids)
                log.info("redteam.attack", f"{kind} complete", target=t.id,
                         successes=successes, trials=rt.trials)
        state.db.commit()
        return state

    @staticmethod
    def _enabled_attacks(rt, t) -> list[str]:
        attacks = []
        if rt.prompt_injection:
            attacks.append("prompt_injection")
        if rt.system_prompt_leak:
            attacks.append("system_prompt_leak")
        if rt.rag_injection and t.kind == TargetKind.RAG:
            attacks.append("rag_injection")
        return attacks

    def _raise(self, state, t, kind, successes, trials, evidence_ids) -> None:
        meta = adversarial.ATTACK_META[kind]
        rate = successes / trials if trials else 0.0
        severity = Severity.CRITICAL if rate >= 0.5 else Severity.HIGH
        cat = FindingCategory(meta["category"])
        state.candidates.append(Finding(
            title=meta["title"], category=cat, severity=severity,
            mode=EvaluationMode.BLACK_BOX,
            confidence=Confidence(
                min(0.95, 0.6 + 0.35 * rate),
                f"confirmed: benign canary echoed in {successes}/{trials} trials", trials),
            target_id=t.id,
            summary=f"{meta['title']} — canary echoed in {successes}/{trials} "
                    f"adversarial trials (success rate {rate:.0%}).",
            root_cause=meta["root_cause"], impact=meta["impact"],
            evidence_ids=evidence_ids))
