"""Report data model and builder.

Assembles the structured report the platform emits from the durable assessment
record (findings, observations, metrics, coverage, scope, timeline). The model is
render-agnostic; :mod:`aegis.reporting.renderer` turns it into Markdown / JSON /
HTML.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..core.types import Severity, now_ts


def severity_weight(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 0)


@dataclass
class Report:
    engagement: str
    generated_at: float = field(default_factory=now_ts)
    executive_summary: str = ""
    scope: dict = field(default_factory=dict)
    architecture: dict = field(default_factory=dict)
    attack_surface: list[dict] = field(default_factory=list)
    ai_findings: list[dict] = field(default_factory=list)
    web_findings: list[dict] = field(default_factory=list)
    risk_ratings: dict = field(default_factory=dict)
    metrics: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)
    mitigation_roadmap: list[dict] = field(default_factory=list)
    regression_plan: list[str] = field(default_factory=list)
    timeline: list[dict] = field(default_factory=list)
    appendices: dict = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__


class ReportBuilder:
    AI_CATEGORIES = {
        "prompt_injection", "instruction_hierarchy", "robustness", "hallucination",
        "confidence_calibration", "long_context", "rag_grounding", "rag_retrieval",
        "tool_use", "agent_autonomy", "mcp_exposure", "cross_domain",
    }
    # Target kinds that unambiguously place a finding in the AI / web section.
    # (data_exposure, api_security, … are shared categories, so the finding's
    # target kind decides first; ai_gateway/hybrid fall back to the category.)
    _AI_KINDS = {"local_llm", "api_llm", "rag", "multi_agent", "copilot", "mcp"}
    _WEB_KINDS = {"web_app", "rest_api", "graphql_api"}

    def _is_ai_finding(self, finding: dict, kind_by_target: dict) -> bool:
        kind = kind_by_target.get(finding.get("target_id"))
        if kind in self._AI_KINDS:
            return True
        if kind in self._WEB_KINDS:
            return False
        return finding.get("category") in self.AI_CATEGORIES

    def build(
        self,
        engagement: str,
        *,
        targets: list[dict],
        findings: list[dict],
        observations: list[dict],
        metrics: dict,
        coverage: dict,
        scope: dict,
        timeline: list[dict] | None = None,
    ) -> Report:
        findings = sorted(findings,
                          key=lambda f: severity_weight(f.get("severity", "info")),
                          reverse=True)
        kind_by_target = {t.get("id"): (t.get("kind") or "") for t in targets}
        ai = [f for f in findings if self._is_ai_finding(f, kind_by_target)]
        web = [f for f in findings if not self._is_ai_finding(f, kind_by_target)]

        counts = {s.value: 0 for s in Severity}
        for f in findings:
            counts[f.get("severity", "info")] = counts.get(f.get("severity", "info"), 0) + 1

        rep = Report(engagement=engagement)
        rep.scope = scope
        rep.architecture = {"targets": targets}
        rep.attack_surface = [
            {"target": t["id"], "kind": t["kind"], "surface": t.get("surface", {})}
            for t in targets
        ]
        rep.ai_findings = ai
        rep.web_findings = web
        rep.risk_ratings = {
            "counts_by_severity": counts,
            "total_findings": len(findings),
            "highest": findings[0]["severity"] if findings else "info",
        }
        rep.metrics = metrics
        rep.coverage = coverage
        rep.mitigation_roadmap = self._roadmap(findings)
        rep.regression_plan = self._regression(findings)
        rep.timeline = timeline or []
        rep.appendices = {
            "observation_count": len(observations),
            "observations": observations[:200],
            "methodologies": self._methodology_reference(),
        }
        rep.executive_summary = self._exec_summary(engagement, counts, coverage, findings)
        return rep

    def _exec_summary(self, engagement, counts, coverage, findings) -> str:
        total = sum(counts.values())
        top = findings[:3]
        cov = coverage.get("mean", coverage.get("overall", 0.0))
        lines = [
            f"Autonomous assessment of '{engagement}' evaluated behavioural "
            f"robustness, long-context retention, calibration, grounding, and "
            f"declared application/agent surfaces.",
            f"{total} finding(s): "
            + ", ".join(f"{c} {s}" for s, c in counts.items() if c) + ".",
            f"Behavioural coverage {cov:.0%} of measurable dimensions.",
        ]
        if top:
            lines.append("Highest-priority items: "
                         + "; ".join(f"{f['title']} ({f['severity']})" for f in top) + ".")
        else:
            lines.append("No material weaknesses met the reporting threshold.")
        return " ".join(lines)

    def _roadmap(self, findings) -> list[dict]:
        roadmap = []
        for f in findings:
            if severity_weight(f.get("severity", "info")) < 1:
                continue
            import json as _j

            mits = f.get("mitigations_json")
            mitigations = _j.loads(mits) if isinstance(mits, str) else (f.get("mitigations") or [])
            roadmap.append({
                "finding": f["title"],
                "severity": f["severity"],
                "priority": "P1" if f["severity"] in ("critical", "high") else "P2",
                "mitigations": mitigations,
            })
        return roadmap

    def _methodology_reference(self) -> list[dict]:
        """Compact summary of the built-in methodology knowledge base.

        Ties each report back to the phased web-app / Active Directory / AI
        red-team methodologies AEGIS ships (see ``aegis/methodology/``), so a
        reader can trace coverage to a standards-mapped test plan.
        """
        try:
            from .. import methodology as _meth
        except Exception:
            return []
        return [
            {
                "id": m.id,
                "title": m.title,
                "domain": m.domain,
                "phases": len(m.phases),
                "techniques": m.technique_count(),
                "references": m.references,
            }
            for m in _meth.list_methodologies()
        ]

    def _regression(self, findings) -> list[str]:
        import json as _j

        out: list[str] = []
        for f in findings:
            rt = f.get("regression_tests_json")
            tests = _j.loads(rt) if isinstance(rt, str) else (f.get("regression_tests") or [])
            out.extend(tests)
        # de-dup preserving order
        seen, uniq = set(), []
        for t in out:
            if t not in seen:
                seen.add(t)
                uniq.append(t)
        return uniq
