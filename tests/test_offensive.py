"""Tests for the offensive agents: active web-exploit confirmation and the
adversarial model red-team. All targets are local/self-owned and in-scope."""

from __future__ import annotations

import html
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qsl, urlparse

import pytest

from aegis.agents.offensive import (
    AdversarialRedTeamAgent,
    ModelToolAgent,
    WebExploitAgent,
)
from aegis.agents.planning import Planner
from aegis.core.authorization import AuthorizationScope, ScopeRule, localhost_scope
from aegis.core.config import Config, LoopConfig, RedTeamConfig, ScanConfig, TargetConfig
from aegis.core.types import FindingCategory
from aegis.graph.workflow import build_state
from aegis.providers.base import Provider, ProviderResponse
from aegis.targets.activeprobe import ActiveExploitProbe

_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


def _make_handler(*, secure: bool):
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence test server
            pass

        def do_GET(self):  # noqa: N802
            params = parse_qsl(urlparse(self.path).query, keep_blank_values=True)
            if not params:
                return self._send(200, "<html>home</html>")
            _k, v = params[0]
            low = v.lower()
            if "passwd" in low or "win.ini" in low:            # path traversal / LFI
                return self._send(200, "not found" if secure else _PASSWD)
            if v.startswith("http") or v.startswith("//"):     # open redirect
                if secure:
                    return self._send(200, "<html>ok</html>")
                self.send_response(302)
                self.send_header("Location", v)
                self.end_headers()
                return
            reflected = html.escape(v) if secure else v         # reflected XSS
            return self._send(200, f"<div>results: {reflected}</div>")

        def _send(self, code, body):
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return _H


@pytest.fixture
def live_server():
    servers = []

    def _start(secure: bool) -> str:
        srv = HTTPServer(("127.0.0.1", 0), _make_handler(secure=secure))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    yield _start
    for s in servers:
        s.shutdown()


def _scope_for(base: str) -> AuthorizationScope:
    host = urlparse(base).hostname
    return AuthorizationScope([
        ScopeRule(label="lab", hosts=[host], url_globs=[f"{base}/*", f"{base}*"],
                  authorization_ref="self-owned test lab")])


def test_active_probe_confirms_vulnerabilities(live_server):
    base = live_server(secure=False)
    probe = ActiveExploitProbe(_scope_for(base), offline=True, timeout_s=5)
    hits = {h.kind for h in probe.assess([base + "/"])}
    assert "reflected_xss" in hits
    assert "path_traversal" in hits
    assert "open_redirect" in hits


def test_active_probe_quiet_on_secure_app(live_server):
    base = live_server(secure=True)
    probe = ActiveExploitProbe(_scope_for(base), offline=True, timeout_s=5)
    assert probe.assess([base + "/"]) == []        # no false positives


def test_active_probe_is_scope_gated(live_server):
    base = live_server(secure=False)
    # a scope that authorizes a DIFFERENT host must refuse every request here
    other = AuthorizationScope([ScopeRule(label="x", hosts=["example.test"])])
    probe = ActiveExploitProbe(other, offline=True, timeout_s=5)
    assert probe.assess([base + "/"]) == []
    assert probe._checks == 0                       # nothing was ever contacted


def test_web_exploit_agent_raises_findings(live_server, tmp_path):
    base = live_server(secure=False)
    cfg = Config(
        engagement="web-exploit-test", scope=_scope_for(base), workdir=tmp_path,
        db_path=tmp_path / "w.db",
        scan=ScanConfig(enabled=True, active_exploit=True, offline=True, timeout_s=5))
    cfg.targets = [TargetConfig(id="app", kind="web_app", provider="mock",
                                endpoint=base)]
    state = build_state(cfg)
    assert WebExploitAgent().should_run(state)
    state = WebExploitAgent().run(state)
    cats = {c.category for c in state.candidates}
    assert FindingCategory.INPUT_VALIDATION in cats     # reflected XSS
    assert FindingCategory.DATA_EXPOSURE in cats        # path traversal
    assert all(c.evidence_ids for c in state.candidates)
    assert not state.errors
    # every active-probe request is recorded in the append-only tool_runs audit
    runs = state.db.tool_runs(state.assessment_id)
    assert runs and all(r["tool"] == "web-exploit" for r in runs)


def test_web_exploit_audits_requests_even_when_nothing_found(live_server, tmp_path):
    base = live_server(secure=True)
    cfg = Config(
        engagement="audit-test", scope=_scope_for(base), workdir=tmp_path,
        db_path=tmp_path / "a.db",
        scan=ScanConfig(enabled=True, active_exploit=True, offline=True, timeout_s=5))
    cfg.targets = [TargetConfig(id="app", kind="web_app", provider="mock",
                                endpoint=base)]
    state = build_state(cfg)
    state = WebExploitAgent().run(state)
    assert not state.candidates                          # secure app => no findings
    runs = state.db.tool_runs(state.assessment_id)       # but requests still audited
    assert runs and any(r["executed"] and r["scope_allowed"] for r in runs)


def test_full_pipeline_with_active_exploit(live_server, tmp_path):
    """A full run_assessment with active_exploit on must carry offensive findings
    through risk-analysis → controlled-validation → reporting without error."""
    from aegis.graph import run_assessment

    base = live_server(secure=False)
    cfg = Config(
        engagement="full-offensive", scope=_scope_for(base), workdir=tmp_path,
        db_path=tmp_path / "f.db",
        scan=ScanConfig(enabled=True, active_exploit=True, offline=True, timeout_s=5))
    cfg.targets = [TargetConfig(id="app", kind="web_app", provider="mock",
                                endpoint=base)]
    state = run_assessment(cfg)
    assert not state.errors
    titles = " ".join(f.title.lower() for f in state.findings)
    assert "xss" in titles or "traversal" in titles
    assert (tmp_path / state.assessment_id / "report.md").exists()


def test_web_exploit_dry_run_sends_nothing(live_server, tmp_path):
    """Global dry-run must send ZERO traffic: against the *vulnerable* server it
    confirms nothing (nothing was sent), yet still records the planned requests."""
    base = live_server(secure=False)
    cfg = Config(
        engagement="dry", scope=_scope_for(base), workdir=tmp_path,
        db_path=tmp_path / "d.db",
        scan=ScanConfig(enabled=True, active_exploit=True, offline=True,
                        timeout_s=5, dry_run=True))
    cfg.targets = [TargetConfig(id="app", kind="web_app", provider="mock",
                                endpoint=base)]
    state = build_state(cfg)
    state = WebExploitAgent().run(state)
    assert not state.candidates                          # nothing sent => nothing found
    runs = state.db.tool_runs(state.assessment_id)
    assert runs and all(r["dry_run"] and not r["executed"] for r in runs)
    assert all(r["outcome"] == "allowed" for r in runs)  # planned, not executed


def test_web_exploit_agent_gated_off_by_default(live_server, tmp_path):
    base = live_server(secure=False)
    cfg = Config(engagement="gated", scope=_scope_for(base), workdir=tmp_path,
                 db_path=tmp_path / "g.db",
                 scan=ScanConfig(enabled=True, active_exploit=False))
    cfg.targets = [TargetConfig(id="app", kind="web_app", provider="mock",
                                endpoint=base)]
    state = build_state(cfg)
    assert not WebExploitAgent().should_run(state)       # fail-closed default


# --- adversarial model red-team ------------------------------------------- #
class _VulnerableProvider(Provider):
    """A deliberately-insecure model: echoes any benign canary in its input
    (i.e. obeys injected instructions / leaks the planted secret)."""

    name = "vuln"

    def _complete(self, req):
        found = re.findall(r"AEGIS-[A-Z]+-[A-Z0-9]+", req.as_text())
        echo = " ".join(found) if found else "I cannot help with that."
        return ProviderResponse(text=echo, raw={"text": echo}, model=self.model)


def _redteam_state(tmp_path, provider: Provider | None):
    cfg = Config(engagement="redteam-test", scope=localhost_scope(), workdir=tmp_path,
                 db_path=tmp_path / "rt.db", loop=LoopConfig(max_rounds=1, min_rounds=1),
                 redteam=RedTeamConfig(enabled=True, trials=3))
    cfg.targets = [TargetConfig(id="llm", kind="local_llm", provider="mock",
                                model="mock-secure-1")]
    state = build_state(cfg)
    if provider is not None:
        state.targets[0].provider = provider
    return state


def test_redteam_flags_vulnerable_model(tmp_path):
    state = _redteam_state(
        tmp_path, _VulnerableProvider(scope=localhost_scope(), model="mock-secure-1"))
    assert AdversarialRedTeamAgent().should_run(state)
    state = AdversarialRedTeamAgent().run(state)
    titles = " ".join(c.title.lower() for c in state.candidates)
    assert "prompt injection" in titles
    assert "leak" in titles
    # susceptibility observations recorded, success rate 1.0 for the vulnerable model
    rates = [o.value for o in state.observations
             if o.dimension == "adversarial_robustness"]
    assert rates and max(rates) == 1.0
    assert not state.errors


def test_redteam_quiet_on_secure_model(tmp_path):
    state = _redteam_state(tmp_path, None)               # default deterministic mock
    state = AdversarialRedTeamAgent().run(state)
    assert not state.candidates                          # mock never echoes a canary
    rates = [o.value for o in state.observations
             if o.dimension == "adversarial_robustness"]
    assert rates and max(rates) == 0.0


def test_redteam_gated_off_by_default(tmp_path):
    cfg = Config(engagement="g", scope=localhost_scope(), workdir=tmp_path,
                 db_path=tmp_path / "g2.db")
    cfg.targets = [TargetConfig(id="llm", kind="local_llm", provider="mock",
                                model="mock-secure-1")]
    state = build_state(cfg)
    assert not AdversarialRedTeamAgent().should_run(state)
    assert cfg.redteam.enabled is False


def test_adversarial_probe_category_matches_attack(tmp_path):
    # Each attack family persists its probe under its own category, not a blanket
    # PROMPT_INJECTION: system-prompt-leak probes are stored as data_exposure.
    state = _redteam_state(
        tmp_path, _VulnerableProvider(scope=localhost_scope(), model="mock-secure-1"))
    state = AdversarialRedTeamAgent().run(state)
    cats = {r[0] for r in state.db.conn.execute(
        "SELECT DISTINCT category FROM probes").fetchall()}
    assert "prompt_injection" in cats                    # injection probes
    assert "data_exposure" in cats                       # system-prompt-leak probes


def _model_tool_state(tmp_path, *, tools=("garak", "promptfoo"), execute=False,
                      endpoint="https://llm.local/v1"):
    scope = AuthorizationScope([ScopeRule(
        label="llm-lab", hosts=["llm.local"], url_globs=["https://llm.local/*"],
        authorization_ref="authorized model endpoint")])
    cfg = Config(engagement="ai-tools", scope=scope, workdir=tmp_path,
                 db_path=tmp_path / "ai.db",
                 scan=ScanConfig(enabled=True, external_tools=True, offline=False,
                                 execute_tools=execute, tools=list(tools),
                                 auto_approve_active=True))
    cfg.targets = [TargetConfig(id="llm", kind="api_llm", provider="mock",
                                model="acme-bot", endpoint=endpoint)]
    return build_state(cfg)


def test_ai_toolchain_dry_run_drives_garak(tmp_path):
    # execute_tools=False => executor dry-run: garak argv is built + audited, the
    # model endpoint is NOT contacted, and promptfoo is skipped without a config.
    state = _model_tool_state(tmp_path, execute=False)
    assert ModelToolAgent().should_run(state)
    state = ModelToolAgent().run(state)
    runs = state.db.tool_runs(state.assessment_id)
    garak = [r for r in runs if r["tool"] == "garak"]
    assert garak and garak[0]["dry_run"] == 1 and "garak" in garak[0]["argv_json"]
    assert not state.candidates                      # dry-run parses/raises nothing
    obs = state.recon["llm"]["tool_observations"]
    assert any(r["tool"] == "promptfoo"
               and "prerequisite" in (r["refused_reason"] or "") for r in obs)
    assert not state.errors


def test_ai_toolchain_finding_carries_evidence(tmp_path):
    state = _model_tool_state(tmp_path)
    t = state.targets[0]
    ModelToolAgent()._raise(state, t, "garak",
                            {"kind": "llm_vuln", "value": "jailbreak: DAN"})
    assert state.candidates and state.candidates[0].evidence_ids
    ev_id = state.candidates[0].evidence_ids[0]
    row = state.db.conn.execute(
        "SELECT id FROM evidence WHERE id=?", (ev_id,)).fetchone()
    assert row is not None                               # evidence persisted


def test_exploit_max_checks_caps_requests(live_server, tmp_path):
    base = live_server(secure=False)
    cfg = Config(
        engagement="budget", scope=_scope_for(base), workdir=tmp_path,
        db_path=tmp_path / "b.db",
        scan=ScanConfig(enabled=True, active_exploit=True, offline=True,
                        timeout_s=5, exploit_max_checks=5))
    cfg.targets = [TargetConfig(id="app", kind="web_app", provider="mock",
                                endpoint=base)]
    state = build_state(cfg)
    state = WebExploitAgent().run(state)
    executed = [r for r in state.db.tool_runs(state.assessment_id)
                if r["tool"] == "web-exploit" and r["executed"]]
    assert 0 < len(executed) <= 5                        # budget honored


def test_ai_toolchain_gated_without_model_endpoint(tmp_path):
    state = _model_tool_state(tmp_path, endpoint=None)   # mock LLM, no endpoint
    assert not ModelToolAgent().should_run(state)


def test_ai_toolchain_gated_when_tools_not_listed(tmp_path):
    state = _model_tool_state(tmp_path, tools=("httpx",))  # garak/promptfoo not allowed
    assert not ModelToolAgent().should_run(state)


def test_planner_lists_offensive_agents_only_when_enabled():
    off = Config()                                       # defaults: both gated off
    assert Planner._with_offensive(["api_security"], off) == ["api_security"]
    assert Planner._with_offensive(["adaptive_evaluation"], off) == ["adaptive_evaluation"]
    on = Config(scan=ScanConfig(active_exploit=True), redteam=RedTeamConfig(enabled=True))
    assert Planner._with_offensive(["api_security"], on) == ["api_security", "web_exploit"]
    assert Planner._with_offensive(["adaptive_evaluation"], on) == \
        ["adaptive_evaluation", "adversarial_redteam"]
