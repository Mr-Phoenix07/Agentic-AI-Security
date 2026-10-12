from __future__ import annotations

import json
from pathlib import Path

from aegis.agents import REGISTRY, WORKFLOW_ORDER
from aegis.core.authorization import localhost_scope
from aegis.core.config import Config, LoopConfig, TargetConfig
from aegis.graph import Phase, run_assessment
from aegis.providers import ProviderRequest, build_provider


def test_registry_agent_count():
    # 24 specialized agents (+ Orchestrator runner): 22 core + 2 offensive
    # (web_exploit, adversarial_redteam), the latter gated off by default.
    assert len(WORKFLOW_ORDER) == 24
    assert "adaptive_evaluation" in REGISTRY
    assert "risk_analysis" in REGISTRY
    assert "web_exploit" in REGISTRY and "adversarial_redteam" in REGISTRY
    assert all(cls.responsibilities for cls in WORKFLOW_ORDER)


def test_mock_provider_is_offline_and_deterministic(scope):
    p = build_provider("mock", scope=scope, model="mock-secure-1")
    r1 = p.complete(ProviderRequest(prompt="Explain TLS.", model="mock-secure-1"))
    r2 = p.complete(ProviderRequest(prompt="Explain TLS.", model="mock-secure-1"))
    assert r1.text and r1.text == r2.text
    assert r1.error is None


def test_provider_refuses_unauthorized_model():
    p = build_provider("mock", scope=localhost_scope(), model="gpt-4o")
    r = p.complete(ProviderRequest(prompt="hi", model="gpt-4o"))
    assert r.error and "Refused" in r.error


def test_full_llm_assessment_runs_clean(llm_config):
    state = run_assessment(llm_config)
    assert not state.errors
    assert "reporting" in state.trail
    assert Path(state.report_paths["markdown"]).exists()
    assert Path(state.report_paths["html"]).exists()
    # verified observations exist and coverage computed
    assert state.verified_observations
    assert 0.0 <= state.coverage.get("mean", 0) <= 1.0


def test_multi_target_assessment_exercises_all_domains(tmp_path):
    cfg = Config(engagement="multi", scope=localhost_scope(), workdir=tmp_path,
                 db_path=tmp_path / "m.db",
                 loop=LoopConfig(max_rounds=2, probes_per_round=12, min_rounds=1))
    cfg.targets = [
        TargetConfig(id="llm", kind="local_llm", provider="mock",
                     model="mock-secure-1"),
        TargetConfig(id="rag", kind="rag", provider="mock", model="mock-secure-1",
                     metadata={"corpus": [{"id": "D1", "text": "least privilege grants "
                                           "minimum access", "source": "kb"}]}),
        TargetConfig(id="api", kind="rest_api", provider="mock",
                     metadata={"endpoints": [
                         {"path": "/v1/chat", "method": "POST",
                          "auth_required": False, "is_ai_endpoint": True,
                          "rate_limited": False}]}),
        TargetConfig(id="mcp", kind="mcp", provider="mock",
                     metadata={"authenticated": False, "tools": [
                         {"name": "send_email", "dangerous": True,
                          "requires_confirmation": False}]}),
    ]
    state = run_assessment(cfg)
    assert not state.errors
    titles = " ".join(f.title for f in state.findings)
    assert "MCP" in titles                     # mcp agent fired
    assert "AI/inference endpoint" in titles   # api security agent fired
    # dashboard json emitted
    assert Path(state.report_paths["dashboard"]).exists()
    data = json.loads(Path(state.report_paths["json"]).read_text())
    assert data["risk_ratings"]["total_findings"] == len(state.findings)


def test_phase_enum_complete():
    assert {p.value for p in Phase} >= {"plan", "evaluate", "analyze", "report"}
