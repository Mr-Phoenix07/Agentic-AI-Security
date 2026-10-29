"""Tests for the AI/ML tool integrations: CLI adapters in the catalog (garak,
promptfoo, modelscan, netron) and the runtime-detected library registry
(giskard, ragas, ART, cleverhans, deepteam)."""

from __future__ import annotations

import pytest

from aegis import integrations as I
from aegis.tools import ToolRegistry
from aegis.tools.catalog import (
    _parse_garak,
    _parse_modelscan,
    _parse_promptfoo,
)
from aegis.tools.execution import ToolResult
from aegis.tools.spec import RiskLevel, ToolCategory, ToolInvocation


@pytest.fixture
def registry():
    return ToolRegistry()


# --- catalog registration + argv building --------------------------------- #
def test_new_ai_tools_registered(registry):
    for name in ("garak", "promptfoo", "modelscan", "netron"):
        assert registry.get(name) is not None, name
    assert registry.get("garak").category == ToolCategory.AI_REDTEAM
    assert registry.get("modelscan").risk_level == RiskLevel.SAFE
    assert registry.get("modelscan").requires_network is False
    # netron is a viewer: documentation-only (no command_builder => never auto-run)
    assert registry.get("netron").executable is False
    assert registry.get("garak").executable is True


def test_garak_argv_validates_and_builds(registry):
    spec = registry.get("garak")
    argv = spec.command_builder(ToolInvocation(
        tool="garak", target="https://llm.example/v1",
        params={"model_type": "rest", "model_name": "acme-bot",
                "probes": "promptinject dan", "generations": 3}))
    assert argv[0] == "garak" and "--model_type" in argv and "rest" in argv
    assert "--probes" in argv and "promptinject,dan" in argv   # space -> comma
    assert "--generations" in argv and "3" in argv


def test_garak_rejects_injection_in_spec(registry):
    spec = registry.get("garak")
    with pytest.raises(ValueError):
        spec.command_builder(ToolInvocation(
            tool="garak", target="https://llm.example",
            params={"probes": "promptinject; rm -rf /"}))   # shell metachars rejected


def test_modelscan_requires_path(registry):
    spec = registry.get("modelscan")
    with pytest.raises(ValueError):
        spec.command_builder(ToolInvocation(tool="modelscan", target="x"))
    argv = spec.command_builder(ToolInvocation(
        tool="modelscan", target="x", params={"path": "/models/m.pkl"}))
    assert argv == ["modelscan", "-p", "/models/m.pkl", "-r", "json", "-o", "/dev/stdout"]


# --- parsers (defensive; real output shapes) ------------------------------- #
def test_parse_modelscan_issues():
    out = ('{"summary": {"total_issues": 1}, "issues": ['
           '{"severity": "CRITICAL", "operator": "posix.system", '
           '"description": "unsafe operator"}]}')
    obs = _parse_modelscan(ToolResult(True, "modelscan", "m", [], stdout=out))
    assert obs and obs[0].kind == "model_issue" and obs[0].severity_hint == "critical"


def test_parse_garak_jsonl_failures():
    out = '{"probe": "promptinject.Hijack", "total": 10, "passed": 6}\nnoise\n'
    obs = _parse_garak(ToolResult(True, "garak", "m", [], stdout=out))
    assert obs and obs[0].kind == "llm_vuln" and obs[0].detail["failed"] == 4


def test_parsers_never_raise_on_junk():
    junk = ToolResult(True, "x", "m", [], stdout="not json at all\n\x00\n{")
    assert _parse_garak(junk) == [] or isinstance(_parse_garak(junk), list)
    assert _parse_promptfoo(junk) == []
    assert _parse_modelscan(junk) == []


# --- runtime-detected library registry ------------------------------------- #
def test_integration_registry_shape():
    names = set(I.LIBRARIES)
    assert {"giskard", "ragas", "art", "cleverhans", "deepteam"} <= names
    avail = I.availability()
    assert set(avail) == names and all(isinstance(v, bool) for v in avail.values())


def test_run_unknown_integration_is_safe():
    r = I.run("does-not-exist")
    assert r["available"] is False and "error" in r


def test_run_absent_library_returns_install_hint():
    # None of the heavy libs are installed in CI; run() must degrade gracefully
    # with an install hint and never raise or import them.
    r = I.run("giskard")
    assert r["available"] is False
    assert "pip install giskard" in r["note"]
    assert "model" in r["required_inputs"] and "dataset" in r["required_inputs"]


def test_describe_matches_spec():
    d = I.describe("ragas")
    assert d["domain"] == "rag" and d["pip_package"] == "ragas"
    assert isinstance(d["available"], bool)


def test_art_availability_probes_submodule(monkeypatch):
    # ART's top-level name "art" collides with the unrelated ASCII-art package,
    # so availability must probe a distinctive submodule and not be fooled by a
    # bare top-level "art" being importable.
    import importlib.util as u

    spec = I.LIBRARIES["art"]
    assert spec.probe_name == "art.attacks"
    seen = []

    def fake_find_spec(name):
        seen.append(name)
        if name == "art":
            return object()                    # unrelated ascii-art pkg present
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(u, "find_spec", fake_find_spec)
    assert spec.available() is False           # not fooled by top-level "art"
    assert seen == ["art.attacks"]             # probed the submodule, not "art"
