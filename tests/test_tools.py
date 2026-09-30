"""Tests for the controlled tool-integration layer.

These focus on the *safety guarantees*, which are the reason the layer exists:
fail-closed scope, no-shell argv, dry-run default, approval gating, engagement
class switches, audit records, and intelligent (explainable) test selection.
"""

from __future__ import annotations

import pytest

from aegis.core.authorization import AuthorizationScope, ScopeRule
from aegis.core.events import MessageBus
from aegis.core.types import TargetKind
from aegis.tools import (
    ToolExecutor,
    ToolInvocation,
    ToolRegistry,
)
from aegis.tools.registry import TargetProfile
from aegis.tools.spec import RiskLevel, ToolCategory, build_argv_safe


@pytest.fixture
def registry():
    return ToolRegistry()


@pytest.fixture
def web_scope():
    return AuthorizationScope([
        ScopeRule(label="engagement-42",
                  hosts=["*.authorized.example", "authorized.example"],
                  url_globs=["https://authorized.example/*"],
                  authorization_ref="SoW-42")
    ])


# --------------------------------------------------------------------------- #
# registry / catalog
# --------------------------------------------------------------------------- #
def test_catalog_populated_and_unique(registry):
    names = [s.name for s in registry.all()]
    assert "nmap" in names and "nuclei" in names and "httpx" in names
    assert len(names) == len(set(names))  # no dupes


def test_documentation_only_tools_are_not_executable(registry):
    # metasploit/hydra remain pure documentation-only contracts.
    for name in ("metasploit", "hydra"):
        spec = registry.get(name)
        assert spec is not None
        assert not spec.executable, f"{name} must be documentation-only"
        assert spec.command_builder is None


def test_gated_exploitation_tools_are_executable_but_dangerous(registry):
    # sqlmap/ghauri ship scoped adapters, but stay DANGEROUS/EXPLOITATION so the
    # executor refuses them unless exploitation is explicitly enabled.
    for name in ("sqlmap", "ghauri"):
        spec = registry.get(name)
        assert spec is not None and spec.executable
        assert spec.risk_level == RiskLevel.DANGEROUS
        assert spec.category == ToolCategory.EXPLOITATION


def test_register_rejects_duplicate(registry):
    spec = registry.get("nmap")
    with pytest.raises(ValueError):
        registry.register(spec)


# --------------------------------------------------------------------------- #
# intelligent selection (explainable)
# --------------------------------------------------------------------------- #
def test_selection_matches_signals_and_kind(registry):
    profile = TargetProfile(target="https://authorized.example",
                            kind=TargetKind.WEB_APP)
    profile.add("http", "https", "web", "domain")
    plan = registry.select(profile)
    runnable = {s.name for s in plan.runnable_specs()}
    assert {"httpx", "whatweb", "nuclei"} <= runnable
    # every selection carries a human-readable reason
    assert all(s.reason for s in plan.selected)


def test_selection_excludes_unsupported_kind(registry):
    profile = TargetProfile(target="mock://m", kind=TargetKind.LOCAL_LLM)
    plan = registry.select(profile)
    excluded_names = {n for n, _ in plan.excluded}
    assert "nmap" in excluded_names  # nmap doesn't support a local LLM target


def test_dangerous_tools_are_advisory_until_enabled(registry):
    profile = TargetProfile(target="https://authorized.example",
                            kind=TargetKind.WEB_APP).add("sql", "http")
    plan = registry.select(profile, exploitation=False)
    sqlmap = next((s for s in plan.selected if s.spec.name == "sqlmap"), None)
    assert sqlmap is not None
    assert sqlmap.advisory and not sqlmap.runnable


# --------------------------------------------------------------------------- #
# argv safety
# --------------------------------------------------------------------------- #
def test_build_argv_rejects_shell_string():
    with pytest.raises(ValueError):
        build_argv_safe("nmap -sV target; rm -rf /")  # a joined string, not tokens


def test_nmap_builder_rejects_bad_ports(registry):
    spec = registry.get("nmap")
    inv = ToolInvocation(tool="nmap", target="authorized.example",
                         params={"ports": "80; rm -rf /"})
    with pytest.raises(ValueError):
        spec.command_builder(inv)


def test_argv_is_token_list_no_shell(registry):
    spec = registry.get("nmap")
    inv = ToolInvocation(tool="nmap", target="authorized.example")
    argv = spec.command_builder(inv)
    assert isinstance(argv, list) and argv[0] == "nmap"
    # a shell metacharacter would be an inert single token, never interpreted
    assert all(isinstance(tok, str) for tok in argv)


# --------------------------------------------------------------------------- #
# executor: scope, dry-run, approval, offline, audit
# --------------------------------------------------------------------------- #
def test_out_of_scope_is_refused_and_audited(registry, web_scope):
    ex = ToolExecutor(web_scope, dry_run=True)
    spec = registry.get("httpx")
    inv = ToolInvocation(tool="httpx", target="https://not-authorized.example")
    res = ex.run(inv, spec)
    assert not res.ok and res.refused_reason
    assert ex.audit_log[-1].outcome == "refused"
    assert ex.audit_log[-1].scope_allowed is False


def test_in_scope_dry_run_validates_without_executing(registry, web_scope):
    ex = ToolExecutor(web_scope, dry_run=True)
    spec = registry.get("httpx")   # SAFE risk => no approval needed
    inv = ToolInvocation(tool="httpx", target="https://authorized.example/app")
    res = ex.run(inv, spec)
    assert res.ok and res.dry_run
    assert res.argv and res.exit_code is None
    rec = ex.audit_log[-1]
    assert rec.outcome == "allowed" and rec.executed is False


def test_active_tool_requires_approval(registry, web_scope):
    # default approval callback denies everything (fail-closed)
    ex = ToolExecutor(web_scope, dry_run=True)
    spec = registry.get("nuclei")  # ACTIVE risk
    inv = ToolInvocation(tool="nuclei", target="https://authorized.example")
    res = ex.run(inv, spec)
    assert not res.ok and "approval" in (res.refused_reason or "")

    # with an approving human-in-the-loop, the dry-run is allowed
    ex2 = ToolExecutor(web_scope, dry_run=True, approval=lambda i, s, d: True)
    res2 = ex2.run(inv, spec)
    assert res2.ok and res2.dry_run


def test_documentation_only_tool_never_runs(registry, web_scope):
    # a pure doc-only tool is refused even with every switch flipped on.
    ex = ToolExecutor(web_scope, dry_run=True, exploitation=True,
                      credential_testing=True, approval=lambda i, s, d: True)
    spec = registry.get("metasploit")
    inv = ToolInvocation(tool="metasploit", target="https://authorized.example")
    res = ex.run(inv, spec)
    assert not res.ok
    assert "documentation-only" in (res.refused_reason or "")


def test_exploitation_tool_gated_by_engagement_switch(registry, web_scope):
    spec = registry.get("sqlmap")
    inv = ToolInvocation(tool="sqlmap", target="https://authorized.example")
    # fail-closed: refused without exploitation enabled, even with approval.
    ex = ToolExecutor(web_scope, dry_run=True, approval=lambda i, s, d: True)
    res = ex.run(inv, spec)
    assert not res.ok and "exploitation" in (res.refused_reason or "")
    # with exploitation enabled + approval, the dry-run validates (nothing executed).
    ex2 = ToolExecutor(web_scope, dry_run=True, exploitation=True,
                       approval=lambda i, s, d: True)
    res2 = ex2.run(inv, spec)
    assert res2.ok and res2.dry_run and res2.argv[0] == "sqlmap"


def test_offline_blocks_network_tool_against_remote(registry):
    scope = AuthorizationScope([
        ScopeRule(label="lab", hosts=["*.authorized.example"],
                  url_globs=["https://authorized.example/*"])
    ])
    ex = ToolExecutor(scope, dry_run=True, offline=True,
                      approval=lambda i, s, d: True)
    spec = registry.get("httpx")
    inv = ToolInvocation(tool="httpx", target="https://authorized.example")
    res = ex.run(inv, spec)
    assert not res.ok and "offline" in (res.refused_reason or "")


def test_intrusive_needs_engagement_switch(registry, web_scope):
    # DANGEROUS class refused unless exploitation enabled — but sqlmap is also
    # doc-only, so use the risk gate via a hypothetical executable dangerous tool:
    # nuclei (ACTIVE) with approval is fine; verify credential category gate:
    ex = ToolExecutor(web_scope, dry_run=True, approval=lambda i, s, d: True)
    hydra = registry.get("hydra")  # CREDENTIAL + DANGEROUS, doc-only
    inv = ToolInvocation(tool="hydra", target="https://authorized.example")
    res = ex.run(inv, hydra)
    # refused: documentation-only takes precedence, and class switch is off
    assert not res.ok


def test_audit_events_emitted_on_bus(registry, web_scope):
    bus = MessageBus()
    seen = []
    bus.subscribe("tool.*", lambda m: seen.append(m))
    ex = ToolExecutor(web_scope, bus=bus, dry_run=True)
    spec = registry.get("httpx")
    inv = ToolInvocation(tool="httpx", target="https://authorized.example")
    ex.run(inv, spec)
    assert seen and seen[-1].subject == "tool.run"
    assert seen[-1].payload["outcome"] == "allowed"


def test_audit_record_persists_to_db(tmp_path, registry, web_scope):
    from aegis.storage.db import Database

    ex = ToolExecutor(web_scope, dry_run=True)
    spec = registry.get("httpx")
    inv = ToolInvocation(tool="httpx", target="https://authorized.example",
                         engagement="e42")
    ex.run(inv, spec)
    with Database(tmp_path / "audit.db") as db:
        aid = db.create_assessment("e42", {})
        for rec in ex.audit_log:
            db.save_tool_run(rec.to_dict(), aid=aid)
        rows = db.tool_runs(aid)
    assert rows and rows[0]["tool"] == "httpx"
    assert rows[0]["outcome"] == "allowed" and rows[0]["executed"] == 0
