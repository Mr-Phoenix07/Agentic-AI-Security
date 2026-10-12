from __future__ import annotations

import pytest

from aegis.core.authorization import (
    AuthorizationError,
    AuthorizationScope,
    ScopeRule,
    localhost_scope,
)


def test_empty_scope_denies_everything():
    scope = AuthorizationScope()
    assert scope.is_empty
    assert not scope.check_url("https://example.com").allowed
    with pytest.raises(AuthorizationError):
        scope.require_url("https://example.com")


def test_localhost_scope_allows_mock_and_localhost():
    scope = localhost_scope()
    assert scope.check_url("mock://chat").allowed
    assert scope.check_url("http://localhost:8080/v1").allowed
    assert scope.check_model("mock-secure-1").allowed


def test_unauthorized_target_is_refused():
    scope = localhost_scope()
    d = scope.check_url("https://api.openai.com/v1/chat/completions")
    assert not d.allowed
    with pytest.raises(AuthorizationError):
        scope.require_url("https://api.openai.com/v1/chat/completions")


def test_host_glob_and_cidr():
    scope = AuthorizationScope([
        ScopeRule(label="lab", hosts=["*.acme.test"], cidrs=["10.0.0.0/8"])
    ])
    assert scope.check_url("https://api.acme.test/x").allowed
    assert scope.check_url("http://10.1.2.3/y").allowed
    assert not scope.check_url("https://acme.evil.com/x").allowed


def test_rate_ceiling_enforced():
    scope = AuthorizationScope([
        ScopeRule(label="lim", model_ids=["m-*"], max_requests=2)
    ])
    # The raising enforcement path consumes the rate/volume budget.
    assert scope.require_model("m-1").allowed
    assert scope.require_model("m-1").allowed
    with pytest.raises(AuthorizationError):
        scope.require_model("m-1")                # third exceeds ceiling


def test_check_is_pure_and_does_not_consume_budget():
    # check_* is a guard predicate: it must not burn the volume budget, however
    # many times it is called. Only require_* consumes it.
    scope = AuthorizationScope([
        ScopeRule(label="lim", model_ids=["m-*"], max_requests=1)
    ])
    for _ in range(5):
        assert scope.check_model("m-1").allowed   # pure: never exceeds the ceiling
    assert scope.require_model("m-1").allowed     # first consuming call is allowed
    with pytest.raises(AuthorizationError):
        scope.require_model("m-1")                # budget now exhausted


def test_time_window():
    import time
    past = ScopeRule(label="expired", model_ids=["*"], not_after=time.time() - 10)
    scope = AuthorizationScope([past])
    assert not scope.check_model("anything").allowed


def test_dry_run_does_not_raise():
    scope = AuthorizationScope(dry_run=True)
    # No rules, but dry_run means require_* returns a decision instead of raising.
    d = scope.require_url("https://example.com")
    assert not d.allowed
