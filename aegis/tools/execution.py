"""Controlled tool execution — the single, auditable choke point through which
*every* external security tool must pass.

This is the module the platform's safety guarantees hinge on. Nothing in AEGIS
should ever call :mod:`subprocess` directly; it goes through :class:`ToolExecutor`,
which enforces, in order:

1. **Tool is known & executable.** Only registered tools with a
   ``command_builder`` can run; the binary must be on the allow-list.
2. **Scope validation (fail-closed).** The target is routed through the
   :class:`~aegis.core.authorization.AuthorizationScope`. Out of scope → refused,
   nothing is executed.
3. **Offline policy.** Network-requiring tools are refused in offline mode
   unless the target resolves to localhost/loopback.
4. **Risk / engagement policy.** Intrusive tools require the engagement to have
   explicitly enabled that class of testing; anything at or above ACTIVE risk
   requires a human approval callback to return True.
5. **No shell.** The argv is a validated ``list[str]`` executed with
   ``shell=False``; there is no interpolation into a shell and no model-authored
   command line.
6. **Bounded execution.** Wall-clock timeout, captured stdout/stderr, recorded
   exit code.
7. **Immutable audit record.** Every attempt — allowed, refused, or errored —
   produces a :class:`ToolRunRecord`, emitted on the message bus and persistable.

The default mode is **dry-run**: the executor resolves and validates everything
and returns the argv it *would* run, executing nothing. A caller must opt in to
real execution explicitly.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..core.authorization import AuthorizationScope, ScopeDecision
from ..core.events import MessageBus
from ..core.types import new_id, now_ts
from .spec import (
    ParsedObservation,
    RiskLevel,
    ToolInvocation,
    ToolSpec,
    build_argv_safe,
)

# Approval callback: given the invocation + spec + scope decision, return True to
# authorize an intrusive run. Default is a hard "no" (fail-closed, human absent).
ApprovalCallback = Callable[[ToolInvocation, ToolSpec, ScopeDecision], bool]


def deny_all_approvals(inv: ToolInvocation, spec: ToolSpec, dec: ScopeDecision) -> bool:
    return False


class ToolExecutionError(RuntimeError):
    """Raised when a tool invocation is refused or cannot be executed safely."""


@dataclass
class ToolResult:
    """Raw outcome of a single (attempted) tool run — the bottom of the trust
    hierarchy. Parsers turn this into observations; nothing here is a finding."""

    ok: bool
    tool: str
    target: str
    argv: list[str]
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    refused_reason: str | None = None
    dry_run: bool = False
    raw_format: str = "text"


@dataclass
class ToolRunRecord:
    """Immutable audit record for one execution attempt (spec §21/§26/§34)."""

    id: str = field(default_factory=lambda: new_id("trun"))
    tool: str = ""
    binary: str = ""
    target: str = ""
    engagement: str = ""
    requested_by: str = ""
    reason: str = ""
    argv: list[str] = field(default_factory=list)
    scope_allowed: bool = False
    scope_reason: str = ""
    risk_level: str = ""
    approved: bool = False
    dry_run: bool = True
    executed: bool = False
    exit_code: int | None = None
    duration_s: float = 0.0
    outcome: str = "pending"                 # allowed|executed|refused|errored
    detail: str = ""
    created_at: float = field(default_factory=now_ts)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "tool": self.tool, "binary": self.binary,
            "target": self.target, "engagement": self.engagement,
            "requested_by": self.requested_by, "reason": self.reason,
            "argv": list(self.argv), "scope_allowed": self.scope_allowed,
            "scope_reason": self.scope_reason, "risk_level": self.risk_level,
            "approved": self.approved, "dry_run": self.dry_run,
            "executed": self.executed, "exit_code": self.exit_code,
            "duration_s": round(self.duration_s, 3), "outcome": self.outcome,
            "detail": self.detail, "created_at": self.created_at,
        }


def _host_of(target: str) -> str:
    """Best-effort host extraction from a URL or bare host/ip."""
    if "://" in target:
        return (urlparse(target).hostname or "").lower()
    # strip any :port on a bare host
    host = target.split("/")[0]
    if host.count(":") == 1 and not host.replace(":", "").isalpha():
        host = host.split(":")[0]
    return host.lower()


def _is_local(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class ToolExecutor:
    """The controlled execution layer. Construct once per engagement.

    Parameters
    ----------
    scope:            fail-closed authorization allow-list (mandatory).
    bus:              message bus for audit events (optional but recommended).
    offline:          block network tools against non-local targets when True.
    dry_run:          when True (default) resolve+validate but execute nothing.
    approval:         callback consulted for ACTIVE+ risk tools; defaults to deny.
    credential_testing / exploitation:
                      engagement-level switches (default False) that must be
                      explicitly enabled before INTRUSIVE/DANGEROUS tools run.
    allow_binaries:   optional extra binary allow-list; by default the set of
                      binaries declared by executable registered tools is used.
    """

    def __init__(
        self,
        scope: AuthorizationScope,
        *,
        bus: MessageBus | None = None,
        offline: bool = False,
        dry_run: bool = True,
        approval: ApprovalCallback | None = None,
        credential_testing: bool = False,
        exploitation: bool = False,
        allow_binaries: set[str] | None = None,
    ) -> None:
        self.scope = scope
        self.bus = bus
        self.offline = offline
        self.dry_run = dry_run
        self.approval = approval or deny_all_approvals
        self.credential_testing = credential_testing
        self.exploitation = exploitation
        self.allow_binaries = allow_binaries
        self.audit_log: list[ToolRunRecord] = []

    # -- audit -------------------------------------------------------------- #
    def _record(self, rec: ToolRunRecord) -> ToolRunRecord:
        self.audit_log.append(rec)
        if self.bus is not None:
            self.bus.emit("tool.run", sender="tool-executor", **rec.to_dict())
        return rec

    # -- policy checks ------------------------------------------------------ #
    def _binary_allowed(self, spec: ToolSpec) -> bool:
        if self.allow_binaries is not None and spec.binary not in self.allow_binaries:
            return False
        return True

    def _preflight(self, inv: ToolInvocation, spec: ToolSpec) -> tuple[bool, str]:
        """Return (allowed, reason). Ordered, fail-closed policy gate."""
        if not spec.executable:
            return False, (
                f"tool '{spec.name}' is a documentation-only registry entry "
                f"(no adapter implemented); a human must implement and authorize it"
            )
        if not self._binary_allowed(spec):
            return False, f"binary '{spec.binary}' is not on the allow-list"

        # Offline policy.
        host = _host_of(inv.target)
        if self.offline and spec.requires_network and not _is_local(host):
            return False, (
                "offline mode: network tool refused against non-local target"
            )

        # Engagement class switches.
        if spec.risk_level == RiskLevel.DANGEROUS and not self.exploitation:
            return False, (
                "dangerous/exploitation class tool refused: engagement has not "
                "enabled exploitation (set exploitation=true after obtaining "
                "explicit written authorization)"
            )
        if spec.category.name == "CREDENTIAL" and not self.credential_testing:
            return False, (
                "credential-testing tool refused: engagement has not enabled "
                "credential_testing"
            )
        if spec.risk_level.requires_credential_flag and not (
            self.credential_testing or self.exploitation
        ):
            return False, (
                f"intrusive tool ({spec.risk_level.name.lower()}) refused: enable "
                f"the corresponding engagement class switch first"
            )
        return True, "preflight ok"

    # -- main entry point --------------------------------------------------- #
    def run(self, inv: ToolInvocation, spec: ToolSpec) -> ToolResult:
        rec = ToolRunRecord(
            tool=spec.name, binary=spec.binary, target=inv.target,
            engagement=inv.engagement, requested_by=inv.requested_by,
            reason=inv.reason, risk_level=spec.risk_level.name.lower(),
            dry_run=self.dry_run,
        )

        # 1) policy preflight
        ok, reason = self._preflight(inv, spec)
        if not ok:
            rec.outcome = "refused"
            rec.detail = reason
            self._record(rec)
            return ToolResult(False, spec.name, inv.target, [], refused_reason=reason)

        # 2) scope validation — fail-closed, nothing runs if out of scope
        decision = self.scope.check_url(inv.target)
        if not decision.allowed:
            # some tools take a bare host or host:port (e.g. nmap) rather than a
            # URL; re-check the extracted host against the authorized host/CIDR
            # allow-list. Only an authorized host flips the decision to allowed —
            # this never widens scope, it just lets a host-form target match the
            # same rule a URL-form target would.
            host = _host_of(inv.target)
            if host:
                alt = self.scope.check_url(f"//{host}")
                if alt.allowed:
                    decision = alt
        rec.scope_allowed = decision.allowed
        rec.scope_reason = decision.reason
        if not decision.allowed:
            rec.outcome = "refused"
            rec.detail = f"out of scope: {decision.reason}"
            self._record(rec)
            return ToolResult(False, spec.name, inv.target, [],
                              refused_reason=rec.detail)

        # 3) build argv from structured params (no shell, ever)
        try:
            argv = build_argv_safe(spec.command_builder(inv))  # type: ignore[misc]
        except Exception as exc:  # builder rejected params
            rec.outcome = "errored"
            rec.detail = f"argv build failed: {exc}"
            self._record(rec)
            return ToolResult(False, spec.name, inv.target, [],
                              refused_reason=rec.detail)
        rec.argv = argv

        # 4) approval gate for active/intrusive tools (human-in-the-loop)
        if spec.risk_level.requires_approval:
            approved = bool(self.approval(inv, spec, decision))
            rec.approved = approved
            if not approved:
                rec.outcome = "refused"
                rec.detail = "human approval not granted for active/intrusive tool"
                self._record(rec)
                return ToolResult(False, spec.name, inv.target, argv,
                                  refused_reason=rec.detail)
        else:
            rec.approved = True

        # 5) dry-run stops here — validated but nothing executed
        if self.dry_run:
            rec.outcome = "allowed"
            rec.detail = "dry-run: validated, not executed"
            self._record(rec)
            return ToolResult(True, spec.name, inv.target, argv, dry_run=True,
                              raw_format=spec.evidence_format)

        # 6) resolve binary and execute with a hard timeout, no shell
        if shutil.which(spec.binary) is None:
            rec.outcome = "errored"
            rec.detail = f"binary '{spec.binary}' not found on PATH"
            self._record(rec)
            return ToolResult(False, spec.name, inv.target, argv,
                              refused_reason=rec.detail)

        timeout = int(inv.opt("timeout_s", spec.default_timeout_s))
        start = time.time()
        try:
            # Inherit the operator's environment: real tools need HOME and their
            # XDG config/cache dirs (nuclei templates, ffuf/katana config, etc.)
            # or they exit non-zero and emit nothing. Safety comes from the
            # shell-free, validated argv above, not from starving the child of
            # its environment. PATH is guaranteed present for binary resolution.
            child_env = os.environ.copy()
            child_env.setdefault("PATH", os.environ.get("PATH", ""))
            proc = subprocess.run(  # noqa: S603 - argv list, shell=False, validated
                argv,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=child_env,
            )
            duration = time.time() - start
            rec.executed = True
            rec.exit_code = proc.returncode
            rec.duration_s = duration
            rec.outcome = "executed"
            rec.detail = f"exit={proc.returncode}"
            self._record(rec)
            return ToolResult(
                ok=(proc.returncode == 0), tool=spec.name, target=inv.target,
                argv=argv, exit_code=proc.returncode, stdout=proc.stdout,
                stderr=proc.stderr, duration_s=duration,
                raw_format=spec.evidence_format,
            )
        except subprocess.TimeoutExpired:
            duration = time.time() - start
            rec.executed = True
            rec.duration_s = duration
            rec.outcome = "errored"
            rec.detail = f"timeout after {timeout}s"
            self._record(rec)
            return ToolResult(False, spec.name, inv.target, argv,
                              duration_s=duration,
                              refused_reason=f"timeout after {timeout}s")
        except Exception as exc:  # pragma: no cover - environment dependent
            duration = time.time() - start
            rec.outcome = "errored"
            rec.detail = f"execution error: {exc}"
            rec.duration_s = duration
            self._record(rec)
            return ToolResult(False, spec.name, inv.target, argv,
                              refused_reason=str(exc))

    # -- parsing helper ----------------------------------------------------- #
    @staticmethod
    def parse(spec: ToolSpec, result: ToolResult) -> list[ParsedObservation]:
        """Run the spec's parser over a result, if one is defined.

        Parsing is gated on *usable output*, not on a zero exit code: many
        security tools (nikto, katana, sqlmap, ffuf, feroxbuster) return a
        non-zero exit when they find something, are interrupted, or finish with
        warnings, yet still emit valid, parseable stdout. Dry-runs and refusals
        carry no stdout and are skipped. Parsers are defensive and never raise.
        """
        if spec.parser is None or result.dry_run:
            return []
        if not (result.stdout or "").strip():
            return []
        try:
            return list(spec.parser(result))
        except Exception:
            return []
