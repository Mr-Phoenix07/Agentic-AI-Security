"""Configuration loading for AEGIS.

Pure-stdlib config with an optional YAML upgrade (used only if ``pyyaml`` is
installed; otherwise JSON works everywhere). Config binds together the
authorization scope, targets, storage location, and evaluation thresholds.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .authorization import AuthorizationScope

try:  # optional
    import yaml  # type: ignore

    _HAVE_YAML = True
except Exception:  # pragma: no cover
    _HAVE_YAML = False


@dataclass
class TargetConfig:
    id: str
    kind: str                              # matches types.TargetKind values
    provider: str = "mock"                 # provider key
    endpoint: str | None = None
    model: str | None = None
    params: dict = field(default_factory=dict)
    mode: str = "black_box"                # black_box|grey_box|white_box
    metadata: dict = field(default_factory=dict)


@dataclass
class LoopConfig:
    """Stopping conditions for the adaptive evaluation loop."""

    max_rounds: int = 6
    probes_per_round: int = 12
    coverage_target: float = 0.85          # fraction of dimensions probed
    confidence_target: float = 0.8         # mean confidence to stop
    min_rounds: int = 2
    seed: int = 1337                       # reproducibility


@dataclass
class ScanConfig:
    """Live web-target scanning — how `aegis run` actually contacts a web app.

    Fail-closed and opt-in. With ``enabled=False`` (default) nothing reaches the
    network and the web pipeline stays a declared-inventory review, so existing
    behaviour and tests are unchanged. When enabled, the WebRecon agent runs the
    built-in, scope-gated :class:`~aegis.targets.livehttp.LiveHttpProbe` against
    each authorized web target, and — if ``external_tools`` is on and the
    binaries are installed — also the scope-gated ToolExecutor (httpx/nuclei).

    * ``active``            include light-active checks (common/sensitive paths,
                            directory listing) on top of passive header review.
    * ``external_tools``    additionally drive httpx/nuclei via the ToolExecutor.
    * ``execute_tools``     False => tools run dry (argv validated, not executed).
    """

    enabled: bool = False
    active: bool = True                    # passive-only when False
    offline: bool = True                   # only contact local hosts
    max_pages: int = 40
    timeout_s: float = 5.0
    crawl_paths: list[str] = field(default_factory=list)   # extra paths to probe
    # optional external-tool layer
    external_tools: bool = False
    tools: list[str] = field(default_factory=lambda: ["httpx", "nuclei"])
    execute_tools: bool = True             # False => dry-run the EXTERNAL tools only
    # Global dry-run: plan everything and send ZERO traffic — the built-in
    # crawler and active-exploit probes don't send, and external tools validate
    # their argv without executing. Scope decisions and the full tool/probe plan
    # are still produced and audited. This is the safe "dry-run first" switch for
    # a live engagement (execute_tools alone leaves the built-in probes sending).
    dry_run: bool = False
    # Default-off (fail-closed): the ACTIVE+ approval callback denies unless the
    # engagement explicitly opts in. Set this true to pre-authorize ACTIVE tools
    # (e.g. nuclei) to run unattended — this stands in for an interactive human
    # approval and should only be set once the engagement is authorized for them.
    auto_approve_active: bool = False
    credential_testing: bool = False
    exploitation: bool = False
    max_risk: str = "active"
    # Built-in active web-exploit CONFIRMATION probes (reflected-XSS, path
    # traversal/LFI, open redirect, optional SSRF). Fail-closed and opt-in: with
    # active_exploit=False (default) the WebExploitAgent is gated out entirely.
    # Payloads are benign unique canaries that confirm a bug exists — no data
    # exfiltration, state change, or code execution. Requires scan.enabled too.
    active_exploit: bool = False
    # Optional out-of-band collaborator host (one you control) for SSRF
    # confirmation, e.g. "oob.mytester.example". None => SSRF checks are skipped.
    oob_host: str | None = None
    # Hard cap on the number of requests the built-in active-exploit probes send
    # per target. Coverage is bounded by this; the agent logs a warning when it is
    # hit so you can raise it for a thorough engagement.
    exploit_max_checks: int = 400
    # recursive discovery (katana / gobuster / ffuf)
    recursive: bool = True                 # re-probe tool-discovered endpoints
    crawl_depth: int = 3                   # katana max crawl depth
    katana_crawl_seconds: int = 90         # katana total crawl-duration ceiling
    rate_limit: int | None = None          # katana requests/sec (politeness)
    scan_threads: int = 10                 # concurrency cap for brute-forcers
                                           # (politeness; avoids crashing single-
                                           # threaded targets)
    wordlist: str | None = None            # gobuster/ffuf wordlist; auto-detect if None
    max_discovered: int = 500              # cap on discovered endpoints kept
    # per-tool wall-clock ceiling (seconds); keeps a live run bounded
    tool_timeout_s: int = 300
    # network scan (nmap) — bare-host service/version detection
    nmap_ports: str = "top-1000"           # "top-1000" | comma/range port spec
    # exploitation confirmation (sqlmap / ghauri) — only used when exploitation=true
    #   Each entry targets a specific injectable endpoint, e.g.:
    #     - {url: "http://127.0.0.1:3000/rest/products/search?q=x", data: null}
    #     - {url: "http://127.0.0.1:3000/rest/user/login",
    #        data: '{"email":"a@a.a*","password":"x"}'}
    #   Empty => sqlmap self-discovers via --forms + shallow --crawl on the base URL.
    injection_targets: list[dict] = field(default_factory=list)
    sqli_level: int = 1                    # sqlmap 1-5 / ghauri 1-3
    sqli_risk: int = 1                     # sqlmap 1-3
    sqli_dbms: str | None = None           # optional back-end DBMS hint (speeds detection)
    # AI red-team toolchain (garak / promptfoo) against authorized model endpoints.
    garak_model_type: str = "openai"       # garak generator type for the endpoint
    garak_probes: str | None = None        # optional garak probe set (default: all)
    promptfoo_config: str | None = None     # promptfoo config path (required to run it)
    # Env var NAMES forwarded to the AI red-team tool subprocesses (garak /
    # promptfoo) only — they need the model's base URL/key to authenticate (e.g.
    # OPENAI_API_BASE, OPENAI_API_KEY). Every other tool, and every other env var,
    # still runs with the curated secret-free environment.
    tool_env: list[str] = field(default_factory=list)

    def wordlist_candidates(self) -> tuple[str, ...]:
        return (
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
            "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            os.path.expanduser("~/.local/share/wordlists/common.txt"),
        )

    def resolve_wordlist(self) -> str | None:
        """Return an explicit wordlist, else auto-detect a common SecLists path."""
        if self.wordlist and os.path.isfile(self.wordlist):
            return self.wordlist
        for cand in self.wordlist_candidates():
            if os.path.isfile(cand):
                return cand
        return None


@dataclass
class RedTeamConfig:
    """Adversarial model red-team suite (authorized LLM/agent testing).

    Fail-closed and opt-in: with ``enabled=False`` (default) the
    ``AdversarialRedTeamAgent`` is gated out and behaviour is unchanged. When
    enabled it sends benign-canary prompt-injection, system-prompt-leak, and
    RAG-injection probes at each authorized model target and reports
    susceptibility (OWASP LLM01 / LLM07). Every probe still passes the provider's
    authorization scope before leaving the process.
    """

    enabled: bool = False
    trials: int = 5                        # repeats per attack (for a rate + CI)
    prompt_injection: bool = True          # instruction-in-data override (LLM01)
    system_prompt_leak: bool = True        # coax out a planted secret (LLM07)
    rag_injection: bool = True             # grounding override via query (RAG only)


@dataclass
class Config:
    engagement: str = "unnamed-engagement"
    workdir: Path = field(default_factory=lambda: Path("./aegis_runs"))
    db_path: Path | None = None
    scope: AuthorizationScope = field(default_factory=AuthorizationScope)
    targets: list[TargetConfig] = field(default_factory=list)
    loop: LoopConfig = field(default_factory=LoopConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    redteam: RedTeamConfig = field(default_factory=RedTeamConfig)
    log_level: str = "INFO"
    raw: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.workdir = Path(self.workdir)
        if self.db_path is None:
            self.db_path = self.workdir / "aegis.db"
        self.db_path = Path(self.db_path)

    # -- loaders ------------------------------------------------------------ #
    @classmethod
    def from_dict(cls, data: dict) -> Config:
        loop = LoopConfig(**(data.get("loop") or {}))
        scan = ScanConfig(**(data.get("scan") or {}))
        redteam = RedTeamConfig(**(data.get("redteam") or {}))
        scope = AuthorizationScope.from_dict(data.get("authorization") or {})
        targets = [TargetConfig(**t) for t in (data.get("targets") or [])]
        return cls(
            engagement=data.get("engagement", "unnamed-engagement"),
            workdir=Path(data.get("workdir", "./aegis_runs")),
            db_path=Path(data["db_path"]) if data.get("db_path") else None,
            scope=scope,
            targets=targets,
            loop=loop,
            scan=scan,
            redteam=redteam,
            log_level=data.get("log_level", "INFO"),
            raw=data,
        )

    @classmethod
    def load(cls, path: str | os.PathLike) -> Config:
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        if p.suffix.lower() in (".yaml", ".yml"):
            if not _HAVE_YAML:
                raise RuntimeError(
                    "YAML config requires 'pyyaml' (pip install aegis-ai-security[extras]) "
                    "or provide JSON.")
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
        return cls.from_dict(data or {})

    def target(self, target_id: str) -> TargetConfig | None:
        return next((t for t in self.targets if t.id == target_id), None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "engagement": self.engagement,
            "workdir": str(self.workdir),
            "db_path": str(self.db_path),
            "authorization": self.scope.summary(),
            "targets": [t.__dict__ for t in self.targets],
            "loop": self.loop.__dict__,
            "scan": self.scan.__dict__,
            "redteam": self.redteam.__dict__,
            "log_level": self.log_level,
        }


def default_config(engagement: str = "demo") -> Config:
    """A safe, runnable default that only authorizes the offline mock target."""
    from .authorization import localhost_scope

    cfg = Config(engagement=engagement, scope=localhost_scope())
    cfg.targets = [
        TargetConfig(id="mock-llm", kind="local_llm", provider="mock",
                     model="mock-secure-1", mode="grey_box"),
    ]
    return cfg
