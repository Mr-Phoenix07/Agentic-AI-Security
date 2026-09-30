"""Built-in live HTTP prober — the scope-gated way AEGIS actually contacts a
web target using only the standard library (no external tools required).

This is deliberately conservative and safe by construction:

* **Scope-gated.** Every request is checked against the engagement
  :class:`~aegis.core.authorization.AuthorizationScope` first; an out-of-scope
  URL is never fetched.
* **Offline-aware.** In offline mode only loopback/local hosts are contacted.
* **No off-scope egress.** Redirects are *not* followed (a 3xx is recorded with
  its ``Location``), so a redirect can never bounce the scan to another host.
* **Bounded.** Per-request timeout, capped body read, capped page count.
* **Passive + light-active, never weaponized.** It reads status/headers/body,
  fingerprints tech, checks security headers, and probes a small list of common
  administrative/sensitive paths. It sends no exploit payloads.

The :class:`WebReconAgent` drives this over each authorized web target and feeds
the results into the existing recon → API-security → findings pipeline.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from ..core.authorization import AuthorizationScope

# Common paths worth a look on almost any web app. Passive in spirit (plain GETs)
# but only sent when active scanning is enabled.
COMMON_PATHS: tuple[str, ...] = (
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/.git/config", "/.env", "/config.json", "/backup", "/backup.zip",
    "/admin", "/administrator", "/login", "/api", "/api-docs",
    "/swagger.json", "/openapi.json", "/graphql",
    "/metrics", "/actuator", "/actuator/health", "/server-status",
    "/ftp", "/status", "/debug", "/.DS_Store",
)

SECURITY_HEADERS: tuple[str, ...] = (
    "content-security-policy", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy",
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_HREF_RE = re.compile(r"""(?:href|src)\s*=\s*["']([^"'#?\s]+)""", re.I)
_MAX_BODY = 262_144  # 256 KiB cap on captured body


def _host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def _is_local(host: str) -> bool:
    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow redirects so the scan can never egress off-scope."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


@dataclass
class PageResult:
    url: str
    status: int | None = None
    reason: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body_snippet: str = ""
    body_len: int = 0
    title: str = ""
    location: str = ""          # for 3xx responses (not followed)
    error: str = ""
    allowed: bool = True        # False => refused by scope/offline policy

    def to_dict(self) -> dict:
        return {
            "url": self.url, "status": self.status, "reason": self.reason,
            "server": self.headers.get("server", ""),
            "content_type": self.headers.get("content-type", ""),
            "title": self.title, "location": self.location,
            "body_len": self.body_len, "error": self.error,
            "allowed": self.allowed,
        }


@dataclass
class ScanResult:
    base_url: str
    pages: list[PageResult] = field(default_factory=list)
    reachable: bool = False
    server: str = ""
    missing_security_headers: list[str] = field(default_factory=list)
    discovered_paths: list[str] = field(default_factory=list)
    directory_listings: list[str] = field(default_factory=list)
    exposed_sensitive: list[str] = field(default_factory=list)   # (path) status 200
    refused: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "base_url": self.base_url, "reachable": self.reachable,
            "server": self.server,
            "missing_security_headers": self.missing_security_headers,
            "discovered_paths": self.discovered_paths,
            "directory_listings": self.directory_listings,
            "exposed_sensitive": self.exposed_sensitive,
            "refused": self.refused,
            "pages": [p.to_dict() for p in self.pages],
        }


# Sensitive resources whose reachability (HTTP 200) is itself a finding. Matched
# by basename/suffix so a deeply-nested hit (e.g. /deep/app/.env, found by a
# recursive crawler) is caught too, not just top-level paths.
_SENSITIVE_NAMES = {
    ".env", ".git", "config.json", "backup", "backup.zip", ".ds_store",
    "metrics", "actuator", "server-status", "debug", "id_rsa", ".htpasswd",
    ".htaccess", "web.config", "credentials", "secrets.json", ".npmrc",
}
_SENSITIVE_SUFFIXES = (
    ".env", ".sql", ".bak", ".old", ".swp", ".zip", ".tar.gz", ".tgz",
    ".pem", ".key", ".p12", ".pfx", "/.git/config",
)


def _is_sensitive(path: str) -> bool:
    p = path.lower().rstrip("/")
    base = p.rsplit("/", 1)[-1]
    if base in _SENSITIVE_NAMES:
        return True
    if "/.git/" in p or p.endswith("/.git"):
        return True
    return any(p.endswith(suf) for suf in _SENSITIVE_SUFFIXES)


class LiveHttpProbe:
    """Scope-gated, stdlib-only HTTP prober."""

    def __init__(
        self,
        scope: AuthorizationScope,
        *,
        offline: bool = True,
        timeout_s: float = 5.0,
        max_pages: int = 40,
        user_agent: str = "AEGIS/0.1 (authorized assessment)",
    ) -> None:
        self.scope = scope
        self.offline = offline
        self.timeout_s = timeout_s
        self.max_pages = max_pages
        self.user_agent = user_agent
        self._opener = urllib.request.build_opener(_NoRedirect)
        self._fetched = 0

    # -- single request ----------------------------------------------------- #
    def fetch(self, url: str, method: str = "GET") -> PageResult:
        # 1) authorization scope — never fetch an out-of-scope URL
        if not self.scope.check_url(url).allowed:
            return PageResult(url=url, allowed=False, error="out of scope")
        # 2) offline policy — only local hosts when offline
        if self.offline and not _is_local(_host_of(url)):
            return PageResult(url=url, allowed=False,
                              error="offline mode: non-local host refused")
        if self._fetched >= self.max_pages:
            return PageResult(url=url, allowed=False, error="page budget exhausted")
        self._fetched += 1

        req = urllib.request.Request(url, method=method,
                                     headers={"User-Agent": self.user_agent})
        try:
            with self._opener.open(req, timeout=self.timeout_s) as resp:
                return self._read(url, resp.status, resp.reason, resp.headers, resp)
        except urllib.error.HTTPError as e:  # 4xx/5xx/3xx — still a real response
            return self._read(url, e.code, e.reason or "", e.headers, e)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            return PageResult(url=url, error=f"{type(e).__name__}: {e}")

    def _read(self, url, status, reason, headers, body_stream) -> PageResult:
        hdrs = {k.lower(): v for k, v in dict(headers or {}).items()}
        raw = b""
        try:
            raw = body_stream.read(_MAX_BODY)
        except Exception:
            pass
        text = raw.decode("utf-8", "replace")
        m = _TITLE_RE.search(text)
        return PageResult(
            url=url, status=status, reason=str(reason or ""), headers=hdrs,
            body_snippet=text[:2000], body_len=len(raw),
            title=(m.group(1).strip()[:200] if m else ""),
            location=hdrs.get("location", ""),
        )

    # -- full scan ---------------------------------------------------------- #
    def _soft404_signature(self, base_url: str) -> dict | None:
        """Fetch an unlikely path to learn what a 'not found' looks like.

        Single-page apps and catch-all routers answer 200 for *every* path, so a
        bare 200 is not proof a resource exists. We fingerprint the response to
        a bogus path and later treat any probe that matches it as "not real".
        """
        import random
        bogus = f"/aegis-404-probe-{random.randint(10**6, 10**7)}"
        pr = self.fetch(base_url + bogus)
        if not pr.allowed or pr.status is None:
            return None
        return {"status": pr.status, "body_len": pr.body_len, "title": pr.title}

    @staticmethod
    def _differs_from_404(pr: PageResult, sig: dict | None) -> bool:
        """True when a response is materially different from the soft-404 baseline."""
        if sig is None:
            return True  # couldn't establish a baseline; don't suppress
        if pr.status != sig["status"]:
            return True
        # same status (typically a 200 catch-all): compare size + title
        tol = max(64, int(sig["body_len"] * 0.05))
        if abs(pr.body_len - sig["body_len"]) > tol:
            return True
        return pr.title != sig["title"]

    def scan(self, base_url: str, *, active: bool = True,
             extra_paths: tuple[str, ...] = ()) -> ScanResult:
        base_url = base_url.rstrip("/") or base_url
        result = ScanResult(base_url=base_url)

        root = self.fetch(base_url + "/")
        result.pages.append(root)
        if not root.allowed:
            result.refused.append(base_url + "/")
        result.reachable = root.status is not None
        result.server = root.headers.get("server", "")
        # learn the "not found" fingerprint so SPA/catch-all 200s aren't false positives
        soft404 = self._soft404_signature(base_url) if result.reachable else None

        # security-header review on the reachable root (passive)
        if result.reachable and root.status and root.status < 400:
            present = set(root.headers)
            result.missing_security_headers = [
                h for h in SECURITY_HEADERS if h not in present
            ]
            if urlparse(base_url).scheme == "https" and \
                    "strict-transport-security" not in present:
                result.missing_security_headers.append("strict-transport-security")

        # discover same-host links from the root page (depth 1)
        for href in _HREF_RE.findall(root.body_snippet or ""):
            absu = urljoin(base_url + "/", href)
            if _host_of(absu) == _host_of(base_url):
                path = urlparse(absu).path or "/"
                if path not in result.discovered_paths:
                    result.discovered_paths.append(path)

        if not active:
            return result

        # active: probe common + discovered + operator-supplied paths
        seen: set[str] = {"/"}
        for path in (*COMMON_PATHS, *extra_paths, *result.discovered_paths):
            if path in seen or self._fetched >= self.max_pages:
                continue
            seen.add(path)
            pr = self.fetch(base_url + path)
            if not pr.allowed:
                result.refused.append(base_url + path)
                continue
            result.pages.append(pr)
            # A resource "exists" only if it is 200 AND distinguishable from the
            # site's soft-404 response (defeats SPA/catch-all false positives).
            real = pr.status == 200 and self._differs_from_404(pr, soft404)
            if real:
                body = pr.body_snippet.lower()
                if "index of /" in body or "<title>index of" in body:
                    result.directory_listings.append(path)
                if _is_sensitive(path):
                    result.exposed_sensitive.append(path)
        return result
