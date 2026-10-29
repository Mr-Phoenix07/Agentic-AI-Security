"""Built-in tool catalog.

Each entry is a :class:`~aegis.tools.spec.ToolSpec`. Two kinds exist:

* **Executable adapters** — ubiquitous, non-destructive *discovery / enumeration
  / scanning / static-analysis* tools. These ship a ``command_builder`` (safe,
  structured argv construction) and a ``parser`` (raw output → observations).
  Their invocation is still fully gated by the executor (scope, offline, risk,
  approval, audit).

* **Documentation-only contracts** — exploitation, credential, and DoS class
  tools. These carry metadata for *planning* (so the orchestrator can say "an
  IDOR here could be validated with X") but ship **no** ``command_builder``.
  AEGIS will refuse to auto-run them; a human must implement and authorize the
  adapter for a specific engagement. No offensive payloads live here.

Argv builders receive a validated :class:`ToolInvocation` and return a token
list. There is no shell; params are inert tokens.
"""

from __future__ import annotations

import json

from ..core.types import TargetKind
from .execution import ToolResult
from .spec import (
    ParsedObservation,
    RiskLevel,
    ToolCategory,
    ToolInvocation,
    ToolSpec,
)

_WEB = (TargetKind.WEB_APP, TargetKind.REST_API, TargetKind.GRAPHQL_API,
        TargetKind.AI_GATEWAY, TargetKind.HYBRID)
_NET = (TargetKind.WEB_APP, TargetKind.REST_API, TargetKind.HYBRID)
_AI = (TargetKind.LOCAL_LLM, TargetKind.API_LLM, TargetKind.RAG,
       TargetKind.MULTI_AGENT, TargetKind.COPILOT, TargetKind.AI_GATEWAY)


# --------------------------------------------------------------------------- #
# argv builders (structured -> tokens). All validate their inputs.
# --------------------------------------------------------------------------- #
def _require_str(inv: ToolInvocation, key: str, *, default: str | None = None) -> str:
    val = inv.opt(key, default)
    if val is None:
        raise ValueError(f"missing required param '{key}'")
    if not isinstance(val, str) or not val.strip():
        raise ValueError(f"param '{key}' must be a non-empty string")
    return val


def _build_subfinder(inv: ToolInvocation) -> list[str]:
    # passive subdomain enumeration for an authorized apex domain
    return ["subfinder", "-silent", "-d", inv.target]


def _build_nmap(inv: ToolInvocation) -> list[str]:
    # service/version detection; no aggressive NSE scripts by default.
    ports = str(inv.opt("ports", "top-1000"))
    argv = ["nmap", "-sV", "-Pn", "--open"]
    if ports == "top-1000":
        argv += ["--top-ports", "1000"]
    else:
        # accept only digits, commas, and dashes for a port spec
        if not all(c.isdigit() or c in ",-" for c in ports):
            raise ValueError("invalid port specification")
        argv += ["-p", ports]
    argv += ["-oX", "-", inv.target]   # XML to stdout
    return argv


def _build_httpx(inv: ToolInvocation) -> list[str]:
    return ["httpx", "-silent", "-json", "-title", "-tech-detect",
            "-status-code", "-u", inv.target]


def _build_whatweb(inv: ToolInvocation) -> list[str]:
    return ["whatweb", "--log-json=-", "--no-errors", inv.target]


def _build_nuclei(inv: ToolInvocation) -> list[str]:
    # signature scan with default templates; jsonl to stdout.
    argv = ["nuclei", "-silent", "-jsonl", "-u", inv.target]
    severity = inv.opt("severity")
    if severity:
        allowed = {"info", "low", "medium", "high", "critical"}
        sev = [s.strip() for s in str(severity).split(",")]
        if not set(sev) <= allowed:
            raise ValueError("invalid severity filter")
        argv += ["-severity", ",".join(sev)]
    return argv


def _build_ffuf(inv: ToolInvocation) -> list[str]:
    # content discovery; operator must supply their own wordlist path.
    wordlist = _require_str(inv, "wordlist")
    url = inv.target
    if "FUZZ" not in url:
        # place the FUZZ keyword on the path safely
        url = url.rstrip("/") + "/FUZZ"
    # -s prints only the matched FUZZ words (one per line) to stdout, which we
    # capture and parse. -ac auto-calibrates a wildcard/soft-404 filter so
    # single-page apps (which answer 200 for every path) don't flood results.
    # (ffuf's file writer, -o, cannot target the captured stdout stream.)
    argv = ["ffuf", "-s", "-ac", "-w", wordlist, "-u", url]
    threads = inv.opt("threads")
    if threads is not None:
        argv += ["-t", str(int(threads))]
    return argv


def _build_gobuster(inv: ToolInvocation) -> list[str]:
    wordlist = _require_str(inv, "wordlist")
    argv = ["gobuster", "dir", "-q", "-u", inv.target, "-w", wordlist]
    threads = inv.opt("threads")
    if threads is not None:
        argv += ["-t", str(int(threads))]
    return argv


def _build_katana(inv: ToolInvocation) -> list[str]:
    # recursive crawler/spider; JSONL to stdout, constrained to the target's own
    # FQDN so the crawl cannot wander to another host.
    argv = ["katana", "-u", inv.target, "-jsonl", "-silent", "-nc",
            "-field-scope", "fqdn"]
    depth = inv.opt("depth")
    if depth is not None:
        d = int(depth)
        if not 0 <= d <= 10:
            raise ValueError("katana depth must be between 0 and 10")
        argv += ["-depth", str(d)]
    if inv.opt("js_crawl"):
        argv += ["-jc"]                       # parse endpoints out of JS files
    rate = inv.opt("rate_limit")
    if rate is not None:
        argv += ["-rate-limit", str(int(rate))]
    # Bound the crawl so it always terminates and returns what it found: a
    # per-request read timeout, and a total crawl-duration ceiling. Without
    # these katana can hang on keep-alive connections and never emit output.
    argv += ["-timeout", str(int(inv.opt("req_timeout", 10)))]
    ct = inv.opt("crawl_duration")
    if ct is not None:
        argv += ["-ct", str(int(ct))]
    return argv


def _build_feroxbuster(inv: ToolInvocation) -> list[str]:
    # fast recursive content discovery; JSONL to stdout.
    wordlist = _require_str(inv, "wordlist")
    argv = ["feroxbuster", "-u", inv.target, "-w", wordlist,
            "--silent", "--json", "--no-state"]
    threads = inv.opt("threads")
    if threads is not None:
        argv += ["--threads", str(int(threads))]
    depth = inv.opt("depth")
    if depth is not None:
        d = int(depth)
        if not 0 <= d <= 10:
            raise ValueError("feroxbuster depth must be between 0 and 10")
        argv += ["--depth", str(d)]
    rate = inv.opt("rate_limit")
    if rate is not None:
        argv += ["--rate-limit", str(int(rate))]
    return argv


def _build_nikto(inv: ToolInvocation) -> list[str]:
    # web server misconfiguration scanner. nikto's file writer appends the format
    # extension (so -output /dev/stdout -> /dev/stdout.json, which fails), so we
    # let it print its default '+ '-prefixed text report to stdout and parse that.
    argv = ["nikto", "-host", inv.target, "-nointeractive", "-ask", "no"]
    maxtime = inv.opt("maxtime")
    if maxtime is not None:
        argv += ["-maxtime", f"{int(maxtime)}s"]   # cap scan; report what's found
    return argv


def _build_arjun(inv: ToolInvocation) -> list[str]:
    # HTTP parameter discovery; JSON to stdout.
    argv = ["arjun", "-u", inv.target, "-oJ", "/dev/stdout", "-q"]
    method = str(inv.opt("method", "GET")).upper()
    if method in ("GET", "POST", "JSON", "XML"):
        argv += ["-m", method]
    return argv


def _zap_argv(binary: str, inv: ToolInvocation) -> list[str]:
    # Shared ZAP argv. Results print to stdout as WARN-*/FAIL-* lines; -I = do
    # not return a failure exit on warnings. The headless wrapper on PATH drives
    # a user-space ZAP daemon via its API and emits those lines.
    argv = [binary, "-t", inv.target, "-I"]
    if inv.opt("ajax"):
        argv += ["-j"]                        # ajax spider for SPAs
    mins = inv.opt("spider_minutes")
    if mins is not None:
        argv += ["-m", str(int(mins))]
    budget = inv.opt("budget_minutes")        # overall wall-clock budget (minutes)
    if budget is not None:
        argv += ["-T", str(int(budget))]
    return argv


def _build_zap(inv: ToolInvocation) -> list[str]:
    # ZAP baseline: spider (+optional AJAX spider) + passive rules only.
    return _zap_argv("zap-baseline.py", inv)


def _build_zap_full(inv: ToolInvocation) -> list[str]:
    # ZAP full scan: baseline PLUS the active scanner (injection/XSS/etc.).
    return _zap_argv("zap-full-scan.py", inv)


# --- gated exploitation adapters (DANGEROUS; require exploitation=true + approval) --- #
# Deliberately DETECTION/CONFIRMATION defaults only: no data-exfiltration
# (--dump*, --passwords) and no OS-takeover (--os-shell/--os-pwn) flags. These
# confirm whether an injection point exists on an AUTHORIZED target; they do not
# weaponize it.
def _build_sqlmap(inv: ToolInvocation) -> list[str]:
    level = int(inv.opt("level", 1))
    risk = int(inv.opt("risk", 1))
    if not 1 <= level <= 5:
        raise ValueError("sqlmap level must be 1-5")
    if not 1 <= risk <= 3:
        raise ValueError("sqlmap risk must be 1-3")
    # --flush-session forces a clean re-test each run: sqlmap's per-host session
    # persists across engagements, and a stale/locked session makes a later run
    # exit early without testing. Deterministic detection matters more here.
    argv = ["sqlmap", "-u", inv.target, "--batch", "--disable-coloring",
            "--flush-session", "--level", str(level), "--risk", str(risk)]
    _append_dbms(argv, inv.opt("dbms"))
    data = inv.opt("data")
    if data:
        argv += ["--data", str(data)]     # test the POST body parameters
    else:
        # A URL that already carries query params (…?q=x) is tested directly by
        # sqlmap — no extra flag needed. --forms is only for self-discovery on a
        # bare base URL (it parses & submits HTML forms); adding it to a param'd
        # URL makes sqlmap look for forms, find none, and abort. So --forms and
        # --crawl are opt-in, used only by the base-URL self-discovery path.
        if inv.opt("forms"):
            argv += ["--forms"]
        crawl = int(inv.opt("crawl", 0))
        if crawl:
            if not 0 <= crawl <= 5:
                raise ValueError("sqlmap crawl depth must be 0-5")
            argv += ["--crawl", str(crawl)]
    return argv


_ALLOWED_DBMS = {"sqlite", "mysql", "postgresql", "postgres", "mssql",
                 "microsoft sql server", "oracle", "mariadb", "db2"}


def _append_dbms(argv: list[str], dbms) -> None:
    """Append an optional, validated --dbms hint (narrows/speeds detection)."""
    if not dbms:
        return
    if str(dbms).lower() not in _ALLOWED_DBMS:
        raise ValueError("unsupported dbms hint")
    argv += ["--dbms", str(dbms).lower()]


def _build_ghauri(inv: ToolInvocation) -> list[str]:
    level = int(inv.opt("level", 1))
    if not 1 <= level <= 3:
        raise ValueError("ghauri level must be 1-3")
    argv = ["ghauri", "-u", inv.target, "--batch", "--level", str(level)]
    _append_dbms(argv, inv.opt("dbms"))
    data = inv.opt("data")
    if data:
        argv += ["--data", str(data)]
    return argv


def _build_semgrep(inv: ToolInvocation) -> list[str]:
    # static analysis over a local, authorized source path (no network).
    path = _require_str(inv, "path")
    config = str(inv.opt("config", "auto"))
    return ["semgrep", "--quiet", "--json", "--config", config, path]


def _build_gitleaks(inv: ToolInvocation) -> list[str]:
    path = _require_str(inv, "path")
    return ["gitleaks", "detect", "--no-banner", "--report-format", "json",
            "--report-path", "-", "--source", path]


def _build_trivy(inv: ToolInvocation) -> list[str]:
    # container/image or filesystem posture scan.
    mode = str(inv.opt("mode", "image"))
    if mode not in {"image", "fs", "config"}:
        raise ValueError("trivy mode must be image|fs|config")
    return ["trivy", mode, "--quiet", "--format", "json", inv.target]


# --- AI/LLM red-team + model-supply-chain adapters ------------------------- #
_SAFE_SPEC = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._,- ")


def _validate_spec(value: str, what: str) -> str:
    if not set(value) <= _SAFE_SPEC:
        raise ValueError(f"invalid {what} (allowed: alnum . _ , - space)")
    return value


def _build_garak(inv: ToolInvocation) -> list[str]:
    # garak LLM vulnerability scanner. The scope-checked target is the endpoint;
    # the model name/type identify what garak talks to. JSONL report to stdout.
    model_type = _validate_spec(str(inv.opt("model_type", "rest")), "model_type")
    model_name = _validate_spec(str(inv.opt("model_name", "")), "model_name")
    argv = ["garak", "--model_type", model_type]
    if model_name:
        argv += ["--model_name", model_name]
    probes = inv.opt("probes")
    if probes:
        argv += ["--probes", _validate_spec(str(probes), "probes").replace(" ", ",")]
    gens = inv.opt("generations")
    if gens is not None:
        argv += ["--generations", str(int(gens))]
    argv += ["--report_prefix", "aegis_garak"]
    return argv


def _build_promptfoo(inv: ToolInvocation) -> list[str]:
    # promptfoo LLM red-team/eval (node CLI). Results JSON to stdout.
    action = str(inv.opt("action", "redteam"))
    argv = (["promptfoo", "redteam", "run"] if action == "redteam"
            else ["promptfoo", "eval"])
    config = inv.opt("config")
    if config:
        argv += ["-c", _require_str(inv, "config")]
    argv += ["--no-progress-bar", "-o", "/dev/stdout"]
    return argv


def _build_modelscan(inv: ToolInvocation) -> list[str]:
    # scan a model artifact for unsafe code / deserialization payloads. Local,
    # no network. JSON report to stdout.
    path = _require_str(inv, "path")
    return ["modelscan", "-p", path, "-r", "json", "-o", "/dev/stdout"]


# --------------------------------------------------------------------------- #
# parsers (raw output -> observations). Defensive: never raise on junk.
# --------------------------------------------------------------------------- #
def _parse_jsonl(result: ToolResult, kind: str) -> list[ParsedObservation]:
    out: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        out.append(ParsedObservation(kind=kind, value=_summ(obj), detail=obj,
                                     raw_ref=f"line:{i}"))
    return out


def _summ(obj: dict) -> str:
    for k in ("matched-at", "url", "input", "host", "matched"):
        v = obj.get(k) if isinstance(obj, dict) else None
        if isinstance(v, str):
            return v
    return json.dumps(obj)[:120]


def _parse_nuclei(result: ToolResult) -> list[ParsedObservation]:
    obs: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        info = obj.get("info", {}) if isinstance(obj, dict) else {}
        obs.append(ParsedObservation(
            kind="template_match",
            value=str(obj.get("template-id") or info.get("name") or "match"),
            detail=obj,
            severity_hint=str(info.get("severity", "info")),
            raw_ref=f"line:{i}",
        ))
    return obs


def _parse_nmap(result: ToolResult) -> list[ParsedObservation]:
    # Parse the XML port table without a full XML dep: pull <port ...> lines.
    obs: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        s = line.strip()
        if s.startswith("<port ") and 'state="open"' in result.stdout[
            result.stdout.find(s):result.stdout.find(s) + 400
        ]:
            portid = _attr(s, "portid")
            proto = _attr(s, "protocol")
            if portid:
                obs.append(ParsedObservation(
                    kind="open_port", value=f"{portid}/{proto or 'tcp'}",
                    detail={"portid": portid, "protocol": proto},
                    raw_ref=f"line:{i}"))
    return obs


def _attr(s: str, name: str) -> str:
    marker = f'{name}="'
    j = s.find(marker)
    if j < 0:
        return ""
    j += len(marker)
    k = s.find('"', j)
    return s[j:k] if k > j else ""


def _parse_httpx(result: ToolResult) -> list[ParsedObservation]:
    return _parse_jsonl(result, kind="http_service")


def _parse_katana(result: ToolResult) -> list[ParsedObservation]:
    """Extract discovered URLs from katana's JSONL (or plain-URL) output."""
    obs: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            if line.startswith("http"):        # tolerate plain-URL output
                obs.append(ParsedObservation(kind="url", value=line, raw_ref=f"line:{i}"))
            continue
        req = obj.get("request", {}) if isinstance(obj, dict) else {}
        url = (req.get("endpoint") if isinstance(req, dict) else None) \
            or obj.get("endpoint") or obj.get("url")
        if not isinstance(url, str):
            continue
        method = req.get("method", "GET") if isinstance(req, dict) else "GET"
        obs.append(ParsedObservation(kind="url", value=url,
                                     detail={"method": method}, raw_ref=f"line:{i}"))
    return obs


def _parse_gobuster(result: ToolResult) -> list[ParsedObservation]:
    """Parse gobuster's text output. Older builds print ``/admin (Status: 200)``;
    3.x prints the bare word ``admin  (Status: 200) [Size: n]`` with no leading
    slash — handle both by keying on the ``(Status:`` marker."""
    obs: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        s = line.strip()
        if "Status:" not in s or not s:
            continue
        token = s.split()[0]
        path = token if token.startswith("/") else "/" + token
        j = s.find("Status:")
        status = s[j + 7:].strip().strip(")]").split(")")[0].split(",")[0].strip()
        obs.append(ParsedObservation(kind="path", value=path,
                                     detail={"status": status}, raw_ref=f"line:{i}"))
    return obs


def _parse_ffuf(result: ToolResult) -> list[ParsedObservation]:
    """Parse ffuf's silent (-s) stdout: one matched FUZZ word/path per line."""
    obs: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        s = line.strip()
        # skip blanks and any stray JSON/diagnostic lines
        if not s or s.startswith("{") or s.startswith("[") or " " in s:
            continue
        obs.append(ParsedObservation(kind="path", value=s, raw_ref=f"line:{i}"))
    return obs


def _parse_feroxbuster(result: ToolResult) -> list[ParsedObservation]:
    """Parse feroxbuster --json (JSONL) 'response' records into discovered URLs."""
    obs: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        if not isinstance(o, dict) or o.get("type") != "response":
            continue
        url = o.get("url")
        if isinstance(url, str) and url:
            obs.append(ParsedObservation(
                kind="url", value=url,
                detail={"status": o.get("status"), "length": o.get("content_length")},
                raw_ref=f"line:{i}"))
    return obs


def _parse_arjun(result: ToolResult) -> list[ParsedObservation]:
    """Parse Arjun's JSON ({url: {params: [...]}} or {url: [...]}) into params.

    Arjun interleaves its own progress/banner text with the JSON on stdout, so
    json.loads over the whole stream fails. Extract the JSON object (first '{'
    to last '}') before parsing.
    """
    obs: list[ParsedObservation] = []
    raw = result.stdout or ""
    start, end = raw.find("{"), raw.rfind("}")
    if start < 0 or end <= start:
        return obs
    try:
        data = json.loads(raw[start:end + 1])
    except Exception:
        return obs
    if not isinstance(data, dict):
        return obs
    for url, info in data.items():
        params = info.get("params", info) if isinstance(info, dict) else info
        if isinstance(params, list) and params:
            obs.append(ParsedObservation(
                kind="parameters", value=str(url),
                detail={"params": params}))
    return obs


# nikto '+ ' lines that are run banner/metadata, not findings.
_NIKTO_BANNER = (
    "target ip", "target hostname", "target port", "start time", "end time",
    "platform", "root page", "no cgi", "scan terminated", "requests:",
    "ssl info", "ciphers:", "1 host(s) tested", "host(s) tested",
)


def _parse_nikto(result: ToolResult) -> list[ParsedObservation]:
    """Parse nikto's default text report: informative lines are prefixed ``+ ``.
    Banner/metadata lines are filtered out; the rest are server findings."""
    obs: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        s = line.strip()
        if not s.startswith("+ "):
            continue
        msg = s[2:].strip()
        low = msg.lower()
        if not msg or any(low.startswith(b) for b in _NIKTO_BANNER):
            continue
        if low.startswith("server:") and "leak" not in low and "outdated" not in low:
            continue  # plain server banner, not a finding
        obs.append(ParsedObservation(kind="nikto_finding", value=msg[:200],
                                     severity_hint="low", raw_ref=f"line:{i}"))
    return obs


def _parse_zap(result: ToolResult) -> list[ParsedObservation]:
    """Parse zap-baseline.py stdout lines: 'WARN-NEW: <name> [id] x N' / 'FAIL-...'."""
    obs: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        s = line.strip()
        tag = next((t for t in ("FAIL-NEW:", "FAIL:", "WARN-NEW:", "WARN:") if s.startswith(t)), None)
        if not tag:
            continue
        name = s[len(tag):].strip()
        sev = "medium" if tag.startswith("FAIL") else "low"
        obs.append(ParsedObservation(kind="zap_alert", value=name,
                                     severity_hint=sev, raw_ref=f"line:{i}"))
    return obs


def _parse_sqli(result: ToolResult) -> list[ParsedObservation]:
    """Detect a CONFIRMED injection in sqlmap/ghauri stdout (no data is dumped).

    Only strong confirmation markers count. Tentative lines ("might be
    injectable", "appears to be") and — critically — the negative verdict
    ("... do not appear to be injectable") must NOT trigger a finding. The bare
    word "injectable" is deliberately excluded because it is a substring of
    sqlmap's own negative output, which previously produced false CRITICALs.
    """
    out = (result.stdout or "").lower()
    positive = ("is vulnerable", "identified the following injection",
                "the back-end dbms is")
    if any(m in out for m in positive) and "is not vulnerable" not in out:
        return [ParsedObservation(
            kind="sql_injection", value="SQL injection point confirmed",
            severity_hint="high",
            detail={"evidence": "tool reported a confirmed injectable parameter"})]
    return []


def _parse_garak(result: ToolResult) -> list[ParsedObservation]:
    """Parse garak output. Prefers JSONL eval records (one per probe/detector
    with a pass-rate); falls back to the human 'probe: ... PASS/FAIL' lines."""
    obs: list[ParsedObservation] = []
    for i, line in enumerate(result.stdout.splitlines()):
        s = line.strip()
        if not s:
            continue
        try:
            o = json.loads(s)
        except Exception:
            low = s.lower()
            if "fail" in low and ("probe" in low or "." in s):
                obs.append(ParsedObservation(kind="llm_vuln", value=s[:160],
                                             severity_hint="high", raw_ref=f"line:{i}"))
            continue
        if not isinstance(o, dict):
            continue
        # garak report rows carry a probe/detector and a passed/total count.
        probe = o.get("probe") or o.get("probe_classname") or o.get("detector")
        total = o.get("total") or o.get("attempts")
        passed = o.get("passed")
        if probe and total:
            failed = (int(total) - int(passed)) if passed is not None else None
            if failed:
                obs.append(ParsedObservation(
                    kind="llm_vuln", value=str(probe),
                    detail={"failed": failed, "total": total},
                    severity_hint="high", raw_ref=f"line:{i}"))
    return obs


def _parse_promptfoo(result: ToolResult) -> list[ParsedObservation]:
    """Parse promptfoo JSON (best-effort): surface failed/flagged test cases."""
    raw = result.stdout or ""
    start, end = raw.find("{"), raw.rfind("}")
    if start < 0 or end <= start:
        return []
    try:
        data = json.loads(raw[start:end + 1])
    except Exception:
        return []
    results = (data.get("results") if isinstance(data, dict) else None) or {}
    rows = results.get("results") if isinstance(results, dict) else None
    obs: list[ParsedObservation] = []
    for j, r in enumerate(rows or []):
        if isinstance(r, dict) and r.get("success") is False:
            obs.append(ParsedObservation(
                kind="llm_vuln",
                value=str((r.get("vars") or {}).get("name") or r.get("description")
                          or "promptfoo failure")[:160],
                detail={"error": str(r.get("error", ""))[:200]},
                severity_hint="high", raw_ref=f"result:{j}"))
    return obs


_MODELSCAN_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
                  "LOW": "low"}


def _parse_modelscan(result: ToolResult) -> list[ParsedObservation]:
    """Parse modelscan JSON: each issue is an unsafe-operator/deserialization risk."""
    raw = result.stdout or ""
    start, end = raw.find("{"), raw.rfind("}")
    if start < 0 or end <= start:
        return []
    try:
        data = json.loads(raw[start:end + 1])
    except Exception:
        return []
    issues = (data.get("issues") if isinstance(data, dict) else None) or []
    obs: list[ParsedObservation] = []
    for j, it in enumerate(issues):
        if not isinstance(it, dict):
            continue
        sev = _MODELSCAN_SEV.get(str(it.get("severity", "")).upper(), "medium")
        desc = it.get("description") or it.get("operator") or "unsafe model operator"
        obs.append(ParsedObservation(
            kind="model_issue", value=str(desc)[:160],
            detail={k: it.get(k) for k in ("severity", "operator", "module",
                                           "source") if k in it},
            severity_hint=sev, raw_ref=f"issue:{j}"))
    return obs


# --------------------------------------------------------------------------- #
# The catalog
# --------------------------------------------------------------------------- #
def default_catalog() -> list[ToolSpec]:
    """Return the built-in tool specs (fresh instances)."""
    return [
        # -- recon / passive ------------------------------------------------ #
        ToolSpec(
            name="subfinder", binary="subfinder", category=ToolCategory.RECON,
            purpose="Passive subdomain enumeration for an authorized apex domain.",
            risk_level=RiskLevel.PASSIVE, supported_targets=_WEB,
            applies_when=("domain",), evidence_format="text",
            input_schema={"target": "apex domain (authorized)"},
            command_builder=_build_subfinder,
            references=("https://github.com/projectdiscovery/subfinder",),
        ),
        # -- network -------------------------------------------------------- #
        ToolSpec(
            name="nmap", binary="nmap", category=ToolCategory.NETWORK,
            purpose="Service/version detection on authorized hosts (no aggressive NSE).",
            risk_level=RiskLevel.ACTIVE, supported_targets=_NET,
            applies_when=("host", "ip", "network"), evidence_format="xml",
            input_schema={"target": "host/ip", "ports": "top-1000 | comma/range spec"},
            command_builder=_build_nmap, parser=_parse_nmap,
            references=("https://nmap.org/book/man.html",),
        ),
        # -- fingerprint ---------------------------------------------------- #
        ToolSpec(
            name="httpx", binary="httpx", category=ToolCategory.FINGERPRINT,
            purpose="HTTP probing: status, title, technology detection.",
            risk_level=RiskLevel.SAFE, supported_targets=_WEB,
            applies_when=("http", "https", "web"), evidence_format="jsonl",
            input_schema={"target": "URL or host"},
            command_builder=_build_httpx, parser=_parse_httpx,
            references=("https://github.com/projectdiscovery/httpx",),
        ),
        ToolSpec(
            name="whatweb", binary="whatweb", category=ToolCategory.FINGERPRINT,
            purpose="Web technology fingerprinting.",
            risk_level=RiskLevel.SAFE, supported_targets=_WEB,
            applies_when=("http", "https", "web"), evidence_format="json",
            input_schema={"target": "URL"},
            command_builder=_build_whatweb,
            references=("https://github.com/urbanadventurer/WhatWeb",),
        ),
        # -- web scan ------------------------------------------------------- #
        ToolSpec(
            name="nuclei", binary="nuclei", category=ToolCategory.WEB_SCAN,
            purpose="Template-based misconfiguration/exposure signature scanning.",
            risk_level=RiskLevel.ACTIVE, supported_targets=_WEB,
            applies_when=("http", "https", "web", "api"), evidence_format="jsonl",
            input_schema={"target": "URL", "severity": "optional severity filter"},
            command_builder=_build_nuclei, parser=_parse_nuclei,
            references=("https://github.com/projectdiscovery/nuclei",),
        ),
        # -- web enumeration ------------------------------------------------ #
        ToolSpec(
            name="katana", binary="katana", category=ToolCategory.WEB_ENUM,
            purpose="Recursive web crawler/spider for endpoint discovery (JS-aware), "
                    "scoped to the target's own FQDN.",
            risk_level=RiskLevel.ACTIVE, supported_targets=_WEB,
            applies_when=("http", "https", "web", "api"), evidence_format="jsonl",
            input_schema={"target": "base URL", "depth": "max crawl depth (0-10)",
                          "js_crawl": "parse endpoints from JS (bool)",
                          "rate_limit": "max requests/sec"},
            command_builder=_build_katana, parser=_parse_katana,
            references=("https://github.com/projectdiscovery/katana",),
        ),
        ToolSpec(
            name="ffuf", binary="ffuf", category=ToolCategory.WEB_ENUM,
            purpose="Content/endpoint discovery via wordlist fuzzing (e.g. SecLists).",
            risk_level=RiskLevel.ACTIVE, supported_targets=_WEB,
            applies_when=("http", "https", "web"), evidence_format="json",
            input_schema={"target": "base URL", "wordlist": "path to a wordlist (SecLists)"},
            command_builder=_build_ffuf, parser=_parse_ffuf,
            references=("https://github.com/ffuf/ffuf",),
        ),
        ToolSpec(
            name="gobuster", binary="gobuster", category=ToolCategory.WEB_ENUM,
            purpose="Directory/content discovery (wordlist, e.g. SecLists).",
            risk_level=RiskLevel.ACTIVE, supported_targets=_WEB,
            applies_when=("http", "https", "web"), evidence_format="text",
            input_schema={"target": "base URL", "wordlist": "path to a wordlist (SecLists)"},
            command_builder=_build_gobuster, parser=_parse_gobuster,
            references=("https://github.com/OJ/gobuster",),
        ),
        ToolSpec(
            name="feroxbuster", binary="feroxbuster", category=ToolCategory.WEB_ENUM,
            purpose="Fast recursive content discovery (wordlist, e.g. SecLists).",
            risk_level=RiskLevel.ACTIVE, supported_targets=_WEB,
            applies_when=("http", "https", "web"), evidence_format="jsonl",
            input_schema={"target": "base URL", "wordlist": "path to a wordlist",
                          "depth": "recursion depth (0-10)", "rate_limit": "req/sec"},
            command_builder=_build_feroxbuster, parser=_parse_feroxbuster,
            references=("https://github.com/epi052/feroxbuster",),
        ),
        ToolSpec(
            name="arjun", binary="arjun", category=ToolCategory.WEB_ENUM,
            purpose="HTTP query/body parameter discovery.",
            risk_level=RiskLevel.ACTIVE, supported_targets=_WEB,
            applies_when=("http", "https", "web", "api"), evidence_format="json",
            input_schema={"target": "URL", "method": "GET|POST|JSON|XML"},
            command_builder=_build_arjun, parser=_parse_arjun,
            references=("https://github.com/s0md3v/Arjun",),
        ),
        # -- web scan (server misconfig / DAST) ----------------------------- #
        ToolSpec(
            name="nikto", binary="nikto", category=ToolCategory.WEB_SCAN,
            purpose="Web server misconfiguration & dangerous-file scanning.",
            risk_level=RiskLevel.ACTIVE, supported_targets=_WEB,
            applies_when=("http", "https", "web"), evidence_format="json",
            input_schema={"target": "URL/host"},
            command_builder=_build_nikto, parser=_parse_nikto,
            references=("https://github.com/sullo/nikto",),
        ),
        ToolSpec(
            name="zap", binary="zap-baseline.py", category=ToolCategory.WEB_SCAN,
            purpose="OWASP ZAP baseline (spider + passive rules) DAST scan.",
            risk_level=RiskLevel.ACTIVE, supported_targets=_WEB,
            applies_when=("http", "https", "web", "api"), evidence_format="text",
            default_timeout_s=900,
            input_schema={"target": "URL", "ajax": "use ajax spider for SPAs (bool)",
                          "spider_minutes": "spider time budget"},
            command_builder=_build_zap, parser=_parse_zap,
            references=("https://www.zaproxy.org/docs/docker/baseline-scan/",),
        ),
        ToolSpec(
            name="zap-full", binary="zap-full-scan.py", category=ToolCategory.WEB_SCAN,
            purpose="OWASP ZAP full DAST scan: spider + AJAX spider + ACTIVE scan "
                    "(injection/XSS/etc.). Much deeper than baseline.",
            # INTRUSIVE: the active scanner sends attack payloads, so it needs the
            # engagement to allow INTRUSIVE+ risk (max_risk) and human approval.
            risk_level=RiskLevel.INTRUSIVE, supported_targets=_WEB,
            applies_when=("http", "https", "web", "api"), evidence_format="text",
            default_timeout_s=2400,
            input_schema={"target": "URL", "ajax": "use ajax spider for SPAs (bool)",
                          "spider_minutes": "spider time budget"},
            command_builder=_build_zap_full, parser=_parse_zap,
            notes="Active DAST. Honours the ZAP_SCAN_BUDGET env (overall wall-clock) "
                  "so it finishes within the per-tool timeout and shuts ZAP down.",
            references=("https://www.zaproxy.org/docs/docker/full-scan/",),
        ),
        # -- static analysis (local, no network) ---------------------------- #
        ToolSpec(
            name="semgrep", binary="semgrep", category=ToolCategory.STATIC_ANALYSIS,
            purpose="Static source analysis over an authorized local code path.",
            risk_level=RiskLevel.SAFE, supported_targets=(TargetKind.WEB_APP,),
            applies_when=("source", "code"), requires_network=False,
            evidence_format="json",
            input_schema={"path": "local source path", "config": "ruleset (default auto)"},
            command_builder=_build_semgrep,
            references=("https://semgrep.dev/docs/",),
        ),
        ToolSpec(
            name="gitleaks", binary="gitleaks", category=ToolCategory.STATIC_ANALYSIS,
            purpose="Detect secrets committed in an authorized local repository.",
            risk_level=RiskLevel.SAFE, supported_targets=(TargetKind.WEB_APP,),
            applies_when=("source", "code", "repo"), requires_network=False,
            evidence_format="json",
            input_schema={"path": "local repo path"},
            command_builder=_build_gitleaks,
            references=("https://github.com/gitleaks/gitleaks",),
        ),
        # -- container / infra ---------------------------------------------- #
        ToolSpec(
            name="trivy", binary="trivy", category=ToolCategory.CONTAINER,
            purpose="Image/filesystem/IaC vulnerability & misconfiguration posture.",
            risk_level=RiskLevel.SAFE, supported_targets=(TargetKind.WEB_APP,),
            applies_when=("container", "image", "iac"), requires_network=False,
            evidence_format="json",
            input_schema={"target": "image ref or path", "mode": "image|fs|config"},
            command_builder=_build_trivy,
            references=("https://aquasecurity.github.io/trivy/",),
        ),

        # -- AI / LLM red-team (active) ------------------------------------- #
        ToolSpec(
            name="garak", binary="garak", category=ToolCategory.AI_REDTEAM,
            purpose="LLM vulnerability scanner (jailbreak, prompt-injection, "
                    "toxicity, leakage probes) against an authorized model endpoint.",
            risk_level=RiskLevel.ACTIVE, supported_targets=_AI,
            applies_when=("llm", "ai", "model", "http", "https"),
            evidence_format="jsonl", default_timeout_s=1800,
            input_schema={"target": "authorized model endpoint (scope-checked)",
                          "model_type": "garak model type (default rest)",
                          "model_name": "model id", "probes": "probe set (optional)"},
            command_builder=_build_garak, parser=_parse_garak,
            references=("https://github.com/NVIDIA/garak",),
        ),
        ToolSpec(
            name="promptfoo", binary="promptfoo", category=ToolCategory.AI_REDTEAM,
            purpose="LLM red-team / eval harness (requires a promptfoo config "
                    "describing the authorized provider).",
            risk_level=RiskLevel.ACTIVE, supported_targets=_AI,
            applies_when=("llm", "ai", "model", "http", "https"),
            evidence_format="json", default_timeout_s=1800,
            input_schema={"target": "authorized model endpoint (scope-checked)",
                          "action": "redteam|eval", "config": "promptfoo config path"},
            command_builder=_build_promptfoo, parser=_parse_promptfoo,
            notes="Node CLI: install with 'npm install -g promptfoo'.",
            references=("https://www.promptfoo.dev/docs/red-team/",),
        ),
        # -- model supply-chain (static, local, no network) ----------------- #
        ToolSpec(
            name="modelscan", binary="modelscan",
            category=ToolCategory.STATIC_ANALYSIS,
            purpose="Scan a model artifact (pickle/h5/SavedModel/…) for unsafe "
                    "code / deserialization payloads before loading it.",
            risk_level=RiskLevel.SAFE, supported_targets=_AI,
            applies_when=("model", "artifact", "weights", "pickle"),
            requires_network=False, evidence_format="json",
            input_schema={"path": "local path to the model file/dir"},
            command_builder=_build_modelscan, parser=_parse_modelscan,
            references=("https://github.com/protectai/modelscan",),
        ),

        # ================================================================== #
        # Documentation-only contracts (no command_builder => never auto-run)
        # ================================================================== #
        ToolSpec(
            name="netron", binary="netron", category=ToolCategory.STATIC_ANALYSIS,
            purpose="Model architecture viewer (graph of layers/ops). A manual "
                    "GUI/web viewer, not an automated scanner.",
            risk_level=RiskLevel.SAFE, supported_targets=_AI,
            applies_when=("model", "artifact", "weights"), requires_network=False,
            command_builder=None,
            notes="Viewer only: open a model with 'netron <file>'. Pair with "
                  "modelscan for the automated supply-chain check.",
            references=("https://github.com/lutzroeder/netron",),
        ),
        # ---- gated exploitation adapters ---------------------------------- #
        # These now ship a command_builder (the "human-implemented scoped adapter"
        # the design calls for), but remain DANGEROUS: the executor refuses them
        # unless the engagement sets exploitation=true, the risk cap allows
        # DANGEROUS, and the approval callback returns True. Defaults confirm an
        # injection point only — no --dump/--os-shell data-theft or takeover.
        ToolSpec(
            name="sqlmap", binary="sqlmap", category=ToolCategory.EXPLOITATION,
            purpose="SQL injection detection/confirmation (batch, bounded level/risk).",
            risk_level=RiskLevel.DANGEROUS, supported_targets=_WEB,
            applies_when=("http", "https", "web", "sql", "injection-candidate"),
            evidence_format="text",
            input_schema={"target": "URL", "data": "POST body (optional)",
                          "level": "1-5 (default 1)", "risk": "1-3 (default 1)"},
            command_builder=_build_sqlmap, parser=_parse_sqli,
            notes="Gated: requires exploitation=true + max_risk>=dangerous + approval. "
                  "Detection defaults only; no data exfiltration/OS takeover flags.",
            references=("https://github.com/sqlmapproject/sqlmap",),
        ),
        ToolSpec(
            name="ghauri", binary="ghauri", category=ToolCategory.EXPLOITATION,
            purpose="SQL injection detection/confirmation (batch, bounded level).",
            risk_level=RiskLevel.DANGEROUS, supported_targets=_WEB,
            applies_when=("http", "https", "web", "sql", "injection-candidate"),
            evidence_format="text",
            input_schema={"target": "URL", "data": "POST body (optional)",
                          "level": "1-3 (default 1)"},
            command_builder=_build_ghauri, parser=_parse_sqli,
            notes="Gated: requires exploitation=true + max_risk>=dangerous + approval. "
                  "Detection defaults only.",
            references=("https://github.com/r0oth3x49/ghauri",),
        ),
        ToolSpec(
            name="metasploit", binary="msfconsole", category=ToolCategory.EXPLOITATION,
            purpose="Exploit validation framework. Documentation-only contract.",
            risk_level=RiskLevel.DANGEROUS, supported_targets=_NET,
            command_builder=None,
            notes="Gated. Exploit validation must be human-driven under written "
                  "authorization; no auto adapter is shipped.",
            references=("https://docs.metasploit.com/",),
        ),
        ToolSpec(
            name="hydra", binary="hydra", category=ToolCategory.CREDENTIAL,
            purpose="Authentication strength testing. Documentation-only contract.",
            risk_level=RiskLevel.DANGEROUS, supported_targets=_WEB,
            command_builder=None,
            notes="Gated. credential_testing=true plus a human-implemented, "
                  "scoped adapter and explicit approval are required.",
            references=("https://github.com/vanhauser-thc/thc-hydra",),
        ),
    ]
