#!/usr/bin/env python3
"""Headless OWASP ZAP scan wrapper (no Docker, user-space).

Installed on PATH under two names:
  * zap-baseline.py   -> spider (+optional AJAX spider) + passive scan
  * zap-full-scan.py  -> the above PLUS the active scanner

It launches a user-space ZAP in daemon mode, drives it through the ZAP API
(stdlib urllib only — no pip dependency), and prints one line per deduplicated
alert in the exact format AEGIS's `_parse_zap` consumes:

    FAIL-NEW: <name> [<pluginId>] x<count>     # High / Medium risk
    WARN-NEW: <name> [<pluginId>] x<count>     # Low / Informational

ZAP is always shut down on exit (even on timeout/interrupt), and the daemon is
started in its own process group so a backstop kill can reap the whole tree.
Exit code is always 0 so a non-zero code never suppresses the parsed output
(the `-I` / "ignore warnings" contract of the official scripts).

Args (subset of the official scripts, enough for the AEGIS adapter):
  -t URL        target (required)
  -j            also run the AJAX spider (best-effort; needs a browser)
  -m MINUTES    spider time budget (minutes)
  -I            ignore warnings for exit code (we always exit 0 anyway)
Env:
  ZAP_PATH            path to zap.sh (else auto-detect ~/.local/opt/zap/zap.sh)
  ZAP_SCAN_BUDGET     overall wall-clock budget in seconds (default 1800)
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request

PROC = None          # ZAP daemon Popen
PORT = None
BASE = None          # http://127.0.0.1:PORT


def log(msg: str) -> None:
    print(f"[zap-wrapper] {msg}", file=sys.stderr, flush=True)


def find_zap() -> str:
    cand = [os.environ.get("ZAP_PATH"),
            os.path.expanduser("~/.local/opt/zap/zap.sh"),
            "/usr/share/zaproxy/zap.sh", "/opt/zap/zap.sh"]
    for c in cand:
        if c and os.path.isfile(c):
            return c
    from shutil import which
    w = which("zap.sh")
    if w:
        return w
    log("ERROR: zap.sh not found (set ZAP_PATH)")
    sys.exit(0)        # exit 0 so the run is simply empty, not a hard failure


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def api(path: str, **params) -> dict:
    url = f"{BASE}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        return {"_error": str(e)}


def wait_up(deadline: float) -> bool:
    while time.time() < deadline:
        if "version" in api("/JSON/core/view/version/"):
            return True
        time.sleep(2)
    return False


def _clean_moz_profiles():
    # The AJAX-spider browsers leave ~100 MB Firefox profiles in /tmp; on a
    # disk-constrained host these pile up fast. Reap them after ZAP is down.
    import glob
    import shutil as _sh
    for d in glob.glob("/tmp/rust_mozprofile*"):
        try:
            _sh.rmtree(d, ignore_errors=True)
        except Exception:
            pass


def shutdown():
    global PROC
    try:
        if BASE:
            api("/JSON/core/action/shutdown/")
    except Exception:
        pass
    if PROC and PROC.poll() is None:
        try:
            os.killpg(os.getpgid(PROC.pid), signal.SIGTERM)
            time.sleep(3)
            if PROC.poll() is None:
                os.killpg(os.getpgid(PROC.pid), signal.SIGKILL)
        except Exception:
            pass
    _clean_moz_profiles()


def poll_until(view_path, key, done_pred, deadline, label, **params):
    """Poll a ZAP status view until done_pred(value) or the deadline.

    A transient API error (``{"_error": ...}`` -> key missing) must NOT be read
    as completion, or a long scan aborts early and under-reports. Keep polling
    through transient errors; only give up after many consecutive failures
    (ZAP genuinely gone) or at the deadline.
    """
    errors = 0
    while time.time() < deadline:
        r = api(view_path, **params)
        val = r.get(key)
        if val is None:                       # transient error / unexpected shape
            errors += 1
            if errors >= 20:                  # ~60s of solid failures -> ZAP gone
                log(f"{label}: repeated API errors, moving on")
                return
            time.sleep(3)
            continue
        errors = 0
        if done_pred(val):
            return
        time.sleep(3)
    log(f"{label}: budget reached, moving on")


def main() -> int:
    global PROC, PORT, BASE
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("-t", dest="target", required=True)
    ap.add_argument("-j", dest="ajax", action="store_true")
    ap.add_argument("-m", dest="minutes", type=int, default=0)
    ap.add_argument("-T", dest="budget_minutes", type=int, default=0)  # overall budget
    ap.add_argument("-I", dest="ignore", action="store_true")
    args, _ = ap.parse_known_args()

    mode = "full" if "full" in os.path.basename(sys.argv[0]) else "baseline"
    target = args.target
    # overall wall-clock budget: -T minutes wins, else ZAP_SCAN_BUDGET, else 1800s
    budget = (args.budget_minutes * 60 if args.budget_minutes > 0
              else int(os.environ.get("ZAP_SCAN_BUDGET", "1800")))
    start = time.time()
    hard_deadline = start + budget

    zap = find_zap()
    PORT = free_port()
    BASE = f"http://127.0.0.1:{PORT}"
    atexit.register(shutdown)

    log(f"mode={mode} target={target} port={PORT} budget={budget}s zap={zap}")
    PROC = subprocess.Popen(
        [zap, "-daemon", "-host", "127.0.0.1", "-port", str(PORT),
         "-config", "api.disablekey=true",
         "-config", "api.addrs.addr.name=.*",
         "-config", "api.addrs.addr.regex=true",
         "-config", "scanner.attackOnStart=false"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)

    if not wait_up(min(start + 180, hard_deadline)):
        log("ZAP did not start in time")
        return 0
    log("ZAP up")

    # Seed the sites tree. For a single-page app the traditional spider finds
    # almost nothing, so we explicitly seed known endpoints (via ZAP_SEED_URLS,
    # comma-separated) so the active scanner has real targets to attack. The AJAX
    # spider is intentionally NOT used: it launches one browser per core, each
    # leaving a ~100 MB /tmp Firefox profile — a swarm that fills a small disk.
    api("/JSON/core/action/accessUrl/", url=target, followRedirects="true")
    seeds = [s.strip() for s in os.environ.get("ZAP_SEED_URLS", "").split(",")
             if s.strip()]
    for s in seeds:
        api("/JSON/core/action/accessUrl/", url=s, followRedirects="true")
    if seeds:
        log(f"seeded {len(seeds)} endpoint(s) for active scan")
    if args.ajax:
        log("ajax spider disabled on this host (browser-swarm/disk safety)")

    # 1) traditional spider
    r = api("/JSON/spider/action/scan/", url=target, recurse="true",
            maxChildren="0")
    sid = r.get("scan")
    if sid is not None:
        poll_until("/JSON/spider/view/status/", "status",
                   lambda v: int(v) >= 100,
                   min(start + 300, hard_deadline), "spider", scanId=sid)
    log("spider done")

    # 3) passive scan queue drain
    poll_until("/JSON/pscan/view/recordsToScan/", "recordsToScan",
               lambda v: int(v) <= 0,
               min(time.time() + 180, hard_deadline), "passive")
    log("passive scan drained")

    # 4) active scan (full mode only)
    if mode == "full" and time.time() < hard_deadline - 60:
        # Throttle the active scanner: pace requests and cap concurrency so a
        # fragile single-process target (e.g. Juice Shop's Node server, ~4 GB
        # heap, no rate limiting) is not driven into an OOM crash.
        api("/JSON/ascan/action/setOptionThreadPerHost/", Integer="2")
        api("/JSON/ascan/action/setOptionDelayInMs/", Integer="100")
        api("/JSON/ascan/action/setOptionMaxRuleDurationInMins/", Integer="4")
        api("/JSON/ascan/action/setOptionMaxScanDurationInMins/", Integer="25")
        r = api("/JSON/ascan/action/scan/", url=target, recurse="true",
                inScopeOnly="false")
        aid = r.get("scan")
        if aid is not None:
            # leave ~45s to collect alerts + shut down cleanly
            poll_until("/JSON/ascan/view/status/", "status",
                       lambda v: int(v) >= 100,
                       hard_deadline - 45, "active", scanId=aid)
            log("active scan finished/stopped")
        else:
            log(f"active scan not started ({r})")

    # 5) collect + dedupe alerts
    alerts = api("/JSON/core/view/alerts/", baseurl=target, start="0",
                 count="0").get("alerts", [])
    if not isinstance(alerts, list):
        alerts = []
    agg = {}
    for a in alerts:
        name = a.get("alert") or a.get("name") or "ZAP alert"
        risk = (a.get("risk") or "Low").split()[0]   # "High (High)" -> "High"
        pid = a.get("pluginId") or a.get("alertRef") or ""
        k = (name, pid, risk)
        agg[k] = agg.get(k, 0) + 1

    log(f"{len(alerts)} raw alerts -> {len(agg)} unique")
    for (name, pid, risk), count in sorted(agg.items(), key=lambda x: -x[1]):
        tag = "FAIL-NEW" if risk in ("High", "Medium") else "WARN-NEW"
        pids = f" [{pid}]" if pid else ""
        print(f"{tag}: {name}{pids} x{count}", flush=True)
    print(f"ZAP {mode} scan complete: {len(agg)} unique alerts "
          f"({len(alerts)} instances) in {int(time.time()-start)}s", flush=True)
    return 0


if __name__ == "__main__":
    try:
        rc = main()
    except KeyboardInterrupt:
        rc = 0
    except Exception as e:                       # never hard-fail the engagement
        log(f"error: {e}")
        rc = 0
    finally:
        shutdown()
    sys.exit(rc)
