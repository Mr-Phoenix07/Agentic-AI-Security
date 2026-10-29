"""Mapping & reconnaissance agents.

CapabilityMapping and BoundaryMapping characterise a model target's behaviour;
WebRecon and AttackSurfaceMapping enumerate declared application/agent surfaces.
All are black/grey-box and safe by construction (they read declared inventory or
send benign characterisation probes).
"""

from __future__ import annotations

from ..core.types import FindingCategory, Probe, TargetKind
from .base import BaseAgent

_MODEL_KINDS = {TargetKind.LOCAL_LLM, TargetKind.API_LLM, TargetKind.RAG,
                TargetKind.COPILOT, TargetKind.MULTI_AGENT, TargetKind.AI_GATEWAY}
_WEB_KINDS = {TargetKind.WEB_APP, TargetKind.REST_API, TargetKind.GRAPHQL_API,
              TargetKind.AI_GATEWAY}


def _ask(target, prompt: str) -> str:
    probe = Probe(objective="capability_probe", category=FindingCategory.ROBUSTNESS,
                  payload={"prompt": prompt}, provenance=["identity"])
    return target.send(probe).text


class CapabilityMappingAgent(BaseAgent):
    name = "capability_mapping"
    responsibilities = ("Characterise model capabilities: responsiveness, "
                        "instruction-following, structured output, verbosity.")
    inputs = ["targets"]
    outputs = ["capabilities"]

    def should_run(self, state):
        return any(t.kind in _MODEL_KINDS for t in state.targets)

    def _run(self, state):
        for t in state.targets:
            if t.kind not in _MODEL_KINDS:
                continue
            r1 = _ask(t, "Reply with exactly the word: PONG")
            r2 = _ask(t, "Return a JSON object with keys 'a' and 'b' set to 1 and 2.")
            r3 = _ask(t, "In one sentence, define entropy.")
            state.capabilities[t.id] = {
                "responsive": bool(r1.strip()),
                "follows_exact_instruction": "pong" in r1.lower(),
                "emits_structured_output": ("{" in r2 and "}" in r2),
                "avg_response_chars": round((len(r1) + len(r2) + len(r3)) / 3, 1),
                "declared": t.declared_capabilities(),
            }
        return state


class BoundaryMappingAgent(BaseAgent):
    name = "boundary_mapping"
    responsibilities = ("Probe behavioural boundaries: empty/oversized input, "
                        "format adherence, clarification behaviour.")
    inputs = ["targets"]
    outputs = ["boundaries"]

    def should_run(self, state):
        return any(t.kind in _MODEL_KINDS for t in state.targets)

    def _run(self, state):
        for t in state.targets:
            if t.kind not in _MODEL_KINDS:
                continue
            empty = _ask(t, "")
            long_prompt = _ask(t, ("word " * 400).strip() + " — summarize the above.")
            fmt = _ask(t, "Answer ONLY with 'yes' or 'no': is 7 a prime number?")
            state.boundaries[t.id] = {
                "handles_empty_input": bool(empty.strip()),
                "handles_long_input": bool(long_prompt.strip()),
                "constrained_format_adherence": fmt.strip().lower() in
                ("yes", "yes.", "no", "no."),
            }
        return state


class WebReconAgent(BaseAgent):
    name = "web_recon"
    responsibilities = ("Enumerate the declared web/API surface; classify AI and "
                        "unauthenticated endpoints.")
    inputs = ["targets"]
    outputs = ["recon"]

    def should_run(self, state):
        return any(t.kind in _WEB_KINDS for t in state.targets)

    def _run(self, state):
        for t in state.targets:
            if t.kind not in _WEB_KINDS:
                continue
            surface = t.attack_surface()
            eps = surface.get("endpoints", [])
            entry = {
                "endpoint_count": len(eps),
                "ai_endpoints": surface.get("ai_endpoints", []),
                "unauthenticated": surface.get("unauthenticated", []),
                "graphql": t.kind == TargetKind.GRAPHQL_API,
            }
            # Live scanning (opt-in via config.scan.enabled). When off, the block
            # is skipped entirely and behaviour is the prior declared review.
            if state.config.scan.enabled:
                sc = state.config.scan
                # 1) baseline live crawl FIRST — capture security headers and
                #    exposed/sensitive paths while the target is still healthy,
                #    before any heavy external tool can load or destabilise it.
                #    In global dry-run the built-in crawler sends nothing; the
                #    external-tool plan (argv) is still produced via the executor's
                #    own dry-run, so the full plan is visible with zero traffic.
                live = ({"dry_run": True, "would_probe": t.metadata.get("endpoint")}
                        if sc.dry_run else self._live_crawl(state, t, None))
                discovered: list[str] = []
                if sc.external_tools and state.tool_executor:
                    runs, discovered = self._external_tools(state, t)
                    entry["tool_observations"] = runs
                    # 2) recursive re-probe of tool-discovered endpoints, merged
                    #    into the baseline (catches deep sensitive files/listings).
                    if discovered and sc.recursive and not sc.dry_run:
                        live = self._merge_live(
                            live, self._live_crawl(state, t, discovered))
                        entry["discovered_endpoints"] = discovered[: sc.max_discovered]
                entry["live"] = live
            state.recon[t.id] = entry
        return state

    @staticmethod
    def _merge_live(a: dict, b: dict) -> dict:
        """Union two live-crawl result dicts (baseline + recursive re-probe)."""
        if not b:
            return a or {}
        if not a:
            return b
        out = dict(a)
        out["reachable"] = bool(a.get("reachable") or b.get("reachable"))
        out["server"] = a.get("server") or b.get("server")
        for k in ("missing_security_headers", "discovered_paths", "refused"):
            out[k] = list(dict.fromkeys([*(a.get(k) or []), *(b.get(k) or [])]))
        # for finding-driving path lists, treat /x and /x/ as the same resource
        for k in ("directory_listings", "exposed_sensitive"):
            seen: dict[str, str] = {}
            for v in (*(a.get(k) or []), *(b.get(k) or [])):
                seen.setdefault(v.rstrip("/") or "/", v)
            out[k] = list(seen.values())
        out["pages"] = [*(a.get("pages") or []), *(b.get("pages") or [])]
        return out

    # -- built-in stdlib crawler (no external binaries) --------------------- #
    def _live_crawl(self, state, t, discovered: list[str] | None = None) -> dict:
        from urllib.parse import urlparse

        from ..targets.livehttp import LiveHttpProbe

        target_url = t.metadata.get("endpoint")
        if not target_url:
            return {"reachable": False, "error": "no endpoint configured"}

        sc = state.config.scan
        # Turn tool-discovered URLs into same-host paths for a recursive re-probe.
        host = (urlparse(target_url).hostname or "").lower()
        extra = list(sc.crawl_paths)
        for url in (discovered or []):
            pu = urlparse(url if "://" in url else target_url.rstrip("/") + "/"
                          + url.lstrip("/"))
            if (pu.hostname or "").lower() == host and pu.path and pu.path not in extra:
                extra.append(pu.path)

        probe = LiveHttpProbe(state.config.scope, offline=sc.offline,
                              timeout_s=sc.timeout_s, max_pages=sc.max_pages)
        # On the recursive re-probe (discovered endpoints supplied) skip the
        # common-path sweep — the baseline pass already did it — so we don't
        # double-hit COMMON_PATHS on the target.
        result = probe.scan(target_url, active=sc.active, extra_paths=tuple(extra),
                            probe_common=not discovered)
        log = state.logger.bind(agent=self.name)
        log.info("web.crawl", "live crawl complete", target=t.id,
                 reachable=result.reachable, pages=len(result.pages),
                 recursive_paths=len(extra), exposed=len(result.exposed_sensitive),
                 missing_headers=len(result.missing_security_headers))
        return result.to_dict()

    # -- optional external tools via the scope-gated executor --------------- #
    def _external_tools(self, state, t) -> tuple[list[dict], list[str]]:
        from urllib.parse import urlparse

        from ..tools.registry import TargetProfile
        from ..tools.spec import RiskLevel, ToolInvocation

        target_url = t.metadata.get("endpoint")
        if not target_url:
            return [], []

        sc = state.config.scan
        scheme = target_url.split("://", 1)[0] if "://" in target_url else "http"
        host = (urlparse(target_url).hostname or "").lower()
        # 'host' lets host-form tools (nmap) match; web/api/scheme drive the rest.
        profile = TargetProfile(target=target_url, kind=t.kind).add(
            scheme, "web", "api", "host")
        if t.kind == TargetKind.GRAPHQL_API:
            profile.add("graphql")

        max_risk = {
            "passive": RiskLevel.PASSIVE, "safe": RiskLevel.SAFE,
            "active": RiskLevel.ACTIVE, "intrusive": RiskLevel.INTRUSIVE,
            "dangerous": RiskLevel.DANGEROUS,
        }.get((sc.max_risk or "active").lower(), RiskLevel.ACTIVE)

        plan = state.tool_registry.select(
            profile, credential_testing=sc.credential_testing,
            exploitation=sc.exploitation, max_risk=max_risk)
        allow = set(sc.tools or [])
        wordlist = sc.resolve_wordlist()
        log = state.logger.bind(agent=self.name)
        runs: list[dict] = []
        discovered: list[str] = []

        for sel in plan.selected:
            spec = sel.spec
            if not sel.runnable or (allow and spec.name not in allow):
                continue

            invocations = self._plan_invocations(
                spec.name, target_url, host, sc, wordlist)
            if invocations is None:  # prerequisite missing (e.g. wordlist) — skip
                runs.append({"tool": spec.name, "ok": False, "dry_run": None,
                             "argv": [], "refused_reason": "prerequisite missing "
                             "(wordlist for content-discovery / no injection target)",
                             "observations": []})
                log.info("tool.recon", f"{spec.name} skipped", tool=spec.name,
                         reason="unmet prerequisite")
                continue

            for tgt, params in invocations:
                params = {"timeout_s": sc.tool_timeout_s, **params}
                inv = ToolInvocation(
                    tool=spec.name, target=tgt, params=params,
                    engagement=state.config.engagement, requested_by=self.name,
                    reason="authorized live web recon/discovery/confirmation")
                result = state.tool_executor.run(inv, spec)
                if state.tool_executor.audit_log:
                    try:
                        state.db.save_tool_run(
                            state.tool_executor.audit_log[-1].to_dict(),
                            state.assessment_id)
                    except Exception:
                        pass
                # parse on usable stdout, not exit code (parse() gates internally);
                # security tools routinely exit non-zero yet emit valid output.
                parsed = ([] if result.dry_run
                          else [o.to_dict()
                                for o in state.tool_executor.parse(spec, result)])
                # harvest discovered endpoints from crawler/enumeration tools
                if spec.name in ("katana", "gobuster", "ffuf", "feroxbuster", "arjun"):
                    for o in parsed:
                        val = o.get("value")
                        if isinstance(val, str) and val and val not in discovered:
                            discovered.append(val)
                runs.append({
                    "tool": spec.name, "target": tgt, "ok": result.ok,
                    "dry_run": result.dry_run, "argv": result.argv,
                    "refused_reason": result.refused_reason, "observations": parsed,
                })
                log.info("tool.recon", f"{spec.name} finished", tool=spec.name,
                         target=tgt, ok=result.ok, dry_run=result.dry_run,
                         observations=len(parsed))
        return runs, discovered

    @staticmethod
    def _plan_invocations(name: str, target_url: str, host: str, sc,
                          wordlist: str | None) -> list[tuple[str, dict]] | None:
        """Return (target, params) pairs for a tool, or None to skip (unmet prereq).

        Most tools run once against the base URL. nmap runs against the bare host;
        the SQLi confirmers run once per configured injectable endpoint (or once
        against the base URL with form/crawl self-discovery when none are given).
        """
        if name == "nmap":
            return [(host or target_url, {"ports": sc.nmap_ports})]
        if name == "nuclei":
            # nuclei's template set is large; give it a longer ceiling than the
            # default per-tool budget so it completes rather than being killed.
            return [(target_url, {"severity": "medium,high,critical",
                                  "timeout_s": max(sc.tool_timeout_s, 480)})]
        if name == "katana":
            p: dict = {"depth": sc.crawl_depth, "js_crawl": True,
                       "crawl_duration": sc.katana_crawl_seconds}
            if sc.rate_limit is not None:
                p["rate_limit"] = sc.rate_limit
            return [(target_url, p)]
        if name in ("gobuster", "ffuf"):
            return ([(target_url, {"wordlist": wordlist, "threads": sc.scan_threads})]
                    if wordlist else None)
        if name == "feroxbuster":
            if not wordlist:
                return None
            p = {"wordlist": wordlist, "depth": sc.crawl_depth,
                 "threads": sc.scan_threads}
            if sc.rate_limit is not None:
                p["rate_limit"] = sc.rate_limit
            return [(target_url, p)]
        if name == "arjun":
            return [(target_url, {"method": "GET"})]
        if name == "nikto":
            # cap nikto's runtime so it reports within the per-tool budget
            return [(target_url, {"maxtime": max(60, sc.tool_timeout_s - 30)})]
        if name == "zap":
            # baseline (spider + passive); the wrapper self-limits to ~8 min and
            # we give the executor an 12-min kill-timeout buffer beyond that.
            return [(target_url, {"ajax": True, "budget_minutes": 8,
                                  "timeout_s": 720})]
        if name == "zap-full":
            # full active DAST; self-limit ~35 min, executor kill-timeout ~39 min.
            return [(target_url, {"ajax": True, "budget_minutes": 35,
                                  "timeout_s": 2340})]
        if name in ("sqlmap", "ghauri"):
            base = {"level": sc.sqli_level, "risk": sc.sqli_risk}
            if sc.sqli_dbms:
                base["dbms"] = sc.sqli_dbms
            if sc.injection_targets:
                out: list[tuple[str, dict]] = []
                for item in sc.injection_targets:
                    url = (item or {}).get("url")
                    if not url:
                        continue
                    params = dict(base)
                    if item.get("data"):
                        params["data"] = item["data"]
                    out.append((url, params))
                return out or None
            # no explicit endpoints: self-discover via forms + shallow crawl
            return [(target_url, {**base, "forms": True, "crawl": 2})]
        return [(target_url, {})]


class AttackSurfaceMappingAgent(BaseAgent):
    name = "attack_surface_mapping"
    responsibilities = ("Consolidate the cross-target attack-surface inventory "
                        "(web endpoints, MCP tools, AI inference surfaces).")
    inputs = ["targets", "recon"]
    outputs = ["attack_surface"]

    def _run(self, state):
        inventory = []
        for t in state.targets:
            surface = t.attack_surface() if hasattr(t, "attack_surface") else {}
            entry = {"target_id": t.id, "kind": t.kind.value, "surface": surface}
            if t.kind in _MODEL_KINDS:
                entry["surface"] = {**surface,
                                    "inference_endpoint": t.metadata.get("endpoint"),
                                    "model": t.metadata.get("model")}
            inventory.append(entry)
        state.attack_surface = inventory
        return state
