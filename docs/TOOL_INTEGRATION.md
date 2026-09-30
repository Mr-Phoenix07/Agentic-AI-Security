# Controlled Tool Integration Layer

> Deliverables addressed: **tool adapter architecture** (§4/§35.5), **tool
> registry format** (§35.12), **intelligent test selection** (§11), **tool
> sandbox / controlled execution** (§21), **AI safety controls** (§34).

AEGIS's agents orchestrate *external* security tooling — Nmap, Nuclei, httpx,
ffuf, Semgrep, Trivy, and so on. The danger with "AI + Kali tools" glue is that
a language model ends up choosing and running commands directly. AEGIS is built
the other way around: **every external tool passes through one controlled,
auditable choke point**, and the model never authors a command line.

Package: [`aegis/tools/`](../aegis/tools/)

```
aegis/tools/
├── spec.py        # the standardized adapter contract (metadata + typed params)
├── catalog.py     # built-in adapters (executable) + documentation-only contracts
├── registry.py    # the registry + intelligent, explainable test selection
└── execution.py   # the single controlled execution choke point
```

## The adapter contract (`ToolSpec`)

Every tool is described by a `ToolSpec` before AEGIS will touch it (spec §4):

| Field | Meaning |
|-------|---------|
| `name` / `binary` | logical name and the allow-listed executable |
| `category` | capability bucket (`recon`, `web_scan`, `network`, `static_analysis`, …) |
| `purpose` | one-line description |
| `risk_level` | `PASSIVE < SAFE < ACTIVE < INTRUSIVE < DANGEROUS` |
| `supported_targets` | which `TargetKind`s it applies to |
| `applies_when` | observed signals that make it applicable (`http`, `graphql`, `domain`, …) |
| `requires_network` | blocked in offline mode against non-local targets |
| `evidence_format` | `text` / `json` / `jsonl` / `xml` |
| `input_schema` | structured, documented parameters |
| `command_builder` | **structured params → argv `list[str]`** (no shell string) |
| `parser` | raw output → structured `ParsedObservation`s |

A tool is invoked with a **`ToolInvocation`** (`tool`, `target`, structured
`params`, attribution, reason) — never a free-form command. The `command_builder`
turns validated params into an argv token list; `build_argv_safe()` rejects a
pre-joined string so shell semantics can't sneak back in.

### Executable vs. documentation-only

`command_builder is None` marks a **documentation-only contract**: AEGIS knows
the tool exists and how it fits the plan, but **will refuse to auto-run it**.
`metasploit` and `hydra` are represented this way — present for *planning* ("an
IDOR here could be validated with X"), but requiring a human to implement and
authorize a scoped adapter.

The **gated exploitation** tools `sqlmap` and `ghauri` *do* ship a scoped
adapter, but stay `DANGEROUS`/`EXPLOITATION` class: the executor refuses them
unless the engagement sets `exploitation=True`, the risk cap allows `DANGEROUS`,
and the approval callback returns `True`. Their defaults **confirm** an injection
point only — no `--dump*`/`--os-shell` data-theft or OS-takeover flags. No
offensive payloads live in the catalog.

### Built-in adapters

Recon/enum/scan adapters (all gated by the executor): `subfinder`, `nmap`,
`httpx`, `whatweb`, `nuclei`, `katana`, `ffuf`, `gobuster`, `feroxbuster`,
`arjun`, `nikto`, `zap` (ZAP baseline), `semgrep`, `gitleaks`, `trivy`. Gated
exploitation: `sqlmap`, `ghauri`. Documentation-only: `metasploit`, `hydra`.
Content-discovery tools (`ffuf`/`gobuster`/`feroxbuster`) use a SecLists-style
wordlist auto-detected from common locations (or `scan.wordlist`).

## Intelligent test selection (`ToolRegistry.select`)

Given an observed `TargetProfile` (kind + signals) the registry returns a
`SelectionPlan` — the applicable tools **with a reason for each**, plus the
tools it *excluded* and why. Nothing is executed; this is planning.

```bash
aegis tools list
aegis tools select --kind web_app --signals http,https,web,domain,graphql,jwt
```

Example (a React + Node + GraphQL + JWT web target): `subfinder`, `httpx`,
`whatweb`, `nuclei`, `ffuf`, `gobuster` are selected as runnable; `sqlmap` /
`ghauri` surface as **advisory** until `exploitation=True` and `max_risk` allows
`DANGEROUS`; `hydra` / `metasploit` stay advisory (documentation-only).

## Driving the tools against a live target

`aegis run` wires the executor into the `web_recon` agent when the engagement
config enables it. The relevant `scan:` block keys:

| Key | Effect |
|-----|--------|
| `enabled` / `active` | turn on live scanning / light-active probing |
| `external_tools` + `tools:[…]` | run these registered adapters via the executor |
| `execute_tools` | `false` ⇒ dry-run (validate argv, execute nothing) |
| `offline` | only contact loopback/local hosts |
| `max_risk` | cap runnable risk class (`active` … `dangerous`) |
| `exploitation` / `credential_testing` | unlock `DANGEROUS` / credential tools |
| `recursive` + `crawl_depth` | re-probe tool-discovered endpoints |
| `wordlist` | content-discovery wordlist (auto-detect if null) |
| `injection_targets` | specific endpoints for `sqlmap`/`ghauri` confirmation |

The flow: the built-in stdlib crawler captures a baseline (headers, exposed
paths) **first**; then the external discovery tools (`katana`/`gobuster`/`ffuf`/
`feroxbuster`) run and their endpoints are **recursively re-probed**; then the
signature/DAST tools (`nuclei`/`nikto`/`zap`) and — when exploitation is enabled
— the SQLi confirmers (`sqlmap`/`ghauri`) run. Every tool's parsed output flows
into the analysis agents as findings. See
[`examples/engagement-fulltools-exploit.yaml`](../examples/engagement-fulltools-exploit.yaml)
for a full, exploitation-enabled localhost engagement.

## The controlled executor (`ToolExecutor`)

Nothing in AEGIS calls `subprocess` directly — it goes through the executor,
which enforces, in strict order, and records **an immutable audit record for
every attempt (allowed, refused, or errored)**:

1. **Known & executable** — registered tool with a `command_builder`; binary on
   the allow-list. Documentation-only tools are refused here.
2. **Scope validation (fail-closed)** — the target is routed through the
   engagement's `AuthorizationScope`. Out of scope ⇒ refused; **nothing spawns**.
3. **Offline policy** — network tools are refused against non-local targets when
   `offline=True`.
4. **Engagement class switches** — `DANGEROUS` tools require `exploitation=True`;
   credential tools require `credential_testing=True`; both default off.
5. **No shell** — argv is a validated `list[str]` run with `shell=False`. There
   is no interpolation and no model-authored command line. The child inherits the
   operator's environment (tools need `HOME`/XDG config & cache dirs, e.g. nuclei
   templates); safety comes from the shell-free, validated argv, not from
   starving the child of its environment.
6. **Approval gate** — anything at or above `ACTIVE` risk requires a human
   approval callback to return `True` (default: deny — fail-closed).
7. **Dry-run by default** — the executor resolves and validates everything and
   returns the argv it *would* run, executing nothing, unless a caller explicitly
   opts into real execution.
8. **Bounded execution** — wall-clock timeout, captured stdout/stderr, exit code.

```python
from aegis.tools import ToolRegistry, ToolExecutor, ToolInvocation
from aegis.core.authorization import AuthorizationScope, ScopeRule

scope = AuthorizationScope([ScopeRule(
    label="engagement-42", hosts=["*.authorized.example"],
    url_globs=["https://authorized.example/*"], authorization_ref="SoW-42")])

reg = ToolRegistry()
ex = ToolExecutor(scope, dry_run=True,                 # preview only
                  approval=lambda inv, spec, dec: True) # human-in-the-loop

res = ex.run(ToolInvocation(tool="nuclei",
                            target="https://authorized.example",
                            reason="signature scan of authorized surface"),
             reg.get("nuclei"))
# res.argv -> the exact command; res.dry_run == True; nothing executed.
# ex.audit_log[-1] -> the ToolRunRecord (scope decision, approval, outcome).
```

Even in real-execution mode with all approvals granted, an out-of-scope target
is refused **before any process is spawned**.

## Audit trail

Each `ToolRunRecord` is emitted on the message bus (`tool.run`) and can be
persisted append-only to the `tool_runs` table
([`aegis/storage/schema.sql`](../aegis/storage/schema.sql)) via
`Database.save_tool_run(...)`. The record captures the command, target, scope
decision, approval, risk level, dry-run flag, exit code, and outcome — satisfying
the "record every tool call" requirement of the AI safety controls (§34) and the
trust hierarchy *raw output → parsed observation → analysis → validated finding*.

## Adding a tool

Implement a `command_builder` (structured params → argv) and, optionally, a
`parser`, then register a `ToolSpec`. The orchestrator picks it up automatically
via `applies_when` / `supported_targets` — the executor's guarantees apply with
no further wiring. For an intrusive tool, ship it **documentation-only** (no
builder) until a human implements and authorizes the adapter for the engagement.
