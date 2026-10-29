"""Orchestrator & workflow graph.

The Orchestrator drives the twenty-three-agent collective over a single shared
:class:`~aegis.graph.state.AssessmentState`. The reference implementation is a
deterministic, dependency-free sequential state machine (phases: PLAN → MAP →
EVALUATE → ANALYZE → REMEDIATE → REPORT → DONE). When ``langgraph`` is installed,
:func:`to_langgraph` builds an equivalent ``StateGraph`` for teams standardising
on that runtime — same agents, same order, richer tracing.
"""

from __future__ import annotations

from enum import Enum

from ..agents import WORKFLOW_ORDER
from ..core.config import Config
from ..core.events import Message, MessageBus
from ..observability.logging import BoundLogger, get_logger
from ..observability.tracing import Tracer
from ..storage.db import Database
from ..targets import build_target
from .state import AssessmentState


class Phase(str, Enum):
    PLAN = "plan"
    MAP = "map"
    EVALUATE = "evaluate"
    ANALYZE = "analyze"
    REMEDIATE = "remediate"
    REPORT = "report"
    DONE = "done"


# Which phase each agent belongs to (drives the state-machine view + progress).
AGENT_PHASE: dict[str, Phase] = {
    "planner": Phase.PLAN, "task_scheduler": Phase.PLAN,
    "capability_mapping": Phase.MAP, "boundary_mapping": Phase.MAP,
    "web_recon": Phase.MAP, "attack_surface_mapping": Phase.MAP,
    "prompt_mutation": Phase.EVALUATE, "prompt_optimization": Phase.EVALUATE,
    "conversation": Phase.EVALUATE, "adaptive_evaluation": Phase.EVALUATE,
    "adversarial_redteam": Phase.EVALUATE, "ai_toolchain": Phase.EVALUATE,
    "long_context": Phase.EVALUATE, "rag_analysis": Phase.EVALUATE,
    "information_verification": Phase.ANALYZE, "api_security": Phase.ANALYZE,
    "web_exploit": Phase.ANALYZE,
    "vulnerability_assessment": Phase.ANALYZE, "controlled_validation": Phase.ANALYZE,
    "evidence_collection": Phase.ANALYZE, "risk_analysis": Phase.ANALYZE,
    "explainability": Phase.REMEDIATE, "mitigation_recommendation": Phase.REMEDIATE,
    "reporting": Phase.REPORT, "dashboard": Phase.REPORT,
}


def build_state(config: Config, *, bus: MessageBus | None = None,
                db: Database | None = None) -> AssessmentState:
    """Materialise durable handles + targets into an :class:`AssessmentState`."""
    logger = get_logger("aegis", level=config.log_level)
    db = db or Database(config.db_path)
    bus = bus or MessageBus()
    tracer = Tracer("aegis")
    aid = db.create_assessment(config.engagement, config.to_dict())
    blog = BoundLogger(logger, assessment_id=aid)

    targets = [build_target(tc, scope=config.scope) for tc in config.targets]
    for t in targets:
        db.add_target(aid, t.id, t.kind.value, t.mode.value,
                      t.metadata.get("model"), t.metadata.get("endpoint"),
                      {k: v for k, v in t.metadata.items() if k not in ("model", "endpoint")})

    tool_executor, tool_registry = _build_tooling(config, bus)

    state = AssessmentState(config=config, assessment_id=aid, db=db, bus=bus,
                            logger=blog, tracer=tracer, targets=targets,
                            tool_executor=tool_executor, tool_registry=tool_registry)
    blog.info("assessment.start", "assessment initialised",
              targets=len(targets), engagement=config.engagement)
    return state


def _build_tooling(config: Config, bus: MessageBus):
    """Construct the scope-gated ToolExecutor + registry, or (None, None).

    Only built when live scanning *and* the external-tool layer are enabled.
    The executor shares the engagement's fail-closed authorization scope, so an
    out-of-scope target is refused before any process is created.
    """
    scan = config.scan
    if not (scan.enabled and scan.external_tools):
        return None, None

    from ..tools import ToolRegistry
    from ..tools.execution import ToolExecutor, deny_all_approvals

    def _approve_active(inv, spec, decision) -> bool:
        return True  # explicit engagement opt-in for ACTIVE+ tools

    approval = _approve_active if scan.auto_approve_active else deny_all_approvals
    executor = ToolExecutor(
        scope=config.scope,
        bus=bus,
        offline=scan.offline,
        dry_run=(not scan.execute_tools) or scan.dry_run,
        approval=approval,
        credential_testing=scan.credential_testing,
        exploitation=scan.exploitation,
        env_passthrough=scan.tool_env,
    )
    return executor, ToolRegistry()


class Orchestrator:
    name = "orchestrator"
    responsibilities = ("Coordinate the agent collective across assessment phases, "
                        "enforce ordering, and surface progress.")

    def __init__(self, agents: list | None = None,
                 progress: callable | None = None) -> None:
        self.agent_classes = agents or WORKFLOW_ORDER
        self.progress = progress or (lambda *_: None)

    def run(self, state: AssessmentState) -> AssessmentState:
        current_phase = None
        with state.tracer.span("orchestrator"):
            for cls in self.agent_classes:
                phase = AGENT_PHASE.get(cls.name, Phase.EVALUATE)
                if phase != current_phase:
                    current_phase = phase
                    state.bus.publish(Message("phase.enter", self.name,
                                              {"phase": phase.value}))
                    self.progress("phase", {"phase": phase.value})
                agent = cls()
                self.progress("agent", {"agent": cls.name, "phase": phase.value})
                state = agent.run(state)
            state.bus.publish(Message("phase.enter", self.name,
                                      {"phase": Phase.DONE.value}))
        state.logger.info("assessment.done", "assessment complete",
                          findings=len(state.findings), errors=len(state.errors))
        return state


def run_assessment(config: Config, *, progress: callable | None = None,
                   bus: MessageBus | None = None) -> AssessmentState:
    """One-call entrypoint: build state, run the orchestrator, return final state."""
    state = build_state(config, bus=bus)
    orch = Orchestrator(progress=progress)
    return orch.run(state)


def to_langgraph(config: Config):  # pragma: no cover - optional runtime
    """Build an equivalent LangGraph ``StateGraph`` (optional dependency).

    Falls back with a clear error if ``langgraph`` is not installed. The graph is
    linear (same order as the sequential runner); AEGIS's adaptivity lives *inside*
    the AdaptiveEvaluationAgent node, so a linear top-level graph is faithful.
    """
    try:
        from langgraph.graph import END, START, StateGraph  # type: ignore
    except Exception as e:
        raise RuntimeError(
            "LangGraph not installed (pip install aegis-ai-security[graph])") from e

    graph = StateGraph(dict)
    names = [cls.name for cls in WORKFLOW_ORDER]

    def make_node(cls):
        def _node(state_dict):
            agent = cls()
            st = state_dict["_state"]
            state_dict["_state"] = agent.run(st)
            return state_dict
        return _node

    for cls in WORKFLOW_ORDER:
        graph.add_node(cls.name, make_node(cls))
    graph.add_edge(START, names[0])
    for a, b in zip(names, names[1:], strict=False):
        graph.add_edge(a, b)
    graph.add_edge(names[-1], END)
    return graph.compile()
