"""Shared assessment state — the blackboard the agent graph operates on.

A single :class:`AssessmentState` instance flows through the workflow. Agents read
the keys they declare as inputs and write the keys they declare as outputs, which
makes data dependencies explicit and lets the scheduler order work correctly.

The state also carries the durable handles (database, memory, bus, logger,
tracer) so agents don't reach for globals.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.config import Config
from ..core.events import MessageBus
from ..core.memory import Memory
from ..core.types import Finding, Observation
from ..evaluation.loop import EvaluationReport
from ..observability.logging import BoundLogger
from ..observability.tracing import Tracer
from ..storage.db import Database
from ..targets.base import Target

if TYPE_CHECKING:  # optional; only built when scan.external_tools is enabled
    from ..tools.execution import ToolExecutor
    from ..tools.registry import ToolRegistry


@dataclass
class AssessmentState:
    config: Config
    assessment_id: str
    db: Database
    bus: MessageBus
    logger: BoundLogger
    tracer: Tracer
    memory: dict[str, Memory] = field(default_factory=dict)   # per target_key
    targets: list[Target] = field(default_factory=list)

    # optional external-tool layer (None unless scan.external_tools is enabled)
    tool_executor: ToolExecutor | None = None
    tool_registry: ToolRegistry | None = None

    # planning
    seeds: list = field(default_factory=list)
    plan: dict = field(default_factory=dict)
    schedule: list = field(default_factory=list)
    strategy: dict = field(default_factory=dict)

    # mapping / recon
    capabilities: dict[str, dict] = field(default_factory=dict)
    boundaries: dict[str, dict] = field(default_factory=dict)
    recon: dict[str, dict] = field(default_factory=dict)
    attack_surface: list[dict] = field(default_factory=list)

    # evaluation
    evaluations: dict[str, EvaluationReport] = field(default_factory=dict)
    pairs: dict[str, list] = field(default_factory=dict)   # target_id -> [ProbePair]
    observations: list[Observation] = field(default_factory=list)
    verified_observations: list[Observation] = field(default_factory=list)
    explanations: dict[str, dict] = field(default_factory=dict)

    # findings pipeline
    candidates: list[Finding] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    correlations: list[dict] = field(default_factory=list)

    # outputs
    report_paths: dict[str, str] = field(default_factory=dict)
    metrics: dict = field(default_factory=dict)
    coverage: dict = field(default_factory=dict)

    # bookkeeping
    trail: list[str] = field(default_factory=list)   # ordered agent execution log
    errors: list[dict] = field(default_factory=list)

    def target(self, target_id: str) -> Target | None:
        return next((t for t in self.targets if t.id == target_id), None)

    def mem_for(self, target: Target) -> Memory:
        key = f"{target.provider.name}:{target.metadata.get('model') or target.id}"
        if key not in self.memory:
            self.memory[key] = Memory(self.db, target_key=key)
        return self.memory[key]
