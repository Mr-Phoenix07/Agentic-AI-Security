"""The AEGIS agent collective.

Twenty-four specialized, collaborating agents, coordinated by the Orchestrator
(see :mod:`aegis.graph.workflow`). ``WORKFLOW_ORDER`` is the canonical
dependency-respecting execution sequence; each agent's ``should_run`` gates it
per target kind and per engagement switch, so the same order serves LLM, RAG,
web, API, and MCP assessments (the two offensive agents stay gated off unless the
engagement explicitly enables active exploitation / model red-teaming).
"""

from __future__ import annotations

from .analysis import (
    APISecurityAgent,
    ControlledValidationAgent,
    EvidenceCollectionAgent,
    InformationVerificationAgent,
    RAGAnalysisAgent,
    RiskAnalysisAgent,
    VulnerabilityAssessmentAgent,
)
from .base import BaseAgent
from .interaction import (
    AdaptiveEvaluationAgent,
    ConversationAgent,
    LongContextAgent,
    PromptMutationAgent,
    PromptOptimizationAgent,
)
from .mapping import (
    AttackSurfaceMappingAgent,
    BoundaryMappingAgent,
    CapabilityMappingAgent,
    WebReconAgent,
)
from .offensive import AdversarialRedTeamAgent, WebExploitAgent
from .planning import Planner, TaskScheduler
from .reporting_agents import (
    DashboardAgent,
    ExplainabilityAgent,
    MitigationRecommendationAgent,
    ReportingAgent,
)

# Canonical, dependency-ordered pipeline (gated per target by should_run).
WORKFLOW_ORDER: list[type[BaseAgent]] = [
    Planner,
    TaskScheduler,
    CapabilityMappingAgent,
    BoundaryMappingAgent,
    WebReconAgent,
    AttackSurfaceMappingAgent,
    PromptMutationAgent,
    PromptOptimizationAgent,
    ConversationAgent,
    AdaptiveEvaluationAgent,
    AdversarialRedTeamAgent,
    LongContextAgent,
    RAGAnalysisAgent,
    InformationVerificationAgent,
    APISecurityAgent,
    WebExploitAgent,
    VulnerabilityAssessmentAgent,
    ControlledValidationAgent,
    EvidenceCollectionAgent,
    RiskAnalysisAgent,
    ExplainabilityAgent,
    MitigationRecommendationAgent,
    ReportingAgent,
    DashboardAgent,
]

REGISTRY: dict[str, type[BaseAgent]] = {cls.name: cls for cls in WORKFLOW_ORDER}

__all__ = ["BaseAgent", "WORKFLOW_ORDER", "REGISTRY",
           *[cls.__name__ for cls in WORKFLOW_ORDER]]
