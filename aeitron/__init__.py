"""
Aeitron Official Python SDK
"""

from .client import AeitronClient
from .exceptions import AeitronError
from .types import (
    ChatMessage,
    CompletionChoice,
    CompletionResponse,
    CompletionTelemetry,
    CompletionUsage,
    DomainRecord,
    Jurisdiction,
    LatencyMatrixResult,
    LatencyMatrixRoute,
    OnboardDomainResult,
    PoPHealthRecord,
    RoutingStrategy,
    TelemetryRateLimit,
    TelemetrySummary,
    VerifyDomainResult,
    SovereignEvaluationResult,
    SchedulingDecision,
    ComputeNodeRecord,
)
from .generated import *

__version__ = "0.1.0"
__all__ = [
    "AeitronClient",
    "AeitronError",
    "ChatMessage",
    "CompletionChoice",
    "CompletionResponse",
    "CompletionTelemetry",
    "CompletionUsage",
    "DomainRecord",
    "Jurisdiction",
    "LatencyMatrixResult",
    "LatencyMatrixRoute",
    "OnboardDomainResult",
    "PoPHealthRecord",
    "RoutingStrategy",
    "TelemetryRateLimit",
    "TelemetrySummary",
    "VerifyDomainResult",
    "SovereignEvaluationResult",
    "SchedulingDecision",
    "ComputeNodeRecord",
]

