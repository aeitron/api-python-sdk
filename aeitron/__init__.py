"""
Aeitron Official Python SDK
"""

from .client import AeitronClient, WebhookSignature
from .exceptions import (
    AeitronError,
    AuthenticationError,
    PermissionDeniedError,
    ApprovalRequiredError,
    NotFoundError,
    ConflictError,
    ExpiredError,
    ValidationError,
    RateLimitError,
    ServerError,
    NetworkError,
)
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
from .generated import (
    DnsDeletionRequest,
    DnsApprovalResult,
)
from .generated import *

__version__ = "0.1.0"
__all__ = [
    "AeitronClient",
    "WebhookSignature",
    "AeitronError",
    "AuthenticationError",
    "PermissionDeniedError",
    "ApprovalRequiredError",
    "NotFoundError",
    "ConflictError",
    "ExpiredError",
    "ValidationError",
    "RateLimitError",
    "ServerError",
    "NetworkError",
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
    "DnsDeletionRequest",
    "DnsApprovalResult",
]
