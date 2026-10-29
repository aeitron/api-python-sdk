"""
Aeitron Python SDK - Exceptions
"""

from typing import Any, Dict, Optional, Union


class AeitronError(Exception):
    """Base exception for all Aeitron client errors."""

    def __init__(
        self,
        status: int,
        message: str,
        code: Optional[Union[str, int]] = None,
        details: Any = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.code = code if code is not None else status
        self.details = details

    def __str__(self) -> str:
        if self.code != self.status:
            return f"[{self.status}:{self.code}] {self.message}"
        return f"[{self.status}] {self.message}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(status={self.status}, code={self.code!r}, message={self.message!r})"


class AuthenticationError(AeitronError):
    """Thrown when API authentication fails (HTTP 401)."""

    def __init__(
        self,
        message: str = "Authentication failed. Provide a valid API key.",
        code: Optional[Union[str, int]] = "UNAUTHORIZED",
        details: Any = None,
    ) -> None:
        super().__init__(401, message, code, details)


class PermissionDeniedError(AeitronError):
    """Thrown when caller lacks required scopes or permissions (HTTP 403)."""

    def __init__(
        self,
        message: str = "Permission denied",
        code: Optional[Union[str, int]] = "FORBIDDEN",
        details: Any = None,
    ) -> None:
        super().__init__(403, message, code, details)


class ApprovalRequiredError(AeitronError):
    """Thrown when a high-risk operation requires independent human operator approval."""

    def __init__(
        self,
        message: str,
        challenge_request_id: str,
        domain: Optional[str] = None,
        record_id: Optional[str] = None,
        details: Any = None,
    ) -> None:
        super().__init__(403, message, "APPROVAL_REQUIRED", details)
        self.challenge_request_id = challenge_request_id
        self.domain = domain
        self.record_id = record_id


class NotFoundError(AeitronError):
    """Thrown when requested resource is not found (HTTP 404)."""

    def __init__(
        self,
        message: str = "Resource not found",
        code: Optional[Union[str, int]] = "NOT_FOUND",
        details: Any = None,
    ) -> None:
        super().__init__(404, message, code, details)


class ConflictError(AeitronError):
    """Thrown on resource state conflict or duplicate creation (HTTP 409)."""

    def __init__(
        self,
        message: str = "Resource conflict",
        code: Optional[Union[str, int]] = "CONFLICT",
        details: Any = None,
    ) -> None:
        super().__init__(409, message, code, details)


class ExpiredError(AeitronError):
    """Thrown when a token, approval, or ephemeral resource has expired (HTTP 410)."""

    def __init__(
        self,
        message: str = "Resource expired or already consumed",
        code: Optional[Union[str, int]] = "GONE",
        details: Any = None,
    ) -> None:
        super().__init__(410, message, code, details)


class ValidationError(AeitronError):
    """Thrown when request validation or parameters fail (HTTP 400 or 422)."""

    def __init__(
        self,
        message: str = "Validation failed",
        code: Optional[Union[str, int]] = "VALIDATION_ERROR",
        details: Any = None,
        status: int = 400,
    ) -> None:
        super().__init__(status, message, code, details)
        self.validation_errors: Optional[Dict[str, Any]] = details if isinstance(details, dict) else None


class RateLimitError(AeitronError):
    """Thrown when request rate limit is exceeded (HTTP 429)."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after_seconds: Optional[int] = None,
        code: Optional[Union[str, int]] = "RATE_LIMIT_EXCEEDED",
        details: Any = None,
    ) -> None:
        super().__init__(429, message, code, details)
        self.retry_after_seconds = retry_after_seconds


class ServerError(AeitronError):
    """Thrown on upstream 5xx edge or gateway failures."""

    def __init__(
        self,
        status: int = 500,
        message: str = "Internal server error",
        code: Optional[Union[str, int]] = "INTERNAL_SERVER_ERROR",
        details: Any = None,
    ) -> None:
        super().__init__(status, message, code, details)


class NetworkError(AeitronError):
    """Thrown on network, connection, or timeout failures."""

    def __init__(
        self,
        message: str = "Network error occurred",
        code: Optional[Union[str, int]] = "NETWORK_ERROR",
        details: Any = None,
        status: int = 0,
    ) -> None:
        super().__init__(status, message, code, details)
