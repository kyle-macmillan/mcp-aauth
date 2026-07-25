from .client import AAuthAgentHTTPAuth
from .middleware import DualAuthMiddleware, MiddlewareFactory, dual_authentication
from .request import (
    ASGIRequestError,
    ASGIRequestErrorCode,
    aauth_request_from_scope,
)
from .routing import (
    CredentialRoute,
    CredentialRoutingError,
    classify_credentials,
)
from .verification import (
    AAuthAgentMiddleware,
    aauth_agent_authentication,
    verify_aauth_agent,
)

__all__ = [
    "AAuthAgentMiddleware",
    "AAuthAgentHTTPAuth",
    "ASGIRequestError",
    "ASGIRequestErrorCode",
    "CredentialRoute",
    "CredentialRoutingError",
    "DualAuthMiddleware",
    "MiddlewareFactory",
    "aauth_request_from_scope",
    "aauth_agent_authentication",
    "classify_credentials",
    "dual_authentication",
    "verify_aauth_agent",
]
