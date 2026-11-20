"""An OAuth 2.1 authorization server plugin for Litestar."""

from litestar_oauth.models import (
    Approval,
    AuthorizationRequest,
    CodeRecord,
    GrantSummary,
    OAuthClient,
    OAuthError,
    TokenKind,
    TokenRecord,
    TokenRequest,
    TokenResponse,
    VerifiedToken,
)
from litestar_oauth.plugin import (
    LitestarOAuth,
    bearer_guard,
    protected_resource_metadata_url,
    verified_token,
)
from litestar_oauth.server import AuthorizationServer, OAuthConfig
from litestar_oauth.stores import (
    ClientStore,
    CodeStore,
    Stores,
    TokenStore,
    in_memory_stores,
)

__version__ = "0.0.1"  # the single source of truth; pyproject reads it via [tool.hatch.version]

__all__ = [
    "Approval",
    "AuthorizationRequest",
    "AuthorizationServer",
    "ClientStore",
    "CodeRecord",
    "CodeStore",
    "GrantSummary",
    "LitestarOAuth",
    "OAuthClient",
    "OAuthConfig",
    "OAuthError",
    "Stores",
    "TokenKind",
    "TokenRecord",
    "TokenRequest",
    "TokenResponse",
    "TokenStore",
    "VerifiedToken",
    "__version__",
    "bearer_guard",
    "in_memory_stores",
    "protected_resource_metadata_url",
    "verified_token",
]
