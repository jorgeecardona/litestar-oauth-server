"""An OAuth 2.1 authorization server plugin for Litestar.

Importing the package does not import Litestar. The models, the stores and ``AuthorizationServer``
are plain Python, so a package that only holds the database layer can use them without the web
framework. The Litestar names (``LitestarOAuth``, ``bearer_guard``, ``verified_token``,
``protected_resource_metadata_url``) load on first use (#3).
"""

from importlib import import_module
from typing import TYPE_CHECKING

from litestar_oauth_server.models import (
    DEFAULT_GRANT_TYPES,
    GRANT_AUTHORIZATION_CODE,
    GRANT_DEVICE_CODE,
    GRANT_REFRESH_TOKEN,
    Approval,
    AuthorizationRequest,
    ClientLike,
    CodeLike,
    CodeRecord,
    DeviceAuthorization,
    DeviceDecision,
    DeviceLike,
    DeviceRecord,
    DeviceRequest,
    DeviceStatus,
    GrantSummary,
    OAuthClient,
    OAuthError,
    TokenKind,
    TokenLike,
    TokenRecord,
    TokenRequest,
    TokenResponse,
    VerifiedToken,
)
from litestar_oauth_server.server import (
    AuthorizationServer,
    OAuthConfig,
    format_user_code,
    normalize_user_code,
)
from litestar_oauth_server.stores import (
    ClientAdmin,
    ClientPurge,
    ClientStore,
    CodeStore,
    DeviceStore,
    Stores,
    TokenStore,
    in_memory_stores,
)

if TYPE_CHECKING:
    from litestar_oauth_server.plugin import (
        LitestarOAuth,
        bearer_guard,
        protected_resource_metadata_url,
        verified_token,
    )

# Names that live in ``plugin``, the only module that imports Litestar (PEP 562).
_LAZY = frozenset(
    {"LitestarOAuth", "bearer_guard", "protected_resource_metadata_url", "verified_token"}
)


def __getattr__(name: str) -> object:
    if name in _LAZY:
        return getattr(import_module("litestar_oauth_server.plugin"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__version__ = "0.0.12"  # the single source of truth; pyproject reads it via [tool.hatch.version]

__all__ = [
    "DEFAULT_GRANT_TYPES",
    "GRANT_AUTHORIZATION_CODE",
    "GRANT_DEVICE_CODE",
    "GRANT_REFRESH_TOKEN",
    "Approval",
    "AuthorizationRequest",
    "AuthorizationServer",
    "ClientAdmin",
    "ClientLike",
    "ClientPurge",
    "ClientStore",
    "CodeLike",
    "CodeRecord",
    "CodeStore",
    "DeviceAuthorization",
    "DeviceDecision",
    "DeviceLike",
    "DeviceRecord",
    "DeviceRequest",
    "DeviceStatus",
    "DeviceStore",
    "GrantSummary",
    "LitestarOAuth",
    "OAuthClient",
    "OAuthConfig",
    "OAuthError",
    "Stores",
    "TokenKind",
    "TokenLike",
    "TokenRecord",
    "TokenRequest",
    "TokenResponse",
    "TokenStore",
    "VerifiedToken",
    "__version__",
    "bearer_guard",
    "format_user_code",
    "in_memory_stores",
    "normalize_user_code",
    "protected_resource_metadata_url",
    "verified_token",
]
