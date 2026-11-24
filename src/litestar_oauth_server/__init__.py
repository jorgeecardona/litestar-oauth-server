"""An OAuth 2.1 authorization server plugin for Litestar.

Importing the package does not import Litestar. The models, the stores and ``AuthorizationServer``
are plain Python, so a package that only holds the database layer can use them without the web
framework. The Litestar names (``LitestarOAuth``, ``bearer_guard``, ``verified_token``,
``protected_resource_metadata_url``) load on first use (#3).
"""

from importlib import import_module
from typing import TYPE_CHECKING

from litestar_oauth_server.models import (
    Approval,
    AuthorizationRequest,
    ClientLike,
    CodeLike,
    CodeRecord,
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
from litestar_oauth_server.server import AuthorizationServer, OAuthConfig
from litestar_oauth_server.stores import (
    ClientAdmin,
    ClientPurge,
    ClientStore,
    CodeStore,
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


__version__ = "0.0.10"  # the single source of truth; pyproject reads it via [tool.hatch.version]

__all__ = [
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
    "in_memory_stores",
    "protected_resource_metadata_url",
    "verified_token",
]
