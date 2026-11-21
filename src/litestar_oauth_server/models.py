"""The data model: every value that crosses the library is a frozen dataclass.

Nothing here knows about Litestar or about a database. The stores in ``stores.py`` persist
these records; the server in ``server.py`` creates and checks them.

Vocabulary:

- **subject**: the signed-in user who approved the client (the host app's user id, as a string).
- **binding**: the tenant the token is pinned to, chosen on the consent screen and opaque to
  this library (for example ``"company:7f3a..."``). A token never crosses its binding; the host
  app reads it from the verified token and applies it.
- **resource**: the canonical URI of the API the token is for (RFC 8707). A token is only valid
  at its own resource.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class TokenKind(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"


@dataclass(frozen=True, slots=True)
class OAuthClient:
    """A registered public client (no secret; PKCE is the proof of possession)."""

    client_id: str
    client_name: str
    redirect_uris: tuple[str, ...]
    created_at: datetime


@dataclass(frozen=True, slots=True)
class AuthorizationRequest:
    """What the client sent to the authorization endpoint, as the consent page forwards it."""

    client_id: str
    redirect_uri: str
    code_challenge: str
    code_challenge_method: str
    state: str = ""
    resource: str = ""
    scope: str = ""


@dataclass(frozen=True, slots=True)
class Approval:
    """The user's decision on the consent screen.

    ``scopes`` is what the user agreed to; it may be narrower than what the client asked for.
    """

    subject: str
    scopes: tuple[str, ...]
    binding: str = ""


@dataclass(frozen=True, slots=True)
class CodeRecord:
    """A single-use authorization code, stored by hash."""

    code_hash: str
    client_id: str
    redirect_uri: str
    code_challenge: str
    subject: str
    binding: str
    scopes: tuple[str, ...]
    resource: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class TokenRecord:
    """An access or refresh token, stored by hash. ``family_id`` ties a refresh chain together."""

    token_hash: str
    kind: TokenKind
    family_id: str
    client_id: str
    subject: str
    binding: str
    scopes: tuple[str, ...]
    resource: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None = None
    revoked_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class VerifiedToken:
    """The result of checking a bearer token at a resource.

    ``family_id`` names the grant the token belongs to (the same id ``list_grants`` and
    ``revoke_family`` use), so a host can tie what it creates to one connected app.
    """

    subject: str
    binding: str
    scopes: tuple[str, ...]
    client_id: str
    family_id: str
    resource: str
    expires_at: datetime

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


@dataclass(frozen=True, slots=True)
class TokenRequest:
    """The form fields of a token endpoint request (RFC 6749 section 4.1.3 and 6)."""

    grant_type: str = ""
    code: str = ""
    redirect_uri: str = ""
    client_id: str = ""
    code_verifier: str = ""
    resource: str = ""
    refresh_token: str = ""


@dataclass(frozen=True, slots=True)
class TokenResponse:
    """The token endpoint success body (RFC 6749 section 5.1), snake_case on the wire."""

    access_token: str
    token_type: str
    expires_in: int
    scope: str
    refresh_token: str


@dataclass(frozen=True, slots=True)
class GrantSummary:
    """One connected client, for a "connected apps" page where the user can revoke access."""

    family_id: str
    client_id: str
    client_name: str
    binding: str
    scopes: tuple[str, ...]
    resource: str
    created_at: datetime


class OAuthError(Exception):
    """An RFC 6749 error: ``error`` is a registry value such as ``invalid_grant``."""

    def __init__(self, error: str, description: str, status: int = 400) -> None:
        super().__init__(f"{error}: {description}")
        self.error = error
        self.description = description
        self.status = status
