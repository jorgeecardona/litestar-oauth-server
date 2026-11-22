"""The authorization server: the rules, with no HTTP in it.

Flow (OAuth 2.1, public clients, PKCE S256 only):

1. A client registers (``register_client``, RFC 7591) or is pre-registered.
2. The client sends the user's browser to the host app's consent page (``authorization_endpoint``).
3. The host app signs the user in with its own login, shows what is asked, and calls ``approve``
   with the user's decision. ``approve`` returns the redirect URL carrying a single-use code.
4. The client calls the token endpoint; ``exchange`` checks the code, the PKCE verifier and the
   resource, and returns an access token and a refresh token.
5. The resource calls ``verify`` on each request.

Rules that carry weight:

- Codes and refresh tokens are single use, claimed atomically *before* they are validated. A code
  that fails a check stays burned.
- A refresh token used twice revokes its whole family (the chain started by one approval).
- Every token is bound to one ``resource`` (RFC 8707) and is rejected at any other.
- Only SHA-256 hashes of codes and tokens are stored.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import urlencode, urlsplit

from litestar_oauth_server.models import (
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
from litestar_oauth_server.stores import ClientPurge, Stores

CODE_CHALLENGE_METHOD = "S256"
_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")
_MAX_CLIENT_NAME = 255


def _utcnow() -> datetime:
    return datetime.now(UTC)


def hash_secret(value: str) -> str:
    """The stored form of a code or token. The values are 256-bit random, so plain SHA-256 holds."""
    return hashlib.sha256(value.encode()).hexdigest()


def pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def redirect_uri_allowed(uri: str) -> bool:
    """OAuth 2.1: an https URI, or an http loopback URI (any port, for CLI and desktop clients)."""
    parts = urlsplit(uri)
    if parts.fragment:
        return False
    if parts.scheme == "https" and parts.netloc:
        return True
    return parts.scheme == "http" and (parts.hostname or "") in _LOOPBACK_HOSTS


def _same_redirect(registered: str, presented: str) -> bool:
    """Exact match, except that a loopback URI may differ in port (RFC 8252 section 7.3)."""
    if registered == presented:
        return True
    a, b = urlsplit(registered), urlsplit(presented)
    if a.scheme != "http" or b.scheme != "http":
        return False
    return (
        (a.hostname or "") in _LOOPBACK_HOSTS
        and a.hostname == b.hostname
        and a.path == b.path
        and a.query == b.query
    )


def normalize_resource(resource: str) -> str:
    return resource.rstrip("/")


@dataclass(frozen=True, slots=True)
class OAuthConfig:
    """Everything the server needs to know about the host app.

    ``resources`` lists the canonical URIs of the APIs that accept our tokens, for example
    ``("https://api.example.com/mcp",)``. ``authorization_endpoint`` is the host app's consent page.

    ``cors_origins`` lists the browser origins allowed to call the OAuth routes (``"*"`` allows
    any). Empty means no CORS headers. It applies only when the app has no ``cors_config`` of its
    own: Litestar's CORS middleware answers first, so the app's list decides (#1).

    ``register_rate_limit`` caps ``POST /oauth/register`` per client address, as ``(unit, count)``
    such as ``("hour", 20)``; ``None`` turns it off (#2). The count is kept in memory by each worker
    process. Behind a proxy the address is the proxy's unless the server reads the forwarded
    headers (for uvicorn, ``--proxy-headers`` with ``--forwarded-allow-ips``).

    ``unused_client_ttl`` is how old a client must be before ``purge_unused_clients`` may delete it
    when no code or token ever referred to it (#2).
    """

    issuer: str
    authorization_endpoint: str
    resources: tuple[str, ...]
    scopes_supported: tuple[str, ...]
    resource_name: str = ""
    code_ttl: timedelta = timedelta(minutes=5)
    access_token_ttl: timedelta = timedelta(hours=1)
    refresh_token_ttl: timedelta = timedelta(days=30)
    registration_enabled: bool = True
    unused_client_ttl: timedelta = timedelta(days=30)
    cors_origins: tuple[str, ...] = ()
    register_rate_limit: tuple[Literal["second", "minute", "hour", "day"], int] | None = (
        "hour",
        20,
    )

    def __post_init__(self) -> None:
        if not self.resources:
            raise ValueError("OAuthConfig.resources must list at least one resource")
        if not self.scopes_supported:
            raise ValueError("OAuthConfig.scopes_supported must list at least one scope")
        if self.register_rate_limit is not None and self.register_rate_limit[1] < 1:
            raise ValueError("OAuthConfig.register_rate_limit count must be at least 1")


@dataclass(frozen=True, slots=True)
class _Grant:
    """What one approval allows; the data every token of a family shares."""

    family_id: str
    client_id: str
    subject: str
    binding: str
    scopes: tuple[str, ...]
    resource: str


@dataclass(frozen=True, slots=True)
class AuthorizationServer:
    config: OAuthConfig
    stores: Stores
    now: Callable[[], datetime] = field(default=_utcnow)

    # -- registration -------------------------------------------------------------------------

    async def register_client(
        self, *, client_name: str, redirect_uris: tuple[str, ...]
    ) -> OAuthClient:
        if not self.config.registration_enabled:
            raise OAuthError("access_denied", "dynamic client registration is disabled", 403)
        return await self.add_client(client_name=client_name, redirect_uris=redirect_uris)

    async def purge_unused_clients(self, older_than: timedelta | None = None) -> int:
        """Delete clients older than ``older_than`` that no code or token refers to (#2).

        ``older_than`` defaults to ``config.unused_client_ttl``. Returns how many were deleted. The
        library has no scheduler: call this from your own periodic job. Raises ``TypeError`` when
        the client store does not implement ``ClientPurge``.
        """
        clients = self.stores.clients
        if not isinstance(clients, ClientPurge):
            raise TypeError(
                f"{type(clients).__name__} has no delete_unused(); implement ClientPurge to purge"
            )
        age = older_than if older_than is not None else self.config.unused_client_ttl
        return await clients.delete_unused(self.now() - age)

    async def add_client(
        self, *, client_name: str, redirect_uris: tuple[str, ...], client_id: str = ""
    ) -> OAuthClient:
        """Register a client. Also the way to pre-register one with a fixed ``client_id``."""
        if not redirect_uris:
            raise OAuthError("invalid_redirect_uri", "redirect_uris is required")
        for uri in redirect_uris:
            if not redirect_uri_allowed(uri):
                raise OAuthError(
                    "invalid_redirect_uri", f"redirect_uri {uri!r} must be https or loopback http"
                )
        client = OAuthClient(
            client_id=client_id or "oc_" + secrets.token_urlsafe(24),
            client_name=client_name[:_MAX_CLIENT_NAME],
            redirect_uris=redirect_uris,
            created_at=self.now(),
        )
        await self.stores.clients.add(client)
        return client

    # -- resource and scope rules -------------------------------------------------------------

    def resolve_resource(self, resource: str) -> str:
        """The canonical resource for a request. An empty value is allowed with one resource."""
        allowed = tuple(normalize_resource(r) for r in self.config.resources)
        if not resource:
            if len(allowed) == 1:
                return allowed[0]
            raise OAuthError("invalid_target", "resource is required")
        wanted = normalize_resource(resource)
        if wanted not in allowed:
            raise OAuthError("invalid_target", "unknown resource")
        return wanted

    def _check_scopes(self, scopes: tuple[str, ...]) -> tuple[str, ...]:
        if not scopes:
            raise OAuthError("invalid_scope", "at least one scope must be approved")
        unknown = [s for s in scopes if s not in self.config.scopes_supported]
        if unknown:
            raise OAuthError("invalid_scope", f"unknown scope: {unknown[0]}")
        return tuple(dict.fromkeys(scopes))

    # -- authorization (called by the host app's consent endpoint) ----------------------------

    async def describe_client(self, client_id: str) -> OAuthClient:
        client = await self.stores.clients.get(client_id)
        if client is None:
            raise OAuthError("invalid_client", "unknown client_id", 404)
        return OAuthClient.of(client)

    async def validate_request(self, request: AuthorizationRequest) -> OAuthClient:
        """Check an authorization request and return its client.

        The consent page calls this before it shows anything, so it never shows (or redirects
        to) a request with an unregistered ``redirect_uri``. ``approve`` and ``deny`` call it too.
        """
        client = await self.stores.clients.get(request.client_id)
        if client is None:
            raise OAuthError("invalid_client", "unknown client_id; the client must register first")
        if not any(_same_redirect(r, request.redirect_uri) for r in client.redirect_uris):
            raise OAuthError("invalid_request", "redirect_uri is not registered for this client")
        if not request.code_challenge:
            raise OAuthError("invalid_request", "code_challenge is required (PKCE)")
        if request.code_challenge_method != CODE_CHALLENGE_METHOD:
            raise OAuthError("invalid_request", "only the S256 code_challenge_method is supported")
        self.resolve_resource(request.resource)
        return OAuthClient.of(client)

    async def deny(self, request: AuthorizationRequest) -> str:
        """The redirect URL that tells the client the user said no (RFC 6749 section 4.1.2.1)."""
        await self.validate_request(request)
        query = {"error": "access_denied"}
        if request.state:
            query["state"] = request.state
        separator = "&" if urlsplit(request.redirect_uri).query else "?"
        return f"{request.redirect_uri}{separator}{urlencode(query)}"

    async def approve(self, request: AuthorizationRequest, approval: Approval) -> str:
        """Mint a single-use code for an approved request and return the redirect URL.

        The caller has already authenticated the user and decided ``approval.binding`` (and
        checked that the user may grant it). This validates the OAuth side.
        """
        await self.validate_request(request)
        resource = self.resolve_resource(request.resource)
        scopes = self._check_scopes(approval.scopes)
        plaintext = secrets.token_urlsafe(32)
        await self.stores.codes.add(
            CodeRecord(
                code_hash=hash_secret(plaintext),
                client_id=request.client_id,
                redirect_uri=request.redirect_uri,
                code_challenge=request.code_challenge,
                subject=approval.subject,
                binding=approval.binding,
                scopes=scopes,
                resource=resource,
                expires_at=self.now() + self.config.code_ttl,
            )
        )
        query = {"code": plaintext}
        if request.state:
            query["state"] = request.state
        separator = "&" if urlsplit(request.redirect_uri).query else "?"
        return f"{request.redirect_uri}{separator}{urlencode(query)}"

    # -- token endpoint -----------------------------------------------------------------------

    async def exchange(self, request: TokenRequest) -> TokenResponse:
        if request.grant_type == "authorization_code":
            return await self._exchange_code(request)
        if request.grant_type == "refresh_token":
            return await self._exchange_refresh(request)
        raise OAuthError("unsupported_grant_type", "use authorization_code or refresh_token")

    async def _exchange_code(self, request: TokenRequest) -> TokenResponse:
        if not request.code or not request.code_verifier or not request.client_id:
            raise OAuthError("invalid_request", "code, code_verifier and client_id are required")
        # Claim first, validate after: a code that fails any check below stays burned.
        record = await self.stores.codes.consume(hash_secret(request.code))
        if record is None or record.expires_at < self.now():
            raise OAuthError("invalid_grant", "unknown, expired or already used code")
        if record.client_id != request.client_id or record.redirect_uri != request.redirect_uri:
            raise OAuthError("invalid_grant", "code was issued to a different client")
        challenge = pkce_challenge(request.code_verifier)
        if not hmac.compare_digest(challenge, record.code_challenge):
            raise OAuthError("invalid_grant", "PKCE verification failed")
        if request.resource and self.resolve_resource(request.resource) != record.resource:
            raise OAuthError("invalid_target", "resource differs from the authorized one")
        return await self._issue(
            _Grant(
                family_id=secrets.token_urlsafe(16),
                client_id=record.client_id,
                subject=record.subject,
                binding=record.binding,
                scopes=tuple(record.scopes),
                resource=record.resource,
            )
        )

    async def _exchange_refresh(self, request: TokenRequest) -> TokenResponse:
        if not request.refresh_token or not request.client_id:
            raise OAuthError("invalid_request", "refresh_token and client_id are required")
        now = self.now()
        token_hash = hash_secret(request.refresh_token)
        record = await self.stores.tokens.consume_refresh(token_hash, now)
        if record is None:
            seen = await self.stores.tokens.get(token_hash)
            if seen is not None and seen.kind == TokenKind.REFRESH and seen.used_at is not None:
                # A rotated token came back: assume theft, end the whole chain.
                await self.stores.tokens.revoke_family(seen.family_id, now)
            raise OAuthError("invalid_grant", "unknown, expired, revoked or already used token")
        if record.revoked_at is not None or record.expires_at < now:
            raise OAuthError("invalid_grant", "unknown, expired, revoked or already used token")
        if record.client_id != request.client_id:
            raise OAuthError("invalid_grant", "token was issued to a different client")
        if request.resource and self.resolve_resource(request.resource) != record.resource:
            raise OAuthError("invalid_target", "resource differs from the authorized one")
        return await self._issue(
            _Grant(
                family_id=record.family_id,
                client_id=record.client_id,
                subject=record.subject,
                binding=record.binding,
                scopes=tuple(record.scopes),
                resource=record.resource,
            )
        )

    async def _issue(self, grant: _Grant) -> TokenResponse:
        now = self.now()
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        for kind, plaintext, ttl in (
            (TokenKind.ACCESS, access, self.config.access_token_ttl),
            (TokenKind.REFRESH, refresh, self.config.refresh_token_ttl),
        ):
            await self.stores.tokens.add(
                TokenRecord(
                    token_hash=hash_secret(plaintext),
                    kind=kind,
                    family_id=grant.family_id,
                    client_id=grant.client_id,
                    subject=grant.subject,
                    binding=grant.binding,
                    scopes=grant.scopes,
                    resource=grant.resource,
                    created_at=now,
                    expires_at=now + ttl,
                )
            )
        return TokenResponse(
            access_token=access,
            token_type="Bearer",  # noqa: S106 (the RFC 6749 token type, not a secret)
            expires_in=int(self.config.access_token_ttl.total_seconds()),
            scope=" ".join(grant.scopes),
            refresh_token=refresh,
        )

    # -- resource side ------------------------------------------------------------------------

    async def verify(self, token: str, resource: str) -> VerifiedToken | None:
        """Check a bearer token for ``resource``. ``None`` means reject with 401."""
        record = await self.stores.tokens.get(hash_secret(token))
        if record is None or record.kind != TokenKind.ACCESS:
            return None
        if record.revoked_at is not None or record.expires_at < self.now():
            return None
        if record.resource != normalize_resource(resource):
            return None
        return VerifiedToken(
            subject=record.subject,
            binding=record.binding,
            scopes=tuple(record.scopes),
            client_id=record.client_id,
            family_id=record.family_id,
            resource=record.resource,
            expires_at=record.expires_at,
        )

    # -- revocation and the "connected apps" page ---------------------------------------------

    async def revoke(self, token: str) -> None:
        """RFC 7009. Always succeeds; an unknown token is not an error. Revokes the family."""
        record = await self.stores.tokens.get(hash_secret(token))
        if record is not None:
            await self.stores.tokens.revoke_family(record.family_id, self.now())

    async def revoke_family(self, family_id: str) -> None:
        await self.stores.tokens.revoke_family(family_id, self.now())

    async def list_grants(self, subject: str) -> tuple[GrantSummary, ...]:
        now = self.now()
        out: list[GrantSummary] = []
        for record in await self.stores.tokens.list_for_subject(subject):
            if record.expires_at < now:
                continue
            client = await self.stores.clients.get(record.client_id)
            out.append(
                GrantSummary(
                    family_id=record.family_id,
                    client_id=record.client_id,
                    client_name=client.client_name if client is not None else record.client_id,
                    binding=record.binding,
                    scopes=tuple(record.scopes),
                    resource=record.resource,
                    created_at=record.created_at,
                )
            )
        return tuple(out)
