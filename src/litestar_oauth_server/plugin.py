"""The Litestar side: endpoints, metadata documents and the bearer guard.

``LitestarOAuth(server)`` adds, with snake_case JSON as the RFCs define it:

- ``GET  /.well-known/oauth-authorization-server``  (RFC 8414)
- ``GET  /.well-known/oauth-protected-resource[/path]``  (RFC 9728), one per configured resource
- ``POST /oauth/register``  (RFC 7591), unless registration is disabled
- ``POST /oauth/token``  (RFC 6749, authorization_code and refresh_token)
- ``POST /oauth/revoke``  (RFC 7009)

The consent page and its approve endpoint stay in the host app, because the host owns the login.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlsplit

import msgspec
from litestar import Request, Response, get, post
from litestar.exceptions import NotAuthorizedException
from litestar.plugins import InitPluginProtocol

from litestar_oauth_server.models import OAuthError, TokenRequest, VerifiedToken
from litestar_oauth_server.server import AuthorizationServer, OAuthConfig, normalize_resource

if TYPE_CHECKING:
    from litestar.config.app import AppConfig
    from litestar.connection import ASGIConnection
    from litestar.handlers import HTTPRouteHandler
    from litestar.handlers.base import BaseRouteHandler

type BearerGuard = Callable[[ASGIConnection[Any, Any, Any, Any], BaseRouteHandler], Awaitable[None]]
"""A Litestar guard function; pass it in ``guards=[...]``."""

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_STATE_KEY = "litestar_oauth_server_token"


@dataclass(frozen=True, slots=True)
class AuthorizationServerMetadata:
    """RFC 8414 section 2, the subset a client needs."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    revocation_endpoint: str
    response_types_supported: tuple[str, ...]
    grant_types_supported: tuple[str, ...]
    code_challenge_methods_supported: tuple[str, ...]
    token_endpoint_auth_methods_supported: tuple[str, ...]
    scopes_supported: tuple[str, ...]
    registration_endpoint: str | None = None


@dataclass(frozen=True, slots=True)
class ProtectedResourceMetadata:
    """RFC 9728 section 2."""

    resource: str
    authorization_servers: tuple[str, ...]
    scopes_supported: tuple[str, ...]
    bearer_methods_supported: tuple[str, ...]
    resource_name: str


@dataclass(frozen=True, slots=True)
class RegisterResponse:
    client_id: str
    client_name: str
    redirect_uris: tuple[str, ...]
    grant_types: tuple[str, ...]
    response_types: tuple[str, ...]
    token_endpoint_auth_method: str


@dataclass(frozen=True, slots=True)
class OAuthErrorBody:
    error: str
    error_description: str


class _RegisterRequest(msgspec.Struct, kw_only=True):
    """Unknown members are ignored: clients send many."""

    redirect_uris: tuple[str, ...] = ()
    client_name: str = ""


def protected_resource_metadata_url(resource: str) -> str:
    """RFC 9728 section 3: insert the well-known segment between the host and the path."""
    parts = urlsplit(normalize_resource(resource))
    path = parts.path
    return f"{parts.scheme}://{parts.netloc}/.well-known/oauth-protected-resource{path}"


def _error_response(error: OAuthError) -> Response[OAuthErrorBody]:
    return Response(
        OAuthErrorBody(error=error.error, error_description=error.description),
        status_code=error.status,
        media_type="application/json",
        headers=_NO_STORE,
    )


def _first(form: dict[str, list[str]], key: str) -> str:
    values = form.get(key, [])
    return values[0] if values else ""


def _protected_resource_handler(config: OAuthConfig, resource: str) -> HTTPRouteHandler:
    path = urlsplit(protected_resource_metadata_url(resource)).path

    @get(path, sync_to_thread=False, tags=["oauth"], name=f"oauth_protected_resource:{path}")
    def handler() -> ProtectedResourceMetadata:
        return ProtectedResourceMetadata(
            resource=normalize_resource(resource),
            authorization_servers=(config.issuer,),
            scopes_supported=config.scopes_supported,
            bearer_methods_supported=("header",),
            resource_name=config.resource_name,
        )

    return handler


def build_route_handlers(server: AuthorizationServer) -> list[HTTPRouteHandler]:
    """The OAuth route handlers for ``server``. ``LitestarOAuth`` registers them."""
    config = server.config
    issuer = config.issuer.rstrip("/")

    @get("/.well-known/oauth-authorization-server", sync_to_thread=False, tags=["oauth"])
    def authorization_server_metadata() -> AuthorizationServerMetadata:
        return AuthorizationServerMetadata(
            issuer=config.issuer,
            authorization_endpoint=config.authorization_endpoint,
            token_endpoint=f"{issuer}/oauth/token",
            revocation_endpoint=f"{issuer}/oauth/revoke",
            registration_endpoint=f"{issuer}/oauth/register"
            if config.registration_enabled
            else None,
            response_types_supported=("code",),
            grant_types_supported=("authorization_code", "refresh_token"),
            code_challenge_methods_supported=("S256",),
            token_endpoint_auth_methods_supported=("none",),
            scopes_supported=config.scopes_supported,
        )

    @post("/oauth/register", status_code=201, tags=["oauth"])
    async def register(request: Request[Any, Any, Any]) -> Response[Any]:
        try:
            body = msgspec.json.decode(await request.body(), type=_RegisterRequest)
        except msgspec.DecodeError as exc:
            return _error_response(
                OAuthError("invalid_client_metadata", f"malformed request: {exc}")
            )
        try:
            client = await server.register_client(
                client_name=body.client_name, redirect_uris=body.redirect_uris
            )
        except OAuthError as exc:
            return _error_response(exc)
        return Response(
            RegisterResponse(
                client_id=client.client_id,
                client_name=client.client_name,
                redirect_uris=client.redirect_uris,
                grant_types=("authorization_code", "refresh_token"),
                response_types=("code",),
                token_endpoint_auth_method="none",  # noqa: S106 (RFC 7591 value, not a secret)
            ),
            status_code=201,
            media_type="application/json",
            headers=_NO_STORE,
        )

    @post("/oauth/token", status_code=200, tags=["oauth"])
    async def token(request: Request[Any, Any, Any]) -> Response[Any]:
        # RFC 6749 section 4.1.3: urlencoded. Parsed by hand so every failure is an OAuth error
        # object and never a framework validation page.
        form = parse_qs((await request.body()).decode(errors="replace"))
        token_request = TokenRequest(
            grant_type=_first(form, "grant_type"),
            code=_first(form, "code"),
            redirect_uri=_first(form, "redirect_uri"),
            client_id=_first(form, "client_id"),
            code_verifier=_first(form, "code_verifier"),
            resource=_first(form, "resource"),
            refresh_token=_first(form, "refresh_token"),
        )
        try:
            issued = await server.exchange(token_request)
        except OAuthError as exc:
            return _error_response(exc)
        return Response(issued, status_code=200, media_type="application/json", headers=_NO_STORE)

    @post("/oauth/revoke", status_code=200, tags=["oauth"])
    async def revoke(request: Request[Any, Any, Any]) -> Response[None]:
        form = parse_qs((await request.body()).decode(errors="replace"))
        value = _first(form, "token")
        if value:
            await server.revoke(value)
        return Response(None, status_code=200, headers=_NO_STORE)

    handlers: list[HTTPRouteHandler] = [authorization_server_metadata, token, revoke]
    if config.registration_enabled:
        handlers.append(register)
    handlers.extend(_protected_resource_handler(config, r) for r in config.resources)
    return handlers


@dataclass(eq=False, slots=True)
class LitestarOAuth(InitPluginProtocol):
    """Add the OAuth endpoints to a Litestar app. Hashable by identity, as Litestar requires."""

    server: AuthorizationServer

    def on_app_init(self, app_config: AppConfig) -> AppConfig:
        app_config.route_handlers.extend(build_route_handlers(self.server))
        return app_config


def bearer_guard(server: AuthorizationServer, resource: str, *, scope: str = "") -> BearerGuard:
    """A Litestar guard for routes served at ``resource``.

    Rejects with 401 and ``WWW-Authenticate: Bearer resource_metadata=...`` (RFC 9728) when the
    token is missing, wrong, expired or for another resource. Rejects with 403 when ``scope`` is
    given and the token lacks it. On success the ``VerifiedToken`` is available through
    ``verified_token(connection)``.
    """
    metadata_url = protected_resource_metadata_url(resource)

    async def guard(
        connection: ASGIConnection[Any, Any, Any, Any], _handler: BaseRouteHandler
    ) -> None:
        header = connection.headers.get("authorization", "")
        scheme, _, value = header.partition(" ")
        challenge = f'Bearer resource_metadata="{metadata_url}"'
        if scheme.lower() != "bearer" or not value.strip():
            raise NotAuthorizedException(
                detail="bearer token required", headers={"WWW-Authenticate": challenge}
            )
        verified = await server.verify(value.strip(), resource)
        if verified is None:
            raise NotAuthorizedException(
                detail="invalid token",
                headers={"WWW-Authenticate": f'{challenge}, error="invalid_token"'},
            )
        if scope and not verified.has_scope(scope):
            raise NotAuthorizedException(
                detail="insufficient scope",
                status_code=403,
                headers={"WWW-Authenticate": f'{challenge}, error="insufficient_scope"'},
            )
        connection.scope["state"][_STATE_KEY] = verified

    return guard


def verified_token(connection: ASGIConnection[Any, Any, Any, Any]) -> VerifiedToken:
    """The token ``bearer_guard`` verified for this request."""
    found = connection.scope["state"].get(_STATE_KEY)
    if not isinstance(found, VerifiedToken):
        raise TypeError("verified_token() called on a route without bearer_guard")
    return found
