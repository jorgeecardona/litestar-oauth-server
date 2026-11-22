# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.9]

### Added

- `AuthorizationServer.list_clients()` and `delete_client()`: list registered clients (newest
  first, paged) and delete one. A client store opts in with the new `ClientAdmin` protocol; a store
  without it raises `TypeError`, and existing stores keep working. The in-memory store implements
  it. Tokens already issued to a deleted client stay valid until they expire or are revoked (#2).

## [0.0.8]

### Added

- `AuthorizationServer.purge_unused_clients()` and `OAuthConfig.unused_client_ttl` (30 days):
  delete clients that no code or token refers to. A client store opts in with the new `ClientPurge`
  protocol (`delete_unused(created_before)`); a store without it raises `TypeError` on purge, and
  existing stores keep working. The in-memory store implements it (#2).

## [0.0.7]

### Changed

- The store protocols take and return `ClientLike`, `CodeLike` and `TokenLike`: any object with
  those attributes (a host's dataclass or ORM row). A host implements the three stores without a
  runtime import from this package. `OAuthClient`, `CodeRecord` and `TokenRecord` still satisfy
  them, so existing stores keep working. `scopes` may be any sequence and `kind` a plain string
  (`"access"` or `"refresh"`). `describe_client` and `validate_request` still return `OAuthClient` (#5).

## [0.0.6]

### Fixed

- `import litestar_oauth_server` no longer imports Litestar. `LitestarOAuth`, `bearer_guard`,
  `verified_token` and `protected_resource_metadata_url` load it on first use, so a package that
  holds only the database layer can import the records and stores without it. A test imports them
  with Litestar blocked (#3).

## [0.0.5]

### Added

- `OAuthConfig.register_rate_limit`: a per-address cap on `POST /oauth/register`, on by default at
  20 an hour; `None` turns it off. The count is kept in memory by each worker process (#2).

## [0.0.4]

### Added

- `OAuthConfig.cors_origins`: browser origins allowed to call the OAuth routes (`"*"` for any).
  The plugin answers the preflight and sets `Access-Control-Allow-Origin` on those routes only.
  It does nothing when the app has its own `cors_config`: Litestar's CORS middleware answers
  first, so add the origins to that list (#1).

## [0.0.3]

### Added

- `VerifiedToken.family_id`: the grant a verified token belongs to.

## [0.0.2]

### Added

- `AuthorizationServer.validate_request`: check an authorization request and return its client, so a
  consent page never shows or redirects to an unregistered `redirect_uri`.
- `AuthorizationServer.deny`: the `access_denied` redirect (RFC 6749 section 4.1.2.1) for a user who
  declines.

## [0.0.1]

### Added

- Authorization server: authorization code flow with PKCE (S256), refresh token rotation with
  reuse detection, revocation, dynamic client registration, resource indicators.
- Litestar plugin `LitestarOAuth`: RFC 8414 and RFC 9728 metadata, `/oauth/register`,
  `/oauth/token`, `/oauth/revoke`.
- `bearer_guard` and `verified_token` for protected routes, with `WWW-Authenticate` on 401.
- Per-token `binding` (tenant) and scopes the user can narrow on the consent screen.
- In-memory stores and the `ClientStore`, `CodeStore` and `TokenStore` protocols.
