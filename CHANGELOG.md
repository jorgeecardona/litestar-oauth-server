# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
