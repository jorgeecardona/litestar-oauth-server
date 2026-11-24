# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.11]

### Added

- The device authorization grant (RFC 8628) for CLI and headless login (#6). Set
  `OAuthConfig(device_verification_uri=...)`. New: `POST /oauth/device_authorization`, the device
  grant on the token endpoint (`authorization_pending`, `slow_down`, `access_denied`,
  `expired_token`), the metadata field `device_authorization_endpoint`, and on the server
  `start_device_authorization`, `describe_device`, `approve_device`, `deny_device` and
  `purge_expired_devices`.
- New store protocol `DeviceStore` and `Stores.devices` (optional; keyword only). The in-memory and
  SQL stores have it, and the contract suite tests it.
- A client has `grant_types`. The device grant is only for a client that has
  `urn:ietf:params:oauth:grant-type:device_code`, so nobody can start a device flow under the name
  of a client that did not ask for it. Dynamic registration reads and echoes `grant_types`. A client
  without `authorization_code` needs no `redirect_uris`.
- `ClientLike` has `grant_types`. A store that does not keep it gives the default (no device grant).

### Changed

- SQL stores: new table `{prefix}devices` and a column `grant_types` on `{prefix}clients`. Add them
  with your own migration. `SqlStores.delete_expired` also deletes expired device authorizations,
  and `purge_unused_clients` counts a pending device as a use.

## [0.0.10]

### Added

- Extra `sqlalchemy`: `oauth_tables(metadata)` and `sql_stores(engine, tables)` in
  `litestar_oauth_server.sqlalchemy`. Stores on Postgres, with the tables on your own `MetaData`.
  Each method commits in its own transaction. `consume` and `consume_refresh` are one statement
  each, tested with concurrent exchanges on a real Postgres. `SqlStores.delete_expired(now)`
  deletes expired codes and tokens. Only Postgres is supported (#7).
- `litestar_oauth_server.testing.CASES`: a contract test suite for any store, without pytest. It
  runs on the in-memory stores, on the plain stores of the tests and on the SQL stores (#7).

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
