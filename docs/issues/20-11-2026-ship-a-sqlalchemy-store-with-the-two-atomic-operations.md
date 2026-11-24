---
title: "Ship a SQLAlchemy store with the two atomic operations"
status: closed
scope: M
owner: null
filed: 2026-11-20
area: stores
verify: test
blocked_by: null
fixed_in: 0.0.10
---

## MEASURED

Only in-memory stores exist. Every host app has to implement `ClientStore`, `CodeStore` and
`TokenStore`, and the security of the server depends on `CodeStore.consume` and
`TokenStore.consume_refresh` being atomic. paas already has a compare-and-set `consume` for codes
(`OAuthCodesRepository.consume`), written after a musil model showed that read-then-mark double mints.

## Done

An optional extra `litestar-oauth-server[sqlalchemy]` with tables and stores where each consume is one
`UPDATE ... WHERE used_at IS NULL RETURNING` or `DELETE ... RETURNING`. A test fires two concurrent
exchanges of one code against Postgres and asserts that exactly one succeeds.

## Related

A store contract test suite that host apps can run against their own stores (same cases, any store).

## Result (2026-11-24)

Shipped in 0.0.10, GitLab #7. Postgres only: an untested SQLite path on the security operations is
worse than none. The store contract suite from "Related" shipped with it (`litestar_oauth_server.testing`).
Found on the way and filed as #11: a refresh replay during a rotation can leave live tokens in a
revoked family.
