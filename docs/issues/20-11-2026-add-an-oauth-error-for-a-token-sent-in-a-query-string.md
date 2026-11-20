---
title: "Reject access tokens sent in the query string with a clear error"
status: open
scope: XS
owner: null
filed: 2026-11-20
area: guard
verify: test
blocked_by: null
fixed_in: null
---

## MEASURED

The spec says tokens MUST NOT appear in the query string. `bearer_guard` reads only the
`Authorization` header, so such a request gets the generic 401 "bearer token required".

## Done

Decide whether a distinct error message helps clients; if so, test it. Low priority.
