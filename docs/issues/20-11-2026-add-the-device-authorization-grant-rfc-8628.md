---
title: "Add the device authorization grant (RFC 8628) for CLI and headless login"
status: open
scope: M
owner: null
filed: 2026-11-20
area: grants
verify: test
blocked_by: null
fixed_in: null
---

## MEASURED

crm has its own device flow (`controllers/device.py`, `rbk_` tokens, read-only GET whitelist). tyko
has `tyko login`. Each project built this alone. The same flow would fit a CLI or a headless agent
that cannot open a browser callback.

## Done

`/oauth/device_authorization` and the `urn:ietf:params:oauth:grant-type:device_code` grant on the
token endpoint, with a polling interval, `slow_down`, and a user code entered on the host app's
page. Tokens carry binding and scopes like the other grants.
