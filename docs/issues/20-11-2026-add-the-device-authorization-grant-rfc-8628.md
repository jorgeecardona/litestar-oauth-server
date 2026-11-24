---
title: "Add the device authorization grant (RFC 8628) for CLI and headless login"
status: closed
scope: M
owner: null
filed: 2026-11-20
area: grants
verify: test
blocked_by: null
fixed_in: 0.0.11
---

## MEASURED

crm has its own device flow (`controllers/device.py`, `rbk_` tokens, read-only GET whitelist). tyko
has `tyko login`. Each project built this alone. The same flow would fit a CLI or a headless agent
that cannot open a browser callback.

## Done

`/oauth/device_authorization` and the `urn:ietf:params:oauth:grant-type:device_code` grant on the
token endpoint, with a polling interval, `slow_down`, and a user code entered on the host app's
page. Tokens carry binding and scopes like the other grants.

## Result (2026-11-24)

Shipped in 0.0.11, GitLab #6. The device grant is opt-in for each client (`grant_types`), so a
known `client_id` of a web client cannot be used to start a device flow (RFC 8628 section 5.4).
The RFC does not say a device code is single use. Here it is: the decided record is deleted in one
step. Found on the way: `approve` (authorization code flow) does not check the approved scopes
against the scopes the client asked for. Not fixed here.
