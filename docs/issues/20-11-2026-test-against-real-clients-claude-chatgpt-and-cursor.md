---
title: "Test the server against real clients: Claude, ChatGPT and Cursor"
status: open
scope: S
owner: null
filed: 2026-11-20
area: interop
verify: probe
blocked_by: null
fixed_in: null
---

## MEASURED

Only the in-process Litestar test client has been used. Claude callback URL, from the connectors
docs: https://claude.ai/api/mcp/auth_callback. Claude Code uses a loopback URL on any port.

## INFERRED (unverified, community reports only)

ChatGPT may skip RFC 9728 discovery and fetch the authorization server metadata directly. Cursor
needs a loopback redirect or the `mcp-remote` shim, and its redirect URI differs per install.

## Done

One deployed example server connected from Claude web, Claude Code, ChatGPT and Cursor, with the
result of each written in the docs: which discovery documents it fetched, which registration method
it used, what failed.
