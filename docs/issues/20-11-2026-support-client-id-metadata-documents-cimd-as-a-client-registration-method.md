---
title: "Support Client ID Metadata Documents (CIMD) as a client registration method"
status: open
scope: M
owner: null
filed: 2026-11-20
area: registration
verify: test
blocked_by: null
fixed_in: null
---

## MEASURED

The MCP authorization spec (2025-11-25) lists Client ID Metadata Documents as a SHOULD and Dynamic
Client Registration as a MAY, kept for backward compatibility. Source:
https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization. Claude Code publishes
its client metadata at https://claude.ai/oauth/claude-code-client-metadata.
Version 0.0.1 supports only Dynamic Client Registration and pre-registered clients.

## INFERRED

Newer clients will prefer CIMD, so a server without it works only through the fallback.

## Done

A `client_id` that is an https URL is fetched, validated (the `client_id` field equals the URL,
redirect URIs pass `redirect_uri_allowed`), cached with a time limit, and the metadata advertises
`client_id_metadata_document_supported: true`. Tests include a fetch of a private IP address, which
must be refused (SSRF), and a redirect to another host, which must be refused.

## Not done on purpose

The fetch is not in 0.0.1 because an unsafe fetch is worse than no fetch.
