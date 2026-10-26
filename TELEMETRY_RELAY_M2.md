# Milestone 2 — telemetry relay receiver prototype

A loopback-only (`127.0.0.1`) in-memory relay is now implemented as `telemetry-relay.cjs`. It provides separate authenticated publishing (`POST /v1/ingest`) and viewer (`GET /v1/snapshot`) endpoints, rejects unsupported payload fields, enforces a 256 KiB request limit, rejects old publish timestamps and immediate duplicate delivery IDs, and expires viewer snapshots after 30 seconds by default. Direct execution refuses startup. **It is not a deployed HTTPS relay, and no website user can access it remotely.**

Verified local synthetic integration tests and existing suite: 30 passing, 0 failures. The transport's read and write roles are distinct, but credentials remain static in the test-only configuration. This prototype deliberately has no live public listener.

Before any remote activation: configure a managed authenticated TLS endpoint, origin/session-based viewer authentication without embedding tokens in public JS, per-install tenant isolation, schema/field-by-field validation of nested telemetry, delivery replay persistence, encryption and retention at rest, key rotation/revocation, throttling, safe logging, and real browser-to-relay integration tests. Do not expose 7331, 7335, or 7336 to the internet.
