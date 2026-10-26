# Milestone 2 — outbound read-only telemetry publisher

Status: **transport component tested; remote relay and remote viewer authentication not deployed.**

The existing `atlas-bridge.cjs` exports its sanitized snapshot builder without binding a network listener when imported; its CLI behavior remains the same (127.0.0.1:7335). `telemetry-publisher.cjs` is an opt-in library with injected HTTPS relay URL and separate high-entropy publishing credential. It only POSTs an allowlist of snapshot fields, rejects redirects and HTTP, bounds payload size, and fails closed on delivery errors. It does not export owner credential state, factory tokens, or raw dispatcher job objects. No relay URL or secret is configured or committed. It does not auto-run.

Tests: `node --test tests/*.test.cjs`: 28 passed, zero failed. Tests mock delivery; no live remote relay handshake was completed.

Production dependencies: deploy a private authenticated relay with ingestion and read authorization, retention limits, per-install identity, rotated credentials, rate limiting and encrypted-at-rest telemetry; validate viewer entitlements independent from writer credentials; add outbound scheduler/retries/backoff and diagnostic telemetry; test real TLS/network/browser behavior; inspect redaction against real job data before any remote publication. Do not expose local BuildWise API ports or use factory/owner approval secrets as the publishing credential.
