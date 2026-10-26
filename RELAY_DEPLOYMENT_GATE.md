# Atlas remote telemetry: deployment gate

Status: not deployed. The only GitHub Actions workflow publishes the static `public/` website; it does not host Node.js services. The relay prototype explicitly refuses direct startup and is intended for loopback operation behind an independently authenticated HTTPS edge. No host URL or viewer identity provider is configured in this repository.

## Required before production wiring

1. Select an authenticated private HTTPS hosting service and pin the expected service origin.
2. Establish independent short-lived viewer authorization. A public website must never contain publisher or viewer bearer credentials.
3. Add per-install tenant isolation, durable delivery deduplication, rate limiting, and retention controls at the receiving service.
4. Test a complete outbound desktop-to-relay and authorized viewer-to-relay path using real TLS certificates and real identity sessions.
5. Enable the website's remote fetch path only after successful authorization and negative tests; leave local telemetry fallback unchanged.

Validation checkpoint: existing 35 Atlas tests pass. No remote credentials configured, no ports exposed, no real network handoff verified. The host-side write attempt for an additional roundtrip test was blocked and no untested test change was committed.
