# Atlas Owner Gateway — Security milestone 2026-10-25

- Gateway standalone startup now fails closed until its BuildWise owner-session binding is configured and reviewed. No production command service is running as a result of this change.
- Request IDs have a five-minute in-memory replay window and a bounded 10,000 entry cache. Duplicate IDs are rejected with HTTP 409 and an audit record. This is NOT durable replay protection across restarts or a distributed relay.
- Authorization tests remain synthetic. They do not prove owner identity, credential vault readiness, remote browser access, session expiry, or permission to perform privileged BuildWise operations.
- Only the prototype health.check action exists in the allowlist; cancel/retry/deploy and other privileged operations remain disabled.
- Full suite: node --test tests/*.test.cjs: 13 passing; no failures.

Before enabling owner control, bind the gateway to BuildWise's authoritative owner approval and use independent short-lived credentials; enforce per-action policies, CSRF and replay protection across restarts, encrypted transport, and durable audit storage. Do not expose a BuildWise factory token to public browser JavaScript.
