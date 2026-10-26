# Atlas Owner Command Gateway — Milestone 1

The public GitHub Pages interface remains **read-only**. `owner-gateway.cjs` is a separate, loopback-bound prototype for *authorized health checks only*. It is not deployed to GitHub Pages or exposed publicly. Never bind the control port to a public network interface.

## Security model
- No owner token or API key in repository, HTML, screenshot, snapshot, audit entry or URL.
- If `ATLAS_OWNER_TOKEN` is missing or shorter than 32 characters, the service refuses to start.
- Exact allowed browser Origin: `https://prowumpus54.github.io`. Note: Origin/CORS is **not authentication**; authorization relies on bearer secret verified server-side. The future production relay requires a hardened owner session.
- Explicit command allowlist: `health.check`, GET only to local `/api/health`. No shell, arbitrary paths, cancellation, retry, deployments, or vault operations.
- Per-request ID, bounded payload and append-only JSONL evidence in the ignored runtime directory.
- Local request handling is limited to port 7336 bound to 127.0.0.1 and a 3-second upstream read timeout.
- Operator must protect bearer credentials; do **not** paste secrets into the public web app. No control UI is enabled.
- Browser-based commands from a public HTTPS origin to loopback HTTP may be restricted by browser private-network policies. **No remote/browser production control is claimed.**

## Start only after secure operator configuration
Set the environment variable `ATLAS_OWNER_TOKEN` to a high-entropy random secret through an authorized local secure configuration mechanism, then start `node owner-gateway.cjs`. Do not write the secret to this repository.

## Validation
`node --test tests/owner-gateway.test.cjs`: 6 passing tests on 2026-10-25. These are unit/integration tests with a mocked BuildWise upstream, **not** a production authorization test.

## Next production gates
1. Integrate with BuildWise's authoritative owner approval and session mechanism; don't create a competing credential authority.
2. Restrict owner commands to a private authenticated relay with TLS, session expiry, replay protection, CSRF defenses and authorization per job.
3. Persist durable structured audit trails with retention, quotas and correlation to BuildWise event IDs.
4. Implement first-run owner pairing and confirmation, and test restart/revocation/failure behavior.
5. Complete end-to-end tests before unlocking UI controls.
