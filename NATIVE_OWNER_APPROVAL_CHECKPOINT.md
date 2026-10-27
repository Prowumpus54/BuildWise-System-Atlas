# Native Windows Hello approval checkpoint

The new start-owner-approved-gateway.cjs launcher binds Atlas to an existing BuildWise session and the protected Windows vault public pin. Only health.check is eligible for owner approval; unsupported commands remain blocked. The existing status-only launcher continues to deny health commands.

The approval adapter sends its own random nonce, action, request ID and expiration to the authenticated loopback BuildWise owner-approval endpoint. It independently verifies the fixed-domain broker signature, installation, exact action/target/request/nonce, decision and deadline. A caller boolean or successful HTTP response is insufficient. Denied/cancelled receipts cannot become approvals.

owner-approval-receipt.cjs is the same portable verifier source as BuildWise server/protected-owner-approval-receipt.js at this checkpoint. Keep the two copies synchronized if the protocol changes. No app credentials, private keys, factory tokens or PINs are committed.

Validation: 42 Atlas tests passed, no failures or skips (1152.0983 ms). This includes signed approval acceptance, native receipt substitutions, unsupported targets, missing pins, cancellation and signed denial, plus the existing telemetry/session/replay tests. These signers are synthetic; installed Windows Hello approval testing is still required.

BuildWise scripts/vault-owner-integration-smoke.js exercises real installed Hello approval and the real Atlas gateway/adapter against a temporary local test session, forwarding the approved read to the running BuildWise health endpoint. Run approve/deny/cancel/timeout from the enrolled Windows desktop. No active desktop token is read and the running application is not replaced. General vault credential access remains disabled.
