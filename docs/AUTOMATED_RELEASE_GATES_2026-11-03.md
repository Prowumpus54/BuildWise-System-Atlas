# Atlas — automated release gates and owner authority (proposal, 2026-11-03)

The Owner has requested that Atlas no longer demand individual owner approval or hands-on live testing for every ordinary feature. Automate evidence-based review **without** granting blanket operational authority.

## Delegated routine work
- Docs, viewer UI, safe read-only diagrams, and reversible non-sensitive changes may be accepted by automated CI and an independent agent review when checks are actually wired up and green.
- More involved telemetry, integration, and deployment changes require exact-commit CI, stage browser smoke, auth/permissions regression tests, signature/health checks, rollback verification and a monitored canary before automated promotion.
- Do not call a merge a deployment, a passing unit test a browser test, or a registered agent a live agent. All results must be recorded by commit SHA, build digest and timestamp.

## Retained owner controls
- **Do not rely on any prior broad Atlas owner approval for new privileged operations.** Require a current explicit narrowly scoped authorization for control plane access, credentials, increased OAuth scopes, paid infrastructure, public network exposure, destructive actions, or similar irreversible/high-risk work.
- Do not weaken existing VaultWise or provider approval gates. If a required approval is denied, stop that operation; ordinary read-only work can continue.
- The read-only Atlas currently embedded in ContextWise does not establish live telemetry or authorize exposing the BuildWise desktop control port.

## Automation prerequisites (not currently verified)
1. Tier and permission-change classifier; uncertain change escalates.
2. CI with lint/unit/security checks, Atlas browser rendering smoke and privacy tests.
3. Artifact/commit provenance and independent agent reviewer.
4. Staging deployment with deterministic smoke, canary monitoring and rollback.
5. Evidence publication to Tasker and ContextWise, showing verified vs stale status.
6. Merge/branch cleanup only after checks; never remove unmerged, protected, default or active branches.

No automerge, live collector, cloud spending, control-plane permission, or production rollout is enabled by this policy file alone.

See the corresponding ContextWise automated acceptance policy for cross-Wise risk tiers.
