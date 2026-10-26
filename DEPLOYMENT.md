# BuildWise Atlas — deployment and live error bridge

## Implementation (2026-10-25)
The repo contains a deployable GitHub Pages frontend in `public/index.html`, the read-only localhost bridge `atlas-bridge.cjs`, and `.github/workflows/deploy.yml`.

## Smoke evidence
- BuildWise `http://127.0.0.1:7331/api/dispatcher/jobs` was reachable through a local bridge on `127.0.0.1:7335`.
- Snapshot returned 20 jobs, 3 active jobs, and 14 FAILED/BLOCKED/ERROR/TIMEOUT historical jobs at test time.
- Examples: FX-020 outside-scope file `.buildwise-lease.json`; FX-017 JSONL limit; FX-016 dirty worktree.
- Origin `https://prowumpus54.github.io` returned HTTP 200 and allow-origin header.
- Untrusted Origin returned 403. Undocumented path returned 404.
- No control token is embedded in the frontend; errors have bounded, redacted messages.
- CPU reading intentionally unavailable; RAM is sampled from local OS. The public site currently connects only from the authorized desktop's browser through localhost and may be subject to browser private-network restrictions.

## Pending website activation
At time of test, `https://prowumpus54.github.io/BuildWise-System-Atlas/` returned HTTP 404; GitHub API /pages likewise returned 404.
Enable under repository Settings -> Pages -> Build and deployment -> Source: GitHub Actions. Then monitor Actions / Deploy BuildWise Atlas and verify the URL. Do not claim the site is live until HTTP 200 and render are confirmed.

## Starting the bridge
On the BuildWise PC:
```powershell
node C:\BuildWiseWorktrees\buildwise-system-atlas\atlas-bridge.cjs
```
This is a development/local-session service, not yet installed for automatic restart.

## Important security and operating limitations
Static GitHub Pages alone cannot receive push events from the desktop. Current UI polls every 10 seconds from a loopback-only read-only bridge. Live visibility away from the BuildWise PC will require a separately authenticated outbound collector and hosted relay with owner authentication, event allowlists, TLS, replay checks, TTL, redaction, and no write endpoints. Do not expose 7331 or 7335 publicly.

This build is a compact first functional replacement and does not yet contain the prior 3D scene, full editable source ZIP export, or per-agent resource accounting. The snapshot export is JSON only.
