# Milestone 2 — strict schema and remote authentication gate

The relay now validates top-level and nested telemetry fields, bounded arrays, numeric resources, ISO timestamps, consistent job counts, and refuses unknown nested properties. Five new schema regression tests pass; total Atlas suite: 35/35.

**Remote integration remains blocked.** The website currently fetches only `http://127.0.0.1:7335/atlas/snapshot`. No deployed, verified HTTPS relay or authenticated viewer session was found in the Atlas configuration. The prototype relay requires different publisher and viewer bearer credentials, but neither should be embedded in public GitHub Pages JavaScript. The public website is intentionally unchanged until a secure viewer-authentication flow and real deployed HTTPS endpoint are available and verified.

Production launch requires encrypted ingress, authenticated tenant-bound read sessions, nested data redaction verification against real jobs, credential rotation, durable replay/rate controls, strict CORS at a trusted edge, and end-to-end browser and desktop tests. Do not expose local BuildWise or Atlas ports.
