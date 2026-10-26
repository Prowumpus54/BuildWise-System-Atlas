# BuildWise System Atlas

Independent, read-only architecture and telemetry visualization for the BuildWise platform.

**Deployment state:** Repository initialized. Application source has not been uploaded yet. The former ChatGPT-hosted website is not controlled by this repository.

## Source of truth
- GitHub repository: `Prowumpus54/BuildWise-System-Atlas`
- Target host: GitHub Pages (configured after source import)
- Canonical job lifecycle: BuildWise desktop orchestrator
- Telemetry connection: future authenticated, outbound-only gateway. Never publish desktop control port 7331 or tokens.

## Import pending
The portable rebuild ZIP is currently available in the ChatGPT conversation as `BuildWise-System-Atlas-Repository-Ready.zip`. Extract its **BuildWise-System-Atlas/** folder and upload the *contents of that folder* to the root of this repository, retaining `.github/workflows/deploy-pages.yml`. Do not upload the ZIP instead of its extracted files.

After upload, enable GitHub Pages with **Settings → Pages → Build and deployment → Source: GitHub Actions** and inspect Actions for the smoke-test and deployment result.

**Important:** The rebuilt Atlas is a reconstructed viewer using demo data, not proof of a live hosted telemetry feed. The original ChatGPT-hosted URL is not replaced by this repository.
