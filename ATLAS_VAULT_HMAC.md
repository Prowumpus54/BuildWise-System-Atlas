# Atlas local vault HMAC connection

Atlas can now request owner-approved HMAC signing of a compact health snapshot through the installed BuildWise desktop API. This local owner tool and reusable server adapter are separate from the read-only GitHub Pages viewer. No webpage control, listener, public relay, automatic signing or bearer/OAuth provider access is enabled.

## Setup and use

Run connect-atlas-vault.cmd from the real Windows owner desktop. Initial setup asks for three Windows Hello approvals: register **buildwise-atlas**, import a generated HMAC secret using the native **Generate secret** form, then sign the first Atlas snapshot. Do not enter a provider API key. The app and credential remain active afterward, and the nonexportable app identity stays in the Windows CurrentUser CNG store.

Run the same shortcut again for a fresh snapshot with one approval. The native review shows the exact canonical message, credential/version, app key fingerprint and message digest. Each operation has a new request ID, nonce and 60-second approval deadline. A status response or enrolled-owner flag never counts as approval.

The public connection manifest is under APPDATA/BuildWiseVaultClients/Atlas/hmac-connection-v1.json. It contains an installation ID, credential ID/version, public key fingerprint and setup phase; no token, secret or private key. Keep it for continuity. Interrupted registration/import with an uncertain response stops for owner review instead of silently retrying or replacing an identity. App names cannot be reused after revocation; recovery/re-enrollment is not automated.

## Scope and verification

atlas-vault-hmac.cjs constructs a fixed, small atlas.telemetry.check message from the live desktop's health and authenticated vault status. It does not accept arbitrary messages, URLs, app IDs or credential IDs from a browser. Source data such as job text, email, paths and upstream extra fields are discarded. The result is a public message, digest, HMAC and a broker-signed receipt. The receipt verifier binds the exact operation, app, credential version, message, nonce, request ID and deadline. It rejects denied/forged/mismatched receipts.

The Windows owner process is hardened before reading the existing desktop HTTP token; that token stays server-side and is never written to output or connection state. The client uses fixed loopback endpoints with redirects disabled. The app identity helper signs with an existing nonexportable CNG key; signing never auto-creates a missing key. Native Windows Hello remains required for every HMAC operation.

The signed receipt proves approval of these bytes, not independent truth of the health observation. The HMAC is not a public-key signature; public receipt verification and any future HMAC verification must use the appropriate distinct mechanisms.

Reviewed SDK files in vendor/buildwise-vault are copied unchanged from BuildWise commit 55c71207e1461d67a345dcc79c3ca93c97121daf. manifest.json records SHA256 hashes normalized to UTF-8/LF and startup verifies them. Source attribution: Prowumpus54/-factory--dashboard, ISC package license; no credential data is included.

## Validation checkpoint

All 52 Atlas tests passed, including five new signing/receipt/security cases. Tests use synthetic keys and mock HTTP only; they are not Windows Hello enrollment evidence. atlas-vault-preflight.cjs checks the installed immutable host/configuration, desktop health and the credential endpoint's unauthenticated 401 without reading a token, creating keys or showing approval UI.

Actual Atlas app enrollment and snapshot signing remain pending until the owner completes the setup shortcut. Existing BuildWise vault physical lifecycle and populated-store restart tests already passed separately.

Revoke access using the native BuildWise Vault manager: revoke the app, then revoke its credential with owner approval. No general credential export endpoint exists. The public viewer and existing status gateway remain unchanged.
