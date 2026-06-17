# Release Pipeline

This document describes the intended release pipeline direction for
OpenAssetWatch. It is not fully implemented yet.

## Current Scaffold State

- Go commands and package layout exist as a foundation.
- Installer scripts exist for Linux, macOS, Windows, and Docker shape review.
- No native signed packages are produced yet.
- No signing keys or credentials are stored in the repository.

## Target Pipeline

1. Run repository safety checks.
2. Run Go formatting and tests.
3. Run Python backend, collector, advisor, enrichment, scoring, reporting, and
   exporter tests where applicable.
4. Build Go binaries for supported platforms.
5. Generate SBOMs.
6. Package native installers:
   - Windows MSI
   - macOS PKG
   - Linux DEB
   - Linux RPM
7. Build Docker images.
8. Sign artifacts using CI/CD secret references.
9. Generate provenance attestations.
10. Publish draft release artifacts.
11. Promote after manual review.

## Safety Gates

Release jobs should fail if active production config paths include:

- `configs/quarantine/`
- raw command wrappers
- raw `args` or `additional_args`
- raw target URLs, IPs, CIDRs, or file paths
- raw usernames, passwords, hashes, API keys, tokens, or secret values
- exploit, payload, brute force, credential validation, C2, webshell, terminal,
  fuzzing, or unrestricted scanner controls

## CI/CD Secrets

The pipeline should reference signing and publishing material only by secret
name. Examples:

- `WINDOWS_CODE_SIGNING_CERT_REF`
- `WINDOWS_CODE_SIGNING_PASSWORD_REF`
- `APPLE_DEVELOPER_ID_CERT_REF`
- `APPLE_NOTARIZATION_CREDENTIAL_REF`
- `LINUX_PACKAGE_SIGNING_KEY_REF`
- `CONTAINER_REGISTRY_TOKEN_REF`
- `PROVENANCE_SIGNING_KEY_REF`

These names are examples of references. They are not secret values.
