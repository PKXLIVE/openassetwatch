# Signed Releases

OpenAssetWatch release artifacts should move toward signed, reproducible,
auditable packages before enterprise production use.

## Target Artifacts

- Windows: signed MSI installer.
- macOS: signed and notarized PKG installer.
- Linux: signed DEB and RPM packages.
- Docker: signed image with SBOM and provenance metadata.
- Checksums: signed checksum manifest for all release artifacts.

Go builds should produce the OpenAssetWatch binaries. Platform packaging tools
should wrap those binaries into native installers instead of reimplementing
runtime behavior in installer scripts.

## Signing Rules

- Signing keys, certificates, Apple notarization credentials, Windows signing
  credentials, package repository credentials, and registry credentials must be
  stored only as CI/CD secret references.
- Do not commit private keys, certificates, passwords, API tokens, or raw secret
  values to this repository.
- Release jobs should use short-lived or tightly scoped credentials where the
  provider supports them.
- Build logs must not print secret values.

## Trust Metadata

Future release artifacts should include:

- artifact checksums
- SBOM
- provenance attestation
- source commit and tag
- builder identity
- package version
- signature verification instructions

## Current State

The installer files in `installers/` are scaffolding only. They define expected
service shape, flags, config paths, and least-privilege defaults, but they are
not yet signed native release packages.
