# Release Pipeline

This document describes the intended release pipeline direction for
OpenAssetWatch. It is not fully implemented yet.

## Current Scaffold State

- Go commands and package layout exist as a foundation.
- Installer scripts exist for Linux, macOS, Windows, and Docker shape review.
- Agent package scaffolding exists under
  [packaging/agent](../packaging/agent/README.md) for future Windows MSI,
  Linux `.deb`, Linux `.rpm`, Linux `.tar.gz`, and macOS package planning.
- Local agent binary artifact generation exists through
  [scripts/release/build_agent_dist.ps1](../scripts/release/build_agent_dist.ps1).
  It builds only the `oaw-agent` binary into ignored `dist/` paths and writes
  SHA256 plus manifest metadata.
- Local `.tar.gz` wrapping exists through
  [scripts/release/package_agent_targz.ps1](../scripts/release/package_agent_targz.ps1).
  It consumes an existing `oaw-agent` dist artifact directory and writes only
  `.tar.gz`, SHA256, and package manifest output under ignored `dist/` paths.
- Local release artifact validation exists through
  [scripts/release/validate_agent_release.ps1](../scripts/release/validate_agent_release.ps1).
  It verifies existing dist/package artifacts and emits JSON only.
- No native signed packages are produced yet.
- No package build, installer execution, service installation, or
  package-manager execution is implemented by the scaffold.
- No signing keys or credentials are stored in the repository.

## Local Agent Binary Artifacts

Use the local release helper to build a host-platform `oaw-agent` binary into
`dist/`:

```powershell
.\scripts\release\build_agent_dist.ps1 -Version 0.1.0-local
```

The helper writes:

- `dist/agent/<version>/<os>-<arch>/oaw-agent`
- `dist/agent/<version>/<os>-<arch>/oaw-agent.exe` on Windows
- `<artifact>.sha256`
- `<artifact>.manifest.json`

The JSON manifest records artifact name, version, OS, architecture,
repo-relative path, SHA256, build timestamp, and git commit when available.
The helper refuses output paths outside the repository and does not build MSI,
DEB, RPM, PKG, or TAR.GZ packages. It does not install software, modify the OS,
write service definitions, run package-manager commands, run service-manager
commands, contact external services, or store secrets.

Generated `dist/` artifacts are local validation output and must not be
committed.

## Local TAR.GZ Package Artifacts

After building a local agent binary artifact, use the local TAR.GZ helper to
wrap that existing artifact directory:

```powershell
.\scripts\release\package_agent_targz.ps1 `
  -ArtifactDir dist\agent\0.1.0-local\windows-amd64
```

The helper writes:

- `dist/agent/<version>/packages/openassetwatch-agent-<version>-<os>-<arch>.tar.gz`
- `<package>.sha256`
- `<package>.manifest.json`

The package manifest records package name, version, OS, architecture,
package type, source artifact path, package path, SHA256, build timestamp, and
git commit when available. The archive contains only the agent binary, binary
checksum, binary manifest, and safe README notes copied from the existing local
dist artifact.

The helper refuses input and output paths outside the repository. It does not
build MSI, DEB, RPM, or PKG packages. It does not install software, modify the
OS, write service definitions to system paths, run package-manager commands,
run service-manager commands, contact external services, include generated
config or identity files, include logs, or store secrets.

## Local Release Artifact Validation

Use the local release validator to check existing dist output:

```powershell
.\scripts\release\validate_agent_release.ps1 `
  -Version 0.1.0-local `
  -IncludePackages
```

The validator reads `dist/agent/<version>/` and writes JSON only:

- `ok`
- `checks`
- `warnings`
- `errors`

It verifies binary artifact directories, agent binary files, binary checksum
files, binary manifests, package archives when `-IncludePackages` is supplied,
package checksums, package manifests, and TAR.GZ archive contents. It checks
that archives do not contain config files, identity files, logs, status files,
service definitions, tokens, secrets, or credentials.

The validator does not build installers, build native packages, install
software, modify the OS, write service definitions, execute package-manager
commands, execute service-manager commands, contact network services, or store
secrets.

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
