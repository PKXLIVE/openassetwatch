# OpenAssetWatch Agent Package Scaffold

This directory contains release and package planning scaffolds for future
OpenAssetWatch agent packages. It is documentation and manifest-template
material only.

Current state:

- no installers are built from this directory
- no package-manager commands are executed from this directory
- no service-manager commands are executed from this directory
- no files are installed, removed, upgraded, or rolled back by this scaffold
- no signing keys, enrollment tokens, license keys, API keys, passwords, or
  other secrets are stored here

Future package targets:

- Windows signed MSI or enterprise deployment package
- Linux `.deb` package for Debian and Ubuntu
- Linux `.rpm` package for RHEL, Rocky Linux, AlmaLinux, CentOS, Fedora, SUSE,
  and openSUSE
- Linux `.tar.gz` fallback for unsupported distributions or manual install
- macOS signed and notarized package

## Scaffold Contents

- [Release Checklist](release-checklist.md)
- [OS Package Mapping](os-package-mapping.md)
- [Windows MSI manifest template](templates/windows-msi.manifest.yaml)
- [Linux DEB manifest template](templates/linux-deb.manifest.yaml)
- [Linux RPM manifest template](templates/linux-rpm.manifest.yaml)
- [Linux TAR.GZ manifest template](templates/linux-targz.manifest.yaml)
- [macOS PKG manifest template](templates/macos-pkg.manifest.yaml)

## Package Boundary

Future package definitions should describe:

- binary path
- config path
- identity path
- log directory
- status file path
- service definition path where applicable
- package metadata path where applicable
- checksum, signature, SBOM, and provenance expectations

Package templates must not contain secrets. Signing, notarization, publishing,
and enrollment material must be referenced only through CI/CD secret references
or deployment-system placeholders.

## Local Binary Artifact Generation

The local release helper
[`scripts/release/build_agent_dist.ps1`](../../scripts/release/build_agent_dist.ps1)
can build only the `oaw-agent` binary into ignored `dist/` paths before any
native package build exists:

```powershell
.\scripts\release\build_agent_dist.ps1 -Version 0.1.0-local
```

The helper writes a binary, SHA256 checksum file, and JSON manifest under
`dist/agent/<version>/<os>-<arch>/`. It does not create MSI, DEB, RPM, PKG, or
TAR.GZ packages, install software, write service definitions, execute
package-manager commands, execute service-manager commands, or contact network
services.

## Related Docs

- [Agent Installation Lifecycle](../../docs/AGENT_INSTALLATION.md)
- [Agent Lifecycle And Service Readiness](../../docs/AGENT_LIFECYCLE.md)
- [Release Pipeline](../../docs/RELEASE_PIPELINE.md)
- [Signed Releases](../../docs/SIGNED_RELEASES.md)

## Safety Boundaries

This scaffold must not introduce:

- installer execution
- package-manager execution
- service-manager execution
- service install or uninstall code
- daemon mode
- scheduling
- self-update behavior
- credential storage
- active scanning
- offensive tooling
- arbitrary shell command execution
