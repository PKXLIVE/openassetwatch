# OpenAssetWatch Agent Package Scaffold

This directory contains release and package planning scaffolds plus the Windows
WiX MSI authoring source for OpenAssetWatch agent packages.

Current state:

- Windows MSI artifacts can be built from the WiX source through
  `scripts/release/build_agent_msi.ps1`
- no package-manager commands are executed from this directory
- no service-manager commands are executed from this directory
- no files are installed, removed, upgraded, or rolled back by this scaffold
- no signing keys, enrollment tokens, license keys, API keys, passwords, or
  other secrets are stored here

Package targets:

- Windows MSI or enterprise deployment package
- Linux `.deb` package for Debian and Ubuntu
- Linux `.rpm` package for RHEL, Rocky Linux, AlmaLinux, CentOS, Fedora, SUSE,
  and openSUSE
- Linux `.tar.gz` fallback for unsupported distributions or manual install
- macOS signed and notarized package

## Scaffold Contents

- [Release Checklist](release-checklist.md)
- [OS Package Mapping](os-package-mapping.md)
- [Windows WiX MSI source](windows/OpenAssetWatchAgent.wxs)
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

## Local TAR.GZ Package Wrapper

The local TAR.GZ helper
[`scripts/release/package_agent_targz.ps1`](../../scripts/release/package_agent_targz.ps1)
can wrap an existing local dist artifact directory into a reviewable archive:

```powershell
.\scripts\release\package_agent_targz.ps1 `
  -ArtifactDir dist\agent\0.1.0-local\linux-amd64
```

The helper writes the `.tar.gz`, package checksum, and package manifest under
`dist/agent/<version>/packages/`. Archive contents are limited to the agent
binary, binary checksum, binary manifest, and safe README notes. It does not
include generated config files, identity files, enrollment tokens, credentials,
logs, local status files, or service definitions.

This helper does not build MSI, DEB, RPM, or PKG packages. It does not install
software, modify the OS, run package-manager commands, run service-manager
commands, or contact network services.

## Local Windows MSI Artifact Generation

The Windows MSI helper
[`scripts/release/build_agent_msi.ps1`](../../scripts/release/build_agent_msi.ps1)
uses the repo-pinned WiX Toolset local tool and the WiX source in
`packaging/agent/windows/` to build an unsigned local MSI under ignored
`dist/` output:

```powershell
.\scripts\release\build_agent_dist.ps1 -Version 0.1.0-local -TargetOS windows -TargetArch amd64
.\scripts\release\build_agent_msi.ps1 -Version 0.1.0-local -TargetArch amd64
python .\scripts\release\validate_agent_windows_msi.py --version 0.1.0-local
```

The MSI installs the native Windows service model using `oaw-agent.exe service
run`. Local MSI output is unsigned and is not production release-ready until
the executable and MSI are signed and verified.

## Related Docs

- [Agent Installation Lifecycle](../../docs/AGENT_INSTALLATION.md)
- [Agent Windows Deployment](../../docs/AGENT_WINDOWS_DEPLOYMENT.md)
- [Agent Lifecycle And Service Readiness](../../docs/AGENT_LIFECYCLE.md)
- [Release Pipeline](../../docs/RELEASE_PIPELINE.md)
- [Signed Releases](../../docs/SIGNED_RELEASES.md)

## Safety Boundaries

This scaffold must not introduce:

- implicit installer execution
- package-manager execution
- service-manager execution
- broad service install or uninstall helpers outside the reviewed MSI and
  explicit administrator tools
- unbounded daemon mode
- Task Scheduler usage for the Windows agent
- self-update behavior
- credential storage
- active scanning
- offensive tooling
- arbitrary shell command execution
