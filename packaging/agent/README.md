# OpenAssetWatch Agent Package Scaffold

This directory contains release and package planning scaffolds plus native
package authoring inputs for OpenAssetWatch agent packages.

Current state:

- Windows MSI artifacts can be built from the WiX source through
  `scripts/release/build_agent_msi.ps1`
- macOS unsigned PKG artifacts can be built from staged LaunchDaemon payloads
  through `scripts/release/build_agent_macos_pkg.sh` on macOS
- Linux DEB artifacts can be built and validated from the canonical Linux
  package source tree through `scripts/release/package_agent_deb.py` and
  `scripts/release/validate_agent_deb.py`
- Linux RPM artifacts can be built and validated when `rpmbuild`/`rpm`
  tooling is available through `scripts/release/package_agent_rpm.py` and
  `scripts/release/validate_agent_rpm.py`; install lifecycle CI currently
  exercises Rocky Linux 9 only
- Linux TAR.GZ remains a manual fallback artifact and does not install users,
  services, or sudoers rules
- Agent release publication CI validates unsigned PR artifacts and tagged
  release-candidate artifacts through `.github/workflows/agent-release.yml`
- no package-manager commands are executed from this directory
- no package-manager commands are executed by this directory
- service-manager commands appear only in reviewed target-install package
  scripts or explicit administrator tools
- no files are installed, removed, upgraded, or rolled back merely by reading
  this scaffold
- no signing keys, enrollment tokens, license keys, API keys, passwords, or
  other secrets are stored here
- Linux package metadata uses the canonical OpenAssetWatch Apache-2.0 license
  declaration and packages license/copyright material for target hosts

Package targets:

- Windows MSI or enterprise deployment package
- Linux `.deb` package for Debian and Ubuntu
- Linux `.rpm` package for RPM-family systems, with Rocky Linux 9 as the
  currently exercised install lifecycle target
- Linux `.tar.gz` fallback for unsupported distributions or manual install
- macOS LaunchDaemon PKG, signed and notarized for production release

## Scaffold Contents

- [Release Checklist](release-checklist.md)
- [OS Package Mapping](os-package-mapping.md)
- [Windows WiX MSI source](windows/OpenAssetWatchAgent.wxs)
- [macOS package scripts](macos/scripts/)
- [Linux package source](linux/)
- [Linux common package source](linux/common/)
- [Linux DEB package source](linux/deb/)
- [Linux RPM package source](linux/rpm/)
- [Linux TAR.GZ fallback notes](linux/targz/)
- [Windows MSI manifest template](templates/windows-msi.manifest.yaml)
- [Linux DEB manifest template](linux/deb/manifest-template.yaml)
- [Linux RPM manifest template](linux/rpm/manifest-template.yaml)
- [Linux TAR.GZ manifest template](linux/targz/manifest-template.yaml)
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

## Linux DEB And RPM Package Sources

Linux package source files live under `packaging/agent/linux/`:

- `common/`: config and identity examples, privileged helper wrappers,
  sudoers allowlist, systemd service/timer units, and shared README content.
- `deb/`: Debian control metadata, `conffiles`, maintainer scripts including
  `prerm`, and
  package-adjacent manifest template.
- `rpm/`: RPM spec template and package-adjacent manifest template.
- `targz/`: manual fallback notes and manifest template.

The production Linux package layout is currently Linux `amd64`/RPM `x86_64`.
The packaged executable is root-owned at
`/opt/openassetwatch/agent/bin/oaw-agent`, `/usr/bin/oaw-agent` is a
compatibility command, state and logs are service-owned under `/var`, and
privileged helper scripts are root-owned under
`/usr/lib/openassetwatch/agent/libexec/`.

Local unsigned DEB artifacts can be built and validated from an existing Linux
dist artifact:

```powershell
.\scripts\release\build_agent_dist.ps1 -Version 0.1.0-local -TargetOS linux -TargetArch amd64
python .\scripts\release\package_agent_deb.py --version 0.1.0-local
python .\scripts\release\validate_agent_deb.py --version 0.1.0-local
```

Local unsigned RPM artifacts require RPM tooling and can be built and
validated in Linux CI or another disposable Linux environment with
`rpmbuild`/`rpm` available:

```bash
pwsh ./scripts/release/build_agent_dist.ps1 -Version 0.1.0-local -TargetOS linux -TargetArch amd64
python3 ./scripts/release/package_agent_rpm.py --version 0.1.0-local
python3 ./scripts/release/validate_agent_rpm.py --version 0.1.0-local
```

Local and pull-request Linux packages are unsigned validation artifacts.
Signed release publication remains a tagged release pipeline responsibility.

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

## Local macOS PKG Artifact Generation

On macOS, the PKG helper can build unsigned LaunchDaemon validation artifacts
under ignored `dist/` output:

```bash
bash scripts/release/build_agent_macos_pkg.sh \
  --version 0.1.0-local \
  --arch-mode universal

python3 scripts/release/validate_agent_macos_install.py \
  --version 0.1.0-local
```

The package installs the native macOS service model using
`/Library/Application Support/OpenAssetWatch/Agent/bin/oaw-agent service run`.
It stages and packages `com.openassetwatch.agent` as a system LaunchDaemon
running as `_openassetwatch`, with config, identity, and state under
`/Library/Application Support/OpenAssetWatch/Agent` and logs under
`/Library/Logs/OpenAssetWatch/Agent`.

Local PKG output is unsigned and is not production release-ready until the
binary and package are signed, notarized, stapled, and verified.

## Release Publication

The release-publication workflow builds the full agent artifact set for pull
requests and `v*` tags, validates checksums and manifests, and uploads
release-candidate artifacts to the workflow run. Pull requests never publish a
GitHub Release. Tag builds may publish only when production signing evidence is
available and the repository variable `OAW_AGENT_RELEASE_PUBLICATION_ENABLED`
is set to `true`.

The publication manifest is validated by
[`scripts/release/validate_agent_release_publication.py`](../../scripts/release/validate_agent_release_publication.py).
It checks expected package coverage, SHA256 metadata, Apache-2.0 license
metadata, signed/notarized claims, and stable or release-candidate version
normalization. SBOM and provenance paths are reserved in the metadata contract
and remain empty until those generators are added.

Production publication remains blocked until Windows signing evidence, macOS
notarization evidence, Linux package signing evidence, SBOM generation, and
provenance/attestation generation are wired into the workflow.

## Related Docs

- [Agent Installation Lifecycle](../../docs/AGENT_INSTALLATION.md)
- [Agent Windows Deployment](../../docs/AGENT_WINDOWS_DEPLOYMENT.md)
- [Agent macOS Deployment](../../docs/AGENT_MACOS_DEPLOYMENT.md)
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
- no active scanning
- offensive tooling
- no arbitrary shell command execution
