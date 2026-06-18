# Release Pipeline

This document describes the intended release pipeline direction for
OpenAssetWatch. It is not fully implemented yet.

## Current Scaffold State

- Go commands and package layout exist as a foundation.
- Installer scripts exist for Linux, macOS, Windows, and Docker shape review.
- Agent package scaffolding exists under
  [packaging/agent](../packaging/agent/README.md) for future Windows MSI,
  Linux `.deb`, Linux `.rpm`, Linux `.tar.gz`, and macOS package planning.
- The MVP deployment sizing baseline is documented in
  [Deployment Sizing](DEPLOYMENT_SIZING.md) so release and packaging work can
  stay aligned with the Linux-first Control Tower deployment target.
- Local agent binary artifact generation exists through
  [scripts/release/build_agent_dist.ps1](../scripts/release/build_agent_dist.ps1).
  It builds only the `oaw-agent` binary into ignored `dist/` paths and writes
  SHA256 plus manifest metadata.
- Local `.tar.gz` wrapping exists through
  [scripts/release/package_agent_targz.ps1](../scripts/release/package_agent_targz.ps1).
  It consumes an existing `oaw-agent` dist artifact directory and writes only
  `.tar.gz`, SHA256, and package manifest output under ignored `dist/` paths.
- Local Linux Debian package artifact generation exists through
  [scripts/release/package_agent_deb.py](../scripts/release/package_agent_deb.py).
  It consumes an existing Linux amd64 `oaw-agent` dist artifact and writes only
  `.deb`, SHA256, and package manifest output under ignored `dist/` paths.
- Local Linux Debian package validation exists through
  [scripts/release/validate_agent_deb.py](../scripts/release/validate_agent_deb.py).
  It inspects an existing `.deb` under ignored `dist/` paths without
  installing it or invoking host package tooling.
- Local release artifact validation exists through
  [scripts/release/validate_agent_release.ps1](../scripts/release/validate_agent_release.ps1).
  It verifies existing dist/package artifacts and emits JSON only.
- Local release orchestration exists through
  [scripts/release/release_agent_local.ps1](../scripts/release/release_agent_local.ps1).
  It runs the local binary build, TAR.GZ wrapping, and release validation
  helpers together and emits JSON only.
- Local install staging exists through
  [scripts/release/stage_agent_install.py](../scripts/release/stage_agent_install.py).
  It validates an existing local TAR.GZ package and expands it only under
  ignored `dist/staging/` paths to prove the future installed layout.
- Local sandbox install proof exists through
  [scripts/release/install_agent_local.py](../scripts/release/install_agent_local.py).
  It consumes a staged layout or TAR.GZ package and writes only under ignored
  `dist/local-install/` paths by default.
- Local sandbox uninstall proof exists through
  [scripts/release/uninstall_agent_local.py](../scripts/release/uninstall_agent_local.py).
  It removes only repo-local sandbox install roots under ignored
  `dist/local-install/` paths.
- Local sandbox upgrade and rollback proof exists through
  [scripts/release/upgrade_agent_local.py](../scripts/release/upgrade_agent_local.py).
  It validates local packages, writes backup metadata under ignored
  `dist/local-install/` paths, and creates only repo-local sandbox install
  roots.
- No signed native packages are produced yet.
- No installer execution, service installation, or package-manager execution
  is implemented by the scaffold.
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

## Local Debian Package Artifacts

After building a Linux amd64 agent binary artifact, use the local Debian helper
to create an unsigned `.deb` artifact under ignored `dist/` output:

```powershell
.\scripts\release\build_agent_dist.ps1 `
  -Version 0.1.0-local `
  -TargetOS linux `
  -TargetArch amd64

python .\scripts\release\package_agent_deb.py `
  --version 0.1.0-local
```

The helper writes:

- `dist/agent/<version>/packages/openassetwatch-agent_<version>_amd64.deb`
- `dist/agent/<version>/packages/openassetwatch-agent_<version>_amd64.deb.sha256`
- `dist/agent/<version>/packages/openassetwatch-agent_<version>_amd64.deb.manifest.json`

The package contains only intended Linux package archive paths:

- `/usr/bin/oaw-agent`
- `/etc/openassetwatch/agent/config.example.json`
- `/etc/openassetwatch/agent/identity.example.json`
- `/lib/systemd/system/oaw-agent.service`
- `/usr/share/doc/openassetwatch-agent/README.md`
- `/usr/share/doc/openassetwatch-agent/release-manifest.json`

The package builder validates the source binary manifest, source binary
checksum, package checksum, package manifest, expected package paths, and
forbidden package content. It uses Python standard library archive writers and
does not run `dpkg`, `apt`, `systemctl`, `service`, `sudo`, package-manager
commands, or service-manager commands. It does not install the package, enable
services, start services, write to host `/usr`, `/etc`, `/var`, `/lib`, `/opt`,
or store real config values, real identity values, logs, status state, tokens,
credentials, API keys, or secrets.

Validate the generated `.deb` artifact without installing it:

```powershell
python .\scripts\release\validate_agent_deb.py `
  --version 0.1.0-local
```

The validator checks package existence, checksum, manifest, Debian archive
members, expected install paths, service unit safety, example config and
identity placeholders, release manifest, unexpected maintainer files, forbidden
content, and path containment. It does not install the package and does not run
host package-manager or service-manager commands.

## Disposable Linux Install Test Guidance

Real install testing for `.deb` packages must happen only inside a disposable
Linux VM or container. Do not run install commands on the Windows build host or
on a developer workstation that is not intended to be disposable.

Manual commands for a disposable Debian or Ubuntu test environment only:

```bash
sudo apt install ./openassetwatch-agent_<version>_amd64.deb
test -x /usr/bin/oaw-agent
test -f /etc/openassetwatch/agent/config.example.json
test -f /etc/openassetwatch/agent/identity.example.json
test -f /lib/systemd/system/oaw-agent.service
/usr/bin/oaw-agent paths
systemctl status oaw-agent.service
sudo apt remove openassetwatch-agent
```

These commands are documentation-only guidance for an isolated Linux test
environment. They are not executed by the release scripts. Package install
tests should verify that the package lays down the expected files, does not
start the service automatically, leaves real config and identity creation under
administrator control, and cleans up according to the package lifecycle policy.

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

## Local Release Orchestration

Use the local release orchestrator to run build, TAR.GZ wrapping, and
validation in one safe local flow:

```powershell
.\scripts\release\release_agent_local.ps1 -Version 0.1.0-local
```

The orchestrator calls the existing local helpers:

1. `build_agent_dist.ps1`
2. `package_agent_targz.ps1`
3. `validate_agent_release.ps1 -IncludePackages`

The orchestrator writes JSON only with:

- `ok`
- `version`
- `artifacts`
- `packages`
- `checks`
- `warnings`
- `errors`

Generated artifacts remain under ignored `dist/` paths. The orchestrator does
not build MSI, DEB, RPM, or PKG packages. It does not install software, modify
the OS, write service definitions, execute package-manager commands, execute
service-manager commands, contact network services, or store secrets.

## Local Install Staging

Use the local install-staging helper to validate an existing TAR.GZ package and
expand it into a repo-local proof layout:

```powershell
python .\scripts\release\stage_agent_install.py `
  --version 0.1.0-local
```

By default the helper writes under:

- `dist/staging/agent/<version>/<os>-<arch>/binary/`
- `dist/staging/agent/<version>/<os>-<arch>/config/`
- `dist/staging/agent/<version>/<os>-<arch>/identity/`
- `dist/staging/agent/<version>/<os>-<arch>/logs/`
- `dist/staging/agent/<version>/<os>-<arch>/status/`
- `dist/staging/agent/<version>/<os>-<arch>/service/`
- `dist/staging/agent/<version>/<os>-<arch>/package-metadata/`

The helper emits JSON only with `ok`, `package`, `staging_dir`, `files`,
`checks`, `warnings`, and `errors`. It validates the package checksum,
manifest fields, archive paths, and forbidden archive entries before writing
the staging tree.

This is not a real system install. It does not write to Program Files,
ProgramData, `/usr`, `/etc`, `/var`, `/Library`, or other system paths. It
does not register services, start services, stop services, execute
package-manager commands, execute service-manager commands, contact network
services, write real config or identity values, write logs, write runtime
status, or store secrets.

## Local Sandbox Install Proof

Use the local sandbox install helper to copy a staged layout or TAR.GZ package
into a repo-local install proof:

```powershell
python .\scripts\release\install_agent_local.py `
  --version 0.1.0-local
```

By default the helper writes under:

- `dist/local-install/agent/<version>/<os>-<arch>/binary/`
- `dist/local-install/agent/<version>/<os>-<arch>/config/`
- `dist/local-install/agent/<version>/<os>-<arch>/identity/`
- `dist/local-install/agent/<version>/<os>-<arch>/logs/`
- `dist/local-install/agent/<version>/<os>-<arch>/status/`
- `dist/local-install/agent/<version>/<os>-<arch>/service/`
- `dist/local-install/agent/<version>/<os>-<arch>/package-metadata/`

The helper emits JSON only with `ok`, `install_root`, `files`, `checks`,
`warnings`, and `errors`. It refuses install roots outside the repository and
does not write outside ignored local `dist/` output in the documented flow.

This is not a real system install. It does not write to Program Files,
ProgramData, `/usr`, `/etc`, `/var`, `/Library`, or other system paths. It
does not register services, start services, stop services, execute
package-manager commands, execute service-manager commands, contact network
services, write real config or identity values, write logs, write runtime
status, or store secrets.

## Local Sandbox Uninstall Proof

Use the local sandbox uninstall helper to remove only a repo-local sandbox
install proof:

```powershell
python .\scripts\release\uninstall_agent_local.py `
  --version 0.1.0-local
```

The helper emits JSON only with `ok`, `install_root`, `removed`, `checks`,
`warnings`, and `errors`. It refuses uninstall roots outside the repository,
refuses paths that look like system paths, and by default requires expected
package metadata from `install_agent_local.py`.

This is not a real system uninstall. It does not remove generated release
packages, unregister services, start services, stop services, execute
package-manager commands, execute service-manager commands, contact network
services, remove config, identity, logs, or status outside the local sandbox
install root, or modify the host operating system.

## Local Sandbox Upgrade And Rollback Proof

Use the local sandbox upgrade and rollback helper to validate version
transitions inside ignored repo-local `dist/` paths:

```powershell
python .\scripts\release\upgrade_agent_local.py upgrade `
  --from-version 0.1.0-local `
  --to-version 0.1.1-local

python .\scripts\release\upgrade_agent_local.py rollback `
  --from-version 0.1.1-local `
  --to-version 0.1.0-local
```

The helper emits JSON only with `ok`, `mode`, `from_version`, `to_version`,
`install_root`, `backup`, `checks`, `warnings`, and `errors`. It operates only
under `dist/local-install/agent/`, `dist/agent/`, and `dist/staging/agent/`.
Backup metadata is written under ignored
`dist/local-install/agent/_backups/`.

This is not a real system upgrade or rollback. It does not remove generated
release packages, unregister services, start services, stop services, execute
package-manager commands, execute service-manager commands, contact network
services, remove config, identity, logs, or status outside the local sandbox
install root, or modify the host operating system.

## Agent Installation Foundation Status

The current phase proves that OpenAssetWatch can build, package, validate, and
stage an agent release safely without modifying the host operating system.

Complete for this phase:

- [x] agent dist artifact generation
- [x] SHA256 checksum generation
- [x] binary manifest generation
- [x] TAR.GZ package creation
- [x] TAR.GZ checksum generation
- [x] Debian package artifact creation
- [x] Debian package checksum generation
- [x] Debian package manifest generation
- [x] package manifest generation
- [x] local release orchestration helper
- [x] release validation helper
- [x] local install-staging helper
- [x] proof install layout under ignored `dist/staging/`
- [x] local sandbox install helper
- [x] proof local install layout under ignored `dist/local-install/`

Future work:

- [ ] real OS installation
- [ ] writing to Program Files, ProgramData, `/usr`, `/etc`, `/var`, or
  `/Library`
- [ ] service installation
- [ ] daemon or service runtime
- [ ] scheduling
- [ ] signed `.deb` release publication and install validation
- [ ] `.rpm` package build
- [ ] Windows MSI
- [ ] macOS signed/notarized package
- [ ] package-manager execution
- [ ] service-manager execution
- [ ] self-update
- [ ] licensing enforcement

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
