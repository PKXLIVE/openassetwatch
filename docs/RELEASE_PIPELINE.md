# Release Pipeline

This document describes the intended release pipeline direction for
OpenAssetWatch. It is not fully implemented yet.

## Current Scaffold State

- Go commands and package layout exist as a foundation.
- Installer scripts exist for Linux, macOS, Windows, and Docker shape review.
- Agent package source exists under
  [packaging/agent](../packaging/agent/README.md) for Windows MSI, Linux
  `.deb`, Linux `.rpm`, Linux `.tar.gz`, and macOS PKG artifacts.
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
- Local Linux RPM artifact generation exists through
  [scripts/release/package_agent_rpm.py](../scripts/release/package_agent_rpm.py).
  It consumes an existing Linux amd64 `oaw-agent` dist artifact, stages the RPM
  build tree from committed package source, invokes `rpmbuild` when available,
  and writes only unsigned `.rpm`, SHA256, and package manifest output under
  ignored `dist/` paths. It does not install the RPM.
- Local Linux RPM package validation exists through
  [scripts/release/validate_agent_rpm.py](../scripts/release/validate_agent_rpm.py).
  It inspects the staging tree, spec file, staged payload, package manifest,
  checksum, and real `.rpm` metadata/payload/scriptlets using RPM query
  tooling without installing the RPM.
- Local Windows install layout staging exists through
  [scripts/release/stage_agent_windows_install.py](../scripts/release/stage_agent_windows_install.py).
  It consumes an existing Windows amd64 `oaw-agent.exe` dist artifact and
  writes only a Program Files/ProgramData proof layout, service metadata, and
  manifest under ignored `dist/` paths.
- Local Windows install layout validation exists through
  [scripts/release/validate_agent_windows_install.py](../scripts/release/validate_agent_windows_install.py).
  It inspects an existing staged Windows install layout, service metadata, and
  manifest under ignored `dist/` paths without installing services, scheduled
  tasks, registry entries, or MSI packages.
- Local Windows MSI generation exists through
  [scripts/release/build_agent_msi.ps1](../scripts/release/build_agent_msi.ps1).
  It uses the repo-pinned WiX Toolset local tool, consumes the Windows amd64
  agent artifact and staged layout, and writes only an unsigned MSI, SHA256,
  and non-secret manifest under ignored `dist/` paths.
- Local Windows MSI validation exists through
  [scripts/release/validate_agent_windows_msi.py](../scripts/release/validate_agent_windows_msi.py).
  It validates checksum/manifest metadata and the WiX source model without
  installing the MSI.
- Windows signing hooks exist through
  [scripts/release/sign_agent_windows.ps1](../scripts/release/sign_agent_windows.ps1).
  They require explicit certificate inputs and support executable/MSI signing
  and verification. CI builds remain unsigned validation artifacts.
- Local macOS LaunchDaemon install staging exists through
  [scripts/release/stage_agent_macos_install.py](../scripts/release/stage_agent_macos_install.py).
  It consumes an existing Darwin agent artifact and writes only a
  `/Library/Application Support`, `/Library/Logs`, and LaunchDaemon proof
  layout under ignored `dist/` paths.
- Local macOS LaunchDaemon install validation exists through
  [scripts/release/validate_agent_macos_install.py](../scripts/release/validate_agent_macos_install.py).
  It inspects the staged LaunchDaemon layout, plist, package scripts, manifests,
  examples, and safety boundaries without installing the package.
- Local macOS PKG generation exists through
  [scripts/release/build_agent_macos_pkg.sh](../scripts/release/build_agent_macos_pkg.sh).
  It runs on macOS, builds Darwin arm64/amd64 slices or a universal binary, and
  writes unsigned PKG, SHA256, and manifest artifacts under ignored `dist/`
  paths.
- macOS signing and notarization hooks exist through
  [scripts/release/sign_notarize_agent_macos.sh](../scripts/release/sign_notarize_agent_macos.sh).
  They require explicit Developer ID and notary inputs, rebuild from verified
  Darwin artifacts, sign the final embedded binary before pkgroot staging, sign
  the product PKG, notarize, staple, validate Gatekeeper assessment, and
  regenerate final checksum/manifest metadata. Local and PR PKG artifacts
  remain unsigned validation artifacts.
- A safe macOS uninstaller exists through
  [scripts/release/uninstall_agent_macos.sh](../scripts/release/uninstall_agent_macos.sh).
  It preserves config, identity, state, logs, and the service account by
  default, with explicit cleanup flags for administrator-controlled removal.
- Explicit Windows service install and uninstall helpers exist through
  [scripts/release/install_agent_windows_service.ps1](../scripts/release/install_agent_windows_service.ps1)
  and
  [scripts/release/uninstall_agent_windows_service.ps1](../scripts/release/uninstall_agent_windows_service.ps1).
  They support dry-run validation and require explicit administrator execution
  for real service changes. They do not build an MSI.
- Explicit Windows file install and uninstall helpers exist through
  [scripts/release/install_agent_windows_files.ps1](../scripts/release/install_agent_windows_files.ps1)
  and
  [scripts/release/uninstall_agent_windows_files.ps1](../scripts/release/uninstall_agent_windows_files.ps1).
  They support dry-run validation and require explicit administrator execution
  for real file copy or cleanup. They preserve config and identity by default
  and do not build an MSI.
- Local release artifact validation exists through
  [scripts/release/validate_agent_release.ps1](../scripts/release/validate_agent_release.ps1).
  It verifies existing dist/package artifacts and emits JSON only.
- Release publication metadata validation exists through
  [scripts/release/validate_agent_release_publication.py](../scripts/release/validate_agent_release_publication.py).
  It validates tag/version normalization, artifact manifest completeness,
  checksum agreement, Apache-2.0 license metadata, unsigned/signed state,
  notarization evidence, expected package coverage, and the GitHub Actions
  release trigger policy.
- Tagged release-publication CI exists through
  [.github/workflows/agent-release.yml](../.github/workflows/agent-release.yml).
  Pull requests build and validate unsigned artifacts without publishing.
  `v*` tags build release-candidate artifacts, require production signing
  evidence for production publication, and gate GitHub Release creation behind
  `OAW_AGENT_RELEASE_PUBLICATION_ENABLED=true`.
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
- No production signed native packages are produced yet.
- Production publication is fail-closed until signing and notarization evidence
  exists for the relevant artifacts.
- Windows MSI and macOS PKG package-script behavior is implemented and tested
  through explicit package artifacts. Local release helpers do not execute
  package-manager commands.
- No signing keys or credentials are stored in the repository.

## Agent Release Publication Workflow

The hosted release workflow is the first production publication framework for
agent artifacts. It separates validation from publication:

- `pull_request`: builds and validates unsigned PR validation artifacts, uploads
  them to the workflow run, and never creates GitHub Releases.
- `workflow_dispatch`: builds unsigned release-candidate artifacts for an
  explicit version when `unsigned_dry_run=true`.
- `push` tags matching `v*`: builds release-candidate artifacts from the tag.
  Production signing and GitHub Release publication are tag-only and fail
  closed unless signing evidence and the explicit repository variable gate are
  present.

The workflow builds the following artifact families when the platform tooling
is available in GitHub Actions:

- Windows `amd64` dist artifact and Windows `amd64` MSI
- macOS `arm64` PKG
- macOS Intel `amd64` PKG
- macOS universal PKG
- Linux `amd64` DEB
- Linux `x86_64` RPM
- Linux `amd64` TAR.GZ fallback
- SHA256 checksum files
- package and binary manifests
- release-publication manifest

SBOM and provenance paths are part of the release-publication metadata contract.
They remain empty until dedicated SBOM/provenance generation is wired into the
pipeline.

## Release Versioning

Git tags are the release source of truth. A stable tag such as `v0.1.0`
normalizes to `0.1.0` for source and package metadata. A pre-release tag such
as `v0.1.0-rc.1` normalizes deterministically:

- source version: `0.1.0-rc.1`
- DEB version metadata: `0.1.0~rc.1`
- RPM version metadata: `0.1.0_rc.1`
- Windows Installer version: `0.1.0`
- macOS package receipt version: `0.1.0`

Windows Installer package versions must satisfy Windows Installer limits:
major and minor values are at most `255`, and the build value is at most
`65535`.

## Release Dry Run

For a hosted unsigned dry run, use the `Agent release publication` workflow
with `workflow_dispatch`, a version such as `v0.1.0-rc.1`, and
`unsigned_dry_run=true`. The workflow uploads artifacts to the workflow run and
does not publish a GitHub Release.

Local validation can be run against any existing `dist/agent/<version>/`
release root:

```powershell
python .\scripts\release\validate_agent_release_publication.py normalize-version --tag v0.1.0-rc.1
python .\scripts\release\validate_agent_release_publication.py check-workflow --workflow .github\workflows\agent-release.yml
python .\scripts\release\validate_agent_release_publication.py validate `
  --version 0.1.0-local `
  --release-root dist\agent\0.1.0-local `
  --classification unsigned-release-candidate `
  --expected-package-type linux-deb `
  --expected-package-type linux-rpm `
  --expected-package-type linux-targz
```

Use the expected package-type list that matches the artifacts present in the
local release root.

## Production Signing Inputs

Signing material must be supplied through GitHub Actions secrets or trusted
external signing services. Do not commit signing material.

Windows production signing requires:

- Authenticode code-signing certificate or signing service
- certificate password or signing-service token
- timestamp server URL

macOS production signing and notarization require:

- Developer ID Application certificate
- Developer ID Installer certificate
- Apple notarization credentials or API key
- keychain password
- Apple team ID

Linux production package signing requires:

- GPG signing key for DEB/RPM package signing
- signing key passphrase if required
- package repository signing plan if repository publication is added later

GitHub release publication may require:

- a release token if `GITHUB_TOKEN` is insufficient
- artifact attestation permissions when provenance attestation is enabled

The release workflow names the production signing secret inputs and fails
closed when required production signing material is missing. It does not fake
signing success.

## Release Verification

Before public publication, verify:

- every expected package type is present in the release-publication manifest
- every artifact manifest includes filename, package type, OS, architecture,
  version, git commit, build timestamp, SHA256, Apache-2.0 license metadata,
  signed state, notarized state where applicable, SBOM path, and provenance path
- every `.sha256` file matches the referenced artifact
- unsigned validation artifacts are marked `signed=false`
- signed artifacts include signing evidence
- macOS notarized artifacts include notarization evidence
- no release metadata contains secrets, tokens, credentials, passwords, private
  keys, or API keys

Current public production release blockers:

- production Windows signing evidence is not yet wired into the publication
  manifest
- production macOS notarization/stapling evidence is not yet wired into the
  publication manifest
- production Linux package signing is not yet wired into the publication
  manifest
- SBOM generation is not yet wired into the release workflow
- provenance/attestation generation is not yet wired into the release workflow

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

## Local Windows Install Layout Staging

After building a Windows amd64 agent binary artifact, use the Windows staging
helper to prove the production install layout under ignored `dist/` output:

```powershell
.\scripts\release\build_agent_dist.ps1 `
  -Version 0.1.0-local `
  -TargetOS windows `
  -TargetArch amd64

python .\scripts\release\stage_agent_windows_install.py `
  --version 0.1.0-local

python .\scripts\release\validate_agent_windows_install.py `
  --version 0.1.0-local

.\scripts\release\install_agent_windows_files.ps1 `
  -WindowsInstallRoot .\dist\agent\0.1.0-local\windows-install `
  -DryRun

.\scripts\release\uninstall_agent_windows_files.ps1 `
  -ServiceMetadata .\dist\agent\0.1.0-local\windows-install\service\oaw-agent-service.json `
  -DryRun

.\scripts\release\install_agent_windows_service.ps1 `
  -InstallRoot .\dist\agent\0.1.0-local\windows-install `
  -ServiceMetadata .\dist\agent\0.1.0-local\windows-install\service\oaw-agent-service.json `
  -DryRun

.\scripts\release\uninstall_agent_windows_service.ps1 `
  -ServiceMetadata .\dist\agent\0.1.0-local\windows-install\service\oaw-agent-service.json `
  -DryRun
```

The helper writes:

- `dist/agent/<version>/windows-install/ProgramFiles/OpenAssetWatch/Agent/bin/oaw-agent.exe`
- `dist/agent/<version>/windows-install/ProgramData/OpenAssetWatch/Agent/config/config.example.json`
- `dist/agent/<version>/windows-install/ProgramData/OpenAssetWatch/Agent/identity/identity.example.json`
- `dist/agent/<version>/windows-install/ProgramData/OpenAssetWatch/Agent/state/`
- `dist/agent/<version>/windows-install/ProgramData/OpenAssetWatch/Agent/logs/`
- `dist/agent/<version>/windows-install/service/oaw-agent-service.json`
- `dist/agent/<version>/windows-install/windows-install-manifest.json`

The service metadata is staging-only. It records the service name, display
name, executable path, `service run` arguments, automatic startup type, delayed
automatic startup metadata, internal supervisor model, and `LocalService`
account recommendation. It also records that Windows Task Scheduler is not
used. The helper does not
create a service, install a scheduled task, write registry keys, write to real
Program Files or ProgramData paths, or build an MSI.

The validator checks the staged Program Files and ProgramData proof layout,
example config and identity placeholders, service metadata, manifest fields,
staged paths, source artifact checksum metadata, safety notes, and forbidden
service-install, scheduled-task, registry, installer-command, credential,
password, token, API-key, and secret markers. It emits JSON only and does not
create a service, install a scheduled task, write registry keys, write to real
Program Files or ProgramData paths, run service-manager commands, or build an
MSI.

The file helper scripts are not run by the staging helper. Install requires
explicit `-WindowsInstallRoot`, validates the staged layout, requires
administrator rights for real file installation, copies the agent binary to
Program Files, creates ProgramData config, identity, state, and log
directories, copies only example config and identity files, and preserves real
config and identity. The ACL model keeps Program Files read/execute for
`LocalService` but not writable, keeps config and identity administrator
controlled with `LocalService` read access, grants `LocalService` write access
only to state and logs, and avoids broad `Everyone` or Users write grants.
Uninstall requires explicit paths or service metadata, requires administrator
rights for real cleanup, removes only the Program Files agent binary and empty
agent directories when safe, and preserves ProgramData config, identity, state,
and logs unless `-RemoveState` or `-RemoveLogs` is supplied.

The service helper scripts are not run by the staging helper. Install requires
explicit `-InstallRoot` and `-ServiceMetadata`, validates the staged layout and
metadata, requires administrator rights for real service creation, defaults to
the `LocalService` recommendation, and does not start the service unless
`-Start` is supplied. Uninstall requires an explicit service name or service
metadata, requires administrator rights for real service removal, stops the
service only when `-Stop` is supplied, and preserves config and identity by
default. Dry-run mode returns intended actions without creating, starting,
stopping, or removing services.

## Local Windows MSI Artifacts

After building a Windows amd64 agent binary artifact, build and validate an
unsigned local MSI under ignored `dist/` output:

```powershell
.\scripts\release\build_agent_msi.ps1 `
  -Version 0.1.0-local `
  -TargetArch amd64

python .\scripts\release\validate_agent_windows_msi.py `
  --version 0.1.0-local
```

The MSI helper pins WiX Toolset through `.config/dotnet-tools.json` and uses
the matching WiX Util extension during the build. It emits:

- `dist/agent/<version>/packages/OpenAssetWatchAgent-<version>-windows-amd64.msi`
- `.msi.sha256`
- `.msi.manifest.json`

The MSI installs `OpenAssetWatchAgent` as a native Windows service that runs
`oaw-agent.exe service run`, uses the `LocalService` account, registers Event
Log source metadata, enables `NT SERVICE\OpenAssetWatchAgent` service-SID ACLs,
configures bounded service recovery metadata, records delayed automatic startup
metadata, and preserves administrator-managed config, identity, state, and
logs. Unsigned local MSI output is not release-ready.

## Local macOS LaunchDaemon PKG Artifacts

On macOS, build and validate a LaunchDaemon PKG under ignored `dist/` output:

```bash
bash scripts/release/build_agent_macos_pkg.sh \
  --version 0.1.0 \
  --arch-mode universal

python3 scripts/release/validate_agent_macos_install.py \
  --version 0.1.0
```

The macOS PKG helper emits:

- `dist/agent/<version>/darwin-arm64/oaw-agent`
- `dist/agent/<version>/darwin-amd64/oaw-agent`
- `dist/agent/<version>/darwin-universal/oaw-agent` for universal mode
- `dist/agent/<version>/macos-install/`
- `dist/agent/<version>/packages/OpenAssetWatchAgent-<version>-macos-<arch-mode>.pkg`
- `.pkg.sha256`
- `.pkg.manifest.json`

The staged and packaged payload contains:

- `/Library/Application Support/OpenAssetWatch/Agent/bin/oaw-agent`
- `/Library/Application Support/OpenAssetWatch/Agent/config/config.example.json`
- `/Library/Application Support/OpenAssetWatch/Agent/identity/identity.example.json`
- `/Library/Application Support/OpenAssetWatch/Agent/state/`
- `/Library/Logs/OpenAssetWatch/Agent/`
- `/Library/LaunchDaemons/com.openassetwatch.agent.plist`
- `/Library/Application Support/OpenAssetWatch/Agent/install-manifest.json`

The LaunchDaemon runs the supported `oaw-agent service run` command with
explicit config, identity, and state paths under
`/Library/Application Support/OpenAssetWatch/Agent`. It uses the
non-interactive `_openassetwatch` service identity, `RunAtLoad=true`,
`KeepAlive=true`, umask `"027"`, and bounded launchd restart throttling. It does
not package `StartInterval`, `StartCalendarInterval`, shell chaining, active
scanning, or offensive tooling.

The package scripts use target-machine `launchctl` operations only as part of
the PKG install/uninstall lifecycle. They do not contact a backend, store
secrets, overwrite real config or identity, or run package-manager commands.
Unsigned local macOS PKG artifacts are validation artifacts only. Production
release output must be signed, notarized, stapled, and verified with
`sign_notarize_agent_macos.sh` or equivalent release infrastructure. Signed but
not notarized packages are signing-validation artifacts only. macOS PKG receipt
versions are numeric only; prerelease/build suffixes are rejected to avoid
receipt-version collisions. Package manifests default tested minimum macOS
metadata to `15.0` because current CI validates macOS 15 arm64 and Intel
runners, plus universal package installation where supported.

The hosted signed macOS release workflow is intentionally tag/manual only. It
imports base64 Developer ID Application and Developer ID Installer P12 secrets
into a temporary keychain, configures non-interactive access for
`codesign`/`productsign`, verifies both expected identities, materializes an App
Store Connect API key from secrets for `notarytool`, and deletes the keychain,
certificate files, and API key in an `always()` cleanup step. Pull-request CI is
unsigned and secret-free.

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

- `/opt/openassetwatch/agent/bin/oaw-agent`
- `/usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show`
- `/usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show`
- `/usr/bin/oaw-agent`, as a symlink to
  `/opt/openassetwatch/agent/bin/oaw-agent`
- `/etc/openassetwatch/agent/config.example.json`
- `/etc/openassetwatch/agent/identity.example.json`
- `/etc/sudoers.d/openassetwatch-agent`
- `/lib/systemd/system/oaw-agent.service`
- `/lib/systemd/system/oaw-agent.timer`
- `/var/lib/openassetwatch/agent/`
- `/var/log/openassetwatch/agent/`
- `/usr/share/doc/openassetwatch-agent/README.md`
- `/usr/share/doc/openassetwatch-agent/release-manifest.json`

The package control metadata declares `Depends: systemd, passwd`. Because the
agent does not yet provide a long-running daemon command, the systemd runtime
uses a one-shot service triggered by a timer. The service runs the supported
`oaw-agent run-once` command from `/opt/openassetwatch/agent/bin/oaw-agent`
with explicit `/etc/openassetwatch/agent/` config and identity paths plus
`--output-dir /var/lib/openassetwatch/agent`. The unit uses
`ConditionPathExists=` checks, runs as `User=openassetwatch` and
`Group=openassetwatch`, and does not use shell execution. With
`ProtectSystem=strict`, the service allows writes only to
`/var/lib/openassetwatch/agent/` for the `run-once` inventory output. The timer
runs shortly after boot, then hourly with a randomized delay.

The package includes `postinst`, `prerm`, and `postrm` maintainer scripts.
`postinst` may create the `openassetwatch` system group and non-interactive
system user with `/usr/sbin/nologin`, or reuse them only after validating the
primary group, shell, home/state path, and absence of unexpected administrative
group membership. It sets ownership on `/var/lib/openassetwatch/agent/` and
`/var/log/openassetwatch/agent/`, runs `systemctl daemon-reload`, and enables
`oaw-agent.timer` on the target Linux machine when systemd is active.
`postinst` may restart the timer only when both
`/etc/openassetwatch/agent/config.json` and
`/etc/openassetwatch/agent/identity.json` already exist. If either file is
missing, `postinst` does not start or restart the timer or service.

`prerm` stops the timer and any active oneshot service on upgrade/deconfigure,
and on final removal it stops `oaw-agent.timer`, stops `oaw-agent.service` only
if active, disables the timer, removes only the OpenAssetWatch enablement
symlink under `/etc/systemd/system/timers.target.wants/`, and reloads systemd.
`postrm` is limited to daemon-reload cleanup. The scripts preserve
administrator-created config and identity, state, logs, and the
`openassetwatch` service principal by default, including ordinary purge. They
skip runtime service operations cleanly when systemd is not active, but they do
not hide real active-systemd failures with unconditional `|| true`.

Maintainer scripts do not overwrite config or identity, create secrets, execute
arbitrary user-controlled commands, call network services, or grant sudo
permissions beyond the packaged allowlist.

The Debian package includes `/etc/sudoers.d/openassetwatch-agent` as a
root-owned file with mode `0440`. The file applies only to the
`openassetwatch` service user and grants `NOPASSWD` only for two
OpenAssetWatch-owned helper scripts with no arguments:

- `/usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show`, which runs exactly
  `/usr/sbin/ip neigh show` for local kernel neighbor-cache review.
- `/usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show`, which runs exactly
  `/usr/sbin/ip addr show` for local interface and address review.

The sudoers file does not contain `NOPASSWD: ALL`, broad `ALL=(ALL) ALL`
grants, shells, interpreters, downloaders, package managers, service managers,
file mutation commands, offensive tooling, wildcards, or arbitrary arguments.
It does not grant direct sudo access to raw `/usr/sbin/ip` commands. The
initial package intentionally excludes `hostname`, `cat`, `readlink`, and
`stat` because the Go agent currently uses Go APIs and local cache files for
host identity and Linux inventory.

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
identity placeholders, release manifest, required package directories, the
`systemd` and `passwd` dependencies, approved service-account maintainer
scripts, unexpected maintainer files, `/opt` binary layout, `/usr/bin`
compatibility symlink, root-owned libexec helpers, sudoers owner/mode/content,
forbidden content, and path containment. It also checks that `postinst` enables
`oaw-agent.timer`, starts or restarts the timer only when both config and
identity files exist, does not change sudoers, and does not start the service
directly or unconditionally. It verifies that `prerm` stops and disables the
timer on final removal, removes only the OpenAssetWatch timer enablement
symlink, distinguishes upgrade/deconfigure from final removal, and does not
delete config, identity, state, logs, or the service principal. It verifies
that sudoers allows only the helper scripts and no longer allows direct raw
`/usr/sbin/ip` commands. It does not install the package and does not run host
package-manager or service-manager commands.

## Local RPM Package Artifacts

After building a Linux amd64 agent binary artifact, use the RPM helper in a
Linux environment with `rpmbuild` available to generate an unsigned `.rpm`
artifact under ignored `dist/` output:

```powershell
.\scripts\release\build_agent_dist.ps1 `
  -Version 0.1.0-local `
  -TargetOS linux `
  -TargetArch amd64

python .\scripts\release\package_agent_rpm.py `
  --version 0.1.0-local
```

The helper writes:

- `dist/agent/<version>/rpm/BUILD/`
- `dist/agent/<version>/rpm/BUILDROOT/`
- `dist/agent/<version>/rpm/RPMS/`
- `dist/agent/<version>/rpm/SOURCES/`
- `dist/agent/<version>/rpm/SPECS/openassetwatch-agent.spec`
- `dist/agent/<version>/rpm/SRPMS/`
- `dist/agent/<version>/rpm/openassetwatch-agent-<version>-1.x86_64.manifest.json`
- `dist/agent/<version>/packages/openassetwatch-agent-<rpm-version>-1.x86_64.rpm`
- `dist/agent/<version>/packages/openassetwatch-agent-<rpm-version>-1.x86_64.rpm.sha256`
- `dist/agent/<version>/packages/openassetwatch-agent-<rpm-version>-1.x86_64.rpm.manifest.json`

The staged payload lives under:

`dist/agent/<version>/rpm/BUILDROOT/openassetwatch-agent-<version>-1.x86_64/`

The staged RPM payload mirrors the Debian production package model while using
RPM-family systemd paths:

- `/opt/openassetwatch/agent/bin/oaw-agent`
- `/usr/bin/oaw-agent`, as a safe compatibility wrapper to
  `/opt/openassetwatch/agent/bin/oaw-agent`
- `/etc/openassetwatch/agent/config.example.json`
- `/etc/openassetwatch/agent/identity.example.json`
- `/var/lib/openassetwatch/agent/`
- `/var/log/openassetwatch/agent/`
- `/usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show`
- `/usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show`
- `/etc/sudoers.d/openassetwatch-agent`
- `/usr/lib/systemd/system/oaw-agent.service`
- `/usr/lib/systemd/system/oaw-agent.timer`
- `/usr/share/doc/openassetwatch-agent/README.md`
- `/usr/share/doc/openassetwatch-agent/release-manifest.json`

The helper scripts remain root-owned package payload entries and execute only
the approved read-only local commands with no arguments:

- `/usr/sbin/ip neigh show`
- `/usr/sbin/ip addr show`

The staged sudoers file allows only those OpenAssetWatch-owned helper scripts.
It does not grant direct sudo access to raw `/usr/sbin/ip` commands, broad
sudo grants, shell access, interpreter access, downloaders, package managers,
service managers, file mutation commands, offensive tooling, wildcards, or
arbitrary arguments.

The helper invokes `rpmbuild` only to create the local RPM artifact from the
reviewed staging tree. It does not run `rpm -i`, `dnf`, `yum`, `systemctl`,
`service`, `sudo`, package-manager install commands, or service-manager
commands. It does not install software, enable services on the build host,
start services, or write to host `/usr`, `/etc`, `/var`, `/lib`, or `/opt`.

Validate the generated RPM staging tree and final RPM package without
installing it:

```powershell
python .\scripts\release\validate_agent_rpm.py `
  --version 0.1.0-local
```

The validator checks the RPM build tree, spec file, staged `BUILDROOT`
payload, staging manifest, package checksum, package manifest, RPM metadata,
RPM requirements, RPM payload paths, RPM file ownership/modes, RPM
`%config(noreplace)` example metadata, RPM scriptlets, embedded release
manifest, service unit, timer unit, helper scripts, sudoers helper-only
allowlist, example config and identity placeholders, and forbidden content
patterns. It verifies that the package creates or reuses the `openassetwatch`
service user and group only after compatibility checks, enables
`oaw-agent.timer` as target-install scriptlet behavior, includes `%preun`
stop/disable behavior for final erase, distinguishes final erase from upgrade,
does not start `oaw-agent.service` directly or unconditionally, does not delete
config or identity files, avoids unconditional `|| true` around active-systemd
operations, and does not grant broad sudo access. It uses `rpm -qp` inspection
commands only and does not install the RPM.

## Disposable Linux Install Test Guidance

Real install testing for `.deb` and `.rpm` packages must happen only inside a
disposable Linux VM or container with systemd genuinely running. Do not run
install commands on the Windows build host or on a developer workstation that
is not intended to be disposable. Current CI exercises the Debian lifecycle on
the GitHub-hosted Ubuntu runner with active systemd, and the RPM lifecycle in a
privileged Rocky Linux 9 container with systemd as PID 1. Other RPM-family
targets remain package-selection targets until separately tested.

Manual commands for a disposable Debian or Ubuntu test environment only:

```bash
sudo apt install ./openassetwatch-agent_<version>_amd64.deb
test -x /opt/openassetwatch/agent/bin/oaw-agent
test -x /usr/bin/oaw-agent
test -f /etc/openassetwatch/agent/config.example.json
test -f /etc/openassetwatch/agent/identity.example.json
test -f /etc/sudoers.d/openassetwatch-agent
test -f /lib/systemd/system/oaw-agent.service
test -f /lib/systemd/system/oaw-agent.timer
/opt/openassetwatch/agent/bin/oaw-agent paths
systemctl status oaw-agent.service
systemctl status oaw-agent.timer
sudo apt remove openassetwatch-agent
```

These commands are documentation-only guidance for an isolated Linux test
environment. They are not executed by the release scripts. Package install
tests should verify that the package lays down the expected files, enables
`oaw-agent.timer`, starts or restarts the timer only when both real config and
identity files exist, leaves real config and identity creation under
administrator control, runs the one-shot `oaw-agent run-once` service through
the timer, creates only the non-interactive `openassetwatch` service identity,
creates only the narrow documented sudoers allowlist, and cleans up according
to the package lifecycle policy. They should also verify
that `/opt/openassetwatch/agent/bin/oaw-agent`,
`/usr/lib/openassetwatch/agent/libexec/`, and the helper scripts are
root-owned and not writable by `openassetwatch`, while state and logs under
`/var/lib/openassetwatch/agent` and `/var/log/openassetwatch/agent` are
owned by `openassetwatch:openassetwatch`. Downgrade is treated as an explicit
administrator rollback action through native package-manager downgrade flags,
not routine repair. Linux package metadata uses the canonical OpenAssetWatch
Apache-2.0 license declaration and packages license/copyright material for
target hosts.

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
- [x] Debian one-shot `oaw-agent run-once` service packaging
- [x] Debian systemd timer packaging
- [x] guarded Debian timer enablement metadata
- [x] RPM package artifact creation when `rpmbuild` is available
- [x] RPM package checksum generation
- [x] RPM package manifest generation
- [x] RPM one-shot `oaw-agent run-once` service packaging
- [x] RPM systemd timer packaging
- [x] package manifest generation
- [x] local release orchestration helper
- [x] release validation helper
- [x] local install-staging helper
- [x] proof install layout under ignored `dist/staging/`
- [x] local sandbox install helper
- [x] proof local install layout under ignored `dist/local-install/`
- [x] Windows native `oaw-agent service run` runtime
- [x] WiX Toolset MSI build helper
- [x] Windows MSI checksum and manifest generation
- [x] macOS native `oaw-agent service run` LaunchDaemon runtime
- [x] macOS LaunchDaemon install staging and validation
- [x] unsigned macOS PKG build helper
- [x] macOS PKG checksum and manifest generation
- [x] macOS safe uninstall helper

Future work:

- [x] Windows real OS installation path through MSI
- [x] Windows service installation path through MSI
- [x] Windows service runtime
- [x] macOS real OS installation path through PKG
- [x] macOS LaunchDaemon installation path through PKG
- [x] macOS service runtime
- [ ] Linux real OS installation path to `/usr`, `/etc`, and `/var`
- [ ] cross-platform service scheduling beyond the packaged Linux timer
- [ ] signed `.deb` release publication and install validation
- [x] unsigned `.rpm` package build helper
- [ ] signed `.rpm` release publication and install validation
- [x] Windows MSI
- [x] macOS unsigned PKG validation artifact
- [ ] production signed Windows release publication
- [ ] production signed/notarized macOS release publication
- [ ] package-manager execution by local release helpers
- [ ] service-manager execution by local release helpers beyond packaged,
  guarded Debian and macOS package-script behavior
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
