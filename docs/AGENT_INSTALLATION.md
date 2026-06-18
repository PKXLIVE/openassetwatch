# Agent Installation Lifecycle

This document defines the future OpenAssetWatch agent installation,
uninstallation, upgrade, rollback, package validation, and deployment
lifecycle before any installer, service install, service uninstall, daemon,
scheduler, or self-update code exists.

Current state: `oaw-agent` is an explicit command-line tool. It can inspect
paths, create non-secret config and identity files, run local diagnostics,
preview future service plans/templates, check in, collect passive local
inventory, and submit that inventory. It does not install itself, modify
service managers, execute package managers, schedule itself, or run as a
background service.

## Supported Future Deployment Models

OpenAssetWatch should support several deployment models without changing the
agent's safe-by-default runtime posture:

- manual binary install for lab, self-hosted, or break-glass environments
- Windows signed installer or MSI
- Linux `.deb` package for Debian and Ubuntu families
- Linux `.rpm` package for RHEL, Rocky Linux, AlmaLinux, CentOS, Fedora, SUSE,
  and openSUSE families
- Linux `.tar.gz` fallback for unsupported distributions or manual install
- macOS signed and notarized package
- enterprise deployment through Intune, SCCM, Jamf, Ansible, Puppet, Chef, and
  shell-based deployment systems

Enterprise deployment tools should run under explicit administrator control.
The running agent must not become a package-manager wrapper, deployment tool,
or self-installing process.

## Expected Installed Paths

These paths are planning targets. Future packages may refine them per operating
system, but any change should preserve clear separation between binary,
configuration, identity, logs, and service metadata.

### Windows

- binary path: `C:\Program Files\OpenAssetWatch\oaw-agent.exe`
- config path: `%ProgramData%\OpenAssetWatch\agent\config.json`
- identity path: `%ProgramData%\OpenAssetWatch\agent\identity.json`
- log directory: `%ProgramData%\OpenAssetWatch\agent\logs\`
- status file path: `%ProgramData%\OpenAssetWatch\agent\logs\status.json`
- service name: `OpenAssetWatchAgent`
- service definition path: Windows Service Control Manager metadata, managed by
  a future signed installer or administrator action rather than a direct file
- package metadata path: Windows Installer product database, plus any future
  non-secret installer manifest under `%ProgramData%\OpenAssetWatch\agent\`

### Linux Systemd

- binary path: `/usr/bin/oaw-agent`
- config path: `/etc/openassetwatch/agent/config.json`
- identity path: `/etc/openassetwatch/agent/identity.json`
- log directory: `/var/log/openassetwatch/agent/`
- status file path: `/var/log/openassetwatch/agent/status.json`
- service name: `openassetwatch-agent`
- service definition path:
  `/etc/systemd/system/openassetwatch-agent.service`
- `.deb` package metadata: dpkg database under `/var/lib/dpkg/status` and
  package file records under `/var/lib/dpkg/info/openassetwatch-agent.*`
- `.rpm` package metadata: rpm database under `/var/lib/rpm/` or
  `/usr/lib/sysimage/rpm/`, depending on the distribution
- `.tar.gz` fallback metadata: no package-manager metadata by default; a future
  non-secret manifest may be written only by explicit installer/admin action

### macOS Launchd

- binary path: `/usr/local/bin/oaw-agent`
- config path: `/etc/openassetwatch/agent/config.json`
- identity path: `/etc/openassetwatch/agent/identity.json`
- log directory: `/var/log/openassetwatch/agent/`
- status file path: `/var/log/openassetwatch/agent/status.json`
- service name: `com.openassetwatch.agent`
- service definition path:
  `/Library/LaunchDaemons/com.openassetwatch.agent.plist`
- package metadata path:
  `/var/db/receipts/com.openassetwatch.agent.*`

## Linux Package Selection

Linux package selection should use read-only distribution detection before
choosing an artifact or instructions. Start with `/etc/os-release` and inspect:

- `ID`
- `ID_LIKE`
- `VERSION_ID`

Conservative package mapping:

- Debian and Ubuntu map to `.deb`.
- RHEL, Rocky Linux, AlmaLinux, CentOS, and Fedora map to `.rpm`.
- SUSE and openSUSE map to `.rpm`.
- Unknown or unsupported Linux distributions map to `.tar.gz` or manual
  install instructions.

Package-manager commands require explicit administrator action. The running
agent must not execute `apt`, `dnf`, `yum`, `zypper`, `rpm`, `dpkg`, or any
other package-manager command on its own.

## Package Scaffold

The future package layout scaffold lives under
[packaging/agent](../packaging/agent/README.md). It contains documentation,
release checklists, OS package mapping, and non-executable manifest templates
for Windows MSI, Linux `.deb`, Linux `.rpm`, Linux `.tar.gz`, and macOS package
planning.

The scaffold is text and YAML only. It does not build packages, install
software, uninstall software, start services, stop services, modify service
managers, execute package managers, or create files outside the repository.

Package planning references:

- [Agent package scaffold](../packaging/agent/README.md)
- [Release artifact checklist](../packaging/agent/release-checklist.md)
- [OS package mapping](../packaging/agent/os-package-mapping.md)

## Read-Only Install Plan

Use the local install plan command to inspect the recommended package and
deployment approach before selecting an installer or package:

```powershell
go run ./cmd/oaw-agent install plan
```

`install plan` writes JSON only. It reports the current operating system,
architecture, recommended package type, install model, expected binary path,
config path, identity path, log directory, status file path, service definition
path where known, package validation expectations, and warnings.

On Linux, the command may read `/etc/os-release` and use `ID`, `ID_LIKE`, and
`VERSION_ID` to recommend `deb`, `rpm`, or `tar.gz/manual`. On Windows, it
recommends a signed MSI or enterprise deployment. On macOS, it recommends a
signed and notarized package.

This command is read-only. It does not create files or directories, install
packages, execute package-manager commands, execute service-manager commands,
modify services, contact a backend, or print secrets.

## Install Lifecycle

Future installer or administrator flow:

1. Verify artifact signature and checksum before execution or extraction.
2. Install the signed binary or package using an administrator-controlled
   process.
3. Create non-secret config with `server_url` and `site_id`.
4. Create local identity with `site_id`, optional `tenant_id`, optional
   deployment-provided `deployment_id`, and generated `agent_id`.
5. Run `oaw-agent doctor`.
6. Run `oaw-agent check-in`.
7. Run `oaw-agent status`.
8. Review `oaw-agent install plan`.
9. Review `oaw-agent service plan`.
10. Review `oaw-agent service template`.
11. Only after the above checks pass, proceed to future service installation
    through a signed installer or explicit administrator action.

Installers must not store enrollment tokens, API keys, passwords, signing
keys, license keys, or other secrets in config, identity, logs, or examples.

## Uninstall Lifecycle

Future uninstaller or administrator flow:

1. Stop the service if service mode exists in the future.
2. Remove the service definition if service mode exists in the future.
3. Remove the binary or package.
4. Preserve config, identity, and logs by default.
5. Optionally remove config, identity, and logs only when an administrator
   explicitly requests data removal.
6. Record the uninstall result in an administrator-visible audit or package log
   where available.

Identity and config files must never be deleted by default without explicit
administrator action. Logs may contain operational metadata and should follow
the organization's retention and privacy policy.

## Upgrade Lifecycle

Future upgrade flow:

1. Verify the new artifact signature and checksum.
2. Stop the service if service mode exists in the future.
3. Replace the binary or package through an administrator-controlled process.
4. Preserve config and identity.
5. Preserve logs unless an administrator explicitly chooses a retention change.
6. Run `oaw-agent doctor`.
7. Run `oaw-agent check-in`.
8. Run `oaw-agent status`.
9. Start the service if service mode exists in the future.
10. Record the upgrade result and installed version.

Upgrade must not silently rotate identity, overwrite config, or erase logs.

## Rollback Lifecycle

Future rollback flow:

1. Retain the previous known-good signed package or binary.
2. Stop the service if service mode exists in the future.
3. Restore the previous binary or package through an administrator-controlled
   process.
4. Preserve config and identity.
5. Preserve logs unless an administrator explicitly chooses a retention change.
6. Run `oaw-agent doctor`.
7. Run `oaw-agent status`.
8. Run `oaw-agent check-in`.
9. Start the service if service mode exists in the future.
10. Document the rollback result, version, reason, and operator.

Rollback should restore executable behavior without changing tenant, site,
deployment, or agent identity.

## Package Validation

Before install, upgrade, or rollback:

- verify the artifact signature using the release channel's trusted signing
  identity
- verify the checksum against a trusted release manifest
- confirm the artifact name, version, operating system, and architecture match
  the intended deployment
- confirm the artifact came from an approved release pipeline
- confirm no signing keys, enrollment tokens, license keys, API keys, or
  passwords are present in repository examples or generated config
- review the future release checklist in
  [packaging/agent/release-checklist.md](../packaging/agent/release-checklist.md)
  before adding package build automation

Signing keys must remain in CI/CD secret stores or signing infrastructure. They
must not be committed to the repository or copied into installer examples.

## Local Install Staging

Use the local install-staging helper to validate an existing local TAR.GZ
package and expand it into a repo-local proof layout:

```powershell
python .\scripts\release\stage_agent_install.py `
  --version 0.1.0-local
```

The default staging root is:

`dist/staging/agent/<version>/<os>-<arch>/`

The staged layout contains:

- `binary/`
- `config/`
- `identity/`
- `logs/`
- `status/`
- `service/`
- `package-metadata/`

This is not a real system install. It proves the future installed layout
without writing to Program Files, ProgramData, `/usr`, `/etc`, `/var`,
`/Library`, service-manager paths, or package-manager metadata paths. The
helper does not create real config values, identity values, logs, runtime
status files, service definitions, tokens, credentials, or secrets.

## Local Sandbox Install Proof

Use the local sandbox install helper to copy a validated staged layout or
TAR.GZ package into a repo-local install proof:

```powershell
python .\scripts\release\install_agent_local.py `
  --version 0.1.0-local
```

The helper can also consume an explicit package or staged layout:

```powershell
python .\scripts\release\install_agent_local.py `
  --package dist\agent\0.1.0-local\packages\openassetwatch-agent-0.1.0-local-windows-amd64.tar.gz

python .\scripts\release\install_agent_local.py `
  --staging-dir dist\staging\agent\0.1.0-local\windows-amd64
```

The default install root is:

`dist/local-install/agent/<version>/<os>-<arch>/`

The local install proof contains:

- `binary/`
- `config/`
- `identity/`
- `logs/`
- `status/`
- `service/`
- `package-metadata/`

This completes the local installation proof path without touching real system
paths. The helper refuses install roots outside the repository. It does not
write to Program Files, ProgramData, `/usr`, `/etc`, `/var`, `/Library`,
service-manager paths, or package-manager metadata paths. It does not create
real config values, identity values, logs, runtime status files, service
definitions, tokens, credentials, or secrets.

## Local Sandbox Uninstall Proof

Use the local sandbox uninstall helper to remove only a repo-local sandbox
install proof:

```powershell
python .\scripts\release\uninstall_agent_local.py `
  --version 0.1.0-local
```

The helper removes only install roots shaped like:

`dist/local-install/agent/<version>/<os>-<arch>/`

It can also remove an explicit repo-local sandbox install root:

```powershell
python .\scripts\release\uninstall_agent_local.py `
  --install-root dist\local-install\agent\0.1.0-local\windows-amd64
```

By default, the helper requires expected package metadata produced by the local
install helper. `--force` may remove an incomplete repo-local sandbox install
root, but it still refuses paths outside the repository and paths that look
like Program Files, ProgramData, `/usr`, `/etc`, `/var`, or `/Library`.

This is not a real system uninstall. It does not remove generated release
packages, unregister services, start services, stop services, execute
package-manager commands, execute service-manager commands, delete config,
identity, logs, or status outside the sandbox install root, or modify the host
operating system.

## Local Sandbox Upgrade And Rollback Proof

Use the local sandbox upgrade and rollback helper to prove version transitions
inside ignored repo-local `dist/` paths:

```powershell
python .\scripts\release\upgrade_agent_local.py upgrade `
  --from-version 0.1.0-local `
  --to-version 0.1.1-local

python .\scripts\release\upgrade_agent_local.py rollback `
  --from-version 0.1.1-local `
  --to-version 0.1.0-local
```

The helper operates only under:

- `dist/local-install/agent/`
- `dist/agent/`
- `dist/staging/agent/`

Upgrade validates the target local release package, writes backup metadata
under ignored `dist/local-install/agent/_backups/`, and creates a new local
sandbox install root for the target version. Rollback validates the previous
local release package and restores the previous version into a local sandbox
install root. Both modes preserve only sandbox placeholder directories for
config and identity; they do not create real config values or identity values.

This is not a real system upgrade or rollback. It does not remove generated
release packages, write to Program Files, ProgramData, `/usr`, `/etc`, `/var`,
or `/Library`, modify services, execute package-manager commands, execute
service-manager commands, contact network services, remove config, identity,
logs, or status outside the sandbox install root, or modify the host operating
system.

## Agent Installation Foundation Status

The current phase proves that OpenAssetWatch can build, package, validate, and
stage an agent release safely without modifying the host operating system.

Complete for this phase:

- [x] agent dist artifact generation
- [x] SHA256 checksum generation
- [x] binary manifest generation
- [x] TAR.GZ package creation
- [x] TAR.GZ checksum generation
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
- [ ] `.deb` package build
- [ ] `.rpm` package build
- [ ] Windows MSI
- [ ] macOS signed/notarized package
- [ ] package-manager execution
- [ ] service-manager execution
- [ ] self-update
- [ ] licensing enforcement

## Safety Boundaries

The future installation lifecycle must preserve OpenAssetWatch's defensive
agent posture:

- no silent self-install
- no silent self-upgrade
- no package-manager execution by the running agent
- no deletion of identity, config, or logs without explicit administrator
  action
- no secrets in logs
- no raw config or identity dumps in logs
- no active scanning by default
- no offensive tooling
- no arbitrary shell command execution
- no service-manager modification by `doctor`, `status`, `service plan`, or
  `service template`
- no scheduler behavior until separately designed and reviewed

The agent may report local state and produce read-only plans/templates. Future
installers, enterprise deployment systems, or administrators must perform any
host-modifying package or service actions explicitly.

## Related Docs

- [Agent Lifecycle](AGENT_LIFECYCLE.md)
- [Agent Check-In](AGENT_CHECKIN.md)
- [Agent Collection](AGENT_COLLECTION.md)
- [Deployment Sizing](DEPLOYMENT_SIZING.md)
- [Local E2E Validation](LOCAL_E2E.md)
- [Installers](INSTALLERS.md)
- [Signed Releases](SIGNED_RELEASES.md)
- [Release Pipeline](RELEASE_PIPELINE.md)
- [Agent Package Scaffold](../packaging/agent/README.md)
