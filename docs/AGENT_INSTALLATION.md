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

- binary path: `/opt/openassetwatch/agent/bin/oaw-agent`
- compatibility command path: `/usr/bin/oaw-agent`, as a package-managed
  symlink to `/opt/openassetwatch/agent/bin/oaw-agent`
- config path: `/etc/openassetwatch/agent/config.json`
- identity path: `/etc/openassetwatch/agent/identity.json`
- log directory: `/var/log/openassetwatch/agent/`
- status file path: `/var/log/openassetwatch/agent/status.json`
- service name: `oaw-agent`
- service definition path:
  `/lib/systemd/system/oaw-agent.service` for the Debian package
- timer definition path:
  `/lib/systemd/system/oaw-agent.timer` for the Debian package
- RPM-family service definition path:
  `/usr/lib/systemd/system/oaw-agent.service`
- RPM-family timer definition path:
  `/usr/lib/systemd/system/oaw-agent.timer`
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

## Local Debian Package Artifact

Use the local Debian helper to build an unsigned Linux amd64 `.deb` artifact
from an existing Linux agent dist artifact:

```powershell
.\scripts\release\build_agent_dist.ps1 `
  -Version 0.1.0-local `
  -TargetOS linux `
  -TargetArch amd64

python .\scripts\release\package_agent_deb.py `
  --version 0.1.0-local
```

The helper writes only under ignored `dist/` output:

- `dist/agent/<version>/packages/openassetwatch-agent_<version>_amd64.deb`
- `dist/agent/<version>/packages/openassetwatch-agent_<version>_amd64.deb.sha256`
- `dist/agent/<version>/packages/openassetwatch-agent_<version>_amd64.deb.manifest.json`

The package archive is intended to contain:

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

The package control metadata declares Linux runtime/service dependencies on
`systemd` and `passwd`. The packaged systemd runtime uses the safest
production model available today: a one-shot service triggered by a systemd
timer. The service runs only:

`/opt/openassetwatch/agent/bin/oaw-agent run-once --config /etc/openassetwatch/agent/config.json --identity-file /etc/openassetwatch/agent/identity.json --output-dir /var/lib/openassetwatch/agent`

The unit includes `ConditionPathExists=` checks for both required real config
and identity files. It does not include shell execution, arbitrary command
execution, service start hooks, network calls, or embedded secrets. It runs as
`User=openassetwatch` and `Group=openassetwatch`; no long-running daemon
command is invented in this package phase. With `ProtectSystem=strict`, the
unit allows writes only to `/var/lib/openassetwatch/agent/` for the
`run-once` inventory output. The timer runs shortly after boot, then
periodically with conservative hourly cadence and randomized delay.

The package may include conservative `postinst` and `postrm` maintainer
scripts. The `postinst` script may create the `openassetwatch` system group and
non-interactive `openassetwatch` system user with `/usr/sbin/nologin`, set
ownership on `/var/lib/openassetwatch/agent/` and
`/var/log/openassetwatch/agent/`, run `systemctl daemon-reload`, and enable
`oaw-agent.timer` on the target Linux machine. It may restart the timer only
when both `/etc/openassetwatch/agent/config.json` and
`/etc/openassetwatch/agent/identity.json` already exist. If either file is
missing, `postinst` must not start or restart the timer or service. The `postrm` script
is limited to `systemctl daemon-reload`; it must not delete administrator-made
config or identity files, remove the `openassetwatch` user or group, or call
network services. Maintainer scripts must not overwrite config, overwrite
identity, create secrets, execute administrator-provided commands, or grant
sudo permissions beyond the packaged allowlist.

The package includes a root-owned sudoers file at
`/etc/sudoers.d/openassetwatch-agent` with mode `0440`. The file applies only
to the `openassetwatch` service user and grants `NOPASSWD` only for two
OpenAssetWatch-owned helper scripts with no arguments:

- `/usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show`: runs exactly
  `/usr/sbin/ip neigh show` to read the local kernel neighbor cache. It does
  not accept arguments and does not scan networks.
- `/usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show`: runs exactly
  `/usr/sbin/ip addr show` to read local interface and address metadata. It
  does not accept arguments and does not scan networks.

The sudoers file must not include `NOPASSWD: ALL`, broad `ALL=(ALL) ALL`
grants, shells, interpreters, downloaders, package managers, service managers,
file modification commands, offensive tooling, command wildcards, or arbitrary
arguments. It must not grant direct sudo access to raw `/usr/sbin/ip`
commands. Commands such as `hostname`, `cat`, `readlink`, and `stat` are not
included in the initial agent package allowlist because the Go agent currently
uses Go APIs and local cache files for host identity and Linux inventory.

Package ownership expectations:

- `/opt/openassetwatch/` and package-managed paths below it are owned by
  `openassetwatch:openassetwatch`.
- `/usr/lib/openassetwatch/agent/libexec/` and the privileged helper scripts
  are owned by `root:root` and are not writable by `openassetwatch`.
- `/var/lib/openassetwatch/agent/` is owned by
  `openassetwatch:openassetwatch`.
- `/var/log/openassetwatch/agent/` is owned by
  `openassetwatch:openassetwatch`.
- `/etc/openassetwatch/agent/` remains root-controlled, with readable example
  placeholder files only.
- `/etc/sudoers.d/openassetwatch-agent` remains root-controlled and uses mode
  `0440`.

This is package artifact generation, not host installation. The helper does
not run `dpkg`, `apt`, `systemctl`, `service`, `sudo`, package-manager
commands, or service-manager commands. It does not install software, enable
services, start services, write to host `/usr`, `/etc`, `/var`, `/lib`, `/opt`,
or create real config values, real identity values, logs, runtime status,
tokens, credentials, API keys, or secrets.

Validate the generated `.deb` artifact without installing it:

```powershell
python .\scripts\release\validate_agent_deb.py `
  --version 0.1.0-local
```

The validator inspects the existing package under `dist/agent/<version>/`,
verifies the package checksum and manifest, checks expected Debian archive
members and install paths, confirms example config and identity placeholders,
checks the service unit, validates the `systemd` dependency, validates the
`passwd` dependency, validates the service-account maintainer scripts, rejects
unexpected maintainer files, confirms the `/opt` binary plus `/usr/bin`
compatibility symlink, verifies service user/group settings, and looks for
forbidden package content. It also validates the sudoers path, owner, mode,
user scope, exact command allowlist, and absence of broad sudo grants. It
checks that `postinst` enables `oaw-agent.timer`, only restarts the timer when
both real config and identity files are present, and never starts the service
directly. It also verifies that `postrm` is limited to daemon-reload cleanup
and does not delete admin-managed identity or config files. It does not install
the package or run host package-manager or service-manager commands.

## Local RPM Spec Staging

Use the local RPM staging helper to prepare an RPM build tree, spec file, and
staged payload from an existing Linux amd64 agent dist artifact:

```powershell
.\scripts\release\build_agent_dist.ps1 `
  -Version 0.1.0-local `
  -TargetOS linux `
  -TargetArch amd64

python .\scripts\release\package_agent_rpm.py `
  --version 0.1.0-local
```

The helper writes only under ignored `dist/` output:

- `dist/agent/<version>/rpm/BUILD/`
- `dist/agent/<version>/rpm/BUILDROOT/`
- `dist/agent/<version>/rpm/RPMS/`
- `dist/agent/<version>/rpm/SOURCES/`
- `dist/agent/<version>/rpm/SPECS/openassetwatch-agent.spec`
- `dist/agent/<version>/rpm/SRPMS/`
- `dist/agent/<version>/rpm/openassetwatch-agent-<version>-1.x86_64.manifest.json`

The staged payload root is:

`dist/agent/<version>/rpm/BUILDROOT/openassetwatch-agent-<version>-1.x86_64/`

The staged payload mirrors the Debian production package model:

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

The generated spec models the same conservative service and timer behavior:
`oaw-agent.service` is a one-shot `run-once` service, `oaw-agent.timer` uses
the conservative boot and hourly cadence, and the timer starts only on a
target system with real config and identity files present. The staged helper
scripts remain root-owned under `/usr/lib/openassetwatch/agent/libexec/`, and
the staged sudoers file allows only those helpers. No direct raw
`/usr/sbin/ip` sudo rules are staged.

This helper does not build an RPM file and does not run `rpm`, `rpmbuild`,
`dnf`, `yum`, `systemctl`, `service`, `sudo`, package-manager commands, or
service-manager commands. It does not install software, enable services, start
services, write to host `/usr`, `/etc`, `/var`, `/lib`, `/opt`, or create real
config values, real identity values, logs, runtime status, tokens,
credentials, API keys, or secrets.

## Disposable Linux Install Test Guidance

Install testing for `.deb` packages should happen only inside a disposable
Linux VM or container. Do not run install commands on the Windows build host or
on a non-disposable developer workstation.

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

Expected checks inside the disposable Linux environment:

- package files exist at the documented paths
- package artifact creation did not enable or start services on the build host
- package installation enables `oaw-agent.timer` on the disposable Linux
  target
- package installation starts or restarts the timer only when both real
  config and identity files already exist
- the timer triggers the one-shot `oaw-agent run-once` service
- real config and identity files are not created without administrator action
- the service account is non-interactive
- the sudoers file contains only the documented OpenAssetWatch helper scripts
  with no arguments and no broad sudo grants
- sudoers does not grant direct access to raw `/usr/sbin/ip` commands
- no tokens, credentials, API keys, logs, runtime status, or secrets are
  present in package examples
- cleanup removes package-managed files while preserving administrator-owned
  data according to future package lifecycle policy

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
- [x] Debian package artifact creation
- [x] Debian package checksum generation
- [x] Debian package manifest generation
- [x] Debian one-shot `oaw-agent run-once` service packaging
- [x] Debian systemd timer packaging
- [x] guarded Debian timer enablement metadata
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
- [ ] long-running daemon or service runtime
- [ ] cross-platform service scheduling beyond the packaged Linux timer
- [ ] signed `.deb` release publication and install validation
- [ ] `.rpm` package build
- [ ] Windows MSI
- [ ] macOS signed/notarized package
- [ ] package-manager execution by local release helpers
- [ ] service-manager execution by local release helpers beyond packaged,
  guarded Debian maintainer-script behavior
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
