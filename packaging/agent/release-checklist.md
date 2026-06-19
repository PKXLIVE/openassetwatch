# Agent Release Artifact Checklist

This checklist defines the future release artifact gates for OpenAssetWatch
agent packages. It is not an implementation and does not build, sign, install,
uninstall, upgrade, roll back, or publish anything.

## Build Inputs

- [ ] version is selected from an approved release channel
- [ ] source commit is reviewed and tagged according to release policy
- [ ] Go agent binary build is reproducible for each supported OS/architecture
- [ ] local `dist/` binary artifact generated with
      `scripts/release/build_agent_dist.ps1` where appropriate
- [ ] package manifest template is selected for the target OS
- [ ] no secrets are present in manifests, docs, config examples, or artifacts

## Binary Artifact Metadata

- [ ] artifact is written under ignored `dist/agent/<version>/<os>-<arch>/`
- [ ] artifact name is `oaw-agent` or `oaw-agent.exe` on Windows
- [ ] SHA256 checksum file is generated
- [ ] JSON manifest is generated
- [ ] manifest includes artifact name, version, OS, architecture,
      repo-relative path, SHA256, build timestamp, and git commit when
      available
- [ ] generated `dist/` artifacts are not committed
- [ ] local binary generation does not build installers or native packages

## TAR.GZ Package Metadata

- [ ] source artifact directory exists under
      `dist/agent/<version>/<os>-<arch>/`
- [ ] source artifact directory contains exactly one binary manifest
- [ ] source artifact checksum matches the binary manifest
- [ ] TAR.GZ package is written under ignored
      `dist/agent/<version>/packages/`
- [ ] package SHA256 checksum file is generated
- [ ] package manifest is generated
- [ ] package manifest includes package name, version, OS, architecture,
      package type, source artifact path, package path, SHA256, build
      timestamp, and git commit when available
- [ ] archive contains only the agent binary, binary checksum, binary manifest,
      and safe README notes
- [ ] archive does not include config files, identity files, enrollment tokens,
      credentials, logs, status files, service definitions, or generated
      secrets

## Release Validation

- [ ] `scripts/release/validate_agent_release.ps1` passes for the selected
      version
- [ ] validation output is JSON only
- [ ] binary artifact directories exist
- [ ] binary SHA256 checksum files match binaries and manifests
- [ ] binary manifests contain required fields
- [ ] package validation runs with `-IncludePackages` when TAR.GZ output is
      expected
- [ ] TAR.GZ package checksums match packages and manifests
- [ ] TAR.GZ package manifests contain required fields
- [ ] TAR.GZ archives do not contain config files, identity files, enrollment
      tokens, credentials, logs, status files, service definitions, or
      generated secrets
- [ ] generated `dist/` artifacts remain ignored and are not committed

## Windows Install Layout Staging

- [ ] `scripts/release/stage_agent_windows_install.py` passes against an
      existing Windows amd64 dist artifact
- [ ] helper output is JSON only
- [ ] helper output includes `ok`, `version`, `windows_install_root`,
      `manifest`, `checks`, `warnings`, and `errors`
- [ ] Windows staging output is written only under ignored
      `dist/agent/<version>/windows-install/`
- [ ] staged Program Files layout includes
      `ProgramFiles/OpenAssetWatch/Agent/bin/oaw-agent.exe`
- [ ] staged ProgramData layout includes
      `ProgramData/OpenAssetWatch/Agent/config/config.example.json`
- [ ] staged ProgramData layout includes
      `ProgramData/OpenAssetWatch/Agent/identity/identity.example.json`
- [ ] staged ProgramData layout includes
      `ProgramData/OpenAssetWatch/Agent/state/`
- [ ] staged ProgramData layout includes
      `ProgramData/OpenAssetWatch/Agent/logs/`
- [ ] staged service metadata exists at
      `service/oaw-agent-service.json`
- [ ] service metadata uses service name `OpenAssetWatchAgent`
- [ ] service metadata uses display name `OpenAssetWatch Agent`
- [ ] service metadata executable path is
      `C:\Program Files\OpenAssetWatch\Agent\bin\oaw-agent.exe`
- [ ] service metadata arguments use `run-once` with explicit ProgramData
      config, identity, and state paths
- [ ] service metadata startup type is `automatic`
- [ ] service account recommendation is `LocalService`
- [ ] service metadata records that no service or scheduled task is installed
      by the helper
- [ ] service metadata contains no embedded account secrets, tokens, or
      passwords
- [ ] manifest exists at `windows-install-manifest.json`
- [ ] manifest records version, architecture, staged paths, source artifact
      checksum, service metadata, safety notes, and generation timestamp
- [ ] helper does not run `sc.exe create`, `New-Service`, `Start-Service`,
      `Stop-Service`, `msiexec`, installer commands, service manager commands,
      or registry writes
- [ ] helper does not write to real Program Files or ProgramData paths
- [ ] helper does not build an MSI
- [ ] generated `dist/` artifacts remain ignored and are not committed

## Windows Install Layout Validation

- [ ] `scripts/release/validate_agent_windows_install.py` passes against the
      selected staged Windows install layout
- [ ] validator supports `--version`
- [ ] validator supports optional `--windows-install-root`
- [ ] validator output is JSON only
- [ ] validator output includes `ok`, `version`, `windows_install_root`,
      `checks`, `warnings`, and `errors`
- [ ] validator inspects `dist/agent/<version>/windows-install/`
- [ ] validator confirms staged
      `ProgramFiles/OpenAssetWatch/Agent/bin/oaw-agent.exe` exists
- [ ] validator confirms staged
      `ProgramData/OpenAssetWatch/Agent/config/config.example.json` exists
- [ ] validator confirms staged
      `ProgramData/OpenAssetWatch/Agent/identity/identity.example.json` exists
- [ ] validator confirms staged
      `ProgramData/OpenAssetWatch/Agent/state/` exists
- [ ] validator confirms staged
      `ProgramData/OpenAssetWatch/Agent/logs/` exists
- [ ] validator confirms `service/oaw-agent-service.json` exists
- [ ] validator confirms `windows-install-manifest.json` exists
- [ ] validator confirms service metadata uses service name
      `OpenAssetWatchAgent`
- [ ] validator confirms service metadata uses display name
      `OpenAssetWatch Agent`
- [ ] validator confirms service metadata executable path is
      `C:\Program Files\OpenAssetWatch\Agent\bin\oaw-agent.exe`
- [ ] validator confirms service metadata arguments use `run-once` with
      explicit ProgramData config, identity, and state paths
- [ ] validator confirms startup type is `automatic`
- [ ] validator confirms service account recommendation is `LocalService`
- [ ] validator confirms service and scheduled-task recommendations are
      metadata only and install nothing
- [ ] validator confirms the manifest includes version, architecture, staged
      paths, source artifact checksum, service metadata, safety notes, and
      generation timestamp
- [ ] validator rejects missing service metadata
- [ ] validator rejects an unexpected executable path
- [ ] validator rejects credential, password, token, API-key, and secret
      markers
- [ ] validator rejects service-install, scheduled-task, registry,
      service-manager, and installer-command markers
- [ ] validator does not create a service, install a scheduled task, modify
      the registry, write to real Program Files or ProgramData paths, run
      installer commands, or build an MSI
- [ ] generated `dist/` artifacts remain ignored and are not committed

## Windows Service Helper Validation

- [ ] `scripts/release/install_agent_windows_service.ps1` parses cleanly
- [ ] `scripts/release/uninstall_agent_windows_service.ps1` parses cleanly
- [ ] install helper requires explicit `-InstallRoot`
- [ ] install helper requires explicit `-ServiceMetadata`
- [ ] install helper validates staged `oaw-agent.exe`
- [ ] install helper validates staged config and identity directories
- [ ] install helper reads `service/oaw-agent-service.json`
- [ ] install helper validates service name `OpenAssetWatchAgent`
- [ ] install helper validates display name `OpenAssetWatch Agent`
- [ ] install helper validates the approved `run-once` command arguments
- [ ] install helper uses automatic startup metadata
- [ ] install helper uses the `LocalService` account recommendation
- [ ] install helper does not accept credentials or passwords
- [ ] install helper supports `-DryRun`
- [ ] install helper requires administrator rights for real service creation
- [ ] install helper does not start the service unless `-Start` is explicitly
      supplied
- [ ] uninstall helper requires explicit `-ServiceName` or `-ServiceMetadata`
- [ ] uninstall helper supports `-DryRun`
- [ ] uninstall helper requires administrator rights for real service removal
- [ ] uninstall helper stops the service only when `-Stop` is explicitly
      supplied
- [ ] uninstall helper removes only the service entry
- [ ] uninstall helper preserves config and identity by default
- [ ] optional `-RemoveState` is limited to staged or test cleanup
- [ ] helper dry-runs return JSON only and do not create, start, stop, or
      remove services
- [ ] helpers do not run `msiexec`
- [ ] helpers do not modify the registry directly
- [ ] helpers do not embed credentials, passwords, tokens, API keys, or
      secrets
- [ ] Windows install validator confirms helper presence, dry-run support,
      admin checks, no default auto-start, config/identity preservation, and
      absence of unsafe registry or secret patterns

## Windows File Helper Validation

- [ ] `scripts/release/install_agent_windows_files.ps1` parses cleanly
- [ ] `scripts/release/uninstall_agent_windows_files.ps1` parses cleanly
- [ ] file install helper requires explicit `-WindowsInstallRoot`
- [ ] file install helper validates the staged Windows install layout
- [ ] file install helper validates staged `oaw-agent.exe`
- [ ] file install helper validates `config.example.json`
- [ ] file install helper validates `identity.example.json`
- [ ] file install helper validates `service/oaw-agent-service.json`
- [ ] file install helper supports `-DryRun`
- [ ] file install helper requires administrator rights for real file install
- [ ] file install helper copies the binary only to
      `C:\Program Files\OpenAssetWatch\Agent\bin\oaw-agent.exe`
- [ ] file install helper creates only approved ProgramData config, identity,
      state, and log directories
- [ ] file install helper copies only example config and identity files
- [ ] file install helper does not create real `config.json`
- [ ] file install helper does not create real `identity.json`
- [ ] file install helper preserves real config and identity if present
- [ ] file install helper defines ACL expectations:
      Program Files not writable by `LocalService`, Program Files binary
      read/execute for `LocalService`, config and identity
      administrator-controlled with `LocalService` read access, state and logs
      writable by `LocalService`, Administrators and SYSTEM full control, and
      no broad `Everyone` or Users write access
- [ ] file uninstall helper requires explicit paths or service metadata
- [ ] file uninstall helper supports `-DryRun`
- [ ] file uninstall helper requires administrator rights for real file cleanup
- [ ] file uninstall helper removes the Program Files agent binary and empty
      agent directories only when safe
- [ ] file uninstall helper preserves ProgramData config and identity by
      default
- [ ] file uninstall helper preserves state and logs by default
- [ ] file uninstall helper supports explicit `-RemoveState`
- [ ] file uninstall helper supports explicit `-RemoveLogs`
- [ ] file uninstall helper refuses destructive cleanup outside
      OpenAssetWatch paths
- [ ] file helper dry-runs return JSON only and do not copy files to real
      Program Files or ProgramData
- [ ] file helpers do not create, remove, start, or stop services
- [ ] file helpers do not run `msiexec`
- [ ] file helpers do not modify registry
- [ ] file helpers do not accept credentials or passwords
- [ ] file helpers do not embed credentials, passwords, tokens, API keys, or
      secrets
- [ ] Windows install validator confirms file helper presence, dry-run support,
      admin checks, config/identity preservation, safe ACL expectations, and
      absence of service, registry, MSI, network, and credential patterns

## Debian Package Metadata

- [ ] `scripts/release/package_agent_deb.py` passes against an existing
      Linux amd64 dist artifact
- [ ] `.deb` package is written under ignored
      `dist/agent/<version>/packages/`
- [ ] `.deb` package name is
      `openassetwatch-agent_<version>_amd64.deb`
- [ ] `.deb` SHA256 checksum file is written next to the package
- [ ] `.deb` package manifest JSON is written next to the package
- [ ] package manifest contains package name, version, OS, architecture,
      package type, package path, SHA256, build timestamp, git commit, and
      package contents
- [ ] package control metadata includes `Depends: systemd, passwd`
- [ ] package contents include `/opt/openassetwatch/agent/bin/oaw-agent`
- [ ] package contents include
      `/usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show`
- [ ] package contents include
      `/usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show`
- [ ] package contents include `/usr/bin/oaw-agent` as a symlink to
      `/opt/openassetwatch/agent/bin/oaw-agent`
- [ ] package contents include
      `/etc/openassetwatch/agent/config.example.json`
- [ ] package contents include
      `/etc/openassetwatch/agent/identity.example.json`
- [ ] package contents include `/etc/sudoers.d/openassetwatch-agent`
- [ ] package contents include `/lib/systemd/system/oaw-agent.service`
- [ ] package contents include `/lib/systemd/system/oaw-agent.timer`
- [ ] package contains `/var/lib/openassetwatch/agent/`
- [ ] package contains `/var/log/openassetwatch/agent/`
- [ ] package contents include
      `/usr/share/doc/openassetwatch-agent/README.md`
- [ ] package contents include
      `/usr/share/doc/openassetwatch-agent/release-manifest.json`
- [ ] package contains only expected maintainer scripts: `postinst` and
      `postrm`
- [ ] `postinst` creates or reuses only the `openassetwatch` system group and
      non-interactive `openassetwatch` system user
- [ ] `postinst` uses `/usr/sbin/nologin` for the service account shell
- [ ] `postinst` sets service ownership only on
      `/var/lib/openassetwatch/agent/` and `/var/log/openassetwatch/agent/`
- [ ] `/opt/openassetwatch/` and package-managed paths below it are owned by
      `openassetwatch:openassetwatch`
- [ ] `/usr/lib/openassetwatch/agent/libexec/` remains root-controlled
- [ ] helper scripts are owned by `root:root` and are not writable by
      `openassetwatch`
- [ ] `postinst` may run `systemctl daemon-reload` and
      `systemctl enable oaw-agent.timer` on the target Linux machine
- [ ] `postinst` starts or restarts `oaw-agent.timer` only when both
      `/etc/openassetwatch/agent/config.json` and
      `/etc/openassetwatch/agent/identity.json` exist
- [ ] `postinst` does not start `oaw-agent.service` directly or
      unconditionally
- [ ] `postrm` is limited to `systemctl daemon-reload` for service-manager
      cleanup
- [ ] maintainer scripts do not overwrite config, overwrite identity, create
      secrets, call network services, execute arbitrary user-controlled
      commands, change sudoers, or grant sudo permissions beyond the packaged
      allowlist
- [ ] sudoers file is owned by root in package metadata
- [ ] sudoers file mode is `0440`
- [ ] sudoers file applies only to the `openassetwatch` service user
- [ ] sudoers file allows only exact no-argument OpenAssetWatch helper
      scripts:
      `/usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show` and
      `/usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show`
- [ ] sudoers file does not directly allow `/usr/sbin/ip neigh show` or
      `/usr/sbin/ip addr show`
- [ ] sudoers file does not include `NOPASSWD: ALL`, broad `ALL=(ALL) ALL`
      grants, shell/interpreter access, downloaders, package managers,
      service managers, file mutation commands, offensive tooling, wildcards,
      or arbitrary arguments
- [ ] service unit uses a one-shot `run-once` runtime because no long-running
      daemon command exists yet
- [ ] service unit includes `ConditionPathExists=` checks for config and
      identity
- [ ] service unit does not contain shell execution
- [ ] service unit runs only
      `/opt/openassetwatch/agent/bin/oaw-agent run-once`
- [ ] service unit uses `ReadWritePaths=/var/lib/openassetwatch/agent` for
      runtime output under `ProtectSystem=strict`
- [ ] timer unit runs shortly after boot and periodically with conservative
      hourly cadence and randomized delay
- [ ] service unit includes `User=openassetwatch`
- [ ] service unit includes `Group=openassetwatch`
- [ ] package build does not run `dpkg`, `apt`, `systemctl`, `service`,
      `sudo`, package-manager commands, or service-manager commands
- [ ] package build does not install software, enable services, start
      services, or modify host OS state
- [ ] package does not contain real config values, real identity values, logs,
      status state, tokens, credentials, API keys, or secrets
- [ ] generated `dist/` artifacts remain ignored and are not committed

## Debian Package Validation

- [ ] `scripts/release/validate_agent_deb.py` passes against the selected
      `.deb` package
- [ ] validator output is JSON only
- [ ] validator output includes `ok`, `package`, `checks`, `warnings`, and
      `errors`
- [ ] `.deb` package exists under `dist/agent/<version>/packages/`
- [ ] `.deb.sha256` exists next to the package
- [ ] `.deb.manifest.json` exists next to the package
- [ ] package checksum matches `.deb.sha256`
- [ ] package manifest SHA256 matches the package
- [ ] expected Debian archive members exist
- [ ] expected data archive paths exist
- [ ] expected package directories exist
- [ ] service unit exists and runs only
      `/opt/openassetwatch/agent/bin/oaw-agent run-once`
- [ ] timer unit exists and targets `oaw-agent.service`
- [ ] service unit includes `User=openassetwatch`
- [ ] service unit includes `Group=openassetwatch`
- [ ] service unit includes config and identity preconditions
- [ ] service unit includes the `/var/lib/openassetwatch/agent` writable path
      for run-once output
- [ ] example config and identity files contain placeholders only
- [ ] release manifest exists and matches expected package paths
- [ ] package control metadata includes `Depends: systemd, passwd`
- [ ] `/opt/openassetwatch/agent/bin/oaw-agent` exists in the package
- [ ] `/usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show` exists in the
      package
- [ ] `/usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show` exists in the
      package
- [ ] helper script contents match the approved exact read-only commands
- [ ] `/usr/bin/oaw-agent` exists as a symlink to the `/opt` binary
- [ ] `/etc/sudoers.d/openassetwatch-agent` exists in the package
- [ ] sudoers file uses mode `0440` and root ownership in package metadata
- [ ] sudoers file contains only the approved `openassetwatch` helper
      allowlist
- [ ] sudoers file no longer grants direct access to raw `/usr/sbin/ip`
      commands
- [ ] sudoers file refuses broad grants such as `NOPASSWD: ALL` and
      `ALL=(ALL) ALL`
- [ ] `/opt/openassetwatch/`, `/opt/openassetwatch/agent/`,
      `/opt/openassetwatch/agent/bin/`, and
      `/opt/openassetwatch/agent/bin/oaw-agent` are owned by
      `openassetwatch:openassetwatch`
- [ ] `/usr/lib/openassetwatch/agent/libexec/` and helper scripts are owned
      by `root:root`
- [ ] `/var/lib/openassetwatch/agent/` and `/var/log/openassetwatch/agent/`
      are owned by `openassetwatch:openassetwatch`
- [ ] `/etc/openassetwatch/agent/` remains root-controlled
- [ ] expected maintainer scripts are present
- [ ] unexpected maintainer files are refused
- [ ] maintainer scripts create the non-interactive service account safely
- [ ] `postinst` enables `oaw-agent.timer`
- [ ] `postinst` starts or restarts `oaw-agent.timer` only when both real
      config and identity files exist
- [ ] `postinst` does not start `oaw-agent.service` directly or
      unconditionally
- [ ] `postinst` does not change sudoers
- [ ] `postrm` is limited to approved daemon-reload cleanup
- [ ] maintainer scripts do not overwrite config or identity
- [ ] maintainer scripts do not grant sudo permissions beyond the packaged
      allowlist
- [ ] package content outside intended Linux install paths is refused
- [ ] validator does not install the package or run package-manager or
      service-manager commands

## RPM Spec Staging

- [ ] `scripts/release/package_agent_rpm.py` passes against an existing Linux
      amd64 dist artifact
- [ ] helper output is JSON only
- [ ] helper output includes `ok`, `version`, `rpm_root`, `spec`,
      `buildroot`, `manifest`, `checks`, `warnings`, and `errors`
- [ ] RPM staging output is written only under ignored
      `dist/agent/<version>/rpm/`
- [ ] RPM build tree contains `BUILD/`, `BUILDROOT/`, `RPMS/`, `SOURCES/`,
      `SPECS/`, and `SRPMS/`
- [ ] spec file exists at
      `dist/agent/<version>/rpm/SPECS/openassetwatch-agent.spec`
- [ ] staged payload exists under
      `dist/agent/<version>/rpm/BUILDROOT/openassetwatch-agent-<version>-1.x86_64/`
- [ ] staged payload includes `/opt/openassetwatch/agent/bin/oaw-agent`
- [ ] staged payload includes `/usr/bin/oaw-agent` as a safe compatibility
      wrapper to `/opt/openassetwatch/agent/bin/oaw-agent`
- [ ] staged payload includes
      `/etc/openassetwatch/agent/config.example.json`
- [ ] staged payload includes
      `/etc/openassetwatch/agent/identity.example.json`
- [ ] staged payload includes `/var/lib/openassetwatch/agent/`
- [ ] staged payload includes `/var/log/openassetwatch/agent/`
- [ ] staged payload includes
      `/usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show`
- [ ] staged payload includes
      `/usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show`
- [ ] staged payload includes `/etc/sudoers.d/openassetwatch-agent`
- [ ] staged payload includes `/usr/lib/systemd/system/oaw-agent.service`
- [ ] staged payload includes `/usr/lib/systemd/system/oaw-agent.timer`
- [ ] staged payload includes
      `/usr/share/doc/openassetwatch-agent/README.md`
- [ ] staged payload includes
      `/usr/share/doc/openassetwatch-agent/release-manifest.json`
- [ ] staged release manifest records helper metadata, sudoers metadata,
      service metadata, timer metadata, and ownership expectations
- [ ] spec declares `Requires: systemd` and `Requires: shadow-utils`
- [ ] spec models the one-shot `oaw-agent run-once` service and timer
      behavior
- [ ] spec enables `oaw-agent.timer` only for target install behavior
- [ ] spec does not start `oaw-agent.service` directly or unconditionally
- [ ] helper scripts run exactly `/usr/sbin/ip neigh show` and
      `/usr/sbin/ip addr show`
- [ ] helper scripts do not accept arguments
- [ ] helper scripts are staged under
      `/usr/lib/openassetwatch/agent/libexec/`
- [ ] sudoers file allows only the OpenAssetWatch-owned helper scripts
- [ ] sudoers file does not directly allow raw `/usr/sbin/ip` commands
- [ ] sudoers file does not include `NOPASSWD: ALL`, broad `ALL=(ALL) ALL`
      grants, wildcards, shell/interpreter access, downloaders, package
      managers, service managers, file mutation commands, offensive tooling,
      or arbitrary arguments
- [ ] helper does not build an RPM file
- [ ] helper does not run `rpm`, `rpmbuild`, `dnf`, `yum`, `systemctl`,
      `service`, `sudo`, package-manager commands, or service-manager
      commands
- [ ] helper does not install software, enable services, start services, or
      modify host OS state
- [ ] generated `dist/` artifacts remain ignored and are not committed

## RPM Staging Validation

- [ ] `scripts/release/validate_agent_rpm.py` passes against the selected RPM
      staging tree
- [ ] validator supports `--version`
- [ ] validator supports optional `--rpm-root`
- [ ] validator output is JSON only
- [ ] validator output includes `ok`, `version`, `rpm_root`, `checks`,
      `warnings`, and `errors`
- [ ] validator inspects `dist/agent/<version>/rpm/`
- [ ] validator inspects `SPECS/openassetwatch-agent.spec`
- [ ] validator inspects
      `BUILDROOT/openassetwatch-agent-<version>-1.x86_64/`
- [ ] validator inspects the staged package manifest JSON
- [ ] validator confirms `BUILD/`, `BUILDROOT/`, `RPMS/`, `SOURCES/`,
      `SPECS/`, and `SRPMS/` exist
- [ ] validator confirms expected staged payload files and directories exist
- [ ] validator confirms service uses `run-once`
- [ ] validator confirms service uses `User=openassetwatch`
- [ ] validator confirms service uses `Group=openassetwatch`
- [ ] validator confirms service has config and identity `ConditionPathExists`
- [ ] validator confirms service has
      `ReadWritePaths=/var/lib/openassetwatch/agent`
- [ ] validator confirms timer exists and has conservative cadence fields
- [ ] validator confirms helpers live under
      `/usr/lib/openassetwatch/agent/libexec/`
- [ ] validator confirms helpers run only the approved exact `ip` commands
- [ ] validator confirms helpers reject arguments
- [ ] validator confirms sudoers allows only helper scripts
- [ ] validator confirms sudoers does not directly allow raw `/usr/sbin/ip`
      commands
- [ ] validator rejects broad sudo grants, `NOPASSWD: ALL`, and wildcard
      command access
- [ ] validator confirms spec contains package name `openassetwatch-agent`
- [ ] validator confirms spec contains expected systemd scriptlet text
- [ ] validator confirms spec creates or reuses the `openassetwatch`
      user/group
- [ ] validator confirms spec enables `oaw-agent.timer`
- [ ] validator rejects unconditional service start behavior
- [ ] validator rejects config or identity deletion behavior
- [ ] validator rejects broad sudo behavior
- [ ] validator fails closed when the spec file is missing
- [ ] validator fails closed when sudoers is missing
- [ ] validator fails closed when sudoers directly allows raw `/usr/sbin/ip`
      commands
- [ ] validator does not build or install an RPM
- [ ] validator does not run `rpm`, `rpmbuild`, `dnf`, `yum`, `systemctl`,
      `service`, `sudo`, package-manager commands, or service-manager
      commands

## Disposable Linux Install Test Guidance

- [ ] install tests run only inside a disposable Debian or Ubuntu VM/container
- [ ] install commands are not run on the Windows build host
- [ ] expected files are present after install in the disposable environment
- [ ] package artifact creation does not enable or start services on the build
      host
- [ ] package installation enables `oaw-agent.timer` inside the disposable
      Linux environment
- [ ] package installation starts or restarts the timer only when both real
      config and identity files already exist
- [ ] timer execution triggers the one-shot `oaw-agent run-once` service
- [ ] real config and identity files remain administrator-controlled
- [ ] cleanup commands are run only inside the disposable environment

## Local Install Staging

- [ ] `scripts/release/stage_agent_install.py` passes against the selected
      TAR.GZ package
- [ ] staging output is JSON only
- [ ] package file exists under `dist/agent/<version>/packages/`
- [ ] package SHA256 checksum matches the package manifest and checksum file
- [ ] package manifest contains required fields
- [ ] archive paths are safe and contain no forbidden entries
- [ ] staging output is written under ignored
      `dist/staging/agent/<version>/<os>-<arch>/`
- [ ] staged layout contains `binary/`, `config/`, `identity/`, `logs/`,
      `status/`, `service/`, and `package-metadata/`
- [ ] staged config and identity directories contain only placeholder README
      files, not real values
- [ ] staged logs and status directories contain only placeholder README files,
      not runtime state
- [ ] staged service directory contains only placeholder README files, not
      installed service definitions
- [ ] no files are written to Program Files, ProgramData, `/usr`, `/etc`,
      `/var`, `/Library`, service-manager paths, or package-manager metadata
      paths
- [ ] generated staging artifacts remain ignored and are not committed

## Local Sandbox Install Proof

- [ ] `scripts/release/install_agent_local.py` passes against the selected
      staged layout or TAR.GZ package
- [ ] install output is JSON only
- [ ] install output includes `ok`, `install_root`, `files`, `checks`,
      `warnings`, and `errors`
- [ ] default install output is written under ignored
      `dist/local-install/agent/<version>/<os>-<arch>/`
- [ ] explicit install roots outside the repository are refused
- [ ] local proof layout contains `binary/`, `config/`, `identity/`, `logs/`,
      `status/`, `service/`, and `package-metadata/`
- [ ] only safe files are copied: agent binary, checksum files, manifest files,
      README/install notes, and package metadata
- [ ] config and identity directories contain only placeholder README files,
      not real values
- [ ] logs and status directories contain only placeholder README files, not
      runtime state
- [ ] service directory contains only placeholder README files, not installed
      service definitions
- [ ] no files are written to Program Files, ProgramData, `/usr`, `/etc`,
      `/var`, `/Library`, service-manager paths, or package-manager metadata
      paths
- [ ] generated local install artifacts remain ignored and are not committed

## Local Sandbox Uninstall Proof

- [ ] `scripts/release/uninstall_agent_local.py` passes against the selected
      local sandbox install root
- [ ] uninstall output is JSON only
- [ ] uninstall output includes `ok`, `install_root`, `removed`, `checks`,
      `warnings`, and `errors`
- [ ] uninstall removes only roots under
      `dist/local-install/agent/<version>/<os>-<arch>/`
- [ ] uninstall roots outside the repository are refused
- [ ] paths that look like Program Files, ProgramData, `/usr`, `/etc`, `/var`,
      or `/Library` are refused
- [ ] expected package metadata is required by default
- [ ] `--force` allows removal of an incomplete repo-local sandbox install
      root only
- [ ] generated release packages under `dist/agent/<version>/packages/` remain
      in place
- [ ] config, identity, logs, and status outside the sandbox install root are
      not removed
- [ ] no services are unregistered, started, stopped, installed, or modified
- [ ] no package-manager or service-manager commands are executed

## Local Sandbox Upgrade And Rollback Proof

- [ ] `scripts/release/upgrade_agent_local.py` passes for upgrade mode
- [ ] `scripts/release/upgrade_agent_local.py` passes for rollback mode
- [ ] upgrade and rollback output is JSON only
- [ ] output includes `ok`, `mode`, `from_version`, `to_version`,
      `install_root`, `backup`, `checks`, `warnings`, and `errors`
- [ ] helper operates only under `dist/local-install/agent/`, `dist/agent/`,
      and `dist/staging/agent/`
- [ ] target release package exists and validates before changing local
      sandbox install output
- [ ] backup metadata is written under ignored
      `dist/local-install/agent/_backups/`
- [ ] sandbox config and identity placeholder directories are preserved
- [ ] no real config values or identity values are created
- [ ] generated release packages under `dist/agent/<version>/packages/` remain
      in place
- [ ] config, identity, logs, and status outside the sandbox install root are
      not removed
- [ ] paths outside the repository are refused
- [ ] paths that look like Program Files, ProgramData, `/usr`, `/etc`, `/var`,
      or `/Library` are refused
- [ ] no services are registered, unregistered, started, stopped, installed, or
      modified
- [ ] no package-manager or service-manager commands are executed

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

## Local Release Orchestration

- [ ] `scripts/release/release_agent_local.ps1` passes for the selected
      version
- [ ] orchestration output is JSON only
- [ ] output includes `ok`, `version`, `artifacts`, `packages`, `checks`,
      `warnings`, and `errors`
- [ ] orchestration calls the build, TAR.GZ package, and release validation
      helpers rather than duplicating their logic
- [ ] generated artifacts remain under ignored `dist/` paths
- [ ] generated artifacts are not staged or committed
- [ ] orchestration does not build MSI, DEB, RPM, or PKG packages
- [ ] orchestration does not install software, modify the OS, write service
      definitions, execute package-manager commands, execute service-manager
      commands, contact network services, or store secrets

## Package Build

- [ ] package build planned for each target package type
- [ ] Windows MSI future package layout reviewed
- [ ] Linux `.deb` future package layout reviewed
- [ ] Linux `.rpm` future package layout reviewed
- [ ] Linux `.tar.gz` fallback layout reviewed
- [ ] macOS signed/notarized package layout reviewed
- [ ] package includes only approved binary and non-secret metadata
- [ ] package preserves config and identity during upgrade
- [ ] package does not delete config, identity, or logs by default

## Artifact Validation

- [ ] checksum generated for each artifact
- [ ] signature placeholder or signing workflow reference documented
- [ ] macOS notarization placeholder documented where applicable
- [ ] SBOM placeholder documented
- [ ] provenance attestation placeholder documented
- [ ] package metadata paths reviewed
- [ ] artifact names include OS, architecture, version, and package type

## Lifecycle Validation

- [ ] install validation planned
- [ ] uninstall validation planned
- [ ] upgrade validation planned
- [ ] rollback validation planned
- [ ] service definition review planned before service installation exists
- [ ] `oaw-agent doctor` validation planned after install or upgrade
- [ ] `oaw-agent status` validation planned after install or upgrade
- [ ] `oaw-agent check-in` validation planned where backend access is available

## Safety Gates

- [ ] no package-manager commands are executed by the running agent
- [ ] no service-manager commands are executed by planning commands
- [ ] no silent self-install behavior exists
- [ ] no silent self-upgrade behavior exists
- [ ] no scheduler or daemon behavior is introduced by package scaffolding
- [ ] no secrets are written to logs, config examples, identity examples, or
      package manifests
- [ ] no active scanning or offensive tooling is packaged
