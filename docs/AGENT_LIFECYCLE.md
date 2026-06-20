# Agent Lifecycle And Service Readiness

This document captures the current manual `oaw-agent` lifecycle and the
readiness checklist for packaged service operation.

Current state: the agent supports explicit command-line operation plus native
service runtimes through `oaw-agent service run` on Windows and macOS. Windows
MSI deployment details live in
[Agent Windows Deployment](AGENT_WINDOWS_DEPLOYMENT.md). macOS LaunchDaemon and
PKG deployment details live in
[Agent macOS Deployment](AGENT_MACOS_DEPLOYMENT.md). The agent does not perform
active scanning.

## Current Manual Lifecycle

Run commands from the repository root during local development.

### 1. Inspect Default Paths

```powershell
go run ./cmd/oaw-agent paths
```

This prints JSON with the resolved default identity, config, log, and status
paths. It does not create files or directories.

Default paths are:

- Windows identity: `%ProgramData%\OpenAssetWatch\Agent\identity\identity.json`
- Windows config: `%ProgramData%\OpenAssetWatch\Agent\config\config.json`
- Windows state: `%ProgramData%\OpenAssetWatch\Agent\state\`
- Windows logs: `%ProgramData%\OpenAssetWatch\Agent\logs\`
- Windows status file: `%ProgramData%\OpenAssetWatch\Agent\state\status.json`
- Linux identity: `/etc/openassetwatch/agent/identity.json`
- Linux config: `/etc/openassetwatch/agent/config.json`
- Linux state: `/var/lib/openassetwatch/agent/`
- Linux logs: `/var/log/openassetwatch/agent/`
- Linux status file: `/var/log/openassetwatch/agent/status.json`
- macOS identity:
  `/Library/Application Support/OpenAssetWatch/Agent/identity/identity.json`
- macOS config:
  `/Library/Application Support/OpenAssetWatch/Agent/config/config.json`
- macOS state: `/Library/Application Support/OpenAssetWatch/Agent/state`
- macOS logs: `/Library/Logs/OpenAssetWatch/Agent/`
- macOS status file:
  `/Library/Application Support/OpenAssetWatch/Agent/state/status.json`

### 2. Initialize Config

```powershell
go run ./cmd/oaw-agent config init `
  --server-url http://localhost:8000 `
  --site-id site-local `
  --output config.json
```

The config file is non-secret and currently stores only:

- `server_url`
- `site_id`

Config initialization validates URL shape and rejects URL credentials, query
strings, and fragments. It does not contact the backend.

### 3. Initialize Identity

```powershell
go run ./cmd/oaw-agent identity init --site-id site-local --output identity.json
```

Optional deployment and tenant identifiers can be supplied when they come from
installer, enrollment, or administrator input:

```powershell
go run ./cmd/oaw-agent identity init `
  --site-id site-local `
  --deployment-id 11111111-1111-4111-8111-111111111111 `
  --tenant-id tenant-example `
  --output identity.json
```

Identity initialization generates `agent_id` only during explicit identity file
creation. It does not fabricate `deployment_id`, and it must not store
enrollment tokens, API keys, passwords, license keys, signing keys, or other
secrets.

### 4. Run Doctor

```powershell
go run ./cmd/oaw-agent doctor --config config.json --identity-file identity.json
```

`doctor` writes JSON only. It checks local setup, including:

- resolved config and identity paths
- config and identity file existence
- JSON parsing
- config `server_url`
- config `site_id`
- identity `site_id`
- identity `agent_id`

It does not create files, modify files, contact the backend, or run a backend
health check.

### 5. Review Local Status

```powershell
go run ./cmd/oaw-agent status --config config.json --identity-file identity.json
```

`status` writes JSON only. It reports resolved config, identity, log, and
status-file paths and whether the local config, identity, log directory, and
last known status file exist. It is a read-only local setup snapshot. It does
not create files or directories, write logs, contact the backend, or run a
backend health check.

### 6. Review Install Plan

```powershell
go run ./cmd/oaw-agent install plan
```

`install plan` writes JSON only. It reports the current operating system,
architecture, recommended package type, install model, expected binary path,
config path, identity path, log directory, status file path, service definition
path where known, package validation expectations, and warnings.

On Linux, it may read `/etc/os-release` and infer the package family:

- Debian and Ubuntu: `deb`
- RHEL, Rocky Linux, AlmaLinux, CentOS, Fedora, SUSE, and openSUSE: `rpm`
- unknown or unsupported Linux: `tar.gz/manual`

It does not create files or directories, install packages, run service-manager
commands, run package-manager commands, modify services, contact the backend,
or run a backend health check.

### 7. Review Future Service Plan

```powershell
go run ./cmd/oaw-agent service plan
```

`service plan` writes JSON only. It reports the current operating system's
future service target, service name, expected binary path, config path,
identity path, log directory, status file path, and service definition path
where known.

On Linux, it may read `/etc/os-release` and infer the future package family:

- Debian and Ubuntu: `deb`
- RHEL, Rocky Linux, AlmaLinux, CentOS, Fedora, SUSE, and openSUSE: `rpm`
- unknown or unsupported Linux: `tar.gz/manual`

It does not create files or directories, install packages, run service-manager
commands, run package-manager commands, start services, stop services, schedule
work, contact the backend, or run a backend health check.

### 8. Preview Future Service Template

```powershell
go run ./cmd/oaw-agent service template
```

`service template` writes JSON only. The JSON includes the future service
target, service name, template type, template text, and warnings. The template
text is generated for the current operating system:

- Windows: Windows Service metadata and example administrator command text
- Linux: systemd unit file content
- macOS: launchd plist content

The generated template includes expected binary, config, identity, log, and
status-file paths. It may include conservative future retry or scheduling
placeholders as comments or inert text, but it does not implement scheduling.

It does not create files or directories, write service definitions, install
packages, run service-manager commands, run package-manager commands, start
services, stop services, schedule work, contact the backend, or run a backend
health check.

### 9. Check In

```powershell
go run ./cmd/oaw-agent check-in --identity-file identity.json --config config.json
```

Check-in sends identity and health metadata to
`/api/v1/agents/check-in`. It does not perform collection, active probing, or
remote command execution.

### 10. Collect Inventory

```powershell
go run ./cmd/oaw-agent collect --once --identity-file identity.json --config config.json --output inventory.json
```

Collection is local and passive-first. It collects local host, platform,
interface, gateway, and local neighbor-cache observations where available.
It does not perform CIDR discovery, port checks, packet injection, credential
collection, or external service calls.

### 11. Submit Inventory

```powershell
go run ./cmd/oaw-agent submit --file inventory.json --config config.json
```

Submit posts the local inventory JSON to
`/api/v1/collections/local-inventory`. It sends the JSON file body unchanged
and does not add enrollment tokens, arbitrary headers, retries, scheduling, or
daemon behavior.

### 12. Run Local E2E Helper

Default local collect and submit flow:

```powershell
.\scripts\e2e\local_collect_submit.ps1 -ServerUrl http://localhost:8000 -SiteId site-local
```

Full config-backed check-in, collection, and submit flow:

```powershell
.\scripts\e2e\local_collect_submit.ps1 -ServerUrl http://localhost:8000 -SiteId site-local -UseConfig -IncludeCheckIn
```

The helper requires an explicit local backend URL, uses temporary files, and
cleans them up unless `-KeepTemp` is supplied.

## Service Readiness Checklist

All items below should be satisfied before adding service, daemon, scheduler,
or installer behavior.

- [ ] Config file location is finalized for Windows, Linux, and macOS.
- [ ] Identity file location is finalized for Windows, Linux, and macOS.
- [ ] Config file exists before service start.
- [ ] Identity file exists before service start.
- [ ] `oaw-agent doctor` passes before service registration or first run.
- [ ] `oaw-agent status` reports the expected local config, identity, log, and
  status-file locations.
- [ ] `oaw-agent install plan` reports the expected package and deployment
  recommendation without modifying the host.
- [ ] `oaw-agent service plan` reports the expected future service target and
  planned paths without modifying the host.
- [ ] `oaw-agent service template` previews future service definition content
  without writing files or modifying the host.
- [ ] Backend URL is configured through non-secret config.
- [ ] Check-in succeeds against the intended backend.
- [ ] Local collection succeeds without elevated privileges where possible.
- [ ] Inventory submit succeeds against the intended backend.
- [ ] Local log location is defined per operating system.
- [ ] Last known local status file location is defined per operating system.
- [ ] Service account or user model is defined per operating system.
- [ ] Install behavior is defined.
- [ ] Uninstall behavior is defined.
- [ ] Upgrade behavior is defined.
- [ ] Rollback behavior is defined.
- [ ] Rollback or failed-upgrade behavior is defined.
- [ ] Signature and checksum validation behavior is defined.
- [ ] Linux distribution detection behavior is defined.
- [ ] Linux package format selection behavior is defined.
- [ ] Future package scaffold templates are reviewed under
  [packaging/agent](../packaging/agent/README.md).
- [ ] Start, stop, restart, and status behavior is defined.
- [ ] Retry and backoff behavior is conservative and bounded.
- [ ] Local queue or spool behavior is defined for offline submissions.
- [ ] Local queue retention limits are defined.
- [ ] Privacy and sensitive-field handling is defined.
- [ ] Logs do not include secrets, tokens, credentials, request bodies, or
  response bodies.
- [ ] Safe failure behavior is defined for missing config, missing identity,
  malformed files, unreachable backend, and submit failure.
- [ ] Service mode does not enable active scanning by default.
- [ ] Service mode has a documented disable/stop path.
- [ ] Service mode has operator-visible diagnostics that do not expose secrets.

## Future Service Mode Design

Future service mode should wrap the existing safe command behavior instead of
introducing broad new capabilities.

For future install, uninstall, upgrade, rollback, package validation, and
enterprise deployment lifecycle planning, see
[Agent Installation](AGENT_INSTALLATION.md).

Use the [agent package source](../packaging/agent/README.md) to review
Windows MSI, Linux `.deb`, Linux `.rpm`, Linux `.tar.gz`, and macOS PKG layout
expectations. Linux DEB and RPM source now lives under
`packaging/agent/linux/`; local and pull-request package artifacts are
unsigned validation outputs until signing and release publication are added.
The source tree and local release helpers do not execute package-manager
install commands, service-manager commands outside reviewed package scripts,
or unprompted host modifications.

Use `oaw-agent service plan` to inspect the future service target for the
current operating system before any service install, uninstall, daemon, or
scheduler implementation exists. The command is intentionally read-only.
Use `oaw-agent service template` to preview future Windows Service, Linux
systemd, or macOS launchd definition content. The template command is also
read-only and writes generated text only to stdout inside JSON.

### Windows Service

Future Windows support should use a signed installer or service wrapper. It
should define:

- service name
- service account model
- default config and identity paths
- log path
- start, stop, restart, and status behavior
- upgrade and uninstall behavior

### Linux Systemd

Future Linux support should use a native package and a systemd unit. It should
define:

- dedicated user or least-privilege account model
- unit file behavior
- environment file policy
- config and identity paths
- log path through journald or explicit local files
- start, stop, restart, and status behavior
- install, uninstall, upgrade, and rollback expectations
- package signature and checksum validation expectations

### Linux Package And Deployment Planning

Future Linux packaging should detect the target distribution before selecting
an artifact or install instructions. This detection should be read-only and
should not install packages or run package-manager commands automatically.

Distribution detection should start with `/etc/os-release` and inspect:

- `ID`
- `ID_LIKE`
- `VERSION_ID`

Package-manager detection may check whether these tools are available:

- `apt`
- `dnf`
- `yum`
- `zypper`

Package selection should follow conservative defaults:

- Debian and Ubuntu map to signed `.deb` artifacts.
- RHEL, Rocky Linux, AlmaLinux, CentOS, and Fedora map to signed `.rpm`
  artifacts.
- SUSE and openSUSE map to signed `.rpm` artifacts.
- Unknown or unsupported Linux distributions map to a signed `.tar.gz`
  artifact or manual install instructions.

Package-manager commands must require explicit administrator action. The
running agent must not act as a package-manager wrapper, must not perform
silent self-install, and must not perform silent self-upgrade. Future
installers may guide operators through package-manager commands, but service
runtime should not execute package installation, removal, or upgrade commands.

Signed `.deb`, `.rpm`, and `.tar.gz` artifacts are future release pipeline
goals. Before service mode is enabled, release planning should document:

- install behavior
- uninstall behavior
- upgrade behavior
- rollback behavior
- package signature validation
- checksum validation
- unsupported-distribution fallback behavior

### macOS Launchd

macOS support uses a system LaunchDaemon installed by a PKG artifact. The
LaunchDaemon runs the existing portable supervisor with:

```text
/Library/Application Support/OpenAssetWatch/Agent/bin/oaw-agent service run --config /Library/Application Support/OpenAssetWatch/Agent/config/config.json --identity-file /Library/Application Support/OpenAssetWatch/Agent/identity/identity.json --output-dir /Library/Application Support/OpenAssetWatch/Agent/state
```

The package creates or reuses the non-interactive `_openassetwatch` service
identity, installs `com.openassetwatch.agent`, and stores state under
`/Library/Application Support/OpenAssetWatch/Agent/state` with logs under
`/Library/Logs/OpenAssetWatch/Agent`. It preserves administrator-managed config
and identity during repair, upgrade, rollback, and uninstall. Local package
artifacts are unsigned validation artifacts; production release artifacts still
require Developer ID signing, notarization, stapling, and signature validation.

See [Agent macOS Deployment](AGENT_MACOS_DEPLOYMENT.md) for install,
provisioning, launchctl lifecycle, signing, notarization, and uninstall
details.

### Scheduling And Retry Expectations

Scheduling should be conservative by default:

- explicit opt-in schedule configuration
- bounded retry count
- bounded exponential backoff with jitter
- no tight loops
- no aggressive reconnect behavior
- local queue or spool for offline submit when explicitly designed
- clear retention limits for queued inventory

### Logs And Diagnostics

Logs should be local, minimal, and safe:

- no secrets
- no enrollment tokens
- no passwords
- no API keys
- no request bodies
- no response bodies
- no raw config dumps
- no raw identity dumps

`doctor` should remain the first local setup diagnostic. `status` should
remain a read-only local setup snapshot. Backend health checks and service
health reporting should be separate future work.

### Default Safety Posture

Future service mode must preserve OpenAssetWatch's current agent safety model:

- passive/local collection by default
- no CIDR discovery by default
- no port checks by default
- no packet injection
- no credential collection
- no arbitrary command execution
- no raw command wrappers
- no offensive tooling

## Non-Goals In This Branch

The current service-planning foundation does not add:

- daemon code
- scheduler code
- installer code
- service wrappers
- service definition file writes
- background execution
- service install or uninstall code
- service start or stop behavior
- package-manager execution
- licensing enforcement
- UI work
- credential storage
- enrollment token storage
- active scanning
- offensive tooling

## Related Docs

- [Agent Collection](AGENT_COLLECTION.md)
- [Agent Check-In](AGENT_CHECKIN.md)
- [Agent Installation](AGENT_INSTALLATION.md)
- [Deployment Sizing](DEPLOYMENT_SIZING.md)
- [Local E2E Validation](LOCAL_E2E.md)
- [Installers](INSTALLERS.md)
- [Agent Package Scaffold](../packaging/agent/README.md)
