# Collector Deployment Planning

This document describes the local install MVP direction for running the
OpenAssetWatch collector continuously. The collector should remain
Python-first and use native service managers for each operating system.

Existing one-shot collector commands remain supported and unchanged. Service
or scheduled operation is opt-in through config files and `--run-forever`.

The MVP installer entry points are:

```text
collector/install/install.py
collector/install/install-linux.sh
collector/install/install-macos.sh
collector/install/install-windows.cmd
```

For install commands and verification steps, see
`docs/setup/local-collector-installation.md`.

## Current Persistent Service Model

The local install MVP uses native OS service managers to keep the Python
collector running:

- Windows uses Task Scheduler at startup. This is not a true Windows Service
  yet.
- Linux uses a `systemd` service.
- macOS uses a LaunchDaemon at
  `/Library/LaunchDaemons/com.openassetwatch.collector.plist`.

All three models call Python directly with
`-m openassetwatch_collector --run-forever --config <config path>`.

## Collector Identity and Grouping

Installed collectors should have a persistent `collector_guid` generated once
at install time and stored in `identity.json`. Reinstall should preserve this
file; purge uninstall is the only normal path that removes it.

Suggested identity paths:

```text
Windows: C:\ProgramData\OpenAssetWatch\Collector\identity.json
Linux: /etc/openassetwatch/identity.json
macOS: /Library/Application Support/OpenAssetWatch/Collector/identity.json
```

`collector_guid` is the backend-stable identity used to avoid duplicate
collector records. `collector_id` remains the friendly/admin-provided
identifier. Backend collector matching should prefer `collector_guid` when
present and fall back to `collector_id` for older collectors.

Collectors can also send deployment metadata for grouping by business unit,
site, environment, location, or rollout campaign:

```yaml
deployment:
  deployment_id: home-lab-cincinnati
  business_unit: lab
  site: home
  environment: test
  install_ring: pilot
```

Flexible labels are optional and should remain JSON/YAML metadata rather than
schema-specific columns:

```yaml
labels:
  owner: dion
  device_group: mac-test
  install_profile: local-collector
```

## General Principles

- Keep the collector Python-first.
- Use native service managers per OS.
- Services should call Python directly instead of relying on shell wrappers for
  ongoing execution.
- Services should use config files instead of long hard-coded command lines.
- Services should restart automatically where the OS service manager supports
  it.
- Logs should be easy to find during local troubleshooting.
- Installers should append timestamped entries to a dedicated `install.log`
  separate from collector runtime logs.
- Installers should write an `install.env` metadata file with platform,
  selected Python, venv Python, backend URL, collector ID, timestamp, and
  installer version.
- Uninstall should preserve config, logs, and state by default unless purge is
  explicitly requested.
- Active scanning and packet capture remain disabled by default.
- Backend check-in and inventory upload should continue to use explicit config.

## Collector API Key MVP

The backend can optionally require a shared collector token for collector POST
endpoints:

```sh
OPENASSETWATCH_COLLECTOR_TOKEN=change-me-dev-token
```

When unset or empty, local development behavior remains open. When set, the
collector must send:

```text
X-OpenAssetWatch-Collector-Token: <token>
```

This protects:

- `POST /api/v1/collectors/checkin`
- `POST /api/v1/collectors/inventory`

It does not protect `GET /health`. Read-only development endpoints remain open
for the MVP.

Installer-provided tokens should be written only to protected collector config
files. They should not be written to `install.env`, installer logs, or normal
collector output.

The expected long-running command shape is:

```sh
python -m openassetwatch_collector --run-forever --config <config path>
```

## Windows MVP

For the MVP, Windows should use Task Scheduler instead of a true Windows
Service.

PowerShell may be useful during installation if it is available, but the
scheduled runtime should not depend on PowerShell. The scheduled task should
call Python directly from the collector virtual environment:

```text
.venv\Scripts\python.exe -m openassetwatch_collector --run-forever --config <config path>
```

Recommended local testing behavior:

- Create a startup scheduled task.
- Run as `SYSTEM` by default for local testing.
- Support a dedicated service account later.
- Configure restart/retry behavior through Task Scheduler where practical.
- Store logs in a predictable local directory, such as:

```text
C:\ProgramData\OpenAssetWatch\Collector\logs\
```

Suggested future install paths:

```text
C:\Program Files\OpenAssetWatch\Collector\
C:\ProgramData\OpenAssetWatch\Collector\config.yaml
C:\ProgramData\OpenAssetWatch\Collector\logs\
```

A true Windows Service can be added later using WinSW, NSSM, pywin32, or a
small native wrapper. That is out of scope for the MVP.

## Linux MVP

Linux should use `systemd`.

Recommended service layout:

- Install the collector under `/opt/openassetwatch/collector`.
- Store config at `/etc/openassetwatch/collector.yaml`.
- Run as a dedicated non-interactive `openassetwatch` user.
- Use systemd restart behavior for resilience.
- Send logs to journald by default.

Recommended command:

```text
/opt/openassetwatch/collector/.venv/bin/python -m openassetwatch_collector --run-forever --config /etc/openassetwatch/collector.yaml
```

Example systemd unit draft:

```ini
[Unit]
Description=OpenAssetWatch Collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=openassetwatch
Group=openassetwatch
WorkingDirectory=/opt/openassetwatch/collector
ExecStart=/opt/openassetwatch/collector/.venv/bin/python -m openassetwatch_collector --run-forever --config /etc/openassetwatch/collector.yaml
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

If privileged commands are needed later, use a narrow sudoers allowlist for
only the specific commands the collector needs. Do not grant unrestricted sudo.

Example allowlist direction:

```text
openassetwatch ALL=(root) NOPASSWD: /usr/sbin/ip neigh show
openassetwatch ALL=(root) NOPASSWD: /usr/sbin/ip addr show
openassetwatch ALL=(root) NOPASSWD: /usr/sbin/arp -a
openassetwatch ALL=(root) NOPASSWD: /usr/bin/hostname
```

Only add commands when the related collector feature is enabled and documented.
The collector should use `sudo -n` for any future privileged command path so it
never hangs waiting for a password. Passive packet capture and active scanning
remain disabled by default.

## macOS MVP

macOS should not reuse the Linux systemd design. The macOS MVP uses `launchd`
through a LaunchDaemon.

The macOS installer requires Python 3.10 or newer, supports `PYTHON_BIN`, and
prefers Python 3.12+ when available. It should never replace system Python or
silently fall back to Apple's older Python if that version does not satisfy the
collector requirement.

Default paths:

```text
/usr/local/openassetwatch/collector
/Library/Application Support/OpenAssetWatch/Collector/config.yaml
/Library/Logs/OpenAssetWatch/
/usr/local/var/openassetwatch
/Library/LaunchDaemons/com.openassetwatch.collector.plist
```

The LaunchDaemon calls Python directly:

```text
/usr/local/openassetwatch/collector/.venv/bin/python -m openassetwatch_collector --run-forever --config "/Library/Application Support/OpenAssetWatch/Collector/config.yaml"
```

The plist should keep the collector alive, run at boot, and write stdout/stderr
to:

```text
/Library/Logs/OpenAssetWatch/collector.out.log
/Library/Logs/OpenAssetWatch/collector.err.log
```

macOS PKG packaging, notarization/signing, and MDM deployment are out of scope
for this MVP.

## Future Packaging Roadmap

Packaging is intentionally out of scope for this installer-hardening PR. Future
packaging work can build on the install, reinstall, uninstall, purge,
metadata, logging, troubleshooting, and test matrix behavior documented here.

Windows future:

- MSI or EXE installer.
- True Windows Service or a service wrapper later.

Linux future:

- DEB/RPM packages.
- Include the `systemd` service in the package.

macOS future:

- PKG installer first.
- Optional DMG wrapper containing the PKG.
- Signing and notarization later.

On macOS, a DMG is a distribution container. The PKG is the better mechanism
for installing LaunchDaemon files, creating protected directories, and setting
system-level permissions.

## Out of Scope for This MVP

- Windows Service implementation.
- Dedicated service account automation on Windows.
- MSI or EXE packaging.
- DEB/RPM packaging.
- macOS PKG packaging, notarization/signing, and MDM deployment.
- Authentication or API key provisioning.
- Active Nmap scanning by default.
- Packet capture by default.
- Zeek or Suricata sensor deployment.
- Frontend service management UI.
