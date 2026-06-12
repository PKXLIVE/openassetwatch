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
