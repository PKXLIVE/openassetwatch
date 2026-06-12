# Local Collector Installation MVP

This guide describes the MVP local installer flow for testing OpenAssetWatch
collectors on multiple machines.

The collector remains Python-first. Native service managers are used only to
keep the Python collector running:

- Windows: Task Scheduler at startup, not a true Windows Service yet.
- Linux: systemd.
- macOS: launchd LaunchDaemon at
  `/Library/LaunchDaemons/com.openassetwatch.collector.plist`.

Existing one-shot collector commands are unchanged.

## Collector Identity and Deployment Labels

Installed collectors have two identities:

- `collector_guid` is the stable installed collector identity. It is generated
  once as a UUIDv4 at install time and stored in `identity.json`.
- `collector_id` is the friendly/admin-provided name used in commands,
  examples, and operations.

The installer preserves `identity.json` during normal reinstall and uninstall.
It is removed only during purge uninstall. This prevents duplicate backend
collector records when a collector service restarts or the collector is
reinstalled.

Identity file paths:

```text
Windows: C:\ProgramData\OpenAssetWatch\Collector\identity.json
Linux: /etc/openassetwatch/identity.json
macOS: /Library/Application Support/OpenAssetWatch/Collector/identity.json
```

Deployment metadata groups collectors by business unit, site, environment,
location, or rollout campaign:

```yaml
deployment:
  deployment_id: home-lab-cincinnati
  business_unit: lab
  site: home
  environment: test
  install_ring: pilot
```

Labels are flexible categorization metadata:

```yaml
labels:
  owner: dion
  device_group: mac-test
  install_profile: local-collector
```

Deployment metadata and labels are sent with collector check-in and inventory
upload payloads.

If the backend sets `OPENASSETWATCH_COLLECTOR_TOKEN`, installed collectors must
be configured with the same token. Installers accept `BACKEND_TOKEN` or
`COLLECTOR_TOKEN` and write the value to the protected collector config. Tokens
are not written to `install.env` and should not appear in installer logs.

## Backend URL

When installing a collector on a different machine from the backend, do not use
`localhost` for the backend URL. Use the backend machine's LAN IP address or a
DNS name reachable from the collector host.

Example:

```text
http://192.168.1.10:8000
```

## Windows Install

Run from an elevated Command Prompt or terminal.

```cmd
cd collector
install\install-windows.cmd ^
  --backend-url http://192.168.1.10:8000 ^
  --backend-token change-me-dev-token ^
  --collector-id windows-lab-01 ^
  --collector-name "Windows Lab 01" ^
  --mode hybrid
```

The Python installer creates:

```text
C:\Program Files\OpenAssetWatch\Collector
C:\ProgramData\OpenAssetWatch\Collector\config.yaml
C:\ProgramData\OpenAssetWatch\Collector\identity.json
C:\ProgramData\OpenAssetWatch\Collector\install.env
C:\ProgramData\OpenAssetWatch\Collector\logs
C:\ProgramData\OpenAssetWatch\Collector\state
```

Installer actions are appended to:

```text
C:\ProgramData\OpenAssetWatch\Collector\logs\install.log
```

It creates a startup scheduled task named `OpenAssetWatch Collector` that runs
as `SYSTEM` and calls Python directly:

```text
C:\Program Files\OpenAssetWatch\Collector\.venv\Scripts\python.exe -m openassetwatch_collector --run-forever --config C:\ProgramData\OpenAssetWatch\Collector\config.yaml
```

PowerShell is not required for ongoing collector execution.

Useful Windows commands:

```cmd
schtasks.exe /Query /TN "OpenAssetWatch Collector" /V /FO LIST
schtasks.exe /Run /TN "OpenAssetWatch Collector"
schtasks.exe /End /TN "OpenAssetWatch Collector"
schtasks.exe /Delete /TN "OpenAssetWatch Collector" /F
```

Uninstall while preserving config, logs, and state:

```cmd
python collector\install\install.py --uninstall
```

Purge config, logs, and state too:

```cmd
python collector\install\install.py --uninstall --purge
```

or:

```cmd
set PURGE=true
python collector\install\install.py --uninstall
```

Manual folder cleanup:

```cmd
schtasks.exe /Delete /TN "OpenAssetWatch Collector" /F
rmdir /S /Q "C:\Program Files\OpenAssetWatch\Collector"
rmdir /S /Q "C:\ProgramData\OpenAssetWatch\Collector"
```

## Linux Install

Run from the repository root on the collector host.

Linux prerequisites vary by package family.

Debian/Ubuntu:

```sh
sudo apt update
sudo apt install -y git curl python3 python3-venv python3-pip
```

If the selected Python is version-specific, install the matching venv package
too. For example:

```sh
sudo apt install -y python3.14-venv
```

Red Hat/Fedora/Rocky/Alma/CentOS:

```sh
sudo dnf install -y git curl python3 python3-pip python3-virtualenv
```

If `dnf` is unavailable but `yum` exists:

```sh
sudo yum install -y git curl python3 python3-pip python3-virtualenv
```

The Linux installer honors `PYTHON_BIN`, accepts any Python 3.10 or newer,
prefers Python 3.12+ when available, prints the selected Python path/version,
and tests venv creation in a temporary directory before creating the collector
venv. If venv support is missing, it prints distro-appropriate package
commands and exits before modifying the service.

```sh
sudo BACKEND_URL=http://192.168.1.10:8000 \
  BACKEND_TOKEN=change-me-dev-token \
  COLLECTOR_ID=linux-lab-01 \
  COLLECTOR_NAME="Linux Lab 01" \
  DEPLOYMENT_ID=home-lab-cincinnati \
  LABEL_INSTALL_PROFILE=local-collector \
  MODE=hybrid \
  collector/install/install-linux.sh
```

The Linux installer creates:

```text
/opt/openassetwatch/collector
/etc/openassetwatch/collector.yaml
/etc/openassetwatch/identity.json
/etc/openassetwatch/install.env
/var/lib/openassetwatch
/var/log/openassetwatch
/etc/systemd/system/openassetwatch-collector.service
```

Installer actions are appended to:

```text
/var/log/openassetwatch/install.log
```

It creates a non-interactive `openassetwatch` user/group and runs the service as
that account:

```text
/opt/openassetwatch/collector/.venv/bin/python -m openassetwatch_collector --run-forever --config /etc/openassetwatch/collector.yaml
```

Service commands:

```sh
sudo systemctl status openassetwatch-collector
sudo systemctl restart openassetwatch-collector
sudo systemctl stop openassetwatch-collector
sudo journalctl -u openassetwatch-collector -f
```

Optional sudoers allowlist:

```sh
sudo BACKEND_URL=http://192.168.1.10:8000 \
  INSTALL_SUDOERS=true \
  collector/install/install-linux.sh
```

The installer never grants unrestricted sudo. If enabled, it writes only
absolute allowlisted command paths that are present on the host and validates
the file with `visudo -cf`. Future collector code that uses these privileged
command paths should call `sudo -n` so it never waits interactively for a
password.

Optional log-read access:

```sh
sudo BACKEND_URL=http://192.168.1.10:8000 \
  ENABLE_LOG_READ=true \
  collector/install/install-linux.sh
```

This may add the `openassetwatch` user to `adm` and/or `systemd-journal` if
those groups exist. It does not chmod or chown all of `/var/log`.

Uninstall while preserving config, logs, and state:

```sh
sudo UNINSTALL=true collector/install/install-linux.sh
```

Purge config, logs, and state too:

```sh
sudo UNINSTALL=true PURGE=true collector/install/install-linux.sh
```

Manual folder cleanup:

```sh
sudo systemctl disable --now openassetwatch-collector
sudo rm -f /etc/systemd/system/openassetwatch-collector.service
sudo systemctl daemon-reload
sudo rm -rf /opt/openassetwatch /etc/openassetwatch /var/lib/openassetwatch /var/log/openassetwatch
sudo rm -f /etc/sudoers.d/openassetwatch-collector
```

Remove the service account only if no other OpenAssetWatch components use it:

```sh
sudo userdel openassetwatch
sudo groupdel openassetwatch
```

## Python Installer

The cross-platform Python installer can also be used directly.

Dry run:

```sh
python collector/install/install.py \
  --backend-url http://192.168.1.10:8000 \
  --collector-id lab-collector-01 \
  --dry-run
```

Linux install:

```sh
sudo python collector/install/install.py \
  --backend-url http://192.168.1.10:8000 \
  --collector-id linux-lab-01 \
  --collector-name "Linux Lab 01"
```

Windows install from an elevated terminal:

```cmd
python collector\install\install.py ^
  --backend-url http://192.168.1.10:8000 ^
  --collector-id windows-lab-01 ^
  --collector-name "Windows Lab 01"
```

## macOS Install

Run from the repository root on the collector host. Use the backend machine's
LAN IP address or DNS name, not `localhost`, when the backend is running on a
different machine.

The collector requires Python 3.10 or newer. The installer honors `PYTHON_BIN`,
prints the selected Python path and version, prefers Python 3.12+ when
available, and refuses to silently use Apple's older system Python if it does
not meet the collector requirement.

Example Python paths:

```text
/opt/homebrew/bin/python3.12
/Library/Frameworks/Python.framework/Versions/3.14/bin/python3
```

```sh
sudo BACKEND_URL=http://192.168.1.10:8000 \
  BACKEND_TOKEN=change-me-dev-token \
  COLLECTOR_ID=mac-lab-01 \
  COLLECTOR_NAME="Mac Lab 01" \
  DEPLOYMENT_ID=home-lab-cincinnati \
  LABEL_DEVICE_GROUP=mac-test \
  MODE=hybrid \
  collector/install/install-macos.sh
```

Real-world validation pattern:

```sh
sudo env \
  PYTHON_BIN=/Library/Frameworks/Python.framework/Versions/3.14/bin/python3 \
  BACKEND_URL=http://100.86.144.109:8000 \
  BACKEND_TOKEN=change-me-dev-token \
  COLLECTOR_ID=mac-lab-01 \
  COLLECTOR_NAME="Mac Lab 01" \
  DEPLOYMENT_ID=home-lab-cincinnati \
  LABEL_DEVICE_GROUP=mac-test \
  MODE=hybrid \
  bash collector/install/install-macos.sh
```

The macOS installer creates:

```text
/usr/local/openassetwatch/collector
/Library/Application Support/OpenAssetWatch/Collector/config.yaml
/Library/Application Support/OpenAssetWatch/Collector/identity.json
/Library/Application Support/OpenAssetWatch/Collector/install.env
/Library/Logs/OpenAssetWatch
/usr/local/var/openassetwatch
/Library/LaunchDaemons/com.openassetwatch.collector.plist
```

Installer actions are appended to:

```text
/Library/Logs/OpenAssetWatch/install.log
```

It creates a LaunchDaemon that runs at boot, keeps the collector alive, and
calls Python directly:

```text
/usr/local/openassetwatch/collector/.venv/bin/python -m openassetwatch_collector --run-forever --config "/Library/Application Support/OpenAssetWatch/Collector/config.yaml"
```

Load/start the LaunchDaemon:

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.openassetwatch.collector.plist
sudo launchctl enable system/com.openassetwatch.collector
```

Stop/unload the LaunchDaemon:

```sh
sudo launchctl bootout system /Library/LaunchDaemons/com.openassetwatch.collector.plist
```

Check logs:

```sh
tail -n 100 /Library/Logs/OpenAssetWatch/collector.out.log
tail -n 100 /Library/Logs/OpenAssetWatch/collector.err.log
```

Uninstall while preserving config, logs, and state:

```sh
sudo UNINSTALL=true collector/install/install-macos.sh
```

Purge config, logs, and state too:

```sh
sudo UNINSTALL=true PURGE=true collector/install/install-macos.sh
```

Manual folder cleanup:

```sh
sudo launchctl bootout system /Library/LaunchDaemons/com.openassetwatch.collector.plist
sudo rm -f /Library/LaunchDaemons/com.openassetwatch.collector.plist
sudo rm -rf /usr/local/openassetwatch/collector
sudo rm -rf "/Library/Application Support/OpenAssetWatch/Collector"
sudo rm -rf /Library/Logs/OpenAssetWatch
sudo rm -rf /usr/local/var/openassetwatch
```

## Verification

From any machine that can reach the backend:

```sh
curl http://<backend-ip>:8000/api/v1/collectors
curl http://<backend-ip>:8000/api/v1/assets
```

The installed collector should appear in the collectors response, and its local
device plus discovered network neighbors should appear in the assets response
after the first scheduled inventory upload.

## Service Management Helper

The MVP service manager provides a consistent wrapper around the native service
mechanism on each OS:

```sh
python collector/install/service_manager.py status
python collector/install/service_manager.py start
python collector/install/service_manager.py stop
python collector/install/service_manager.py restart
python collector/install/service_manager.py logs
python collector/install/service_manager.py uninstall-info
```

Use `--dry-run` to print the native commands without running them:

```sh
python collector/install/service_manager.py restart --dry-run
```

Windows remains a Task Scheduler MVP. The helper uses `schtasks.exe` for
status, start, stop, and restart.

Linux uses `systemctl` for service control and `journalctl` for recent logs.
Run the helper with `sudo` when the action requires service-manager privileges:

```sh
sudo python collector/install/service_manager.py restart
sudo python collector/install/service_manager.py logs
```

macOS uses `launchctl` with the LaunchDaemon at
`/Library/LaunchDaemons/com.openassetwatch.collector.plist`. Run service
actions with `sudo`:

```sh
sudo python collector/install/service_manager.py status
sudo python collector/install/service_manager.py restart
```

## Policy Retrieval

Collector policy retrieval is disabled by default. If enabled in config or with
`--enable-policy`, the collector retrieves policy from the OpenAssetWatch
Control Plane after check-in.

Example config:

```yaml
policy:
  enabled: false
  cache_path: null
  hold_file_path: null
  check_interval_seconds: 3600
```

The policy MVP can adjust only safe local collector settings such as mode,
scheduler intervals, `open_detector` enabled/disabled, and a one-time
`run_inventory_now` action. It does not allow arbitrary shell commands, binary
updates, Nmap, packet capture, SNMP execution, or network sensor behavior.

If policy retrieval fails, the collector keeps running with local config or the
last known good cached policy. A local emergency hold file blocks policy
retrieval and application:

```text
Windows: C:\ProgramData\OpenAssetWatch\Collector\policy.hold
Linux: /etc/openassetwatch/policy.hold
macOS: /Library/Application Support/OpenAssetWatch/Collector/policy.hold
```

## Troubleshooting

Windows:

```cmd
python collector\install\service_manager.py status
python collector\install\service_manager.py logs
schtasks.exe /Query /TN "OpenAssetWatch Collector" /V /FO LIST
type "C:\ProgramData\OpenAssetWatch\Collector\install.env"
type "C:\ProgramData\OpenAssetWatch\Collector\logs\install.log"
curl http://<backend-ip>:8000/health
curl http://<backend-ip>:8000/api/v1/collectors
curl http://<backend-ip>:8000/api/v1/assets
```

Linux:

```sh
sudo python collector/install/service_manager.py status
sudo python collector/install/service_manager.py logs
sudo systemctl status openassetwatch-collector
sudo journalctl -u openassetwatch-collector -n 100
sudo cat /etc/openassetwatch/install.env
sudo tail -n 100 /var/log/openassetwatch/install.log
ls -la /var/log/openassetwatch
curl http://<backend-ip>:8000/health
curl http://<backend-ip>:8000/api/v1/collectors
curl http://<backend-ip>:8000/api/v1/assets
```

macOS:

```sh
sudo python collector/install/service_manager.py status
python collector/install/service_manager.py logs
sudo launchctl print system/com.openassetwatch.collector
sudo cat "/Library/Application Support/OpenAssetWatch/Collector/install.env"
tail -n 100 /Library/Logs/OpenAssetWatch/install.log
tail -n 100 /Library/Logs/OpenAssetWatch/collector.out.log
tail -n 100 /Library/Logs/OpenAssetWatch/collector.err.log
curl http://<backend-ip>:8000/health
curl http://<backend-ip>:8000/api/v1/collectors
curl http://<backend-ip>:8000/api/v1/assets
```

## Future Packaging Roadmap

Packaging is not part of this installer-hardening PR. This PR stays focused on
install, reinstall/idempotency, uninstall, purge behavior, installer logs,
install metadata, troubleshooting docs, and the installer test matrix.

Windows future:

- MSI or EXE installer.
- True Windows Service or service wrapper later.

Linux future:

- DEB/RPM packages.
- Include the `systemd` service in the package.

macOS future:

- PKG installer first.
- Optional DMG wrapper containing the PKG.
- Signing and notarization later.

A DMG is a distribution container. The PKG is the better mechanism for
installing LaunchDaemon files and setting protected system permissions.

## Out of Scope

- MSI packages.
- EXE installers.
- DEB/RPM packages.
- True Windows Service implementation.
- DMG packaging.
- macOS PKG installer.
- macOS notarization/signing.
- MDM deployment.
- Authentication or API keys.
- Frontend service management.
- AI, Splunk TA, packet capture, Nmap, masscan, Zeek, or Suricata.
