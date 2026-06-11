# Local Collector Installation MVP

This guide describes the MVP local installer flow for testing OpenAssetWatch
collectors on multiple machines.

The collector remains Python-first. Native service managers are used only to
keep the Python collector running:

- Windows: Task Scheduler.
- Linux: systemd.
- macOS: launchd LaunchDaemon.

Existing one-shot collector commands are unchanged.

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
  --collector-id windows-lab-01 ^
  --collector-name "Windows Lab 01" ^
  --mode hybrid
```

The Python installer creates:

```text
C:\Program Files\OpenAssetWatch\Collector
C:\ProgramData\OpenAssetWatch\Collector\config.yaml
C:\ProgramData\OpenAssetWatch\Collector\logs
C:\ProgramData\OpenAssetWatch\Collector\state
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

Manual uninstall for the MVP:

```cmd
schtasks.exe /Delete /TN "OpenAssetWatch Collector" /F
rmdir /S /Q "C:\Program Files\OpenAssetWatch\Collector"
rmdir /S /Q "C:\ProgramData\OpenAssetWatch\Collector"
```

## Linux Install

Run from the repository root on the collector host.

```sh
sudo BACKEND_URL=http://192.168.1.10:8000 \
  COLLECTOR_ID=linux-lab-01 \
  COLLECTOR_NAME="Linux Lab 01" \
  MODE=hybrid \
  collector/install/install-linux.sh
```

The Linux installer creates:

```text
/opt/openassetwatch/collector
/etc/openassetwatch/collector.yaml
/var/lib/openassetwatch
/var/log/openassetwatch
/etc/systemd/system/openassetwatch-collector.service
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

Manual uninstall for the MVP:

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

```sh
sudo BACKEND_URL=http://192.168.1.10:8000 \
  COLLECTOR_ID=mac-lab-01 \
  COLLECTOR_NAME="Mac Lab 01" \
  MODE=hybrid \
  collector/install/install-macos.sh
```

The macOS installer creates:

```text
/usr/local/openassetwatch/collector
/Library/Application Support/OpenAssetWatch/Collector/config.yaml
/Library/Logs/OpenAssetWatch
/usr/local/var/openassetwatch
/Library/LaunchDaemons/com.openassetwatch.collector.plist
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
tail -f /Library/Logs/OpenAssetWatch/collector.out.log
tail -f /Library/Logs/OpenAssetWatch/collector.err.log
```

Manual uninstall for the MVP:

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

## Out of Scope

- MSI packages.
- DEB/RPM packages.
- True Windows Service implementation.
- macOS PKG installer.
- macOS notarization/signing.
- MDM deployment.
- Authentication or API keys.
- Frontend service management.
- AI, Splunk TA, packet capture, Nmap, masscan, Zeek, or Suricata.
