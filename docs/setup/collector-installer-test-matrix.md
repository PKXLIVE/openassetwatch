# Collector Installer Test Matrix

This matrix is for validating the OpenAssetWatch collector installers across
Windows, Linux, and macOS.

Use a backend URL reachable from the collector host. For remote collectors, use
the backend machine's LAN IP, Tailscale IP, or DNS name. Do not use `localhost`
unless the backend is running on the same machine.

## Windows

| Scenario | Command / Check | Expected Result |
| --- | --- | --- |
| Dry run | `python collector\install\install.py --backend-url http://<backend-ip>:8000 --collector-id windows-test --dry-run --no-start` | Prints directories, config, venv install, and `schtasks.exe` commands without writing system files. |
| Install | `python collector\install\install.py --backend-url http://<backend-ip>:8000 --collector-id windows-test --collector-name "Windows Test"` | Creates venv, config, metadata, logs/state directories, and startup scheduled task. |
| Scheduled task starts | `schtasks.exe /Query /TN "OpenAssetWatch Collector" /V /FO LIST` | Task exists and points to `.venv\Scripts\python.exe -m openassetwatch_collector --run-forever --config ...`. |
| Service manager status | `python collector\install\service_manager.py status` | Prints scheduled task status through `schtasks.exe`; confirms this is the Task Scheduler MVP. |
| Service manager restart | `python collector\install\service_manager.py restart --dry-run` | Prints `schtasks.exe /End` followed by `schtasks.exe /Run` without running them. |
| Service manager logs | `python collector\install\service_manager.py logs` | Points to `C:\ProgramData\OpenAssetWatch\Collector\logs` and `install.log`. |
| Backend receives collector | `curl http://<backend-ip>:8000/api/v1/collectors` | Collector appears after check-in/inventory cycle. |
| Backend receives assets | `curl http://<backend-ip>:8000/api/v1/assets` | Local device and network observations appear. |
| Identity file | `type "C:\ProgramData\OpenAssetWatch\Collector\identity.json"` | Stable `collector_guid` exists and is not regenerated after reinstall. |
| Installer log | `type "C:\ProgramData\OpenAssetWatch\Collector\logs\install.log"` | Timestamped install/reinstall/uninstall actions are present without secrets. |
| Reinstall | Run the install command again. | Install completes, service definition is updated safely, config/metadata are refreshed intentionally. |
| Uninstall | `python collector\install\install.py --uninstall` | Scheduled task and install directory are removed; config/log/state are preserved. |
| Purge uninstall | `python collector\install\install.py --uninstall --purge` | Scheduled task, install, config, log, and state directories are removed. |

## Linux

| Scenario | Command / Check | Expected Result |
| --- | --- | --- |
| Dry run | `sudo python collector/install/install.py --backend-url http://<backend-ip>:8000 --collector-id linux-test --dry-run --no-start` | Prints user, permissions, config, metadata, systemd, and optional sudoers actions without writing system files. |
| Install | `sudo BACKEND_URL=http://<backend-ip>:8000 COLLECTOR_ID=linux-test COLLECTOR_NAME="Linux Test" collector/install/install-linux.sh` | Creates `openassetwatch` user/group, venv, config, metadata, systemd service, logs/state directories. |
| systemd service starts | `sudo systemctl status openassetwatch-collector` | Service is active or restarting with clear logs. |
| Service manager status | `sudo python collector/install/service_manager.py status` | Runs `systemctl status openassetwatch-collector`. |
| Service manager restart | `sudo python collector/install/service_manager.py restart --dry-run` | Prints `systemctl restart openassetwatch-collector` without running it. |
| Logs | `sudo journalctl -u openassetwatch-collector -n 100` | Scheduler/check-in/inventory messages are visible. |
| Service manager logs | `sudo python collector/install/service_manager.py logs` | Runs `journalctl -u openassetwatch-collector -n 100 --no-pager` and points to `/var/log/openassetwatch`. |
| Backend receives collector | `curl http://<backend-ip>:8000/api/v1/collectors` | Collector appears after check-in/inventory cycle. |
| Backend receives assets | `curl http://<backend-ip>:8000/api/v1/assets` | Local device and network observations appear. |
| Identity file | `sudo cat /etc/openassetwatch/identity.json` | Stable `collector_guid` exists and is not regenerated after reinstall. |
| Installer log | `sudo tail -n 100 /var/log/openassetwatch/install.log` | Timestamped install/reinstall/uninstall actions are present without secrets. |
| Reinstall | Run the install command again. | Install completes, systemd unit is replaced safely, config/metadata are refreshed intentionally. |
| Uninstall | `sudo UNINSTALL=true collector/install/install-linux.sh` | systemd service, service file, sudoers file, and install directory are removed; config/log/state are preserved. |
| Purge uninstall | `sudo UNINSTALL=true PURGE=true collector/install/install-linux.sh` | Install, config, log, state, service, and sudoers files are removed. |

## macOS

| Scenario | Command / Check | Expected Result |
| --- | --- | --- |
| Install with `PYTHON_BIN` | `sudo env PYTHON_BIN=/Library/Frameworks/Python.framework/Versions/3.14/bin/python3 BACKEND_URL=http://<backend-ip>:8000 COLLECTOR_ID=mac-test COLLECTOR_NAME="Mac Test" MODE=hybrid bash collector/install/install-macos.sh` | Installer prints selected Python path/version, creates venv, config, metadata, logs/state directories, and LaunchDaemon plist. |
| LaunchDaemon starts | `sudo launchctl print system/com.openassetwatch.collector` | LaunchDaemon is loaded and running or retrying with logs. |
| Service manager status | `sudo python collector/install/service_manager.py status` | Runs `launchctl print system/com.openassetwatch.collector`. |
| Service manager restart | `sudo python collector/install/service_manager.py restart --dry-run` | Prints `launchctl bootout` followed by `launchctl bootstrap` without running them. |
| Logs | `tail -n 100 /Library/Logs/OpenAssetWatch/collector.out.log` and `tail -n 100 /Library/Logs/OpenAssetWatch/collector.err.log` | Scheduler/check-in/inventory messages are visible. |
| Service manager logs | `python collector/install/service_manager.py logs` | Points to collector stdout/stderr logs and installer log. |
| Backend receives collector | `curl http://<backend-ip>:8000/api/v1/collectors` | Collector appears after check-in/inventory cycle. |
| Backend receives assets | `curl http://<backend-ip>:8000/api/v1/assets` | Local device and network observations appear. |
| Identity file | `sudo cat "/Library/Application Support/OpenAssetWatch/Collector/identity.json"` | Stable `collector_guid` exists and is not regenerated after reinstall. |
| Installer log | `tail -n 100 /Library/Logs/OpenAssetWatch/install.log` | Timestamped install/reinstall/uninstall actions are present without secrets. |
| Reinstall | Run the install command again. | Install completes, LaunchDaemon plist is replaced safely, config/metadata are refreshed intentionally. |
| Uninstall | `sudo UNINSTALL=true collector/install/install-macos.sh` | LaunchDaemon is booted out, plist and install directory are removed; config/log/state are preserved. |
| Purge uninstall | `sudo UNINSTALL=true PURGE=true collector/install/install-macos.sh` | Install, config, log, state, and plist files are removed. |

## Out of Scope

- MSI, DEB/RPM, PKG packaging.
- Remote binary update.
- macOS notarization/signing.
- MDM deployment.
- Packet capture.
- Nmap, masscan, Zeek, Suricata, or OSINT tools.
- Authentication/API keys.
- Frontend, AI, and Splunk TA work.
