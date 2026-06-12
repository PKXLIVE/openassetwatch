#!/usr/bin/env bash
set -euo pipefail

INSTALLER_VERSION="${INSTALLER_VERSION:-0.1.0}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/openassetwatch/collector}"
CONFIG_DIR="${CONFIG_DIR:-/Library/Application Support/OpenAssetWatch/Collector}"
CONFIG_PATH="${CONFIG_PATH:-${CONFIG_DIR}/config.yaml}"
METADATA_PATH="${METADATA_PATH:-${CONFIG_DIR}/install.env}"
LOG_DIR="${LOG_DIR:-/Library/Logs/OpenAssetWatch}"
INSTALL_LOG="${INSTALL_LOG:-${LOG_DIR}/install.log}"
STATE_DIR="${STATE_DIR:-/usr/local/var/openassetwatch}"
PLIST_PATH="${PLIST_PATH:-/Library/LaunchDaemons/com.openassetwatch.collector.plist}"
LABEL="com.openassetwatch.collector"
MODE="${MODE:-hybrid}"
HEARTBEAT_INTERVAL_SECONDS="${HEARTBEAT_INTERVAL_SECONDS:-3600}"
INVENTORY_INTERVAL_SECONDS="${INVENTORY_INTERVAL_SECONDS:-86400}"
COLLECTOR_ID="${COLLECTOR_ID:-$(hostname)-collector}"
COLLECTOR_NAME="${COLLECTOR_NAME:-$(hostname)}"
START_SERVICE="${START_SERVICE:-true}"
UNINSTALL="${UNINSTALL:-false}"
PURGE="${PURGE:-false}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_SOURCE_DIR="${COLLECTOR_SOURCE_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
PYTHON_BIN="${PYTHON_BIN:-}"

log() {
  mkdir -p "${LOG_DIR}" >/dev/null 2>&1 || true
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*" >> "${INSTALL_LOG}" 2>/dev/null || true
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  log "error installer invoked on non-macOS host"
  echo "This installer is for macOS only." >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  log "error macOS installation must be run as root"
  echo "macOS installation must be run as root. Re-run with sudo." >&2
  exit 1
fi

if [[ "${UNINSTALL}" == "true" ]]; then
  log "uninstall start platform=macos"
  launchctl bootout system "${PLIST_PATH}" >/dev/null 2>&1 || true
  log "launchdaemon bootout requested plist=${PLIST_PATH}"
  rm -f "${PLIST_PATH}"
  log "launchdaemon plist removed path=${PLIST_PATH}"
  rm -rf "${INSTALL_DIR}"
  log "removed install directory path=${INSTALL_DIR}"
  if [[ "${PURGE}" == "true" ]]; then
    log "purge requested"
    log "uninstall complete platform=macos purge=true"
    rm -rf "${CONFIG_DIR}" "${LOG_DIR}" "${STATE_DIR}"
  else
    echo "Preserving config directory: ${CONFIG_DIR}"
    echo "Preserving log directory: ${LOG_DIR}"
    echo "Preserving state directory: ${STATE_DIR}"
    log "uninstall complete platform=macos"
  fi
  echo "OpenAssetWatch collector uninstalled."
  exit 0
fi

if [[ -z "${BACKEND_URL:-}" ]]; then
  log "error BACKEND_URL is required"
  echo "BACKEND_URL is required, for example BACKEND_URL=http://192.168.1.10:8000" >&2
  exit 1
fi

python_version() {
  "$1" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")'
}

python_is_supported() {
  "$1" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1
}

resolve_python() {
  if [[ -n "${PYTHON_BIN}" ]]; then
    command -v "${PYTHON_BIN}"
    return
  fi

  local candidates=(
    "/opt/homebrew/bin/python3.14"
    "/opt/homebrew/bin/python3.13"
    "/opt/homebrew/bin/python3.12"
    "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3"
    "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3"
    "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3"
    "python3.14"
    "python3.13"
    "python3.12"
    "python3.11"
    "python3.10"
    "python3"
  )

  local candidate
  for candidate in "${candidates[@]}"; do
    if command -v "${candidate}" >/dev/null 2>&1; then
      command -v "${candidate}"
      return
    fi
  done
}

SELECTED_PYTHON="$(resolve_python || true)"
if [[ -z "${SELECTED_PYTHON}" ]]; then
  log "error Python >=3.10 is required; no supported Python found"
  echo "Python >=3.10 is required. Set PYTHON_BIN to a supported Python path." >&2
  exit 1
fi

PYTHON_VERSION="$(python_version "${SELECTED_PYTHON}")"
echo "Using Python: ${SELECTED_PYTHON} (${PYTHON_VERSION})"
log "install start platform=macos installer_version=${INSTALLER_VERSION}"
log "selected python path=${SELECTED_PYTHON} version=${PYTHON_VERSION}"

if ! python_is_supported "${SELECTED_PYTHON}"; then
  log "error unsupported python path=${SELECTED_PYTHON} version=${PYTHON_VERSION}"
  echo "Python >=3.10 is required, but ${SELECTED_PYTHON} is ${PYTHON_VERSION}." >&2
  echo "Set PYTHON_BIN to a supported Python, such as /opt/homebrew/bin/python3.12 or /Library/Frameworks/Python.framework/Versions/3.14/bin/python3." >&2
  exit 1
fi

install -d -m 0755 "${INSTALL_DIR}"
install -d -m 0750 "${CONFIG_DIR}"
install -d -m 0755 "${LOG_DIR}"
install -d -m 0755 "${STATE_DIR}"

if [[ -x "${INSTALL_DIR}/.venv/bin/python" ]] && ! python_is_supported "${INSTALL_DIR}/.venv/bin/python"; then
  EXISTING_VENV_VERSION="$(python_version "${INSTALL_DIR}/.venv/bin/python")"
  echo "Existing collector venv uses unsupported Python ${EXISTING_VENV_VERSION}; recreating ${INSTALL_DIR}/.venv"
  log "venv recreation required existing_python_version=${EXISTING_VENV_VERSION} venv=${INSTALL_DIR}/.venv"
  rm -rf "${INSTALL_DIR}/.venv"
fi

log "venv create/update start venv=${INSTALL_DIR}/.venv"
"${SELECTED_PYTHON}" -m venv "${INSTALL_DIR}/.venv"
log "venv create/update complete venv=${INSTALL_DIR}/.venv"
log "package install start"
"${INSTALL_DIR}/.venv/bin/python" -m pip install "${COLLECTOR_SOURCE_DIR}"
log "package install complete"

cat > "${CONFIG_PATH}.tmp" <<EOF
collector:
  id: "${COLLECTOR_ID}"
  name: "${COLLECTOR_NAME}"
  mode: ${MODE}

backend:
  url: "${BACKEND_URL}"

checkin:
  enabled: true

inventory:
  upload_enabled: true

scheduler:
  enabled: true
  heartbeat_interval_seconds: ${HEARTBEAT_INTERVAL_SECONDS}
  inventory_interval_seconds: ${INVENTORY_INTERVAL_SECONDS}
EOF

install -m 0640 -o root -g wheel "${CONFIG_PATH}.tmp" "${CONFIG_PATH}"
rm -f "${CONFIG_PATH}.tmp"
log "config write/update path=${CONFIG_PATH}"

cat > "${METADATA_PATH}.tmp" <<EOF
INSTALLER_VERSION=${INSTALLER_VERSION}
INSTALL_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PLATFORM=macos
SELECTED_PYTHON_PATH=${SELECTED_PYTHON}
SELECTED_PYTHON_VERSION=${PYTHON_VERSION}
VENV_PYTHON_PATH=${INSTALL_DIR}/.venv/bin/python
BACKEND_URL=${BACKEND_URL}
COLLECTOR_ID=${COLLECTOR_ID}
EOF

install -m 0640 -o root -g wheel "${METADATA_PATH}.tmp" "${METADATA_PATH}"
rm -f "${METADATA_PATH}.tmp"
log "metadata write/update path=${METADATA_PATH}"

touch "${LOG_DIR}/collector.out.log" "${LOG_DIR}/collector.err.log"
chown -R root:wheel "${INSTALL_DIR}" "${CONFIG_DIR}" "${LOG_DIR}" "${STATE_DIR}"
chmod 0755 "${INSTALL_DIR}" "${STATE_DIR}" "${LOG_DIR}"
chmod 0750 "${CONFIG_DIR}"
chmod 0640 "${CONFIG_PATH}" "${METADATA_PATH}"
chmod 0644 "${LOG_DIR}/collector.out.log" "${LOG_DIR}/collector.err.log"

cat > "${PLIST_PATH}.tmp" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${INSTALL_DIR}/.venv/bin/python</string>
    <string>-m</string>
    <string>openassetwatch_collector</string>
    <string>--run-forever</string>
    <string>--config</string>
    <string>${CONFIG_PATH}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${INSTALL_DIR}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${LOG_DIR}/collector.out.log</string>
  <key>StandardErrorPath</key>
  <string>${LOG_DIR}/collector.err.log</string>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
EOF

if command -v plutil >/dev/null 2>&1; then
  plutil -lint "${PLIST_PATH}.tmp"
fi

install -m 0644 -o root -g wheel "${PLIST_PATH}.tmp" "${PLIST_PATH}"
rm -f "${PLIST_PATH}.tmp"
log "launchdaemon plist write/update path=${PLIST_PATH}"

if [[ "${START_SERVICE}" == "true" ]]; then
  launchctl bootout system "${PLIST_PATH}" >/dev/null 2>&1 || true
  log "launchdaemon bootout requested before bootstrap plist=${PLIST_PATH}"
  launchctl bootstrap system "${PLIST_PATH}"
  log "launchdaemon bootstrap complete plist=${PLIST_PATH}"
  launchctl enable "system/${LABEL}" >/dev/null 2>&1 || true
  log "launchdaemon enable requested label=${LABEL}"
fi

log "install complete platform=macos"
echo "OpenAssetWatch collector installed."
echo "LaunchDaemon: ${PLIST_PATH}"
echo "Config: ${CONFIG_PATH}"
echo "Logs:"
echo "  ${LOG_DIR}/collector.out.log"
echo "  ${LOG_DIR}/collector.err.log"
