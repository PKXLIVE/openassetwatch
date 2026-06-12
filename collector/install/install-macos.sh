#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/usr/local/openassetwatch/collector}"
CONFIG_DIR="${CONFIG_DIR:-/Library/Application Support/OpenAssetWatch/Collector}"
CONFIG_PATH="${CONFIG_PATH:-${CONFIG_DIR}/config.yaml}"
LOG_DIR="${LOG_DIR:-/Library/Logs/OpenAssetWatch}"
STATE_DIR="${STATE_DIR:-/usr/local/var/openassetwatch}"
PLIST_PATH="${PLIST_PATH:-/Library/LaunchDaemons/com.openassetwatch.collector.plist}"
LABEL="com.openassetwatch.collector"
MODE="${MODE:-hybrid}"
HEARTBEAT_INTERVAL_SECONDS="${HEARTBEAT_INTERVAL_SECONDS:-3600}"
INVENTORY_INTERVAL_SECONDS="${INVENTORY_INTERVAL_SECONDS:-86400}"
COLLECTOR_ID="${COLLECTOR_ID:-$(hostname)-collector}"
COLLECTOR_NAME="${COLLECTOR_NAME:-$(hostname)}"
START_SERVICE="${START_SERVICE:-true}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_SOURCE_DIR="${COLLECTOR_SOURCE_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
PYTHON_BIN="${PYTHON_BIN:-}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer is for macOS only." >&2
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "macOS installation must be run as root. Re-run with sudo." >&2
  exit 1
fi

if [[ -z "${BACKEND_URL:-}" ]]; then
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
  echo "Python >=3.10 is required. Set PYTHON_BIN to a supported Python path." >&2
  exit 1
fi

PYTHON_VERSION="$(python_version "${SELECTED_PYTHON}")"
echo "Using Python: ${SELECTED_PYTHON} (${PYTHON_VERSION})"

if ! python_is_supported "${SELECTED_PYTHON}"; then
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
  rm -rf "${INSTALL_DIR}/.venv"
fi

"${SELECTED_PYTHON}" -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/python" -m pip install "${COLLECTOR_SOURCE_DIR}"

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

touch "${LOG_DIR}/collector.out.log" "${LOG_DIR}/collector.err.log"
chown -R root:wheel "${INSTALL_DIR}" "${CONFIG_DIR}" "${LOG_DIR}" "${STATE_DIR}"
chmod 0755 "${INSTALL_DIR}" "${STATE_DIR}" "${LOG_DIR}"
chmod 0750 "${CONFIG_DIR}"
chmod 0640 "${CONFIG_PATH}"
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

if [[ "${START_SERVICE}" == "true" ]]; then
  launchctl bootout system "${PLIST_PATH}" >/dev/null 2>&1 || true
  launchctl bootstrap system "${PLIST_PATH}"
  launchctl enable "system/${LABEL}" >/dev/null 2>&1 || true
fi

echo "OpenAssetWatch collector installed."
echo "LaunchDaemon: ${PLIST_PATH}"
echo "Config: ${CONFIG_PATH}"
echo "Logs:"
echo "  ${LOG_DIR}/collector.out.log"
echo "  ${LOG_DIR}/collector.err.log"
