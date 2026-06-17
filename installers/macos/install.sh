#!/usr/bin/env bash
set -euo pipefail

OAW_VERSION="0.1.0-foundation"
MODE="agent"
SERVICE_NAME=""
CONFIG_PATH=""
BIN_PATH=""
RUN_USER="nobody"

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

Options:
  --mode agent|sensor        Install agent or sensor service. Default: agent
  --service-name NAME        Override LaunchDaemon label.
  --config PATH              Config path. Default: /Library/Application Support/OpenAssetWatch/<mode>.json
  --bin PATH                 OAW binary path. Default: /usr/local/bin/oaw-<mode>
  --user NAME                LaunchDaemon user. Default: nobody
  --version                  Print installer version and exit.
  --help                     Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:?missing mode}"; shift 2 ;;
    --service-name) SERVICE_NAME="${2:?missing service name}"; shift 2 ;;
    --config) CONFIG_PATH="${2:?missing config path}"; shift 2 ;;
    --bin) BIN_PATH="${2:?missing binary path}"; shift 2 ;;
    --user) RUN_USER="${2:?missing user}"; shift 2 ;;
    --version) echo "OpenAssetWatch macOS installer ${OAW_VERSION}"; exit 0 ;;
    --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "${MODE}" in
  agent|sensor) ;;
  *) echo "--mode must be agent or sensor" >&2; exit 2 ;;
esac

if [[ "$(id -u)" != "0" ]]; then
  echo "install.sh must be run as root to create a LaunchDaemon" >&2
  exit 1
fi

SERVICE_NAME="${SERVICE_NAME:-com.openassetwatch.${MODE}}"
CONFIG_PATH="${CONFIG_PATH:-/Library/Application Support/OpenAssetWatch/${MODE}.json}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/oaw-${MODE}}"
PLIST_PATH="/Library/LaunchDaemons/${SERVICE_NAME}.plist"

install -d -m 0750 "/Library/Application Support/OpenAssetWatch"
install -d -m 0750 "/Library/Logs/OpenAssetWatch"

if [[ ! -x "${BIN_PATH}" ]]; then
  echo "warning: ${BIN_PATH} is not executable yet; LaunchDaemon will be staged only" >&2
fi

cat > "${PLIST_PATH}" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${SERVICE_NAME}</string>
  <key>UserName</key>
  <string>${RUN_USER}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${BIN_PATH}</string>
    <string>--config</string>
    <string>${CONFIG_PATH}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/Library/Logs/OpenAssetWatch/${MODE}.log</string>
  <key>StandardErrorPath</key>
  <string>/Library/Logs/OpenAssetWatch/${MODE}.err.log</string>
</dict>
</plist>
PLIST

chmod 0644 "${PLIST_PATH}"
launchctl bootstrap system "${PLIST_PATH}" 2>/dev/null || true
launchctl enable "system/${SERVICE_NAME}" 2>/dev/null || true

echo "Installed ${SERVICE_NAME}"
echo "Mode: ${MODE}"
echo "Config: ${CONFIG_PATH}"
echo "Version: ${OAW_VERSION}"
