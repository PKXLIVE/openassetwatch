#!/usr/bin/env bash
set -euo pipefail

OAW_VERSION="0.1.0-foundation"
MODE="agent"
SERVICE_NAME=""
PURGE_CONFIG="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:?missing mode}"; shift 2 ;;
    --service-name) SERVICE_NAME="${2:?missing service name}"; shift 2 ;;
    --purge-config) PURGE_CONFIG="true"; shift ;;
    --version) echo "OpenAssetWatch macOS uninstaller ${OAW_VERSION}"; exit 0 ;;
    --help) echo "Usage: uninstall.sh [--mode agent|sensor] [--service-name NAME] [--purge-config] [--version]"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "${MODE}" in
  agent|sensor) ;;
  *) echo "--mode must be agent or sensor" >&2; exit 2 ;;
esac

if [[ "$(id -u)" != "0" ]]; then
  echo "uninstall.sh must be run as root to remove a LaunchDaemon" >&2
  exit 1
fi

SERVICE_NAME="${SERVICE_NAME:-com.openassetwatch.${MODE}}"
PLIST_PATH="/Library/LaunchDaemons/${SERVICE_NAME}.plist"
CONFIG_PATH="/Library/Application Support/OpenAssetWatch/${MODE}.json"

launchctl bootout "system/${SERVICE_NAME}" 2>/dev/null || true
rm -f "${PLIST_PATH}"

if [[ "${PURGE_CONFIG}" == "true" ]]; then
  rm -f "${CONFIG_PATH}"
fi

echo "Uninstalled ${SERVICE_NAME}"
echo "Config purged: ${PURGE_CONFIG}"
echo "Version: ${OAW_VERSION}"
