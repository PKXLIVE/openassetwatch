#!/usr/bin/env bash
set -euo pipefail

OAW_VERSION="0.1.0-foundation"
MODE="agent"
SERVICE_NAME=""
PURGE_CONFIG="false"

usage() {
  cat <<'USAGE'
Usage: uninstall.sh [options]

Options:
  --mode agent|sensor        Uninstall agent or sensor service. Default: agent
  --service-name NAME        Override service name.
  --purge-config             Remove /etc/openassetwatch/<mode>.json.
  --version                  Print installer version and exit.
  --help                     Show this help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:?missing mode}"; shift 2 ;;
    --service-name) SERVICE_NAME="${2:?missing service name}"; shift 2 ;;
    --purge-config) PURGE_CONFIG="true"; shift ;;
    --version) echo "OpenAssetWatch Linux uninstaller ${OAW_VERSION}"; exit 0 ;;
    --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "${MODE}" in
  agent|sensor) ;;
  *) echo "--mode must be agent or sensor" >&2; exit 2 ;;
esac

if [[ "$(id -u)" != "0" ]]; then
  echo "uninstall.sh must be run as root to remove a system service" >&2
  exit 1
fi

SERVICE_NAME="${SERVICE_NAME:-oaw-${MODE}}"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
CONFIG_PATH="/etc/openassetwatch/${MODE}.json"

systemctl disable --now "${SERVICE_NAME}" >/dev/null 2>&1 || true
rm -f "${UNIT_PATH}"
systemctl daemon-reload

if [[ "${PURGE_CONFIG}" == "true" ]]; then
  rm -f "${CONFIG_PATH}"
fi

echo "Uninstalled ${SERVICE_NAME}"
echo "Config purged: ${PURGE_CONFIG}"
echo "Version: ${OAW_VERSION}"
