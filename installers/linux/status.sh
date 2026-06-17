#!/usr/bin/env bash
set -euo pipefail

OAW_VERSION="0.1.0-foundation"
MODE="agent"
SERVICE_NAME=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:?missing mode}"; shift 2 ;;
    --service-name) SERVICE_NAME="${2:?missing service name}"; shift 2 ;;
    --version) echo "OpenAssetWatch Linux status ${OAW_VERSION}"; exit 0 ;;
    --help) echo "Usage: status.sh [--mode agent|sensor] [--service-name NAME] [--version]"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "${MODE}" in
  agent|sensor) ;;
  *) echo "--mode must be agent or sensor" >&2; exit 2 ;;
esac

SERVICE_NAME="${SERVICE_NAME:-oaw-${MODE}}"

echo "Service: ${SERVICE_NAME}"
echo "Mode: ${MODE}"
echo "Version: ${OAW_VERSION}"
systemctl status "${SERVICE_NAME}" --no-pager || true
