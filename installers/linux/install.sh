#!/usr/bin/env bash
set -euo pipefail

OAW_VERSION="0.1.0-foundation"
MODE="agent"
SERVICE_NAME=""
CONFIG_PATH=""
BIN_PATH=""
RUN_USER="openassetwatch"

usage() {
  cat <<'USAGE'
Usage: install.sh [options]

Options:
  --mode agent|sensor        Install agent or sensor service. Default: agent
  --service-name NAME        Override service name.
  --config PATH              Config path. Default: /etc/openassetwatch/<mode>.json
  --bin PATH                 OpenAssetWatch binary path. Default: /usr/local/bin/oaw-<mode>
  --user NAME                Service user. Default: openassetwatch
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
    --version) echo "OpenAssetWatch Linux installer ${OAW_VERSION}"; exit 0 ;;
    --help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "${MODE}" in
  agent|sensor) ;;
  *) echo "--mode must be agent or sensor" >&2; exit 2 ;;
esac

if [[ "$(id -u)" != "0" ]]; then
  echo "install.sh must be run as root to create the service user and systemd unit" >&2
  exit 1
fi

SERVICE_NAME="${SERVICE_NAME:-oaw-${MODE}}"
CONFIG_PATH="${CONFIG_PATH:-/etc/openassetwatch/${MODE}.json}"
BIN_PATH="${BIN_PATH:-/usr/local/bin/oaw-${MODE}}"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

if ! id "${RUN_USER}" >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/openassetwatch --shell /usr/sbin/nologin "${RUN_USER}"
fi

install -d -m 0750 -o "${RUN_USER}" -g "${RUN_USER}" /etc/openassetwatch
install -d -m 0750 -o "${RUN_USER}" -g "${RUN_USER}" /var/lib/openassetwatch
install -d -m 0750 -o "${RUN_USER}" -g "${RUN_USER}" /var/log/openassetwatch

if [[ ! -x "${BIN_PATH}" ]]; then
  echo "warning: ${BIN_PATH} is not executable yet; service unit will be staged only" >&2
fi

cat > "${UNIT_PATH}" <<UNIT
[Unit]
Description=OpenAssetWatch ${MODE} service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_USER}
ExecStart=${BIN_PATH} --config ${CONFIG_PATH}
Restart=on-failure
RestartSec=15
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/openassetwatch /var/log/openassetwatch

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"

echo "Installed ${SERVICE_NAME}"
echo "Mode: ${MODE}"
echo "Config: ${CONFIG_PATH}"
echo "Version: ${OAW_VERSION}"
