#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/openassetwatch/collector}"
CONFIG_DIR="${CONFIG_DIR:-/etc/openassetwatch}"
CONFIG_PATH="${CONFIG_PATH:-${CONFIG_DIR}/collector.yaml}"
STATE_DIR="${STATE_DIR:-/var/lib/openassetwatch}"
LOG_DIR="${LOG_DIR:-/var/log/openassetwatch}"
SERVICE_PATH="${SERVICE_PATH:-/etc/systemd/system/openassetwatch-collector.service}"
SERVICE_NAME="openassetwatch-collector.service"
USER_NAME="${USER_NAME:-openassetwatch}"
GROUP_NAME="${GROUP_NAME:-openassetwatch}"
MODE="${MODE:-hybrid}"
HEARTBEAT_INTERVAL_SECONDS="${HEARTBEAT_INTERVAL_SECONDS:-3600}"
INVENTORY_INTERVAL_SECONDS="${INVENTORY_INTERVAL_SECONDS:-86400}"
COLLECTOR_ID="${COLLECTOR_ID:-$(hostname)-collector}"
COLLECTOR_NAME="${COLLECTOR_NAME:-$(hostname)}"
ENABLE_LOG_READ="${ENABLE_LOG_READ:-false}"
INSTALL_SUDOERS="${INSTALL_SUDOERS:-false}"
START_SERVICE="${START_SERVICE:-true}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_SOURCE_DIR="${COLLECTOR_SOURCE_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Linux installation must be run as root. Re-run with sudo." >&2
  exit 1
fi

if [[ -z "${BACKEND_URL:-}" ]]; then
  echo "BACKEND_URL is required, for example BACKEND_URL=http://192.168.1.10:8000" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is required for the Linux MVP installer" >&2
  exit 1
fi

if ! getent group "${GROUP_NAME}" >/dev/null 2>&1; then
  groupadd --system "${GROUP_NAME}"
fi

if ! id -u "${USER_NAME}" >/dev/null 2>&1; then
  LOGIN_SHELL="/bin/false"
  if [[ -x /usr/sbin/nologin ]]; then
    LOGIN_SHELL="/usr/sbin/nologin"
  fi
  useradd \
    --system \
    --gid "${GROUP_NAME}" \
    --home-dir "${STATE_DIR}" \
    --shell "${LOGIN_SHELL}" \
    --no-create-home \
    "${USER_NAME}"
fi

if command -v passwd >/dev/null 2>&1; then
  passwd -l "${USER_NAME}" >/dev/null 2>&1 || true
elif command -v usermod >/dev/null 2>&1; then
  usermod -L "${USER_NAME}" >/dev/null 2>&1 || true
fi

install -d -m 0755 "${INSTALL_DIR}"
install -d -m 0750 -o "${USER_NAME}" -g "${GROUP_NAME}" "${STATE_DIR}"
install -d -m 0750 -o "${USER_NAME}" -g "${GROUP_NAME}" "${LOG_DIR}"
install -d -m 0750 -o root -g "${GROUP_NAME}" "${CONFIG_DIR}"

python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/python" -m pip install "${COLLECTOR_SOURCE_DIR}"

cat > "${CONFIG_PATH}.tmp" <<EOF
collector:
  id: ${COLLECTOR_ID}
  name: ${COLLECTOR_NAME}
  mode: ${MODE}

backend:
  url: ${BACKEND_URL}

checkin:
  enabled: true

inventory:
  upload_enabled: true

scheduler:
  enabled: true
  heartbeat_interval_seconds: ${HEARTBEAT_INTERVAL_SECONDS}
  inventory_interval_seconds: ${INVENTORY_INTERVAL_SECONDS}
EOF

install -m 0640 -o root -g "${GROUP_NAME}" "${CONFIG_PATH}.tmp" "${CONFIG_PATH}"
rm -f "${CONFIG_PATH}.tmp"

chown -R "${USER_NAME}:${GROUP_NAME}" /opt/openassetwatch
chown -R "${USER_NAME}:${GROUP_NAME}" "${STATE_DIR}" "${LOG_DIR}"
chown root:"${GROUP_NAME}" "${CONFIG_DIR}" "${CONFIG_PATH}"
chmod 0750 "${CONFIG_DIR}"
chmod 0640 "${CONFIG_PATH}"

if [[ "${INSTALL_SUDOERS}" == "true" ]]; then
  if ! command -v visudo >/dev/null 2>&1; then
    echo "visudo is required when INSTALL_SUDOERS=true" >&2
    exit 1
  fi

  SUDOERS_TMP="$(mktemp)"
  {
    echo "# OpenAssetWatch collector command allowlist."
    echo "# Never grant unrestricted sudo."
    if command -v ip >/dev/null 2>&1; then
      IP_PATH="$(command -v ip)"
      echo "${USER_NAME} ALL=(root) NOPASSWD: ${IP_PATH} neigh show"
      echo "${USER_NAME} ALL=(root) NOPASSWD: ${IP_PATH} addr show"
    fi
    if command -v arp >/dev/null 2>&1; then
      echo "${USER_NAME} ALL=(root) NOPASSWD: $(command -v arp) -a"
    fi
    if command -v hostname >/dev/null 2>&1; then
      echo "${USER_NAME} ALL=(root) NOPASSWD: $(command -v hostname)"
    fi
  } > "${SUDOERS_TMP}"

  visudo -cf "${SUDOERS_TMP}"
  install -m 0440 -o root -g root "${SUDOERS_TMP}" /etc/sudoers.d/openassetwatch-collector
  rm -f "${SUDOERS_TMP}"
  visudo -cf /etc/sudoers.d/openassetwatch-collector
fi

if [[ "${ENABLE_LOG_READ}" == "true" ]]; then
  for GROUP in adm systemd-journal; do
    if getent group "${GROUP}" >/dev/null 2>&1; then
      usermod -aG "${GROUP}" "${USER_NAME}"
    fi
  done
fi

cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=OpenAssetWatch Collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${USER_NAME}
Group=${GROUP_NAME}
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/.venv/bin/python -m openassetwatch_collector --run-forever --config ${CONFIG_PATH}
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

chown root:root "${SERVICE_PATH}"
chmod 0644 "${SERVICE_PATH}"

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"

if [[ "${START_SERVICE}" == "true" ]]; then
  systemctl restart "${SERVICE_NAME}"
fi

echo "OpenAssetWatch collector installed."
echo "Service: ${SERVICE_NAME}"
echo "Config: ${CONFIG_PATH}"
echo "Logs: journalctl -u ${SERVICE_NAME} -f"
