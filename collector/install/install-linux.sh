#!/usr/bin/env bash
set -euo pipefail

INSTALLER_VERSION="${INSTALLER_VERSION:-0.1.0}"
INSTALL_DIR="${INSTALL_DIR:-/opt/openassetwatch/collector}"
CONFIG_DIR="${CONFIG_DIR:-/etc/openassetwatch}"
CONFIG_PATH="${CONFIG_PATH:-${CONFIG_DIR}/collector.yaml}"
METADATA_PATH="${METADATA_PATH:-${CONFIG_DIR}/install.env}"
IDENTITY_PATH="${IDENTITY_PATH:-${CONFIG_DIR}/identity.json}"
STATE_DIR="${STATE_DIR:-/var/lib/openassetwatch}"
LOG_DIR="${LOG_DIR:-/var/log/openassetwatch}"
INSTALL_LOG="${INSTALL_LOG:-${LOG_DIR}/install.log}"
SERVICE_PATH="${SERVICE_PATH:-/etc/systemd/system/openassetwatch-collector.service}"
SERVICE_NAME="openassetwatch-collector.service"
USER_NAME="${USER_NAME:-openassetwatch}"
GROUP_NAME="${GROUP_NAME:-openassetwatch}"
MODE="${MODE:-hybrid}"
HEARTBEAT_INTERVAL_SECONDS="${HEARTBEAT_INTERVAL_SECONDS:-3600}"
INVENTORY_INTERVAL_SECONDS="${INVENTORY_INTERVAL_SECONDS:-86400}"
COLLECTOR_ID="${COLLECTOR_ID:-$(hostname)-collector}"
COLLECTOR_NAME="${COLLECTOR_NAME:-$(hostname)}"
DEPLOYMENT_ID="${DEPLOYMENT_ID:-}"
BUSINESS_UNIT="${BUSINESS_UNIT:-}"
SITE="${SITE:-}"
ENVIRONMENT="${ENVIRONMENT:-}"
INSTALL_RING="${INSTALL_RING:-}"
LABEL_OWNER="${LABEL_OWNER:-}"
LABEL_DEVICE_GROUP="${LABEL_DEVICE_GROUP:-}"
LABEL_INSTALL_PROFILE="${LABEL_INSTALL_PROFILE:-}"
ENABLE_LOG_READ="${ENABLE_LOG_READ:-false}"
INSTALL_SUDOERS="${INSTALL_SUDOERS:-false}"
START_SERVICE="${START_SERVICE:-true}"
UNINSTALL="${UNINSTALL:-false}"
PURGE="${PURGE:-false}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COLLECTOR_SOURCE_DIR="${COLLECTOR_SOURCE_DIR:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

log() {
  install -d -m 0750 -o "${USER_NAME}" -g "${GROUP_NAME}" "${LOG_DIR}" >/dev/null 2>&1 || mkdir -p "${LOG_DIR}" || true
  printf '%s %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" "$*" >> "${INSTALL_LOG}" 2>/dev/null || true
}

if [[ "${EUID}" -ne 0 ]]; then
  log "error Linux installation must be run as root"
  echo "Linux installation must be run as root. Re-run with sudo." >&2
  exit 1
fi

if [[ "${UNINSTALL}" != "true" && -z "${BACKEND_URL:-}" ]]; then
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

if [[ "${UNINSTALL}" == "true" ]]; then
  log "uninstall start platform=linux"
  systemctl disable --now "${SERVICE_NAME}" >/dev/null 2>&1 || true
  log "systemd disable/stop requested service=${SERVICE_NAME}"
  rm -f "${SERVICE_PATH}" /etc/sudoers.d/openassetwatch-collector
  log "removed service and sudoers files if present"
  systemctl daemon-reload >/dev/null 2>&1 || true
  rm -rf "${INSTALL_DIR}"
  log "removed install directory path=${INSTALL_DIR}"
  if [[ "${PURGE}" == "true" ]]; then
    log "purge requested"
    log "uninstall complete platform=linux purge=true"
    rm -rf "${CONFIG_DIR}" "${LOG_DIR}" "${STATE_DIR}"
  else
    echo "Preserving config directory: ${CONFIG_DIR}"
    echo "Preserving log directory: ${LOG_DIR}"
    echo "Preserving state directory: ${STATE_DIR}"
    log "uninstall complete platform=linux"
  fi
  echo "OpenAssetWatch collector uninstalled."
  exit 0
fi

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  log "error ${PYTHON_BIN} is required"
  echo "${PYTHON_BIN} is required" >&2
  exit 1
fi

SELECTED_PYTHON="$(command -v "${PYTHON_BIN}")"
PYTHON_VERSION="$(python_version "${SELECTED_PYTHON}")"
echo "Using Python: ${SELECTED_PYTHON} (${PYTHON_VERSION})"
log "install start platform=linux installer_version=${INSTALLER_VERSION}"
log "selected python path=${SELECTED_PYTHON} version=${PYTHON_VERSION}"

if ! python_is_supported "${SELECTED_PYTHON}"; then
  log "error unsupported python path=${SELECTED_PYTHON} version=${PYTHON_VERSION}"
  echo "Python >=3.10 is required, but ${SELECTED_PYTHON} is ${PYTHON_VERSION}." >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  log "error systemctl is required"
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

if [[ -f "${IDENTITY_PATH}" ]]; then
  COLLECTOR_GUID="$("${SELECTED_PYTHON}" -c 'import json,sys,uuid; data=json.load(open(sys.argv[1], encoding="utf-8")); print(str(uuid.UUID(str(data["collector_guid"]))))' "${IDENTITY_PATH}")"
  echo "Preserving collector identity: ${IDENTITY_PATH}"
  log "identity preserved path=${IDENTITY_PATH} collector_guid=${COLLECTOR_GUID}"
else
  COLLECTOR_GUID="$("${SELECTED_PYTHON}" -c 'import uuid; print(uuid.uuid4())')"
  "${SELECTED_PYTHON}" -c 'import datetime,json,sys; payload={"collector_guid": sys.argv[2], "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00","Z"), "install_source": "linux-systemd"}; open(sys.argv[1], "w", encoding="utf-8").write(json.dumps(payload, indent=2, sort_keys=True) + "\n")' "${IDENTITY_PATH}" "${COLLECTOR_GUID}"
  echo "Created collector identity: ${IDENTITY_PATH}"
  log "identity create path=${IDENTITY_PATH} collector_guid=${COLLECTOR_GUID}"
fi

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
  id: ${COLLECTOR_ID}
  name: ${COLLECTOR_NAME}
  mode: ${MODE}

identity:
  path: ${IDENTITY_PATH}

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

if [[ -n "${DEPLOYMENT_ID}${BUSINESS_UNIT}${SITE}${ENVIRONMENT}${INSTALL_RING}" ]]; then
  {
    echo
    echo "deployment:"
    [[ -n "${DEPLOYMENT_ID}" ]] && echo "  deployment_id: ${DEPLOYMENT_ID}"
    [[ -n "${BUSINESS_UNIT}" ]] && echo "  business_unit: ${BUSINESS_UNIT}"
    [[ -n "${SITE}" ]] && echo "  site: ${SITE}"
    [[ -n "${ENVIRONMENT}" ]] && echo "  environment: ${ENVIRONMENT}"
    [[ -n "${INSTALL_RING}" ]] && echo "  install_ring: ${INSTALL_RING}"
  } >> "${CONFIG_PATH}.tmp"
fi

if [[ -n "${LABEL_OWNER}${LABEL_DEVICE_GROUP}${LABEL_INSTALL_PROFILE}" ]]; then
  {
    echo
    echo "labels:"
    [[ -n "${LABEL_OWNER}" ]] && echo "  owner: ${LABEL_OWNER}"
    [[ -n "${LABEL_DEVICE_GROUP}" ]] && echo "  device_group: ${LABEL_DEVICE_GROUP}"
    [[ -n "${LABEL_INSTALL_PROFILE}" ]] && echo "  install_profile: ${LABEL_INSTALL_PROFILE}"
  } >> "${CONFIG_PATH}.tmp"
fi

install -m 0640 -o root -g "${GROUP_NAME}" "${CONFIG_PATH}.tmp" "${CONFIG_PATH}"
rm -f "${CONFIG_PATH}.tmp"
log "config write/update path=${CONFIG_PATH}"

cat > "${METADATA_PATH}.tmp" <<EOF
INSTALLER_VERSION=${INSTALLER_VERSION}
INSTALL_TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PLATFORM=linux
SELECTED_PYTHON_PATH=${SELECTED_PYTHON}
SELECTED_PYTHON_VERSION=${PYTHON_VERSION}
VENV_PYTHON_PATH=${INSTALL_DIR}/.venv/bin/python
BACKEND_URL=${BACKEND_URL}
COLLECTOR_ID=${COLLECTOR_ID}
COLLECTOR_GUID=${COLLECTOR_GUID}
DEPLOYMENT_ID=${DEPLOYMENT_ID}
EOF

install -m 0640 -o root -g "${GROUP_NAME}" "${METADATA_PATH}.tmp" "${METADATA_PATH}"
rm -f "${METADATA_PATH}.tmp"
log "metadata write/update path=${METADATA_PATH}"

chown -R "${USER_NAME}:${GROUP_NAME}" /opt/openassetwatch
chown -R "${USER_NAME}:${GROUP_NAME}" "${STATE_DIR}" "${LOG_DIR}"
chown root:"${GROUP_NAME}" "${CONFIG_DIR}" "${CONFIG_PATH}" "${METADATA_PATH}" "${IDENTITY_PATH}"
chmod 0750 "${CONFIG_DIR}"
chmod 0640 "${CONFIG_PATH}" "${METADATA_PATH}" "${IDENTITY_PATH}"

if [[ "${INSTALL_SUDOERS}" == "true" ]]; then
  if ! command -v visudo >/dev/null 2>&1; then
    log "error visudo is required when INSTALL_SUDOERS=true"
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
  log "sudoers write/update path=/etc/sudoers.d/openassetwatch-collector"
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
log "systemd service write/update path=${SERVICE_PATH}"

chown root:root "${SERVICE_PATH}"
chmod 0644 "${SERVICE_PATH}"

systemctl daemon-reload
log "systemd daemon-reload complete"
systemctl enable "${SERVICE_NAME}"
log "systemd service enabled service=${SERVICE_NAME}"

if [[ "${START_SERVICE}" == "true" ]]; then
  systemctl restart "${SERVICE_NAME}"
  log "systemd service restart requested service=${SERVICE_NAME}"
fi

log "install complete platform=linux"
echo "OpenAssetWatch collector installed."
echo "Service: ${SERVICE_NAME}"
echo "Config: ${CONFIG_PATH}"
echo "Logs: journalctl -u ${SERVICE_NAME} -f"
