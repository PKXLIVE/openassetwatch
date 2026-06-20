#!/usr/bin/env bash
set -euo pipefail

DRY_RUN=false
REMOVE_STATE=false
REMOVE_LOGS=false
PURGE=false
FORGET_RECEIPT=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --remove-state) REMOVE_STATE=true; shift ;;
    --remove-logs) REMOVE_LOGS=true; shift ;;
    --purge) PURGE=true; shift ;;
    --forget-receipt) FORGET_RECEIPT=true; shift ;;
    -h|--help)
      echo "Usage: uninstall_agent_macos.sh [--dry-run] [--remove-state] [--remove-logs] [--purge] [--forget-receipt]"
      exit 0
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

LABEL="com.openassetwatch.agent"
PACKAGE_ID="com.openassetwatch.agent"
APP_ROOT="/Library/Application Support/OpenAssetWatch/Agent"
BIN_DIR="$APP_ROOT/bin"
CONFIG_DIR="$APP_ROOT/config"
IDENTITY_DIR="$APP_ROOT/identity"
STATE_DIR="$APP_ROOT/state"
LOG_DIR="/Library/Logs/OpenAssetWatch/Agent"
PLIST="/Library/LaunchDaemons/com.openassetwatch.agent.plist"
MANIFEST="$APP_ROOT/install-manifest.json"
SERVICE_USER="_openassetwatch"

ACTIONS=()
REMOVED=()
ERRORS=()
WARNINGS=()

add_action() { ACTIONS+=("$*"); }
add_removed() { REMOVED+=("$*"); }
add_error() { ERRORS+=("$*"); }
add_warning() { WARNINGS+=("$*"); }

json_string() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '"%s"' "$value"
}

json_array() {
  local first=true
  printf '['
  for item in "$@"; do
    if [ "$first" = true ]; then
      first=false
    else
      printf ','
    fi
    json_string "$item"
  done
  printf ']'
}

emit_report() {
  local ok="$1"
  printf '{\n'
  printf '  "ok": %s,\n' "$ok"
  printf '  "dry_run": %s,\n' "$DRY_RUN"
  printf '  "actions": %s,\n' "$(json_array "${ACTIONS[@]}")"
  printf '  "removed": %s,\n' "$(json_array "${REMOVED[@]}")"
  printf '  "warnings": %s,\n' "$(json_array "${WARNINGS[@]}")"
  printf '  "errors": %s\n' "$(json_array "${ERRORS[@]}")"
  printf '}\n'
}

safe_path() {
  path="$1"
  case "$path" in
    "$APP_ROOT"|"$APP_ROOT"/*|"$LOG_DIR"|"$LOG_DIR"/*|"$PLIST") return 0 ;;
    *) return 1 ;;
  esac
}

has_symlink_component() {
  path="$1"
  while [ "$path" != "/" ] && [ -n "$path" ]; do
    if [ -L "$path" ]; then
      return 0
    fi
    path="$(dirname "$path")"
  done
  return 1
}

remove_path() {
  path="$1"
  [ -n "$path" ] || { add_error "refusing empty removal path"; return; }
  safe_path "$path" || { add_error "refusing removal outside OpenAssetWatch roots: $path"; return; }
  if has_symlink_component "$path"; then
    add_error "refusing symlink removal path: $path"
    return
  fi
  add_action "Remove $path"
  if [ "$DRY_RUN" = false ] && [ -e "$path" ]; then
    if rm -rf "$path"; then
      add_removed "$path"
    else
      add_error "failed to remove $path"
    fi
  fi
}

if [ "$DRY_RUN" = false ] && [ "$(id -u)" -ne 0 ]; then
  add_error "root is required for real macOS uninstall"
  emit_report false
  exit 1
fi

add_action "Boot out LaunchDaemon $LABEL if loaded"
if [ "$DRY_RUN" = false ]; then
  if ! /bin/launchctl bootout system "$PLIST" >/dev/null 2>&1; then
    add_warning "LaunchDaemon was not loaded or could not be booted out."
  fi
fi

remove_path "$PLIST"
remove_path "$BIN_DIR/oaw-agent"
remove_path "$MANIFEST"
remove_path "$CONFIG_DIR/config.example.json"
remove_path "$IDENTITY_DIR/identity.example.json"

if [ "$PURGE" = true ]; then
  REMOVE_STATE=true
  REMOVE_LOGS=true
  remove_path "$CONFIG_DIR"
  remove_path "$IDENTITY_DIR"
else
  add_warning "Preserving config and identity; use --purge only for explicit full cleanup."
fi

if [ "$REMOVE_STATE" = true ]; then
  remove_path "$STATE_DIR"
else
  add_warning "Preserving state by default."
fi

if [ "$REMOVE_LOGS" = true ]; then
  remove_path "$LOG_DIR"
else
  add_warning "Preserving logs by default."
fi

if [ "$FORGET_RECEIPT" = true ]; then
  add_action "Forget package receipt $PACKAGE_ID"
  if [ "$DRY_RUN" = false ]; then
    if ! /usr/sbin/pkgutil --forget "$PACKAGE_ID" >/dev/null 2>&1; then
      add_warning "Package receipt was already absent or could not be forgotten."
    fi
  fi
fi

if [ "$PURGE" = true ]; then
  if pgrep -u "$SERVICE_USER" >/dev/null 2>&1; then
    add_error "refusing service-account purge while processes still run as $SERVICE_USER"
  else
    add_warning "Service account is preserved by default; remove manually only after confirming no dependencies."
  fi
else
  add_warning "Service account $SERVICE_USER preserved by default."
fi

OK=true
[ "${#ERRORS[@]}" -eq 0 ] || OK=false
emit_report "$OK"

[ "$OK" = true ]
