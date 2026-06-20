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

json_array() {
  python3 - "$@" <<'PY'
import json, sys
print(json.dumps(list(sys.argv[1:])))
PY
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
    rm -rf "$path"
    add_removed "$path"
  fi
}

if [ "$DRY_RUN" = false ] && [ "$(id -u)" -ne 0 ]; then
  add_error "root is required for real macOS uninstall"
fi

add_action "Boot out LaunchDaemon $LABEL if loaded"
if [ "$DRY_RUN" = false ]; then
  /bin/launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
fi

remove_path "$PLIST"
remove_path "$BIN_DIR/oaw-agent"
remove_path "$MANIFEST"
remove_path "$CONFIG_DIR/config.example.json"
remove_path "$IDENTITY_DIR/identity.example.json"

if [ "$PURGE" = true ]; then
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
    /usr/sbin/pkgutil --forget "$PACKAGE_ID" >/dev/null 2>&1 || true
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
python3 - "$OK" "$DRY_RUN" "$(json_array "${ACTIONS[@]}")" "$(json_array "${REMOVED[@]}")" "$(json_array "${WARNINGS[@]}")" "$(json_array "${ERRORS[@]}")" <<'PY'
import json, sys
ok = sys.argv[1] == "true"
value = {
    "ok": ok,
    "dry_run": sys.argv[2] == "true",
    "actions": json.loads(sys.argv[3]),
    "removed": json.loads(sys.argv[4]),
    "warnings": json.loads(sys.argv[5]),
    "errors": json.loads(sys.argv[6]),
}
print(json.dumps(value, indent=2))
PY

[ "$OK" = true ]
