#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: sign_notarize_agent_macos.sh --pkg <pkg> --binary <oaw-agent> --app-identity <id> --installer-identity <id> [options]

Options:
  --notary-profile <profile>      notarytool keychain profile.
  --api-key <path>                App Store Connect API key .p8 path.
  --api-key-id <id>               App Store Connect API key id.
  --api-issuer <id>               App Store Connect issuer id.
  --skip-notarization             Sign and assess only; do not submit.
USAGE
}

PKG=""
BINARY=""
APP_IDENTITY=""
INSTALLER_IDENTITY=""
NOTARY_PROFILE=""
API_KEY=""
API_KEY_ID=""
API_ISSUER=""
SKIP_NOTARIZATION=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --pkg) PKG="${2:-}"; shift 2 ;;
    --binary) BINARY="${2:-}"; shift 2 ;;
    --app-identity) APP_IDENTITY="${2:-}"; shift 2 ;;
    --installer-identity) INSTALLER_IDENTITY="${2:-}"; shift 2 ;;
    --notary-profile) NOTARY_PROFILE="${2:-}"; shift 2 ;;
    --api-key) API_KEY="${2:-}"; shift 2 ;;
    --api-key-id) API_KEY_ID="${2:-}"; shift 2 ;;
    --api-issuer) API_ISSUER="${2:-}"; shift 2 ;;
    --skip-notarization) SKIP_NOTARIZATION=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$PKG" ] || { echo "--pkg is required" >&2; exit 2; }
[ -n "$BINARY" ] || { echo "--binary is required" >&2; exit 2; }
[ -n "$APP_IDENTITY" ] || { echo "--app-identity is required" >&2; exit 2; }
[ -n "$INSTALLER_IDENTITY" ] || { echo "--installer-identity is required" >&2; exit 2; }
[ -f "$PKG" ] || { echo "pkg not found" >&2; exit 1; }
[ -f "$BINARY" ] || { echo "binary not found" >&2; exit 1; }

command -v codesign >/dev/null || { echo "codesign is required" >&2; exit 1; }
command -v productsign >/dev/null || { echo "productsign is required" >&2; exit 1; }
command -v pkgutil >/dev/null || { echo "pkgutil is required" >&2; exit 1; }
command -v spctl >/dev/null || { echo "spctl is required" >&2; exit 1; }
command -v xcrun >/dev/null || { echo "xcrun is required" >&2; exit 1; }

SIGNED_PKG="${PKG%.pkg}-signed.pkg"
NOTARY_LOG="${SIGNED_PKG}.notary-log.json"

codesign --force --timestamp --options runtime --sign "$APP_IDENTITY" "$BINARY"
codesign --verify --strict --verbose=2 "$BINARY"

productsign --sign "$INSTALLER_IDENTITY" --timestamp "$PKG" "$SIGNED_PKG"
pkgutil --check-signature "$SIGNED_PKG"
spctl --assess --type install --verbose "$SIGNED_PKG" || true

NOTARY_STATUS="skipped"
NOTARY_ID=""
if [ "$SKIP_NOTARIZATION" != true ]; then
  if [ -n "$NOTARY_PROFILE" ]; then
    SUBMIT_ARGS=(notarytool submit "$SIGNED_PKG" --keychain-profile "$NOTARY_PROFILE" --wait --output-format json)
  else
    [ -n "$API_KEY" ] && [ -n "$API_KEY_ID" ] && [ -n "$API_ISSUER" ] || {
      echo "notarization requires --notary-profile or API key inputs" >&2
      exit 2
    }
    SUBMIT_ARGS=(notarytool submit "$SIGNED_PKG" --key "$API_KEY" --key-id "$API_KEY_ID" --issuer "$API_ISSUER" --wait --output-format json)
  fi
  xcrun "${SUBMIT_ARGS[@]}" > "$NOTARY_LOG"
  NOTARY_STATUS="$(python3 - "$NOTARY_LOG" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
print(data.get("status", ""))
PY
)"
  NOTARY_ID="$(python3 - "$NOTARY_LOG" <<'PY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
print(data.get("id", ""))
PY
)"
  [ "$NOTARY_STATUS" = "Accepted" ] || { cat "$NOTARY_LOG" >&2; exit 1; }
  xcrun stapler staple "$SIGNED_PKG"
  xcrun stapler validate "$SIGNED_PKG"
  spctl --assess --type install --verbose "$SIGNED_PKG"
fi

python3 - "$SIGNED_PKG" "$NOTARY_STATUS" "$NOTARY_ID" "$NOTARY_LOG" <<'PY'
import json, os, sys
pkg, status, notary_id, log = sys.argv[1:]
print(json.dumps({
    "ok": True,
    "signed_pkg": os.path.relpath(pkg, os.getcwd()).replace(os.sep, "/"),
    "notarization_status": status,
    "notarization_id": notary_id,
    "notarization_log": os.path.relpath(log, os.getcwd()).replace(os.sep, "/") if os.path.exists(log) else "",
}, indent=2))
PY
