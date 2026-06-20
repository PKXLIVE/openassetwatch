#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: sign_notarize_agent_macos.sh --version <version> --app-identity <id> --installer-identity <id> [options]

Builds a signed macOS PKG from verified agent artifacts. The embedded
oaw-agent binary is signed before pkgroot staging, so this helper cannot
produce a signed PKG containing an unsigned payload binary.

Options:
  --arch-mode <universal|arm64|amd64>   Package architecture mode. Default: universal.
  --output-dir <dir>                    Repository-local output root. Default: dist.
  --arm64-artifact-dir <dir>            Existing darwin-arm64 artifact directory.
  --amd64-artifact-dir <dir>            Existing darwin-amd64 artifact directory.
  --notary-profile <profile>            notarytool keychain profile.
  --api-key <path>                      App Store Connect API key .p8 path.
  --api-key-id <id>                     App Store Connect API key id.
  --api-issuer <id>                     App Store Connect issuer id.
  --skip-notarization                   Build signed, non-notarized artifact only.
USAGE
}

VERSION=""
ARCH_MODE="universal"
OUTPUT_DIR="dist"
ARM64_ARTIFACT_DIR=""
AMD64_ARTIFACT_DIR=""
APP_IDENTITY=""
INSTALLER_IDENTITY=""
NOTARY_PROFILE=""
API_KEY=""
API_KEY_ID=""
API_ISSUER=""
SKIP_NOTARIZATION=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --arch-mode) ARCH_MODE="${2:-}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
    --arm64-artifact-dir) ARM64_ARTIFACT_DIR="${2:-}"; shift 2 ;;
    --amd64-artifact-dir) AMD64_ARTIFACT_DIR="${2:-}"; shift 2 ;;
    --app-identity) APP_IDENTITY="${2:-}"; shift 2 ;;
    --installer-identity) INSTALLER_IDENTITY="${2:-}"; shift 2 ;;
    --notary-profile) NOTARY_PROFILE="${2:-}"; shift 2 ;;
    --api-key) API_KEY="${2:-}"; shift 2 ;;
    --api-key-id) API_KEY_ID="${2:-}"; shift 2 ;;
    --api-issuer) API_ISSUER="${2:-}"; shift 2 ;;
    --skip-notarization) SKIP_NOTARIZATION=true; shift ;;
    --pkg|--binary)
      echo "$1 is no longer supported; signed macOS releases must rebuild the package from verified artifacts" >&2
      exit 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$VERSION" ] || { echo "--version is required" >&2; exit 2; }
[ -n "$APP_IDENTITY" ] || { echo "--app-identity is required" >&2; exit 2; }
[ -n "$INSTALLER_IDENTITY" ] || { echo "--installer-identity is required" >&2; exit 2; }
case "$ARCH_MODE" in universal|arm64|amd64) ;; *) echo "invalid --arch-mode" >&2; exit 2 ;; esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

command -v codesign >/dev/null || { echo "codesign is required" >&2; exit 1; }
command -v pkgutil >/dev/null || { echo "pkgutil is required" >&2; exit 1; }
command -v spctl >/dev/null || { echo "spctl is required" >&2; exit 1; }
command -v xcrun >/dev/null || { echo "xcrun is required" >&2; exit 1; }

BUILD_ARGS=(--version "$VERSION" --arch-mode "$ARCH_MODE" --output-dir "$OUTPUT_DIR" --app-identity "$APP_IDENTITY" --installer-identity "$INSTALLER_IDENTITY")
[ -z "$ARM64_ARTIFACT_DIR" ] || BUILD_ARGS+=(--arm64-artifact-dir "$ARM64_ARTIFACT_DIR")
[ -z "$AMD64_ARTIFACT_DIR" ] || BUILD_ARGS+=(--amd64-artifact-dir "$AMD64_ARTIFACT_DIR")

bash "$SCRIPT_DIR/build_agent_macos_pkg.sh" "${BUILD_ARGS[@]}" >/dev/null

PKG="$OUTPUT_DIR/agent/$VERSION/packages/OpenAssetWatchAgent-${VERSION}-macos-${ARCH_MODE}.pkg"
PKG="$(python3 - "$PKG" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve())
PY
)"
[ -f "$PKG" ] || { echo "signed package was not produced" >&2; exit 1; }

verify_binary_signature() {
  local binary="$1"
  codesign --verify --strict --verbose=2 "$binary"
  local details
  details="$(codesign -dvv "$binary" 2>&1 || true)"
  printf '%s\n' "$details" | grep -qi "runtime" || { echo "binary lacks hardened runtime flag" >&2; exit 1; }
  printf '%s\n' "$details" | grep -q "Timestamp=" || { echo "binary lacks secure timestamp" >&2; exit 1; }
  local entitlements
  entitlements="$(codesign -d --entitlements :- "$binary" 2>/dev/null || true)"
  if printf '%s\n' "$entitlements" | grep -Eq "get-task-allow|com\.apple\.security\.get-task-allow"; then
    echo "binary must not include get-task-allow entitlement" >&2
    exit 1
  fi
}

verify_embedded_binary_signature() {
  local pkg="$1"
  local temp_dir
  temp_dir="$(mktemp -d)"
  pkgutil --expand-full "$pkg" "$temp_dir"
  local embedded
  embedded="$(find "$temp_dir" -path '*/Library/Application Support/OpenAssetWatch/Agent/bin/oaw-agent' -type f -print -quit)"
  [ -n "$embedded" ] || { rm -rf "$temp_dir"; echo "signed package is missing embedded oaw-agent binary" >&2; exit 1; }
  verify_binary_signature "$embedded"
  rm -rf "$temp_dir"
}

pkgutil --check-signature "$PKG"
verify_embedded_binary_signature "$PKG"
spctl --assess --type install --verbose "$PKG" >/dev/null 2>&1 || true

NOTARY_STATUS="skipped"
NOTARY_ID=""
NOTARY_LOG="${PKG}.notary-log.json"
DETAILED_NOTARY_LOG="${PKG}.notary-detail.json"
STAPLED=false
GATEKEEPER_ASSESSED=false

if [ "$SKIP_NOTARIZATION" != true ]; then
  if [ -n "$NOTARY_PROFILE" ]; then
    NOTARY_AUTH=(--keychain-profile "$NOTARY_PROFILE")
  else
    [ -n "$API_KEY" ] && [ -n "$API_KEY_ID" ] && [ -n "$API_ISSUER" ] || {
      echo "notarization requires --notary-profile or API key inputs" >&2
      exit 2
    }
    NOTARY_AUTH=(--key "$API_KEY" --key-id "$API_KEY_ID" --issuer "$API_ISSUER")
  fi
  xcrun notarytool submit "$PKG" "${NOTARY_AUTH[@]}" --wait --output-format json > "$NOTARY_LOG"
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
  [ -n "$NOTARY_ID" ] || { echo "notarytool did not return a submission id" >&2; exit 1; }
  xcrun notarytool log "$NOTARY_ID" "${NOTARY_AUTH[@]}" --output-format json > "$DETAILED_NOTARY_LOG"
  xcrun stapler staple "$PKG"
  xcrun stapler validate "$PKG"
  STAPLED=true
  spctl --assess --type install --verbose "$PKG"
  GATEKEEPER_ASSESSED=true
fi

SHA="$(shasum -a 256 "$PKG" | awk '{print $1}')"
printf '%s  %s\n' "$SHA" "$(basename "$PKG")" > "$PKG.sha256"
python3 - "$PKG.manifest.json" "$PKG" "$SHA" "$NOTARY_STATUS" "$NOTARY_ID" "$NOTARY_LOG" "$DETAILED_NOTARY_LOG" "$STAPLED" "$GATEKEEPER_ASSESSED" <<'PY'
import json, os, sys
from datetime import datetime, timezone
manifest_path, pkg, sha, status, notary_id, notary_log, detailed_log, stapled, assessed = sys.argv[1:]
data = json.load(open(manifest_path, encoding="utf-8"))
data.update({
    "path": os.path.relpath(pkg, os.getcwd()).replace(os.sep, "/"),
    "sha256": sha,
    "signed": True,
    "binary_signed": True,
    "installer_signed": True,
    "notarized": status == "Accepted",
    "notarization_status": status,
    "notarization_id": notary_id,
    "notarization_log": os.path.relpath(notary_log, os.getcwd()).replace(os.sep, "/") if os.path.exists(notary_log) else "",
    "notarization_detail_log": os.path.relpath(detailed_log, os.getcwd()).replace(os.sep, "/") if os.path.exists(detailed_log) else "",
    "stapled": stapled == "true",
    "gatekeeper_assessed": assessed == "true",
    "finalized_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "signing_order": [
        "build arm64 and amd64 slices as needed",
        "assemble universal binary when requested",
        "sign final package payload binary with Developer ID Application",
        "verify hardened runtime, timestamp, and get-task-allow absence",
        "stage signed binary into pkgroot",
        "build component and product PKG",
        "sign product PKG with Developer ID Installer",
        "verify package signature and embedded binary signature",
        "submit to notarytool and require Accepted status",
        "download detailed notarization log",
        "staple and validate ticket",
        "rerun Gatekeeper assessment",
        "regenerate checksum and release manifest after signing and stapling",
    ],
})
with open(manifest_path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

python3 - "$PKG" "$PKG.sha256" "$PKG.manifest.json" "$NOTARY_STATUS" "$NOTARY_ID" <<'PY'
import json, os, sys
pkg, checksum, manifest, status, notary_id = sys.argv[1:]
print(json.dumps({
    "ok": True,
    "signed_pkg": os.path.relpath(pkg, os.getcwd()).replace(os.sep, "/"),
    "checksum": os.path.relpath(checksum, os.getcwd()).replace(os.sep, "/"),
    "manifest": os.path.relpath(manifest, os.getcwd()).replace(os.sep, "/"),
    "notarization_status": status,
    "notarization_id": notary_id,
}, indent=2))
PY
