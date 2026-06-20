#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: build_agent_macos_pkg.sh --version <version> [options]

Options:
  --arch-mode <universal|arm64|amd64>   Package architecture mode. Default: universal.
  --output-dir <dir>                    Repository-local output root. Default: dist.
  --arm64-artifact-dir <dir>            Existing darwin-arm64 artifact directory.
  --amd64-artifact-dir <dir>            Existing darwin-amd64 artifact directory.
  --app-identity <identity>             Developer ID Application identity for the embedded oaw-agent binary.
  --installer-identity <identity>       Developer ID Installer identity for productbuild.
  --sign-identity <identity>            Alias for --installer-identity.
  --min-macos <version>                 Tested minimum macOS metadata; not enforced by this unsigned build helper.
USAGE
}

VERSION=""
ARCH_MODE="universal"
OUTPUT_DIR="dist"
ARM64_ARTIFACT_DIR=""
AMD64_ARTIFACT_DIR=""
APP_IDENTITY=""
INSTALLER_IDENTITY=""
MIN_MACOS="13.0"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --arch-mode) ARCH_MODE="${2:-}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
    --arm64-artifact-dir) ARM64_ARTIFACT_DIR="${2:-}"; shift 2 ;;
    --amd64-artifact-dir) AMD64_ARTIFACT_DIR="${2:-}"; shift 2 ;;
    --app-identity) APP_IDENTITY="${2:-}"; shift 2 ;;
    --installer-identity) INSTALLER_IDENTITY="${2:-}"; shift 2 ;;
    --sign-identity) INSTALLER_IDENTITY="${2:-}"; shift 2 ;;
    --min-macos) MIN_MACOS="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$VERSION" ] || { echo "--version is required" >&2; exit 2; }
case "$ARCH_MODE" in universal|arm64|amd64) ;; *) echo "invalid --arch-mode" >&2; exit 2 ;; esac
if { [ -n "$APP_IDENTITY" ] && [ -z "$INSTALLER_IDENTITY" ]; } || { [ -z "$APP_IDENTITY" ] && [ -n "$INSTALLER_IDENTITY" ]; }; then
  echo "signed macOS packages require both --app-identity and --installer-identity" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

OUTPUT_ROOT="$(python3 - "$OUTPUT_DIR" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve())
PY
)"
case "$OUTPUT_ROOT" in "$REPO_ROOT"/*|"$REPO_ROOT") ;; *) echo "output directory must stay inside repository" >&2; exit 2 ;; esac

command -v go >/dev/null || { echo "go is required" >&2; exit 1; }
command -v pkgbuild >/dev/null || { echo "pkgbuild is required on macOS" >&2; exit 1; }
command -v productbuild >/dev/null || { echo "productbuild is required on macOS" >&2; exit 1; }
command -v pkgutil >/dev/null || { echo "pkgutil is required on macOS" >&2; exit 1; }
command -v plutil >/dev/null || { echo "plutil is required on macOS" >&2; exit 1; }
command -v lipo >/dev/null || { echo "lipo is required to verify macOS binary architectures" >&2; exit 1; }
command -v file >/dev/null || { echo "file is required to inspect macOS binaries" >&2; exit 1; }
if [ -n "$APP_IDENTITY" ]; then
  command -v codesign >/dev/null || { echo "codesign is required for signed macOS packages" >&2; exit 1; }
fi

PACKAGE_VERSION="$(PYTHONPATH="$SCRIPT_DIR" python3 - "$VERSION" <<'PY'
from stage_agent_macos_install import normalize_package_version
import sys
print(normalize_package_version(sys.argv[1]))
PY
)"

AGENT_ROOT="$OUTPUT_ROOT/agent/$VERSION"
PACKAGES_DIR="$AGENT_ROOT/packages"
mkdir -p "$PACKAGES_DIR"

write_manifest() {
  local artifact="$1"
  local arch="$2"
  local source_artifact="${3:-}"
  local source_checksum="${4:-}"
  local source_manifest="${5:-}"
  local manifest="$artifact.manifest.json"
  local checksum="$artifact.sha256"
  local rel
  rel="$(python3 - "$artifact" <<'PY'
from pathlib import Path
import os, sys
print(os.path.relpath(Path(sys.argv[1]).resolve(), Path.cwd()))
PY
)"
  local sha
  sha="$(shasum -a 256 "$artifact" | awk '{print $1}')"
  printf '%s  %s\n' "$sha" "$(basename "$artifact")" > "$checksum"
  python3 - "$manifest" "$VERSION" "$arch" "$rel" "$sha" "$source_artifact" "$source_checksum" "$source_manifest" <<'PY'
import json, os, subprocess, sys
manifest, version, arch, rel, sha, source_artifact, source_checksum, source_manifest = sys.argv[1:]
try:
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
except Exception:
    commit = ""
value = {
    "artifact_type": "oaw-agent-binary",
    "artifact_name": "oaw-agent",
    "version": version,
    "os": "darwin",
    "arch": arch,
    "path": rel.replace(os.sep, "/"),
    "sha256": sha,
    "build_timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat().replace("+00:00", "Z"),
    "git_commit": commit,
}
if arch == "universal":
    value["architectures"] = ["arm64", "amd64"]
if source_manifest:
    try:
        source = json.load(open(source_manifest, encoding="utf-8"))
    except Exception as exc:
        raise SystemExit(f"unable to read source manifest: {exc}")
    value["source_provenance"] = {
        "artifact": os.path.relpath(source_artifact, os.getcwd()).replace(os.sep, "/"),
        "checksum": os.path.relpath(source_checksum, os.getcwd()).replace(os.sep, "/"),
        "manifest": os.path.relpath(source_manifest, os.getcwd()).replace(os.sep, "/"),
        "sha256": source.get("sha256", ""),
        "git_commit": source.get("git_commit", ""),
        "version": source.get("version", ""),
        "os": source.get("os", ""),
        "arch": source.get("arch", ""),
    }
with open(manifest, "w", encoding="utf-8") as handle:
    json.dump(value, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

verify_binary_arch() {
  local binary="$1"
  local arch="$2"
  case "$arch" in
    arm64) lipo -verify_arch arm64 "$binary" >/dev/null ;;
    amd64) lipo -verify_arch x86_64 "$binary" >/dev/null ;;
    universal)
      lipo -verify_arch arm64 x86_64 "$binary" >/dev/null
      local arches
      arches="$(lipo -archs "$binary" | tr ' ' '\n' | sed '/^$/d' | sort | tr '\n' ' ' | sed 's/ $//')"
      [ "$arches" = "arm64 x86_64" ] || {
        echo "universal binary contains unexpected slices: $arches" >&2
        return 1
      }
      ;;
    *) echo "unsupported binary architecture check: $arch" >&2; return 2 ;;
  esac
}

verify_supplied_artifact_dir() {
  local artifact_dir="$1"
  local arch="$2"
  local artifact="$artifact_dir/oaw-agent"
  local checksum="$artifact_dir/oaw-agent.sha256"
  local manifest="$artifact_dir/oaw-agent.manifest.json"
  [ -f "$artifact" ] || { echo "supplied $arch artifact is missing oaw-agent" >&2; exit 1; }
  [ -f "$checksum" ] || { echo "supplied $arch artifact is missing checksum" >&2; exit 1; }
  [ -f "$manifest" ] || { echo "supplied $arch artifact is missing manifest" >&2; exit 1; }
  python3 - "$VERSION" "$arch" "$artifact" "$checksum" "$manifest" <<'PY'
import hashlib, json, pathlib, sys
version, arch, artifact, checksum, manifest = sys.argv[1:]
data = json.load(open(manifest, encoding="utf-8"))
required = ("artifact_name", "version", "os", "arch", "path", "sha256", "git_commit")
missing = [field for field in required if not str(data.get(field, "")).strip()]
if missing:
    raise SystemExit(f"supplied artifact manifest missing fields: {', '.join(missing)}")
if data["artifact_name"] != "oaw-agent":
    raise SystemExit("supplied artifact manifest artifact_name mismatch")
if data["version"] != version:
    raise SystemExit("supplied artifact manifest version mismatch")
if data["os"] != "darwin":
    raise SystemExit("supplied artifact manifest os must be darwin")
if data["arch"] != arch:
    raise SystemExit(f"supplied artifact manifest arch must be {arch}")
if pathlib.Path(data["path"]).resolve() != pathlib.Path(artifact).resolve():
    raise SystemExit("supplied artifact manifest path mismatch")
actual = hashlib.sha256(open(artifact, "rb").read()).hexdigest()
checksum_value = open(checksum, encoding="ascii").read().strip().split()[0].lower()
if actual != str(data["sha256"]).lower():
    raise SystemExit("supplied artifact hash does not match manifest")
if actual != checksum_value:
    raise SystemExit("supplied artifact hash does not match checksum file")
PY
  verify_binary_arch "$artifact" "$arch"
}

sign_agent_binary() {
  local binary="$1"
  [ -n "$APP_IDENTITY" ] || return 0
  codesign --force --timestamp --options runtime --sign "$APP_IDENTITY" "$binary"
  codesign --verify --strict --verbose=2 "$binary"
  local details
  details="$(codesign -dvv "$binary" 2>&1 || true)"
  printf '%s\n' "$details" | grep -qi "runtime" || { echo "signed binary lacks hardened runtime flag" >&2; exit 1; }
  printf '%s\n' "$details" | grep -q "Timestamp=" || { echo "signed binary lacks secure timestamp" >&2; exit 1; }
  local entitlements
  entitlements="$(codesign -d --entitlements :- "$binary" 2>/dev/null || true)"
  if printf '%s\n' "$entitlements" | grep -Eq "get-task-allow|com\.apple\.security\.get-task-allow"; then
    echo "signed binary must not include get-task-allow entitlement" >&2
    exit 1
  fi
}

verify_pkg_embedded_binary_signature() {
  local pkg="$1"
  [ -n "$APP_IDENTITY" ] || return 0
  local temp_dir
  temp_dir="$(mktemp -d)"
  pkgutil --expand-full "$pkg" "$temp_dir"
  local embedded
  embedded="$(find "$temp_dir" -path '*/Library/Application Support/OpenAssetWatch/Agent/bin/oaw-agent' -type f -print -quit)"
  [ -n "$embedded" ] || { rm -rf "$temp_dir"; echo "signed package is missing embedded oaw-agent binary" >&2; exit 1; }
  codesign --verify --strict --verbose=2 "$embedded"
  local details
  details="$(codesign -dvv "$embedded" 2>&1 || true)"
  printf '%s\n' "$details" | grep -qi "runtime" || { rm -rf "$temp_dir"; echo "embedded binary lacks hardened runtime flag" >&2; exit 1; }
  printf '%s\n' "$details" | grep -q "Timestamp=" || { rm -rf "$temp_dir"; echo "embedded binary lacks secure timestamp" >&2; exit 1; }
  rm -rf "$temp_dir"
}

build_slice() {
  local arch="$1"
  local existing_dir="$2"
  local out_dir="$AGENT_ROOT/darwin-$arch"
  mkdir -p "$out_dir"
  if [ -n "$existing_dir" ]; then
    existing_dir="$(python3 - "$existing_dir" <<'PY'
from pathlib import Path
import sys
print(Path(sys.argv[1]).resolve())
PY
)"
    verify_supplied_artifact_dir "$existing_dir" "$arch"
    cp "$existing_dir/oaw-agent" "$out_dir/oaw-agent"
  else
    GOOS=darwin GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$out_dir/oaw-agent" ./cmd/oaw-agent
  fi
  chmod 0755 "$out_dir/oaw-agent"
  verify_binary_arch "$out_dir/oaw-agent" "$arch"
  if [ "$ARCH_MODE" != "universal" ]; then
    sign_agent_binary "$out_dir/oaw-agent"
  fi
  if [ -n "$existing_dir" ]; then
    write_manifest "$out_dir/oaw-agent" "$arch" "$existing_dir/oaw-agent" "$existing_dir/oaw-agent.sha256" "$existing_dir/oaw-agent.manifest.json"
  else
    write_manifest "$out_dir/oaw-agent" "$arch"
  fi
}

if [ "$ARCH_MODE" = "universal" ] || [ "$ARCH_MODE" = "arm64" ]; then
  build_slice arm64 "$ARM64_ARTIFACT_DIR"
fi
if [ "$ARCH_MODE" = "universal" ] || [ "$ARCH_MODE" = "amd64" ]; then
  build_slice amd64 "$AMD64_ARTIFACT_DIR"
fi

if [ "$ARCH_MODE" = "universal" ]; then
  UNIVERSAL_DIR="$AGENT_ROOT/darwin-universal"
  mkdir -p "$UNIVERSAL_DIR"
  lipo -create "$AGENT_ROOT/darwin-arm64/oaw-agent" "$AGENT_ROOT/darwin-amd64/oaw-agent" -output "$UNIVERSAL_DIR/oaw-agent"
  verify_binary_arch "$UNIVERSAL_DIR/oaw-agent" universal
  chmod 0755 "$UNIVERSAL_DIR/oaw-agent"
  sign_agent_binary "$UNIVERSAL_DIR/oaw-agent"
  write_manifest "$UNIVERSAL_DIR/oaw-agent" universal
  STAGE_ARCH_MODE=universal
else
  STAGE_ARCH_MODE="$ARCH_MODE"
fi

python3 "$SCRIPT_DIR/stage_agent_macos_install.py" --version "$VERSION" --arch-mode "$STAGE_ARCH_MODE" --output-dir "$OUTPUT_ROOT"
python3 "$SCRIPT_DIR/validate_agent_macos_install.py" --version "$VERSION" --macos-install-root "$AGENT_ROOT/macos-install"
plutil -lint "$AGENT_ROOT/macos-install/pkgroot/Library/LaunchDaemons/com.openassetwatch.agent.plist" >/dev/null

COMPONENT_PKG="$PACKAGES_DIR/OpenAssetWatchAgent-${VERSION}-component.pkg"
FINAL_PKG="$PACKAGES_DIR/OpenAssetWatchAgent-${VERSION}-macos-${ARCH_MODE}.pkg"
rm -f "$COMPONENT_PKG" "$FINAL_PKG"

pkgbuild \
  --root "$AGENT_ROOT/macos-install/pkgroot" \
  --scripts "$AGENT_ROOT/macos-install/scripts" \
  --identifier com.openassetwatch.agent \
  --version "$PACKAGE_VERSION" \
  --install-location / \
  "$COMPONENT_PKG"

PRODUCT_ARGS=(--package "$COMPONENT_PKG")
if [ -n "$INSTALLER_IDENTITY" ]; then
  PRODUCT_ARGS+=(--sign "$INSTALLER_IDENTITY" --timestamp)
fi
productbuild "${PRODUCT_ARGS[@]}" "$FINAL_PKG"
pkgutil --payload-files "$FINAL_PKG" > "$FINAL_PKG.payload.txt"
if [ -n "$INSTALLER_IDENTITY" ]; then
  pkgutil --check-signature "$FINAL_PKG" > "$FINAL_PKG.signature.txt" 2>&1
else
  pkgutil --check-signature "$FINAL_PKG" > "$FINAL_PKG.signature.txt" 2>&1 || true
fi
verify_pkg_embedded_binary_signature "$FINAL_PKG"

PKG_SHA="$(shasum -a 256 "$FINAL_PKG" | awk '{print $1}')"
printf '%s  %s\n' "$PKG_SHA" "$(basename "$FINAL_PKG")" > "$FINAL_PKG.sha256"
python3 - "$FINAL_PKG.manifest.json" "$VERSION" "$PACKAGE_VERSION" "$ARCH_MODE" "$FINAL_PKG" "$PKG_SHA" "$MIN_MACOS" "$APP_IDENTITY" "$INSTALLER_IDENTITY" <<'PY'
import json, os, sys
from datetime import datetime, timezone
manifest, version, package_version, arch_mode, pkg, sha, min_macos, app_identity, installer_identity = sys.argv[1:]
value = {
    "package_name": os.path.basename(pkg),
    "package_identifier": "com.openassetwatch.agent",
    "launchd_label": "com.openassetwatch.agent",
    "version": version,
    "package_version": package_version,
    "os": "darwin",
    "arch_mode": arch_mode,
    "package_type": "pkg",
    "path": os.path.relpath(pkg, os.getcwd()).replace(os.sep, "/"),
    "sha256": sha,
    "tested_minimum_macos_version": min_macos,
    "minimum_macos_version_enforced": False,
    "signed": bool(installer_identity),
    "binary_signed": bool(app_identity),
    "installer_signed": bool(installer_identity),
    "notarized": False,
    "stapled": False,
    "build_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "signing_order": [
        "build architecture slices",
        "assemble universal binary when requested",
        "sign final packaged binary when signing identities are supplied",
        "stage signed binary into pkgroot",
        "build component and product package",
        "sign product package when installer identity is supplied",
    ],
}
with open(manifest, "w", encoding="utf-8") as handle:
    json.dump(value, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

python3 - "$FINAL_PKG" "$FINAL_PKG.sha256" "$FINAL_PKG.manifest.json" <<'PY'
import json, os, sys
print(json.dumps({
    "ok": True,
    "package": os.path.relpath(sys.argv[1], os.getcwd()).replace(os.sep, "/"),
    "checksum": os.path.relpath(sys.argv[2], os.getcwd()).replace(os.sep, "/"),
    "manifest": os.path.relpath(sys.argv[3], os.getcwd()).replace(os.sep, "/"),
}, indent=2))
PY
