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
  --sign-identity <identity>            Developer ID Installer identity for productbuild.
  --min-macos <version>                 Minimum supported macOS version metadata.
USAGE
}

VERSION=""
ARCH_MODE="universal"
OUTPUT_DIR="dist"
ARM64_ARTIFACT_DIR=""
AMD64_ARTIFACT_DIR=""
SIGN_IDENTITY=""
MIN_MACOS="13.0"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --arch-mode) ARCH_MODE="${2:-}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
    --arm64-artifact-dir) ARM64_ARTIFACT_DIR="${2:-}"; shift 2 ;;
    --amd64-artifact-dir) AMD64_ARTIFACT_DIR="${2:-}"; shift 2 ;;
    --sign-identity) SIGN_IDENTITY="${2:-}"; shift 2 ;;
    --min-macos) MIN_MACOS="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$VERSION" ] || { echo "--version is required" >&2; exit 2; }
case "$ARCH_MODE" in universal|arm64|amd64) ;; *) echo "invalid --arch-mode" >&2; exit 2 ;; esac

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
if [ "$ARCH_MODE" = "universal" ]; then
  command -v lipo >/dev/null || { echo "lipo is required for universal packages" >&2; exit 1; }
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
  python3 - "$manifest" "$VERSION" "$arch" "$rel" "$sha" <<'PY'
import json, os, subprocess, sys
manifest, version, arch, rel, sha = sys.argv[1:]
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
with open(manifest, "w", encoding="utf-8") as handle:
    json.dump(value, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
}

build_slice() {
  local arch="$1"
  local existing_dir="$2"
  local out_dir="$AGENT_ROOT/darwin-$arch"
  mkdir -p "$out_dir"
  if [ -n "$existing_dir" ]; then
    cp "$existing_dir/oaw-agent" "$out_dir/oaw-agent"
  else
    GOOS=darwin GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$out_dir/oaw-agent" ./cmd/oaw-agent
  fi
  chmod 0755 "$out_dir/oaw-agent"
  write_manifest "$out_dir/oaw-agent" "$arch"
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
  lipo -verify_arch arm64 x86_64 "$UNIVERSAL_DIR/oaw-agent"
  chmod 0755 "$UNIVERSAL_DIR/oaw-agent"
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
if [ -n "$SIGN_IDENTITY" ]; then
  PRODUCT_ARGS+=(--sign "$SIGN_IDENTITY" --timestamp)
fi
productbuild "${PRODUCT_ARGS[@]}" "$FINAL_PKG"
pkgutil --payload-files "$FINAL_PKG" > "$FINAL_PKG.payload.txt"
pkgutil --check-signature "$FINAL_PKG" > "$FINAL_PKG.signature.txt" 2>&1 || true

PKG_SHA="$(shasum -a 256 "$FINAL_PKG" | awk '{print $1}')"
printf '%s  %s\n' "$PKG_SHA" "$(basename "$FINAL_PKG")" > "$FINAL_PKG.sha256"
python3 - "$FINAL_PKG.manifest.json" "$VERSION" "$PACKAGE_VERSION" "$ARCH_MODE" "$FINAL_PKG" "$PKG_SHA" "$MIN_MACOS" "$SIGN_IDENTITY" <<'PY'
import json, os, sys
from datetime import datetime, timezone
manifest, version, package_version, arch_mode, pkg, sha, min_macos, sign_identity = sys.argv[1:]
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
    "minimum_macos_version": min_macos,
    "signed": bool(sign_identity),
    "notarized": False,
    "build_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
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
