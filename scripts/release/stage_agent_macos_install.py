#!/usr/bin/env python3
"""Stage a macOS LaunchDaemon install layout for the OpenAssetWatch agent."""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import shutil
import stat
import struct
from pathlib import Path
from typing import Any

from release_common import (
    get_repo_root,
    is_inside,
    read_json,
    resolve_repo_path,
    sha256_file,
    to_repo_relative,
    utc_timestamp,
    validate_version,
)


TARGET_OS = "darwin"
PACKAGE_ID = "com.openassetwatch.agent"
LAUNCHD_LABEL = "com.openassetwatch.agent"
SERVICE_USER = "_openassetwatch"
SERVICE_GROUP = "_openassetwatch"
MACOS_INSTALL_DIR = "macos-install"
ARTIFACT_NAME = "oaw-agent"
PKGROOT_DIR = "pkgroot"
SCRIPTS_DIR = "scripts"
MANIFEST_NAME = "macos-install-manifest.json"

BINARY_PATH = "/Library/Application Support/OpenAssetWatch/Agent/bin/oaw-agent"
CONFIG_PATH = "/Library/Application Support/OpenAssetWatch/Agent/config/config.json"
IDENTITY_PATH = "/Library/Application Support/OpenAssetWatch/Agent/identity/identity.json"
STATE_DIR = "/Library/Application Support/OpenAssetWatch/Agent/state"
STATUS_PATH = "/Library/Application Support/OpenAssetWatch/Agent/state/status.json"
INVENTORY_PATH = "/Library/Application Support/OpenAssetWatch/Agent/state/last-inventory.json"
LOG_DIR = "/Library/Logs/OpenAssetWatch/Agent"
PLIST_PATH = "/Library/LaunchDaemons/com.openassetwatch.agent.plist"
INSTALL_MANIFEST_PATH = "/Library/Application Support/OpenAssetWatch/Agent/install-manifest.json"

REQUIRED_BINARY_FIELDS = ("artifact_name", "version", "os", "arch", "path", "sha256")
MACOS_PACKAGE_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,2}$")
MACHO_CPU_TYPES = {
    0x0100000C: "arm64",
    0x01000007: "amd64",
}
FORBIDDEN_STAGE_TERMS = (
    "token",
    "secret",
    "credential",
    "password",
    "api_key",
    "apikey",
    "private_key",
    "authorization",
)


class Reporter:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []

    def check(self, name: str, ok: bool, message: str = "") -> bool:
        self.checks.append({"name": name, "ok": ok, "message": message})
        if not ok and message:
            self.errors.append(message)
        return ok


def normalize_package_version(version: str) -> str:
    if not MACOS_PACKAGE_VERSION_RE.fullmatch(version):
        raise ValueError(
            "macOS PKG builds require a numeric package version with one to three dot-separated components; "
            "prerelease/build suffixes are rejected to avoid receipt-version collisions."
        )
    parts = version.split(".")
    if len(parts) > 3:
        raise ValueError("macOS package version must have at most three numeric components.")
    normalized: list[str] = []
    for part in parts:
        normalized.append(str(int(part)))
    while len(normalized) < 3:
        normalized.append("0")
    return ".".join(normalized)


def macho_architectures(path: Path) -> list[str]:
    data = path.read_bytes()
    if len(data) < 8:
        raise ValueError("macOS binary is too small to contain a Mach-O header.")
    magic = data[:4]
    arches: list[str] = []
    if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        _, count = struct.unpack(">II", data[:8])
        offset = 8
        entry_size = 20 if magic == b"\xca\xfe\xba\xbe" else 32
        for _ in range(count):
            if len(data) < offset + entry_size:
                raise ValueError("macOS universal binary has a truncated fat header.")
            cputype = struct.unpack(">I", data[offset : offset + 4])[0]
            arch = MACHO_CPU_TYPES.get(cputype)
            if arch:
                arches.append(arch)
            offset += entry_size
        if not arches:
            raise ValueError("macOS universal binary contains no supported arm64 or amd64 slices.")
        return sorted(set(arches))
    if magic == b"\xcf\xfa\xed\xfe":
        cputype = struct.unpack("<I", data[4:8])[0]
    elif magic == b"\xfe\xed\xfa\xcf":
        cputype = struct.unpack(">I", data[4:8])[0]
    else:
        raise ValueError("macOS binary is not a Mach-O or universal binary.")
    arch = MACHO_CPU_TYPES.get(cputype)
    if not arch:
        raise ValueError("macOS binary architecture is not supported.")
    return [arch]


def expected_architectures(arch_mode: str) -> list[str]:
    if arch_mode == "universal":
        return ["amd64", "arm64"]
    return [arch_mode]


def macos_install_root(repo_root: Path, output_root: Path, version: str) -> Path:
    root = output_root / "agent" / version / MACOS_INSTALL_DIR
    if not is_inside(repo_root, root):
        raise ValueError("macOS install staging output must stay inside the repository.")
    return root


def remove_tree(path: Path) -> None:
    def remove_readonly(func: Any, item: str, _exc_info: Any) -> None:
        os.chmod(item, stat.S_IWRITE)
        func(item)

    if path.exists():
        shutil.rmtree(path, onerror=remove_readonly)


def payload_path(root: Path, absolute_path: str) -> Path:
    return root / PKGROOT_DIR / absolute_path.lstrip("/")


def stage_paths(root: Path) -> dict[str, Path]:
    return {
        "binary": payload_path(root, BINARY_PATH),
        "config_example": payload_path(root, "/Library/Application Support/OpenAssetWatch/Agent/config/config.example.json"),
        "identity_example": payload_path(root, "/Library/Application Support/OpenAssetWatch/Agent/identity/identity.example.json"),
        "state_dir": payload_path(root, STATE_DIR),
        "logs_dir": payload_path(root, LOG_DIR),
        "plist": payload_path(root, PLIST_PATH),
        "install_manifest": payload_path(root, INSTALL_MANIFEST_PATH),
        "preinstall": root / SCRIPTS_DIR / "preinstall",
        "postinstall": root / SCRIPTS_DIR / "postinstall",
        "manifest": root / MANIFEST_NAME,
    }


def artifact_dir_name(arch_mode: str) -> str:
    if arch_mode == "universal":
        return "darwin-universal"
    if arch_mode == "arm64":
        return "darwin-arm64"
    if arch_mode == "amd64":
        return "darwin-amd64"
    raise ValueError(f"unsupported architecture mode: {arch_mode}")


def artifact_paths(
    repo_root: Path, output_root: Path, version: str, arch_mode: str, artifact_dir_arg: str | None
) -> tuple[Path, Path, Path, dict[str, Any]]:
    artifact_dir = output_root / "agent" / version / artifact_dir_name(arch_mode)
    if artifact_dir_arg:
        artifact_dir = resolve_repo_path(repo_root, artifact_dir_arg)
    if not is_inside(repo_root, artifact_dir):
        raise ValueError("macOS artifact directory must stay inside the repository.")

    artifact_path = artifact_dir / ARTIFACT_NAME
    checksum_path = artifact_dir / f"{ARTIFACT_NAME}.sha256"
    manifest_path = artifact_dir / f"{ARTIFACT_NAME}.manifest.json"
    if not artifact_path.is_file():
        raise ValueError("macOS agent binary is missing.")
    if not checksum_path.is_file():
        raise ValueError("macOS agent checksum is missing.")
    if not manifest_path.is_file():
        raise ValueError("macOS agent binary manifest is missing.")

    manifest = read_json(manifest_path)
    missing = [field for field in REQUIRED_BINARY_FIELDS if not str(manifest.get(field, "")).strip()]
    if missing:
        raise ValueError(f"macOS binary manifest missing fields: {', '.join(missing)}.")
    if manifest["version"] != version:
        raise ValueError("macOS binary manifest version does not match requested version.")
    if manifest["os"] != TARGET_OS:
        raise ValueError("macOS binary manifest must have os=darwin.")
    expected_arch = "universal" if arch_mode == "universal" else arch_mode
    if manifest["arch"] != expected_arch:
        raise ValueError(f"macOS binary manifest arch must be {expected_arch}.")
    if resolve_repo_path(repo_root, str(manifest["path"])) != artifact_path.resolve():
        raise ValueError("macOS binary manifest path does not match artifact.")
    if not str(manifest.get("git_commit", "")).strip():
        raise ValueError("macOS binary manifest must include git_commit source metadata.")

    actual_hash = sha256_file(artifact_path).lower()
    checksum_hash = checksum_path.read_text(encoding="ascii").strip().split()[0].lower()
    if actual_hash != str(manifest["sha256"]).lower():
        raise ValueError("macOS binary SHA256 does not match manifest.")
    if actual_hash != checksum_hash:
        raise ValueError("macOS binary SHA256 does not match checksum file.")
    actual_arches = macho_architectures(artifact_path)
    expected_arches = expected_architectures(arch_mode)
    if actual_arches != expected_arches:
        raise ValueError(f"macOS binary architectures = {actual_arches}, want {expected_arches}.")
    manifest_arches = sorted(manifest.get("architectures", [manifest["arch"]]))
    if expected_arch == "universal" and manifest_arches != expected_arches:
        raise ValueError("macOS universal binary manifest must list arm64 and amd64 architectures.")
    return artifact_path, checksum_path, manifest_path, manifest


def config_example() -> dict[str, str]:
    return {"server_url": "https://control-tower.example.invalid", "site_id": "site-example"}


def identity_example() -> dict[str, str]:
    return {
        "site_id": "site-example",
        "agent_id": "replace-with-generated-agent-id",
        "deployment_id": "replace-with-deployment-guid",
        "tenant_id": "optional-tenant-id",
        "created_at": "replace-with-created-at",
        "updated_at": "replace-with-updated-at",
    }


def launchd_plist() -> dict[str, Any]:
    return {
        "Label": LAUNCHD_LABEL,
        "ProgramArguments": [
            BINARY_PATH,
            "service",
            "run",
            "--config",
            CONFIG_PATH,
            "--identity-file",
            IDENTITY_PATH,
            "--output-dir",
            STATE_DIR,
        ],
        "UserName": SERVICE_USER,
        "GroupName": SERVICE_GROUP,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 60,
        "ProcessType": "Background",
        "ExitTimeOut": 30,
        "WorkingDirectory": STATE_DIR,
        "Umask": "027",
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_plist(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        plistlib.dump(value, handle, sort_keys=False)


def write_package_scripts(repo_root: Path, root: Path, package_version: str) -> None:
    scripts_source = repo_root / "packaging" / "agent" / "macos" / "scripts"
    scripts_dest = root / SCRIPTS_DIR
    scripts_dest.mkdir(parents=True, exist_ok=True)
    for name in ("preinstall", "postinstall"):
        source = scripts_source / name
        text = source.read_text(encoding="utf-8").replace("__OAW_PACKAGE_VERSION__", package_version)
        dest = scripts_dest / name
        dest.write_text(text, encoding="utf-8")
        dest.chmod(0o755)


def production_paths() -> dict[str, str]:
    return {
        "binary": BINARY_PATH,
        "config": CONFIG_PATH,
        "identity": IDENTITY_PATH,
        "state_dir": STATE_DIR,
        "status": STATUS_PATH,
        "inventory": INVENTORY_PATH,
        "log_dir": LOG_DIR,
        "launchdaemon": PLIST_PATH,
        "install_manifest": INSTALL_MANIFEST_PATH,
    }


def ownership_intent() -> list[dict[str, str]]:
    return [
        {"path": BINARY_PATH, "owner": "root", "group": "wheel", "mode": "0755", "writable_by_service": "false"},
        {"path": PLIST_PATH, "owner": "root", "group": "wheel", "mode": "0644", "writable_by_service": "false"},
        {"path": CONFIG_PATH, "owner": "root", "group": SERVICE_GROUP, "mode": "0640", "writable_by_service": "false"},
        {"path": IDENTITY_PATH, "owner": "root", "group": SERVICE_GROUP, "mode": "0640", "writable_by_service": "false"},
        {"path": STATE_DIR, "owner": SERVICE_USER, "group": SERVICE_GROUP, "mode": "0750", "writable_by_service": "true"},
        {"path": LOG_DIR, "owner": SERVICE_USER, "group": SERVICE_GROUP, "mode": "0750", "writable_by_service": "true"},
    ]


def ensure_no_forbidden_content(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            target = path.resolve()
            if not is_inside(root, target):
                raise ValueError(f"staged symlink escapes root: {path}")
        lowered = path.name.lower()
        if lowered in {"config.json", "identity.json", "status.json", "last-inventory.json"}:
            raise ValueError(f"staging must not include runtime data file: {path}")
        if any(term in lowered for term in FORBIDDEN_STAGE_TERMS):
            raise ValueError(f"staging filename contains forbidden marker: {path}")
        if path.is_file() and path.name.endswith(".example.json") and path.stat().st_size < 256 * 1024:
            text = path.read_text(encoding="utf-8", errors="ignore")
            lowered_text = text.lower()
            if any(term in lowered_text for term in FORBIDDEN_STAGE_TERMS):
                raise ValueError(f"staged file contains forbidden marker: {path}")


def write_staging(
    repo_root: Path,
    root: Path,
    version: str,
    package_version: str,
    arch_mode: str,
    artifact_path: Path,
    checksum_path: Path,
    binary_manifest_path: Path,
    binary_manifest: dict[str, Any],
) -> None:
    if root.exists():
        if not is_inside(repo_root, root):
            raise ValueError("Refusing to replace macOS staging outside the repository.")
        remove_tree(root)

    paths = stage_paths(root)
    paths["binary"].parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(artifact_path, paths["binary"])
    write_json(paths["config_example"], config_example())
    write_json(paths["identity_example"], identity_example())
    paths["state_dir"].mkdir(parents=True, exist_ok=True)
    paths["logs_dir"].mkdir(parents=True, exist_ok=True)
    write_plist(paths["plist"], launchd_plist())
    write_package_scripts(repo_root, root, package_version)

    install_manifest = {
        "package_identifier": PACKAGE_ID,
        "launchd_label": LAUNCHD_LABEL,
        "version": version,
        "package_version": package_version,
        "os": TARGET_OS,
        "architectures": binary_manifest.get("architectures", [binary_manifest["arch"]]),
        "service_account": SERVICE_USER,
        "service_group": SERVICE_GROUP,
        "production_paths": production_paths(),
        "ownership_intent": ownership_intent(),
        "installed_by_pkg": True,
        "contains_secrets": False,
    }
    write_json(paths["install_manifest"], install_manifest)

    manifest = {
        "version": version,
        "package_version": package_version,
        "os": TARGET_OS,
        "arch_mode": arch_mode,
        "architectures": install_manifest["architectures"],
        "source_artifact": to_repo_relative(repo_root, artifact_path),
        "source_checksum": to_repo_relative(repo_root, checksum_path),
        "source_manifest": to_repo_relative(repo_root, binary_manifest_path),
        "source_artifact_sha256": binary_manifest["sha256"],
        "source_git_commit": binary_manifest.get("git_commit", ""),
        "source_provenance": {
            "artifact": to_repo_relative(repo_root, artifact_path),
            "checksum": to_repo_relative(repo_root, checksum_path),
            "manifest": to_repo_relative(repo_root, binary_manifest_path),
            "git_commit": binary_manifest.get("git_commit", ""),
            "sha256": binary_manifest["sha256"],
        },
        "macos_install_root": to_repo_relative(repo_root, root),
        "staged_paths": {name: to_repo_relative(repo_root, path) for name, path in paths.items()},
        "production_paths": production_paths(),
        "package_identifier": PACKAGE_ID,
        "launchd_label": LAUNCHD_LABEL,
        "service_account": SERVICE_USER,
        "service_group": SERVICE_GROUP,
        "ownership_intent": ownership_intent(),
        "generated_at": utc_timestamp(),
        "git_commit": binary_manifest.get("git_commit", ""),
        "signing": {"state": "unsigned", "release_ready": False},
        "notarization": {"state": "not_submitted", "release_ready": False},
        "safety_notes": [
            "staging only; no host installation occurs",
            "examples are placeholders only",
            "LaunchDaemon uses service run and the portable supervisor",
            "launchd KeepAlive=true keeps the daemon available after fatal nonzero exits; transient runtime failures stay inside the supervisor loop",
            "no active scanning, shell command strings, or installer network calls",
        ],
    }
    write_json(paths["manifest"], manifest)
    ensure_no_forbidden_content(root)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--package-version")
    parser.add_argument("--arch-mode", choices=("universal", "arm64", "amd64"), default="universal")
    parser.add_argument("--output-dir", default="dist")
    parser.add_argument("--artifact-dir")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    root_display = ""
    manifest_display = ""
    try:
        version = validate_version(args.version)
        package_version = normalize_package_version(args.package_version or version)
        repo_root = get_repo_root()
        output_root = resolve_repo_path(repo_root, args.output_dir)
        if not is_inside(repo_root, output_root):
            raise ValueError("Output directory must stay inside the repository.")
        root = macos_install_root(repo_root, output_root, version)
        artifact_path, checksum_path, binary_manifest_path, binary_manifest = artifact_paths(
            repo_root, output_root, version, args.arch_mode, args.artifact_dir
        )
        write_staging(
            repo_root,
            root,
            version,
            package_version,
            args.arch_mode,
            artifact_path,
            checksum_path,
            binary_manifest_path,
            binary_manifest,
        )
        root_display = to_repo_relative(repo_root, root)
        manifest_display = to_repo_relative(repo_root, stage_paths(root)["manifest"])
        reporter.check("macos install staging", True, "macOS LaunchDaemon install layout was staged.")
        reporter.check("macos launchd plist", True, "LaunchDaemon plist uses the approved service run model.")
    except Exception as exc:
        reporter.check("macos install staging helper", False, str(exc))

    result = {
        "ok": not reporter.errors,
        "version": args.version,
        "macos_install_root": root_display,
        "manifest": manifest_display,
        "checks": reporter.checks,
        "warnings": reporter.warnings,
        "errors": reporter.errors,
    }
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
