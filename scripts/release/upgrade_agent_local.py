#!/usr/bin/env python3
"""Upgrade or roll back a repo-local OpenAssetWatch agent sandbox install proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


LAYOUT_DIRS = ("binary", "config", "identity", "logs", "status", "service", "package-metadata")
RESTRICTED_PLACEHOLDER_DIRS = ("config", "identity")
SYSTEM_PATH_RE = re.compile(
    r"(^|[\\/])(program files|programdata|usr|etc|var|library)([\\/]|$)",
    re.IGNORECASE,
)
VERSION_RE = re.compile(r"^[A-Za-z0-9._+-]+$")
FORBIDDEN_NAME_RE = re.compile(
    r"(config\.json|identity\.json|status\.json|\.log$|token|secret|"
    r"credential|password|\.pem$|\.key$|\.service$|\.plist$)",
    re.IGNORECASE,
)
REQUIRED_PACKAGE_FIELDS = (
    "package_name",
    "version",
    "os",
    "arch",
    "package_type",
    "source_artifact_path",
    "package_path",
    "sha256",
    "build_timestamp",
    "git_commit",
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

    def warn(self, message: str) -> None:
        self.warnings.append(message)


def get_repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def is_inside(parent: Path, child: Path) -> bool:
    parent_value = os.path.normcase(str(parent.resolve()))
    child_value = os.path.normcase(str(child.resolve()))
    try:
        return os.path.commonpath([parent_value, child_value]) == parent_value
    except ValueError:
        return False


def to_repo_relative(repo_root: Path, path: Path) -> str:
    return path.resolve().relative_to(repo_root.resolve()).as_posix()


def looks_like_system_path(value: str | None, resolved: Path | None = None) -> bool:
    values: list[str] = []
    if value:
        values.append(value.strip().replace("\\", "/"))
    if resolved is not None:
        values.append(str(resolved).replace("\\", "/"))
    for item in values:
        lowered = item.lower()
        if lowered.startswith(("/usr", "/etc", "/var", "/library")):
            return True
        if SYSTEM_PATH_RE.search(lowered):
            return True
    return False


def validate_version(value: str, label: str) -> str:
    if not value:
        raise ValueError(f"{label} cannot be empty.")
    if looks_like_system_path(value):
        raise ValueError(f"{label} cannot look like a system path.")
    if any(part in value for part in ("/", "\\", ":")):
        raise ValueError(f"{label} cannot contain path separators or drive markers.")
    if not VERSION_RE.fullmatch(value):
        raise ValueError(f"{label} must contain only letters, numbers, '.', '_', '+', or '-'.")
    return value


def resolve_repo_path(repo_root: Path, value: str) -> Path:
    if not value:
        raise ValueError("Path value cannot be empty.")
    if looks_like_system_path(value):
        raise ValueError("Refusing path that looks like a system path.")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    resolved = candidate.resolve()
    if looks_like_system_path(value, resolved):
        raise ValueError("Refusing path that looks like a system path.")
    if not is_inside(repo_root, resolved):
        raise ValueError("Path must resolve inside the repository.")
    return resolved


def local_install_base(repo_root: Path) -> Path:
    return repo_root / "dist" / "local-install" / "agent"


def release_base(repo_root: Path) -> Path:
    return repo_root / "dist" / "agent"


def staging_base(repo_root: Path) -> Path:
    return repo_root / "dist" / "staging" / "agent"


def assert_allowed_dist_path(repo_root: Path, path: Path) -> None:
    allowed_roots = (local_install_base(repo_root), release_base(repo_root), staging_base(repo_root))
    if not any(is_inside(root, path) for root in allowed_roots):
        raise ValueError("Path must stay under dist/local-install/agent, dist/agent, or dist/staging/agent.")
    if looks_like_system_path(str(path)):
        raise ValueError("Refusing path that looks like a system path.")


def default_install_root(repo_root: Path, version: str, target_os: str, target_arch: str) -> Path:
    return local_install_base(repo_root) / version / f"{target_os}-{target_arch}"


def validate_install_root(repo_root: Path, install_root: Path, version: str | None = None) -> tuple[str, str]:
    base = local_install_base(repo_root).resolve()
    if not is_inside(base, install_root):
        raise ValueError("Install root must be under dist/local-install/agent/.")
    relative_parts = install_root.resolve().relative_to(base).parts
    if len(relative_parts) != 2:
        raise ValueError("Install root must match dist/local-install/agent/<version>/<os>-<arch>/.")
    root_version, target = relative_parts
    if version and root_version != version:
        raise ValueError("Install root version does not match requested version.")
    if "-" not in target:
        raise ValueError("Install root target directory must look like <os>-<arch>.")
    return root_version, target


def find_install_root(repo_root: Path, version: str) -> Path:
    version_root = local_install_base(repo_root) / version
    assert_allowed_dist_path(repo_root, version_root)
    candidates = [path for path in sorted(version_root.iterdir()) if path.is_dir()] if version_root.exists() else []
    if not candidates:
        raise ValueError(f"No sandbox install root found under {to_repo_relative(repo_root, version_root)}.")
    if len(candidates) > 1:
        raise ValueError(f"Multiple sandbox install roots found under {to_repo_relative(repo_root, version_root)}.")
    install_root = candidates[0].resolve()
    validate_install_root(repo_root, install_root, version)
    return install_root


def find_package(repo_root: Path, version: str) -> Path:
    package_dir = release_base(repo_root) / version / "packages"
    assert_allowed_dist_path(repo_root, package_dir)
    packages = sorted(package_dir.glob("*.tar.gz"))
    if not packages:
        raise ValueError(f"No TAR.GZ package found under {to_repo_relative(repo_root, package_dir)}.")
    if len(packages) > 1:
        raise ValueError(f"Multiple TAR.GZ packages found under {to_repo_relative(repo_root, package_dir)}.")
    return packages[0].resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return value


def validate_checksum_file(package_path: Path, checksum_path: Path, expected_hash: str) -> None:
    checksum_text = checksum_path.read_text(encoding="ascii").strip()
    checksum_hash = checksum_text.split()[0].lower() if checksum_text else ""
    actual_hash = sha256_file(package_path).lower()
    expected = expected_hash.lower()
    if actual_hash != expected:
        raise ValueError("Package SHA256 does not match package manifest.")
    if actual_hash != checksum_hash:
        raise ValueError("Package SHA256 does not match checksum file.")


def validate_manifest(manifest: dict[str, Any], requested_version: str) -> tuple[str, str, str]:
    missing = [field for field in REQUIRED_PACKAGE_FIELDS if not str(manifest.get(field, "")).strip()]
    if missing:
        raise ValueError(f"Package manifest missing fields: {', '.join(missing)}.")
    if manifest["package_type"] != "tar.gz":
        raise ValueError("Package manifest package_type must be tar.gz.")
    if manifest["version"] != requested_version:
        raise ValueError("Package manifest version does not match requested version.")
    return str(manifest["version"]), str(manifest["os"]), str(manifest["arch"])


def validate_package_location(repo_root: Path, package_path: Path, version: str) -> None:
    expected_dir = (release_base(repo_root) / version / "packages").resolve()
    if package_path.resolve().parent != expected_dir:
        raise ValueError("Package must be under dist/agent/<version>/packages/.")


def load_package_context(repo_root: Path, version: str) -> tuple[Path, Path, Path, str, str, str]:
    package_path = find_package(repo_root, version)
    if not package_path.is_file():
        raise ValueError("Package file does not exist.")
    checksum_path = Path(str(package_path) + ".sha256")
    manifest_path = Path(str(package_path) + ".manifest.json")
    if not checksum_path.is_file():
        raise ValueError("Package checksum file is missing.")
    if not manifest_path.is_file():
        raise ValueError("Package manifest file is missing.")

    manifest = read_json(manifest_path)
    package_version, target_os, target_arch = validate_manifest(manifest, version)
    validate_package_location(repo_root, package_path, package_version)
    if resolve_repo_path(repo_root, str(manifest["package_path"])) != package_path.resolve():
        raise ValueError("Package manifest path does not match selected package.")
    validate_checksum_file(package_path, checksum_path, str(manifest["sha256"]))
    return package_path, checksum_path, manifest_path, package_version, target_os, target_arch


def safe_archive_members(tar: tarfile.TarFile) -> tuple[list[tarfile.TarInfo], tarfile.TarInfo]:
    metadata_members: list[tarfile.TarInfo] = []
    binary_members: list[tarfile.TarInfo] = []
    regular_files: list[tarfile.TarInfo] = []

    for member in tar.getmembers():
        name = member.name
        pure = PurePosixPath(name)
        if name.startswith("/") or "\\" in name or ".." in pure.parts or any(":" in part for part in pure.parts):
            raise ValueError(f"Archive contains unsafe path: {name}")
        if FORBIDDEN_NAME_RE.search(name):
            raise ValueError(f"Archive contains forbidden entry: {name}")
        if not (member.isdir() or member.isfile()):
            raise ValueError(f"Archive contains unsupported entry type: {name}")
        if not member.isfile():
            continue

        regular_files.append(member)
        leaf = pure.name
        if leaf == "README.md" or leaf.endswith(".sha256") or leaf.endswith(".manifest.json"):
            metadata_members.append(member)
        else:
            binary_members.append(member)

    if len(binary_members) != 1:
        raise ValueError("Archive must contain exactly one agent binary file.")
    if not any(PurePosixPath(member.name).name.endswith(".sha256") for member in regular_files):
        raise ValueError("Archive must contain a binary checksum file.")
    if not any(PurePosixPath(member.name).name.endswith(".manifest.json") for member in regular_files):
        raise ValueError("Archive must contain a binary manifest file.")
    return metadata_members, binary_members[0]


def metadata_complete(install_root: Path) -> tuple[bool, list[str]]:
    missing: list[str] = []
    for name in LAYOUT_DIRS:
        if not (install_root / name).is_dir():
            missing.append(f"{name}/")

    package_metadata = install_root / "package-metadata"
    if package_metadata.is_dir():
        if not list(package_metadata.glob("*.tar.gz.manifest.json")):
            missing.append("package-metadata/*.tar.gz.manifest.json")
        if not list(package_metadata.glob("*.tar.gz.sha256")):
            missing.append("package-metadata/*.tar.gz.sha256")
        if not [path for path in package_metadata.glob("*.manifest.json") if ".tar.gz." not in path.name]:
            missing.append("package-metadata/<binary>.manifest.json")
        if not [path for path in package_metadata.glob("*.sha256") if ".tar.gz." not in path.name]:
            missing.append("package-metadata/<binary>.sha256")
    return not missing, missing


def write_readme(directory: Path, title: str, body: list[str]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "README.md"
    path.write_text("\n".join([f"# {title}", "", *body, ""]), encoding="utf-8")
    return path


def safe_copy_file(source: Path, destination: Path) -> None:
    if FORBIDDEN_NAME_RE.search(source.name):
        raise ValueError(f"Refusing to copy forbidden file name: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


def prepare_install_root(repo_root: Path, install_root: Path, version: str, target_os: str, target_arch: str) -> None:
    assert_allowed_dist_path(repo_root, install_root)
    validate_install_root(repo_root, install_root, version)
    expected = default_install_root(repo_root, version, target_os, target_arch).resolve()
    if install_root.resolve() != expected:
        raise ValueError("Install root does not match package version and target.")
    if install_root.exists():
        if not is_inside(local_install_base(repo_root), install_root):
            raise ValueError("Refusing to replace existing install root outside local sandbox installs.")
        shutil.rmtree(install_root)
    for name in LAYOUT_DIRS:
        (install_root / name).mkdir(parents=True, exist_ok=True)


def write_layout_readmes(install_root: Path) -> None:
    for name in LAYOUT_DIRS:
        write_readme(
            install_root / name,
            f"OpenAssetWatch Agent local {name} install proof",
            [
                "This is a local sandbox upgrade or rollback proof only.",
                "It does not represent a real system install.",
                "No host operating system paths, services, or runtime state are modified.",
            ],
        )


def preserve_placeholder_dirs(source_root: Path, target_root: Path) -> None:
    for name in RESTRICTED_PLACEHOLDER_DIRS:
        source_readme = source_root / name / "README.md"
        target_readme = target_root / name / "README.md"
        if source_readme.is_file() and not FORBIDDEN_NAME_RE.search(source_readme.name):
            shutil.copy2(source_readme, target_readme)


def install_from_package(
    repo_root: Path,
    package_path: Path,
    checksum_path: Path,
    manifest_path: Path,
    install_root: Path,
) -> None:
    assert_allowed_dist_path(repo_root, package_path)
    assert_allowed_dist_path(repo_root, install_root)
    with tarfile.open(package_path, "r:gz") as tar:
        metadata_members, binary_member = safe_archive_members(tar)
        write_layout_readmes(install_root)

        source = tar.extractfile(binary_member)
        if source is None:
            raise ValueError("Unable to read agent binary from archive.")
        binary_path = install_root / "binary" / PurePosixPath(binary_member.name).name
        with source, binary_path.open("wb") as target:
            shutil.copyfileobj(source, target)

        safe_copy_file(checksum_path, install_root / "package-metadata" / checksum_path.name)
        safe_copy_file(manifest_path, install_root / "package-metadata" / manifest_path.name)
        for member in metadata_members:
            leaf_name = PurePosixPath(member.name).name
            if leaf_name == "README.md":
                continue
            source = tar.extractfile(member)
            if source is None:
                continue
            destination = install_root / "package-metadata" / leaf_name
            with source, destination.open("wb") as target:
                shutil.copyfileobj(source, target)


def write_backup_metadata(
    repo_root: Path,
    mode: str,
    from_version: str,
    to_version: str,
    current_install_root: Path,
    target_install_root: Path,
) -> dict[str, str]:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = local_install_base(repo_root) / "_backups" / f"{timestamp}-{mode}-{from_version}-to-{to_version}"
    assert_allowed_dist_path(repo_root, backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    metadata_path = backup_dir / "backup.json"
    current_metadata = [
        to_repo_relative(repo_root, path)
        for path in sorted((current_install_root / "package-metadata").glob("*"))
        if path.is_file()
    ]
    metadata = {
        "mode": mode,
        "from_version": from_version,
        "to_version": to_version,
        "current_install_root": to_repo_relative(repo_root, current_install_root),
        "target_install_root": to_repo_relative(repo_root, target_install_root),
        "current_package_metadata": current_metadata,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "note": "Repo-local sandbox metadata only. No real config, identity, logs, or service state is stored.",
    }
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return {
        "directory": to_repo_relative(repo_root, backup_dir),
        "metadata": to_repo_relative(repo_root, metadata_path),
    }


def run_mode(reporter: Reporter, repo_root: Path, mode: str, from_version: str, to_version: str) -> tuple[Path, dict[str, str]]:
    if from_version == to_version:
        raise ValueError("from-version and to-version must be different.")

    current_install_root = find_install_root(repo_root, from_version)
    assert_allowed_dist_path(repo_root, current_install_root)
    _, current_target = validate_install_root(repo_root, current_install_root, from_version)
    reporter.check("current install root", True, "Current sandbox install root exists.")

    complete, missing = metadata_complete(current_install_root)
    if not complete:
        raise ValueError(f"Current sandbox install metadata is incomplete: {', '.join(missing)}.")
    reporter.check("current install metadata", True, "Current sandbox install metadata is complete.")

    package_path, checksum_path, manifest_path, package_version, target_os, target_arch = load_package_context(
        repo_root, to_version
    )
    reporter.check("target package validation", True, "Target package checksum and manifest validation passed.")

    target_install_root = default_install_root(repo_root, package_version, target_os, target_arch)
    target_label = f"{target_os}-{target_arch}"
    if current_target != target_label:
        raise ValueError("Target package OS/architecture does not match current sandbox install target.")
    prepare_install_root(repo_root, target_install_root, package_version, target_os, target_arch)
    reporter.check("target install root", True, "Target sandbox install root is repo-local.")

    backup = write_backup_metadata(repo_root, mode, from_version, to_version, current_install_root, target_install_root)
    reporter.check("backup metadata", True, "Backup metadata written under ignored local sandbox install paths.")

    install_from_package(repo_root, package_path, checksum_path, manifest_path, target_install_root)
    preserve_placeholder_dirs(current_install_root, target_install_root)
    reporter.check(mode, True, f"Local sandbox {mode} proof completed.")
    return target_install_root, backup


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Upgrade or roll back a local oaw-agent sandbox install proof.")
    subparsers = parser.add_subparsers(dest="mode", required=True)
    for name in ("upgrade", "rollback"):
        mode_parser = subparsers.add_parser(name, help=f"Run a local sandbox {name} proof.")
        mode_parser.add_argument("--from-version", required=True, help="Currently installed local sandbox version.")
        mode_parser.add_argument("--to-version", required=True, help="Target local release version.")
    return parser.parse_args()


def build_summary(
    reporter: Reporter,
    mode: str,
    from_version: str,
    to_version: str,
    repo_root: Path,
    install_root: Path | None,
    backup: dict[str, str] | None,
) -> dict[str, Any]:
    return {
        "ok": not reporter.errors,
        "mode": mode,
        "from_version": from_version,
        "to_version": to_version,
        "install_root": to_repo_relative(repo_root, install_root) if install_root else "",
        "backup": backup or {},
        "checks": reporter.checks,
        "warnings": reporter.warnings,
        "errors": reporter.errors,
    }


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    repo_root = get_repo_root()
    mode = str(args.mode or "")
    from_version = str(args.from_version or "")
    to_version = str(args.to_version or "")
    install_root: Path | None = None
    backup: dict[str, str] | None = None

    try:
        from_version = validate_version(from_version, "from-version")
        to_version = validate_version(to_version, "to-version")
        if mode not in {"upgrade", "rollback"}:
            raise ValueError("Mode must be upgrade or rollback.")
        install_root, backup = run_mode(reporter, repo_root, mode, from_version, to_version)
    except Exception as exc:
        reporter.check("local upgrade rollback helper", False, str(exc))

    summary = build_summary(reporter, mode, from_version, to_version, repo_root, install_root, backup)
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
