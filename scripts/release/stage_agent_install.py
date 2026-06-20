#!/usr/bin/env python3
"""Validate an agent TAR.GZ package and expand it into local install staging."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


FORBIDDEN_ARCHIVE_RE = re.compile(
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
        self.files: list[str] = []

    def check(self, name: str, ok: bool, message: str = "") -> bool:
        self.checks.append({"name": name, "ok": ok, "message": message})
        if not ok and message:
            self.errors.append(message)
        return ok

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def add_file(self, repo_root: Path, path: Path) -> None:
        self.files.append(to_repo_relative(repo_root, path))


def get_repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def is_inside(parent: Path, child: Path) -> bool:
    parent_value = os.path.normcase(str(parent.resolve()))
    child_value = os.path.normcase(str(child.resolve()))
    try:
        return os.path.commonpath([parent_value, child_value]) == parent_value
    except ValueError:
        return False


def resolve_repo_path(repo_root: Path, value: str) -> Path:
    if not value:
        raise ValueError("Path value cannot be empty.")
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    resolved = candidate.resolve()
    if not is_inside(repo_root, resolved):
        raise ValueError("Path must resolve inside the repository.")
    return resolved


def to_repo_relative(repo_root: Path, path: Path) -> str:
    return path.resolve().relative_to(repo_root.resolve()).as_posix()


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


def find_package(repo_root: Path, version: str) -> Path:
    package_dir = repo_root / "dist" / "agent" / version / "packages"
    packages = sorted(package_dir.glob("*.tar.gz"))
    if not packages:
        raise ValueError(f"No TAR.GZ package found under {to_repo_relative(repo_root, package_dir)}.")
    if len(packages) > 1:
        raise ValueError(
            f"Multiple TAR.GZ packages found under {to_repo_relative(repo_root, package_dir)}; use --package."
        )
    return packages[0].resolve()


def validate_checksum_file(package_path: Path, checksum_path: Path, expected_hash: str) -> None:
    checksum_text = checksum_path.read_text(encoding="ascii").strip()
    checksum_hash = checksum_text.split()[0].lower() if checksum_text else ""
    actual_hash = sha256_file(package_path).lower()
    expected = expected_hash.lower()
    if actual_hash != expected:
        raise ValueError("Package SHA256 does not match package manifest.")
    if actual_hash != checksum_hash:
        raise ValueError("Package SHA256 does not match checksum file.")


def validate_manifest(manifest: dict[str, Any], requested_version: str | None) -> tuple[str, str, str]:
    missing = [field for field in REQUIRED_PACKAGE_FIELDS if not str(manifest.get(field, "")).strip()]
    if missing:
        raise ValueError(f"Package manifest missing fields: {', '.join(missing)}.")
    if manifest["package_type"] != "tar.gz":
        raise ValueError("Package manifest package_type must be tar.gz.")
    if requested_version and manifest["version"] != requested_version:
        raise ValueError("Package manifest version does not match --version.")
    return str(manifest["version"]), str(manifest["os"]), str(manifest["arch"])


def validate_package_location(repo_root: Path, package_path: Path, version: str) -> None:
    expected_dir = (repo_root / "dist" / "agent" / version / "packages").resolve()
    if package_path.resolve().parent != expected_dir:
        raise ValueError("Package must be under dist/agent/<version>/packages/.")


def safe_archive_members(tar: tarfile.TarFile) -> tuple[list[tarfile.TarInfo], tarfile.TarInfo, list[tarfile.TarInfo]]:
    members = tar.getmembers()
    if not members:
        raise ValueError("Package archive is empty.")

    regular_files: list[tarfile.TarInfo] = []
    metadata_files: list[tarfile.TarInfo] = []
    binary_files: list[tarfile.TarInfo] = []

    for member in members:
        name = member.name
        pure = PurePosixPath(name)
        if name.startswith("/") or "\\" in name or ".." in pure.parts or any(":" in part for part in pure.parts):
            raise ValueError(f"Archive contains unsafe path: {name}")
        if FORBIDDEN_ARCHIVE_RE.search(name):
            raise ValueError(f"Archive contains forbidden entry: {name}")
        if not (member.isdir() or member.isfile()):
            raise ValueError(f"Archive contains unsupported entry type: {name}")
        if not member.isfile():
            continue

        regular_files.append(member)
        leaf = pure.name
        if leaf == "README.md" or leaf.endswith(".sha256") or leaf.endswith(".manifest.json"):
            metadata_files.append(member)
        else:
            binary_files.append(member)

    if len(binary_files) != 1:
        raise ValueError("Archive must contain exactly one agent binary file.")
    if not any(PurePosixPath(member.name).name.endswith(".sha256") for member in regular_files):
        raise ValueError("Archive must contain a binary checksum file.")
    if not any(PurePosixPath(member.name).name.endswith(".manifest.json") for member in regular_files):
        raise ValueError("Archive must contain a binary manifest file.")

    return metadata_files, binary_files[0], regular_files


def future_path_notes(target_os: str) -> dict[str, str]:
    if target_os == "windows":
        return {
            "binary": r"C:\Program Files\OpenAssetWatch\oaw-agent.exe",
            "config": r"%ProgramData%\OpenAssetWatch\agent\config.json",
            "identity": r"%ProgramData%\OpenAssetWatch\agent\identity.json",
            "logs": r"%ProgramData%\OpenAssetWatch\agent\logs\\",
            "status": r"%ProgramData%\OpenAssetWatch\agent\logs\status.json",
            "service": "Windows Service Control Manager metadata",
            "package-metadata": "%ProgramData%\\OpenAssetWatch\\agent\\",
        }
    if target_os == "darwin":
        return {
            "binary": "/Library/Application Support/OpenAssetWatch/Agent/bin/oaw-agent",
            "config": "/Library/Application Support/OpenAssetWatch/Agent/config/config.json",
            "identity": "/Library/Application Support/OpenAssetWatch/Agent/identity/identity.json",
            "logs": "/Library/Logs/OpenAssetWatch/Agent/",
            "status": "/Library/Application Support/OpenAssetWatch/Agent/state/status.json",
            "service": "/Library/LaunchDaemons/com.openassetwatch.agent.plist",
            "package-metadata": "/var/db/receipts/com.openassetwatch.agent.*",
        }
    return {
        "binary": "/usr/bin/oaw-agent",
        "config": "/etc/openassetwatch/agent/config.json",
        "identity": "/etc/openassetwatch/agent/identity.json",
        "logs": "/var/log/openassetwatch/agent/",
        "status": "/var/log/openassetwatch/agent/status.json",
        "service": "/etc/systemd/system/openassetwatch-agent.service",
        "package-metadata": "package manager metadata or explicit TAR.GZ manifest",
    }


def write_readme(path: Path, title: str, body: list[str]) -> None:
    content = [f"# {title}", "", *body, ""]
    path.write_text("\n".join(content), encoding="utf-8")


def write_staging_layout(
    reporter: Reporter,
    repo_root: Path,
    staging_dir: Path,
    package_path: Path,
    checksum_path: Path,
    manifest_path: Path,
    target_os: str,
    tar: tarfile.TarFile,
    metadata_members: list[tarfile.TarInfo],
    binary_member: tarfile.TarInfo,
) -> None:
    if staging_dir.exists():
        if not is_inside(repo_root / "dist", staging_dir):
            raise ValueError("Refusing to replace staging directory outside dist/.")
        shutil.rmtree(staging_dir)

    dirs = {
        "binary": staging_dir / "binary",
        "config": staging_dir / "config",
        "identity": staging_dir / "identity",
        "logs": staging_dir / "logs",
        "status": staging_dir / "status",
        "service": staging_dir / "service",
        "package-metadata": staging_dir / "package-metadata",
    }
    for directory in dirs.values():
        directory.mkdir(parents=True, exist_ok=True)

    notes = future_path_notes(target_os)
    for name, directory in dirs.items():
        readme = directory / "README.md"
        if name in {"config", "identity"}:
            body = [
                f"Future path: `{notes[name]}`.",
                "This staging directory intentionally contains no real values.",
                "Do not place sensitive local material here.",
            ]
        elif name in {"logs", "status", "service"}:
            body = [
                f"Future path: `{notes[name]}`.",
                "This staging directory is a proof of layout only.",
                "No logs, runtime status, service definitions, or host modifications are created.",
            ]
        elif name == "binary":
            body = [
                f"Future path: `{notes[name]}`.",
                "The staged binary is copied from the validated local TAR.GZ package.",
            ]
        else:
            body = [
                f"Future path: `{notes[name]}`.",
                "Metadata here is copied from validated local package artifacts.",
                "No signing material, sensitive values, config values, or identity values are stored.",
            ]
        write_readme(readme, f"OpenAssetWatch Agent {name} staging", body)
        reporter.add_file(repo_root, readme)

    binary_target = dirs["binary"] / PurePosixPath(binary_member.name).name
    source = tar.extractfile(binary_member)
    if source is None:
        raise ValueError("Unable to read agent binary from archive.")
    with source, binary_target.open("wb") as target:
        shutil.copyfileobj(source, target)
    reporter.add_file(repo_root, binary_target)

    metadata_dir = dirs["package-metadata"]
    shutil.copy2(checksum_path, metadata_dir / checksum_path.name)
    reporter.add_file(repo_root, metadata_dir / checksum_path.name)
    shutil.copy2(manifest_path, metadata_dir / manifest_path.name)
    reporter.add_file(repo_root, metadata_dir / manifest_path.name)

    for member in metadata_members:
        leaf_name = PurePosixPath(member.name).name
        if leaf_name == "README.md":
            continue
        source = tar.extractfile(member)
        if source is None:
            continue
        destination = metadata_dir / leaf_name
        with source, destination.open("wb") as target:
            shutil.copyfileobj(source, target)
        reporter.add_file(repo_root, destination)


def build_summary(
    reporter: Reporter,
    package_path: Path | None,
    staging_dir: Path | None,
    repo_root: Path,
) -> dict[str, Any]:
    return {
        "ok": not reporter.errors,
        "package": to_repo_relative(repo_root, package_path) if package_path else "",
        "staging_dir": to_repo_relative(repo_root, staging_dir) if staging_dir else "",
        "files": reporter.files,
        "checks": reporter.checks,
        "warnings": reporter.warnings,
        "errors": reporter.errors,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stage a validated OpenAssetWatch agent TAR.GZ package locally.")
    parser.add_argument("--version", help="Release version under dist/agent/<version>/packages/.")
    parser.add_argument("--package", dest="package_path", help="Repo-local TAR.GZ package path.")
    parser.add_argument("--staging-dir", help="Repo-local staging output directory.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    repo_root = get_repo_root()
    package_path: Path | None = None
    staging_dir: Path | None = None

    try:
        if args.package_path:
            package_path = resolve_repo_path(repo_root, args.package_path)
        elif args.version:
            package_path = find_package(repo_root, args.version)
        else:
            raise ValueError("Either --version or --package is required.")

        reporter.check("package exists", package_path.is_file(), "Package file checked.")
        if not package_path.is_file():
            raise ValueError("Package file does not exist.")

        checksum_path = Path(str(package_path) + ".sha256")
        manifest_path = Path(str(package_path) + ".manifest.json")
        reporter.check("package checksum exists", checksum_path.is_file(), "Package checksum checked.")
        reporter.check("package manifest exists", manifest_path.is_file(), "Package manifest checked.")
        if not checksum_path.is_file() or not manifest_path.is_file():
            raise ValueError("Package checksum or manifest is missing.")

        manifest = read_json(manifest_path)
        version, target_os, target_arch = validate_manifest(manifest, args.version)
        reporter.check("package manifest fields", True, "Package manifest fields are present.")
        validate_package_location(repo_root, package_path, version)
        reporter.check("package location", True, "Package is under dist/agent/<version>/packages/.")
        if resolve_repo_path(repo_root, str(manifest["package_path"])) != package_path:
            raise ValueError("Package manifest path does not match selected package.")
        reporter.check("package manifest path", True, "Package manifest path matches selected package.")

        validate_checksum_file(package_path, checksum_path, str(manifest["sha256"]))
        reporter.check("package checksum", True, "Package checksum matches manifest and checksum file.")

        if args.staging_dir:
            staging_dir = resolve_repo_path(repo_root, args.staging_dir)
        else:
            staging_dir = repo_root / "dist" / "staging" / "agent" / version / f"{target_os}-{target_arch}"
        if not is_inside(repo_root, staging_dir):
            raise ValueError("Staging directory must resolve inside the repository.")
        reporter.check("staging path containment", True, "Staging path resolves inside the repository.")

        with tarfile.open(package_path, "r:gz") as tar:
            metadata_members, binary_member, regular_files = safe_archive_members(tar)
            reporter.check("archive contents", True, "Archive contains only safe paths and supported file types.")
            reporter.check("archive forbidden content", True, "Archive contains no forbidden entries.")
            reporter.check("archive required files", True, "Archive contains binary, checksum, and manifest entries.")
            write_staging_layout(
                reporter,
                repo_root,
                staging_dir,
                package_path,
                checksum_path,
                manifest_path,
                target_os,
                tar,
                metadata_members,
                binary_member,
            )
            reporter.check(
                "staging layout",
                True,
                f"Staged {len(regular_files)} archive file(s) plus layout README files.",
            )
    except Exception as exc:
        reporter.check("install staging", False, str(exc))

    summary = build_summary(reporter, package_path, staging_dir, repo_root)
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
