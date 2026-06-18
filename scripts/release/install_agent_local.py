#!/usr/bin/env python3
"""Create a local sandbox install proof from an agent package or staging tree."""

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


LAYOUT_DIRS = ("binary", "config", "identity", "logs", "status", "service", "package-metadata")
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
        self.files: list[str] = []
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


def find_staging_dir(repo_root: Path, version: str) -> Path:
    staging_root = repo_root / "dist" / "staging" / "agent" / version
    candidates = [path for path in sorted(staging_root.iterdir()) if path.is_dir()] if staging_root.exists() else []
    if not candidates:
        raise ValueError(f"No staging layout found under {to_repo_relative(repo_root, staging_root)}.")
    if len(candidates) > 1:
        raise ValueError(
            f"Multiple staging layouts found under {to_repo_relative(repo_root, staging_root)}; use --staging-dir."
        )
    return candidates[0].resolve()


def infer_from_staging_dir(repo_root: Path, staging_dir: Path) -> tuple[str, str, str]:
    relative_parts = staging_dir.resolve().relative_to(repo_root.resolve()).parts
    marker = ("dist", "staging", "agent")
    for index in range(len(relative_parts) - len(marker)):
        if tuple(relative_parts[index : index + len(marker)]) == marker:
            version_index = index + len(marker)
            target_index = version_index + 1
            if target_index >= len(relative_parts):
                break
            version = relative_parts[version_index]
            target = relative_parts[target_index]
            if "-" not in target:
                break
            target_os, target_arch = target.rsplit("-", 1)
            return version, target_os, target_arch
    raise ValueError("Unable to infer version and target from staging directory path.")


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


def validate_staging_layout(staging_dir: Path) -> None:
    for name in LAYOUT_DIRS:
        directory = staging_dir / name
        if not directory.is_dir():
            raise ValueError(f"Staging layout missing {name}/.")

    restricted_dirs = ("config", "identity", "logs", "status", "service")
    for name in restricted_dirs:
        files = [path for path in (staging_dir / name).iterdir() if path.is_file()]
        unexpected = [path.name for path in files if path.name != "README.md"]
        if unexpected:
            raise ValueError(f"Staging {name}/ contains unexpected files: {', '.join(unexpected)}.")

    binary_files = [
        path for path in (staging_dir / "binary").iterdir() if path.is_file() and path.name != "README.md"
    ]
    if len(binary_files) != 1:
        raise ValueError("Staging binary/ must contain exactly one agent binary.")


def safe_copy_file(reporter: Reporter, repo_root: Path, source: Path, destination: Path) -> None:
    if FORBIDDEN_NAME_RE.search(source.name):
        raise ValueError(f"Refusing to copy forbidden file name: {source.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    reporter.add_file(repo_root, destination)


def write_readme(reporter: Reporter, repo_root: Path, directory: Path, title: str, body: list[str]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "README.md"
    path.write_text("\n".join([f"# {title}", "", *body, ""]), encoding="utf-8")
    reporter.add_file(repo_root, path)


def prepare_install_root(repo_root: Path, install_root: Path) -> None:
    if not is_inside(repo_root, install_root):
        raise ValueError("Install root must resolve inside the repository.")
    if install_root.exists():
        if not is_inside(repo_root / "dist", install_root):
            raise ValueError("Refusing to replace existing install root outside dist/.")
        shutil.rmtree(install_root)
    for name in LAYOUT_DIRS:
        (install_root / name).mkdir(parents=True, exist_ok=True)


def default_install_root(repo_root: Path, version: str, target_os: str, target_arch: str) -> Path:
    return repo_root / "dist" / "local-install" / "agent" / version / f"{target_os}-{target_arch}"


def install_from_staging(reporter: Reporter, repo_root: Path, staging_dir: Path, install_root: Path) -> None:
    validate_staging_layout(staging_dir)
    reporter.check("staging layout", True, "Staging layout has required proof directories.")

    for name in LAYOUT_DIRS:
        write_readme(
            reporter,
            repo_root,
            install_root / name,
            f"OpenAssetWatch Agent local {name} install proof",
            [
                "This is a local sandbox install proof only.",
                "It does not represent a real system install.",
                "No host operating system paths, services, or runtime state are modified.",
            ],
        )

    for source in sorted((staging_dir / "binary").iterdir()):
        if source.is_file() and source.name != "README.md" and not FORBIDDEN_NAME_RE.search(source.name):
            safe_copy_file(reporter, repo_root, source, install_root / "binary" / source.name)

    for source in sorted((staging_dir / "package-metadata").iterdir()):
        if not source.is_file():
            continue
        if source.name.endswith(".sha256") or source.name.endswith(".manifest.json"):
            safe_copy_file(reporter, repo_root, source, install_root / "package-metadata" / source.name)


def install_from_package(
    reporter: Reporter,
    repo_root: Path,
    package_path: Path,
    checksum_path: Path,
    manifest_path: Path,
    install_root: Path,
) -> None:
    with tarfile.open(package_path, "r:gz") as tar:
        metadata_members, binary_member = safe_archive_members(tar)
        reporter.check("archive contents", True, "Archive contains safe paths and expected file types.")

        for name in LAYOUT_DIRS:
            write_readme(
                reporter,
                repo_root,
                install_root / name,
                f"OpenAssetWatch Agent local {name} install proof",
                [
                    "This is a local sandbox install proof only.",
                    "It does not represent a real system install.",
                    "No host operating system paths, services, or runtime state are modified.",
                ],
            )

        source = tar.extractfile(binary_member)
        if source is None:
            raise ValueError("Unable to read agent binary from archive.")
        binary_path = install_root / "binary" / PurePosixPath(binary_member.name).name
        with source, binary_path.open("wb") as target:
            shutil.copyfileobj(source, target)
        reporter.add_file(repo_root, binary_path)

        safe_copy_file(reporter, repo_root, checksum_path, install_root / "package-metadata" / checksum_path.name)
        safe_copy_file(reporter, repo_root, manifest_path, install_root / "package-metadata" / manifest_path.name)
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
            reporter.add_file(repo_root, destination)


def load_package_context(repo_root: Path, package_path: Path, requested_version: str | None) -> tuple[str, str, str]:
    if not package_path.is_file():
        raise ValueError("Package file does not exist.")
    checksum_path = Path(str(package_path) + ".sha256")
    manifest_path = Path(str(package_path) + ".manifest.json")
    if not checksum_path.is_file():
        raise ValueError("Package checksum file is missing.")
    if not manifest_path.is_file():
        raise ValueError("Package manifest file is missing.")
    manifest = read_json(manifest_path)
    version, target_os, target_arch = validate_manifest(manifest, requested_version)
    validate_package_location(repo_root, package_path, version)
    if resolve_repo_path(repo_root, str(manifest["package_path"])) != package_path.resolve():
        raise ValueError("Package manifest path does not match selected package.")
    validate_checksum_file(package_path, checksum_path, str(manifest["sha256"]))
    return version, target_os, target_arch


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create a local sandbox install proof for oaw-agent.")
    parser.add_argument("--version", help="Release version under dist/agent/<version>/packages/.")
    parser.add_argument("--package", dest="package_path", help="Repo-local TAR.GZ package path.")
    parser.add_argument("--staging-dir", help="Repo-local staged install layout path.")
    parser.add_argument("--install-root", help="Repo-local install proof output path.")
    return parser.parse_args()


def build_summary(reporter: Reporter, repo_root: Path, install_root: Path | None) -> dict[str, Any]:
    return {
        "ok": not reporter.errors,
        "install_root": to_repo_relative(repo_root, install_root) if install_root else "",
        "files": reporter.files,
        "checks": reporter.checks,
        "warnings": reporter.warnings,
        "errors": reporter.errors,
    }


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    repo_root = get_repo_root()
    install_root: Path | None = None

    try:
        if args.staging_dir:
            staging_dir = resolve_repo_path(repo_root, args.staging_dir)
            if not staging_dir.is_dir():
                raise ValueError("Staging directory does not exist.")
            version, target_os, target_arch = infer_from_staging_dir(repo_root, staging_dir)
            if args.version and args.version != version:
                raise ValueError("Staging directory version does not match --version.")
            install_root = (
                resolve_repo_path(repo_root, args.install_root)
                if args.install_root
                else default_install_root(repo_root, version, target_os, target_arch)
            )
            prepare_install_root(repo_root, install_root)
            reporter.check("install root containment", True, "Install root resolves inside the repository.")
            install_from_staging(reporter, repo_root, staging_dir, install_root)
            reporter.check("local install proof", True, "Local install proof copied from staging layout.")
        else:
            if args.package_path:
                package_path = resolve_repo_path(repo_root, args.package_path)
            elif args.version:
                package_path = find_package(repo_root, args.version)
            else:
                raise ValueError("Either --version, --package, or --staging-dir is required.")

            version, target_os, target_arch = load_package_context(repo_root, package_path, args.version)
            checksum_path = Path(str(package_path) + ".sha256")
            manifest_path = Path(str(package_path) + ".manifest.json")
            reporter.check("package validation", True, "Package checksum and manifest validation passed.")
            install_root = (
                resolve_repo_path(repo_root, args.install_root)
                if args.install_root
                else default_install_root(repo_root, version, target_os, target_arch)
            )
            prepare_install_root(repo_root, install_root)
            reporter.check("install root containment", True, "Install root resolves inside the repository.")
            install_from_package(reporter, repo_root, package_path, checksum_path, manifest_path, install_root)
            reporter.check("local install proof", True, "Local install proof copied from package.")
    except Exception as exc:
        reporter.check("local install helper", False, str(exc))

    summary = build_summary(reporter, repo_root, install_root)
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
