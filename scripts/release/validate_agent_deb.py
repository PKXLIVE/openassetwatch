#!/usr/bin/env python3
"""Validate an existing OpenAssetWatch agent Debian package artifact."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import Any


PACKAGE_NAME = "openassetwatch-agent"
TARGET_OS = "linux"
TARGET_ARCH = "amd64"
DEBIAN_ARCH = "amd64"
EXPECTED_DATA_FILES = {
    "./usr/bin/oaw-agent",
    "./etc/openassetwatch/agent/config.example.json",
    "./etc/openassetwatch/agent/identity.example.json",
    "./lib/systemd/system/oaw-agent.service",
    "./usr/share/doc/openassetwatch-agent/README.md",
    "./usr/share/doc/openassetwatch-agent/release-manifest.json",
}
ALLOWED_DATA_DIRS = {
    "./usr",
    "./usr/bin",
    "./usr/share",
    "./usr/share/doc",
    "./usr/share/doc/openassetwatch-agent",
    "./etc",
    "./etc/openassetwatch",
    "./etc/openassetwatch/agent",
    "./lib",
    "./lib/systemd",
    "./lib/systemd/system",
}
REQUIRED_MANIFEST_FIELDS = (
    "package_name",
    "version",
    "os",
    "arch",
    "package_type",
    "package_path",
    "sha256",
    "build_timestamp",
    "git_commit",
    "contents",
)
FORBIDDEN_TEXT_RE = re.compile(
    r"(token|secret|credential|password|api[_-]?key|private[_-]?key|enrollment|"
    r"status\.json|\.log$|\.pem$|\.key$)",
    re.IGNORECASE,
)
VERSION_RE = re.compile(r"^[A-Za-z0-9.+~_-]+$")
PACKAGE_RE = re.compile(r"^openassetwatch-agent_(?P<version>[A-Za-z0-9.+~_-]+)_amd64\.deb$")


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


def validate_version(version: str) -> str:
    if not version:
        raise ValueError("Version cannot be empty.")
    if any(part in version for part in ("/", "\\", ":", "..")):
        raise ValueError("Version cannot contain path-like values.")
    if not VERSION_RE.fullmatch(version):
        raise ValueError("Version contains unsupported characters for this validator.")
    return version


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


def package_dir(repo_root: Path, version: str) -> Path:
    return repo_root / "dist" / "agent" / version / "packages"


def default_package_path(repo_root: Path, version: str) -> Path:
    return package_dir(repo_root, version) / f"{PACKAGE_NAME}_{version}_{DEBIAN_ARCH}.deb"


def infer_version_from_package(repo_root: Path, package_path: Path) -> str:
    match = PACKAGE_RE.fullmatch(package_path.name)
    if not match:
        raise ValueError("Package name must match openassetwatch-agent_<version>_amd64.deb.")
    version = validate_version(match.group("version"))
    expected_parent = package_dir(repo_root, version).resolve()
    if package_path.resolve().parent != expected_parent:
        raise ValueError("Package must be under dist/agent/<version>/packages/.")
    return version


def select_package(repo_root: Path, version: str | None, package_value: str | None) -> tuple[str, Path]:
    if package_value:
        package_path = resolve_repo_path(repo_root, package_value)
        inferred = infer_version_from_package(repo_root, package_path)
        if version and validate_version(version) != inferred:
            raise ValueError("Package filename/path version does not match --version.")
        return inferred, package_path
    if not version:
        raise ValueError("Either --version or --package is required.")
    selected_version = validate_version(version)
    return selected_version, default_package_path(repo_root, selected_version)


def validate_package_metadata(repo_root: Path, package_path: Path, version: str) -> tuple[Path, dict[str, Any]]:
    if not package_path.is_file():
        raise ValueError("DEB package does not exist.")
    checksum_path = Path(str(package_path) + ".sha256")
    manifest_path = Path(str(package_path) + ".manifest.json")
    if not checksum_path.is_file():
        raise ValueError("DEB package checksum file is missing.")
    if not manifest_path.is_file():
        raise ValueError("DEB package manifest file is missing.")

    actual_hash = sha256_file(package_path).lower()
    checksum_text = checksum_path.read_text(encoding="ascii").strip()
    checksum_hash = checksum_text.split()[0].lower() if checksum_text else ""
    if checksum_hash != actual_hash:
        raise ValueError("DEB package checksum file does not match package.")

    manifest = read_json(manifest_path)
    missing = [field for field in REQUIRED_MANIFEST_FIELDS if not str(manifest.get(field, "")).strip()]
    if missing:
        raise ValueError(f"DEB package manifest missing fields: {', '.join(missing)}.")
    if manifest["package_name"] != PACKAGE_NAME:
        raise ValueError("DEB package manifest package_name mismatch.")
    if manifest["version"] != version:
        raise ValueError("DEB package manifest version mismatch.")
    if manifest["os"] != TARGET_OS or manifest["arch"] != TARGET_ARCH:
        raise ValueError("DEB package manifest must be for linux/amd64.")
    if manifest["package_type"] != "deb":
        raise ValueError("DEB package manifest package_type must be deb.")
    if str(manifest["sha256"]).lower() != actual_hash:
        raise ValueError("DEB package manifest SHA256 does not match package.")
    if resolve_repo_path(repo_root, str(manifest["package_path"])) != package_path.resolve():
        raise ValueError("DEB package manifest path does not match selected package.")
    contents = set(manifest.get("contents", []))
    if contents != EXPECTED_DATA_FILES:
        raise ValueError("DEB package manifest contents do not match expected package paths.")
    return manifest_path, manifest


def parse_ar(path: Path) -> dict[str, bytes]:
    data = path.read_bytes()
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("DEB artifact is not an ar archive.")
    offset = 8
    members: dict[str, bytes] = {}
    while offset < len(data):
        header = data[offset : offset + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            raise ValueError("DEB ar member header is malformed.")
        name = header[0:16].decode("ascii").strip()
        if name.endswith("/"):
            name = name[:-1]
        size = int(header[48:58].decode("ascii").strip())
        offset += 60
        member_data = data[offset : offset + size]
        if len(member_data) != size:
            raise ValueError("DEB ar member size is invalid.")
        members[name] = member_data
        offset += size
        if offset % 2:
            offset += 1
    return members


def tar_members_from_gzip(data: bytes) -> tuple[dict[str, bytes], set[str]]:
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as gz:
        tar_bytes = gz.read()
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tar:
        for member in tar.getmembers():
            pure = PurePosixPath(member.name)
            if member.name.startswith("/") or "\\" in member.name or ".." in pure.parts:
                raise ValueError(f"Package archive contains unsafe path: {member.name}")
            if not (member.isdir() or member.isfile()):
                raise ValueError(f"Package archive contains unsupported entry type: {member.name}")
            if member.isfile():
                source = tar.extractfile(member)
                files[member.name] = source.read() if source else b""
            else:
                directories.add(member.name)
    return files, directories


def validate_control_archive(control_files: dict[str, bytes]) -> None:
    if set(control_files) != {"./control"}:
        unexpected = ", ".join(sorted(set(control_files) - {"./control"}))
        raise ValueError(f"DEB control archive contains unexpected maintainer files: {unexpected}")
    control_text = control_files["./control"].decode("utf-8")
    required_lines = (
        f"Package: {PACKAGE_NAME}",
        "Architecture: amd64",
    )
    for line in required_lines:
        if line not in control_text:
            raise ValueError(f"DEB control file missing expected line: {line}")


def validate_example_config(data: bytes) -> None:
    value = json.loads(data.decode("utf-8"))
    if set(value) != {"server_url", "site_id"}:
        raise ValueError("Example config must contain only server_url and site_id.")
    if not str(value["server_url"]).endswith(".example.invalid"):
        raise ValueError("Example config server_url must use example.invalid.")
    if value["site_id"] != "site-example":
        raise ValueError("Example config site_id must be site-example.")


def validate_example_identity(data: bytes) -> None:
    value = json.loads(data.decode("utf-8"))
    expected_keys = {"site_id", "agent_id", "deployment_id", "tenant_id", "created_at", "updated_at"}
    if set(value) != expected_keys:
        raise ValueError("Example identity contains unexpected fields.")
    if value["site_id"] != "site-example":
        raise ValueError("Example identity site_id must be site-example.")
    for key in ("agent_id", "deployment_id", "created_at", "updated_at"):
        if not str(value[key]).startswith("replace-with-"):
            raise ValueError(f"Example identity {key} must be an explicit placeholder.")
    if value["tenant_id"] != "optional-tenant-id":
        raise ValueError("Example identity tenant_id must be optional-tenant-id.")


def validate_service_unit(data: bytes) -> None:
    text = data.decode("utf-8")
    forbidden = ("sh -c", "/bin/sh", "bash", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload")
    found = [item for item in forbidden if item in text]
    if found:
        raise ValueError(f"Service unit contains unsafe directives or shell usage: {', '.join(found)}.")
    required_lines = {
        "ConditionPathExists=/etc/openassetwatch/agent/config.json",
        "ConditionPathExists=/etc/openassetwatch/agent/identity.json",
        "ExecStart=/usr/bin/oaw-agent doctor --config /etc/openassetwatch/agent/config.json --identity-file /etc/openassetwatch/agent/identity.json",
    }
    missing = [line for line in sorted(required_lines) if line not in text]
    if missing:
        raise ValueError(f"Service unit missing expected safe lines: {', '.join(missing)}.")


def validate_release_manifest(data: bytes, version: str) -> None:
    value = json.loads(data.decode("utf-8"))
    if value.get("package_name") != PACKAGE_NAME:
        raise ValueError("Release manifest package_name mismatch.")
    if value.get("version") != version:
        raise ValueError("Release manifest version mismatch.")
    if value.get("os") != TARGET_OS or value.get("arch") != TARGET_ARCH:
        raise ValueError("Release manifest must be for linux/amd64.")
    installed_paths = set(value.get("installed_paths", []))
    if installed_paths != EXPECTED_DATA_FILES:
        raise ValueError("Release manifest installed_paths do not match expected package paths.")
    service = value.get("service", {})
    if service.get("enabled_by_package_build") is not False or service.get("started_by_package_build") is not False:
        raise ValueError("Release manifest must show service is not enabled or started by package build.")


def validate_forbidden_content(data_files: dict[str, bytes]) -> None:
    for name, data in data_files.items():
        if name == "./usr/bin/oaw-agent":
            continue
        if name in {
            "./etc/openassetwatch/agent/config.example.json",
            "./etc/openassetwatch/agent/identity.example.json",
            "./lib/systemd/system/oaw-agent.service",
        }:
            continue
        leaf = PurePosixPath(name).name
        if FORBIDDEN_TEXT_RE.search(leaf):
            raise ValueError(f"DEB data archive contains forbidden path: {name}")
        text = data.decode("utf-8", errors="ignore")
        if FORBIDDEN_TEXT_RE.search(text):
            raise ValueError(f"DEB data archive contains forbidden content: {name}")


def validate_data_archive(data_files: dict[str, bytes], data_dirs: set[str], version: str) -> None:
    if set(data_files) != EXPECTED_DATA_FILES:
        missing = EXPECTED_DATA_FILES - set(data_files)
        unexpected = set(data_files) - EXPECTED_DATA_FILES
        message = []
        if missing:
            message.append(f"missing: {', '.join(sorted(missing))}")
        if unexpected:
            message.append(f"unexpected: {', '.join(sorted(unexpected))}")
        raise ValueError(f"DEB data archive file paths mismatch ({'; '.join(message)}).")
    unexpected_dirs = data_dirs - ALLOWED_DATA_DIRS
    if unexpected_dirs:
        raise ValueError(f"DEB data archive contains unexpected directories: {', '.join(sorted(unexpected_dirs))}.")
    validate_example_config(data_files["./etc/openassetwatch/agent/config.example.json"])
    validate_example_identity(data_files["./etc/openassetwatch/agent/identity.example.json"])
    validate_service_unit(data_files["./lib/systemd/system/oaw-agent.service"])
    validate_release_manifest(data_files["./usr/share/doc/openassetwatch-agent/release-manifest.json"], version)
    validate_forbidden_content(data_files)


def validate_deb(package_path: Path, version: str) -> None:
    ar_members = parse_ar(package_path)
    expected_members = {"debian-binary", "control.tar.gz", "data.tar.gz"}
    if set(ar_members) != expected_members:
        raise ValueError("DEB archive must contain debian-binary, control.tar.gz, and data.tar.gz.")
    if ar_members["debian-binary"] != b"2.0\n":
        raise ValueError("DEB debian-binary member must be 2.0.")
    control_files, control_dirs = tar_members_from_gzip(ar_members["control.tar.gz"])
    if control_dirs:
        raise ValueError("DEB control archive contains unexpected directories.")
    validate_control_archive(control_files)
    data_files, data_dirs = tar_members_from_gzip(ar_members["data.tar.gz"])
    validate_data_archive(data_files, data_dirs, version)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate an OpenAssetWatch agent Debian package artifact.")
    parser.add_argument("--version", help="Release version under dist/agent/<version>/packages/.")
    parser.add_argument("--package", dest="package_path", help="Repo-local DEB package path.")
    return parser.parse_args()


def build_summary(reporter: Reporter, repo_root: Path, package_path: Path | None) -> dict[str, Any]:
    return {
        "ok": not reporter.errors,
        "package": to_repo_relative(repo_root, package_path) if package_path else "",
        "checks": reporter.checks,
        "warnings": reporter.warnings,
        "errors": reporter.errors,
    }


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    repo_root = get_repo_root()
    package_path: Path | None = None

    try:
        version, package_path = select_package(repo_root, args.version, args.package_path)
        reporter.check("package path", True, "Package path resolves under dist/agent/<version>/packages/.")
        manifest_path, _manifest = validate_package_metadata(repo_root, package_path, version)
        reporter.check("package metadata", True, "Package file, checksum, and manifest validation passed.")
        validate_deb(package_path, version)
        reporter.check("package archive", True, "Package archive contains expected safe Debian members and data paths.")
        reporter.check("package manifest", manifest_path.is_file(), "Package manifest exists.")
    except Exception as exc:
        reporter.check("deb package validation", False, str(exc))

    summary = build_summary(reporter, repo_root, package_path)
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
