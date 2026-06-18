#!/usr/bin/env python3
"""Build a Debian package artifact for the OpenAssetWatch agent."""

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
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


PACKAGE_NAME = "openassetwatch-agent"
TARGET_OS = "linux"
TARGET_ARCH = "amd64"
DEBIAN_ARCH = "amd64"
EXPECTED_DATA_PATHS = (
    "./usr/bin/oaw-agent",
    "./etc/openassetwatch/agent/config.example.json",
    "./etc/openassetwatch/agent/identity.example.json",
    "./lib/systemd/system/oaw-agent.service",
    "./usr/share/doc/openassetwatch-agent/README.md",
    "./usr/share/doc/openassetwatch-agent/release-manifest.json",
)
EXPECTED_DATA_DIRS = (
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
    "./var",
    "./var/lib",
    "./var/lib/openassetwatch",
    "./var/lib/openassetwatch/agent",
    "./var/log",
    "./var/log/openassetwatch",
    "./var/log/openassetwatch/agent",
)
EXPECTED_CONTROL_PATHS = (
    "./control",
    "./postinst",
    "./postrm",
)
REQUIRED_BINARY_FIELDS = (
    "artifact_name",
    "version",
    "os",
    "arch",
    "path",
    "sha256",
    "git_commit",
)
REQUIRED_PACKAGE_FIELDS = (
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
FORBIDDEN_CONTENT_RE = re.compile(
    r"(token|secret|credential|password|api[_-]?key|private[_-]?key|enrollment|"
    r"status\.json|\.log$|\.pem$|\.key$)",
    re.IGNORECASE,
)
VERSION_RE = re.compile(r"^[A-Za-z0-9.+~_-]+$")


class Reporter:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.contents: list[str] = []

    def check(self, name: str, ok: bool, message: str = "") -> bool:
        self.checks.append({"name": name, "ok": ok, "message": message})
        if not ok and message:
            self.errors.append(message)
        return ok

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def add_content(self, path: str) -> None:
        self.contents.append(path)


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
        raise ValueError("Version contains unsupported characters for this package helper.")
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


def validate_binary_artifact(
    repo_root: Path,
    version: str,
) -> tuple[Path, Path, Path, dict[str, Any]]:
    artifact_dir = repo_root / "dist" / "agent" / version / f"{TARGET_OS}-{TARGET_ARCH}"
    if not is_inside(repo_root / "dist" / "agent", artifact_dir):
        raise ValueError("Artifact directory must stay under dist/agent/.")
    if not artifact_dir.is_dir():
        raise ValueError(f"Linux agent artifact directory does not exist: {to_repo_relative(repo_root, artifact_dir)}")

    artifact_path = artifact_dir / "oaw-agent"
    checksum_path = artifact_dir / "oaw-agent.sha256"
    manifest_path = artifact_dir / "oaw-agent.manifest.json"
    if not artifact_path.is_file():
        raise ValueError("Linux agent binary is missing.")
    if not checksum_path.is_file():
        raise ValueError("Linux agent checksum is missing.")
    if not manifest_path.is_file():
        raise ValueError("Linux agent manifest is missing.")

    manifest = read_json(manifest_path)
    missing = [field for field in REQUIRED_BINARY_FIELDS if not str(manifest.get(field, "")).strip()]
    if missing:
        raise ValueError(f"Binary manifest missing fields: {', '.join(missing)}.")
    if manifest.get("artifact_type") and manifest["artifact_type"] != "oaw-agent-binary":
        raise ValueError("Binary manifest artifact_type must be oaw-agent-binary.")
    if manifest["artifact_name"] != "oaw-agent":
        raise ValueError("Binary manifest artifact_name must be oaw-agent.")
    if manifest["version"] != version:
        raise ValueError("Binary manifest version does not match requested version.")
    if manifest["os"] != TARGET_OS or manifest["arch"] != TARGET_ARCH:
        raise ValueError("Binary manifest must be for linux/amd64.")
    if resolve_repo_path(repo_root, str(manifest["path"])) != artifact_path.resolve():
        raise ValueError("Binary manifest path does not match linux agent artifact.")

    actual_hash = sha256_file(artifact_path).lower()
    expected_hash = str(manifest["sha256"]).lower()
    checksum_text = checksum_path.read_text(encoding="ascii").strip()
    checksum_hash = checksum_text.split()[0].lower() if checksum_text else ""
    if actual_hash != expected_hash:
        raise ValueError("Linux agent binary SHA256 does not match manifest.")
    if actual_hash != checksum_hash:
        raise ValueError("Linux agent binary SHA256 does not match checksum file.")
    return artifact_path, checksum_path, manifest_path, manifest


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def package_paths(repo_root: Path, version: str) -> tuple[Path, Path, Path]:
    package_dir = repo_root / "dist" / "agent" / version / "packages"
    if not is_inside(repo_root / "dist" / "agent", package_dir):
        raise ValueError("Package output must stay under dist/agent/.")
    package_dir.mkdir(parents=True, exist_ok=True)
    package_path = package_dir / f"{PACKAGE_NAME}_{version}_{DEBIAN_ARCH}.deb"
    checksum_path = Path(str(package_path) + ".sha256")
    manifest_path = Path(str(package_path) + ".manifest.json")
    return package_path, checksum_path, manifest_path


def control_file(version: str) -> bytes:
    description = (
        "Description: OpenAssetWatch defensive local asset inventory agent\n"
        " The OpenAssetWatch agent collects local, passive asset inventory\n"
        " observations for administrator-approved OpenAssetWatch deployments.\n"
        " This package installs a conservative service unit template but does\n"
        " not enable or start the service as part of package creation.\n"
    )
    fields = [
        f"Package: {PACKAGE_NAME}",
        f"Version: {version}",
        "Section: admin",
        "Priority: optional",
        f"Architecture: {DEBIAN_ARCH}",
        "Maintainer: OpenAssetWatch <noreply@openassetwatch.example>",
        "Depends: systemd",
        "Installed-Size: 1",
        description.rstrip("\n"),
        "",
    ]
    return "\n".join(fields).encode("utf-8")


def maintainer_script() -> bytes:
    return "\n".join(
        [
            "#!/bin/sh",
            "set -e",
            'if command -v systemctl >/dev/null 2>&1; then',
            "    systemctl daemon-reload || true",
            "fi",
            "exit 0",
            "",
        ]
    ).encode("utf-8")


def config_example() -> bytes:
    return (
        json.dumps(
            {
                "server_url": "https://control-tower.example.invalid",
                "site_id": "site-example",
            },
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def identity_example() -> bytes:
    return (
        json.dumps(
            {
                "site_id": "site-example",
                "agent_id": "replace-with-generated-agent-id",
                "deployment_id": "replace-with-deployment-guid",
                "tenant_id": "optional-tenant-id",
                "created_at": "replace-with-created-at",
                "updated_at": "replace-with-updated-at",
            },
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def service_unit() -> bytes:
    return "\n".join(
        [
            "[Unit]",
            "Description=OpenAssetWatch Agent",
            "Documentation=https://openassetwatch.example.invalid/docs",
            "ConditionPathExists=/etc/openassetwatch/agent/config.json",
            "ConditionPathExists=/etc/openassetwatch/agent/identity.json",
            "",
            "[Service]",
            "Type=oneshot",
            "ExecStart=/usr/bin/oaw-agent doctor --config /etc/openassetwatch/agent/config.json --identity-file /etc/openassetwatch/agent/identity.json",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    ).encode("utf-8")


def package_readme(version: str) -> bytes:
    return "\n".join(
        [
            "# OpenAssetWatch Agent Debian Package",
            "",
            f"Package: `{PACKAGE_NAME}`",
            f"Version: `{version}`",
            "",
            "This package contains the OpenAssetWatch agent binary, example",
            "configuration placeholders, an example identity placeholder, a",
            "conservative systemd unit template, and release metadata.",
            "",
            "The package artifact is built locally under the repository `dist/`",
            "directory. Building the artifact does not install, enable, or start",
            "software on the build machine.",
            "",
        ]
    ).encode("utf-8")


def release_manifest(
    version: str,
    binary_manifest: dict[str, Any],
    artifact_path: Path,
    repo_root: Path,
) -> bytes:
    value = {
        "package_name": PACKAGE_NAME,
        "version": version,
        "os": TARGET_OS,
        "arch": TARGET_ARCH,
        "binary": {
            "path": "/usr/bin/oaw-agent",
            "source_artifact": to_repo_relative(repo_root, artifact_path),
            "sha256": binary_manifest["sha256"],
            "git_commit": binary_manifest["git_commit"],
        },
        "installed_paths": list(EXPECTED_DATA_PATHS),
        "service": {
            "path": "/lib/systemd/system/oaw-agent.service",
            "model": "oneshot-readiness-check",
            "command": "/usr/bin/oaw-agent doctor --config /etc/openassetwatch/agent/config.json --identity-file /etc/openassetwatch/agent/identity.json",
            "enabled_by_package_build": False,
            "started_by_package_build": False,
        },
        "directories": list(EXPECTED_DATA_DIRS),
        "dependencies": ["systemd"],
        "maintainer_scripts": ["postinst", "postrm"],
        "build_timestamp": utc_timestamp(),
    }
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def tarinfo_for(path: str, data: bytes | None, mode: int, mtime: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(path)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = mtime
    if data is None:
        info.type = tarfile.DIRTYPE
        info.size = 0
    else:
        info.size = len(data)
    return info


def add_dir(tar: tarfile.TarFile, path: str, mtime: int) -> None:
    tar.addfile(tarinfo_for(path, None, 0o755, mtime))


def add_file(tar: tarfile.TarFile, path: str, data: bytes, mode: int, mtime: int) -> None:
    tar.addfile(tarinfo_for(path, data, mode, mtime), io.BytesIO(data))


def build_control_tar(version: str, mtime: int) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        add_file(tar, "./control", control_file(version), 0o644, mtime)
        add_file(tar, "./postinst", maintainer_script(), 0o755, mtime)
        add_file(tar, "./postrm", maintainer_script(), 0o755, mtime)
    return output.getvalue()


def build_data_tar(
    version: str,
    artifact_path: Path,
    binary_manifest: dict[str, Any],
    repo_root: Path,
    reporter: Reporter,
    mtime: int,
) -> bytes:
    binary_data = artifact_path.read_bytes()
    release_manifest_data = release_manifest(version, binary_manifest, artifact_path, repo_root)
    files = {
        "./usr/bin/oaw-agent": (binary_data, 0o755),
        "./etc/openassetwatch/agent/config.example.json": (config_example(), 0o644),
        "./etc/openassetwatch/agent/identity.example.json": (identity_example(), 0o644),
        "./lib/systemd/system/oaw-agent.service": (service_unit(), 0o644),
        "./usr/share/doc/openassetwatch-agent/README.md": (package_readme(version), 0o644),
        "./usr/share/doc/openassetwatch-agent/release-manifest.json": (release_manifest_data, 0o644),
    }
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        for directory in EXPECTED_DATA_DIRS:
            add_dir(tar, directory, mtime)
        for path, (data, mode) in files.items():
            add_file(tar, path, data, mode, mtime)
            reporter.add_content(path)
    return output.getvalue()


def ar_header(name: str, size: int, mtime: int, mode: int = 0o100644) -> bytes:
    if len(name) > 15:
        raise ValueError(f"ar member name is too long: {name}")
    fields = (
        f"{name}/".ljust(16),
        str(mtime).ljust(12),
        "0".ljust(6),
        "0".ljust(6),
        oct(mode)[2:].ljust(8),
        str(size).ljust(10),
        "`\n",
    )
    return "".join(fields).encode("ascii")


def write_ar(path: Path, members: list[tuple[str, bytes]], mtime: int) -> None:
    with path.open("wb") as handle:
        handle.write(b"!<arch>\n")
        for name, data in members:
            handle.write(ar_header(name, len(data), mtime))
            handle.write(data)
            if len(data) % 2:
                handle.write(b"\n")


def write_deb(
    repo_root: Path,
    version: str,
    artifact_path: Path,
    binary_manifest: dict[str, Any],
    package_path: Path,
    reporter: Reporter,
) -> None:
    mtime = int(datetime.now(timezone.utc).timestamp())
    control_tar = build_control_tar(version, mtime)
    data_tar = build_data_tar(version, artifact_path, binary_manifest, repo_root, reporter, mtime)
    members = [
        ("debian-binary", b"2.0\n"),
        ("control.tar.gz", control_tar),
        ("data.tar.gz", data_tar),
    ]
    write_ar(package_path, members, mtime)


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


def tar_members_from_gzip(data: bytes) -> dict[str, bytes | None]:
    result: dict[str, bytes | None] = {}
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
                result[member.name] = source.read() if source else b""
            else:
                result[member.name] = None
    return result


def validate_service_unit(contents: bytes) -> None:
    text = contents.decode("utf-8")
    forbidden = ("sh -c", "/bin/sh", "bash", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload")
    found = [item for item in forbidden if item in text]
    if found:
        raise ValueError(f"Service unit contains unsafe directives or shell usage: {', '.join(found)}.")
    if "User=" in text or "Group=" in text:
        raise ValueError("Service unit must not reference an unprovisioned fixed service user or group.")
    exec_lines = [line for line in text.splitlines() if line.startswith("ExecStart=")]
    if exec_lines != [
        "ExecStart=/usr/bin/oaw-agent doctor --config /etc/openassetwatch/agent/config.json --identity-file /etc/openassetwatch/agent/identity.json"
    ]:
        raise ValueError("Service unit ExecStart must run only the oaw-agent binary.")
    required_lines = (
        "Type=oneshot",
        "ConditionPathExists=/etc/openassetwatch/agent/config.json",
        "ConditionPathExists=/etc/openassetwatch/agent/identity.json",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
    )
    for line in required_lines:
        if line not in text:
            raise ValueError(f"Service unit missing expected safe line: {line}")


def validate_maintainer_script(name: str, contents: bytes) -> None:
    expected = maintainer_script().decode("utf-8")
    text = contents.decode("utf-8")
    if text != expected:
        raise ValueError(f"{name} maintainer script must match the approved daemon-reload-only template.")
    forbidden = (
        " enable ",
        " start ",
        " restart ",
        " reload-or-restart ",
        " apt",
        " dpkg",
        " curl",
        " wget",
        " useradd",
        " adduser",
        "groupadd",
        "chown",
        "chmod",
        "cat >",
        "tee ",
    )
    found = [item for item in forbidden if item in text]
    if found:
        raise ValueError(f"{name} maintainer script contains unsafe command text: {', '.join(found)}.")


def validate_control_archive(control_members: dict[str, bytes | None]) -> None:
    if set(control_members) != set(EXPECTED_CONTROL_PATHS):
        raise ValueError("DEB control archive must contain only control, postinst, and postrm.")
    control = (control_members["./control"] or b"").decode("utf-8")
    for line in (f"Package: {PACKAGE_NAME}", "Architecture: amd64", "Depends: systemd"):
        if line not in control:
            raise ValueError(f"DEB control file missing expected line: {line}")
    validate_maintainer_script("postinst", control_members["./postinst"] or b"")
    validate_maintainer_script("postrm", control_members["./postrm"] or b"")


def validate_deb_contents(package_path: Path, reporter: Reporter) -> None:
    members = parse_ar(package_path)
    expected_members = {"debian-binary", "control.tar.gz", "data.tar.gz"}
    if set(members) != expected_members:
        raise ValueError("DEB archive must contain debian-binary, control.tar.gz, and data.tar.gz.")
    if members["debian-binary"] != b"2.0\n":
        raise ValueError("DEB debian-binary member must be 2.0.")
    control_members = tar_members_from_gzip(members["control.tar.gz"])
    validate_control_archive(control_members)
    data_members = tar_members_from_gzip(members["data.tar.gz"])
    missing = [path for path in EXPECTED_DATA_PATHS if path not in data_members]
    if missing:
        raise ValueError(f"DEB data archive missing expected paths: {', '.join(missing)}.")
    for name, contents in data_members.items():
        if name == "./usr/bin/oaw-agent":
            continue
        if name in {"./etc/openassetwatch/agent/config.example.json", "./etc/openassetwatch/agent/identity.example.json"}:
            continue
        if name == "./lib/systemd/system/oaw-agent.service":
            validate_service_unit(contents or b"")
            continue
        if FORBIDDEN_CONTENT_RE.search(PurePosixPath(name).name):
            raise ValueError(f"DEB data archive contains forbidden path: {name}")
        if contents and FORBIDDEN_CONTENT_RE.search(contents.decode("utf-8", errors="ignore")):
            raise ValueError(f"DEB data archive contains forbidden content: {name}")
    for path in EXPECTED_DATA_PATHS:
        reporter.add_content(path)


def write_package_metadata(
    repo_root: Path,
    version: str,
    package_path: Path,
    checksum_path: Path,
    manifest_path: Path,
    artifact_path: Path,
    checksum_source_path: Path,
    manifest_source_path: Path,
    binary_manifest: dict[str, Any],
    reporter: Reporter,
) -> None:
    package_hash = sha256_file(package_path).lower()
    checksum_path.write_text(f"{package_hash}  {package_path.name}\n", encoding="ascii")
    manifest = {
        "package_name": PACKAGE_NAME,
        "version": version,
        "os": TARGET_OS,
        "arch": TARGET_ARCH,
        "package_type": "deb",
        "source_artifact_path": to_repo_relative(repo_root, artifact_path),
        "source_checksum_path": to_repo_relative(repo_root, checksum_source_path),
        "source_manifest_path": to_repo_relative(repo_root, manifest_source_path),
        "package_path": to_repo_relative(repo_root, package_path),
        "sha256": package_hash,
        "build_timestamp": utc_timestamp(),
        "git_commit": binary_manifest["git_commit"],
        "contents": list(EXPECTED_DATA_PATHS),
        "directories": list(EXPECTED_DATA_DIRS),
        "control_members": list(EXPECTED_CONTROL_PATHS),
        "dependencies": ["systemd"],
        "package_builder": "scripts/release/package_agent_deb.py",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    missing = [field for field in REQUIRED_PACKAGE_FIELDS if not str(manifest.get(field, "")).strip()]
    if missing:
        raise ValueError(f"Package manifest missing fields: {', '.join(missing)}.")
    reporter.check("package manifest fields", True, "Package manifest fields are present.")


def validate_package_metadata(package_path: Path, checksum_path: Path, manifest_path: Path) -> None:
    if not package_path.is_file():
        raise ValueError("DEB package was not created.")
    if not checksum_path.is_file():
        raise ValueError("DEB package checksum was not created.")
    if not manifest_path.is_file():
        raise ValueError("DEB package manifest was not created.")
    manifest = read_json(manifest_path)
    missing = [field for field in REQUIRED_PACKAGE_FIELDS if not str(manifest.get(field, "")).strip()]
    if missing:
        raise ValueError(f"Package manifest missing fields: {', '.join(missing)}.")
    actual_hash = sha256_file(package_path).lower()
    checksum_text = checksum_path.read_text(encoding="ascii").strip()
    checksum_hash = checksum_text.split()[0].lower() if checksum_text else ""
    if str(manifest["sha256"]).lower() != actual_hash:
        raise ValueError("DEB package SHA256 does not match package manifest.")
    if checksum_hash != actual_hash:
        raise ValueError("DEB package SHA256 does not match checksum file.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a local Debian package artifact for oaw-agent.")
    parser.add_argument("--version", required=True, help="Linux agent release version under dist/agent/<version>/linux-amd64/.")
    return parser.parse_args()


def build_summary(
    reporter: Reporter,
    repo_root: Path,
    package_path: Path | None,
    checksum_path: Path | None,
    manifest_path: Path | None,
) -> dict[str, Any]:
    return {
        "ok": not reporter.errors,
        "package": to_repo_relative(repo_root, package_path) if package_path else "",
        "checksum": to_repo_relative(repo_root, checksum_path) if checksum_path else "",
        "manifest": to_repo_relative(repo_root, manifest_path) if manifest_path else "",
        "contents": sorted(set(reporter.contents)),
        "checks": reporter.checks,
        "warnings": reporter.warnings,
        "errors": reporter.errors,
    }


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    repo_root = get_repo_root()
    package_path: Path | None = None
    checksum_path: Path | None = None
    manifest_path: Path | None = None

    try:
        version = validate_version(args.version)
        artifact_path, source_checksum_path, source_manifest_path, binary_manifest = validate_binary_artifact(
            repo_root, version
        )
        reporter.check("linux artifact validation", True, "Linux amd64 agent artifact validation passed.")

        package_path, checksum_path, manifest_path = package_paths(repo_root, version)
        write_deb(repo_root, version, artifact_path, binary_manifest, package_path, reporter)
        reporter.check("deb package", True, "DEB package artifact was created under ignored dist output.")

        write_package_metadata(
            repo_root,
            version,
            package_path,
            checksum_path,
            manifest_path,
            artifact_path,
            source_checksum_path,
            source_manifest_path,
            binary_manifest,
            reporter,
        )
        validate_package_metadata(package_path, checksum_path, manifest_path)
        reporter.check("deb package metadata", True, "DEB checksum and manifest validation passed.")

        validate_deb_contents(package_path, reporter)
        reporter.check("deb package contents", True, "DEB package contains expected safe Linux paths.")
    except Exception as exc:
        reporter.check("deb package helper", False, str(exc))

    summary = build_summary(reporter, repo_root, package_path, checksum_path, manifest_path)
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
