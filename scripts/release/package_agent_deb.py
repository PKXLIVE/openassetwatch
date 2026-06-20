#!/usr/bin/env python3
"""Build a Debian package artifact for the OpenAssetWatch agent."""

from __future__ import annotations

import argparse
import gzip
import io
import json
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

import linux_packaging as linuxsrc
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


PACKAGE_NAME = linuxsrc.PACKAGE_NAME
TARGET_OS = linuxsrc.TARGET_OS
TARGET_ARCH = linuxsrc.TARGET_ARCH
DEBIAN_ARCH = linuxsrc.DEBIAN_ARCH
SERVICE_USER = linuxsrc.SERVICE_USER
SERVICE_GROUP = linuxsrc.SERVICE_GROUP
OPT_BINARY = linuxsrc.OPT_BINARY
OPT_BINARY_PACKAGE_PATH = linuxsrc.OPT_BINARY_PACKAGE_PATH
USR_BIN_PACKAGE_PATH = linuxsrc.USR_BIN_PACKAGE_PATH
USR_BIN_LINK_TARGET = linuxsrc.USR_BIN_LINK_TARGET
IP_NEIGH_HELPER = linuxsrc.IP_NEIGH_HELPER
IP_ADDR_HELPER = linuxsrc.IP_ADDR_HELPER
IP_NEIGH_HELPER_PACKAGE_PATH = linuxsrc.IP_NEIGH_HELPER_PACKAGE_PATH
IP_ADDR_HELPER_PACKAGE_PATH = linuxsrc.IP_ADDR_HELPER_PACKAGE_PATH
SERVICE_COMMAND = linuxsrc.SERVICE_COMMAND
TIMER_PACKAGE_PATH = "./lib/systemd/system/oaw-agent.timer"
TIMER_INSTALL_PATH = linuxsrc.TIMER_INSTALL_PATH
PACKAGE_DEPENDENCIES = linuxsrc.PACKAGE_DEPENDENCIES_DEB
SUDOERS_PACKAGE_PATH = linuxsrc.SUDOERS_PACKAGE_PATH
SUDOERS_INSTALL_PATH = linuxsrc.SUDOERS_INSTALL_PATH
APPROVED_SUDOERS_COMMANDS = linuxsrc.APPROVED_SUDOERS_COMMANDS
PRIVILEGED_HELPERS = linuxsrc.PRIVILEGED_HELPERS
SERVICE_OWNED_DIRS = linuxsrc.SERVICE_OWNED_DIRS
ROOT_OWNED_DIRS = linuxsrc.ROOT_OWNED_DIRS + (
    "./lib/systemd/system/oaw-agent.service",
    TIMER_PACKAGE_PATH,
)
EXPECTED_DATA_FILES = (
    OPT_BINARY_PACKAGE_PATH,
    IP_NEIGH_HELPER_PACKAGE_PATH,
    IP_ADDR_HELPER_PACKAGE_PATH,
    "./etc/openassetwatch/agent/config.example.json",
    "./etc/openassetwatch/agent/identity.example.json",
    SUDOERS_PACKAGE_PATH,
    "./lib/systemd/system/oaw-agent.service",
    TIMER_PACKAGE_PATH,
    "./usr/share/doc/openassetwatch-agent/README.md",
    "./usr/share/doc/openassetwatch-agent/release-manifest.json",
)
EXPECTED_DATA_SYMLINKS = {
    USR_BIN_PACKAGE_PATH: USR_BIN_LINK_TARGET,
}
EXPECTED_DATA_PATHS = EXPECTED_DATA_FILES + tuple(EXPECTED_DATA_SYMLINKS)
EXPECTED_DATA_DIRS = (
    "./opt",
    "./opt/openassetwatch",
    "./opt/openassetwatch/agent",
    "./opt/openassetwatch/agent/bin",
    "./usr",
    "./usr/bin",
    "./usr/lib",
    "./usr/lib/openassetwatch",
    "./usr/lib/openassetwatch/agent",
    "./usr/lib/openassetwatch/agent/libexec",
    "./usr/share",
    "./usr/share/doc",
    "./usr/share/doc/openassetwatch-agent",
    "./etc",
    "./etc/openassetwatch",
    "./etc/openassetwatch/agent",
    "./etc/sudoers.d",
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
    "./conffiles",
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
FORBIDDEN_CONTENT_RE = linuxsrc.FORBIDDEN_CONTENT_RE


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


def validate_binary_artifact(
    repo_root: Path,
    version: str,
) -> tuple[Path, Path, Path, dict[str, Any]]:
    return linuxsrc.validate_linux_binary_artifact(repo_root, version)


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
    return linuxsrc.deb_control_file(version)


def postinst_script() -> bytes:
    return linuxsrc.deb_postinst_script()


def postrm_script() -> bytes:
    return linuxsrc.deb_postrm_script()


def conffiles_file() -> bytes:
    return linuxsrc.deb_conffiles()


def config_example() -> bytes:
    return linuxsrc.config_example()


def identity_example() -> bytes:
    return linuxsrc.identity_example()


def ip_neigh_helper_script() -> bytes:
    return linuxsrc.ip_neigh_helper_script()


def ip_addr_helper_script() -> bytes:
    return linuxsrc.ip_addr_helper_script()


def sudoers_file() -> bytes:
    return linuxsrc.sudoers_file()


def service_unit() -> bytes:
    return linuxsrc.deb_service_unit()


def timer_unit() -> bytes:
    return linuxsrc.deb_timer_unit()


def package_readme(version: str) -> bytes:
    return linuxsrc.package_readme(version)


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
        "package_type": "deb",
        "binary": {
            "path": OPT_BINARY,
            "compatibility_symlink": "/usr/bin/oaw-agent",
            "source_artifact": to_repo_relative(repo_root, artifact_path),
            "sha256": binary_manifest["sha256"],
            "git_commit": binary_manifest["git_commit"],
        },
        "installed_paths": list(EXPECTED_DATA_PATHS),
        "service": {
            "path": "/lib/systemd/system/oaw-agent.service",
            "model": "oneshot-run-once",
            "command": SERVICE_COMMAND,
            "user": SERVICE_USER,
            "group": SERVICE_GROUP,
            "enabled_by_package_build": False,
            "started_by_package_build": False,
            "enabled_by_package_install": False,
            "started_by_package_install": False,
            "config_required_for_start": "/etc/openassetwatch/agent/config.json",
            "identity_required_for_start": "/etc/openassetwatch/agent/identity.json",
        },
        "timer": {
            "path": TIMER_INSTALL_PATH,
            "unit": "oaw-agent.service",
            "on_boot": "5min",
            "period": "1h",
            "randomized_delay": "10min",
            "persistent": True,
            "enabled_by_package_build": False,
            "started_by_package_build": False,
            "enabled_by_package_install": True,
            "started_by_package_install": "only_when_config_and_identity_exist",
            "config_required_for_start": "/etc/openassetwatch/agent/config.json",
            "identity_required_for_start": "/etc/openassetwatch/agent/identity.json",
        },
        "directories": list(EXPECTED_DATA_DIRS),
        "ownership": {
            "openassetwatch:openassetwatch": list(SERVICE_OWNED_DIRS),
            "root:root": list(ROOT_OWNED_DIRS),
        },
        "privileged_helpers": [
            {
                "path": install_path,
                "package_path": package_path,
                "runs": command,
                "owner": "root:root",
                "mode": "0755",
                "accepts_arguments": False,
            }
            for package_path, install_path, command in PRIVILEGED_HELPERS
        ],
        "sudoers": {
            "path": SUDOERS_INSTALL_PATH,
            "mode": "0440",
            "user": SERVICE_USER,
            "commands": list(APPROVED_SUDOERS_COMMANDS),
        },
        "dependencies": list(PACKAGE_DEPENDENCIES),
        "maintainer_scripts": ["postinst", "postrm"],
        "build_timestamp": utc_timestamp(),
    }
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def tarinfo_for(
    path: str,
    data: bytes | None,
    mode: int,
    mtime: int,
    owner: str = "root",
    group: str = "root",
) -> tarfile.TarInfo:
    info = tarfile.TarInfo(path)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = owner
    info.gname = group
    info.mtime = mtime
    if data is None:
        info.type = tarfile.DIRTYPE
        info.size = 0
    else:
        info.size = len(data)
    return info


def owner_for_data_path(path: str) -> tuple[str, str]:
    if path in SERVICE_OWNED_DIRS:
        return SERVICE_USER, SERVICE_GROUP
    return "root", "root"


def add_dir(tar: tarfile.TarFile, path: str, mtime: int) -> None:
    owner, group = owner_for_data_path(path)
    tar.addfile(tarinfo_for(path, None, 0o755, mtime, owner, group))


def add_file(tar: tarfile.TarFile, path: str, data: bytes, mode: int, mtime: int) -> None:
    owner, group = owner_for_data_path(path)
    tar.addfile(tarinfo_for(path, data, mode, mtime, owner, group), io.BytesIO(data))


def add_symlink(tar: tarfile.TarFile, path: str, target: str, mtime: int) -> None:
    info = tarinfo_for(path, b"", 0o777, mtime)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    info.size = 0
    tar.addfile(info)


def build_control_tar(version: str, mtime: int) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.GNU_FORMAT) as tar:
        add_file(tar, "./control", control_file(version), 0o644, mtime)
        add_file(tar, "./conffiles", conffiles_file(), 0o644, mtime)
        add_file(tar, "./postinst", postinst_script(), 0o755, mtime)
        add_file(tar, "./postrm", postrm_script(), 0o755, mtime)
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
        OPT_BINARY_PACKAGE_PATH: (binary_data, 0o755),
        IP_NEIGH_HELPER_PACKAGE_PATH: (ip_neigh_helper_script(), 0o755),
        IP_ADDR_HELPER_PACKAGE_PATH: (ip_addr_helper_script(), 0o755),
        "./etc/openassetwatch/agent/config.example.json": (config_example(), 0o644),
        "./etc/openassetwatch/agent/identity.example.json": (identity_example(), 0o644),
        SUDOERS_PACKAGE_PATH: (sudoers_file(), 0o440),
        "./lib/systemd/system/oaw-agent.service": (service_unit(), 0o644),
        TIMER_PACKAGE_PATH: (timer_unit(), 0o644),
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
        for path, target in EXPECTED_DATA_SYMLINKS.items():
            add_symlink(tar, path, target, mtime)
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


def tar_members_from_gzip(
    data: bytes,
) -> tuple[dict[str, bytes], set[str], dict[str, str], dict[str, tuple[str, str]], dict[str, int]]:
    files: dict[str, bytes] = {}
    directories: set[str] = set()
    symlinks: dict[str, str] = {}
    ownership: dict[str, tuple[str, str]] = {}
    modes: dict[str, int] = {}
    with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as gz:
        tar_bytes = gz.read()
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as tar:
        for member in tar.getmembers():
            pure = PurePosixPath(member.name)
            if member.name.startswith("/") or "\\" in member.name or ".." in pure.parts:
                raise ValueError(f"Package archive contains unsafe path: {member.name}")
            if not (member.isdir() or member.isfile() or member.issym()):
                raise ValueError(f"Package archive contains unsupported entry type: {member.name}")
            ownership[member.name] = (member.uname or "root", member.gname or "root")
            modes[member.name] = member.mode & 0o7777
            if member.isfile():
                source = tar.extractfile(member)
                files[member.name] = source.read() if source else b""
            elif member.isdir():
                directories.add(member.name)
            else:
                symlinks[member.name] = member.linkname
    return files, directories, symlinks, ownership, modes


def validate_service_unit(contents: bytes) -> None:
    text = contents.decode("utf-8")
    forbidden = ("sh -c", "/bin/sh", "bash", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecReload")
    found = [item for item in forbidden if item in text]
    if found:
        raise ValueError(f"Service unit contains unsafe directives or shell usage: {', '.join(found)}.")
    exec_lines = [line for line in text.splitlines() if line.startswith("ExecStart=")]
    if exec_lines != [f"ExecStart={SERVICE_COMMAND}"]:
        raise ValueError("Service unit ExecStart must run only the packaged oaw-agent run-once command.")
    required_lines = (
        "Type=oneshot",
        f"User={SERVICE_USER}",
        f"Group={SERVICE_GROUP}",
        "ConditionPathExists=/etc/openassetwatch/agent/config.json",
        "ConditionPathExists=/etc/openassetwatch/agent/identity.json",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ReadWritePaths=/var/lib/openassetwatch/agent",
    )
    for line in required_lines:
        if line not in text:
            raise ValueError(f"Service unit missing expected safe line: {line}")


def validate_timer_unit(contents: bytes) -> None:
    text = contents.decode("utf-8")
    forbidden = ("sh -c", "/bin/sh", "bash", "ExecStart", "ExecStop", "ExecReload")
    found = [item for item in forbidden if item in text]
    if found:
        raise ValueError(f"Timer unit contains unsafe directives or shell usage: {', '.join(found)}.")
    required_lines = (
        "OnBootSec=5min",
        "OnUnitActiveSec=1h",
        "RandomizedDelaySec=10min",
        "Persistent=true",
        "Unit=oaw-agent.service",
        "WantedBy=timers.target",
    )
    for line in required_lines:
        if line not in text:
            raise ValueError(f"Timer unit missing expected safe line: {line}")


def validate_maintainer_script(name: str, contents: bytes) -> None:
    expected = postinst_script().decode("utf-8") if name == "postinst" else postrm_script().decode("utf-8")
    text = contents.decode("utf-8")
    if text != expected:
        raise ValueError(f"{name} maintainer script must match the approved service-account template.")
    forbidden = (
        " reload-or-restart ",
        " apt",
        " dpkg",
        " curl",
        " wget",
        "chmod",
        "cat >",
        "tee ",
        "sudo",
        "sudoers",
    )
    found = [item for item in forbidden if item in text]
    if found:
        raise ValueError(f"{name} maintainer script contains unsafe command text: {', '.join(found)}.")
    if name == "postinst":
        guarded_restart = (
            "    if [ -f /etc/openassetwatch/agent/config.json ] "
            "&& [ -f /etc/openassetwatch/agent/identity.json ]; then\n"
            "        systemctl restart oaw-agent.timer || true\n"
            "    fi"
        )
        required = (
            f"groupadd --system {SERVICE_GROUP}",
            f"useradd --system --gid {SERVICE_GROUP}",
            "--shell /usr/sbin/nologin",
            f"chown -R {SERVICE_USER}:{SERVICE_GROUP} /var/lib/openassetwatch/agent",
            f"chown -R {SERVICE_USER}:{SERVICE_GROUP} /var/log/openassetwatch/agent",
            "systemctl daemon-reload || true",
            "systemctl enable oaw-agent.timer || true",
            guarded_restart,
        )
        for item in required:
            if item not in text:
                raise ValueError(f"postinst missing expected service account command text: {item}")
        if "systemctl start oaw-agent.service" in text:
            raise ValueError("postinst must not start the service unconditionally.")
        if "systemctl restart oaw-agent.service" in text:
            raise ValueError("postinst must not restart the service directly.")
        if "systemctl enable oaw-agent.service" in text:
            raise ValueError("postinst must enable the timer instead of the service.")
        if text.count("systemctl restart oaw-agent.timer || true") != 1:
            raise ValueError("postinst must contain exactly one guarded timer restart.")
    elif name == "postrm":
        if any(item in text for item in ("useradd", "groupadd", "chown")):
            raise ValueError("postrm must not create users, groups, or change ownership.")
        if any(item in text for item in ("enable", "start", "restart", "stop")):
            raise ValueError("postrm must not enable, start, restart, or stop services.")


def validate_sudoers_file(contents: bytes) -> None:
    text = contents.decode("utf-8")
    rule_lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    rule_text = "\n".join(rule_lines)
    forbidden = (
        "NOPASSWD: ALL",
        "ALL=(ALL) ALL",
        "ALL=(ALL:ALL)",
        "/bin/sh",
        "/bin/bash",
        " bash",
        " sh ",
        "python",
        "curl",
        "wget",
        " nc",
        "nmap",
        "tcpdump",
        "apt",
        "dpkg",
        "systemctl",
        "service",
        "chmod",
        "chown",
        "rm ",
        "cp ",
        "mv ",
        "*",
        "?",
    )
    found = [item for item in forbidden if item in rule_text]
    if found:
        raise ValueError(f"sudoers file contains unsafe allowlist text: {', '.join(found)}.")

    if "/usr/sbin/ip neigh show" in rule_text or "/usr/sbin/ip addr show" in rule_text:
        raise ValueError("sudoers file must not directly allow raw /usr/sbin/ip commands.")

    expected_lines = [f'{SERVICE_USER} ALL=(root) NOPASSWD: {command} ""' for command in APPROVED_SUDOERS_COMMANDS]
    if rule_lines != expected_lines:
        raise ValueError("sudoers file must contain only the approved openassetwatch command allowlist.")

    for line in rule_lines:
        if not line.startswith(f"{SERVICE_USER} ALL=(root) NOPASSWD: "):
            raise ValueError("sudoers file must apply only to the openassetwatch service user.")


def validate_helper_script(path: str, contents: bytes) -> None:
    expected = {
        IP_NEIGH_HELPER_PACKAGE_PATH: ip_neigh_helper_script(),
        IP_ADDR_HELPER_PACKAGE_PATH: ip_addr_helper_script(),
    }.get(path)
    if expected is None:
        raise ValueError(f"Unknown privileged helper path: {path}")
    if contents != expected:
        raise ValueError(f"Privileged helper {path} must match the approved no-argument wrapper.")


def validate_control_archive(control_members: dict[str, bytes | None]) -> None:
    if set(control_members) != set(EXPECTED_CONTROL_PATHS):
        raise ValueError("DEB control archive must contain only control, conffiles, postinst, and postrm.")
    control = (control_members["./control"] or b"").decode("utf-8")
    for line in (f"Package: {PACKAGE_NAME}", "Architecture: amd64", f"Depends: {', '.join(PACKAGE_DEPENDENCIES)}"):
        if line not in control:
            raise ValueError(f"DEB control file missing expected line: {line}")
    if control_members["./conffiles"] != conffiles_file():
        raise ValueError("DEB conffiles metadata must match the committed package source.")
    validate_maintainer_script("postinst", control_members["./postinst"] or b"")
    validate_maintainer_script("postrm", control_members["./postrm"] or b"")


def validate_deb_contents(package_path: Path, reporter: Reporter) -> None:
    members = parse_ar(package_path)
    expected_members = {"debian-binary", "control.tar.gz", "data.tar.gz"}
    if set(members) != expected_members:
        raise ValueError("DEB archive must contain debian-binary, control.tar.gz, and data.tar.gz.")
    if members["debian-binary"] != b"2.0\n":
        raise ValueError("DEB debian-binary member must be 2.0.")
    control_files, control_dirs, control_symlinks, _control_ownership, _control_modes = tar_members_from_gzip(members["control.tar.gz"])
    if control_dirs or control_symlinks:
        raise ValueError("DEB control archive must not contain directories or symlinks.")
    validate_control_archive(control_files)
    data_files, data_dirs, data_symlinks, ownership, modes = tar_members_from_gzip(members["data.tar.gz"])
    missing_files = [path for path in EXPECTED_DATA_FILES if path not in data_files]
    missing_links = [path for path in EXPECTED_DATA_SYMLINKS if data_symlinks.get(path) != EXPECTED_DATA_SYMLINKS[path]]
    missing_dirs = [path for path in EXPECTED_DATA_DIRS if path not in data_dirs]
    missing = missing_files + missing_links + missing_dirs
    if missing:
        raise ValueError(f"DEB data archive missing expected paths: {', '.join(missing)}.")
    unexpected_files = set(data_files) - set(EXPECTED_DATA_FILES)
    unexpected_links = set(data_symlinks) - set(EXPECTED_DATA_SYMLINKS)
    unexpected_dirs = set(data_dirs) - set(EXPECTED_DATA_DIRS)
    if unexpected_files or unexpected_links or unexpected_dirs:
        raise ValueError("DEB data archive contains unexpected package entries.")
    for name, contents in data_files.items():
        if name == OPT_BINARY_PACKAGE_PATH:
            continue
        if name in {IP_NEIGH_HELPER_PACKAGE_PATH, IP_ADDR_HELPER_PACKAGE_PATH}:
            validate_helper_script(name, contents or b"")
            continue
        if name in {"./etc/openassetwatch/agent/config.example.json", "./etc/openassetwatch/agent/identity.example.json"}:
            continue
        if name == SUDOERS_PACKAGE_PATH:
            validate_sudoers_file(contents or b"")
            continue
        if name == "./lib/systemd/system/oaw-agent.service":
            validate_service_unit(contents or b"")
            continue
        if name == TIMER_PACKAGE_PATH:
            validate_timer_unit(contents or b"")
            continue
        if FORBIDDEN_CONTENT_RE.search(PurePosixPath(name).name):
            raise ValueError(f"DEB data archive contains forbidden path: {name}")
        if contents and FORBIDDEN_CONTENT_RE.search(contents.decode("utf-8", errors="ignore")):
            raise ValueError(f"DEB data archive contains forbidden content: {name}")
    for path in SERVICE_OWNED_DIRS:
        if ownership.get(path) != (SERVICE_USER, SERVICE_GROUP):
            raise ValueError(f"DEB data archive ownership for {path} must be {SERVICE_USER}:{SERVICE_GROUP}.")
    for path in ROOT_OWNED_DIRS:
        if ownership.get(path) != ("root", "root"):
            raise ValueError(f"DEB data archive ownership for {path} must be root:root.")
    for path in (IP_NEIGH_HELPER_PACKAGE_PATH, IP_ADDR_HELPER_PACKAGE_PATH):
        if modes.get(path) & 0o022:
            raise ValueError(f"Privileged helper {path} must not be writable by group or others.")
    if ownership.get("./etc/openassetwatch/agent") != ("root", "root"):
        raise ValueError("Config directory must remain root-controlled.")
    if ownership.get(SUDOERS_PACKAGE_PATH) != ("root", "root"):
        raise ValueError("sudoers file must be owned by root:root in package metadata.")
    if modes.get(SUDOERS_PACKAGE_PATH) != 0o440:
        raise ValueError("sudoers file must use mode 0440 in package metadata.")
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
        "symlinks": dict(EXPECTED_DATA_SYMLINKS),
        "service": {
            "path": "/lib/systemd/system/oaw-agent.service",
            "model": "oneshot-run-once",
            "command": SERVICE_COMMAND,
            "user": SERVICE_USER,
            "group": SERVICE_GROUP,
            "enabled_by_package_build": False,
            "started_by_package_build": False,
            "enabled_by_package_install": False,
            "started_by_package_install": False,
            "config_required_for_start": "/etc/openassetwatch/agent/config.json",
            "identity_required_for_start": "/etc/openassetwatch/agent/identity.json",
        },
        "timer": {
            "path": TIMER_INSTALL_PATH,
            "unit": "oaw-agent.service",
            "on_boot": "5min",
            "period": "1h",
            "randomized_delay": "10min",
            "persistent": True,
            "enabled_by_package_build": False,
            "started_by_package_build": False,
            "enabled_by_package_install": True,
            "started_by_package_install": "only_when_config_and_identity_exist",
            "config_required_for_start": "/etc/openassetwatch/agent/config.json",
            "identity_required_for_start": "/etc/openassetwatch/agent/identity.json",
        },
        "privileged_helpers": [
            {
                "path": install_path,
                "package_path": package_path,
                "runs": command,
                "owner": "root:root",
                "mode": "0755",
                "accepts_arguments": False,
            }
            for package_path, install_path, command in PRIVILEGED_HELPERS
        ],
        "sudoers": {
            "path": SUDOERS_INSTALL_PATH,
            "mode": "0440",
            "user": SERVICE_USER,
            "commands": list(APPROVED_SUDOERS_COMMANDS),
        },
        "control_members": list(EXPECTED_CONTROL_PATHS),
        "dependencies": list(PACKAGE_DEPENDENCIES),
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
