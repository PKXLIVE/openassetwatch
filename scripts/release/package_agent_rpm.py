#!/usr/bin/env python3
"""Build an RPM package artifact for the OpenAssetWatch agent."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from linux_packaging import (
    APPROVED_SUDOERS_COMMANDS,
    FORBIDDEN_CONTENT_RE,
    IP_ADDR_HELPER,
    IP_ADDR_HELPER_PACKAGE_PATH,
    IP_NEIGH_HELPER,
    IP_NEIGH_HELPER_PACKAGE_PATH,
    OPT_BINARY,
    OPT_BINARY_PACKAGE_PATH,
    PACKAGE_NAME,
    PACKAGE_DEPENDENCIES_RPM,
    PRIVILEGED_HELPERS,
    RPM_ARCH,
    RPM_RELEASE,
    ROOT_OWNED_DIRS,
    SERVICE_COMMAND,
    SERVICE_GROUP,
    SERVICE_OWNED_DIRS,
    SERVICE_USER,
    SUDOERS_INSTALL_PATH,
    TARGET_ARCH,
    TARGET_OS,
    USR_BIN_PACKAGE_PATH,
    config_example,
    identity_example,
    ip_addr_helper_script,
    ip_neigh_helper_script,
    package_readme,
    rpm_service_unit,
    rpm_spec_file,
    rpm_timer_unit,
    sudoers_file,
    validate_linux_binary_artifact,
)
from release_common import (
    get_repo_root,
    is_inside,
    read_json,
    sha256_file,
    to_repo_relative,
    utc_timestamp,
    validate_version,
)
from validate_agent_deb import (
    validate_example_config,
    validate_example_identity,
    validate_helper_script,
    validate_service_unit,
    validate_sudoers_file,
    validate_timer_unit,
)


RPM_ROOT_DIRS = ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS")
RPM_SYSTEMD_DIR = "/usr/lib/systemd/system"
RPM_SERVICE_PACKAGE_PATH = "./usr/lib/systemd/system/oaw-agent.service"
RPM_TIMER_PACKAGE_PATH = "./usr/lib/systemd/system/oaw-agent.timer"
RPM_TIMER_INSTALL_PATH = "/usr/lib/systemd/system/oaw-agent.timer"
PACKAGE_DEPENDENCIES = PACKAGE_DEPENDENCIES_RPM
SUDOERS_PACKAGE_PATH = "./etc/sudoers.d/openassetwatch-agent"

RPM_EXPECTED_FILES = (
    OPT_BINARY_PACKAGE_PATH,
    "./usr/bin/oaw-agent",
    IP_NEIGH_HELPER_PACKAGE_PATH,
    IP_ADDR_HELPER_PACKAGE_PATH,
    "./etc/openassetwatch/agent/config.example.json",
    "./etc/openassetwatch/agent/identity.example.json",
    SUDOERS_PACKAGE_PATH,
    RPM_SERVICE_PACKAGE_PATH,
    RPM_TIMER_PACKAGE_PATH,
    "./usr/share/doc/openassetwatch-agent/README.md",
    "./usr/share/doc/openassetwatch-agent/release-manifest.json",
)

RPM_EXPECTED_DIRS = (
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
    "./usr/lib/systemd",
    "./usr/lib/systemd/system",
    "./usr/share",
    "./usr/share/doc",
    "./usr/share/doc/openassetwatch-agent",
    "./etc",
    "./etc/openassetwatch",
    "./etc/openassetwatch/agent",
    "./etc/sudoers.d",
    "./var",
    "./var/lib",
    "./var/lib/openassetwatch",
    "./var/lib/openassetwatch/agent",
    "./var/log",
    "./var/log/openassetwatch",
    "./var/log/openassetwatch/agent",
)

ROOT_OWNED_PATHS = ROOT_OWNED_DIRS + (RPM_SERVICE_PACKAGE_PATH, RPM_TIMER_PACKAGE_PATH)

RPM_REQUIRED_MANIFEST_FIELDS = (
    "package_name",
    "version",
    "os",
    "arch",
    "package_type",
    "rpm_root",
    "spec_path",
    "buildroot",
    "build_timestamp",
    "git_commit",
    "contents",
)
RPM_PACKAGE_REQUIRED_FIELDS = (
    "package_name",
    "version",
    "os",
    "arch",
    "rpm_arch",
    "package_type",
    "package_path",
    "sha256",
    "build_timestamp",
    "git_commit",
    "contents",
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


def rpm_version(version: str) -> str:
    """Return an RPM-safe Version value while preserving source version elsewhere."""
    return version.replace("-", "_")


def rpm_paths(repo_root: Path, version: str) -> tuple[Path, Path, Path, Path]:
    rpm_root = repo_root / "dist" / "agent" / version / "rpm"
    if not is_inside(repo_root / "dist" / "agent", rpm_root):
        raise ValueError("RPM staging output must stay under dist/agent/.")
    buildroot = rpm_root / "BUILDROOT" / f"{PACKAGE_NAME}-{version}-{RPM_RELEASE}.{RPM_ARCH}"
    spec_path = rpm_root / "SPECS" / f"{PACKAGE_NAME}.spec"
    manifest_path = rpm_root / f"{PACKAGE_NAME}-{version}-{RPM_RELEASE}.{RPM_ARCH}.manifest.json"
    return rpm_root, buildroot, spec_path, manifest_path


def rpm_package_paths(repo_root: Path, version: str) -> tuple[Path, Path, Path]:
    package_dir = repo_root / "dist" / "agent" / version / "packages"
    if not is_inside(repo_root / "dist" / "agent", package_dir):
        raise ValueError("RPM package output must stay under dist/agent/.")
    package_dir.mkdir(parents=True, exist_ok=True)
    package_path = package_dir / f"{PACKAGE_NAME}-{rpm_version(version)}-{RPM_RELEASE}.{RPM_ARCH}.rpm"
    checksum_path = Path(str(package_path) + ".sha256")
    manifest_path = Path(str(package_path) + ".manifest.json")
    return package_path, checksum_path, manifest_path


def clean_rpm_root(repo_root: Path, rpm_root: Path) -> None:
    if not is_inside(repo_root / "dist" / "agent", rpm_root):
        raise ValueError("Refusing to clean an RPM staging path outside dist/agent/.")
    if rpm_root.exists():
        def remove_readonly(func: Any, path: str, _exc_info: Any) -> None:
            os.chmod(path, stat.S_IWRITE)
            func(path)

        shutil.rmtree(rpm_root, onerror=remove_readonly)


def ensure_rpm_tree(rpm_root: Path) -> None:
    for name in RPM_ROOT_DIRS:
        (rpm_root / name).mkdir(parents=True, exist_ok=True)


def payload_path(buildroot: Path, package_path: str) -> Path:
    pure = PurePosixPath(package_path)
    if package_path.startswith("/") or "\\" in package_path or ".." in pure.parts:
        raise ValueError(f"Unsafe package path: {package_path}")
    trimmed = package_path[2:] if package_path.startswith("./") else package_path
    return buildroot / Path(trimmed)


def install_path(package_path: str) -> str:
    trimmed = package_path[2:] if package_path.startswith("./") else package_path
    return f"/{trimmed}"


def write_file(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    os.chmod(path, mode)


def write_text_file(path: Path, text: str, mode: int = 0o644) -> None:
    write_file(path, text.encode("utf-8"), mode)


def compatibility_wrapper() -> bytes:
    return "\n".join(
        [
            "#!/bin/sh",
            "exec /opt/openassetwatch/agent/bin/oaw-agent \"$@\"",
            "",
        ]
    ).encode("utf-8")


def release_manifest(
    repo_root: Path,
    version: str,
    binary_manifest: dict[str, Any],
    artifact_path: Path,
    rpm_root: Path,
    spec_path: Path,
    buildroot: Path,
) -> bytes:
    value = {
        "package_name": PACKAGE_NAME,
        "version": version,
        "os": TARGET_OS,
        "arch": TARGET_ARCH,
        "package_type": "rpm",
        "binary": {
            "path": OPT_BINARY,
            "compatibility_wrapper": "/usr/bin/oaw-agent",
            "source_artifact": to_repo_relative(repo_root, artifact_path),
            "sha256": binary_manifest["sha256"],
            "git_commit": binary_manifest["git_commit"],
        },
        "rpm_root": to_repo_relative(repo_root, rpm_root),
        "spec_path": to_repo_relative(repo_root, spec_path),
        "buildroot": to_repo_relative(repo_root, buildroot),
        "installed_paths": [install_path(path) for path in RPM_EXPECTED_FILES],
        "directories": [install_path(path) for path in RPM_EXPECTED_DIRS],
        "service": {
            "path": f"{RPM_SYSTEMD_DIR}/oaw-agent.service",
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
            "path": RPM_TIMER_INSTALL_PATH,
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
        "ownership": {
            "openassetwatch:openassetwatch": [install_path(path) for path in SERVICE_OWNED_DIRS],
            "root:root": [install_path(path) for path in ROOT_OWNED_PATHS],
        },
        "privileged_helpers": [
            {
                "path": helper_install_path,
                "package_path": install_path(helper_package_path),
                "runs": command,
                "owner": "root:root",
                "mode": "0755",
                "accepts_arguments": False,
            }
            for helper_package_path, helper_install_path, command in PRIVILEGED_HELPERS
        ],
        "sudoers": {
            "path": SUDOERS_INSTALL_PATH,
            "mode": "0440",
            "user": SERVICE_USER,
            "commands": list(APPROVED_SUDOERS_COMMANDS),
        },
        "dependencies": list(PACKAGE_DEPENDENCIES),
        "spec": {
            "name": PACKAGE_NAME,
            "version": rpm_version(version),
            "source_version": version,
            "release": RPM_RELEASE,
            "arch": RPM_ARCH,
        },
        "build_timestamp": utc_timestamp(),
    }
    return (json.dumps(value, indent=2) + "\n").encode("utf-8")


def spec_file(version: str) -> bytes:
    return rpm_spec_file(version)


def stage_payload(
    repo_root: Path,
    version: str,
    artifact_path: Path,
    binary_manifest: dict[str, Any],
    rpm_root: Path,
    spec_path: Path,
    buildroot: Path,
) -> None:
    release_manifest_data = release_manifest(
        repo_root,
        version,
        binary_manifest,
        artifact_path,
        rpm_root,
        spec_path,
        buildroot,
    )
    files: dict[str, tuple[bytes, int]] = {
        OPT_BINARY_PACKAGE_PATH: (artifact_path.read_bytes(), 0o755),
        "./usr/bin/oaw-agent": (compatibility_wrapper(), 0o755),
        IP_NEIGH_HELPER_PACKAGE_PATH: (ip_neigh_helper_script(), 0o755),
        IP_ADDR_HELPER_PACKAGE_PATH: (ip_addr_helper_script(), 0o755),
        "./etc/openassetwatch/agent/config.example.json": (config_example(), 0o644),
        "./etc/openassetwatch/agent/identity.example.json": (identity_example(), 0o644),
        SUDOERS_PACKAGE_PATH: (sudoers_file(), 0o440),
        RPM_SERVICE_PACKAGE_PATH: (rpm_service_unit(), 0o644),
        RPM_TIMER_PACKAGE_PATH: (rpm_timer_unit(), 0o644),
        "./usr/share/doc/openassetwatch-agent/README.md": (package_readme(version), 0o644),
        "./usr/share/doc/openassetwatch-agent/release-manifest.json": (release_manifest_data, 0o644),
    }
    for directory in RPM_EXPECTED_DIRS:
        payload_path(buildroot, directory).mkdir(parents=True, exist_ok=True)
    for package_path, (data, mode) in files.items():
        write_file(payload_path(buildroot, package_path), data, mode)


def write_manifest(
    repo_root: Path,
    version: str,
    artifact_path: Path,
    checksum_source_path: Path,
    manifest_source_path: Path,
    binary_manifest: dict[str, Any],
    rpm_root: Path,
    spec_path: Path,
    buildroot: Path,
    manifest_path: Path,
) -> None:
    manifest = {
        "package_name": PACKAGE_NAME,
        "version": version,
        "os": TARGET_OS,
        "arch": TARGET_ARCH,
        "rpm_arch": RPM_ARCH,
        "package_type": "rpm-staging",
        "source_artifact_path": to_repo_relative(repo_root, artifact_path),
        "source_checksum_path": to_repo_relative(repo_root, checksum_source_path),
        "source_manifest_path": to_repo_relative(repo_root, manifest_source_path),
        "rpm_root": to_repo_relative(repo_root, rpm_root),
        "spec_path": to_repo_relative(repo_root, spec_path),
        "buildroot": to_repo_relative(repo_root, buildroot),
        "build_timestamp": utc_timestamp(),
        "git_commit": binary_manifest["git_commit"],
        "contents": [install_path(path) for path in RPM_EXPECTED_FILES],
        "directories": [install_path(path) for path in RPM_EXPECTED_DIRS],
        "service": {
            "path": f"{RPM_SYSTEMD_DIR}/oaw-agent.service",
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
            "path": RPM_TIMER_INSTALL_PATH,
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
        "ownership": {
            "openassetwatch:openassetwatch": [install_path(path) for path in SERVICE_OWNED_DIRS],
            "root:root": [install_path(path) for path in ROOT_OWNED_PATHS],
        },
        "privileged_helpers": [
            {
                "path": helper_install_path,
                "package_path": install_path(helper_package_path),
                "runs": command,
                "owner": "root:root",
                "mode": "0755",
                "accepts_arguments": False,
            }
            for helper_package_path, helper_install_path, command in PRIVILEGED_HELPERS
        ],
        "sudoers": {
            "path": SUDOERS_INSTALL_PATH,
            "mode": "0440",
            "user": SERVICE_USER,
            "commands": list(APPROVED_SUDOERS_COMMANDS),
        },
        "dependencies": list(PACKAGE_DEPENDENCIES),
        "package_builder": "scripts/release/package_agent_rpm.py",
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def validate_file_mode(path: Path, mode: int) -> None:
    if os.name == "nt":
        # Windows cannot faithfully represent all Unix mode bits in a staging
        # directory. The RPM spec and manifests carry the authoritative modes.
        return
    actual = stat.S_IMODE(path.stat().st_mode)
    if actual != mode:
        raise ValueError(f"{path} mode is {oct(actual)}, expected {oct(mode)}.")


def validate_wrapper(data: bytes) -> None:
    expected = compatibility_wrapper()
    if data != expected:
        raise ValueError("/usr/bin/oaw-agent wrapper must exec only the /opt agent binary.")


def validate_spec(path: Path, version: str) -> None:
    text = path.read_text(encoding="utf-8")
    required = (
        f"Name: {PACKAGE_NAME}",
        f"Version: {rpm_version(version)}",
        "BuildArch: x86_64",
        "Requires: systemd",
        "Requires: shadow-utils",
        "%pre",
        "%post",
        "%postun",
        "%files",
        "systemctl enable oaw-agent.timer || true",
        "systemctl restart oaw-agent.timer || true",
        "%attr(0440,root,root) /etc/sudoers.d/openassetwatch-agent",
        "%attr(0755,root,root) /usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show",
        "%attr(0755,root,root) /usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show",
        "%attr(0755,root,root) /opt/openassetwatch/agent/bin/oaw-agent",
    )
    missing = [item for item in required if item not in text]
    if missing:
        raise ValueError(f"RPM spec missing expected content: {', '.join(missing)}.")
    forbidden = (
        "systemctl start oaw-agent.service",
        "systemctl restart oaw-agent.service",
        "systemctl enable oaw-agent.service",
        "NOPASSWD: ALL",
        "ALL=(ALL) ALL",
        "sudo ",
        "curl ",
        "wget ",
        "dnf ",
        "yum ",
    )
    found = [item for item in forbidden if item in text]
    if found:
        raise ValueError(f"RPM spec contains unsafe content: {', '.join(found)}.")


def validate_manifest(path: Path) -> None:
    manifest = read_json(path)
    missing = [field for field in RPM_REQUIRED_MANIFEST_FIELDS if not str(manifest.get(field, "")).strip()]
    if missing:
        raise ValueError(f"RPM staging manifest missing fields: {', '.join(missing)}.")
    if manifest.get("package_type") != "rpm-staging":
        raise ValueError("RPM staging manifest package_type must be rpm-staging.")
    if manifest.get("service", {}).get("command") != SERVICE_COMMAND:
        raise ValueError("RPM staging manifest service command must use run-once.")
    if manifest.get("sudoers", {}).get("commands") != list(APPROVED_SUDOERS_COMMANDS):
        raise ValueError("RPM staging manifest sudoers commands do not match approved helpers.")


def validate_staging(
    repo_root: Path,
    rpm_root: Path,
    buildroot: Path,
    spec_path: Path,
    manifest_path: Path,
    version: str,
) -> None:
    if not is_inside(repo_root / "dist" / "agent", rpm_root):
        raise ValueError("RPM staging root must stay under ignored dist/agent/.")
    missing_tree = [name for name in RPM_ROOT_DIRS if not (rpm_root / name).is_dir()]
    if missing_tree:
        raise ValueError(f"RPM build tree missing directories: {', '.join(missing_tree)}.")
    missing_dirs = [path for path in RPM_EXPECTED_DIRS if not payload_path(buildroot, path).is_dir()]
    missing_files = [path for path in RPM_EXPECTED_FILES if not payload_path(buildroot, path).is_file()]
    if missing_dirs or missing_files:
        raise ValueError(f"RPM staged payload missing paths: {', '.join(missing_dirs + missing_files)}.")

    validate_helper_script(IP_NEIGH_HELPER_PACKAGE_PATH, payload_path(buildroot, IP_NEIGH_HELPER_PACKAGE_PATH).read_bytes())
    validate_helper_script(IP_ADDR_HELPER_PACKAGE_PATH, payload_path(buildroot, IP_ADDR_HELPER_PACKAGE_PATH).read_bytes())
    validate_file_mode(payload_path(buildroot, IP_NEIGH_HELPER_PACKAGE_PATH), 0o755)
    validate_file_mode(payload_path(buildroot, IP_ADDR_HELPER_PACKAGE_PATH), 0o755)
    validate_wrapper(payload_path(buildroot, "./usr/bin/oaw-agent").read_bytes())
    validate_sudoers_file(payload_path(buildroot, SUDOERS_PACKAGE_PATH).read_bytes())
    validate_file_mode(payload_path(buildroot, SUDOERS_PACKAGE_PATH), 0o440)
    validate_service_unit(payload_path(buildroot, RPM_SERVICE_PACKAGE_PATH).read_bytes())
    validate_timer_unit(payload_path(buildroot, RPM_TIMER_PACKAGE_PATH).read_bytes())
    validate_example_config(payload_path(buildroot, "./etc/openassetwatch/agent/config.example.json").read_bytes())
    validate_example_identity(payload_path(buildroot, "./etc/openassetwatch/agent/identity.example.json").read_bytes())
    validate_spec(spec_path, version)
    validate_manifest(manifest_path)

    release = read_json(payload_path(buildroot, "./usr/share/doc/openassetwatch-agent/release-manifest.json"))
    if release.get("package_type") != "rpm":
        raise ValueError("Embedded release manifest must identify rpm.")
    if release.get("privileged_helpers") != read_json(manifest_path).get("privileged_helpers"):
        raise ValueError("Embedded release manifest helper metadata mismatch.")

    for package_path in RPM_EXPECTED_FILES:
        if package_path in {OPT_BINARY_PACKAGE_PATH, "./usr/bin/oaw-agent"}:
            continue
        data = payload_path(buildroot, package_path).read_bytes()
        if package_path in {IP_NEIGH_HELPER_PACKAGE_PATH, IP_ADDR_HELPER_PACKAGE_PATH, SUDOERS_PACKAGE_PATH}:
            continue
        if FORBIDDEN_CONTENT_RE.search(PurePosixPath(package_path).name):
            raise ValueError(f"RPM staging contains forbidden path: {package_path}")
        if data and FORBIDDEN_CONTENT_RE.search(data.decode("utf-8", errors="ignore")):
            raise ValueError(f"RPM staging contains forbidden content: {package_path}")

    sudoers_text = payload_path(buildroot, SUDOERS_PACKAGE_PATH).read_text(encoding="utf-8")
    sudoers_rules = "\n".join(
        line.strip()
        for line in sudoers_text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )
    if "/usr/sbin/ip neigh show" in sudoers_rules or "/usr/sbin/ip addr show" in sudoers_rules:
        raise ValueError("RPM sudoers must not directly allow raw /usr/sbin/ip commands.")
    if IP_NEIGH_HELPER not in sudoers_rules or IP_ADDR_HELPER not in sudoers_rules:
        raise ValueError("RPM sudoers must allow only the packaged helper scripts.")


def build_rpm_with_rpmbuild(repo_root: Path, rpm_root: Path, buildroot: Path, spec_path: Path, version: str) -> Path:
    rpmbuild = shutil.which("rpmbuild")
    if not rpmbuild:
        raise ValueError("rpmbuild is required to build a real RPM package.")
    command = [
        rpmbuild,
        "-bb",
        "--noclean",
        "--buildroot",
        str(buildroot),
        "--define",
        f"_topdir {rpm_root}",
        "--define",
        "_build_id_links none",
        str(spec_path),
    ]
    result = subprocess.run(command, cwd=repo_root, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        details = "\n".join(
            item
            for item in (
                f"rpmbuild exit code: {result.returncode}",
                f"stdout: {result.stdout.strip()}",
                f"stderr: {result.stderr.strip()}",
            )
            if item
        )
        raise ValueError(details)
    candidates = sorted((rpm_root / "RPMS").glob(f"**/{PACKAGE_NAME}-{rpm_version(version)}-{RPM_RELEASE}*.rpm"))
    if not candidates:
        raise ValueError("rpmbuild completed but no RPM artifact was found under RPMS/.")
    return candidates[0]


def write_rpm_package_metadata(
    repo_root: Path,
    version: str,
    built_rpm: Path,
    package_path: Path,
    checksum_path: Path,
    manifest_path: Path,
    staging_manifest_path: Path,
    binary_manifest: dict[str, Any],
) -> None:
    shutil.copy2(built_rpm, package_path)
    package_hash = sha256_file(package_path).lower()
    checksum_path.write_text(f"{package_hash}  {package_path.name}\n", encoding="ascii")
    manifest = {
        "package_name": PACKAGE_NAME,
        "version": version,
        "os": TARGET_OS,
        "arch": TARGET_ARCH,
        "rpm_arch": RPM_ARCH,
        "package_type": "rpm",
        "package_path": to_repo_relative(repo_root, package_path),
        "source_rpmbuild_path": to_repo_relative(repo_root, built_rpm),
        "staging_manifest_path": to_repo_relative(repo_root, staging_manifest_path),
        "sha256": package_hash,
        "build_timestamp": utc_timestamp(),
        "git_commit": binary_manifest["git_commit"],
        "contents": [install_path(path) for path in RPM_EXPECTED_FILES],
        "directories": [install_path(path) for path in RPM_EXPECTED_DIRS],
        "dependencies": list(PACKAGE_DEPENDENCIES),
        "service": {
            "path": f"{RPM_SYSTEMD_DIR}/oaw-agent.service",
            "model": "oneshot-run-once",
            "command": SERVICE_COMMAND,
            "user": SERVICE_USER,
            "group": SERVICE_GROUP,
        },
        "timer": {
            "path": RPM_TIMER_INSTALL_PATH,
            "unit": "oaw-agent.service",
            "on_boot": "5min",
            "period": "1h",
            "randomized_delay": "10min",
            "persistent": True,
        },
        "privileged_helpers": [
            {
                "path": helper_install_path,
                "package_path": install_path(helper_package_path),
                "runs": command,
                "owner": "root:root",
                "mode": "0755",
                "accepts_arguments": False,
            }
            for helper_package_path, helper_install_path, command in PRIVILEGED_HELPERS
        ],
        "sudoers": {
            "path": SUDOERS_INSTALL_PATH,
            "mode": "0440",
            "user": SERVICE_USER,
            "commands": list(APPROVED_SUDOERS_COMMANDS),
        },
        "package_builder": "scripts/release/package_agent_rpm.py",
    }
    missing = [field for field in RPM_PACKAGE_REQUIRED_FIELDS if not str(manifest.get(field, "")).strip()]
    if missing:
        raise ValueError(f"RPM package manifest missing fields: {', '.join(missing)}.")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a local RPM package artifact for oaw-agent.")
    parser.add_argument("--version", required=True, help="Linux agent release version under dist/agent/<version>/linux-amd64/.")
    return parser.parse_args()


def build_summary(
    reporter: Reporter,
    repo_root: Path,
    version: str,
    rpm_root: Path | None,
    spec_path: Path | None,
    buildroot: Path | None,
    manifest_path: Path | None,
    package_path: Path | None = None,
    checksum_path: Path | None = None,
    package_manifest_path: Path | None = None,
) -> dict[str, Any]:
    return {
        "ok": not reporter.errors,
        "version": version,
        "rpm_root": to_repo_relative(repo_root, rpm_root) if rpm_root else "",
        "spec": to_repo_relative(repo_root, spec_path) if spec_path else "",
        "buildroot": to_repo_relative(repo_root, buildroot) if buildroot else "",
        "manifest": to_repo_relative(repo_root, manifest_path) if manifest_path else "",
        "package": to_repo_relative(repo_root, package_path) if package_path else "",
        "checksum": to_repo_relative(repo_root, checksum_path) if checksum_path else "",
        "package_manifest": to_repo_relative(repo_root, package_manifest_path) if package_manifest_path else "",
        "checks": reporter.checks,
        "warnings": reporter.warnings,
        "errors": reporter.errors,
    }


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    repo_root = get_repo_root()
    version = ""
    rpm_root: Path | None = None
    buildroot: Path | None = None
    spec_path: Path | None = None
    manifest_path: Path | None = None
    package_path: Path | None = None
    checksum_path: Path | None = None
    package_manifest_path: Path | None = None

    try:
        version = validate_version(args.version)
        artifact_path, source_checksum_path, source_manifest_path, binary_manifest = validate_linux_binary_artifact(
            repo_root, version
        )
        reporter.check("linux artifact validation", True, "Linux amd64 agent artifact validation passed.")

        rpm_root, buildroot, spec_path, manifest_path = rpm_paths(repo_root, version)
        clean_rpm_root(repo_root, rpm_root)
        ensure_rpm_tree(rpm_root)
        reporter.check("rpm build tree", True, "RPM build tree was created under ignored dist output.")

        stage_payload(repo_root, version, artifact_path, binary_manifest, rpm_root, spec_path, buildroot)
        reporter.check("rpm payload staging", True, "RPM payload was staged under BUILDROOT only.")

        write_file(spec_path, spec_file(version), 0o644)
        reporter.check("rpm spec", True, "RPM spec file was generated without invoking RPM tooling.")

        write_manifest(
            repo_root,
            version,
            artifact_path,
            source_checksum_path,
            source_manifest_path,
            binary_manifest,
            rpm_root,
            spec_path,
            buildroot,
            manifest_path,
        )
        reporter.check("rpm staging manifest", True, "RPM staging manifest was written under ignored dist output.")

        validate_staging(repo_root, rpm_root, buildroot, spec_path, manifest_path, version)
        reporter.check("rpm staging validation", True, "RPM staging output contains the expected safe package layout.")

        built_rpm = build_rpm_with_rpmbuild(repo_root, rpm_root, buildroot, spec_path, version)
        reporter.check("rpm package build", True, "rpmbuild created a real RPM package under ignored dist output.")

        package_path, checksum_path, package_manifest_path = rpm_package_paths(repo_root, version)
        write_rpm_package_metadata(
            repo_root,
            version,
            built_rpm,
            package_path,
            checksum_path,
            package_manifest_path,
            manifest_path,
            binary_manifest,
        )
        reporter.check("rpm package metadata", True, "RPM checksum and package manifest were written.")
    except Exception as exc:
        reporter.check("rpm staging helper", False, str(exc))

    summary = build_summary(
        reporter,
        repo_root,
        version,
        rpm_root,
        spec_path,
        buildroot,
        manifest_path,
        package_path,
        checksum_path,
        package_manifest_path,
    )
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
