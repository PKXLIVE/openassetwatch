#!/usr/bin/env python3
"""Stage an RPM build tree for the OpenAssetWatch agent without building it."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import Any

from package_agent_deb import (
    APPROVED_SUDOERS_COMMANDS,
    FORBIDDEN_CONTENT_RE,
    IP_ADDR_HELPER,
    IP_ADDR_HELPER_PACKAGE_PATH,
    IP_NEIGH_HELPER,
    IP_NEIGH_HELPER_PACKAGE_PATH,
    OPT_BINARY,
    OPT_BINARY_PACKAGE_PATH,
    PACKAGE_NAME,
    PRIVILEGED_HELPERS,
    SERVICE_COMMAND,
    SERVICE_GROUP,
    SERVICE_OWNED_DIRS,
    SERVICE_USER,
    SUDOERS_INSTALL_PATH,
    TARGET_ARCH,
    TARGET_OS,
    USR_BIN_LINK_TARGET,
    USR_BIN_PACKAGE_PATH,
    config_example,
    get_repo_root,
    identity_example,
    ip_addr_helper_script,
    ip_neigh_helper_script,
    is_inside,
    package_readme,
    read_json,
    service_unit,
    sha256_file,
    sudoers_file,
    timer_unit,
    to_repo_relative,
    utc_timestamp,
    validate_binary_artifact,
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


RPM_ARCH = "x86_64"
RPM_RELEASE = "1"
RPM_ROOT_DIRS = ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS")
RPM_SYSTEMD_DIR = "/usr/lib/systemd/system"
RPM_SERVICE_PACKAGE_PATH = "./usr/lib/systemd/system/oaw-agent.service"
RPM_TIMER_PACKAGE_PATH = "./usr/lib/systemd/system/oaw-agent.timer"
RPM_TIMER_INSTALL_PATH = "/usr/lib/systemd/system/oaw-agent.timer"
PACKAGE_DEPENDENCIES = ("systemd", "shadow-utils")
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

ROOT_OWNED_PATHS = (
    "./usr/bin/oaw-agent",
    "./usr/lib/openassetwatch",
    "./usr/lib/openassetwatch/agent",
    "./usr/lib/openassetwatch/agent/libexec",
    IP_NEIGH_HELPER_PACKAGE_PATH,
    IP_ADDR_HELPER_PACKAGE_PATH,
    "./etc/openassetwatch",
    "./etc/openassetwatch/agent",
    SUDOERS_PACKAGE_PATH,
    RPM_SERVICE_PACKAGE_PATH,
    RPM_TIMER_PACKAGE_PATH,
)

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
        "package_type": "rpm-staging",
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
    spec_version = rpm_version(version)
    files = [
        "%dir %attr(0755,openassetwatch,openassetwatch) /opt/openassetwatch",
        "%dir %attr(0755,openassetwatch,openassetwatch) /opt/openassetwatch/agent",
        "%dir %attr(0755,openassetwatch,openassetwatch) /opt/openassetwatch/agent/bin",
        "%attr(0755,openassetwatch,openassetwatch) /opt/openassetwatch/agent/bin/oaw-agent",
        "%attr(0755,root,root) /usr/bin/oaw-agent",
        "%dir %attr(0755,root,root) /usr/lib/openassetwatch",
        "%dir %attr(0755,root,root) /usr/lib/openassetwatch/agent",
        "%dir %attr(0755,root,root) /usr/lib/openassetwatch/agent/libexec",
        "%attr(0755,root,root) /usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show",
        "%attr(0755,root,root) /usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show",
        "%dir %attr(0755,root,root) /etc/openassetwatch",
        "%dir %attr(0755,root,root) /etc/openassetwatch/agent",
        "%config(noreplace) %attr(0644,root,root) /etc/openassetwatch/agent/config.example.json",
        "%config(noreplace) %attr(0644,root,root) /etc/openassetwatch/agent/identity.example.json",
        "%attr(0440,root,root) /etc/sudoers.d/openassetwatch-agent",
        "%attr(0644,root,root) /usr/lib/systemd/system/oaw-agent.service",
        "%attr(0644,root,root) /usr/lib/systemd/system/oaw-agent.timer",
        "%dir %attr(0755,openassetwatch,openassetwatch) /var/lib/openassetwatch/agent",
        "%dir %attr(0755,openassetwatch,openassetwatch) /var/log/openassetwatch/agent",
        "%doc /usr/share/doc/openassetwatch-agent/README.md",
        "%attr(0644,root,root) /usr/share/doc/openassetwatch-agent/release-manifest.json",
    ]
    return "\n".join(
        [
            f"Name: {PACKAGE_NAME}",
            f"Version: {spec_version}",
            f"Release: {RPM_RELEASE}%{{?dist}}",
            "Summary: OpenAssetWatch defensive local asset inventory agent",
            "License: Proprietary",
            "URL: https://openassetwatch.example.invalid",
            f"# OpenAssetWatch-Source-Version: {version}",
            "BuildArch: x86_64",
            "Requires: systemd",
            "Requires: shadow-utils",
            "",
            "%description",
            "The OpenAssetWatch agent collects local, passive asset inventory",
            "observations for administrator-approved OpenAssetWatch deployments.",
            "",
            "%pre",
            f"if ! getent group {SERVICE_GROUP} >/dev/null 2>&1; then",
            f"    groupadd --system {SERVICE_GROUP}",
            "fi",
            f"if ! id -u {SERVICE_USER} >/dev/null 2>&1; then",
            (
                f"    useradd --system --gid {SERVICE_GROUP} "
                "--home-dir /var/lib/openassetwatch/agent --no-create-home "
                f"--shell /usr/sbin/nologin {SERVICE_USER}"
            ),
            "fi",
            "",
            "%post",
            f"chown -R {SERVICE_USER}:{SERVICE_GROUP} /opt/openassetwatch/agent",
            f"chown -R {SERVICE_USER}:{SERVICE_GROUP} /var/lib/openassetwatch/agent",
            f"chown -R {SERVICE_USER}:{SERVICE_GROUP} /var/log/openassetwatch/agent",
            "if command -v systemctl >/dev/null 2>&1; then",
            "    systemctl daemon-reload || true",
            "    systemctl enable oaw-agent.timer || true",
            (
                "    if [ -f /etc/openassetwatch/agent/config.json ] "
                "&& [ -f /etc/openassetwatch/agent/identity.json ]; then"
            ),
            "        systemctl restart oaw-agent.timer || true",
            "    fi",
            "fi",
            "",
            "%postun",
            "if command -v systemctl >/dev/null 2>&1; then",
            "    systemctl daemon-reload || true",
            "fi",
            "",
            "%files",
            *files,
            "",
        ]
    ).encode("utf-8")


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
        RPM_SERVICE_PACKAGE_PATH: (service_unit(), 0o644),
        RPM_TIMER_PACKAGE_PATH: (timer_unit(), 0o644),
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
        "%attr(0755,openassetwatch,openassetwatch) /opt/openassetwatch/agent/bin/oaw-agent",
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
    if release.get("package_type") != "rpm-staging":
        raise ValueError("Embedded release manifest must identify rpm-staging.")
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stage a local RPM build tree for oaw-agent without building an RPM.")
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
) -> dict[str, Any]:
    return {
        "ok": not reporter.errors,
        "version": version,
        "rpm_root": to_repo_relative(repo_root, rpm_root) if rpm_root else "",
        "spec": to_repo_relative(repo_root, spec_path) if spec_path else "",
        "buildroot": to_repo_relative(repo_root, buildroot) if buildroot else "",
        "manifest": to_repo_relative(repo_root, manifest_path) if manifest_path else "",
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

    try:
        version = validate_version(args.version)
        artifact_path, source_checksum_path, source_manifest_path, binary_manifest = validate_binary_artifact(
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
    except Exception as exc:
        reporter.check("rpm staging helper", False, str(exc))

    summary = build_summary(reporter, repo_root, version, rpm_root, spec_path, buildroot, manifest_path)
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
