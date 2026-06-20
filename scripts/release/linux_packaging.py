#!/usr/bin/env python3
"""Canonical Linux package source loading and constants."""

from __future__ import annotations

import re
from pathlib import Path

from release_common import is_inside, read_json, resolve_repo_path, sha256_file, to_repo_relative, get_repo_root


PACKAGE_NAME = "openassetwatch-agent"
TARGET_OS = "linux"
TARGET_ARCH = "amd64"
DEBIAN_ARCH = "amd64"
RPM_ARCH = "x86_64"
RPM_RELEASE = "1"
SERVICE_USER = "openassetwatch"
SERVICE_GROUP = "openassetwatch"
OPT_BINARY = "/opt/openassetwatch/agent/bin/oaw-agent"
OPT_BINARY_PACKAGE_PATH = "./opt/openassetwatch/agent/bin/oaw-agent"
USR_BIN_PACKAGE_PATH = "./usr/bin/oaw-agent"
USR_BIN_LINK_TARGET = OPT_BINARY
LIBEXEC_DIR = "/usr/lib/openassetwatch/agent/libexec"
IP_NEIGH_HELPER = f"{LIBEXEC_DIR}/oaw-ip-neigh-show"
IP_ADDR_HELPER = f"{LIBEXEC_DIR}/oaw-ip-addr-show"
IP_NEIGH_HELPER_PACKAGE_PATH = "./usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show"
IP_ADDR_HELPER_PACKAGE_PATH = "./usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show"
SERVICE_COMMAND = (
    f"{OPT_BINARY} run-once --config /etc/openassetwatch/agent/config.json "
    "--identity-file /etc/openassetwatch/agent/identity.json "
    "--output-dir /var/lib/openassetwatch/agent"
)
TIMER_INSTALL_PATH = "/lib/systemd/system/oaw-agent.timer"
SUDOERS_PACKAGE_PATH = "./etc/sudoers.d/openassetwatch-agent"
SUDOERS_INSTALL_PATH = "/etc/sudoers.d/openassetwatch-agent"
RPM_SYSTEMD_DIR = "/usr/lib/systemd/system"
RPM_TIMER_INSTALL_PATH = "/usr/lib/systemd/system/oaw-agent.timer"
PACKAGE_DEPENDENCIES_DEB = ("systemd", "passwd")
PACKAGE_DEPENDENCIES_RPM = ("systemd", "shadow-utils")
APPROVED_SUDOERS_COMMANDS = (
    IP_NEIGH_HELPER,
    IP_ADDR_HELPER,
)
PRIVILEGED_HELPERS = (
    (IP_NEIGH_HELPER_PACKAGE_PATH, IP_NEIGH_HELPER, "/usr/sbin/ip neigh show"),
    (IP_ADDR_HELPER_PACKAGE_PATH, IP_ADDR_HELPER, "/usr/sbin/ip addr show"),
)
SERVICE_OWNED_DIRS = (
    "./var/lib/openassetwatch/agent",
    "./var/log/openassetwatch/agent",
)
ROOT_OWNED_DIRS = (
    "./opt/openassetwatch",
    "./opt/openassetwatch/agent",
    "./opt/openassetwatch/agent/bin",
    OPT_BINARY_PACKAGE_PATH,
    "./usr/bin/oaw-agent",
    "./usr/lib/openassetwatch",
    "./usr/lib/openassetwatch/agent",
    "./usr/lib/openassetwatch/agent/libexec",
    IP_NEIGH_HELPER_PACKAGE_PATH,
    IP_ADDR_HELPER_PACKAGE_PATH,
    "./etc/openassetwatch",
    "./etc/openassetwatch/agent",
    SUDOERS_PACKAGE_PATH,
)
FORBIDDEN_CONTENT_RE = re.compile(
    r"(token|secret|credential|password|api[_-]?key|private[_-]?key|enrollment|"
    r"status\.json|\.log$|\.pem$|\.key$)",
    re.IGNORECASE,
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


def linux_source_root() -> Path:
    return get_repo_root() / "packaging" / "agent" / "linux"


def read_source_bytes(relative_path: str) -> bytes:
    path = linux_source_root() / relative_path
    return path.read_bytes()


def read_source_text(relative_path: str) -> str:
    return read_source_bytes(relative_path).decode("utf-8")


def render_template(relative_path: str, values: dict[str, str]) -> bytes:
    text = read_source_text(relative_path)
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", value)
    unresolved = re.findall(r"{{[A-Z0-9_]+}}", text)
    if unresolved:
        raise ValueError(f"Unresolved placeholders in {relative_path}: {', '.join(sorted(set(unresolved)))}")
    return text.encode("utf-8")


def template_values(version: str) -> dict[str, str]:
    return {
        "PACKAGE_NAME": PACKAGE_NAME,
        "VERSION": version,
        "RPM_VERSION": version.replace("-", "_"),
        "RPM_RELEASE": RPM_RELEASE,
        "SERVICE_USER": SERVICE_USER,
        "SERVICE_GROUP": SERVICE_GROUP,
        "OPT_BINARY": OPT_BINARY,
        "SERVICE_COMMAND": SERVICE_COMMAND,
        "TIMER_INSTALL_PATH": TIMER_INSTALL_PATH,
        "RPM_TIMER_INSTALL_PATH": RPM_TIMER_INSTALL_PATH,
        "IP_NEIGH_HELPER": IP_NEIGH_HELPER,
        "IP_ADDR_HELPER": IP_ADDR_HELPER,
    }


def config_example() -> bytes:
    return read_source_bytes("common/examples/config.example.json")


def identity_example() -> bytes:
    return read_source_bytes("common/examples/identity.example.json")


def ip_neigh_helper_script() -> bytes:
    return read_source_bytes("common/libexec/oaw-ip-neigh-show")


def ip_addr_helper_script() -> bytes:
    return read_source_bytes("common/libexec/oaw-ip-addr-show")


def sudoers_file() -> bytes:
    return read_source_bytes("common/sudoers/openassetwatch-agent")


def deb_service_unit() -> bytes:
    return read_source_bytes("common/systemd/oaw-agent.service")


def rpm_service_unit() -> bytes:
    return read_source_bytes("common/systemd/oaw-agent.service")


def deb_timer_unit() -> bytes:
    return read_source_bytes("common/systemd/oaw-agent.timer")


def rpm_timer_unit() -> bytes:
    return read_source_bytes("common/systemd/oaw-agent.timer")


def deb_control_file(version: str) -> bytes:
    return render_template("deb/control.in", template_values(version))


def deb_postinst_script() -> bytes:
    return read_source_bytes("deb/postinst")


def deb_postrm_script() -> bytes:
    return read_source_bytes("deb/postrm")


def deb_conffiles() -> bytes:
    return read_source_bytes("deb/conffiles")


def package_readme(version: str) -> bytes:
    return render_template("common/README.md", template_values(version))


def rpm_spec_file(version: str) -> bytes:
    return render_template("rpm/openassetwatch-agent.spec.in", template_values(version))


def validate_linux_binary_artifact(repo_root: Path, version: str) -> tuple[Path, Path, Path, dict[str, object]]:
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
