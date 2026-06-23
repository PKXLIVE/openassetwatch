#!/usr/bin/env python3
"""Validate an existing OpenAssetWatch agent RPM staging tree."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import linux_packaging as linuxsrc
from linux_packaging import (
    APPROVED_SUDOERS_COMMANDS,
    FORBIDDEN_CONTENT_RE,
    IP_ADDR_HELPER,
    IP_ADDR_HELPER_PACKAGE_PATH,
    IP_NEIGH_HELPER,
    IP_NEIGH_HELPER_PACKAGE_PATH,
    OPT_BINARY_PACKAGE_PATH,
    PACKAGE_NAME,
    SERVICE_COMMAND,
    SERVICE_GROUP,
    SERVICE_OWNED_DIRS,
    SERVICE_USER,
    SUDOERS_INSTALL_PATH,
    TARGET_ARCH,
    TARGET_OS,
)
from release_common import get_repo_root, is_inside, read_json, resolve_repo_path, sha256_file, to_repo_relative, validate_version
from package_agent_rpm import (
    PACKAGE_DEPENDENCIES,
    ROOT_OWNED_PATHS,
    RPM_ARCH,
    RPM_EXPECTED_DIRS,
    RPM_EXPECTED_FILES,
    RPM_PACKAGE_REQUIRED_FIELDS,
    RPM_RELEASE,
    RPM_REQUIRED_MANIFEST_FIELDS,
    RPM_ROOT_DIRS,
    RPM_SERVICE_PACKAGE_PATH,
    RPM_SYSTEMD_DIR,
    RPM_TIMER_INSTALL_PATH,
    RPM_TIMER_PACKAGE_PATH,
    SUDOERS_PACKAGE_PATH,
    compatibility_wrapper,
    install_path,
    payload_path,
    rpm_paths,
    rpm_version,
)
from validate_agent_deb import (
    validate_example_config,
    validate_example_identity,
    validate_helper_script,
    validate_service_unit,
    validate_sudoers_file,
    validate_timer_unit,
)


EXPECTED_SERVICE_LINES = (
    "Type=oneshot",
    f"User={SERVICE_USER}",
    f"Group={SERVICE_GROUP}",
    "ConditionPathExists=/etc/openassetwatch/agent/config.json",
    "ConditionPathExists=/etc/openassetwatch/agent/identity.json",
    f"ExecStart={SERVICE_COMMAND}",
    "ReadWritePaths=/var/lib/openassetwatch/agent",
)

EXPECTED_TIMER_LINES = (
    "OnBootSec=5min",
    "OnUnitActiveSec=1h",
    "RandomizedDelaySec=10min",
    "Persistent=true",
    "Unit=oaw-agent.service",
)

SPEC_REQUIRED_TEXT = (
    f"Name: {PACKAGE_NAME}",
    "BuildArch: x86_64",
    "Requires: systemd",
    "Requires: shadow-utils",
    "%pre",
    "%post",
    "%preun",
    "%postun",
    "%files",
    'groupadd --system "$SERVICE_GROUP"',
    'useradd --system --gid "$SERVICE_GROUP"',
    "--shell /usr/sbin/nologin",
    f"License: {linuxsrc.PACKAGE_LICENSE}",
    f"URL: {linuxsrc.PACKAGE_URL}",
    "systemctl daemon-reload",
    "systemctl enable oaw-agent.timer",
    "systemctl restart oaw-agent.timer",
    "systemctl stop oaw-agent.timer",
    "systemctl disable oaw-agent.timer",
    "rm -f /etc/systemd/system/timers.target.wants/oaw-agent.timer",
    "grep -Eq '^(sudo|admin|wheel)$'",
    "%attr(0440,root,root) /etc/sudoers.d/openassetwatch-agent",
    "%attr(0755,root,root) /usr/lib/openassetwatch/agent/libexec/oaw-ip-neigh-show",
    "%attr(0755,root,root) /usr/lib/openassetwatch/agent/libexec/oaw-ip-addr-show",
    "%attr(0755,root,root) /opt/openassetwatch/agent/bin/oaw-agent",
)

SPEC_FORBIDDEN_TEXT = (
    "systemctl start oaw-agent.service",
    "systemctl restart oaw-agent.service",
    "systemctl enable oaw-agent.service",
    "|| true",
    "rm -rf /etc/openassetwatch",
    "rm -rf /var/lib/openassetwatch",
    "rm -rf /var/log/openassetwatch",
    "NOPASSWD: ALL",
    "ALL=(ALL) ALL",
    "ALL=(ALL:ALL)",
    "/bin/bash",
    " bash",
    "python ",
    "curl ",
    "wget ",
    "dnf ",
    "yum ",
    "sudo ",
    "rpmbuild",
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


def resolve_rpm_root(repo_root: Path, version: str, rpm_root_arg: str | None) -> Path:
    if rpm_root_arg:
        root = resolve_repo_path(repo_root, rpm_root_arg)
    else:
        root, _buildroot, _spec_path, _manifest_path = rpm_paths(repo_root, version)
    if not is_inside(repo_root / "dist" / "agent", root):
        raise ValueError("RPM staging root must resolve under dist/agent/.")
    return root


def expected_paths(rpm_root: Path, version: str) -> tuple[Path, Path, Path]:
    buildroot = rpm_root / "BUILDROOT" / f"{PACKAGE_NAME}-{version}-{RPM_RELEASE}.{RPM_ARCH}"
    spec_path = rpm_root / "SPECS" / f"{PACKAGE_NAME}.spec"
    manifest_path = rpm_root / f"{PACKAGE_NAME}-{version}-{RPM_RELEASE}.{RPM_ARCH}.manifest.json"
    return buildroot, spec_path, manifest_path


def resolve_rpm_package(repo_root: Path, version: str, package_arg: str | None) -> tuple[Path, Path, Path]:
    if package_arg:
        package_path = resolve_repo_path(repo_root, package_arg)
        if not is_inside(repo_root / "dist" / "agent", package_path):
            raise ValueError("RPM package path must resolve under dist/agent/.")
        checksum_path = Path(str(package_path) + ".sha256")
        manifest_path = Path(str(package_path) + ".manifest.json")
        return package_path, checksum_path, manifest_path
    package_dir = repo_root / "dist" / "agent" / version / "packages"
    package_path = package_dir / f"{PACKAGE_NAME}-{rpm_version(version)}-{RPM_RELEASE}.{RPM_ARCH}.rpm"
    checksum_path = Path(str(package_path) + ".sha256")
    manifest_path = Path(str(package_path) + ".manifest.json")
    return package_path, checksum_path, manifest_path


def run_rpm(args: list[str]) -> str:
    rpm = shutil.which("rpm")
    if not rpm:
        raise ValueError("rpm tooling is required to validate a real RPM package.")
    result = subprocess.run([rpm, *args], capture_output=True, text=True, check=False)
    if result.returncode != 0:
        details = "\n".join(
            item
            for item in (
                f"rpm exit code: {result.returncode}",
                f"stdout: {result.stdout.strip()}",
                f"stderr: {result.stderr.strip()}",
            )
            if item
        )
        raise ValueError(details)
    return result.stdout


def read_payload_text(buildroot: Path, package_path: str) -> str:
    return payload_path(buildroot, package_path).read_text(encoding="utf-8")


def validate_build_tree(rpm_root: Path) -> None:
    missing = [name for name in RPM_ROOT_DIRS if not (rpm_root / name).is_dir()]
    if missing:
        raise ValueError(f"RPM build tree missing directories: {', '.join(missing)}.")


def validate_payload_paths(buildroot: Path) -> None:
    missing_dirs = [path for path in RPM_EXPECTED_DIRS if not payload_path(buildroot, path).is_dir()]
    missing_files = [path for path in RPM_EXPECTED_FILES if not payload_path(buildroot, path).is_file()]
    missing = missing_dirs + missing_files
    if missing:
        raise ValueError(f"RPM staged payload missing paths: {', '.join(missing)}.")


def validate_wrapper(buildroot: Path) -> None:
    wrapper = payload_path(buildroot, "./usr/bin/oaw-agent").read_bytes()
    if wrapper != compatibility_wrapper():
        raise ValueError("/usr/bin/oaw-agent must be the approved compatibility wrapper.")


def validate_service_and_timer(buildroot: Path) -> None:
    service = payload_path(buildroot, RPM_SERVICE_PACKAGE_PATH).read_bytes()
    timer = payload_path(buildroot, RPM_TIMER_PACKAGE_PATH).read_bytes()
    validate_service_unit(service)
    validate_timer_unit(timer)

    service_text = service.decode("utf-8")
    missing_service = [line for line in EXPECTED_SERVICE_LINES if line not in service_text]
    if missing_service:
        raise ValueError(f"RPM service unit missing expected lines: {', '.join(missing_service)}.")
    if "run-once" not in service_text:
        raise ValueError("RPM service unit must use the run-once runtime command.")

    timer_text = timer.decode("utf-8")
    missing_timer = [line for line in EXPECTED_TIMER_LINES if line not in timer_text]
    if missing_timer:
        raise ValueError(f"RPM timer unit missing expected lines: {', '.join(missing_timer)}.")


def validate_helpers_and_sudoers(buildroot: Path) -> None:
    helper_files = {
        IP_NEIGH_HELPER_PACKAGE_PATH: payload_path(buildroot, IP_NEIGH_HELPER_PACKAGE_PATH).read_bytes(),
        IP_ADDR_HELPER_PACKAGE_PATH: payload_path(buildroot, IP_ADDR_HELPER_PACKAGE_PATH).read_bytes(),
    }
    for package_path, data in helper_files.items():
        validate_helper_script(package_path, data)
        text = data.decode("utf-8")
        if 'if [ "$#" -ne 0 ]; then' not in text:
            raise ValueError(f"Helper {package_path} must reject arguments.")

    sudoers = payload_path(buildroot, SUDOERS_PACKAGE_PATH).read_bytes()
    validate_sudoers_file(sudoers)
    rules = "\n".join(
        line.strip()
        for line in sudoers.decode("utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    )
    if "/usr/sbin/ip neigh show" in rules or "/usr/sbin/ip addr show" in rules:
        raise ValueError("RPM sudoers must not directly allow raw /usr/sbin/ip commands.")
    expected_rules = [
        f'{SERVICE_USER} ALL=(root) NOPASSWD: {command} ""'
        for command in APPROVED_SUDOERS_COMMANDS
    ]
    if rules.splitlines() != expected_rules:
        raise ValueError("RPM sudoers must contain only the approved helper-script rules.")
    if IP_NEIGH_HELPER not in rules or IP_ADDR_HELPER not in rules:
        raise ValueError("RPM sudoers must allow only the packaged helper scripts.")


def validate_examples(buildroot: Path) -> None:
    validate_example_config(payload_path(buildroot, "./etc/openassetwatch/agent/config.example.json").read_bytes())
    validate_example_identity(payload_path(buildroot, "./etc/openassetwatch/agent/identity.example.json").read_bytes())


def validate_manifest(repo_root: Path, rpm_root: Path, buildroot: Path, spec_path: Path, manifest_path: Path, version: str) -> None:
    manifest = read_json(manifest_path)
    missing = [field for field in RPM_REQUIRED_MANIFEST_FIELDS if not str(manifest.get(field, "")).strip()]
    if missing:
        raise ValueError(f"RPM staging manifest missing fields: {', '.join(missing)}.")
    if manifest.get("package_name") != PACKAGE_NAME:
        raise ValueError("RPM staging manifest package_name mismatch.")
    if manifest.get("version") != version:
        raise ValueError("RPM staging manifest version mismatch.")
    if manifest.get("os") != TARGET_OS or manifest.get("arch") != TARGET_ARCH:
        raise ValueError("RPM staging manifest must describe linux/amd64.")
    if manifest.get("rpm_arch") != RPM_ARCH:
        raise ValueError("RPM staging manifest rpm_arch mismatch.")
    if manifest.get("package_type") != "rpm-staging":
        raise ValueError("RPM staging manifest package_type must be rpm-staging.")
    if manifest.get("package_url") != linuxsrc.PACKAGE_URL:
        raise ValueError("RPM staging manifest package_url must be the canonical repository URL.")
    if manifest.get("package_license") != linuxsrc.PACKAGE_LICENSE:
        raise ValueError("RPM staging manifest package_license must match the repository license decision.")
    if resolve_repo_path(repo_root, str(manifest["rpm_root"])) != rpm_root.resolve():
        raise ValueError("RPM staging manifest rpm_root mismatch.")
    if resolve_repo_path(repo_root, str(manifest["spec_path"])) != spec_path.resolve():
        raise ValueError("RPM staging manifest spec_path mismatch.")
    if resolve_repo_path(repo_root, str(manifest["buildroot"])) != buildroot.resolve():
        raise ValueError("RPM staging manifest buildroot mismatch.")
    if set(manifest.get("contents", [])) != {install_path(path) for path in RPM_EXPECTED_FILES}:
        raise ValueError("RPM staging manifest contents do not match expected payload files.")
    if set(manifest.get("directories", [])) != {install_path(path) for path in RPM_EXPECTED_DIRS}:
        raise ValueError("RPM staging manifest directories do not match expected payload directories.")
    if set(manifest.get("dependencies", [])) != set(PACKAGE_DEPENDENCIES):
        raise ValueError("RPM staging manifest dependencies mismatch.")
    if manifest.get("service", {}).get("command") != SERVICE_COMMAND:
        raise ValueError("RPM staging manifest service command must use run-once.")
    if manifest.get("service", {}).get("user") != SERVICE_USER or manifest.get("service", {}).get("group") != SERVICE_GROUP:
        raise ValueError("RPM staging manifest service user/group mismatch.")
    if manifest.get("service", {}).get("path") != f"{RPM_SYSTEMD_DIR}/oaw-agent.service":
        raise ValueError("RPM staging manifest service path mismatch.")
    timer = manifest.get("timer", {})
    if timer.get("path") != RPM_TIMER_INSTALL_PATH or timer.get("unit") != "oaw-agent.service":
        raise ValueError("RPM staging manifest timer path/unit mismatch.")
    if timer.get("on_boot") != "5min" or timer.get("period") != "1h" or timer.get("randomized_delay") != "10min":
        raise ValueError("RPM staging manifest timer cadence mismatch.")
    if manifest.get("sudoers", {}).get("commands") != list(APPROVED_SUDOERS_COMMANDS):
        raise ValueError("RPM staging manifest sudoers commands mismatch.")
    if manifest.get("sudoers", {}).get("path") != SUDOERS_INSTALL_PATH:
        raise ValueError("RPM staging manifest sudoers path mismatch.")
    ownership = manifest.get("ownership", {})
    if set(ownership.get("openassetwatch:openassetwatch", [])) != {install_path(path) for path in SERVICE_OWNED_DIRS}:
        raise ValueError("RPM staging manifest service-owned paths mismatch.")
    if set(ownership.get("root:root", [])) != {install_path(path) for path in ROOT_OWNED_PATHS}:
        raise ValueError("RPM staging manifest root-owned paths mismatch.")
    lifecycle = manifest.get("lifecycle", {})
    if lifecycle.get("remove") != "stop_disable_timer_remove_enablement_link_preserve_customer_data":
        raise ValueError("RPM staging manifest must describe timer stop/disable behavior on removal.")
    if lifecycle.get("downgrade") != "native_package_manager_downgrade_is_explicit_admin_action":
        raise ValueError("RPM staging manifest must describe explicit admin downgrade policy.")


def validate_embedded_release_manifest(manifest_path: Path, buildroot: Path, version: str) -> None:
    package_manifest = read_json(manifest_path)
    release_manifest = read_json(payload_path(buildroot, "./usr/share/doc/openassetwatch-agent/release-manifest.json"))
    if release_manifest.get("package_name") != PACKAGE_NAME:
        raise ValueError("Embedded release manifest package_name mismatch.")
    if release_manifest.get("version") != version:
        raise ValueError("Embedded release manifest version mismatch.")
    if release_manifest.get("package_type") != "rpm":
        raise ValueError("Embedded release manifest package_type must be rpm.")
    if release_manifest.get("package_url") != linuxsrc.PACKAGE_URL:
        raise ValueError("Embedded release manifest package_url must use the canonical repository URL.")
    if release_manifest.get("package_license") != linuxsrc.PACKAGE_LICENSE:
        raise ValueError("Embedded release manifest package_license mismatch.")
    for field in ("service", "timer", "privileged_helpers", "sudoers"):
        if release_manifest.get(field) != package_manifest.get(field):
            raise ValueError(f"Embedded release manifest {field} metadata mismatch.")


def validate_forbidden_content(buildroot: Path) -> None:
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


def validate_spec_file(spec_path: Path, version: str) -> None:
    text = spec_path.read_text(encoding="utf-8")
    missing = [item for item in SPEC_REQUIRED_TEXT if item not in text]
    if missing:
        raise ValueError(f"RPM spec missing expected text: {', '.join(missing)}.")
    if f"Version: {rpm_version(version)}" not in text:
        raise ValueError("RPM spec Version does not match the requested version.")
    if f"# OpenAssetWatch-Source-Version: {version}" not in text:
        raise ValueError("RPM spec must preserve the source version comment.")
    found = [item for item in SPEC_FORBIDDEN_TEXT if item in text]
    if found:
        raise ValueError(f"RPM spec contains unsafe text: {', '.join(found)}.")
    if "systemctl restart oaw-agent.timer" in text:
        guard = (
            "if [ -f /etc/openassetwatch/agent/config.json ] "
            "&& [ -f /etc/openassetwatch/agent/identity.json ]; then\n"
            "        systemctl restart oaw-agent.timer\n"
            "    fi"
        )
        if guard not in text:
            raise ValueError("RPM spec must guard timer restart on config and identity existence.")
    if "rm " in text or "rm\t" in text:
        if "rm -f /etc/systemd/system/timers.target.wants/oaw-agent.timer" not in text:
            raise ValueError("RPM spec must not delete files except the timer enablement symlink.")
    if "sudoers" in text and "%attr(0440,root,root) /etc/sudoers.d/openassetwatch-agent" not in text:
        raise ValueError("RPM spec sudoers handling must be limited to file metadata.")


def validate_package_metadata(
    repo_root: Path,
    version: str,
    package_path: Path,
    checksum_path: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    if not package_path.is_file():
        raise ValueError(f"RPM package is missing: {to_repo_relative(repo_root, package_path)}")
    if not checksum_path.is_file():
        raise ValueError("RPM package checksum is missing.")
    if not manifest_path.is_file():
        raise ValueError("RPM package manifest is missing.")
    manifest = read_json(manifest_path)
    missing = [field for field in RPM_PACKAGE_REQUIRED_FIELDS if not str(manifest.get(field, "")).strip()]
    if missing:
        raise ValueError(f"RPM package manifest missing fields: {', '.join(missing)}.")
    if manifest.get("package_name") != PACKAGE_NAME:
        raise ValueError("RPM package manifest package_name mismatch.")
    if manifest.get("version") != version:
        raise ValueError("RPM package manifest version mismatch.")
    if manifest.get("os") != TARGET_OS or manifest.get("arch") != TARGET_ARCH:
        raise ValueError("RPM package manifest must describe linux/amd64.")
    if manifest.get("rpm_arch") != RPM_ARCH:
        raise ValueError("RPM package manifest rpm_arch mismatch.")
    if manifest.get("package_type") != "rpm":
        raise ValueError("RPM package manifest package_type must be rpm.")
    if manifest.get("package_url") != linuxsrc.PACKAGE_URL:
        raise ValueError("RPM package manifest package_url must be the canonical repository URL.")
    if manifest.get("package_license") != linuxsrc.PACKAGE_LICENSE:
        raise ValueError("RPM package manifest package_license must match the repository license decision.")
    if resolve_repo_path(repo_root, str(manifest["package_path"])) != package_path.resolve():
        raise ValueError("RPM package manifest path mismatch.")
    actual_hash = sha256_file(package_path).lower()
    checksum_text = checksum_path.read_text(encoding="ascii").strip()
    checksum_hash = checksum_text.split()[0].lower() if checksum_text else ""
    if str(manifest["sha256"]).lower() != actual_hash:
        raise ValueError("RPM package SHA256 does not match package manifest.")
    if checksum_hash != actual_hash:
        raise ValueError("RPM package SHA256 does not match checksum file.")
    if set(manifest.get("contents", [])) != {install_path(path) for path in RPM_EXPECTED_FILES}:
        raise ValueError("RPM package manifest contents do not match expected payload files.")
    if set(manifest.get("directories", [])) != {install_path(path) for path in RPM_EXPECTED_DIRS}:
        raise ValueError("RPM package manifest directories do not match expected payload directories.")
    if set(manifest.get("dependencies", [])) != set(PACKAGE_DEPENDENCIES):
        raise ValueError("RPM package manifest dependencies mismatch.")
    if manifest.get("privileged_helpers") != read_json(resolve_repo_path(repo_root, str(manifest["staging_manifest_path"]))).get("privileged_helpers"):
        raise ValueError("RPM package manifest helper metadata must match the staging manifest.")
    lifecycle = manifest.get("lifecycle", {})
    if lifecycle.get("remove") != "stop_disable_timer_remove_enablement_link_preserve_customer_data":
        raise ValueError("RPM package manifest must describe timer stop/disable behavior on removal.")
    if lifecycle.get("downgrade") != "native_package_manager_downgrade_is_explicit_admin_action":
        raise ValueError("RPM package manifest must describe explicit admin downgrade policy.")
    return manifest


def validate_rpm_query_metadata(package_path: Path, version: str) -> None:
    query = run_rpm(["-qp", "--qf", "%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n", str(package_path)])
    values = query.splitlines()
    if len(values) < 4:
        raise ValueError("RPM metadata query returned incomplete package metadata.")
    name, rpm_version_value, release, arch = values[:4]
    if name != PACKAGE_NAME:
        raise ValueError(f"RPM package name is {name}, expected {PACKAGE_NAME}.")
    if rpm_version_value != rpm_version(version):
        raise ValueError(f"RPM package version is {rpm_version_value}, expected {rpm_version(version)}.")
    if not release.startswith(RPM_RELEASE):
        raise ValueError(f"RPM package release is {release}, expected prefix {RPM_RELEASE}.")
    if arch != RPM_ARCH:
        raise ValueError(f"RPM package architecture is {arch}, expected {RPM_ARCH}.")
    license_value = run_rpm(["-qp", "--qf", "%{LICENSE}\n%{URL}\n", str(package_path)]).splitlines()
    if len(license_value) < 2:
        raise ValueError("RPM metadata query returned incomplete license/URL metadata.")
    if license_value[0] != linuxsrc.PACKAGE_LICENSE:
        raise ValueError("RPM package license metadata does not match the repository license decision.")
    if license_value[1] != linuxsrc.PACKAGE_URL:
        raise ValueError("RPM package URL metadata must be the canonical repository URL.")


def validate_rpm_payload_listing(package_path: Path) -> None:
    listing = {line.strip() for line in run_rpm(["-qpl", str(package_path)]).splitlines() if line.strip()}
    expected = {install_path(path) for path in RPM_EXPECTED_FILES} | {install_path(path) for path in RPM_EXPECTED_DIRS}
    missing = expected - listing
    if missing:
        raise ValueError(f"RPM payload listing missing expected paths: {', '.join(sorted(missing))}.")
    unexpected = [path for path in listing if FORBIDDEN_CONTENT_RE.search(PurePosixPath(path).name)]
    if unexpected:
        raise ValueError(f"RPM payload listing contains forbidden paths: {', '.join(sorted(unexpected))}.")


def validate_rpm_requires(package_path: Path) -> None:
    requires = run_rpm(["-qp", "--requires", str(package_path)])
    missing = [dependency for dependency in PACKAGE_DEPENDENCIES if dependency not in requires]
    if missing:
        raise ValueError(f"RPM package is missing required dependencies: {', '.join(missing)}.")


def validate_rpm_scriptlets(package_path: Path) -> None:
    scripts = run_rpm(["-qp", "--scripts", str(package_path)])
    missing = [item for item in SPEC_REQUIRED_TEXT if item.startswith(("groupadd", "useradd", "systemctl")) and item not in scripts]
    if missing:
        raise ValueError(f"RPM package scriptlets are missing expected lifecycle text: {', '.join(missing)}.")
    forbidden = [item for item in SPEC_FORBIDDEN_TEXT if item in scripts]
    if forbidden:
        raise ValueError(f"RPM package scriptlets contain unsafe text: {', '.join(forbidden)}.")
    guard = (
        "if [ -f /etc/openassetwatch/agent/config.json ] "
        "&& [ -f /etc/openassetwatch/agent/identity.json ]; then"
    )
    if guard not in scripts or "systemctl restart oaw-agent.timer" not in scripts:
        raise ValueError("RPM package scriptlets must guard timer restart on config and identity existence.")
    if "systemctl start oaw-agent.service" in scripts or "systemctl restart oaw-agent.service" in scripts:
        raise ValueError("RPM package scriptlets must not directly start or restart oaw-agent.service.")
    if "|| true" in scripts:
        raise ValueError("RPM package scriptlets must not hide systemd failures with unconditional || true.")
    for required in (
        "systemctl stop oaw-agent.timer",
        "systemctl disable oaw-agent.timer",
        "rm -f /etc/systemd/system/timers.target.wants/oaw-agent.timer",
        "grep -Eq '^(sudo|admin|wheel)$'",
    ):
        if required not in scripts:
            raise ValueError(f"RPM package scriptlets missing expected lifecycle text: {required}.")


def parse_rpm_dump(package_path: Path) -> dict[str, dict[str, str]]:
    dump = run_rpm(["-qp", "--dump", str(package_path)])
    entries: dict[str, dict[str, str]] = {}
    for line in dump.splitlines():
        parts = line.split()
        if len(parts) < 9:
            continue
        entries[parts[0]] = {
            "mode": parts[4],
            "owner": parts[5],
            "group": parts[6],
            "is_config": parts[7],
            "is_doc": parts[8],
        }
    if not entries:
        raise ValueError("RPM package dump returned no payload metadata.")
    return entries


def validate_rpm_dump(package_path: Path) -> None:
    entries = parse_rpm_dump(package_path)
    for package_path_value in ROOT_OWNED_PATHS:
        install_value = install_path(package_path_value)
        metadata = entries.get(install_value)
        if not metadata:
            raise ValueError(f"RPM package dump missing metadata for {install_value}.")
        if metadata["owner"] != "root" or metadata["group"] != "root":
            raise ValueError(f"RPM package {install_value} must be owned by root:root.")
    for package_path_value in SERVICE_OWNED_DIRS:
        install_value = install_path(package_path_value)
        metadata = entries.get(install_value)
        if not metadata:
            raise ValueError(f"RPM package dump missing metadata for {install_value}.")
        if metadata["owner"] != SERVICE_USER or metadata["group"] != SERVICE_GROUP:
            raise ValueError(f"RPM package {install_value} must be owned by {SERVICE_USER}:{SERVICE_GROUP}.")
    sudoers_metadata = entries.get(SUDOERS_INSTALL_PATH)
    if not sudoers_metadata or not sudoers_metadata["mode"].endswith("440"):
        raise ValueError("RPM sudoers payload must use mode 0440.")
    for helper in (IP_NEIGH_HELPER, IP_ADDR_HELPER):
        metadata = entries.get(helper)
        if not metadata or not metadata["mode"].endswith("755"):
            raise ValueError(f"RPM helper {helper} must be executable with mode 0755.")
    for example in (
        "/etc/openassetwatch/agent/config.example.json",
        "/etc/openassetwatch/agent/identity.example.json",
    ):
        metadata = entries.get(example)
        if not metadata or metadata["is_config"] != "1":
            raise ValueError(f"RPM example file {example} must be marked %config(noreplace).")


def validate_real_rpm_package(repo_root: Path, version: str, package_path: Path, checksum_path: Path, manifest_path: Path) -> None:
    validate_package_metadata(repo_root, version, package_path, checksum_path, manifest_path)
    validate_rpm_query_metadata(package_path, version)
    validate_rpm_payload_listing(package_path)
    validate_rpm_requires(package_path)
    validate_rpm_scriptlets(package_path)
    validate_rpm_dump(package_path)


def validate_rpm(
    repo_root: Path,
    version: str,
    rpm_root: Path,
    package_path: Path,
    checksum_path: Path,
    package_manifest_path: Path,
    reporter: Reporter,
) -> None:
    buildroot, spec_path, manifest_path = expected_paths(rpm_root, version)
    if not rpm_root.is_dir():
        raise ValueError(f"RPM staging root does not exist: {to_repo_relative(repo_root, rpm_root)}")
    if not spec_path.is_file():
        raise ValueError("RPM spec file is missing.")
    if not buildroot.is_dir():
        raise ValueError("RPM BUILDROOT payload root is missing.")
    if not manifest_path.is_file():
        raise ValueError("RPM staging manifest is missing.")

    validate_build_tree(rpm_root)
    reporter.check("rpm build tree", True, "RPM build tree exists.")
    validate_payload_paths(buildroot)
    reporter.check("rpm payload paths", True, "RPM staged payload paths exist.")
    validate_wrapper(buildroot)
    reporter.check("compatibility wrapper", True, "/usr/bin/oaw-agent wrapper is safe.")
    validate_service_and_timer(buildroot)
    reporter.check("service and timer", True, "Systemd service and timer use the approved run-once model.")
    validate_helpers_and_sudoers(buildroot)
    reporter.check("helper sudoers model", True, "Helpers and sudoers match the approved allowlist.")
    validate_examples(buildroot)
    reporter.check("example files", True, "Config and identity examples contain placeholders only.")
    validate_manifest(repo_root, rpm_root, buildroot, spec_path, manifest_path, version)
    reporter.check("rpm staging manifest", True, "RPM staging manifest fields are valid.")
    validate_embedded_release_manifest(manifest_path, buildroot, version)
    reporter.check("embedded release manifest", True, "Embedded release manifest metadata matches.")
    validate_forbidden_content(buildroot)
    reporter.check("forbidden content", True, "Forbidden content patterns are absent from staged payload.")
    validate_spec_file(spec_path, version)
    reporter.check("rpm spec", True, "RPM spec uses the approved scriptlet and packaging model.")
    validate_real_rpm_package(repo_root, version, package_path, checksum_path, package_manifest_path)
    reporter.check("rpm package artifact", True, "Real RPM package metadata, payload, scriptlets, and checksum are valid.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a local RPM package and staging tree for oaw-agent.")
    parser.add_argument("--version", required=True, help="Linux agent release version under dist/agent/<version>/rpm/.")
    parser.add_argument("--rpm-root", help="Optional RPM staging root. Must resolve inside the repository dist/agent tree.")
    parser.add_argument("--package", help="Optional RPM package path. Must resolve inside the repository dist/agent tree.")
    return parser.parse_args()


def build_summary(
    reporter: Reporter,
    repo_root: Path,
    version: str,
    rpm_root: Path | None,
    package_path: Path | None,
) -> dict[str, Any]:
    return {
        "ok": not reporter.errors,
        "version": version,
        "rpm_root": to_repo_relative(repo_root, rpm_root) if rpm_root else "",
        "package": to_repo_relative(repo_root, package_path) if package_path else "",
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
    package_path: Path | None = None

    try:
        version = validate_version(args.version)
        rpm_root = resolve_rpm_root(repo_root, version, args.rpm_root)
        package_path, checksum_path, package_manifest_path = resolve_rpm_package(repo_root, version, args.package)
        validate_rpm(repo_root, version, rpm_root, package_path, checksum_path, package_manifest_path, reporter)
    except Exception as exc:
        reporter.check("rpm validator", False, str(exc))

    summary = build_summary(reporter, repo_root, version, rpm_root, package_path)
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
