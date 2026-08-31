#!/usr/bin/env python3
"""Validate generated OpenAssetWatch Windows MSI release metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from release_common import get_repo_root, is_inside, read_json, resolve_repo_path, to_repo_relative, validate_version


TARGET_ARCH = "amd64"
PACKAGE_PREFIX = "OpenAssetWatchAgent"
WXS_RELATIVE = Path("packaging") / "agent" / "windows" / "OpenAssetWatchAgent.wxs"
TABLE_VALIDATOR_RELATIVE = Path("scripts") / "release" / "validate_agent_windows_msi_tables.ps1"
WIX_NAMESPACE = "http://wixtoolset.org/schemas/v4/wxs"
UTIL_NAMESPACE = "http://wixtoolset.org/schemas/v4/wxs/util"
AGENT_SERVICE_SID = "S-1-5-80-630466807-4251148593-2853048944-3410275790-4186592652"
CREDENTIAL_DIRECTORY_SDDL = (
    "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    f"(A;OICI;0x1301bf;;;{AGENT_SERVICE_SID})"
)
MANAGED_ANCESTOR_SDDL = (
    "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)"
)
CREDENTIAL_ACL_REPAIR_COMMAND = "repair-private-state-acl"
FORBIDDEN_RE = re.compile(
    r"(credential|password|token|api[_-]?key|private[_-]?key|secret|Task Scheduler|run-once --config)",
    re.IGNORECASE,
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


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def default_paths(repo_root: Path, version: str) -> tuple[Path, Path, Path]:
    packages = repo_root / "dist" / "agent" / version / "packages"
    msi = packages / f"{PACKAGE_PREFIX}-{version}-windows-{TARGET_ARCH}.msi"
    return msi, packages / f"{msi.name}.sha256", packages / f"{msi.name}.manifest.json"


def resolve_inputs(repo_root: Path, version: str, msi_arg: str | None) -> tuple[Path, Path, Path]:
    if msi_arg:
        msi = resolve_repo_path(repo_root, msi_arg)
        checksum = Path(str(msi) + ".sha256")
        manifest = Path(str(msi) + ".manifest.json")
    else:
        msi, checksum, manifest = default_paths(repo_root, version)
    dist_root = repo_root / "dist" / "agent"
    for path in (msi, checksum, manifest):
        if not is_inside(dist_root, path):
            raise ValueError("MSI validation inputs must stay under dist/agent/.")
    return msi, checksum, manifest


def validate_checksum(msi: Path, checksum: Path, manifest: dict[str, Any]) -> None:
    if not msi.is_file():
        raise ValueError("MSI artifact is missing.")
    if not checksum.is_file():
        raise ValueError("MSI checksum file is missing.")
    actual = sha256_file(msi).lower()
    checksum_text = checksum.read_text(encoding="ascii").strip()
    checksum_hash = checksum_text.split()[0].lower() if checksum_text else ""
    if actual != checksum_hash:
        raise ValueError("MSI checksum file does not match package SHA256.")
    if actual != str(manifest.get("sha256", "")).lower():
        raise ValueError("MSI manifest SHA256 does not match package SHA256.")


def validate_manifest(repo_root: Path, version: str, msi: Path, checksum: Path, manifest_path: Path) -> dict[str, Any]:
    if not manifest_path.is_file():
        raise ValueError("MSI manifest is missing.")
    manifest = read_json(manifest_path)
    required = (
        "package_name",
        "artifact_name",
        "package_type",
        "version",
        "msi_version",
        "os",
        "arch",
        "wix_tool_version",
        "wix_util_extension",
        "source_artifact",
        "windows_install_root",
        "package_path",
        "sha256",
        "checksum",
        "git_commit",
        "generated_at",
        "signing",
    )
    missing = [field for field in required if not manifest.get(field)]
    if missing:
        raise ValueError(f"MSI manifest missing fields: {', '.join(missing)}.")
    if manifest["package_name"] != "openassetwatch-agent":
        raise ValueError("MSI manifest package_name mismatch.")
    if manifest["package_type"] != "msi":
        raise ValueError("MSI manifest package_type must be msi.")
    if manifest["version"] != version:
        raise ValueError("MSI manifest version mismatch.")
    if manifest["os"] != "windows" or manifest["arch"] != TARGET_ARCH:
        raise ValueError("MSI manifest target must be windows/amd64.")
    if manifest["wix_tool_version"] != "6.0.2":
        raise ValueError("MSI manifest must pin WiX Toolset 6.0.2.")
    if manifest["wix_util_extension"] != "WixToolset.Util.wixext/6.0.2":
        raise ValueError("MSI manifest must pin the WiX Util extension.")
    if resolve_repo_path(repo_root, str(manifest["package_path"])) != msi.resolve():
        raise ValueError("MSI manifest package_path mismatch.")
    if resolve_repo_path(repo_root, str(manifest["checksum"])) != checksum.resolve():
        raise ValueError("MSI manifest checksum path mismatch.")
    if manifest.get("signing", {}).get("signed") is not False:
        raise ValueError("Local MSI manifest must mark unsigned local artifacts explicitly.")
    return manifest


def validate_wix_source(repo_root: Path) -> None:
    wxs = repo_root / WXS_RELATIVE
    text = wxs.read_text(encoding="utf-8")
    required = (
        'Name="OpenAssetWatchAgent"',
        'InstallerVersion="500"',
        'DisplayName="OpenAssetWatch Agent"',
        'Account="NT AUTHORITY\\LocalService"',
        'Start="auto"',
        'ServiceControl',
        'Start="install"',
        'Stop="both"',
        'Remove="uninstall"',
        'service run --config',
        'util:ServiceConfig',
        'FirstFailureActionType="restart"',
        'SecondFailureActionType="restart"',
        'util:EventSource',
        'EventMessageFile="[SystemFolder]EventCreate.exe"',
        'OpenAssetWatchAgent',
        'SYSTEM\\CurrentControlSet\\Services\\OpenAssetWatchAgent',
        'DelayedAutoStart',
        'ServiceSidType',
        'Domain="NT SERVICE"',
        'User="OpenAssetWatchAgent"',
        '<Directory Id="AgentCredentialDir" Name="credential" />',
        '<Component Id="AgentCredentialDirectoryComponent"',
        'Name="CredentialDir" Type="string" Value="[AgentCredentialDir]"',
        'Id="RepairPrivateStateAcl"',
    )
    missing = [item for item in required if item not in text]
    if missing:
        raise ValueError(f"WiX source missing expected MSI/service metadata: {', '.join(missing)}.")
    if 'User="LocalService" GenericWrite="yes"' in text:
        raise ValueError("WiX source must not grant broad LocalService write ACLs.")
    if text.count('Domain="NT SERVICE" User="OpenAssetWatchAgent"') < 4:
        raise ValueError("WiX source must use service-specific SID ACLs for binary/config/identity/state/log paths.")

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("WiX source is not valid XML.") from exc
    wix = f"{{{WIX_NAMESPACE}}}"
    util = f"{{{UTIL_NAMESPACE}}}"
    for directory_id, component_id in (
        ("OpenAssetWatchProgramData", "OpenAssetWatchProgramDataAclComponent"),
        ("AgentProgramData", "AgentProgramDataAclComponent"),
    ):
        directory_ref = root.find(f".//{wix}DirectoryRef[@Id='{directory_id}']")
        ancestor_component = (
            directory_ref.find(f"{wix}Component[@Id='{component_id}']")
            if directory_ref is not None
            else None
        )
        matching_ancestors = root.findall(f".//{wix}Component[@Id='{component_id}']")
        create_folder = (
            ancestor_component.find(f"{wix}CreateFolder")
            if ancestor_component is not None
            else None
        )
        permissions = list(create_folder) if create_folder is not None else []
        if (
            ancestor_component is None
            or len(matching_ancestors) != 1
            or ancestor_component is not matching_ancestors[0]
            or len(permissions) != 1
            or permissions[0].tag != f"{wix}PermissionEx"
            or permissions[0].attrib != {"Sddl": MANAGED_ANCESTOR_SDDL}
        ):
            raise ValueError(
                "WiX managed ProgramData ancestors must use the exact protected read-only broad DACL."
            )
    credential_ref = root.find(f".//{wix}DirectoryRef[@Id='AgentCredentialDir']")
    component = (
        credential_ref.find(f"{wix}Component[@Id='AgentCredentialDirectoryComponent']")
        if credential_ref is not None
        else None
    )
    matching_components = root.findall(
        f".//{wix}Component[@Id='AgentCredentialDirectoryComponent']"
    )
    if component is None or len(matching_components) != 1 or component is not matching_components[0]:
        raise ValueError(
            "WiX credential directory component must be directly attached to AgentCredentialDir."
        )
    create_folder = component.find(f"{wix}CreateFolder") if component is not None else None
    children = list(create_folder) if create_folder is not None else []
    permission = [child for child in children if child.tag == f"{wix}PermissionEx"]
    legacy_permissions = [child for child in children if child.tag == f"{util}PermissionEx"]
    if (
        len(children) != 1
        or len(permission) != 1
        or legacy_permissions
        or permission[0].attrib != {"Sddl": CREDENTIAL_DIRECTORY_SDDL}
    ):
        raise ValueError(
            "WiX credential directory must use the exact protected service-specific DACL."
        )
    repair = root.find(f".//{wix}CustomAction[@Id='RepairPrivateStateAcl']")
    expected_repair = {
        "Id": "RepairPrivateStateAcl",
        "FileRef": "AgentExe",
        "ExeCommand": CREDENTIAL_ACL_REPAIR_COMMAND,
        "Execute": "deferred",
        "Impersonate": "no",
        "Return": "check",
    }
    sequence = root.find(
        f".//{wix}InstallExecuteSequence/{wix}Custom[@Action='RepairPrivateStateAcl']"
    )
    expected_sequence = {
        "Action": "RepairPrivateStateAcl",
        "After": "Wix4SchedSecureObjects_X64",
        "Condition": 'NOT (REMOVE~="ALL")',
    }
    if (
        repair is None
        or repair.attrib != expected_repair
        or sequence is None
        or sequence.attrib != expected_sequence
    ):
        raise ValueError(
            "WiX credential ACL repair must run deferred as SYSTEM after the protected ACL is scheduled."
        )
    sanitized = text
    for allowed in (
        "AgentCredentialDir",
        "AgentCredentialDirectoryComponent",
        'Name="credential"',
        'Name="CredentialDir"',
    ):
        sanitized = sanitized.replace(allowed, "reviewed-private-state")
    forbidden = sorted({match.group(0) for match in FORBIDDEN_RE.finditer(sanitized)})
    if forbidden:
        raise ValueError(f"WiX source contains forbidden text: {', '.join(forbidden)}.")


def validate_compiled_msi_tables(repo_root: Path, msi: Path) -> dict[str, Any] | None:
    if os.name != "nt":
        return None
    powershell = shutil.which("pwsh") or shutil.which("powershell")
    if not powershell:
        raise ValueError("PowerShell is required for compiled MSI table validation on Windows.")
    validator = repo_root / TABLE_VALIDATOR_RELATIVE
    if not validator.is_file():
        raise ValueError("Compiled MSI table validator is missing.")
    completed = subprocess.run(
        [
            powershell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(validator),
            "-Msi",
            str(msi),
        ],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise ValueError("Compiled MSI credential-security table validation failed.")
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("Compiled MSI table validator returned invalid output.") from exc
    if result.get("ok") is not True or not all(result.get("checks", {}).values()):
        raise ValueError("Compiled MSI credential-security table validation failed.")
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate generated OpenAssetWatch Windows MSI artifacts.")
    parser.add_argument("--version", required=True, help="Release version under dist/agent/<version>/.")
    parser.add_argument("--msi", help="Optional explicit MSI path under dist/agent/.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    repo_root = get_repo_root()
    version = ""
    msi: Path | None = None

    try:
        version = validate_version(args.version)
        msi, checksum, manifest_path = resolve_inputs(repo_root, version, args.msi)
        manifest = validate_manifest(repo_root, version, msi, checksum, manifest_path)
        reporter.check("msi manifest", True, "MSI manifest fields are present and consistent.")
        validate_checksum(msi, checksum, manifest)
        reporter.check("msi checksum", True, "MSI checksum matches the artifact and manifest.")
        validate_wix_source(repo_root)
        reporter.check("wix source", True, "WiX source contains the approved native service model.")
        compiled = validate_compiled_msi_tables(repo_root, msi)
        if compiled is None:
            reporter.warnings.append(
                "Compiled MSI table validation requires Windows Installer APIs and was not run."
            )
        else:
            reporter.check(
                "compiled msi tables",
                True,
                "Compiled MSI contains the approved credential ACL and pre-service repair action.",
            )
    except Exception as exc:
        reporter.check("windows msi validator", False, str(exc))

    summary = {
        "ok": not reporter.errors,
        "version": version,
        "msi": to_repo_relative(repo_root, msi) if msi else "",
        "checks": reporter.checks,
        "warnings": reporter.warnings,
        "errors": reporter.errors,
    }
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
