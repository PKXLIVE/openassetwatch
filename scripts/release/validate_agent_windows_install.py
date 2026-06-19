#!/usr/bin/env python3
"""Validate a staged Windows install layout for the OpenAssetWatch agent."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from package_agent_deb import (
    get_repo_root,
    is_inside,
    read_json,
    resolve_repo_path,
    to_repo_relative,
    validate_version,
)
from stage_agent_windows_install import (
    MANIFEST_NAME,
    PROGRAMDATA_CONFIG,
    PROGRAMDATA_IDENTITY,
    PROGRAMDATA_STATE,
    PROGRAM_FILES_BINARY,
    SERVICE_DISPLAY_NAME,
    SERVICE_METADATA_RELATIVE,
    SERVICE_NAME,
    TARGET_ARCH,
    WINDOWS_INSTALL_DIR,
    service_arguments,
    service_metadata,
    stage_paths,
    windows_install_root,
)


FORBIDDEN_METADATA_RE = re.compile(
    r"(credential|password|token|api[_-]?key|private[_-]?key|secret)",
    re.IGNORECASE,
)
FORBIDDEN_ACTION_RE = re.compile(
    r"("
    r"sc(?:\.exe)?\s+create|"
    r"New-Service|"
    r"Start-Service|"
    r"Stop-Service|"
    r"msiexec|"
    r"installer\s+commands?|"
    r"reg(?:\.exe)?\s+(?:add|delete|import)|"
    r"Set-ItemProperty|"
    r"New-ItemProperty|"
    r"Remove-ItemProperty"
    r")",
    re.IGNORECASE,
)
INSTALL_INTENT_KEYS = (
    "service_installed_by_this_helper",
    "scheduled_task_installed_by_this_helper",
    "installed_by_this_helper",
    "registry_modified_by_this_helper",
)
INSTALL_HELPER_RELATIVE = Path("scripts") / "release" / "install_agent_windows_service.ps1"
UNINSTALL_HELPER_RELATIVE = Path("scripts") / "release" / "uninstall_agent_windows_service.ps1"
FILE_INSTALL_HELPER_RELATIVE = Path("scripts") / "release" / "install_agent_windows_files.ps1"
FILE_UNINSTALL_HELPER_RELATIVE = Path("scripts") / "release" / "uninstall_agent_windows_files.ps1"
HELPER_SECRET_ASSIGNMENT_RE = re.compile(
    r"(credential|password|token|api[_-]?key|private[_-]?key|secret)\s*=",
    re.IGNORECASE,
)
HELPER_FORBIDDEN_RE = re.compile(
    r"(msiexec|reg(?:\.exe)?\s+(?:add|delete|import)|Set-ItemProperty|"
    r"New-ItemProperty|Remove-ItemProperty|Get-Credential|PSCredential|"
    r"ConvertTo-SecureString|Write-Host)",
    re.IGNORECASE,
)
FILE_HELPER_FORBIDDEN_RE = re.compile(
    r"(sc(?:\.exe)?\s|New-Service|Start-Service|Stop-Service|Set-Service|"
    r"Get-Service|msiexec|reg(?:\.exe)?\s+(?:add|delete|import)|"
    r"Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|"
    r"Invoke-WebRequest|Invoke-RestMethod|Get-Credential|PSCredential|"
    r"ConvertTo-SecureString|Write-Host)",
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


def resolve_windows_install_root(repo_root: Path, version: str, root_arg: str | None) -> Path:
    if root_arg:
        root = resolve_repo_path(repo_root, root_arg)
    else:
        root = windows_install_root(repo_root, version)
    if not is_inside(repo_root / "dist" / "agent", root):
        raise ValueError("Windows install root must resolve under dist/agent/.")
    return root


def validate_layout(root: Path) -> None:
    paths = stage_paths(root)
    missing = [name for name, path in paths.items() if not path.exists()]
    if missing:
        raise ValueError(f"Windows install staging missing paths: {', '.join(missing)}.")
    if not paths["binary"].is_file():
        raise ValueError("Staged Windows agent binary must be a file.")
    if not paths["config_example"].is_file():
        raise ValueError("Staged Windows config example must be a file.")
    if not paths["identity_example"].is_file():
        raise ValueError("Staged Windows identity example must be a file.")
    if not paths["state_dir"].is_dir():
        raise ValueError("Staged Windows state path must be a directory.")
    if not paths["logs_dir"].is_dir():
        raise ValueError("Staged Windows logs path must be a directory.")
    if not paths["service_metadata"].is_file():
        raise ValueError("Staged Windows service metadata must be a file.")
    if not paths["manifest"].is_file():
        raise ValueError("Staged Windows install manifest must be a file.")


def validate_example_files(root: Path) -> None:
    paths = stage_paths(root)
    config = read_json(paths["config_example"])
    if set(config) != {"server_url", "site_id"}:
        raise ValueError("Windows config example must contain only server_url and site_id.")
    if not str(config["server_url"]).endswith(".example.invalid"):
        raise ValueError("Windows config example server_url must use example.invalid.")
    if config["site_id"] != "site-example":
        raise ValueError("Windows config example site_id must be site-example.")

    identity = read_json(paths["identity_example"])
    expected_identity_keys = {"site_id", "agent_id", "deployment_id", "tenant_id", "created_at", "updated_at"}
    if set(identity) != expected_identity_keys:
        raise ValueError("Windows identity example contains unexpected fields.")
    if identity["site_id"] != "site-example":
        raise ValueError("Windows identity example site_id must be site-example.")
    if identity["tenant_id"] != "optional-tenant-id":
        raise ValueError("Windows identity example tenant_id must be optional-tenant-id.")
    for key in ("agent_id", "deployment_id", "created_at", "updated_at"):
        if not str(identity[key]).startswith("replace-with-"):
            raise ValueError(f"Windows identity example {key} must be an explicit placeholder.")


def assert_no_forbidden_metadata_text(path: Path, label: str) -> None:
    text = path.read_text(encoding="utf-8", errors="ignore")
    if FORBIDDEN_METADATA_RE.search(text):
        raise ValueError(f"{label} contains credential, password, token, API key, or secret markers.")


def assert_no_forbidden_actions(path: Path, label: str) -> None:
    text = path.read_text(encoding="utf-8", errors="ignore")
    found = sorted({match.group(0) for match in FORBIDDEN_ACTION_RE.finditer(text)})
    if found:
        raise ValueError(f"{label} contains forbidden install/service/registry command text: {', '.join(found)}.")


def validate_no_install_intent(value: dict[str, Any], label: str) -> None:
    def walk(node: Any, path: str = "") -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                child_path = f"{path}.{key}" if path else str(key)
                if key in INSTALL_INTENT_KEYS and child is not False:
                    raise ValueError(f"{label} must not mark {child_path} as installed or modified.")
                walk(child, child_path)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f"{path}[{index}]")

    walk(value)


def validate_service_metadata_file(path: Path) -> dict[str, Any]:
    value = read_json(path)
    expected = service_metadata()
    if value != expected:
        raise ValueError("Windows service metadata does not match the approved staging model.")
    if value.get("service_name") != SERVICE_NAME:
        raise ValueError("Windows service metadata service_name mismatch.")
    if value.get("display_name") != SERVICE_DISPLAY_NAME:
        raise ValueError("Windows service metadata display_name mismatch.")
    if value.get("executable_path") != PROGRAM_FILES_BINARY:
        raise ValueError("Windows service metadata executable path mismatch.")
    arguments = str(value.get("arguments", ""))
    if arguments != service_arguments():
        raise ValueError("Windows service metadata arguments mismatch.")
    if "run-once" not in arguments.split():
        raise ValueError("Windows service metadata arguments must use run-once.")
    for expected_path in (PROGRAMDATA_CONFIG, PROGRAMDATA_IDENTITY, PROGRAMDATA_STATE):
        if expected_path not in arguments:
            raise ValueError(f"Windows service metadata arguments missing expected path: {expected_path}")
    if value.get("startup_type") != "automatic":
        raise ValueError("Windows service metadata startup_type must be automatic.")
    if value.get("service_account_recommendation") != "LocalService":
        raise ValueError("Windows service metadata service account recommendation must be LocalService.")
    validate_no_install_intent(value, "Windows service metadata")
    if value.get("timer_recommendation", {}).get("windows_has_systemd_timers") is not False:
        raise ValueError("Windows service metadata must note that Windows does not have systemd timers.")
    assert_no_forbidden_metadata_text(path, "Windows service metadata")
    return value


def validate_manifest(repo_root: Path, root: Path, version: str, service_value: dict[str, Any]) -> None:
    paths = stage_paths(root)
    manifest = read_json(paths["manifest"])
    required_fields = (
        "version",
        "os",
        "architecture",
        "source_artifact",
        "source_checksum",
        "source_manifest",
        "source_artifact_sha256",
        "windows_install_root",
        "staged_paths",
        "production_paths",
        "service_metadata",
        "safety_notes",
        "generated_at",
    )
    missing = [field for field in required_fields if not manifest.get(field)]
    if missing:
        raise ValueError(f"Windows install manifest missing fields: {', '.join(missing)}.")
    if manifest["version"] != version:
        raise ValueError("Windows install manifest version mismatch.")
    if manifest["os"] != "windows" or manifest["architecture"] != TARGET_ARCH:
        raise ValueError("Windows install manifest target must be windows/amd64.")
    if len(str(manifest["source_artifact_sha256"])) != 64:
        raise ValueError("Windows install manifest source artifact checksum must be a SHA256 hex value.")
    if manifest["service_metadata"] != service_value:
        raise ValueError("Windows install manifest service metadata must match service metadata file.")
    expected_staged_paths = {name: to_repo_relative(repo_root, path) for name, path in paths.items()}
    if manifest["staged_paths"] != expected_staged_paths:
        raise ValueError("Windows install manifest staged paths do not match the staged layout.")
    if manifest["windows_install_root"] != to_repo_relative(repo_root, root):
        raise ValueError("Windows install manifest root path mismatch.")
    expected_production_paths = {
        "binary": PROGRAM_FILES_BINARY,
        "config": PROGRAMDATA_CONFIG,
        "identity": PROGRAMDATA_IDENTITY,
        "state": PROGRAMDATA_STATE,
        "logs": r"C:\ProgramData\OpenAssetWatch\Agent\logs",
    }
    if manifest["production_paths"] != expected_production_paths:
        raise ValueError("Windows install manifest production paths mismatch.")
    if not isinstance(manifest["safety_notes"], list) or not manifest["safety_notes"]:
        raise ValueError("Windows install manifest safety notes must be a non-empty list.")
    validate_no_install_intent(manifest, "Windows install manifest")
    assert_no_forbidden_metadata_text(paths["manifest"], "Windows install manifest")


def validate_safety(root: Path) -> None:
    paths = stage_paths(root)
    for name in ("service_metadata", "manifest"):
        assert_no_forbidden_actions(paths[name], f"Windows {name}")


def validate_helper_script(path: Path, helper_name: str) -> str:
    if not path.is_file():
        raise ValueError(f"{helper_name} is missing.")
    text = path.read_text(encoding="utf-8-sig")
    if HELPER_SECRET_ASSIGNMENT_RE.search(text):
        raise ValueError(f"{helper_name} appears to contain hardcoded secret assignment text.")
    forbidden = sorted({match.group(0) for match in HELPER_FORBIDDEN_RE.finditer(text)})
    if forbidden:
        raise ValueError(f"{helper_name} contains unsafe helper text: {', '.join(forbidden)}.")
    if "[switch]$DryRun" not in text:
        raise ValueError(f"{helper_name} must support -DryRun.")
    if "Test-IsAdministrator" not in text or "WindowsBuiltInRole]::Administrator" not in text:
        raise ValueError(f"{helper_name} must include an administrator check.")
    if "Administrator rights are required" not in text:
        raise ValueError(f"{helper_name} must fail closed for real non-admin execution.")
    if "ConvertTo-Json" not in text:
        raise ValueError(f"{helper_name} must output JSON.")
    if "Write-Output" in text or "Write-Error" in text or "Write-Information" in text:
        raise ValueError(f"{helper_name} must not write non-JSON output streams explicitly.")
    return text


def validate_install_helper(repo_root: Path) -> None:
    text = validate_helper_script(repo_root / INSTALL_HELPER_RELATIVE, "Windows service install helper")
    required = (
        "[string]$InstallRoot",
        "[string]$ServiceMetadata",
        "[switch]$Start",
        '$ServiceAccount = "NT AUTHORITY\\LocalService"',
        "$createArgs = @(",
        '"create"',
        '"binPath="',
        "$binaryPath",
        '"start="',
        '"auto"',
        '"DisplayName="',
        "$metadata.display_name",
        '"obj="',
        "$ServiceAccount",
        "Invoke-ScExe",
        "& sc.exe @Arguments",
        "Set-ScCreateDiagnostics",
        "sc_create",
        "exit_code",
        "stdout",
        "stderr",
        "arguments",
        "account",
        "binary_path",
        "Sanitize-Text",
        "Read-ServiceMetadata",
        "Staged oaw-agent.exe is missing",
        "Config directory is missing",
        "Identity directory is missing",
    )
    missing = [item for item in required if item not in text]
    if missing:
        raise ValueError(f"Windows service install helper missing expected text: {', '.join(missing)}.")
    if "Start-Service" in text and "if ($Start)" not in text:
        raise ValueError("Windows service install helper must start service only when -Start is supplied.")
    forbidden_joined_args = (
        '"binPath= $binaryPath"',
        '"start= auto"',
        '"DisplayName= $($metadata.display_name)"',
        '"obj= $ServiceAccount"',
    )
    joined_present = [item for item in forbidden_joined_args if item in text]
    if joined_present:
        raise ValueError(f"Windows service install helper must separate sc.exe option names and values: {', '.join(joined_present)}.")
    if "service_installed_by_this_helper -ne $false" not in text:
        raise ValueError("Windows service install helper must reject metadata that claims staging installed the service.")


def validate_uninstall_helper(repo_root: Path) -> None:
    text = validate_helper_script(repo_root / UNINSTALL_HELPER_RELATIVE, "Windows service uninstall helper")
    required = (
        "[string]$ServiceName",
        "[string]$ServiceMetadata",
        "[switch]$Stop",
        "[switch]$RemoveState",
        "sc.exe delete",
        "Preserve config, identity, logs, and state",
        "InstallRoot is required with -RemoveState",
    )
    missing = [item for item in required if item not in text]
    if missing:
        raise ValueError(f"Windows service uninstall helper missing expected text: {', '.join(missing)}.")
    if "Start-Service" in text:
        raise ValueError("Windows service uninstall helper must not start services.")
    if "Stop-Service" in text and "if ($Stop" not in text:
        raise ValueError("Windows service uninstall helper must stop service only when -Stop is supplied.")
    for line in text.splitlines():
        if "Remove-Item" in line and ("config" in line.lower() or "identity" in line.lower()):
            raise ValueError("Windows service uninstall helper must not remove config or identity paths.")


def validate_helpers(repo_root: Path) -> None:
    validate_install_helper(repo_root)
    validate_uninstall_helper(repo_root)
    validate_file_install_helper(repo_root)
    validate_file_uninstall_helper(repo_root)


def validate_file_helper_script(path: Path, helper_name: str) -> str:
    if not path.is_file():
        raise ValueError(f"{helper_name} is missing.")
    text = path.read_text(encoding="utf-8-sig")
    if HELPER_SECRET_ASSIGNMENT_RE.search(text):
        raise ValueError(f"{helper_name} appears to contain hardcoded secret assignment text.")
    forbidden = sorted({match.group(0) for match in FILE_HELPER_FORBIDDEN_RE.finditer(text)})
    if forbidden:
        raise ValueError(f"{helper_name} contains unsafe helper text: {', '.join(forbidden)}.")
    if "[switch]$DryRun" not in text:
        raise ValueError(f"{helper_name} must support -DryRun.")
    if "Test-IsAdministrator" not in text or "WindowsBuiltInRole]::Administrator" not in text:
        raise ValueError(f"{helper_name} must include an administrator check.")
    if "Administrator rights are required" not in text:
        raise ValueError(f"{helper_name} must fail closed for real non-admin execution.")
    if "ConvertTo-Json" not in text:
        raise ValueError(f"{helper_name} must output JSON.")
    if "Write-Output" in text or "Write-Error" in text or "Write-Information" in text:
        raise ValueError(f"{helper_name} must not write non-JSON output streams explicitly.")
    return text


def validate_file_install_helper(repo_root: Path) -> None:
    text = validate_file_helper_script(repo_root / FILE_INSTALL_HELPER_RELATIVE, "Windows file install helper")
    required = (
        "[string]$WindowsInstallRoot",
        "ProgramFiles\\OpenAssetWatch\\Agent\\bin\\oaw-agent.exe",
        "ProgramData\\OpenAssetWatch\\Agent\\config",
        "ProgramData\\OpenAssetWatch\\Agent\\identity",
        "ProgramData\\OpenAssetWatch\\Agent\\state",
        "ProgramData\\OpenAssetWatch\\Agent\\logs",
        "config.example.json",
        "identity.example.json",
        "service\\oaw-agent-service.json",
        "windows-install-manifest.json",
        "Copy-Item",
        "Set-DirectoryAcl",
        "NT AUTHORITY\\LOCAL SERVICE",
        "Administrators and SYSTEM retain full control",
        "No broad Everyone or Users write access is granted",
        "Preserve config.json and identity.json",
    )
    missing = [item for item in required if item not in text]
    if missing:
        raise ValueError(f"Windows file install helper missing expected text: {', '.join(missing)}.")
    if "config.json" in text and "Copy-Item -LiteralPath $staged.config_example" not in text:
        raise ValueError("Windows file install helper must copy only config.example.json, not real config.json.")
    if "identity.json" in text and "Copy-Item -LiteralPath $staged.identity_example" not in text:
        raise ValueError("Windows file install helper must copy only identity.example.json, not real identity.json.")


def validate_file_uninstall_helper(repo_root: Path) -> None:
    text = validate_file_helper_script(repo_root / FILE_UNINSTALL_HELPER_RELATIVE, "Windows file uninstall helper")
    required = (
        "[string]$ProgramFilesAgentRoot",
        "[string]$ProgramDataAgentRoot",
        "[string]$ServiceMetadata",
        "[switch]$RemoveState",
        "[switch]$RemoveLogs",
        "ProgramFilesAgentRoot or ServiceMetadata is required",
        "Assert-OpenAssetWatchRoot",
        "Preserve ProgramData config and identity directories by default",
        "Preserve ProgramData state unless -RemoveState is supplied",
        "Preserve ProgramData logs unless -RemoveLogs is supplied",
        "Remove-DirectoryIfEmpty",
        "Remove-DirectoryTreeIfPresent",
    )
    missing = [item for item in required if item not in text]
    if missing:
        raise ValueError(f"Windows file uninstall helper missing expected text: {', '.join(missing)}.")
    for line in text.splitlines():
        lowered = line.lower()
        if "remove-item" in lowered and ("config" in lowered or "identity" in lowered):
            raise ValueError("Windows file uninstall helper must not remove config or identity paths.")


def validate_windows_install(repo_root: Path, version: str, root: Path, reporter: Reporter) -> None:
    if not root.is_dir():
        raise ValueError(f"Windows install root does not exist: {to_repo_relative(repo_root, root)}")
    expected_name = WINDOWS_INSTALL_DIR
    if root.name != expected_name:
        raise ValueError(f"Windows install root must end with {expected_name}.")

    validate_layout(root)
    reporter.check("windows staged layout", True, "Windows staged layout paths exist.")
    validate_example_files(root)
    reporter.check("windows example files", True, "Windows config and identity examples are placeholders only.")
    service_value = validate_service_metadata_file(root / SERVICE_METADATA_RELATIVE)
    reporter.check("windows service metadata", True, "Windows service metadata matches the approved staging model.")
    validate_manifest(repo_root, root, version, service_value)
    reporter.check("windows install manifest", True, "Windows install manifest fields and staged paths are valid.")
    validate_safety(root)
    reporter.check("windows install safety", True, "Windows metadata contains no install, service, registry, or secret markers.")
    validate_helpers(repo_root)
    reporter.check("windows service helpers", True, "Windows service install and uninstall helpers match the approved dry-run model.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a staged Windows install layout for oaw-agent.")
    parser.add_argument("--version", required=True, help="Windows agent release version under dist/agent/<version>/windows-install/.")
    parser.add_argument(
        "--windows-install-root",
        help="Optional staged Windows install root. Must resolve inside the repository dist/agent tree.",
    )
    return parser.parse_args()


def build_summary(reporter: Reporter, repo_root: Path, version: str, root: Path | None) -> dict[str, Any]:
    return {
        "ok": not reporter.errors,
        "version": version,
        "windows_install_root": to_repo_relative(repo_root, root) if root else "",
        "checks": reporter.checks,
        "warnings": reporter.warnings,
        "errors": reporter.errors,
    }


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    repo_root = get_repo_root()
    version = ""
    root: Path | None = None

    try:
        version = validate_version(args.version)
        root = resolve_windows_install_root(repo_root, version, args.windows_install_root)
        validate_windows_install(repo_root, version, root, reporter)
    except Exception as exc:
        reporter.check("windows install validator", False, str(exc))

    summary = build_summary(reporter, repo_root, version, root)
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
