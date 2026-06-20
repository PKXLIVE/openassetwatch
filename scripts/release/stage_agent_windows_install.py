#!/usr/bin/env python3
"""Stage a Windows production install layout for the OpenAssetWatch agent."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path
from typing import Any

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


TARGET_OS = "windows"
TARGET_ARCH = "amd64"
ARTIFACT_NAME = "oaw-agent.exe"
WINDOWS_INSTALL_DIR = "windows-install"
PROGRAM_FILES_BINARY = r"C:\Program Files\OpenAssetWatch\Agent\bin\oaw-agent.exe"
PROGRAMDATA_CONFIG = r"C:\ProgramData\OpenAssetWatch\Agent\config\config.json"
PROGRAMDATA_IDENTITY = r"C:\ProgramData\OpenAssetWatch\Agent\identity\identity.json"
PROGRAMDATA_STATE = r"C:\ProgramData\OpenAssetWatch\Agent\state"
PROGRAMDATA_STATUS = r"C:\ProgramData\OpenAssetWatch\Agent\state\status.json"
PROGRAMDATA_INVENTORY = r"C:\ProgramData\OpenAssetWatch\Agent\state\last-inventory.json"
PROGRAMDATA_LOGS = r"C:\ProgramData\OpenAssetWatch\Agent\logs"
SERVICE_NAME = "OpenAssetWatchAgent"
SERVICE_DISPLAY_NAME = "OpenAssetWatch Agent"
SERVICE_METADATA_RELATIVE = Path("service") / "oaw-agent-service.json"
MANIFEST_NAME = "windows-install-manifest.json"
REQUIRED_BINARY_FIELDS = (
    "artifact_name",
    "version",
    "os",
    "arch",
    "path",
    "sha256",
    "git_commit",
)
FORBIDDEN_STAGE_RE = re.compile(
    r"(token|secret|credential|password|api[_-]?key|private[_-]?key|\.log$|status\.json|\.pem$|\.key$)",
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

    def warn(self, message: str) -> None:
        self.warnings.append(message)


def artifact_paths(
    repo_root: Path, output_root: Path, version: str, artifact_dir_arg: str | None
) -> tuple[Path, Path, Path, dict[str, Any]]:
    artifact_dir = output_root / "agent" / version / f"{TARGET_OS}-{TARGET_ARCH}"
    if artifact_dir_arg:
        artifact_dir = resolve_repo_path(repo_root, artifact_dir_arg)
    if not is_inside(repo_root, artifact_dir):
        raise ValueError("Artifact directory must stay inside the repository.")
    if not artifact_dir.is_dir():
        raise ValueError(f"Windows agent artifact directory does not exist: {to_repo_relative(repo_root, artifact_dir)}")

    artifact_path = artifact_dir / ARTIFACT_NAME
    checksum_path = artifact_dir / f"{ARTIFACT_NAME}.sha256"
    manifest_path = artifact_dir / f"{ARTIFACT_NAME}.manifest.json"
    if not artifact_path.is_file():
        raise ValueError("Windows agent binary is missing.")
    if not checksum_path.is_file():
        raise ValueError("Windows agent checksum is missing.")
    if not manifest_path.is_file():
        raise ValueError("Windows agent manifest is missing.")

    manifest = read_json(manifest_path)
    missing = [field for field in REQUIRED_BINARY_FIELDS if not str(manifest.get(field, "")).strip()]
    if missing:
        raise ValueError(f"Binary manifest missing fields: {', '.join(missing)}.")
    if manifest.get("artifact_type") and manifest["artifact_type"] != "oaw-agent-binary":
        raise ValueError("Binary manifest artifact_type must be oaw-agent-binary.")
    if manifest["artifact_name"] != ARTIFACT_NAME:
        raise ValueError("Binary manifest artifact_name must be oaw-agent.exe.")
    if manifest["version"] != version:
        raise ValueError("Binary manifest version does not match requested version.")
    if manifest["os"] != TARGET_OS or manifest["arch"] != TARGET_ARCH:
        raise ValueError("Binary manifest must be for windows/amd64.")
    if resolve_repo_path(repo_root, str(manifest["path"])) != artifact_path.resolve():
        raise ValueError("Binary manifest path does not match windows agent artifact.")

    actual_hash = sha256_file(artifact_path).lower()
    checksum_text = checksum_path.read_text(encoding="ascii").strip()
    checksum_hash = checksum_text.split()[0].lower() if checksum_text else ""
    if actual_hash != str(manifest["sha256"]).lower():
        raise ValueError("Windows agent binary SHA256 does not match manifest.")
    if actual_hash != checksum_hash:
        raise ValueError("Windows agent binary SHA256 does not match checksum file.")
    return artifact_path, checksum_path, manifest_path, manifest


def windows_install_root(repo_root: Path, output_root: Path, version: str) -> Path:
    root = output_root / "agent" / version / WINDOWS_INSTALL_DIR
    if not is_inside(repo_root, root):
        raise ValueError("Windows install staging output must stay inside the repository.")
    return root


def remove_tree(path: Path) -> None:
    def remove_readonly(func: Any, item: str, _exc_info: Any) -> None:
        os.chmod(item, stat.S_IWRITE)
        func(item)

    if path.exists():
        shutil.rmtree(path, onerror=remove_readonly)


def stage_paths(root: Path) -> dict[str, Path]:
    agent_root = root / "ProgramFiles" / "OpenAssetWatch" / "Agent"
    data_root = root / "ProgramData" / "OpenAssetWatch" / "Agent"
    return {
        "binary": agent_root / "bin" / ARTIFACT_NAME,
        "config_example": data_root / "config" / "config.example.json",
        "identity_example": data_root / "identity" / "identity.example.json",
        "state_dir": data_root / "state",
        "logs_dir": data_root / "logs",
        "service_metadata": root / SERVICE_METADATA_RELATIVE,
        "manifest": root / MANIFEST_NAME,
    }


def config_example() -> dict[str, str]:
    return {
        "server_url": "https://control-tower.example.invalid",
        "site_id": "site-example",
    }


def identity_example() -> dict[str, str]:
    return {
        "site_id": "site-example",
        "agent_id": "replace-with-generated-agent-id",
        "deployment_id": "replace-with-deployment-guid",
        "tenant_id": "optional-tenant-id",
        "created_at": "replace-with-created-at",
        "updated_at": "replace-with-updated-at",
    }


def service_arguments() -> str:
    return (
        r"service run --config C:\ProgramData\OpenAssetWatch\Agent\config\config.json "
        r"--identity-file C:\ProgramData\OpenAssetWatch\Agent\identity\identity.json "
        r"--output-dir C:\ProgramData\OpenAssetWatch\Agent\state"
    )


def service_metadata() -> dict[str, Any]:
    return {
        "service_name": SERVICE_NAME,
        "display_name": SERVICE_DISPLAY_NAME,
        "executable_path": PROGRAM_FILES_BINARY,
        "arguments": service_arguments(),
        "startup_type": "automatic",
        "delayed_auto_start": True,
        "service_runtime_model": "native Windows SCM service using oaw-agent service run",
        "service_account_recommendation": "LocalService",
        "sensitive_values_embedded": False,
        "service_installed_by_this_helper": False,
        "scheduled_task_installed_by_this_helper": False,
        "scheduler_model": "internal bounded supervisor loop; Task Scheduler is not used",
    }


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def write_staging(
    repo_root: Path,
    root: Path,
    version: str,
    artifact_path: Path,
    checksum_path: Path,
    binary_manifest_path: Path,
    binary_manifest: dict[str, Any],
) -> Path:
    if root.exists():
        if not is_inside(repo_root, root):
            raise ValueError("Refusing to replace Windows install staging outside the repository.")
        remove_tree(root)

    paths = stage_paths(root)
    paths["binary"].parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(artifact_path, paths["binary"])
    write_json(paths["config_example"], config_example())
    write_json(paths["identity_example"], identity_example())
    paths["state_dir"].mkdir(parents=True, exist_ok=True)
    paths["logs_dir"].mkdir(parents=True, exist_ok=True)
    write_json(paths["service_metadata"], service_metadata())

    manifest = {
        "version": version,
        "os": TARGET_OS,
        "architecture": TARGET_ARCH,
        "source_artifact": to_repo_relative(repo_root, artifact_path),
        "source_checksum": to_repo_relative(repo_root, checksum_path),
        "source_manifest": to_repo_relative(repo_root, binary_manifest_path),
        "source_artifact_sha256": binary_manifest["sha256"],
        "windows_install_root": to_repo_relative(repo_root, root),
        "staged_paths": {name: to_repo_relative(repo_root, path) for name, path in paths.items()},
        "production_paths": {
            "binary": PROGRAM_FILES_BINARY,
            "config": PROGRAMDATA_CONFIG,
            "identity": PROGRAMDATA_IDENTITY,
            "state": PROGRAMDATA_STATE,
            "status": PROGRAMDATA_STATUS,
            "last_inventory": PROGRAMDATA_INVENTORY,
            "logs": PROGRAMDATA_LOGS,
        },
        "service_metadata": service_metadata(),
        "safety_notes": [
        "Staging output is local proof material under the requested repository-local output root.",
            "No Windows service, scheduled task, registry entry, or installer action is performed.",
            "Config and identity files are examples only; real values remain administrator-managed.",
            "State and log directories are empty placeholders in this staging layout.",
            "Windows production service execution uses oaw-agent service run, not Task Scheduler or raw run-once registration.",
        ],
        "generated_at": utc_timestamp(),
    }
    write_json(paths["manifest"], manifest)
    return paths["manifest"]


def assert_no_forbidden_terms(path: Path, label: str) -> None:
    text = path.read_text(encoding="utf-8", errors="ignore")
    if FORBIDDEN_STAGE_RE.search(text):
        raise ValueError(f"{label} contains forbidden sensitive or runtime-state terms.")


def validate_service_metadata(path: Path) -> None:
    value = read_json(path)
    expected = service_metadata()
    if value != expected:
        raise ValueError("Service metadata does not match the approved Windows staging model.")
    assert_no_forbidden_terms(path, "Service metadata")
    if value["service_name"] != SERVICE_NAME:
        raise ValueError("Service metadata service_name mismatch.")
    if value["display_name"] != SERVICE_DISPLAY_NAME:
        raise ValueError("Service metadata display_name mismatch.")
    if value["executable_path"] != PROGRAM_FILES_BINARY:
        raise ValueError("Service metadata executable_path mismatch.")
    if value["arguments"] != service_arguments():
        raise ValueError("Service metadata arguments mismatch.")
    if not value["arguments"].startswith("service run "):
        raise ValueError("Service metadata must use the native service run command.")
    if value["service_account_recommendation"] != "LocalService":
        raise ValueError("Service account recommendation must be LocalService.")
    if value.get("delayed_auto_start") is not True:
        raise ValueError("Service metadata must request delayed automatic service startup.")
    if value.get("scheduler_model") != "internal bounded supervisor loop; Task Scheduler is not used":
        raise ValueError("Service metadata must explicitly avoid Task Scheduler.")
    if value["service_installed_by_this_helper"] or value["scheduled_task_installed_by_this_helper"]:
        raise ValueError("Service metadata must show no service or scheduled task is installed.")


def validate_examples(paths: dict[str, Path]) -> None:
    config = read_json(paths["config_example"])
    if set(config) != {"server_url", "site_id"}:
        raise ValueError("Config example must contain only server_url and site_id.")
    if not str(config["server_url"]).endswith(".example.invalid"):
        raise ValueError("Config example server_url must use example.invalid.")
    if config["site_id"] != "site-example":
        raise ValueError("Config example site_id must be site-example.")

    identity = read_json(paths["identity_example"])
    expected_keys = {"site_id", "agent_id", "deployment_id", "tenant_id", "created_at", "updated_at"}
    if set(identity) != expected_keys:
        raise ValueError("Identity example contains unexpected fields.")
    for key in ("agent_id", "deployment_id", "created_at", "updated_at"):
        if not str(identity[key]).startswith("replace-with-"):
            raise ValueError(f"Identity example {key} must be an explicit placeholder.")


def validate_staging(repo_root: Path, root: Path, version: str, source_hash: str) -> None:
    if not is_inside(repo_root, root):
        raise ValueError("Windows install staging root must stay inside the repository.")
    paths = stage_paths(root)
    missing = [name for name, path in paths.items() if not path.exists()]
    if missing:
        raise ValueError(f"Windows install staging missing paths: {', '.join(missing)}.")
    if not paths["state_dir"].is_dir() or not paths["logs_dir"].is_dir():
        raise ValueError("State and logs must be staged as directories.")
    validate_examples(paths)
    validate_service_metadata(paths["service_metadata"])

    manifest = read_json(paths["manifest"])
    if manifest.get("version") != version:
        raise ValueError("Windows install manifest version mismatch.")
    if manifest.get("os") != TARGET_OS or manifest.get("architecture") != TARGET_ARCH:
        raise ValueError("Windows install manifest target mismatch.")
    if str(manifest.get("source_artifact_sha256", "")).lower() != source_hash.lower():
        raise ValueError("Windows install manifest source artifact checksum mismatch.")
    if manifest.get("service_metadata") != service_metadata():
        raise ValueError("Windows install manifest service metadata mismatch.")
    assert_no_forbidden_terms(paths["service_metadata"], "Service metadata")

    for name, path in paths.items():
        if name in {"state_dir", "logs_dir"}:
            files = [item for item in path.rglob("*") if item.is_file()]
            if files:
                raise ValueError(f"{name} must not contain generated runtime files.")
            continue
        if name in {"config_example", "identity_example", "manifest", "service_metadata"}:
            if FORBIDDEN_STAGE_RE.search(path.name):
                raise ValueError(f"Staged file has forbidden name: {path.name}.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stage a Windows install layout for oaw-agent under ignored dist output.")
    parser.add_argument("--version", required=True, help="Windows agent release version under dist/agent/<version>/windows-amd64/.")
    parser.add_argument("--output-dir", default="dist", help="Repository-local output root. Defaults to dist.")
    parser.add_argument("--artifact-dir", help="Optional explicit repository-local windows-amd64 artifact directory.")
    return parser.parse_args()


def build_summary(reporter: Reporter, repo_root: Path, version: str, root: Path | None, manifest_path: Path | None) -> dict[str, Any]:
    return {
        "ok": not reporter.errors,
        "version": version,
        "windows_install_root": to_repo_relative(repo_root, root) if root else "",
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
    root: Path | None = None
    manifest_path: Path | None = None

    try:
        version = validate_version(args.version)
        output_root = resolve_repo_path(repo_root, args.output_dir)
        if not is_inside(repo_root, output_root):
            raise ValueError("Output directory must stay inside the repository.")
        artifact_path, checksum_path, binary_manifest_path, binary_manifest = artifact_paths(
            repo_root, output_root, version, args.artifact_dir
        )
        reporter.check("windows artifact validation", True, "Windows amd64 agent artifact validation passed.")

        root = windows_install_root(repo_root, output_root, version)
        manifest_path = write_staging(
            repo_root,
            root,
            version,
            artifact_path,
            checksum_path,
            binary_manifest_path,
            binary_manifest,
        )
        reporter.check("windows install staging", True, "Windows install layout was staged under the requested repository-local output root.")

        validate_staging(repo_root, root, version, str(binary_manifest["sha256"]))
        reporter.check("windows install validation", True, "Windows staged layout matches the approved production path model.")
    except Exception as exc:
        reporter.check("windows install staging helper", False, str(exc))

    summary = build_summary(reporter, repo_root, version, root, manifest_path)
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
