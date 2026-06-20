#!/usr/bin/env python3
"""Validate a staged macOS LaunchDaemon install layout for OpenAssetWatch."""

from __future__ import annotations

import argparse
import json
import plistlib
import re
from pathlib import Path
from typing import Any

from package_agent_deb import (
    get_repo_root,
    is_inside,
    read_json,
    resolve_repo_path,
    sha256_file,
    to_repo_relative,
    validate_version,
)
from stage_agent_macos_install import (
    BINARY_PATH,
    CONFIG_PATH,
    IDENTITY_PATH,
    INSTALL_MANIFEST_PATH,
    INVENTORY_PATH,
    LAUNCHD_LABEL,
    LOG_DIR,
    MACOS_INSTALL_DIR,
    PACKAGE_ID,
    PLIST_PATH,
    SERVICE_GROUP,
    SERVICE_USER,
    STATE_DIR,
    STATUS_PATH,
    macos_install_root,
    production_paths,
    stage_paths,
)


FORBIDDEN_SCRIPT_RE = re.compile(
    r"(curl|wget|nc |ncat|nmap|tcpdump|/bin/sh\s+-c|launchctl\s+load|launchctl\s+unload|"
    r"StartInterval|StartCalendarInterval|Authorization:|api[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)
FORBIDDEN_DATA_NAMES = {"config.json", "identity.json", "status.json", "last-inventory.json"}
EXPECTED_PROGRAM_ARGUMENTS = [
    BINARY_PATH,
    "service",
    "run",
    "--config",
    CONFIG_PATH,
    "--identity-file",
    IDENTITY_PATH,
    "--output-dir",
    STATE_DIR,
]


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


def resolve_macos_install_root(repo_root: Path, version: str, root_arg: str | None) -> Path:
    if root_arg:
        root = resolve_repo_path(repo_root, root_arg)
    else:
        root = macos_install_root(repo_root, repo_root / "dist", version)
    if not is_inside(repo_root / "dist" / "agent", root):
        raise ValueError("macOS install root must resolve under dist/agent/.")
    return root


def validate_layout(root: Path) -> dict[str, Path]:
    paths = stage_paths(root)
    missing = [name for name, path in paths.items() if not path.exists()]
    if missing:
        raise ValueError(f"macOS install staging missing paths: {', '.join(missing)}.")
    if not paths["binary"].is_file():
        raise ValueError("staged macOS agent binary must be a file.")
    if not paths["plist"].is_file():
        raise ValueError("staged LaunchDaemon plist must be a file.")
    for name in ("state_dir", "logs_dir"):
        if not paths[name].is_dir():
            raise ValueError(f"staged {name} must be a directory.")
    return paths


def validate_no_runtime_data(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink() and not is_inside(root, path.resolve()):
            raise ValueError(f"staged symlink escapes root: {path}")
        if path.name in FORBIDDEN_DATA_NAMES:
            raise ValueError(f"staging must not include runtime data file: {path.name}")


def validate_examples(paths: dict[str, Path]) -> None:
    config = read_json(paths["config_example"])
    identity = read_json(paths["identity_example"])
    if config.get("server_url") != "https://control-tower.example.invalid":
        raise ValueError("macOS config example must use example.invalid.")
    for field in ("agent_id", "deployment_id", "created_at", "updated_at"):
        if not str(identity.get(field, "")).startswith("replace-with-"):
            raise ValueError(f"macOS identity example {field} must be a placeholder.")


def validate_plist(paths: dict[str, Path]) -> None:
    with paths["plist"].open("rb") as handle:
        plist = plistlib.load(handle)
    expected = {
        "Label": LAUNCHD_LABEL,
        "ProgramArguments": EXPECTED_PROGRAM_ARGUMENTS,
        "UserName": SERVICE_USER,
        "GroupName": SERVICE_GROUP,
        "RunAtLoad": True,
        "ThrottleInterval": 60,
        "ProcessType": "Background",
        "ExitTimeOut": 30,
        "WorkingDirectory": STATE_DIR,
        "Umask": 0o027,
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
    }
    for key, value in expected.items():
        if plist.get(key) != value:
            raise ValueError(f"LaunchDaemon plist {key} = {plist.get(key)!r}, want {value!r}.")
    if plist.get("KeepAlive") != {"Crashed": True}:
        raise ValueError("LaunchDaemon plist KeepAlive must restart crashed daemon only.")
    for forbidden in ("StartInterval", "StartCalendarInterval", "EnvironmentVariables"):
        if forbidden in plist:
            raise ValueError(f"LaunchDaemon plist must not contain {forbidden}.")
    if any("/bin/sh" in str(arg) or "sh -c" in str(arg) for arg in plist["ProgramArguments"]):
        raise ValueError("LaunchDaemon ProgramArguments must not invoke a shell.")


def validate_manifest(repo_root: Path, root: Path, paths: dict[str, Path]) -> None:
    manifest = read_json(paths["manifest"])
    install_manifest = read_json(paths["install_manifest"])
    if manifest.get("package_identifier") != PACKAGE_ID:
        raise ValueError("macOS staging manifest package identifier mismatch.")
    if manifest.get("launchd_label") != LAUNCHD_LABEL:
        raise ValueError("macOS staging manifest launchd label mismatch.")
    if manifest.get("service_account") != SERVICE_USER or manifest.get("service_group") != SERVICE_GROUP:
        raise ValueError("macOS staging manifest service principal mismatch.")
    if manifest.get("production_paths") != production_paths():
        raise ValueError("macOS staging manifest production paths mismatch.")
    if install_manifest.get("production_paths") != production_paths():
        raise ValueError("embedded install manifest production paths mismatch.")
    required_paths = {
        "binary": BINARY_PATH,
        "config": CONFIG_PATH,
        "identity": IDENTITY_PATH,
        "state_dir": STATE_DIR,
        "status": STATUS_PATH,
        "inventory": INVENTORY_PATH,
        "log_dir": LOG_DIR,
        "launchdaemon": PLIST_PATH,
        "install_manifest": INSTALL_MANIFEST_PATH,
    }
    for key, value in required_paths.items():
        if manifest["production_paths"].get(key) != value:
            raise ValueError(f"production path {key} mismatch.")
    artifact = resolve_repo_path(repo_root, str(manifest["source_artifact"]))
    if not is_inside(repo_root, artifact):
        raise ValueError("source artifact path escapes repository.")
    if sha256_file(artifact).lower() != str(manifest["source_artifact_sha256"]).lower():
        raise ValueError("source artifact SHA256 does not match staging manifest.")
    for name, rel_path in manifest.get("staged_paths", {}).items():
        staged_path = resolve_repo_path(repo_root, str(rel_path))
        if not is_inside(root, staged_path):
            raise ValueError(f"staged path {name} escapes macOS staging root.")


def validate_scripts(paths: dict[str, Path]) -> None:
    for name in ("preinstall", "postinstall"):
        text = paths[name].read_text(encoding="utf-8")
        if FORBIDDEN_SCRIPT_RE.search(text):
            raise ValueError(f"{name} contains a forbidden command or sensitive marker.")
        if "launchctl load" in text or "launchctl unload" in text:
            raise ValueError(f"{name} must use modern launchctl bootstrap/bootout commands.")
        if "curl" in text or "wget" in text:
            raise ValueError(f"{name} must not make network calls.")
    postinstall = paths["postinstall"].read_text(encoding="utf-8")
    for required in (
        "/usr/bin/dscl . -create",
        "/bin/launchctl bootstrap system",
        "/bin/launchctl enable \"system/$LABEL\"",
        "/bin/launchctl kickstart -k \"system/$LABEL\"",
        "/bin/launchctl print \"system/$LABEL\"",
        "/usr/bin/plutil -lint",
        "/var/empty",
        "/usr/bin/false",
    ):
        if required not in postinstall:
            raise ValueError(f"postinstall missing required behavior: {required}")
    preinstall = paths["preinstall"].read_text(encoding="utf-8")
    if "/bin/launchctl bootout system" not in preinstall:
        raise ValueError("preinstall must boot out an existing daemon before upgrade.")
    uninstall = Path(__file__).with_name("uninstall_agent_macos.sh")
    if uninstall.exists():
        uninstall_text = uninstall.read_text(encoding="utf-8")
        if "has_symlink_component" not in uninstall_text:
            raise ValueError("macOS uninstaller must refuse symlink components during cleanup.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--macos-install-root")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    root_display = ""
    try:
        version = validate_version(args.version)
        repo_root = get_repo_root()
        root = resolve_macos_install_root(repo_root, version, args.macos_install_root)
        root_display = to_repo_relative(repo_root, root)
        paths = validate_layout(root)
        validate_no_runtime_data(root)
        validate_examples(paths)
        validate_plist(paths)
        validate_manifest(repo_root, root, paths)
        validate_scripts(paths)
        reporter.check("macos staged layout", True, "macOS staged LaunchDaemon layout paths exist.")
        reporter.check("macos launchd plist", True, "LaunchDaemon plist matches production service run model.")
        reporter.check("macos package scripts", True, "Package scripts use safe modern launchctl lifecycle behavior.")
    except Exception as exc:
        reporter.check("macos install validator", False, str(exc))

    result = {
        "ok": not reporter.errors,
        "version": args.version,
        "macos_install_root": root_display,
        "checks": reporter.checks,
        "warnings": reporter.warnings,
        "errors": reporter.errors,
    }
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
