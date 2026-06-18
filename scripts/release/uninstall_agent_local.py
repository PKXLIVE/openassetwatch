#!/usr/bin/env python3
"""Remove a repo-local OpenAssetWatch agent sandbox install proof."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any


LAYOUT_DIRS = ("binary", "config", "identity", "logs", "status", "service", "package-metadata")
SYSTEM_PATH_RE = re.compile(
    r"(^|[\\/])(program files|programdata|usr|etc|var|library)([\\/]|$)",
    re.IGNORECASE,
)


class Reporter:
    def __init__(self) -> None:
        self.removed: list[str] = []
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

    def add_removed(self, repo_root: Path, path: Path) -> None:
        self.removed.append(to_repo_relative(repo_root, path))


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


def looks_like_system_path(value: str | None, resolved: Path | None = None) -> bool:
    values: list[str] = []
    if value:
        values.append(value.strip().replace("\\", "/"))
    if resolved is not None:
        values.append(str(resolved).replace("\\", "/"))
    for item in values:
        lowered = item.lower()
        if lowered.startswith(("/usr", "/etc", "/var", "/library")):
            return True
        if SYSTEM_PATH_RE.search(lowered):
            return True
    return False


def resolve_repo_path(repo_root: Path, value: str) -> Path:
    if not value:
        raise ValueError("Path value cannot be empty.")
    if looks_like_system_path(value):
        raise ValueError("Refusing path that looks like a system path.")

    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    resolved = candidate.resolve()
    if looks_like_system_path(value, resolved):
        raise ValueError("Refusing path that looks like a system path.")
    if not is_inside(repo_root, resolved):
        raise ValueError("Path must resolve inside the repository.")
    return resolved


def sandbox_base(repo_root: Path) -> Path:
    return repo_root / "dist" / "local-install" / "agent"


def validate_sandbox_root(repo_root: Path, install_root: Path) -> tuple[str, str]:
    base = sandbox_base(repo_root).resolve()
    if not is_inside(base, install_root):
        raise ValueError("Install root must be under dist/local-install/agent/.")
    relative_parts = install_root.resolve().relative_to(base).parts
    if len(relative_parts) != 2:
        raise ValueError("Install root must match dist/local-install/agent/<version>/<os>-<arch>/.")
    version, target = relative_parts
    if "-" not in target:
        raise ValueError("Install root target directory must look like <os>-<arch>.")
    return version, target


def find_install_root(repo_root: Path, version: str) -> Path:
    if not version:
        raise ValueError("Version cannot be empty.")
    if looks_like_system_path(version):
        raise ValueError("Version cannot look like a system path.")

    version_root = sandbox_base(repo_root) / version
    candidates = [path for path in sorted(version_root.iterdir()) if path.is_dir()] if version_root.exists() else []
    if not candidates:
        raise ValueError(f"No sandbox install root found under {to_repo_relative(repo_root, version_root)}.")
    if len(candidates) > 1:
        raise ValueError(
            f"Multiple sandbox install roots found under {to_repo_relative(repo_root, version_root)}; use --install-root."
        )
    return candidates[0].resolve()


def metadata_complete(install_root: Path) -> tuple[bool, list[str]]:
    missing: list[str] = []
    for name in LAYOUT_DIRS:
        if not (install_root / name).is_dir():
            missing.append(f"{name}/")

    package_metadata = install_root / "package-metadata"
    if package_metadata.is_dir():
        if not list(package_metadata.glob("*.tar.gz.manifest.json")):
            missing.append("package-metadata/*.tar.gz.manifest.json")
        if not list(package_metadata.glob("*.tar.gz.sha256")):
            missing.append("package-metadata/*.tar.gz.sha256")
        if not [path for path in package_metadata.glob("*.manifest.json") if ".tar.gz." not in path.name]:
            missing.append("package-metadata/<binary>.manifest.json")
        if not [path for path in package_metadata.glob("*.sha256") if ".tar.gz." not in path.name]:
            missing.append("package-metadata/<binary>.sha256")
    return not missing, missing


def collect_paths(root: Path) -> list[Path]:
    paths = sorted(root.rglob("*"), key=lambda value: len(value.parts), reverse=True)
    paths.append(root)
    return paths


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Remove a local oaw-agent sandbox install proof.")
    parser.add_argument("--version", help="Release version under dist/local-install/agent/<version>/.")
    parser.add_argument("--install-root", help="Repo-local sandbox install root to remove.")
    parser.add_argument("--force", action="store_true", help="Remove an incomplete repo-local sandbox install root.")
    return parser.parse_args()


def build_summary(reporter: Reporter, repo_root: Path, install_root: Path | None) -> dict[str, Any]:
    return {
        "ok": not reporter.errors,
        "install_root": to_repo_relative(repo_root, install_root) if install_root else "",
        "removed": reporter.removed,
        "checks": reporter.checks,
        "warnings": reporter.warnings,
        "errors": reporter.errors,
    }


def main() -> int:
    args = parse_args()
    reporter = Reporter()
    repo_root = get_repo_root()
    install_root: Path | None = None

    try:
        if args.install_root:
            install_root = resolve_repo_path(repo_root, args.install_root)
        elif args.version:
            install_root = find_install_root(repo_root, args.version)
        else:
            raise ValueError("Either --version or --install-root is required.")

        validate_sandbox_root(repo_root, install_root)
        reporter.check("sandbox root", True, "Install root is a repo-local sandbox install root.")

        if looks_like_system_path(str(install_root)):
            raise ValueError("Refusing install root that looks like a system path.")
        reporter.check("system path refusal", True, "Install root does not look like a system path.")

        if not install_root.exists() or not install_root.is_dir():
            raise ValueError("Install root does not exist or is not a directory.")
        reporter.check("install root exists", True, "Install root exists.")

        complete, missing = metadata_complete(install_root)
        if not complete and not args.force:
            raise ValueError(f"Install root metadata is incomplete: {', '.join(missing)}.")
        if complete:
            reporter.check("install metadata", True, "Install root metadata is complete.")
        else:
            reporter.warn(f"Install metadata incomplete; --force allowed removal: {', '.join(missing)}.")
            reporter.check("install metadata", True, "--force allowed incomplete metadata.")

        for path in collect_paths(install_root):
            reporter.add_removed(repo_root, path)
        shutil.rmtree(install_root)
        reporter.check("sandbox uninstall", True, "Sandbox install root removed.")
    except Exception as exc:
        reporter.check("sandbox uninstall", False, str(exc))

    summary = build_summary(reporter, repo_root, install_root)
    print(json.dumps(summary, indent=2))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
