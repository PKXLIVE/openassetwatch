"""Safety helpers for passive software detection."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


MAX_VERSION_OUTPUT_LENGTH = 160


def expand_path(path: str) -> str:
    return os.path.expanduser(os.path.expandvars(path))


def safe_path_exists(path: str) -> bool:
    """Check path existence without reading file contents."""

    try:
        return Path(expand_path(path)).exists()
    except (OSError, RuntimeError, ValueError):
        return False


def is_path_within_base(path: str, base_path: str) -> bool:
    """Return whether a resolved path stays inside an expected base path."""

    try:
        resolved_path = Path(expand_path(path)).resolve(strict=False)
        resolved_base = Path(expand_path(base_path)).resolve(strict=False)
        return resolved_path == resolved_base or resolved_base in resolved_path.parents
    except (OSError, RuntimeError, ValueError):
        return False


def safe_version_output(command: list[str]) -> str | None:
    """Run a short, read-only version command and return one compact line."""

    if not command:
        return None

    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    output = result.stdout.strip() or result.stderr.strip()
    if not output:
        return None

    line = output.splitlines()[0].strip()
    if not line:
        return None

    return line[:MAX_VERSION_OUTPUT_LENGTH]
