"""Platform abstraction for passive local software detection."""

from __future__ import annotations

import platform
import shutil
from dataclasses import dataclass

from .safety import safe_path_exists, safe_version_output


def normalize_system(system: str | None = None) -> str:
    value = (system or platform.system() or "unknown").lower()
    if value.startswith("win"):
        return "windows"
    if value == "darwin":
        return "darwin"
    if value == "linux":
        return "linux"
    return value or "unknown"


@dataclass(frozen=True)
class PlatformContext:
    """Minimal host context exposed to detectors."""

    system_key: str

    @classmethod
    def current(cls, platform_info: dict[str, object] | None = None) -> "PlatformContext":
        if platform_info:
            system_key = platform_info.get("system_key")
            if isinstance(system_key, str) and system_key:
                return cls(system_key=system_key)
        return cls(system_key=normalize_system())

    def command_path(self, command: str) -> str | None:
        return shutil.which(command)

    def command_exists(self, command: str) -> bool:
        return self.command_path(command) is not None

    def path_exists(self, path: str) -> bool:
        return safe_path_exists(path)

    def version_output(self, command: list[str]) -> str | None:
        if not command or not self.command_exists(command[0]):
            return None
        return safe_version_output(command)
