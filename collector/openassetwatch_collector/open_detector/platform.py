"""Platform abstraction for passive local software detection."""

from __future__ import annotations

import platform
import shutil
import os
from dataclasses import dataclass

from .safety import safe_path_exists, safe_version_output


def normalize_system(system: str | None = None) -> str:
    source = platform.system() if system is None else system
    value = (source or "").strip().lower()
    if not value:
        return "unknown"
    if value.startswith("win"):
        return "windows"
    if value == "darwin":
        return "darwin"
    if value == "linux":
        return "linux"
    return value


def is_admin(system_key: str) -> bool:
    if system_key == "windows":
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


def privilege_level(system_key: str) -> str:
    return "admin" if is_admin(system_key) else "standard"


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

    def privilege_level(self) -> str:
        return privilege_level(self.system_key)
