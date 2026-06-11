"""Platform and tool capability detection for collector hosts."""

from __future__ import annotations

import os
import platform
import shutil
import sys


SUPPORTED_MODES = ["device", "network", "hybrid"]

COMMANDS_BY_SYSTEM = {
    "windows": [
        "arp",
        "ipconfig",
        "getmac",
        "powershell",
        "netsh",
        "nslookup",
        "ping",
        "nmap",
    ],
    "linux": [
        "ip",
        "arp",
        "arp-scan",
        "nmap",
        "avahi-resolve-address",
        "avahi-browse",
        "nmblookup",
        "dig",
        "nslookup",
        "hostname",
        "nmcli",
        "tcpdump",
        "zeek",
    ],
    "darwin": [
        "arp",
        "ifconfig",
        "route",
        "networksetup",
        "dns-sd",
        "scutil",
        "nmap",
        "tcpdump",
    ],
}

COMMAND_ALIASES = {
    "powershell": ["powershell", "powershell.exe", "pwsh", "pwsh.exe"],
}

ARCHITECTURE_FAMILIES = {
    "amd64": "x86_64",
    "x64": "x86_64",
    "x86_64": "x86_64",
    "i386": "x86",
    "i686": "x86",
    "x86": "x86",
    "arm64": "arm64",
    "arm64e": "arm64",
    "aarch64": "arm64",
    "armel": "arm",
    "armhf": "arm",
    "armv5": "arm",
    "armv5l": "arm",
    "armv6": "arm",
    "armv6l": "arm",
    "armv7": "arm",
    "armv7a": "arm",
    "armv7l": "arm",
    "armv8": "arm64",
    "armv8l": "arm64",
}


def normalize_system(system: str) -> str:
    value = system.lower()
    if not value:
        return "unknown"
    if value == "darwin":
        return "darwin"
    if value.startswith("win"):
        return "windows"
    if value == "linux":
        return "linux"
    return value


def architecture_family(machine: str) -> str:
    normalized = machine.lower()
    return ARCHITECTURE_FAMILIES.get(normalized, normalized or "unknown")


def command_available(command: str) -> bool:
    candidates = COMMAND_ALIASES.get(command, [command])
    return any(shutil.which(candidate) for candidate in candidates)


def command_sets(system_key: str) -> tuple[list[str], list[str]]:
    commands = COMMANDS_BY_SYSTEM.get(system_key, [])
    available = [command for command in commands if command_available(command)]
    missing = [command for command in commands if command not in available]
    return available, missing


def available_only(names: list[str], available_commands: list[str]) -> list[str]:
    available = set(available_commands)
    return [name for name in names if name in available]


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


def recommended_modes(system_key: str, available_commands: list[str]) -> list[str]:
    available = set(available_commands)
    modes = ["device"]

    if system_key == "windows" and {"powershell", "arp"} & available:
        modes.append("network")
    elif system_key == "linux" and {"ip", "arp"} & available:
        modes.append("network")
    elif system_key == "darwin" and "arp" in available:
        modes.append("network")
    elif "arp" in available:
        modes.append("network")

    if "network" in modes:
        modes.append("hybrid")

    return modes


def future_fingerprinting_tools(
    system_key: str,
    available_commands: list[str],
) -> dict[str, list[str]]:
    if system_key == "windows":
        return {
            "passive": [],
            "active_light": available_only(["arp", "ping", "nmap"], available_commands),
            "name_resolution": available_only(["nslookup"], available_commands),
            "netbios": available_only(["netsh"], available_commands),
            "mdns": [],
            "sensor": [],
        }

    if system_key == "linux":
        return {
            "passive": available_only(["tcpdump"], available_commands),
            "active_light": available_only(["ip", "arp", "arp-scan", "nmap"], available_commands),
            "name_resolution": available_only(["dig", "nslookup", "hostname"], available_commands),
            "netbios": available_only(["nmblookup"], available_commands),
            "mdns": available_only(["avahi-resolve-address", "avahi-browse"], available_commands),
            "sensor": available_only(["zeek"], available_commands),
        }

    if system_key == "darwin":
        return {
            "passive": available_only(["tcpdump"], available_commands),
            "active_light": available_only(["arp", "route", "nmap"], available_commands),
            "name_resolution": available_only(["dns-sd", "scutil"], available_commands),
            "netbios": [],
            "mdns": available_only(["dns-sd"], available_commands),
            "sensor": [],
        }

    return {
        "passive": [],
        "active_light": [],
        "name_resolution": [],
        "netbios": [],
        "mdns": [],
        "sensor": [],
    }


def collect_platform_capabilities() -> dict[str, object]:
    system = platform.system()
    system_name = system or "unknown"
    release = platform.release()
    machine = platform.machine()
    family = architecture_family(machine)
    system_key = normalize_system(system)
    available_commands, missing_commands = command_sets(system_key)
    admin = is_admin(system_key)

    return {
        "system_key": system_key,
        "system": system_name,
        "release": release or None,
        "architecture": machine or None,
        "architecture_family": family,
        "is_arm": family in {"arm", "arm64"},
        "is_64bit": sys.maxsize > 2**32 or family in {"x86_64", "arm64"} or "64" in machine.lower(),
        "is_admin": admin,
        "privilege_level": "admin" if admin else "standard",
        "available_commands": available_commands,
        "missing_commands": missing_commands,
        "supported_modes": SUPPORTED_MODES,
        "recommended_modes": recommended_modes(system_key, available_commands),
        "future_fingerprinting_tools": future_fingerprinting_tools(
            system_key,
            available_commands,
        ),
    }
