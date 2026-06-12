#!/usr/bin/env python3
from __future__ import annotations

import argparse
import platform
import shlex
import subprocess
from dataclasses import dataclass


WINDOWS_TASK_NAME = "OpenAssetWatch Collector"
WINDOWS_LOG_DIR = r"C:\ProgramData\OpenAssetWatch\Collector\logs"
LINUX_SERVICE_NAME = "openassetwatch-collector"
LINUX_LOG_DIR = "/var/log/openassetwatch"
MACOS_LABEL = "com.openassetwatch.collector"
MACOS_PLIST = "/Library/LaunchDaemons/com.openassetwatch.collector.plist"
MACOS_LOG_DIR = "/Library/Logs/OpenAssetWatch"


@dataclass(frozen=True)
class ManagedCommand:
    args: tuple[str, ...]
    check: bool = True


@dataclass(frozen=True)
class ServicePlan:
    system: str
    action: str
    commands: tuple[ManagedCommand, ...]
    notes: tuple[str, ...] = ()


def normalize_system(system: str | None = None) -> str:
    value = (system or platform.system() or "unknown").strip().lower()
    if value in {"windows", "win32"}:
        return "windows"
    if value in {"linux"}:
        return "linux"
    if value in {"darwin", "macos", "mac"}:
        return "darwin"
    return value or "unknown"


def shell_join(command: tuple[str, ...], system: str | None = None) -> str:
    if normalize_system(system) == "windows":
        return subprocess.list2cmdline(list(command))
    return " ".join(shlex.quote(part) for part in command)


def build_service_plan(action: str, system: str | None = None) -> ServicePlan:
    system_key = normalize_system(system)
    action_key = action.strip().lower()

    if system_key == "windows":
        return build_windows_plan(action_key)
    if system_key == "linux":
        return build_linux_plan(action_key)
    if system_key == "darwin":
        return build_macos_plan(action_key)
    raise ValueError(f"unsupported operating system for service management: {system_key}")


def build_windows_plan(action: str) -> ServicePlan:
    task = WINDOWS_TASK_NAME
    notes = (
        "Windows uses Task Scheduler for the MVP, not a true Windows Service.",
    )
    plans = {
        "status": (
            ManagedCommand(("schtasks.exe", "/Query", "/TN", task, "/V", "/FO", "LIST")),
            notes
            + (
                "Review Last Run Time, Last Result, and Task To Run in the scheduled task output.",
            ),
        ),
        "start": (
            ManagedCommand(("schtasks.exe", "/Run", "/TN", task)),
            notes,
        ),
        "stop": (
            ManagedCommand(("schtasks.exe", "/End", "/TN", task)),
            notes,
        ),
        "restart": (
            (
                ManagedCommand(("schtasks.exe", "/End", "/TN", task), check=False),
                ManagedCommand(("schtasks.exe", "/Run", "/TN", task)),
            ),
            notes,
        ),
        "logs": (
            (),
            (
                f"Collector runtime logs are under {WINDOWS_LOG_DIR}.",
                f"Installer log: {WINDOWS_LOG_DIR}\\install.log",
            ),
        ),
        "uninstall-info": (
            (),
            (
                "Uninstall while preserving config, logs, state, and identity:",
                "python collector\\install\\install.py --uninstall",
                "Purge local config, logs, state, and identity:",
                "python collector\\install\\install.py --uninstall --purge",
            ),
        ),
    }
    return plan_from_mapping("windows", action, plans)


def build_linux_plan(action: str) -> ServicePlan:
    plans = {
        "status": (
            ManagedCommand(("systemctl", "status", LINUX_SERVICE_NAME)),
            (),
        ),
        "start": (
            ManagedCommand(("systemctl", "start", LINUX_SERVICE_NAME)),
            (),
        ),
        "stop": (
            ManagedCommand(("systemctl", "stop", LINUX_SERVICE_NAME)),
            (),
        ),
        "restart": (
            ManagedCommand(("systemctl", "restart", LINUX_SERVICE_NAME)),
            (),
        ),
        "logs": (
            ManagedCommand(("journalctl", "-u", LINUX_SERVICE_NAME, "-n", "100", "--no-pager")),
            (f"Collector log directory: {LINUX_LOG_DIR}",),
        ),
        "uninstall-info": (
            (),
            (
                "Uninstall while preserving config, logs, state, and identity:",
                "sudo UNINSTALL=true collector/install/install-linux.sh",
                "Purge local config, logs, state, and identity:",
                "sudo UNINSTALL=true PURGE=true collector/install/install-linux.sh",
            ),
        ),
    }
    return plan_from_mapping("linux", action, plans)


def build_macos_plan(action: str) -> ServicePlan:
    plans = {
        "status": (
            ManagedCommand(("launchctl", "print", f"system/{MACOS_LABEL}")),
            (),
        ),
        "start": (
            ManagedCommand(("launchctl", "bootstrap", "system", MACOS_PLIST)),
            (),
        ),
        "stop": (
            ManagedCommand(("launchctl", "bootout", "system", MACOS_PLIST)),
            (),
        ),
        "restart": (
            (
                ManagedCommand(("launchctl", "bootout", "system", MACOS_PLIST), check=False),
                ManagedCommand(("launchctl", "bootstrap", "system", MACOS_PLIST)),
            ),
            (),
        ),
        "logs": (
            (),
            (
                f"Collector stdout log: {MACOS_LOG_DIR}/collector.out.log",
                f"Collector stderr log: {MACOS_LOG_DIR}/collector.err.log",
                f"Installer log: {MACOS_LOG_DIR}/install.log",
            ),
        ),
        "uninstall-info": (
            (),
            (
                "Uninstall while preserving config, logs, state, and identity:",
                "sudo UNINSTALL=true collector/install/install-macos.sh",
                "Purge local config, logs, state, and identity:",
                "sudo UNINSTALL=true PURGE=true collector/install/install-macos.sh",
            ),
        ),
    }
    return plan_from_mapping("darwin", action, plans)


def plan_from_mapping(
    system: str,
    action: str,
    plans: dict[str, tuple[ManagedCommand | tuple[ManagedCommand, ...] | tuple[()], tuple[str, ...]]],
) -> ServicePlan:
    if action not in plans:
        raise ValueError(f"unsupported action: {action}")
    raw_commands, notes = plans[action]
    if isinstance(raw_commands, ManagedCommand):
        commands = (raw_commands,)
    else:
        commands = tuple(raw_commands)
    return ServicePlan(system=system, action=action, commands=commands, notes=notes)


def execute_plan(plan: ServicePlan, *, dry_run: bool = False) -> int:
    for note in plan.notes:
        print(note)

    exit_code = 0
    for command in plan.commands:
        print(f"+ {shell_join(command.args, plan.system)}")
        if dry_run:
            continue
        result = subprocess.run(list(command.args), check=False)
        if result.returncode != 0 and command.check:
            return result.returncode
        if result.returncode != 0:
            exit_code = result.returncode
    return exit_code


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage the OpenAssetWatch collector service")
    parser.add_argument(
        "action",
        choices=("status", "start", "stop", "restart", "logs", "uninstall-info"),
        help="service management action to run",
    )
    parser.add_argument(
        "--system",
        choices=("windows", "linux", "darwin"),
        help="override platform detection, mainly for dry-run testing",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the native commands without running them",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        plan = build_service_plan(args.action, args.system)
    except ValueError as exc:
        print(f"error: {exc}")
        return 2
    return execute_plan(plan, dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
