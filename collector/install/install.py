#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import venv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


INSTALLER_VERSION = "0.1.0"
DEFAULT_MODE = "hybrid"
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 3600
DEFAULT_INVENTORY_INTERVAL_SECONDS = 86400
LINUX_USER = "openassetwatch"
LINUX_GROUP = "openassetwatch"
LINUX_SERVICE_NAME = "openassetwatch-collector.service"
WINDOWS_TASK_NAME = "OpenAssetWatch Collector"


@dataclass(frozen=True)
class InstallPaths:
    install_dir: Path
    config_path: Path
    logs_dir: Path
    state_dir: Path

    @property
    def venv_dir(self) -> Path:
        return self.install_dir / ".venv"


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def collector_source_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def detect_system() -> str:
    return platform.system().lower()


def default_paths(system: str) -> InstallPaths:
    if system == "windows":
        return InstallPaths(
            install_dir=Path(r"C:\Program Files\OpenAssetWatch\Collector"),
            config_path=Path(r"C:\ProgramData\OpenAssetWatch\Collector\config.yaml"),
            logs_dir=Path(r"C:\ProgramData\OpenAssetWatch\Collector\logs"),
            state_dir=Path(r"C:\ProgramData\OpenAssetWatch\Collector\state"),
        )
    if system == "linux":
        return InstallPaths(
            install_dir=Path("/opt/openassetwatch/collector"),
            config_path=Path("/etc/openassetwatch/collector.yaml"),
            logs_dir=Path("/var/log/openassetwatch"),
            state_dir=Path("/var/lib/openassetwatch"),
        )
    if system == "darwin":
        return InstallPaths(
            install_dir=Path("/usr/local/openassetwatch/collector"),
            config_path=Path("/Library/Application Support/OpenAssetWatch/Collector/config.yaml"),
            logs_dir=Path("/Library/Logs/OpenAssetWatch"),
            state_dir=Path("/Library/Application Support/OpenAssetWatch/Collector/state"),
        )
    raise SystemExit(f"unsupported operating system: {platform.system() or 'unknown'}")


def display_command(command: list[str]) -> str:
    if os.name == "nt":
        return subprocess.list2cmdline([str(part) for part in command])
    return " ".join(shlex.quote(str(part)) for part in command)


def run(command: list[str], *, dry_run: bool, check: bool = True) -> subprocess.CompletedProcess[str] | None:
    print(f"+ {display_command(command)}")
    if dry_run:
        return None
    return subprocess.run([str(part) for part in command], check=check, text=True)


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def command_succeeds(command: list[str], *, dry_run: bool) -> bool:
    if dry_run:
        print(f"+ {display_command(command)}")
        return False
    return subprocess.run([str(part) for part in command], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def venv_python(paths: InstallPaths, system: str) -> Path:
    if system == "windows":
        return paths.venv_dir / "Scripts" / "python.exe"
    return paths.venv_dir / "bin" / "python"


def metadata_path(paths: InstallPaths) -> Path:
    return paths.config_path.parent / "install.env"


def installer_log_path(paths: InstallPaths) -> Path:
    return paths.logs_dir / "install.log"


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def log_event(paths: InstallPaths, message: str, *, dry_run: bool) -> None:
    line = f"{timestamp()} {message}"
    if dry_run:
        print(f"log: {line}")
        return
    try:
        paths.logs_dir.mkdir(parents=True, exist_ok=True)
        with installer_log_path(paths).open("a", encoding="utf-8") as log_file:
            log_file.write(f"{line}\n")
    except OSError as exc:
        print(f"warning: unable to write installer log: {exc}")


def python_version(command: Path | str) -> str | None:
    try:
        result = subprocess.run(
            [
                str(command),
                "-c",
                "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip() or None


def python_is_supported(command: Path | str) -> bool:
    try:
        return (
            subprocess.run(
                [
                    str(command),
                    "-c",
                    "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        )
    except OSError:
        return False


def ensure_directory(path: Path, *, dry_run: bool) -> None:
    print(f"create directory: {path}")
    if not dry_run:
        path.mkdir(parents=True, exist_ok=True)


def create_directories(paths: InstallPaths, *, dry_run: bool) -> None:
    ensure_directory(paths.install_dir, dry_run=dry_run)
    ensure_directory(paths.config_path.parent, dry_run=dry_run)
    ensure_directory(paths.logs_dir, dry_run=dry_run)
    ensure_directory(paths.state_dir, dry_run=dry_run)


def create_venv(paths: InstallPaths, system: str, *, dry_run: bool) -> None:
    python_path = venv_python(paths, system)
    if python_path.exists():
        existing_version = python_version(python_path) or "unknown"
        if not python_is_supported(python_path):
            print(
                f"existing venv uses unsupported Python {existing_version}; recreating {paths.venv_dir}"
            )
            log_event(
                paths,
                f"venv recreation required existing_python_version={existing_version} venv={paths.venv_dir}",
                dry_run=dry_run,
            )
            if not dry_run:
                shutil.rmtree(paths.venv_dir)
        else:
            print(f"venv exists: {paths.venv_dir} ({existing_version})")
            log_event(
                paths,
                f"venv exists python_version={existing_version} venv={paths.venv_dir}",
                dry_run=dry_run,
            )
            return

    if python_path.exists():
        print(f"venv exists: {paths.venv_dir}")
        return
    print(f"create virtual environment: {paths.venv_dir}")
    log_event(paths, f"venv create start venv={paths.venv_dir}", dry_run=dry_run)
    if not dry_run:
        venv.EnvBuilder(with_pip=True).create(paths.venv_dir)
    log_event(paths, f"venv create complete venv={paths.venv_dir}", dry_run=dry_run)


def install_collector_package(paths: InstallPaths, system: str, *, dry_run: bool) -> None:
    log_event(paths, "package install start", dry_run=dry_run)
    run(
        [str(venv_python(paths, system)), "-m", "pip", "install", str(collector_source_dir())],
        dry_run=dry_run,
    )
    log_event(paths, "package install complete", dry_run=dry_run)


def yaml_text(args: argparse.Namespace) -> str:
    collector_id = args.collector_id or f"{socket.gethostname()}-collector"
    collector_name = args.collector_name or socket.gethostname()
    return "\n".join(
        [
            "collector:",
            f"  id: {yaml_scalar(collector_id)}",
            f"  name: {yaml_scalar(collector_name)}",
            f"  mode: {args.mode}",
            "",
            "backend:",
            f"  url: {yaml_scalar(args.backend_url)}",
            "",
            "checkin:",
            "  enabled: true",
            "",
            "inventory:",
            "  upload_enabled: true",
            "",
            "scheduler:",
            "  enabled: true",
            f"  heartbeat_interval_seconds: {args.heartbeat_interval_seconds}",
            f"  inventory_interval_seconds: {args.inventory_interval_seconds}",
            "",
        ]
    )


def yaml_scalar(value: object) -> str:
    return json.dumps(str(value))


def write_config(paths: InstallPaths, args: argparse.Namespace, *, dry_run: bool) -> None:
    print(f"write/update config: {paths.config_path}")
    log_event(paths, f"config write/update path={paths.config_path}", dry_run=dry_run)
    text = yaml_text(args)
    if dry_run:
        print(text)
        return
    paths.config_path.write_text(text, encoding="utf-8")


def write_metadata(paths: InstallPaths, args: argparse.Namespace, system: str, *, dry_run: bool) -> None:
    selected_python = Path(sys.executable)
    selected_version = python_version(selected_python) or platform.python_version()
    text = "\n".join(
        [
            f"INSTALLER_VERSION={INSTALLER_VERSION}",
            f"INSTALL_TIMESTAMP={datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}",
            f"PLATFORM={system}",
            f"SELECTED_PYTHON_PATH={selected_python}",
            f"SELECTED_PYTHON_VERSION={selected_version}",
            f"VENV_PYTHON_PATH={venv_python(paths, system)}",
            f"BACKEND_URL={args.backend_url}",
            f"COLLECTOR_ID={args.collector_id or f'{socket.gethostname()}-collector'}",
            "",
        ]
    )
    path = metadata_path(paths)
    print(f"write install metadata: {path}")
    log_event(paths, f"metadata write/update path={path}", dry_run=dry_run)
    if dry_run:
        print(text)
        return
    path.write_text(text, encoding="utf-8")


def write_windows_wrapper(paths: InstallPaths, *, dry_run: bool) -> None:
    wrapper_path = paths.install_dir / "run-collector.cmd"
    python_path = venv_python(paths, "windows")
    text = "\n".join(
        [
            "@echo off",
            f'"{python_path}" -m openassetwatch_collector --run-forever --config "{paths.config_path}"',
            "",
        ]
    )
    print(f"write helper wrapper: {wrapper_path}")
    if not dry_run:
        wrapper_path.write_text(text, encoding="utf-8")


def install_windows_task(paths: InstallPaths, args: argparse.Namespace, *, dry_run: bool) -> None:
    python_path = venv_python(paths, "windows")
    task_command = f'"{python_path}" -m openassetwatch_collector --run-forever --config "{paths.config_path}"'
    run(
        [
            "schtasks.exe",
            "/Create",
            "/TN",
            args.windows_task_name,
            "/SC",
            "ONSTART",
            "/RU",
            "SYSTEM",
            "/RL",
            "HIGHEST",
            "/F",
            "/TR",
            task_command,
        ],
        dry_run=dry_run,
    )
    log_event(paths, f"windows scheduled task create/update name={args.windows_task_name}", dry_run=dry_run)
    if not args.no_start:
        run(["schtasks.exe", "/Run", "/TN", args.windows_task_name], dry_run=dry_run)
        log_event(paths, f"windows scheduled task start requested name={args.windows_task_name}", dry_run=dry_run)


def remove_path(path: Path, *, dry_run: bool) -> None:
    print(f"remove path: {path}")
    if dry_run:
        return
    if path.is_dir():
        shutil.rmtree(path, ignore_errors=True)
    else:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def uninstall_windows(paths: InstallPaths, args: argparse.Namespace, *, dry_run: bool) -> int:
    log_event(paths, "uninstall start platform=windows", dry_run=dry_run)
    run(["schtasks.exe", "/End", "/TN", args.windows_task_name], dry_run=dry_run, check=False)
    log_event(paths, f"windows scheduled task stop requested name={args.windows_task_name}", dry_run=dry_run)
    run(["schtasks.exe", "/Delete", "/TN", args.windows_task_name, "/F"], dry_run=dry_run, check=False)
    log_event(paths, f"windows scheduled task delete requested name={args.windows_task_name}", dry_run=dry_run)
    remove_path(paths.install_dir, dry_run=dry_run)
    log_event(paths, f"removed install directory path={paths.install_dir}", dry_run=dry_run)
    if args.purge:
        log_event(paths, f"purge requested path={paths.config_path.parent}", dry_run=dry_run)
        log_event(paths, "uninstall complete platform=windows purge=true", dry_run=dry_run)
        remove_path(paths.config_path.parent, dry_run=dry_run)
    else:
        print(f"preserving config/log/state directory: {paths.config_path.parent}")
        log_event(paths, f"preserved config/log/state path={paths.config_path.parent}", dry_run=dry_run)
        log_event(paths, "uninstall complete platform=windows", dry_run=dry_run)
    return 0


def ensure_linux_root(*, dry_run: bool) -> None:
    if dry_run:
        return
    if os.geteuid() != 0:
        raise SystemExit("Linux installation must be run as root. Re-run with sudo.")


def ensure_linux_user(*, dry_run: bool) -> None:
    if not command_succeeds(["getent", "group", LINUX_GROUP], dry_run=dry_run):
        run(["groupadd", "--system", LINUX_GROUP], dry_run=dry_run)
    if not command_succeeds(["id", "-u", LINUX_USER], dry_run=dry_run):
        shell = "/usr/sbin/nologin" if Path("/usr/sbin/nologin").exists() else "/bin/false"
        run(
            [
                "useradd",
                "--system",
                "--gid",
                LINUX_GROUP,
                "--home-dir",
                "/var/lib/openassetwatch",
                "--shell",
                shell,
                "--no-create-home",
                LINUX_USER,
            ],
            dry_run=dry_run,
        )
    if command_exists("passwd"):
        run(["passwd", "-l", LINUX_USER], dry_run=dry_run, check=False)
    elif command_exists("usermod"):
        run(["usermod", "-L", LINUX_USER], dry_run=dry_run, check=False)


def linux_chown(path: Path, owner: str, *, recursive: bool, dry_run: bool) -> None:
    command = ["chown"]
    if recursive:
        command.append("-R")
    command.extend([owner, str(path)])
    run(command, dry_run=dry_run)


def linux_chmod(path: Path, mode: str, *, dry_run: bool) -> None:
    run(["chmod", mode, str(path)], dry_run=dry_run)


def configure_linux_permissions(paths: InstallPaths, *, dry_run: bool) -> None:
    install_metadata_path = metadata_path(paths)
    linux_chown(Path("/opt/openassetwatch"), f"{LINUX_USER}:{LINUX_GROUP}", recursive=True, dry_run=dry_run)
    linux_chown(paths.logs_dir, f"{LINUX_USER}:{LINUX_GROUP}", recursive=True, dry_run=dry_run)
    linux_chown(paths.state_dir, f"{LINUX_USER}:{LINUX_GROUP}", recursive=True, dry_run=dry_run)
    linux_chown(paths.config_path.parent, f"root:{LINUX_GROUP}", recursive=False, dry_run=dry_run)
    linux_chown(paths.config_path, f"root:{LINUX_GROUP}", recursive=False, dry_run=dry_run)
    if dry_run or install_metadata_path.exists():
        linux_chown(install_metadata_path, f"root:{LINUX_GROUP}", recursive=False, dry_run=dry_run)
        linux_chmod(install_metadata_path, "0640", dry_run=dry_run)
    linux_chmod(paths.config_path, "0640", dry_run=dry_run)


def write_linux_systemd_service(paths: InstallPaths, *, dry_run: bool) -> None:
    service_path = Path("/etc/systemd/system") / LINUX_SERVICE_NAME
    python_path = venv_python(paths, "linux")
    text = "\n".join(
        [
            "[Unit]",
            "Description=OpenAssetWatch Collector",
            "After=network-online.target",
            "Wants=network-online.target",
            "",
            "[Service]",
            "Type=simple",
            f"User={LINUX_USER}",
            f"Group={LINUX_GROUP}",
            f"WorkingDirectory={paths.install_dir}",
            (
                "ExecStart="
                f"{python_path} -m openassetwatch_collector --run-forever --config {paths.config_path}"
            ),
            "Restart=always",
            "RestartSec=30",
            "StandardOutput=journal",
            "StandardError=journal",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )
    print(f"write systemd service: {service_path}")
    log_event(paths, f"linux systemd service write/update path={service_path}", dry_run=dry_run)
    if not dry_run:
        service_path.write_text(text, encoding="utf-8")
    linux_chown(service_path, "root:root", recursive=False, dry_run=dry_run)
    linux_chmod(service_path, "0644", dry_run=dry_run)


def sudoers_entries() -> list[str]:
    entries: list[str] = []
    candidates = [
        ("ip", ["neigh show", "addr show"]),
        ("arp", ["-a"]),
        ("hostname", [""]),
    ]
    for command, arg_sets in candidates:
        command_path = shutil.which(command)
        if not command_path:
            continue
        for args in arg_sets:
            suffix = f" {args}" if args else ""
            entries.append(f"{LINUX_USER} ALL=(root) NOPASSWD: {command_path}{suffix}")
    return entries


def write_linux_sudoers(*, dry_run: bool) -> None:
    entries = sudoers_entries()
    if not entries:
        print("no sudoers entries created: no allowlisted commands found")
        return
    if not command_exists("visudo") and not dry_run:
        raise SystemExit("visudo is required to validate sudoers rules")

    sudoers_path = Path("/etc/sudoers.d/openassetwatch-collector")
    temp_path = Path("/tmp/openassetwatch-collector.sudoers")
    text = "\n".join(
        [
            "# OpenAssetWatch collector command allowlist.",
            "# Never grant unrestricted sudo.",
            *entries,
            "",
        ]
    )
    print(f"write sudoers allowlist: {sudoers_path}")
    if dry_run:
        print(text)
        return

    temp_path.write_text(text, encoding="utf-8")
    try:
        run(["visudo", "-cf", str(temp_path)], dry_run=False)
        shutil.copyfile(temp_path, sudoers_path)
        linux_chown(sudoers_path, "root:root", recursive=False, dry_run=False)
        linux_chmod(sudoers_path, "0440", dry_run=False)
        run(["visudo", "-cf", str(sudoers_path)], dry_run=False)
    finally:
        try:
            temp_path.unlink()
        except OSError:
            pass


def configure_linux_log_read(*, dry_run: bool) -> None:
    for group_name in ("adm", "systemd-journal"):
        if command_succeeds(["getent", "group", group_name], dry_run=dry_run):
            run(["usermod", "-aG", group_name, LINUX_USER], dry_run=dry_run)


def install_linux_service(paths: InstallPaths, args: argparse.Namespace, *, dry_run: bool) -> None:
    ensure_linux_root(dry_run=dry_run)
    ensure_linux_user(dry_run=dry_run)
    configure_linux_permissions(paths, dry_run=dry_run)
    if args.write_sudoers:
        write_linux_sudoers(dry_run=dry_run)
        log_event(paths, "linux sudoers write/update requested", dry_run=dry_run)
    if args.enable_log_read:
        configure_linux_log_read(dry_run=dry_run)
    write_linux_systemd_service(paths, dry_run=dry_run)
    if command_exists("systemctl") or dry_run:
        run(["systemctl", "daemon-reload"], dry_run=dry_run)
        log_event(paths, "linux systemd daemon-reload complete", dry_run=dry_run)
        run(["systemctl", "enable", LINUX_SERVICE_NAME], dry_run=dry_run)
        log_event(paths, f"linux systemd enable service={LINUX_SERVICE_NAME}", dry_run=dry_run)
        if not args.no_start:
            run(["systemctl", "restart", LINUX_SERVICE_NAME], dry_run=dry_run)
            log_event(paths, f"linux systemd restart service={LINUX_SERVICE_NAME}", dry_run=dry_run)
    else:
        print("systemctl not found; service file written but not enabled or started")


def uninstall_linux(paths: InstallPaths, args: argparse.Namespace, *, dry_run: bool) -> int:
    ensure_linux_root(dry_run=dry_run)
    log_event(paths, "uninstall start platform=linux", dry_run=dry_run)
    if command_exists("systemctl") or dry_run:
        run(["systemctl", "disable", "--now", LINUX_SERVICE_NAME], dry_run=dry_run, check=False)
        log_event(paths, f"linux systemd disable/stop service={LINUX_SERVICE_NAME}", dry_run=dry_run)
    remove_path(Path("/etc/systemd/system") / LINUX_SERVICE_NAME, dry_run=dry_run)
    log_event(paths, f"linux systemd service file removed service={LINUX_SERVICE_NAME}", dry_run=dry_run)
    remove_path(Path("/etc/sudoers.d/openassetwatch-collector"), dry_run=dry_run)
    log_event(paths, "linux sudoers file removed if present", dry_run=dry_run)
    if command_exists("systemctl") or dry_run:
        run(["systemctl", "daemon-reload"], dry_run=dry_run, check=False)
    remove_path(paths.install_dir, dry_run=dry_run)
    log_event(paths, f"removed install directory path={paths.install_dir}", dry_run=dry_run)
    if args.purge:
        log_event(paths, "purge requested platform=linux", dry_run=dry_run)
        log_event(paths, "uninstall complete platform=linux purge=true", dry_run=dry_run)
        remove_path(paths.config_path.parent, dry_run=dry_run)
        remove_path(paths.logs_dir, dry_run=dry_run)
        remove_path(paths.state_dir, dry_run=dry_run)
    else:
        print(f"preserving config directory: {paths.config_path.parent}")
        print(f"preserving logs directory: {paths.logs_dir}")
        print(f"preserving state directory: {paths.state_dir}")
        log_event(paths, "preserved config/log/state platform=linux", dry_run=dry_run)
        log_event(paths, "uninstall complete platform=linux", dry_run=dry_run)
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Install the OpenAssetWatch collector locally.")
    parser.add_argument("--backend-url", help="Backend URL reachable from this collector host.")
    parser.add_argument("--collector-id", help="Stable collector ID. Defaults to '<hostname>-collector'.")
    parser.add_argument("--collector-name", help="Human-readable collector name. Defaults to hostname.")
    parser.add_argument("--mode", choices=("device", "network", "hybrid"), default=DEFAULT_MODE)
    parser.add_argument(
        "--heartbeat-interval-seconds",
        type=positive_int,
        default=DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
    )
    parser.add_argument(
        "--inventory-interval-seconds",
        type=positive_int,
        default=DEFAULT_INVENTORY_INTERVAL_SECONDS,
    )
    parser.add_argument("--install-dir", type=Path, help="Override collector install directory.")
    parser.add_argument("--config-path", type=Path, help="Override collector config path.")
    parser.add_argument("--logs-dir", type=Path, help="Override collector logs directory.")
    parser.add_argument("--state-dir", type=Path, help="Override collector state directory.")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without changing the host.")
    parser.add_argument("--no-start", action="store_true", help="Install service/task without starting it.")
    parser.add_argument("--uninstall", action="store_true", help="Remove service/task and installed collector files.")
    parser.add_argument(
        "--purge",
        action="store_true",
        default=os.environ.get("PURGE", "").lower() == "true",
        help="With --uninstall, remove config, logs, and state too. Also honors PURGE=true.",
    )
    parser.add_argument(
        "--windows-task-name",
        default=WINDOWS_TASK_NAME,
        help="Windows Task Scheduler task name.",
    )
    parser.add_argument(
        "--write-sudoers",
        action="store_true",
        help="Linux only: create a narrow sudoers allowlist for collector commands.",
    )
    parser.add_argument(
        "--enable-log-read",
        action="store_true",
        help="Linux only: add collector user to log-reading groups when they exist.",
    )
    return parser.parse_args()


def resolve_paths(args: argparse.Namespace, system: str) -> InstallPaths:
    defaults = default_paths(system)
    return InstallPaths(
        install_dir=args.install_dir or defaults.install_dir,
        config_path=args.config_path or defaults.config_path,
        logs_dir=args.logs_dir or defaults.logs_dir,
        state_dir=args.state_dir or defaults.state_dir,
    )


def main() -> int:
    args = parse_args()
    system = detect_system()
    paths = resolve_paths(args, system)

    if system == "darwin":
        raise SystemExit("macOS launchd installation is documented for future work but not implemented yet")
    if system == "linux":
        ensure_linux_root(dry_run=args.dry_run)
    if not args.uninstall and not args.backend_url:
        raise SystemExit("--backend-url is required for installation")

    print(f"detected system: {system}")
    print(f"installer version: {INSTALLER_VERSION}")
    print(f"selected Python: {sys.executable} ({platform.python_version()})")
    log_event(
        paths,
        f"selected python path={sys.executable} version={platform.python_version()}",
        dry_run=args.dry_run,
    )
    print(f"collector source: {collector_source_dir()}")
    print(f"install directory: {paths.install_dir}")
    print(f"config path: {paths.config_path}")
    print(f"logs directory: {paths.logs_dir}")
    print(f"state directory: {paths.state_dir}")

    if args.uninstall:
        if system == "windows":
            return uninstall_windows(paths, args, dry_run=args.dry_run)
        if system == "linux":
            return uninstall_linux(paths, args, dry_run=args.dry_run)
        raise SystemExit(f"unsupported operating system: {platform.system() or 'unknown'}")

    log_event(paths, f"install start platform={system} installer_version={INSTALLER_VERSION}", dry_run=args.dry_run)
    create_directories(paths, dry_run=args.dry_run)
    create_venv(paths, system, dry_run=args.dry_run)
    install_collector_package(paths, system, dry_run=args.dry_run)
    write_config(paths, args, dry_run=args.dry_run)
    write_metadata(paths, args, system, dry_run=args.dry_run)

    if system == "windows":
        write_windows_wrapper(paths, dry_run=args.dry_run)
        install_windows_task(paths, args, dry_run=args.dry_run)
    elif system == "linux":
        install_linux_service(paths, args, dry_run=args.dry_run)
    else:
        raise SystemExit(f"unsupported operating system: {platform.system() or 'unknown'}")

    log_event(paths, f"install complete platform={system}", dry_run=args.dry_run)
    print("OpenAssetWatch collector installation completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
