#!/usr/bin/env python3
"""Install and manage the hardened OpenAssetWatch Linux sensor service."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - Linux-only production path
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


SERVICE_USER = "openassetwatch-sensor"
SERVICE_GROUP = "openassetwatch-sensor"
SERVICE_NAME = "oaw-sensor.service"
SERVICE_HOME = "/var/lib/openassetwatch/sensor"
NOLOGIN_SHELLS = ("/usr/sbin/nologin", "/sbin/nologin")

BINARY_PATH = "/usr/bin/oaw-sensor"
CONFIG_DIR = "/etc/openassetwatch/sensor"
CONFIG_PATH = CONFIG_DIR + "/sensor.json"
STATE_DIR = SERVICE_HOME
IDENTITY_PATH = STATE_DIR + "/identity.json"
CREDENTIAL_PATH = STATE_DIR + "/credential.json"
SPOOL_PATH = STATE_DIR + "/spool"
STATUS_PATH = STATE_DIR + "/status.json"
UNIT_PATH = "/etc/systemd/system/" + SERVICE_NAME

MAX_BINARY_BYTES = 128 << 20
MAX_CONFIG_BYTES = 64 << 10
MAX_UNIT_BYTES = 64 << 10
MAX_STATE_ENTRIES = 10_000
SENSOR_TYPE = "passive-network-sensor"
TOKEN_ENV = "OPENASSETWATCH_COLLECTOR_TOKEN"
CREDENTIAL_ENV = "OPENASSETWATCH_SENSOR_CREDENTIAL"
REQUIRED_CAPABILITY = "CAP_NET_RAW"
FORBIDDEN_CAPABILITIES = ("CAP_NET_ADMIN", "CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE")

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[2]
DEFAULT_UNIT_TEMPLATE = REPO_ROOT / "packaging" / "sensor" / "linux" / "systemd" / SERVICE_NAME


class InstallError(RuntimeError):
    pass


@dataclass(frozen=True)
class Account:
    uid: int
    gid: int
    created_user: bool = False
    created_group: bool = False


@dataclass
class Snapshot:
    existed: bool
    data: bytes = b""
    mode: int = 0
    uid: int = -1
    gid: int = -1


class Reporter:
    def __init__(self, action: str, dry_run: bool, test_mode: bool) -> None:
        self.action = action
        self.dry_run = dry_run
        self.test_mode = test_mode
        self.checks: list[dict[str, Any]] = []
        self.changes: list[str] = []
        self.preserved: list[str] = []
        self.warnings: list[str] = []

    def check(self, name: str, message: str) -> None:
        self.checks.append({"name": name, "ok": True, "message": message})

    def change(self, message: str) -> None:
        self.changes.append(message)

    def preserve(self, path: str) -> None:
        if path not in self.preserved:
            self.preserved.append(path)

    def summary(self, ok: bool, error: str = "") -> dict[str, Any]:
        result: dict[str, Any] = {
            "ok": ok,
            "action": self.action,
            "dry_run": self.dry_run,
            "test_mode": self.test_mode,
            "service": SERVICE_NAME,
            "service_user": SERVICE_USER,
            "service_group": SERVICE_GROUP,
            "runtime_user_is_root": False,
            "capabilities": [REQUIRED_CAPABILITY],
            "checks": self.checks,
            "changes": self.changes,
            "preserved": self.preserved,
            "warnings": self.warnings,
        }
        if error:
            result["error"] = error
        return result


def current_uid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else 0


def current_gid() -> int:
    return os.getegid() if hasattr(os, "getegid") else 0


def require_production_root(reporter: Reporter) -> None:
    if not reporter.test_mode and not reporter.dry_run and current_uid() != 0:
        raise InstallError("Linux sensor service management must run as root")


def rooted(root: Path, absolute_path: str) -> Path:
    pure = PurePosixPath(absolute_path)
    if not pure.is_absolute() or ".." in pure.parts:
        raise InstallError("installer path must be an absolute fixed path")
    relative = Path(*pure.parts[1:])
    candidate = root / relative
    resolved_root = root.resolve()
    resolved_parent = candidate.parent.resolve(strict=False)
    try:
        resolved_parent.relative_to(resolved_root)
    except ValueError as exc:
        raise InstallError("installer path escaped the selected root") from exc
    return candidate


def lstat_regular(path: Path, maximum: int, purpose: str) -> os.stat_result:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise InstallError(f"{purpose} does not exist") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise InstallError(f"{purpose} must be a regular non-symlink file")
    if info.st_nlink != 1:
        raise InstallError(f"{purpose} must have exactly one hard link")
    if info.st_size < 1 or info.st_size > maximum:
        raise InstallError(f"{purpose} has an invalid size")
    return info


def read_regular(path: Path, maximum: int, purpose: str) -> tuple[bytes, os.stat_result]:
    before = lstat_regular(path, maximum, purpose)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InstallError(f"failed to open {purpose}") from exc
    try:
        after = os.fstat(descriptor)
        if (
            not stat.S_ISREG(after.st_mode)
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or after.st_nlink != 1
        ):
            raise InstallError(f"{purpose} changed while opening")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(1 << 20, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != after.st_size or len(data) > maximum:
            raise InstallError(f"{purpose} changed or exceeded its size limit")
        return bytes(data), after
    finally:
        os.close(descriptor)


def validate_source_binary(path: Path, reporter: Reporter) -> bytes:
    data, info = read_regular(path, MAX_BINARY_BYTES, "sensor binary")
    if info.st_mode & 0o022:
        raise InstallError("sensor binary source must not be writable by group or other users")
    if not data.startswith(b"\x7fELF"):
        raise InstallError("sensor binary must be a Linux ELF executable")
    reporter.check("binary_source", f"regular ELF source; sha256={hashlib.sha256(data).hexdigest()}")
    return data


def validate_unit_text(data: bytes, reporter: Reporter) -> str:
    if len(data) < 1 or len(data) > MAX_UNIT_BYTES:
        raise InstallError("systemd unit has an invalid size")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InstallError("systemd unit must be UTF-8") from exc
    required = (
        f"User={SERVICE_USER}",
        f"Group={SERVICE_GROUP}",
        f"ExecStart={BINARY_PATH} service run --config {CONFIG_PATH}",
        "Restart=on-failure",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ProtectKernelTunables=true",
        "ProtectKernelModules=true",
        "ProtectControlGroups=true",
        "RestrictSUIDSGID=true",
        "LockPersonality=true",
        "MemoryDenyWriteExecute=true",
        f"ReadWritePaths={STATE_DIR}",
        f"CapabilityBoundingSet={REQUIRED_CAPABILITY}",
        f"AmbientCapabilities={REQUIRED_CAPABILITY}",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK AF_PACKET",
    )
    missing = [value for value in required if value not in text]
    if missing:
        raise InstallError("systemd unit is missing required hardening directives")
    if "User=root" in text or "Group=root" in text:
        raise InstallError("systemd unit must not run as root")
    for capability in FORBIDDEN_CAPABILITIES:
        if capability in text:
            raise InstallError(f"systemd unit contains forbidden capability {capability}")
    if "Environment=" in text or "EnvironmentFile=" in text:
        raise InstallError("systemd unit must not contain credential-bearing environment directives")
    reporter.check("unit_template", "service user, fixed paths, hardening, and capability allowlist validated")
    return text


def absolute_without_symlink_resolution(value: str) -> Path:
    return Path(os.path.abspath(os.fspath(value)))


def validate_hub_url(value: str) -> str:
    if value != value.strip() or len(value) > 2048:
        raise InstallError("hub URL is invalid")
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise InstallError("hub URL must use HTTP(S) and include a host")
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise InstallError("hub URL contains unsupported components")
    host = parsed.hostname.rstrip(".").lower()
    if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
        raise InstallError("non-loopback hub URLs must use HTTPS")
    return value.rstrip("/")


def safe_identifier(value: str, name: str, maximum: int) -> str:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    if not value or len(value) > maximum or any(character not in allowed for character in value):
        raise InstallError(f"{name} is invalid")
    return value


def safe_interface(value: str) -> str:
    if not value or value != value.strip() or len(value) > 64:
        raise InstallError("capture interface is invalid")
    if any(ord(character) < 0x20 or character in "/\\" for character in value):
        raise InstallError("capture interface is invalid")
    return value


def build_config(args: argparse.Namespace) -> bytes:
    config = {
        "hub_url": validate_hub_url(args.hub_url),
        "site_id": safe_identifier(args.site_id, "site ID", 128),
        "sensor_name": (args.sensor_name or "OpenAssetWatch Passive Sensor").strip(),
        "capture_mode": "live",
        "capture_interface": safe_interface(args.interface),
        "identity_path": IDENTITY_PATH,
        "credential_path": CREDENTIAL_PATH,
        "spool_path": SPOOL_PATH,
        "status_path": STATUS_PATH,
        "credential_env": CREDENTIAL_ENV,
        "token_env": TOKEN_ENV,
        "batch_size": 250,
        "batch_interval_seconds": 60,
        "request_timeout_seconds": 10,
        "retry_initial_seconds": 2,
        "retry_max_seconds": 300,
        "spool_max_items": 1000,
        "spool_max_bytes": 256 << 20,
        "aggregation_max_devices": 2048,
        "aggregation_ttl_seconds": 1800,
    }
    if not config["sensor_name"] or len(config["sensor_name"]) > 160:
        raise InstallError("sensor name is invalid")
    data = (json.dumps(config, indent=2) + "\n").encode("utf-8")
    if len(data) > MAX_CONFIG_BYTES:
        raise InstallError("generated sensor config exceeds size limit")
    return data


def ensure_parent_chain(root: Path, reporter: Reporter) -> None:
    for absolute in ("/usr", "/usr/bin", "/etc", "/etc/systemd", "/etc/systemd/system", "/var", "/var/lib"):
        path = rooted(root, absolute)
        if reporter.test_mode and not path.exists():
            path.mkdir(mode=0o755)
        validate_directory(path, {0, current_uid()} if reporter.test_mode else {0}, allow_sticky=False)


def validate_directory(path: Path, allowed_uids: set[int], allow_sticky: bool) -> os.stat_result:
    try:
        before = path.lstat()
    except FileNotFoundError as exc:
        raise InstallError(f"required parent directory is missing: {path}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise InstallError(f"directory must be a non-symlink directory: {path}")
    if hasattr(before, "st_uid") and before.st_uid not in allowed_uids:
        raise InstallError(f"directory has unsafe ownership: {path}")
    permissions = stat.S_IMODE(before.st_mode)
    if permissions & 0o022 and not (allow_sticky and before.st_mode & stat.S_ISVTX):
        raise InstallError(f"directory is group or other writable: {path}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        after = os.fstat(descriptor)
        if before.st_dev != after.st_dev or before.st_ino != after.st_ino:
            raise InstallError(f"directory changed while opening: {path}")
    finally:
        os.close(descriptor)
    return before


def ensure_directory(path: Path, mode: int, uid: int, gid: int, reporter: Reporter) -> None:
    if reporter.dry_run:
        reporter.change(f"ensure directory {path} mode {mode:04o}")
        return
    if not path.exists():
        path.mkdir(mode=mode)
        reporter.change(f"created directory {path}")
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise InstallError(f"refusing unsafe directory path: {path}")
    if before.st_mode & 0o022:
        raise InstallError(f"refusing writable existing directory: {path}")
    os.chmod(path, mode, follow_symlinks=False)
    if not reporter.test_mode:
        os.chown(path, uid, gid, follow_symlinks=False)
    validate_directory(path, {uid, current_uid()} if reporter.test_mode else {uid}, allow_sticky=False)


def destination_snapshot(path: Path, maximum: int, expected_uids: set[int]) -> Snapshot:
    try:
        data, info = read_regular(path, maximum, f"existing {path.name}")
    except FileNotFoundError:
        return Snapshot(False)
    except InstallError as exc:
        if not path.exists() and not path.is_symlink():
            return Snapshot(False)
        raise exc
    if hasattr(info, "st_uid") and info.st_uid not in expected_uids:
        raise InstallError(f"existing destination has unsafe ownership: {path}")
    return Snapshot(True, data, stat.S_IMODE(info.st_mode), getattr(info, "st_uid", -1), getattr(info, "st_gid", -1))


def safe_atomic_write(
    path: Path,
    data: bytes,
    mode: int,
    uid: int,
    gid: int,
    maximum: int,
    reporter: Reporter,
) -> None:
    if len(data) < 1 or len(data) > maximum:
        raise InstallError(f"refusing invalid data size for {path}")
    if reporter.dry_run:
        reporter.change(f"atomically install {path} mode {mode:04o}")
        return
    parent = path.parent
    validate_directory(parent, {0, current_uid()} if reporter.test_mode else {0, uid}, allow_sticky=False)
    parent_fd = os.open(
        parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    temp_name = f".{path.name}.{secrets.token_hex(16)}.tmp"
    descriptor = -1
    try:
        existing: os.stat_result | None
        try:
            existing = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except (FileNotFoundError, TypeError, NotImplementedError):
            existing = None
            if path.exists() or path.is_symlink():
                existing = path.lstat()
        if existing is not None:
            if stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode) or existing.st_nlink != 1:
                raise InstallError(f"refusing unsafe existing destination: {path}")
            allowed = {uid, current_uid()} if reporter.test_mode else {uid}
            if hasattr(existing, "st_uid") and existing.st_uid not in allowed:
                raise InstallError(f"refusing destination with unsafe ownership: {path}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(temp_name, flags, mode, dir_fd=parent_fd)
        except (TypeError, NotImplementedError):
            descriptor = os.open(parent / temp_name, flags, mode)
        offset = 0
        while offset < len(data):
            offset += os.write(descriptor, data[offset:])
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
        if not reporter.test_mode:
            os.fchown(descriptor, uid, gid)
        temporary = os.fstat(descriptor)
        if not stat.S_ISREG(temporary.st_mode) or temporary.st_nlink != 1:
            raise InstallError("temporary installer file failed validation")
        os.close(descriptor)
        descriptor = -1
        try:
            os.replace(temp_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except (TypeError, NotImplementedError):
            os.replace(parent / temp_name, path)
        os.fsync(parent_fd)
        installed = path.lstat()
        if stat.S_ISLNK(installed.st_mode) or not stat.S_ISREG(installed.st_mode) or installed.st_nlink != 1:
            raise InstallError(f"installed file failed validation: {path}")
        if stat.S_IMODE(installed.st_mode) != mode:
            raise InstallError(f"installed file mode is incorrect: {path}")
        if not reporter.test_mode and (installed.st_uid != uid or installed.st_gid != gid):
            raise InstallError(f"installed file ownership is incorrect: {path}")
        reporter.change(f"installed {path}")
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temp_name, dir_fd=parent_fd)
        except (FileNotFoundError, TypeError, NotImplementedError):
            try:
                (parent / temp_name).unlink()
            except FileNotFoundError:
                pass
        os.close(parent_fd)


def validate_unlink_target(path: Path, expected_uids: set[int]) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise InstallError(f"refusing to remove unsafe file: {path}")
    if hasattr(info, "st_uid") and info.st_uid not in expected_uids:
        raise InstallError(f"refusing to remove file with unsafe ownership: {path}")


def safe_unlink(path: Path, expected_uids: set[int], reporter: Reporter) -> None:
    validate_unlink_target(path, expected_uids)
    if not path.exists() and not path.is_symlink():
        return
    if reporter.dry_run:
        reporter.change(f"remove {path}")
        return
    path.unlink()
    reporter.change(f"removed {path}")


def command(args: list[str], *, check: bool = True, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            check=check,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InstallError(f"required command failed safely: {args[0]}") from exc


def ensure_service_account(reporter: Reporter) -> Account:
    if reporter.test_mode:
        reporter.check("service_account", "test mode models a locked non-root system account")
        return Account(current_uid(), current_gid())
    if current_uid() != 0:
        raise InstallError("Linux sensor installation must run as root")
    if grp is None or pwd is None:
        raise InstallError("Linux account databases are unavailable")
    created_group = False
    created_user = False
    try:
        group = grp.getgrnam(SERVICE_GROUP)
    except KeyError:
        command(["groupadd", "--system", SERVICE_GROUP])
        group = grp.getgrnam(SERVICE_GROUP)
        created_group = True
    try:
        user = pwd.getpwnam(SERVICE_USER)
    except KeyError:
        shell = next((value for value in NOLOGIN_SHELLS if Path(value).exists()), NOLOGIN_SHELLS[0])
        command(
            [
                "useradd",
                "--system",
                "--gid",
                SERVICE_GROUP,
                "--home-dir",
                SERVICE_HOME,
                "--no-create-home",
                "--shell",
                shell,
                SERVICE_USER,
            ]
        )
        command(["usermod", "--lock", SERVICE_USER])
        user = pwd.getpwnam(SERVICE_USER)
        created_user = True
    if user.pw_uid == 0 or user.pw_gid != group.gr_gid or user.pw_dir != SERVICE_HOME or user.pw_shell not in NOLOGIN_SHELLS:
        raise InstallError("sensor service account does not match the required locked system identity")
    command(["usermod", "--lock", SERVICE_USER])
    password_status = command(["passwd", "--status", SERVICE_USER]).stdout.split()
    if len(password_status) < 2 or password_status[1] not in {"L", "LK"}:
        raise InstallError("sensor service account is not locked")
    reporter.check("service_account", "dedicated non-root account and group validated")
    return Account(user.pw_uid, group.gr_gid, created_user, created_group)


def validate_private_state(root: Path, account: Account, reporter: Reporter) -> None:
    state = rooted(root, STATE_DIR)
    spool = rooted(root, SPOOL_PATH)
    allowed = {account.uid, current_uid()} if reporter.test_mode else {account.uid}
    for path in (state, spool):
        validate_directory(path, allowed, allow_sticky=False)
        if stat.S_IMODE(path.lstat().st_mode) != 0o700:
            raise InstallError(f"private sensor directory mode must be 0700: {path}")
    for absolute in (IDENTITY_PATH, CREDENTIAL_PATH, STATUS_PATH):
        path = rooted(root, absolute)
        if not path.exists() and not path.is_symlink():
            continue
        info = lstat_regular(path, MAX_CONFIG_BYTES, path.name)
        if hasattr(info, "st_uid") and info.st_uid not in allowed:
            raise InstallError(f"private sensor file has unsafe ownership: {path}")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise InstallError(f"private sensor file mode must be 0600: {path}")
        reporter.preserve(absolute)
    entry_count = 0
    for entry in spool.iterdir():
        entry_count += 1
        if entry_count > MAX_STATE_ENTRIES:
            raise InstallError("sensor spool entry count exceeds installer validation limit")
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise InstallError("sensor spool contains an unsafe entry")
        if hasattr(info, "st_uid") and info.st_uid not in allowed:
            raise InstallError("sensor spool entry has unsafe ownership")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise InstallError("sensor spool entry mode must be 0600")
    reporter.preserve(SPOOL_PATH)


def systemd_verify(unit: Path, reporter: Reporter) -> None:
    if reporter.test_mode:
        reporter.check("unit_validation", "static unit validation completed before activation")
        return
    command(["systemd-analyze", "verify", str(unit)])
    reporter.check("unit_validation", "systemd-analyze verify completed before activation")


def validate_installed_binary_and_config(root: Path, account: Account, reporter: Reporter) -> None:
    if reporter.test_mode:
        reporter.check("runtime_validation", "test mode validated binary and config structure")
        return
    binary = rooted(root, BINARY_PATH)
    config = rooted(root, CONFIG_PATH)
    command(
        [
            "runuser",
            "--user",
            SERVICE_USER,
            "--",
            str(binary),
            "config",
            "validate",
            "--config",
            str(config),
        ],
        timeout=30,
    )
    reporter.check("runtime_validation", "config validated through the installed binary as the service account")


def rollback_file(
    path: Path,
    snapshot: Snapshot,
    maximum: int,
    default_uid: int,
    default_gid: int,
    reporter: Reporter,
) -> None:
    if snapshot.existed:
        uid = snapshot.uid if snapshot.uid >= 0 else default_uid
        gid = snapshot.gid if snapshot.gid >= 0 else default_gid
        safe_atomic_write(path, snapshot.data, snapshot.mode, uid, gid, maximum, reporter)
    else:
        safe_unlink(path, {default_uid, current_uid()}, reporter)


def install_or_repair(args: argparse.Namespace, reporter: Reporter) -> None:
    root = Path(args.root).resolve()
    if root != Path("/") and not reporter.test_mode:
        raise InstallError("--root is allowed only with --test-mode")
    if reporter.test_mode and root == Path("/"):
        raise InstallError("test mode requires a disposable non-root filesystem root")
    binary_source = absolute_without_symlink_resolution(args.binary)
    binary_data = validate_source_binary(binary_source, reporter)
    unit_source = absolute_without_symlink_resolution(args.unit_template)
    unit_data, _ = read_regular(unit_source, MAX_UNIT_BYTES, "systemd unit template")
    canonical_unit, _ = read_regular(DEFAULT_UNIT_TEMPLATE, MAX_UNIT_BYTES, "canonical systemd unit template")
    if unit_data != canonical_unit:
        raise InstallError("systemd unit template must match the reviewed canonical sensor unit")
    validate_unit_text(unit_data, reporter)
    generated_config: bytes | None = None

    config_target = rooted(root, CONFIG_PATH)
    config_exists = config_target.exists() or config_target.is_symlink()
    if not config_exists:
        if not args.hub_url or not args.site_id or not args.interface:
            raise InstallError("new installation requires --hub-url, --site-id, and --interface")
        generated_config = build_config(args)
        reporter.check("generated_config", "live mode uses an explicit capture interface and contains no secret values")
    else:
        reporter.preserve(CONFIG_PATH)

    if reporter.dry_run:
        reporter.check("plan", "validated install plan without changing the filesystem")
        for path in (BINARY_PATH, CONFIG_PATH, UNIT_PATH, STATE_DIR, SPOOL_PATH):
            reporter.change(f"plan fixed path {path}")
        return

    ensure_parent_chain(root, reporter)
    account = ensure_service_account(reporter)
    root_uid = current_uid() if reporter.test_mode else 0
    root_gid = current_gid() if reporter.test_mode else 0

    ensure_directory(rooted(root, "/etc/openassetwatch"), 0o755, root_uid, root_gid, reporter)
    ensure_directory(rooted(root, CONFIG_DIR), 0o750, root_uid, account.gid, reporter)
    ensure_directory(rooted(root, "/var/lib/openassetwatch"), 0o755, root_uid, root_gid, reporter)
    ensure_directory(rooted(root, STATE_DIR), 0o700, account.uid, account.gid, reporter)
    ensure_directory(rooted(root, SPOOL_PATH), 0o700, account.uid, account.gid, reporter)
    was_active = False
    if not reporter.test_mode:
        was_active = command(["systemctl", "is-active", "--quiet", SERVICE_NAME], check=False).returncode == 0
        if was_active:
            command(["systemctl", "stop", SERVICE_NAME])
            reporter.change(f"stopped {SERVICE_NAME} for atomic lifecycle update")

    binary_target = rooted(root, BINARY_PATH)
    unit_target = rooted(root, UNIT_PATH)
    expected_root_uids = {root_uid, current_uid()} if reporter.test_mode else {0}
    binary_before = destination_snapshot(binary_target, MAX_BINARY_BYTES, expected_root_uids)
    unit_before = destination_snapshot(unit_target, MAX_UNIT_BYTES, expected_root_uids)
    config_before = destination_snapshot(config_target, MAX_CONFIG_BYTES, expected_root_uids)
    try:
        if config_before.existed:
            if config_before.mode & 0o027:
                raise InstallError("existing sensor config grants unsafe write or other-user access")
            os.chmod(config_target, 0o640, follow_symlinks=False)
            if not reporter.test_mode:
                os.chown(config_target, root_uid, account.gid, follow_symlinks=False)
            reporter.change(f"validated root-controlled configuration {config_target}")
        safe_atomic_write(binary_target, binary_data, 0o755, root_uid, root_gid, MAX_BINARY_BYTES, reporter)
        if generated_config is not None:
            safe_atomic_write(config_target, generated_config, 0o640, root_uid, account.gid, MAX_CONFIG_BYTES, reporter)
        safe_atomic_write(unit_target, unit_data, 0o644, root_uid, root_gid, MAX_UNIT_BYTES, reporter)
        validate_private_state(root, account, reporter)
        validate_installed_binary_and_config(root, account, reporter)
        systemd_verify(unit_target, reporter)
        if not reporter.test_mode:
            command(["systemctl", "daemon-reload"])
            reporter.change("systemd daemon-reload")
            command(["systemctl", "enable", SERVICE_NAME])
            reporter.change(f"enabled {SERVICE_NAME}")
            if args.start or was_active:
                command(["systemctl", "restart", SERVICE_NAME])
                reporter.change(f"restarted {SERVICE_NAME}")
        reporter.check("activation_order", "unit and runtime validation completed before systemd activation")
    except Exception:
        rollback_file(binary_target, binary_before, MAX_BINARY_BYTES, root_uid, root_gid, reporter)
        rollback_file(unit_target, unit_before, MAX_UNIT_BYTES, root_uid, root_gid, reporter)
        rollback_file(config_target, config_before, MAX_CONFIG_BYTES, root_uid, account.gid, reporter)
        if not reporter.test_mode and was_active:
            command(["systemctl", "daemon-reload"], check=False)
            command(["systemctl", "start", SERVICE_NAME], check=False)
        raise


def stop_and_disable(reporter: Reporter) -> None:
    if reporter.test_mode or reporter.dry_run:
        reporter.change(f"stop and disable {SERVICE_NAME}")
        return
    command(["systemctl", "disable", "--now", SERVICE_NAME], check=False)
    reporter.change(f"stopped and disabled {SERVICE_NAME}")


def uninstall(args: argparse.Namespace, reporter: Reporter) -> None:
    root = Path(args.root).resolve()
    if root != Path("/") and not reporter.test_mode:
        raise InstallError("--root is allowed only with --test-mode")
    if reporter.test_mode and root == Path("/"):
        raise InstallError("test mode requires a disposable non-root filesystem root")
    require_production_root(reporter)
    stop_and_disable(reporter)
    expected = {current_uid()} if reporter.test_mode else {0}
    safe_unlink(rooted(root, UNIT_PATH), expected, reporter)
    safe_unlink(rooted(root, BINARY_PATH), expected, reporter)
    for path in (CONFIG_PATH, IDENTITY_PATH, CREDENTIAL_PATH, SPOOL_PATH, STATUS_PATH):
        reporter.preserve(path)
    if not reporter.test_mode and not reporter.dry_run:
        command(["systemctl", "daemon-reload"])


def validate_purge_tree(path: Path, allowed_uids: set[int]) -> os.stat_result:
    root_info = validate_directory(path, allowed_uids, allow_sticky=False)
    root_device = root_info.st_dev
    pending = [path]
    entry_count = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                entry_count += 1
                if entry_count > MAX_STATE_ENTRIES:
                    raise InstallError("purge tree exceeds installer validation limit")
                info = entry.stat(follow_symlinks=False)
                if info.st_dev != root_device or getattr(info, "st_uid", -1) not in allowed_uids:
                    raise InstallError(f"purge tree contains unsafe ownership or a mounted filesystem: {entry.path}")
                if stat.S_ISDIR(info.st_mode):
                    if stat.S_IMODE(info.st_mode) & 0o022:
                        raise InstallError(f"purge tree contains a writable directory: {entry.path}")
                    pending.append(Path(entry.path))
                elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise InstallError(f"purge tree contains an unsafe file: {entry.path}")
    return root_info


def quarantine_and_remove(
    path: Path,
    parent_allowed_uids: set[int],
    target_allowed_uids: set[int],
    reporter: Reporter,
) -> None:
    if not path.exists() and not path.is_symlink():
        return
    validate_directory(path.parent, parent_allowed_uids, allow_sticky=False)
    before = validate_purge_tree(path, target_allowed_uids)
    if reporter.dry_run:
        reporter.change(f"purge directory {path}")
        return
    tombstone = path.parent / f".{path.name}.purge-{secrets.token_hex(16)}"
    os.replace(path, tombstone)
    moved = tombstone.lstat()
    if before.st_dev != moved.st_dev or before.st_ino != moved.st_ino or not stat.S_ISDIR(moved.st_mode):
        raise InstallError(f"purge directory changed during quarantine: {path}")
    os.chmod(tombstone, 0o700, follow_symlinks=False)
    if not reporter.test_mode:
        os.chown(tombstone, 0, 0, follow_symlinks=False)
    shutil.rmtree(tombstone)
    reporter.change(f"purged directory {path}")


def remove_service_account(reporter: Reporter) -> None:
    if reporter.test_mode or reporter.dry_run:
        reporter.change(f"remove service account {SERVICE_USER}")
        return
    command(["userdel", SERVICE_USER], check=False)
    command(["groupdel", SERVICE_GROUP], check=False)
    reporter.change(f"removed service account {SERVICE_USER}")


def purge(args: argparse.Namespace, reporter: Reporter) -> None:
    if not args.confirm_purge:
        raise InstallError("purge requires --confirm-purge")
    root = Path(args.root).resolve()
    if root != Path("/") and not reporter.test_mode:
        raise InstallError("--root is allowed only with --test-mode")
    if reporter.test_mode and root == Path("/"):
        raise InstallError("test mode requires a disposable non-root filesystem root")
    require_production_root(reporter)
    expected_root = {current_uid()} if reporter.test_mode else {0}
    if reporter.test_mode:
        expected_state = {current_uid()}
    else:
        if pwd is None:
            raise InstallError("Linux account database is unavailable")
        try:
            service_user = pwd.getpwnam(SERVICE_USER)
        except KeyError as exc:
            if rooted(root, STATE_DIR).exists():
                raise InstallError("cannot verify sensor state ownership without the service account") from exc
            expected_state = set()
        else:
            if service_user.pw_uid == 0:
                raise InstallError("refusing purge with a root sensor service identity")
            expected_state = {service_user.pw_uid}
    unit_path = rooted(root, UNIT_PATH)
    binary_path = rooted(root, BINARY_PATH)
    config_path = rooted(root, CONFIG_DIR)
    state_path = rooted(root, STATE_DIR)
    validate_unlink_target(unit_path, expected_root)
    validate_unlink_target(binary_path, expected_root)
    if config_path.exists() or config_path.is_symlink():
        validate_directory(config_path.parent, expected_root, allow_sticky=False)
        validate_purge_tree(config_path, expected_root)
    if state_path.exists() or state_path.is_symlink():
        validate_directory(state_path.parent, expected_root, allow_sticky=False)
        validate_purge_tree(state_path, expected_state)
    stop_and_disable(reporter)
    safe_unlink(unit_path, expected_root, reporter)
    safe_unlink(binary_path, expected_root, reporter)
    quarantine_and_remove(config_path, expected_root, expected_root, reporter)
    quarantine_and_remove(state_path, expected_root, expected_state, reporter)
    remove_service_account(reporter)
    if not reporter.test_mode and not reporter.dry_run:
        command(["systemctl", "daemon-reload"])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install, repair, upgrade, uninstall, or purge the hardened Linux oaw-sensor service."
    )
    parser.add_argument("--root", default="/", help=argparse.SUPPRESS)
    parser.add_argument("--test-mode", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--dry-run", action="store_true", help="Validate and print the fixed-path plan without changes.")
    subparsers = parser.add_subparsers(dest="action", required=True)
    for name in ("install", "repair", "upgrade"):
        action = subparsers.add_parser(name)
        action.add_argument("--binary", required=True, help="Linux oaw-sensor ELF binary to install.")
        action.add_argument("--unit-template", default=str(DEFAULT_UNIT_TEMPLATE), help="Canonical sensor systemd unit.")
        action.add_argument("--hub-url", help="Hub URL for a new configuration.")
        action.add_argument("--site-id", help="Site ID for a new configuration.")
        action.add_argument("--interface", help="Explicit capture interface for a new configuration.")
        action.add_argument("--sensor-name", default="OpenAssetWatch Passive Sensor")
        action.add_argument("--start", action="store_true", help="Start or restart the service after validation.")
    subparsers.add_parser("uninstall")
    purge_parser = subparsers.add_parser("purge")
    purge_parser.add_argument("--confirm-purge", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    reporter = Reporter(args.action, args.dry_run, args.test_mode)
    try:
        if sys.platform != "linux" and not args.test_mode:
            raise InstallError("the sensor system installer is Linux-only")
        if args.action in {"install", "repair", "upgrade"}:
            install_or_repair(args, reporter)
        elif args.action == "uninstall":
            uninstall(args, reporter)
        elif args.action == "purge":
            purge(args, reporter)
        else:
            raise InstallError("unsupported installer action")
    except InstallError as exc:
        print(json.dumps(reporter.summary(False, str(exc)), indent=2))
        return 1
    print(json.dumps(reporter.summary(True), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
