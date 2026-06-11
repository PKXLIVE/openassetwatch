"""Standalone collection entry point for OpenAssetWatch."""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import platform
import re
import shutil
import socket
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from . import __version__
from .capabilities import collect_platform_capabilities, command_available
from .open_detector import scan_software


SCHEMA_VERSION = "1.0"
POWERSHELL_COMMANDS = ("powershell", "powershell.exe", "pwsh", "pwsh.exe")
DEFAULT_MODE = "device"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_optional_text(value: Any, lowercase: bool = False) -> str | None:
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    return text.lower() if lowercase else text


def normalize_mac(value: Any) -> str | None:
    text = normalize_optional_text(value)
    if not text:
        return None

    cleaned = text.lower().replace("-", ":")
    if cleaned in {"", "00:00:00:00:00:00"}:
        return None

    compact = re.sub(r"[^0-9a-f]", "", cleaned)
    if len(compact) != 12:
        return cleaned

    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def is_non_host_ip_address(value: Any) -> bool:
    text = normalize_optional_text(value)
    if not text:
        return True

    try:
        ip_address = ipaddress.ip_address(text)
    except ValueError:
        return True

    if ip_address.version != 4:
        return True

    return (
        ip_address.is_multicast
        or ip_address.is_unspecified
        or ip_address.is_loopback
        or text == "255.255.255.255"
    )


def is_non_host_mac_address(value: Any) -> bool:
    mac_address = normalize_mac(value)
    if not mac_address:
        return True

    return (
        mac_address == "ff:ff:ff:ff:ff:ff"
        or mac_address.startswith("01:00:5e:")
        or mac_address.startswith("33:33:")
    )


def get_primary_ip() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return None


def get_mac_from_getmac() -> str | None:
    output = run_command(["getmac", "/fo", "csv", "/nh"])
    if not output:
        return None

    for row in csv.reader(io.StringIO(output)):
        if not row:
            continue
        mac = normalize_mac(row[0])
        if mac:
            return mac

    return None


def get_mac_from_ipconfig(primary_ip: str | None) -> str | None:
    output = run_command(["ipconfig", "/all"])
    if not output:
        return None

    blocks = re.split(r"\r?\n\s*\r?\n", output)
    candidates: list[str] = []
    for block in blocks:
        match = re.search(r"Physical Address[ .]*:\s*([0-9A-Fa-f-]{17})", block)
        if not match:
            continue
        mac = normalize_mac(match.group(1))
        if not mac:
            continue
        if primary_ip and primary_ip in block:
            return mac
        candidates.append(mac)

    return candidates[0] if candidates else None


def get_host_mac(primary_ip: str | None = None) -> str | None:
    command_mac = get_mac_from_getmac()
    if command_mac:
        return command_mac

    ipconfig_mac = get_mac_from_ipconfig(primary_ip)
    if ipconfig_mac:
        return ipconfig_mac

    node = uuid.getnode()
    if (node >> 40) & 1:
        return None
    return normalize_mac(f"{node:012x}")


def collect_device() -> dict[str, Any]:
    primary_ip = get_primary_ip()
    return {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "platform": platform.system().lower() or None,
        "platform_release": platform.release() or None,
        "platform_version": platform.version() or None,
        "architecture": platform.machine() or None,
        "primary_ip": primary_ip,
        "mac_address": get_host_mac(primary_ip),
    }


def run_command(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    return result.stdout


def resolve_powershell_command() -> str | None:
    for command in POWERSHELL_COMMANDS:
        if shutil.which(command):
            return command
    return None


def normalize_network_entry(
    ip: Any,
    mac: Any,
    interface: Any,
    state: Any,
    source: str,
) -> dict[str, Any]:
    normalized_mac = normalize_mac(mac)
    return {
        "ip_address": normalize_optional_text(ip),
        "mac_address": normalized_mac,
        "interface": normalize_optional_text(interface),
        "state": normalize_optional_text(state, lowercase=True),
        "source": source,
        "sources": [source],
    }


def collect_network_from_ip_neigh() -> list[dict[str, Any]]:
    output = run_command(["ip", "neigh"])
    if not output:
        return []

    entries: list[dict[str, Any]] = []
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue

        ip = parts[0]
        interface = parts[parts.index("dev") + 1] if "dev" in parts else None
        mac = parts[parts.index("lladdr") + 1] if "lladdr" in parts else None
        state = parts[-1] if parts else None
        entries.append(normalize_network_entry(ip, mac, interface, state, "ip neigh"))

    return entries


def collect_network_from_windows_neighbor() -> list[dict[str, Any]]:
    powershell_command = resolve_powershell_command()
    if not powershell_command:
        return []

    command = [
        powershell_command,
        "-NoProfile",
        "-Command",
        (
            "Get-NetNeighbor | "
            "Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,State | "
            "ConvertTo-Json -Depth 2"
        ),
    ]
    output = run_command(command)
    if not output:
        return []

    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        return []

    rows = payload if isinstance(payload, list) else [payload]
    entries: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ip = row.get("IPAddress")
        if not isinstance(ip, str) or ":" in ip:
            continue
        entries.append(
            normalize_network_entry(
                ip,
                row.get("LinkLayerAddress"),
                row.get("InterfaceAlias"),
                row.get("State"),
                "Get-NetNeighbor",
            )
        )

    return entries


def collect_network_from_arp() -> list[dict[str, Any]]:
    output = run_command(["arp", "-a"])
    if not output:
        return []

    entries: list[dict[str, Any]] = []
    current_interface: str | None = None
    windows_row = re.compile(
        r"^\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<mac>[0-9a-fA-F:-]{11,17})\s+"
        r"(?P<state>\w+)\s*$"
    )

    for line in output.splitlines():
        interface_match = re.match(r"^Interface:\s+(?P<interface>\S+)", line)
        if interface_match:
            current_interface = interface_match.group("interface")
            continue

        windows_match = windows_row.match(line)
        if windows_match:
            entries.append(
                normalize_network_entry(
                    windows_match.group("ip"),
                    windows_match.group("mac"),
                    current_interface,
                    windows_match.group("state"),
                    "arp -a",
                )
            )
            continue

        if " at " in line:
            parts = line.split()
            ip_part = next((part for part in parts if re.match(r"^\(?\d+\.\d+\.\d+\.\d+\)?$", part)), None)
            ip = ip_part.strip("()") if ip_part else None
            mac = parts[3] if len(parts) > 3 else None
            interface = parts[parts.index("on") + 1] if "on" in parts else None
            entries.append(normalize_network_entry(ip, mac, interface, None, "arp -a"))

    return entries


def network_collectors_for_platform(
    platform_info: dict[str, object],
) -> list[tuple[str, Any]]:
    system_key = platform_info.get("system_key")
    available_commands = set(platform_info.get("available_commands", []))

    if system_key == "windows":
        collectors = []
        if "powershell" in available_commands:
            collectors.append(("Get-NetNeighbor", collect_network_from_windows_neighbor))
        if "arp" in available_commands:
            collectors.append(("arp -a", collect_network_from_arp))
        return collectors

    if system_key == "linux":
        collectors = []
        if "ip" in available_commands:
            collectors.append(("ip neigh", collect_network_from_ip_neigh))
        if "arp" in available_commands:
            collectors.append(("arp -a", collect_network_from_arp))
        return collectors

    if system_key == "darwin":
        return [("arp -a", collect_network_from_arp)] if "arp" in available_commands else []

    return [("arp -a", collect_network_from_arp)] if command_available("arp") else []


def collect_network(platform_info: dict[str, object]) -> list[dict[str, Any]]:
    entries_by_key: dict[tuple[str | None, str | None], dict[str, Any]] = {}

    collectors = network_collectors_for_platform(platform_info)
    for collector in collectors:
        _, collect = collector
        for entry in collect():
            ip_address = entry.get("ip_address")
            mac_address = entry.get("mac_address")
            if is_non_host_ip_address(ip_address):
                continue
            if is_non_host_mac_address(mac_address):
                continue

            key = (ip_address, mac_address)
            existing = entries_by_key.setdefault(key, entry)
            sources = existing.setdefault("sources", [])
            for source in entry.get("sources", []):
                if source not in sources:
                    sources.append(source)

            if not existing.get("interface") and entry.get("interface"):
                existing["interface"] = entry["interface"]
            if not existing.get("state") and entry.get("state"):
                existing["state"] = entry["state"]

    return list(entries_by_key.values())


def build_payload(mode: str) -> dict[str, Any]:
    platform_info = collect_platform_capabilities()
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "collector": "openassetwatch_collector",
        "collector_version": __version__,
        "mode": mode,
        "collected_at": utc_now(),
        "platform": platform_info,
    }

    if mode in {"device", "hybrid"}:
        payload["device"] = collect_device()
        payload["software"] = scan_software(platform_info)

    if mode in {"network", "hybrid"}:
        payload["network"] = collect_network(platform_info)

    return payload


def build_checkin_payload(
    payload: dict[str, Any],
    collector_id: str,
    collector_name: str | None,
) -> dict[str, Any]:
    device = payload.get("device", {})
    checkin_payload: dict[str, Any] = {
        "collector_id": collector_id,
        "hostname": device.get("hostname") or socket.gethostname(),
        "collector_version": __version__,
        "mode": payload["mode"],
        "platform": payload.get("platform"),
        "status": "healthy",
        "message": "manual collector check-in",
    }
    if collector_name:
        checkin_payload["collector_name"] = collector_name
    return checkin_payload


def send_checkin(backend_url: str, checkin_payload: dict[str, Any]) -> dict[str, Any]:
    url = f"{backend_url.rstrip('/')}/api/v1/collectors/checkin"
    body = json.dumps(checkin_payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=15) as response:
        response_body = response.read().decode("utf-8")
    return json.loads(response_body) if response_body else {}


def parse_simple_config_value(value: str) -> Any:
    cleaned = value.strip().strip("'\"")
    lowered = cleaned.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "none", "~"}:
        return None
    return cleaned


def load_simple_yaml_config(text: str) -> dict[str, Any]:
    config: dict[str, Any] = {}
    section: dict[str, Any] | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        if ":" not in stripped:
            raise ValueError(f"invalid config line: {line}")

        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip()

        if indent == 0 and not value:
            section = {}
            config[key] = section
            continue

        if indent > 0 and section is not None:
            section[key] = parse_simple_config_value(value)
            continue

        config[key] = parse_simple_config_value(value)
        section = None

    return config


def load_config(path: str | None) -> dict[str, Any]:
    if not path:
        return {}

    with open(path, encoding="utf-8") as config_file:
        text = config_file.read()

    if path.lower().endswith(".json"):
        payload = json.loads(text)
    else:
        try:
            import yaml
        except ImportError:
            payload = load_simple_yaml_config(text)
        else:
            payload = yaml.safe_load(text)

    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ValueError("config file must contain an object at the top level")
    return payload


def config_value(config: dict[str, Any], section: str, key: str) -> Any:
    value = config.get(section)
    if not isinstance(value, dict):
        return None
    return value.get(key)


def apply_config_defaults(args: argparse.Namespace) -> argparse.Namespace:
    config = load_config(args.config)

    if args.mode is None:
        args.mode = config_value(config, "collector", "mode") or DEFAULT_MODE
    if args.backend_url is None:
        args.backend_url = config_value(config, "backend", "url")
    if args.collector_id is None:
        args.collector_id = config_value(config, "collector", "id")
    if args.collector_name is None:
        args.collector_name = config_value(config, "collector", "name")
    if not args.checkin:
        args.checkin = bool(config_value(config, "checkin", "enabled"))

    return args


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the OpenAssetWatch collector.")
    parser.add_argument(
        "--mode",
        choices=("device", "network", "hybrid"),
        default=None,
        help="Collection mode to run.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print normalized JSON output.",
    )
    parser.add_argument(
        "--backend-url",
        help="Backend base URL for collector check-in.",
    )
    parser.add_argument(
        "--collector-id",
        help="Stable collector identifier used for backend check-in.",
    )
    parser.add_argument(
        "--collector-name",
        help="Optional human-readable collector name used for backend check-in.",
    )
    parser.add_argument(
        "--checkin",
        action="store_true",
        help="Send a lightweight collector check-in to the backend.",
    )
    parser.add_argument(
        "--config",
        help="Path to a collector YAML or JSON config file.",
    )
    return apply_config_defaults(parser.parse_args())


def main() -> int:
    args = parse_args()
    if args.checkin and not args.backend_url:
        raise SystemExit("--backend-url is required when --checkin is provided")
    if args.checkin and not args.collector_id:
        raise SystemExit("--collector-id is required when --checkin is provided")

    payload = build_payload(args.mode)

    if args.checkin:
        checkin_payload = build_checkin_payload(
            payload,
            args.collector_id,
            args.collector_name,
        )
        try:
            checkin_response = send_checkin(args.backend_url, checkin_payload)
        except HTTPError as exc:
            print(f"collector check-in failed: HTTP {exc.code}", file=sys.stderr)
            return 1
        except (URLError, TimeoutError, OSError) as exc:
            print(f"collector check-in failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({"checkin": checkin_response}, sort_keys=True), file=sys.stderr)

    indent = 2 if args.pretty else None
    print(json.dumps(payload, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
