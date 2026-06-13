"""Standalone collection entry point for OpenAssetWatch."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from . import __version__
from .capabilities import collect_platform_capabilities, command_available
from .open_detector import scan_software


SCHEMA_VERSION = "1.0"
POWERSHELL_COMMANDS = ("powershell", "powershell.exe", "pwsh", "pwsh.exe")
DEFAULT_MODE = "device"
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 3600
DEFAULT_INVENTORY_INTERVAL_SECONDS = 86400
COLLECTOR_TOKEN_HEADER = "X-OpenAssetWatch-Collector-Token"
DEFAULT_POLICY_CHECK_INTERVAL_SECONDS = 3600
CAPABILITY_DEVICE_INVENTORY = "device_inventory"
CAPABILITY_NETWORK_NEIGHBORS = "network_neighbors"
CAPABILITY_OPEN_DETECTOR = "open_detector"
KNOWN_CAPABILITIES = (
    CAPABILITY_DEVICE_INVENTORY,
    CAPABILITY_NETWORK_NEIGHBORS,
    CAPABILITY_OPEN_DETECTOR,
    "reverse_dns",
    "mdns",
    "ssdp",
    "netbios",
    "snmp",
    "nmap_light",
    "passive_sensor",
)
INVALID_MAC_TEXT_VALUES = {
    "(incomplete)",
    "<incomplete>",
    "incomplete",
    "none",
    "null",
}


def default_policy_cache_path() -> str:
    system = platform.system().lower()
    if system == "windows":
        return r"C:\ProgramData\OpenAssetWatch\Collector\state\policy-cache.json"
    if system == "linux":
        return "/var/lib/openassetwatch/policy-cache.json"
    if system == "darwin":
        return "/usr/local/var/openassetwatch/policy-cache.json"
    return "policy-cache.json"


def default_policy_hold_file_path() -> str:
    system = platform.system().lower()
    if system == "windows":
        return r"C:\ProgramData\OpenAssetWatch\Collector\policy.hold"
    if system == "linux":
        return "/etc/openassetwatch/policy.hold"
    if system == "darwin":
        return "/Library/Application Support/OpenAssetWatch/Collector/policy.hold"
    return "policy.hold"


class ConfigError(ValueError):
    """Raised when a collector config file cannot be loaded."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_or_create_collector_identity(path: str, install_source: str = "collector-runtime") -> dict[str, Any]:
    identity_path = Path(path)
    if identity_path.exists():
        try:
            payload = json.loads(identity_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ConfigError(f"unable to read collector identity file '{path}': {exc}") from exc
        if not isinstance(payload, dict):
            raise ConfigError(f"collector identity file '{path}' must contain an object")

        collector_guid = normalize_optional_text(payload.get("collector_guid"))
        if not collector_guid:
            raise ConfigError(f"collector identity file '{path}' is missing collector_guid")
        try:
            payload["collector_guid"] = str(uuid.UUID(collector_guid))
        except ValueError as exc:
            raise ConfigError(f"collector identity file '{path}' has invalid collector_guid") from exc
        return payload

    payload = {
        "collector_guid": str(uuid.uuid4()),
        "created_at": utc_now(),
        "install_source": install_source,
    }
    try:
        identity_path.parent.mkdir(parents=True, exist_ok=True)
        identity_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"unable to create collector identity file '{path}': {exc}") from exc
    return payload


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
    if cleaned in INVALID_MAC_TEXT_VALUES or cleaned in {"", "00:00:00:00:00:00"}:
        return None

    compact = re.sub(r"[^0-9a-f]", "", cleaned)
    if len(compact) != 12:
        return None

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


def collect_supported_capabilities(platform_info: dict[str, object]) -> list[str]:
    supported = [
        CAPABILITY_DEVICE_INVENTORY,
        CAPABILITY_OPEN_DETECTOR,
    ]
    if network_collectors_for_platform(platform_info):
        supported.append(CAPABILITY_NETWORK_NEIGHBORS)
    return [capability for capability in KNOWN_CAPABILITIES if capability in supported]


def collect_enabled_capabilities(
    mode: str,
    supported_capabilities: list[str],
    *,
    open_detector_enabled: bool = True,
) -> list[str]:
    supported = set(supported_capabilities)
    enabled: list[str] = []
    if mode in {"device", "hybrid"} and CAPABILITY_DEVICE_INVENTORY in supported:
        enabled.append(CAPABILITY_DEVICE_INVENTORY)
    if mode in {"network", "hybrid"} and CAPABILITY_NETWORK_NEIGHBORS in supported:
        enabled.append(CAPABILITY_NETWORK_NEIGHBORS)
    if (
        mode in {"device", "hybrid"}
        and open_detector_enabled
        and CAPABILITY_OPEN_DETECTOR in supported
    ):
        enabled.append(CAPABILITY_OPEN_DETECTOR)
    return [capability for capability in KNOWN_CAPABILITIES if capability in enabled]


def build_payload(
    mode: str,
    *,
    collector_guid: str | None = None,
    deployment: dict[str, Any] | None = None,
    labels: dict[str, Any] | None = None,
    open_detector_enabled: bool = True,
) -> dict[str, Any]:
    platform_info = collect_platform_capabilities()
    supported_capabilities = collect_supported_capabilities(platform_info)
    enabled_capabilities = collect_enabled_capabilities(
        mode,
        supported_capabilities,
        open_detector_enabled=open_detector_enabled,
    )
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "collector": "openassetwatch_collector",
        "collector_version": __version__,
        "mode": mode,
        "collected_at": utc_now(),
        "platform": platform_info,
        "supported_capabilities": supported_capabilities,
        "enabled_capabilities": enabled_capabilities,
    }
    if collector_guid:
        payload["collector_guid"] = collector_guid
    if deployment:
        payload["deployment"] = deployment
    if labels:
        payload["labels"] = labels

    if mode in {"device", "hybrid"}:
        payload["device"] = collect_device()
        payload["software"] = scan_software(platform_info) if open_detector_enabled else []

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
    for key in ("collector_guid", "deployment", "labels"):
        if payload.get(key):
            checkin_payload[key] = payload[key]
    for key in ("supported_capabilities", "enabled_capabilities"):
        if isinstance(payload.get(key), list):
            checkin_payload[key] = payload[key]
    return checkin_payload


def backend_headers(backend_token: str | None = None) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if backend_token:
        headers[COLLECTOR_TOKEN_HEADER] = backend_token
    return headers


def send_checkin(
    backend_url: str,
    checkin_payload: dict[str, Any],
    backend_token: str | None = None,
) -> dict[str, Any]:
    url = f"{backend_url.rstrip('/')}/api/v1/collectors/checkin"
    body = json.dumps(checkin_payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers=backend_headers(backend_token),
        method="POST",
    )
    with urlopen(request, timeout=15) as response:
        response_body = response.read().decode("utf-8")
    return json.loads(response_body) if response_body else {}


def build_inventory_payload(
    payload: dict[str, Any],
    collector_id: str | None,
    collector_name: str | None,
) -> dict[str, Any]:
    inventory_payload = dict(payload)
    if collector_id:
        inventory_payload["collector_id"] = collector_id
    if collector_name:
        inventory_payload["collector_name"] = collector_name
    return inventory_payload


def send_inventory(
    backend_url: str,
    inventory_payload: dict[str, Any],
    backend_token: str | None = None,
) -> dict[str, Any]:
    url = f"{backend_url.rstrip('/')}/api/v1/collectors/inventory"
    body = json.dumps(inventory_payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers=backend_headers(backend_token),
        method="POST",
    )
    with urlopen(request, timeout=15) as response:
        response_body = response.read().decode("utf-8")
    return json.loads(response_body) if response_body else {}


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def calculate_policy_hash(policy_payload: dict[str, Any]) -> str:
    policy_copy = dict(policy_payload)
    policy_copy.pop("policy_hash", None)
    return f"sha256:{hashlib.sha256(canonical_json(policy_copy).encode('utf-8')).hexdigest()}"


def validate_policy_payload(policy_payload: dict[str, Any]) -> None:
    required = {
        "policy_id",
        "policy_version",
        "policy_hash",
        "license_status",
        "assigned_capabilities",
        "denied_capabilities",
        "policy",
    }
    missing = sorted(required - set(policy_payload))
    if missing:
        raise ConfigError(f"policy is missing required fields: {', '.join(missing)}")
    if not isinstance(policy_payload["policy"], dict):
        raise ConfigError("policy.policy must be an object")
    if policy_payload["policy_hash"] != calculate_policy_hash(policy_payload):
        raise ConfigError("policy hash validation failed")

    policy = policy_payload["policy"]
    mode = policy.get("mode")
    if mode is not None and mode not in {"device", "network", "hybrid"}:
        raise ConfigError("policy mode must be device, network, or hybrid")

    scheduler = policy.get("scheduler", {})
    if scheduler is not None and not isinstance(scheduler, dict):
        raise ConfigError("policy.scheduler must be an object")
    for key in ("heartbeat_interval_seconds", "inventory_interval_seconds"):
        if isinstance(scheduler, dict) and scheduler.get(key) is not None:
            config_interval_seconds(scheduler.get(key), 1, f"policy.scheduler.{key}")

    modules = policy.get("modules", {})
    if modules is not None and not isinstance(modules, dict):
        raise ConfigError("policy.modules must be an object")
    actions = policy.get("actions", {})
    if actions is not None and not isinstance(actions, dict):
        raise ConfigError("policy.actions must be an object")


def send_policy_request(
    backend_url: str,
    backend_token: str | None = None,
    query_params: dict[str, str] | None = None,
) -> dict[str, Any]:
    url = f"{backend_url.rstrip('/')}/api/v1/collectors/policy"
    if query_params:
        url = f"{url}?{urlencode(query_params)}"
    request = Request(
        url,
        headers=backend_headers(backend_token),
        method="GET",
    )
    with urlopen(request, timeout=15) as response:
        response_body = response.read().decode("utf-8")
    return json.loads(response_body) if response_body else {}


def build_policy_query_params(args: argparse.Namespace) -> dict[str, str]:
    query_params: dict[str, str] = {}
    for key in ("collector_guid", "collector_id", "deployment_id"):
        value = getattr(args, key, None)
        if value:
            query_params[key] = str(value)

    platform_value = getattr(args, "policy_platform", None)
    if platform_value:
        query_params["platform"] = str(platform_value)

    labels = getattr(args, "labels", None)
    if isinstance(labels, dict) and labels:
        query_params["labels"] = canonical_json(labels)

    return query_params


def send_policy_status(
    backend_url: str,
    status_payload: dict[str, Any],
    backend_token: str | None = None,
) -> dict[str, Any]:
    url = f"{backend_url.rstrip('/')}/api/v1/collectors/policy-status"
    body = json.dumps(status_payload).encode("utf-8")
    request = Request(
        url,
        data=body,
        headers=backend_headers(backend_token),
        method="POST",
    )
    with urlopen(request, timeout=15) as response:
        response_body = response.read().decode("utf-8")
    return json.loads(response_body) if response_body else {}


def cache_policy(policy_payload: dict[str, Any], cache_path: str | None) -> None:
    if not cache_path:
        return
    path = Path(cache_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(policy_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_cached_policy(cache_path: str | None) -> dict[str, Any] | None:
    if not cache_path:
        return None
    path = Path(cache_path)
    if not path.exists():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ConfigError("cached policy must be an object")
    validate_policy_payload(payload)
    return payload


def apply_policy_to_args(args: argparse.Namespace, policy_payload: dict[str, Any]) -> bool:
    validate_policy_payload(policy_payload)
    policy = policy_payload["policy"]
    supported_capabilities = set(getattr(args, "supported_capabilities", []) or [])
    assigned_capabilities = policy_payload.get("assigned_capabilities")
    if not isinstance(assigned_capabilities, list):
        assigned_capabilities = []
    assigned_capability_set = {str(capability) for capability in assigned_capabilities}
    ignored_capabilities = sorted(assigned_capability_set - supported_capabilities)
    if ignored_capabilities:
        print(
            f"collector ignored unsupported assigned capabilities: {', '.join(ignored_capabilities)}",
            file=sys.stderr,
        )

    mode = policy.get("mode")
    if mode in {"device", "network", "hybrid"}:
        args.mode = mode

    scheduler = policy.get("scheduler")
    if isinstance(scheduler, dict):
        if scheduler.get("heartbeat_interval_seconds") is not None:
            args.heartbeat_interval_seconds = config_interval_seconds(
                scheduler.get("heartbeat_interval_seconds"),
                args.heartbeat_interval_seconds,
                "policy.scheduler.heartbeat_interval_seconds",
            )
        if scheduler.get("inventory_interval_seconds") is not None:
            args.inventory_interval_seconds = config_interval_seconds(
                scheduler.get("inventory_interval_seconds"),
                args.inventory_interval_seconds,
                "policy.scheduler.inventory_interval_seconds",
            )

    modules = policy.get("modules")
    if isinstance(modules, dict):
        open_detector = modules.get("open_detector")
        if (
            isinstance(open_detector, dict)
            and open_detector.get("enabled") is not None
            and CAPABILITY_OPEN_DETECTOR in supported_capabilities
            and CAPABILITY_OPEN_DETECTOR in assigned_capability_set
        ):
            args.open_detector_enabled = bool(open_detector.get("enabled"))

    actions = policy.get("actions")
    return bool(isinstance(actions, dict) and actions.get("run_inventory_now"))


def build_policy_status_payload(
    args: argparse.Namespace,
    policy_payload: dict[str, Any] | None,
    status: str,
    error: str | None = None,
) -> dict[str, Any]:
    payload = {
        "collector_guid": args.collector_guid,
        "collector_id": args.collector_id,
        "policy_id": "local-policy-hold",
        "policy_version": 0,
        "policy_hash": "sha256:none",
        "policy_status": status,
    }
    if policy_payload:
        payload["policy_id"] = policy_payload.get("policy_id") or payload["policy_id"]
        payload["policy_version"] = policy_payload.get("policy_version") or payload["policy_version"]
        payload["policy_hash"] = policy_payload.get("policy_hash") or payload["policy_hash"]
    if error:
        payload["policy_error"] = error
    return {key: value for key, value in payload.items() if value is not None}


def report_policy_status(
    args: argparse.Namespace,
    policy_payload: dict[str, Any] | None,
    status: str,
    error: str | None = None,
) -> None:
    if not args.backend_url:
        return
    try:
        response = send_policy_status(
            args.backend_url,
            build_policy_status_payload(args, policy_payload, status, error),
            args.backend_token,
        )
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        print(f"collector policy status report failed: {exc}", file=sys.stderr)
        return
    print(json.dumps({"policy_status": response}, sort_keys=True), file=sys.stderr)


def retrieve_and_apply_policy(args: argparse.Namespace) -> bool:
    if not getattr(args, "policy_enabled", False):
        return False

    if args.policy_hold_file_path and Path(args.policy_hold_file_path).exists():
        print(f"collector policy held by {args.policy_hold_file_path}", file=sys.stderr)
        cached_policy = None
        try:
            cached_policy = load_cached_policy(args.policy_cache_path)
        except (OSError, json.JSONDecodeError, ConfigError) as exc:
            print(f"collector cached policy unavailable while held: {exc}", file=sys.stderr)
        report_policy_status(args, cached_policy, "held")
        return False

    try:
        policy_payload = send_policy_request(
            args.backend_url,
            args.backend_token,
            build_policy_query_params(args),
        )
        validate_policy_payload(policy_payload)
        cache_policy(policy_payload, args.policy_cache_path)
        run_inventory_now = apply_policy_to_args(args, policy_payload)
        report_policy_status(args, policy_payload, "applied")
        return run_inventory_now
    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError, ConfigError) as exc:
        print(f"collector policy retrieval failed: {exc}", file=sys.stderr)
        try:
            cached_policy = load_cached_policy(args.policy_cache_path)
            if cached_policy is None:
                raise ConfigError("no cached policy found")
            run_inventory_now = apply_policy_to_args(args, cached_policy)
            print("collector using cached policy", file=sys.stderr)
            return run_inventory_now
        except (OSError, json.JSONDecodeError, ConfigError) as cache_exc:
            print(f"collector cached policy unavailable: {cache_exc}", file=sys.stderr)
        return False


def perform_checkin(
    *,
    backend_url: str,
    backend_token: str | None,
    payload: dict[str, Any],
    collector_id: str,
    collector_name: str | None,
) -> bool:
    checkin_payload = build_checkin_payload(
        payload,
        collector_id,
        collector_name,
    )
    try:
        checkin_response = send_checkin(backend_url, checkin_payload, backend_token)
    except HTTPError as exc:
        print(f"collector check-in failed: HTTP {exc.code}", file=sys.stderr)
        return False
    except (URLError, TimeoutError, OSError) as exc:
        print(f"collector check-in failed: {exc}", file=sys.stderr)
        return False

    print(json.dumps({"checkin": checkin_response}, sort_keys=True), file=sys.stderr)
    return True


def perform_inventory_upload(
    *,
    backend_url: str,
    backend_token: str | None,
    payload: dict[str, Any],
    collector_id: str | None,
    collector_name: str | None,
) -> bool:
    inventory_payload = build_inventory_payload(
        payload,
        collector_id,
        collector_name,
    )
    try:
        inventory_response = send_inventory(backend_url, inventory_payload, backend_token)
    except HTTPError as exc:
        print(f"collector inventory upload failed: HTTP {exc.code}", file=sys.stderr)
        return False
    except (URLError, TimeoutError, OSError) as exc:
        print(f"collector inventory upload failed: {exc}", file=sys.stderr)
        return False

    print(json.dumps({"inventory": inventory_response}, sort_keys=True), file=sys.stderr)
    return True


def run_backend_cycle(
    args: argparse.Namespace,
    *,
    checkin: bool,
    upload_inventory: bool,
) -> dict[str, Any]:
    payload = build_payload(
        args.mode,
        collector_guid=args.collector_guid,
        deployment=args.deployment,
        labels=args.labels,
        open_detector_enabled=getattr(args, "open_detector_enabled", True),
    )
    args.supported_capabilities = payload.get("supported_capabilities", [])
    platform_info = payload.get("platform")
    if isinstance(platform_info, dict):
        args.policy_platform = platform_info.get("system_key") or platform_info.get("system")

    if checkin:
        print(f"{utc_now()} collector check-in starting", file=sys.stderr)
        perform_checkin(
            backend_url=args.backend_url,
            backend_token=args.backend_token,
            payload=payload,
            collector_id=args.collector_id,
            collector_name=args.collector_name,
        )
        run_inventory_now = retrieve_and_apply_policy(args)
        if getattr(args, "policy_enabled", False):
            payload = build_payload(
                args.mode,
                collector_guid=args.collector_guid,
                deployment=args.deployment,
                labels=args.labels,
                open_detector_enabled=getattr(args, "open_detector_enabled", True),
            )
            args.supported_capabilities = payload.get("supported_capabilities", [])
            platform_info = payload.get("platform")
            if isinstance(platform_info, dict):
                args.policy_platform = platform_info.get("system_key") or platform_info.get("system")
        if run_inventory_now:
            upload_inventory = True

    if upload_inventory:
        print(f"{utc_now()} collector inventory upload starting", file=sys.stderr)
        perform_inventory_upload(
            backend_url=args.backend_url,
            backend_token=args.backend_token,
            payload=payload,
            collector_id=args.collector_id,
            collector_name=args.collector_name,
        )

    return payload


def run_scheduler(
    args: argparse.Namespace,
    *,
    sleep_func: Any = time.sleep,
    monotonic_func: Any = time.monotonic,
    max_cycles: int | None = None,
) -> int:
    print(
        (
            f"{utc_now()} scheduler starting "
            f"heartbeat_interval_seconds={args.heartbeat_interval_seconds} "
            f"inventory_interval_seconds={args.inventory_interval_seconds}"
        ),
        file=sys.stderr,
    )

    try:
        run_backend_cycle(args, checkin=True, upload_inventory=True)
        completed_cycles = 1
        if max_cycles is not None and completed_cycles >= max_cycles:
            return 0

        next_heartbeat = monotonic_func() + args.heartbeat_interval_seconds
        next_inventory = monotonic_func() + args.inventory_interval_seconds

        while True:
            now = monotonic_func()
            wait_seconds = max(0.0, min(next_heartbeat, next_inventory) - now)
            if wait_seconds:
                sleep_func(wait_seconds)

            now = monotonic_func()
            run_checkin = now >= next_heartbeat
            run_inventory = now >= next_inventory
            if run_checkin or run_inventory:
                run_backend_cycle(args, checkin=run_checkin, upload_inventory=run_inventory)
                completed_cycles += 1
                if run_checkin:
                    next_heartbeat = now + args.heartbeat_interval_seconds
                if run_inventory:
                    next_inventory = now + args.inventory_interval_seconds

            if max_cycles is not None and completed_cycles >= max_cycles:
                return 0
    except KeyboardInterrupt:
        print(f"{utc_now()} scheduler stopped", file=sys.stderr)
        return 0


def parse_simple_config_value(value: str) -> Any:
    cleaned = value.strip().strip("'\"")
    lowered = cleaned.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "none", "~"}:
        return None
    if re.fullmatch(r"-?\d+", cleaned):
        return int(cleaned)
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

    try:
        with open(path, encoding="utf-8") as config_file:
            text = config_file.read()
    except OSError as exc:
        message = exc.strerror or str(exc)
        raise ConfigError(f"unable to read config file '{path}': {message}") from exc

    if path.lower().endswith(".json"):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"invalid config file '{path}': {exc.msg}") from exc
    else:
        try:
            import yaml
        except ImportError:
            try:
                payload = load_simple_yaml_config(text)
            except ValueError as exc:
                raise ConfigError(f"invalid config file '{path}': {exc}") from exc
        else:
            try:
                payload = yaml.safe_load(text)
            except Exception as exc:
                raise ConfigError(f"invalid config file '{path}': {exc}") from exc

    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ConfigError(f"config file '{path}' must contain an object at the top level")
    return payload


def config_value(config: dict[str, Any], section: str, key: str) -> Any:
    value = config.get(section)
    if not isinstance(value, dict):
        return None
    return value.get(key)


def config_section(config: dict[str, Any], section: str) -> dict[str, Any]:
    value = config.get(section)
    return value if isinstance(value, dict) else {}


def parse_label_args(label_items: list[str] | None) -> dict[str, str]:
    labels: dict[str, str] = {}
    for item in label_items or []:
        if "=" not in item:
            raise ConfigError("--label values must use key=value format")
        key, value = item.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ConfigError("--label values must include a non-empty key")
        labels[key] = value
    return labels


def normalize_metadata_mapping(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be an object")
    return {
        str(key): item
        for key, item in value.items()
        if str(key).strip() and item is not None
    }


def deployment_from_args(args: argparse.Namespace) -> dict[str, Any] | None:
    deployment = {
        "deployment_id": args.deployment_id,
        "business_unit": args.business_unit,
        "site": args.site,
        "environment": args.deployment_environment,
        "install_ring": args.install_ring,
    }
    cleaned = {key: value for key, value in deployment.items() if value is not None}
    return cleaned or None


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def config_interval_seconds(value: Any, default: int, key: str) -> int:
    if value is None:
        return default
    display_key = key if key.startswith("policy.") else f"scheduler.{key}"
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{display_key} must be an integer") from exc
    if parsed <= 0:
        raise ConfigError(f"{display_key} must be greater than 0")
    return parsed


def apply_config_defaults(args: argparse.Namespace) -> argparse.Namespace:
    config = load_config(args.config)

    if args.mode is None:
        args.mode = config_value(config, "collector", "mode") or DEFAULT_MODE
    if args.backend_url is None:
        args.backend_url = config_value(config, "backend", "url")
    if args.backend_token is None:
        args.backend_token = config_value(config, "backend", "token")
    if args.collector_id is None:
        args.collector_id = config_value(config, "collector", "id")
    if args.collector_name is None:
        args.collector_name = config_value(config, "collector", "name")
    if args.collector_guid is None:
        args.collector_guid = config_value(config, "collector", "guid")
    if args.identity_file is None:
        args.identity_file = config_value(config, "identity", "path")
    if args.deployment_id is None:
        args.deployment_id = config_value(config, "deployment", "deployment_id")
    if args.business_unit is None:
        args.business_unit = config_value(config, "deployment", "business_unit")
    if args.site is None:
        args.site = config_value(config, "deployment", "site")
    if args.deployment_environment is None:
        args.deployment_environment = config_value(config, "deployment", "environment")
    if args.install_ring is None:
        args.install_ring = config_value(config, "deployment", "install_ring")
    if not args.checkin:
        args.checkin = bool(config_value(config, "checkin", "enabled"))
    if not args.upload_inventory:
        args.upload_inventory = bool(config_value(config, "inventory", "upload_enabled"))
    if not args.run_forever:
        args.run_forever = bool(config_value(config, "scheduler", "enabled"))
    if args.heartbeat_interval_seconds is None:
        args.heartbeat_interval_seconds = config_interval_seconds(
            config_value(config, "scheduler", "heartbeat_interval_seconds"),
            DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
            "heartbeat_interval_seconds",
        )
    if args.inventory_interval_seconds is None:
        args.inventory_interval_seconds = config_interval_seconds(
            config_value(config, "scheduler", "inventory_interval_seconds"),
            DEFAULT_INVENTORY_INTERVAL_SECONDS,
            "inventory_interval_seconds",
        )
    if not getattr(args, "policy_enabled", False):
        args.policy_enabled = bool(config_value(config, "policy", "enabled"))
    if getattr(args, "policy_cache_path", None) is None:
        args.policy_cache_path = config_value(config, "policy", "cache_path")
    if getattr(args, "policy_hold_file_path", None) is None:
        args.policy_hold_file_path = config_value(config, "policy", "hold_file_path")
    if getattr(args, "policy_check_interval_seconds", None) is None:
        args.policy_check_interval_seconds = config_interval_seconds(
            config_value(config, "policy", "check_interval_seconds"),
            DEFAULT_POLICY_CHECK_INTERVAL_SECONDS,
            "policy.check_interval_seconds",
        )
    if getattr(args, "open_detector_enabled", None) is None:
        args.open_detector_enabled = True

    if args.policy_enabled:
        if args.policy_cache_path is None:
            args.policy_cache_path = default_policy_cache_path()
        if args.policy_hold_file_path is None:
            args.policy_hold_file_path = default_policy_hold_file_path()

    config_labels = normalize_metadata_mapping(config_section(config, "labels"), "labels")
    cli_labels = parse_label_args(getattr(args, "label", []))
    labels = {**config_labels, **cli_labels}
    args.labels = labels or None
    args.deployment = deployment_from_args(args)

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
        "--backend-token",
        help="Optional backend collector token sent in the collector auth header.",
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
        "--collector-guid",
        help="Stable installed collector GUID. Usually loaded from identity.json.",
    )
    parser.add_argument(
        "--identity-file",
        help="Path to persistent collector identity.json.",
    )
    parser.add_argument(
        "--deployment-id",
        help="Optional deployment grouping ID.",
    )
    parser.add_argument(
        "--business-unit",
        help="Optional deployment business unit label.",
    )
    parser.add_argument(
        "--site",
        help="Optional deployment site/location label.",
    )
    parser.add_argument(
        "--environment",
        dest="deployment_environment",
        help="Optional deployment environment label.",
    )
    parser.add_argument(
        "--install-ring",
        help="Optional deployment install ring.",
    )
    parser.add_argument(
        "--label",
        action="append",
        default=[],
        help="Optional flexible label in key=value form. May be repeated.",
    )
    parser.add_argument(
        "--checkin",
        action="store_true",
        help="Send a lightweight collector check-in to the backend.",
    )
    parser.add_argument(
        "--upload-inventory",
        action="store_true",
        help="Upload the full collector inventory payload to the backend.",
    )
    parser.add_argument(
        "--run-forever",
        action="store_true",
        help="Run scheduled check-in and inventory upload cycles until stopped.",
    )
    parser.add_argument(
        "--daemon",
        action="store_true",
        dest="run_forever",
        help="Alias for --run-forever.",
    )
    parser.add_argument(
        "--heartbeat-interval-seconds",
        type=positive_int,
        default=None,
        help="Scheduled check-in interval in seconds.",
    )
    parser.add_argument(
        "--inventory-interval-seconds",
        type=positive_int,
        default=None,
        help="Scheduled inventory upload interval in seconds.",
    )
    parser.add_argument(
        "--enable-policy",
        action="store_true",
        dest="policy_enabled",
        help="Enable collector policy retrieval from the OpenAssetWatch Control Plane.",
    )
    parser.add_argument(
        "--policy-cache-path",
        help="Path for cached last known good collector policy.",
    )
    parser.add_argument(
        "--policy-hold-file-path",
        help="Path to an emergency hold file that blocks remote policy application.",
    )
    parser.add_argument(
        "--policy-check-interval-seconds",
        type=positive_int,
        default=None,
        help="Future policy check interval in seconds.",
    )
    parser.set_defaults(open_detector_enabled=None)
    parser.add_argument(
        "--config",
        help="Path to a collector YAML or JSON config file.",
    )
    try:
        return apply_config_defaults(parser.parse_args())
    except ConfigError as exc:
        parser.error(str(exc))


def main() -> int:
    args = parse_args()
    if args.identity_file and not args.collector_guid:
        try:
            identity = load_or_create_collector_identity(args.identity_file)
        except ConfigError as exc:
            raise SystemExit(str(exc)) from exc
        args.collector_guid = identity["collector_guid"]

    if args.run_forever and not args.backend_url:
        raise SystemExit("--backend-url is required when scheduled mode is enabled")
    if args.run_forever and not args.collector_id:
        raise SystemExit("--collector-id is required when scheduled mode is enabled")
    if args.checkin and not args.backend_url:
        raise SystemExit("--backend-url is required when --checkin is provided")
    if args.checkin and not args.collector_id:
        raise SystemExit("--collector-id is required when --checkin is provided")
    if args.upload_inventory and not args.backend_url:
        raise SystemExit("--backend-url is required when --upload-inventory is provided")
    if args.policy_enabled and not args.backend_url:
        raise SystemExit("--backend-url is required when policy retrieval is enabled")

    if args.run_forever:
        return run_scheduler(args)

    payload = build_payload(
        args.mode,
        collector_guid=args.collector_guid,
        deployment=args.deployment,
        labels=args.labels,
        open_detector_enabled=getattr(args, "open_detector_enabled", True),
    )
    args.supported_capabilities = payload.get("supported_capabilities", [])

    if args.checkin:
        if not perform_checkin(
            backend_url=args.backend_url,
            backend_token=args.backend_token,
            payload=payload,
            collector_id=args.collector_id,
            collector_name=args.collector_name,
        ):
            return 1
        run_inventory_now = retrieve_and_apply_policy(args)
        if getattr(args, "policy_enabled", False):
            payload = build_payload(
                args.mode,
                collector_guid=args.collector_guid,
                deployment=args.deployment,
                labels=args.labels,
                open_detector_enabled=getattr(args, "open_detector_enabled", True),
            )
            args.supported_capabilities = payload.get("supported_capabilities", [])
        if run_inventory_now:
            args.upload_inventory = True

    if args.upload_inventory:
        if not perform_inventory_upload(
            backend_url=args.backend_url,
            backend_token=args.backend_token,
            payload=payload,
            collector_id=args.collector_id,
            collector_name=args.collector_name,
        ):
            return 1

    indent = 2 if args.pretty else None
    print(json.dumps(payload, indent=indent, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
