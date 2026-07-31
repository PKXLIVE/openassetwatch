"""Deterministic normalization for software, packages, and firmware evidence."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Mapping, Sequence
from urllib.parse import quote, unquote, urlsplit


COMPONENT_MODEL_VERSION = "oaw.components.v1"
MAX_COMPONENTS_PER_ASSET = 1_000
MAX_COMPONENT_NAME = 240
MAX_COMPONENT_VERSION = 160
MAX_COMPONENT_METADATA_FIELDS = 8
MAX_COMPONENT_EVIDENCE_IDS = 16
MAX_COMPONENT_FUTURE_SKEW = timedelta(minutes=5)
DEFAULT_COMPONENT_FRESH_HOURS = 72
DEFAULT_COMPONENT_STALE_HOURS = 24 * 30

ComponentType = Literal[
    "application",
    "operating-system-package",
    "library",
    "runtime",
    "driver",
    "firmware",
    "operating-system",
    "security-tool",
    "unknown",
]
FirmwareEvidenceType = Literal[
    "direct",
    "vendor-reported",
    "collector-reported",
    "inferred",
    "unknown",
]
NormalizationStatus = Literal[
    "normalized",
    "identity-uncertain",
    "version-unknown",
    "unsupported-ecosystem",
    "insufficient-firmware-evidence",
]

SUPPORTED_ECOSYSTEMS = frozenset(
    {
        "pypi",
        "npm",
        "maven",
        "nuget",
        "golang",
        "deb",
        "rpm",
        "alpine",
        "generic",
        "firmware",
        "operating-system",
    }
)
PURL_TYPES = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "nuget": "nuget",
    "golang": "golang",
    "deb": "deb",
    "rpm": "rpm",
    "alpine": "alpine",
    "generic": "generic",
}
COMPONENT_TYPE_ALIASES = {
    "app": "application",
    "application": "application",
    "package": "operating-system-package",
    "os-package": "operating-system-package",
    "operating-system-package": "operating-system-package",
    "library": "library",
    "runtime": "runtime",
    "driver": "driver",
    "firmware": "firmware",
    "os": "operating-system",
    "operating-system": "operating-system",
    "security-tool": "security-tool",
    "security_tool": "security-tool",
    "unknown": "unknown",
}
ECOSYSTEM_ALIASES = {
    "python": "pypi",
    "pypi": "pypi",
    "node": "npm",
    "nodejs": "npm",
    "npm": "npm",
    "java": "maven",
    "maven": "maven",
    "dotnet": "nuget",
    "nuget": "nuget",
    "go": "golang",
    "golang": "golang",
    "debian": "deb",
    "ubuntu": "deb",
    "dpkg": "deb",
    "deb": "deb",
    "redhat": "rpm",
    "rhel": "rpm",
    "fedora": "rpm",
    "centos": "rpm",
    "rpm": "rpm",
    "apk": "alpine",
    "alpine": "alpine",
    "application": "generic",
    "generic": "generic",
    "firmware": "firmware",
    "os": "operating-system",
    "operating-system": "operating-system",
}
FIRMWARE_EVIDENCE_TYPES = frozenset(
    {
        "direct",
        "vendor-reported",
        "collector-reported",
        "inferred",
        "unknown",
    }
)
SAFE_METADATA_FIELDS = frozenset(
    {
        "channel",
        "description",
        "edition",
        "install_state",
        "language",
        "release",
        "repository",
        "service_pack",
    }
)
_CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x1f\x7f]")
_SAFE_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._+~-]{0,239}$")
_SAFE_PURL_SEGMENT_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,239}$"
)
_SAFE_ARCHITECTURE_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,39}$")
_PURL_RE = re.compile(
    r"^pkg:(?P<type>[a-z][a-z0-9.+-]*)/"
    r"(?:(?P<namespace>[^@?#]+)/)?"
    r"(?P<name>[^@?#]+)"
    r"(?:@(?P<version>[^?#]+))?$"
)


class ComponentValidationError(ValueError):
    """Raised when component data exceeds a trust or boundedness contract."""


@dataclass(frozen=True)
class ParsedPurl:
    ecosystem: str
    namespace: str | None
    name: str
    version: str | None
    canonical: str


@dataclass(frozen=True)
class NormalizedComponent:
    component_id: str
    asset_id: str
    site_id: str
    component_type: ComponentType
    ecosystem: str
    namespace: str | None
    vendor: str | None
    name: str
    normalized_name: str
    version: str | None
    normalized_version: str | None
    architecture: str | None
    package_manager: str | None
    canonical_identifier: str | None
    cpe_hint: str | None
    install_scope: str
    source_type: str
    source_id: str
    firmware_evidence_type: FirmwareEvidenceType
    evidence_ids: tuple[str, ...]
    observed_at: datetime
    first_seen_at: datetime
    last_seen_at: datetime
    freshness: str
    confidence: float
    normalization_status: NormalizationStatus
    metadata: dict[str, str]
    inventory_complete: bool
    model_version: str = COMPONENT_MODEL_VERSION

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def bounded_text(value: Any, *, limit: int = MAX_COMPONENT_NAME) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = " ".join(value.strip().split())
    if not cleaned or _CONTROL_CHARACTER_RE.search(cleaned):
        return ""
    return cleaned[:limit]


def normalized_token(value: Any, *, limit: int = MAX_COMPONENT_NAME) -> str:
    text = bounded_text(value, limit=limit).casefold()
    text = re.sub(r"[\s_/\\]+", "-", text)
    text = re.sub(r"[^a-z0-9.+~-]+", "-", text)
    return re.sub(r"-{2,}", "-", text).strip("-.")


def normalize_ecosystem(value: Any, *, component_type: str = "") -> str:
    candidate = normalized_token(value, limit=40)
    if not candidate:
        if component_type == "firmware":
            return "firmware"
        if component_type == "operating-system":
            return "operating-system"
        return "generic"
    return ECOSYSTEM_ALIASES.get(candidate, candidate)


def normalize_component_type(value: Any, *, ecosystem: str) -> ComponentType:
    candidate = normalized_token(value, limit=48)
    if candidate in COMPONENT_TYPE_ALIASES:
        return COMPONENT_TYPE_ALIASES[candidate]  # type: ignore[return-value]
    if ecosystem in {"deb", "rpm", "alpine"}:
        return "operating-system-package"
    if ecosystem == "firmware":
        return "firmware"
    if ecosystem == "operating-system":
        return "operating-system"
    return "application"


def normalize_version_text(value: Any) -> str | None:
    version = bounded_text(value, limit=MAX_COMPONENT_VERSION)
    if not version:
        return None
    if any(character.isspace() for character in version):
        version = " ".join(version.split())
    return version


def normalize_architecture(value: Any) -> str | None:
    architecture = normalized_token(value, limit=40)
    if architecture in {"x86-64", "x64"}:
        architecture = "amd64"
    elif architecture in {"aarch64"}:
        architecture = "arm64"
    if not architecture or not _SAFE_ARCHITECTURE_RE.fullmatch(architecture):
        return None
    return architecture


def _purl_segment(value: str) -> str:
    return quote(value, safe="._-~+")


def _canonical_purl_name(ecosystem: str, value: str) -> str | None:
    if not value or "/" in value or "\\" in value:
        return None
    if ecosystem == "pypi":
        value = re.sub(r"[-_.]+", "-", value).casefold()
    elif ecosystem in {"npm", "nuget", "deb", "rpm", "alpine"}:
        value = value.casefold()
    if not _SAFE_PURL_SEGMENT_RE.fullmatch(value):
        return None
    return value


def _canonical_purl_namespace(
    ecosystem: str,
    value: str | None,
) -> str | None:
    if not value:
        return None
    if ecosystem in {"pypi", "nuget"}:
        return None
    parts = value.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        return None
    normalized: list[str] = []
    for index, part in enumerate(parts):
        if ecosystem == "npm" and index == 0 and part.startswith("@"):
            part = part[1:]
            if not part:
                return None
            part = "@" + part.casefold()
            if not _SAFE_PURL_SEGMENT_RE.fullmatch(part[1:]):
                return None
        else:
            if ecosystem in {"deb", "rpm", "alpine"}:
                part = part.casefold()
            if not _SAFE_PURL_SEGMENT_RE.fullmatch(part):
                return None
        normalized.append(part)
    return "/".join(normalized)


def build_purl(
    *,
    ecosystem: str,
    namespace: str | None,
    name: str,
    version: str | None = None,
) -> str | None:
    purl_type = PURL_TYPES.get(ecosystem)
    safe_name = _canonical_purl_name(ecosystem, name)
    safe_namespace = _canonical_purl_namespace(ecosystem, namespace)
    if not purl_type or not safe_name:
        return None
    if namespace and safe_namespace is None:
        return None
    path = (
        "/".join(_purl_segment(part) for part in safe_namespace.split("/"))
        + "/"
        if safe_namespace
        else ""
    )
    path += _purl_segment(safe_name)
    safe_version = normalize_version_text(version)
    if safe_version:
        path += "@" + quote(safe_version, safe="._+~:-")
    return f"pkg:{purl_type}/{path}"


def parse_purl(value: Any) -> ParsedPurl | None:
    raw = bounded_text(value, limit=600)
    if not raw or raw != raw.strip() or "?" in raw or "#" in raw:
        return None
    if re.search(r"%(?![0-9A-Fa-f]{2})", raw):
        return None
    match = _PURL_RE.fullmatch(raw)
    if not match:
        return None
    purl_type = match.group("type")
    if purl_type not in PURL_TYPES:
        return None
    ecosystem = PURL_TYPES[purl_type]
    namespace = unquote(match.group("namespace") or "")
    name = unquote(match.group("name") or "")
    version = unquote(match.group("version") or "") or None
    if "/" in name or "\\" in namespace or "\\" in name:
        return None
    safe_namespace = _canonical_purl_namespace(
        ecosystem,
        namespace or None,
    )
    if namespace and safe_namespace is None:
        return None
    safe_name = _canonical_purl_name(ecosystem, name)
    if safe_name is None:
        return None
    safe_version = normalize_version_text(version)
    canonical = build_purl(
        ecosystem=ecosystem,
        namespace=safe_namespace,
        name=safe_name,
        version=safe_version,
    )
    if canonical is None:
        return None
    return ParsedPurl(
        ecosystem=ecosystem,
        namespace=safe_namespace,
        name=safe_name,
        version=safe_version,
        canonical=canonical,
    )


def purl_identity(value: str | None) -> str | None:
    parsed = parse_purl(value)
    if parsed is None:
        return None
    return build_purl(
        ecosystem=parsed.ecosystem,
        namespace=parsed.namespace,
        name=parsed.name,
    )


def _utc(value: Any, *, received_at: datetime) -> datetime:
    if isinstance(value, datetime):
        candidate = value
    elif isinstance(value, str):
        try:
            candidate = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return received_at
    else:
        return received_at
    if candidate.tzinfo is None or candidate.utcoffset() is None:
        return received_at
    candidate = candidate.astimezone(timezone.utc)
    return min(candidate, received_at + MAX_COMPONENT_FUTURE_SKEW)


def component_freshness(observed_at: datetime, *, now: datetime) -> str:
    age = max(timedelta(0), now - observed_at)
    if age <= timedelta(hours=DEFAULT_COMPONENT_FRESH_HOURS):
        return "fresh"
    if age <= timedelta(hours=DEFAULT_COMPONENT_STALE_HOURS):
        return "aging"
    return "stale"


def _confidence(value: Any, *, default: float) -> float:
    if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        return default
    return max(0.0, min(float(value), 1.0))


def _source_context(
    payload: Mapping[str, Any],
    *,
    asset: Mapping[str, Any],
    source_authenticated: bool,
) -> tuple[str, str, bool]:
    declared_type = normalized_token(payload.get("sensor_type"), limit=64)
    observation_source = normalized_token(
        payload.get("observation_source"),
        limit=64,
    )
    source_id = bounded_text(
        payload.get("sensor_id")
        or payload.get("agent_id")
        or asset.get("source_agent_id"),
        limit=160,
    )
    if not source_authenticated:
        return "untrusted-ingestion", "untrusted-local-inventory", False
    if declared_type in {"endpoint-collector", "endpoint-agent", "collector"}:
        return "endpoint-collector", source_id or "endpoint-source", True
    if declared_type == "passive-network-sensor":
        return "passive-network-sensor", source_id or "passive-source", False
    if declared_type == "connector":
        return "reviewed-connector", source_id or "connector-source", True
    if observation_source in {"endpoint-inventory", "local-inventory"}:
        return "connector", source_id or "connector-source", False
    if observation_source == "passive-network":
        return "passive-network-sensor", source_id or "passive-source", False
    return "connector", source_id or "connector-source", False


def _component_entries(asset: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    metadata = asset.get("metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    values: list[Mapping[str, Any]] = []
    for container in (asset, metadata):
        for field_name, default_type in (
            ("components", None),
            ("software", "application"),
            ("packages", "operating-system-package"),
            ("firmware", "firmware"),
        ):
            entries = container.get(field_name)
            if isinstance(entries, Mapping) and field_name == "firmware":
                entries = [entries]
            if not isinstance(entries, list):
                continue
            for entry in entries[:MAX_COMPONENTS_PER_ASSET]:
                if isinstance(entry, Mapping):
                    values.append(
                        {**entry, "_default_component_type": default_type}
                    )
                elif isinstance(entry, str):
                    values.append(
                        {
                            "name": entry,
                            "_default_component_type": default_type,
                        }
                    )
                if len(values) >= MAX_COMPONENTS_PER_ASSET:
                    return values
    return values


def _safe_metadata(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    result: dict[str, str] = {}
    for key in sorted(SAFE_METADATA_FIELDS):
        text = bounded_text(value.get(key), limit=160)
        if text:
            result[key] = text
        if len(result) >= MAX_COMPONENT_METADATA_FIELDS:
            break
    return result


def _evidence_ids(
    entry: Mapping[str, Any],
    *,
    site_id: str,
    asset_id: str,
    source_id: str,
    identity: str,
    observed_at: datetime,
) -> tuple[str, ...]:
    supplied = entry.get("evidence_ids")
    values: list[str] = []
    claims: list[str] = []
    if isinstance(supplied, Sequence) and not isinstance(supplied, (str, bytes)):
        for value in supplied[:MAX_COMPONENT_EVIDENCE_IDS]:
            candidate = bounded_text(value, limit=80)
            if re.fullmatch(r"[a-z][a-z0-9_-]{3,79}", candidate):
                claims.append(candidate)
    for claim in claims or ["server-observation"]:
        canonical = "\x00".join(
            (
                site_id,
                asset_id,
                source_id,
                identity,
                claim,
            )
        )
        values.append(
            "cpe_"
            + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]
        )
    return tuple(dict.fromkeys(values))


def component_id_for(
    *,
    site_id: str,
    asset_id: str,
    identity: str,
    architecture: str | None,
    install_scope: str,
) -> str:
    canonical = "\x00".join(
        (
            site_id,
            asset_id,
            identity.casefold(),
            architecture or "",
            install_scope,
        )
    )
    return "cmp_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def _normalized_component(
    entry: Mapping[str, Any],
    *,
    site_id: str,
    asset_id: str,
    source_type: str,
    source_id: str,
    direct_source: bool,
    received_at: datetime,
    default_observed_at: Any,
    default_confidence: float,
    inventory_complete: bool,
) -> NormalizedComponent | None:
    raw_purl = entry.get("purl") or entry.get("package_url")
    parsed_purl = parse_purl(raw_purl)
    initial_type = (
        entry.get("component_type")
        or entry.get("type")
        or entry.get("_default_component_type")
        or ""
    )
    ecosystem = (
        parsed_purl.ecosystem
        if parsed_purl
        else normalize_ecosystem(
            entry.get("ecosystem") or entry.get("package_manager"),
            component_type=normalized_token(initial_type, limit=48),
        )
    )
    component_type = normalize_component_type(initial_type, ecosystem=ecosystem)
    raw_name = (
        entry.get("name")
        or entry.get("product")
        or entry.get("package")
        or (parsed_purl.name if parsed_purl else None)
    )
    name = bounded_text(raw_name)
    normalized_name = normalized_token(
        parsed_purl.name if parsed_purl else name
    )
    if not name or not normalized_name:
        return None
    raw_namespace = entry.get("namespace") or (
        parsed_purl.namespace if parsed_purl else None
    )
    namespace = (
        parsed_purl.namespace
        if parsed_purl
        else _canonical_purl_namespace(
            ecosystem,
            bounded_text(raw_namespace, limit=160) or None,
        )
    )
    vendor = bounded_text(
        entry.get("vendor") or entry.get("manufacturer"),
        limit=160,
    ) or None
    if component_type == "firmware" and not vendor and namespace:
        vendor = namespace
    version = normalize_version_text(
        entry.get("version")
        or entry.get("firmware_version")
        or (parsed_purl.version if parsed_purl else None)
    )
    architecture = normalize_architecture(entry.get("architecture"))
    package_manager = normalized_token(entry.get("package_manager"), limit=48)
    package_manager = package_manager or None
    install_scope = normalized_token(
        entry.get("install_scope") or entry.get("scope") or "system",
        limit=40,
    ) or "system"

    canonical_identifier = (
        purl_identity(parsed_purl.canonical)
        if parsed_purl
        else build_purl(
            ecosystem=ecosystem,
            namespace=namespace,
            name=name,
        )
        if ecosystem not in {"generic", "firmware", "operating-system"}
        else None
    )
    reviewed_cpe = bool(entry.get("cpe_reviewed"))
    cpe_hint = (
        bounded_text(entry.get("cpe_hint") or entry.get("cpe"), limit=500)
        if reviewed_cpe
        else ""
    ) or None
    declared_firmware_evidence = normalized_token(
        entry.get("firmware_evidence_type")
        or entry.get("evidence_type"),
        limit=40,
    )
    if component_type == "firmware":
        if declared_firmware_evidence not in FIRMWARE_EVIDENCE_TYPES:
            declared_firmware_evidence = (
                "collector-reported" if direct_source else "inferred"
            )
        if not direct_source and declared_firmware_evidence in {
            "direct",
            "collector-reported",
        }:
            declared_firmware_evidence = "inferred"
    else:
        declared_firmware_evidence = "unknown"
    firmware_evidence_type: FirmwareEvidenceType = declared_firmware_evidence  # type: ignore[assignment]

    observed_at = _utc(
        entry.get("observed_at") or default_observed_at,
        received_at=received_at,
    )
    identity = canonical_identifier or "\x1f".join(
        (
            ecosystem,
            normalized_token(vendor, limit=160),
            namespace or "",
            normalized_name,
        )
    )
    evidence_ids = _evidence_ids(
        entry,
        site_id=site_id,
        asset_id=asset_id,
        source_id=source_id,
        identity=identity,
        observed_at=observed_at,
    )
    confidence = _confidence(
        entry.get("confidence"),
        default=default_confidence if direct_source else min(default_confidence, 0.55),
    )
    if ecosystem not in SUPPORTED_ECOSYSTEMS:
        status: NormalizationStatus = "unsupported-ecosystem"
    elif component_type == "firmware" and (
        not vendor
        or not version
        or firmware_evidence_type in {"inferred", "unknown"}
    ):
        status = "insufficient-firmware-evidence"
    elif not version:
        status = "version-unknown"
    elif component_type == "firmware":
        status = "normalized"
    elif canonical_identifier is None or (
        ecosystem == "generic" and not vendor and not namespace
    ):
        status = "identity-uncertain"
    else:
        status = "normalized"
    component_id = component_id_for(
        site_id=site_id,
        asset_id=asset_id,
        identity=identity,
        architecture=architecture,
        install_scope=install_scope,
    )
    return NormalizedComponent(
        component_id=component_id,
        asset_id=asset_id,
        site_id=site_id,
        component_type=component_type,
        ecosystem=ecosystem,
        namespace=namespace,
        vendor=vendor,
        name=name,
        normalized_name=normalized_name,
        version=version,
        normalized_version=version,
        architecture=architecture,
        package_manager=package_manager,
        canonical_identifier=canonical_identifier,
        cpe_hint=cpe_hint,
        install_scope=install_scope,
        source_type=source_type,
        source_id=source_id,
        firmware_evidence_type=firmware_evidence_type,
        evidence_ids=evidence_ids,
        observed_at=observed_at,
        first_seen_at=observed_at,
        last_seen_at=observed_at,
        freshness=component_freshness(observed_at, now=received_at),
        confidence=confidence,
        normalization_status=status,
        metadata=_safe_metadata(entry.get("metadata")),
        inventory_complete=inventory_complete,
    )


def normalize_components_for_asset(
    *,
    asset: Mapping[str, Any],
    payload: Mapping[str, Any],
    received_at: datetime,
    source_authenticated: bool,
) -> tuple[NormalizedComponent, ...]:
    """Normalize one asset's bounded component evidence without active probing."""

    site_id = bounded_text(asset.get("site_id"), limit=128)
    asset_id = bounded_text(asset.get("asset_id"), limit=160)
    if not site_id or not asset_id:
        return ()
    source_type, source_id, direct_source = _source_context(
        payload,
        asset=asset,
        source_authenticated=source_authenticated,
    )
    complete_requested = bool(
        payload.get("component_inventory_complete")
        or payload.get("inventory_complete")
        or asset.get("component_inventory_complete")
    )
    inventory_complete = complete_requested and direct_source
    default_confidence = _confidence(payload.get("confidence"), default=0.8)
    components: dict[str, NormalizedComponent] = {}
    for entry in _component_entries(asset):
        component = _normalized_component(
            entry,
            site_id=site_id,
            asset_id=asset_id,
            source_type=source_type,
            source_id=source_id,
            direct_source=direct_source,
            received_at=received_at,
            default_observed_at=(
                asset.get("observed_at")
                or payload.get("observed_at")
                or payload.get("collected_at")
            ),
            default_confidence=default_confidence,
            inventory_complete=inventory_complete,
        )
        if component is None:
            continue
        existing = components.get(component.component_id)
        if existing is None or (
            component.observed_at,
            component.confidence,
            component.evidence_ids,
        ) > (
            existing.observed_at,
            existing.confidence,
            existing.evidence_ids,
        ):
            components[component.component_id] = component
    return tuple(components.values())


def complete_component_inventory_scope(
    *,
    asset: Mapping[str, Any],
    payload: Mapping[str, Any],
    received_at: datetime,
    source_authenticated: bool,
) -> tuple[str, str, str, datetime] | None:
    """Return a trusted complete-inventory scope, never a client-only claim."""

    site_id = bounded_text(asset.get("site_id"), limit=128)
    asset_id = bounded_text(asset.get("asset_id"), limit=160)
    source_type, source_id, direct_source = _source_context(
        payload,
        asset=asset,
        source_authenticated=source_authenticated,
    )
    complete_requested = bool(
        payload.get("component_inventory_complete")
        or payload.get("inventory_complete")
        or asset.get("component_inventory_complete")
    )
    if (
        not site_id
        or not asset_id
        or not source_id
        or source_type != "endpoint-collector"
        or not direct_source
        or not complete_requested
    ):
        return None
    observed_at = _utc(
        asset.get("observed_at")
        or payload.get("observed_at")
        or payload.get("collected_at"),
        received_at=received_at,
    )
    return site_id, asset_id, source_id, observed_at


def normalize_component_payload(
    *,
    payload: Mapping[str, Any],
    site_id: str,
    received_at: datetime,
    source_authenticated: bool,
) -> tuple[NormalizedComponent, ...]:
    """Normalize all component evidence from an accepted local inventory payload."""

    raw_assets = payload.get("assets")
    if not isinstance(raw_assets, list):
        return ()
    normalized: list[NormalizedComponent] = []
    for index, raw_asset in enumerate(raw_assets[:50_000]):
        if not isinstance(raw_asset, Mapping):
            continue
        asset_id = bounded_text(
            raw_asset.get("asset_id")
            or raw_asset.get("hostname")
            or raw_asset.get("mac")
            or raw_asset.get("primary_ip"),
            limit=160,
        )
        if not asset_id:
            asset_id = f"observed-{index + 1}"
        asset = {
            **raw_asset,
            "site_id": site_id,
            "asset_id": asset_id,
            "source_agent_id": payload.get("sensor_id")
            or payload.get("agent_id"),
            "metadata": raw_asset,
        }
        normalized.extend(
            normalize_components_for_asset(
                asset=asset,
                payload=payload,
                received_at=received_at,
                source_authenticated=source_authenticated,
            )
        )
    return tuple(normalized)


def validate_reference_url(value: Any) -> str | None:
    """Validate a non-fetching advisory reference URL for bounded display."""

    url = bounded_text(value, limit=500)
    if not url:
        return None
    parsed = urlsplit(url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password or parsed.fragment:
        return None
    return url
