"""Deterministic, versioned asset classification and evidence fusion.

Collected strings are always data.  This module has a static registry and does
not load executable rules, plugins, model output, or packet-provided behavior.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Literal, Mapping, Sequence


AssetCategory = Literal[
    "workstation",
    "server",
    "mobile",
    "network-device",
    "printer",
    "camera",
    "media-device",
    "storage",
    "iot",
    "ot-industrial",
    "virtual-machine",
    "unknown",
]
ClassificationStatus = Literal[
    "classified",
    "partially-classified",
    "unknown",
    "conflicting",
    "insufficient-evidence",
]
Expectation = Literal["expected", "not-expected", "unknown"]
EvidenceStrength = Literal["direct", "medium", "weak"]
EvidenceFreshness = Literal["fresh", "aging", "stale", "unknown"]

CLASSIFIER_VERSION = "oaw.classifier.v1"
MAX_CLASSIFICATION_EVIDENCE = 256
MAX_CLASSIFICATION_EVIDENCE_INPUT = 4096
MAX_CLASSIFICATION_EVIDENCE_PER_SOURCE = 48
MAX_CLASSIFICATION_REFERENCES = 32
MAX_REASON_CODES = 12
MAX_CONFLICTS = 16
MAX_FUTURE_EVIDENCE_SKEW = timedelta(minutes=5)

SUPPORTED_CATEGORIES = frozenset(
    {
        "workstation",
        "server",
        "mobile",
        "network-device",
        "printer",
        "camera",
        "media-device",
        "storage",
        "iot",
        "ot-industrial",
        "virtual-machine",
        "unknown",
    }
)
SUPPORTED_STATUSES = frozenset(
    {
        "classified",
        "partially-classified",
        "unknown",
        "conflicting",
        "insufficient-evidence",
    }
)
SUPPORTED_REASON_CODES = frozenset(
    {
        "direct-category",
        "direct-endpoint-os",
        "direct-device-role",
        "passive-dhcp-vendor-class",
        "passive-mdns-service",
        "passive-ssdp-device-type",
        "passive-nbns-name",
        "weak-hostname-pattern",
        "vendor-catalog-match",
        "independent-source-agreement",
        "material-evidence-conflict",
        "stale-evidence-discounted",
        "future-evidence-rejected",
        "revoked-source-discounted",
        "manufacturer-only-evidence",
        "insufficient-category-evidence",
        "no-category-evidence",
    }
)

_CATEGORY_ALIASES = {
    "desktop": "workstation",
    "laptop": "workstation",
    "pc": "workstation",
    "workstation": "workstation",
    "server": "server",
    "mobile": "mobile",
    "phone": "mobile",
    "smartphone": "mobile",
    "tablet": "mobile",
    "network": "network-device",
    "network appliance": "network-device",
    "network device": "network-device",
    "network-device": "network-device",
    "router": "network-device",
    "switch": "network-device",
    "firewall": "network-device",
    "access point": "network-device",
    "printer": "printer",
    "camera": "camera",
    "ip camera": "camera",
    "media": "media-device",
    "media device": "media-device",
    "media-device": "media-device",
    "storage": "storage",
    "nas": "storage",
    "iot": "iot",
    "embedded": "iot",
    "ot": "ot-industrial",
    "industrial": "ot-industrial",
    "ot-industrial": "ot-industrial",
    "virtual machine": "virtual-machine",
    "virtual-machine": "virtual-machine",
    "vm": "virtual-machine",
    "unknown": "unknown",
}
_ENDPOINT_SOURCE_TYPES = frozenset({"endpoint-collector", "endpoint-agent", "collector"})
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SPACE = re.compile(r"\s+")


@dataclass(frozen=True)
class ManagedCapability:
    endpoint_collector: Expectation
    endpoint_security: Expectation
    software_inventory: Expectation
    patch_management: Expectation

    def as_dict(self) -> dict[str, Expectation]:
        return {
            "endpoint_collector": self.endpoint_collector,
            "endpoint_security": self.endpoint_security,
            "software_inventory": self.software_inventory,
            "patch_management": self.patch_management,
        }


@dataclass(frozen=True)
class ClassificationEvidence:
    evidence_id: str
    site_id: str
    asset_id: str
    source_id: str
    source_type: str
    collection_method: str
    kind: str
    value: str
    observed_at: datetime
    direct: bool
    strength: EvidenceStrength
    source_confidence: float
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    observation_count: int = 1
    source_revoked: bool = False

    @property
    def source_key(self) -> str:
        return f"{self.source_type}\x00{self.source_id}"


@dataclass(frozen=True)
class ClassificationConflict:
    conflict_type: str
    selected_value: str
    conflicting_value: str
    supporting_evidence_ids: tuple[str, ...]
    conflicting_evidence_ids: tuple[str, ...]
    reason_code: str = "material-evidence-conflict"

    def as_dict(self) -> dict[str, Any]:
        return {
            "conflict_type": self.conflict_type,
            "selected_value": self.selected_value,
            "conflicting_value": self.conflicting_value,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "conflicting_evidence_ids": list(self.conflicting_evidence_ids),
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class ClassificationResult:
    classification_id: str
    asset_id: str
    site_id: str
    classifier_version: str
    category: AssetCategory
    subtype: str | None
    manufacturer: str | None
    product_hint: str | None
    os_family: str | None
    os_version_hint: str | None
    managed_capability: ManagedCapability
    confidence: float
    status: ClassificationStatus
    supporting_evidence_ids: tuple[str, ...]
    conflicting_evidence_ids: tuple[str, ...]
    independent_source_count: int
    evidence_count: int
    first_classified_at: datetime
    last_classified_at: datetime
    evaluated_at: datetime
    superseded_at: datetime | None
    freshness: EvidenceFreshness
    reason_codes: tuple[str, ...]
    conflicts: tuple[ClassificationConflict, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "classification_id": self.classification_id,
            "asset_id": self.asset_id,
            "site_id": self.site_id,
            "classifier_version": self.classifier_version,
            "category": self.category,
            "subtype": self.subtype,
            "manufacturer": self.manufacturer,
            "product_hint": self.product_hint,
            "os_family": self.os_family,
            "os_version_hint": self.os_version_hint,
            "managed_capability": self.managed_capability.as_dict(),
            "confidence": self.confidence,
            "status": self.status,
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "conflicting_evidence_ids": list(self.conflicting_evidence_ids),
            "independent_source_count": self.independent_source_count,
            "evidence_count": self.evidence_count,
            "first_classified_at": self.first_classified_at,
            "last_classified_at": self.last_classified_at,
            "evaluated_at": self.evaluated_at,
            "superseded_at": self.superseded_at,
            "freshness": self.freshness,
            "reason_codes": list(self.reason_codes),
            "conflicts": [conflict.as_dict() for conflict in self.conflicts],
        }


@dataclass(frozen=True)
class _Signal:
    attribute: str
    value: str
    weight: float
    evidence_id: str
    source_key: str
    direct: bool
    freshness: EvidenceFreshness
    reason_code: str


def bounded_text(value: Any, *, limit: int = 512) -> str:
    """Return safe, bounded display data without interpreting it as code."""

    if not isinstance(value, str):
        return ""
    cleaned = _CONTROL_CHARACTERS.sub("", value)
    return _SPACE.sub(" ", cleaned).strip()[:limit]


def normalized_text(value: Any, *, limit: int = 512) -> str:
    return bounded_text(value, limit=limit).casefold()


def classification_id_for(site_id: str, asset_id: str) -> str:
    canonical = "\x00".join((site_id, asset_id))
    return "cls_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def evidence_id_for(
    *,
    site_id: str,
    asset_id: str,
    source_type: str,
    source_id: str,
    collection_method: str,
    kind: str,
    value: str,
) -> str:
    canonical = "\x00".join(
        (
            bounded_text(site_id, limit=128),
            bounded_text(asset_id, limit=160),
            bounded_text(source_type, limit=64).casefold(),
            bounded_text(source_id, limit=160),
            bounded_text(collection_method, limit=64).casefold(),
            bounded_text(kind, limit=80).casefold(),
            normalized_text(value),
        )
    )
    return "cev_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:40]


def category_name(value: Any) -> AssetCategory | None:
    normalized = normalized_text(value, limit=80).replace("_", " ").replace("/", " ")
    normalized = _SPACE.sub(" ", normalized).strip()
    category = _CATEGORY_ALIASES.get(normalized)
    if category in SUPPORTED_CATEGORIES:
        return category  # type: ignore[return-value]
    return None


def managed_capability_for(category: AssetCategory) -> ManagedCapability:
    if category in {"workstation", "server", "virtual-machine"}:
        return ManagedCapability("expected", "expected", "expected", "expected")
    if category == "mobile":
        return ManagedCapability("expected", "expected", "unknown", "expected")
    if category in {
        "network-device",
        "printer",
        "camera",
        "media-device",
        "storage",
        "iot",
        "ot-industrial",
    }:
        return ManagedCapability("not-expected", "not-expected", "not-expected", "unknown")
    return ManagedCapability("unknown", "unknown", "unknown", "unknown")


def evidence_freshness(
    observed_at: datetime | None,
    *,
    now: datetime,
    source_revoked: bool = False,
) -> EvidenceFreshness:
    if source_revoked:
        return "stale"
    if observed_at is None or observed_at.tzinfo is None or observed_at.utcoffset() is None:
        return "unknown"
    normalized = observed_at.astimezone(timezone.utc)
    if normalized > now + MAX_FUTURE_EVIDENCE_SKEW:
        return "unknown"
    age = max(now - normalized, timedelta())
    if age <= timedelta(hours=24):
        return "fresh"
    if age <= timedelta(hours=72):
        return "aging"
    return "stale"


def _freshness_factor(freshness: EvidenceFreshness, *, revoked: bool) -> float:
    if revoked:
        return 0.1
    return {
        "fresh": 1.0,
        "aging": 0.8,
        "stale": 0.35,
        "unknown": 0.45,
    }[freshness]


def _finite_confidence(value: Any, *, default: float = 0.5) -> float:
    if not isinstance(value, (int, float)):
        return default
    number = float(value)
    if not math.isfinite(number):
        return default
    return max(0.0, min(number, 1.0))


def _os_family(value: str) -> str | None:
    normalized = normalized_text(value, limit=160)
    if "windows" in normalized:
        return "Windows"
    if any(token in normalized for token in ("macos", "mac os", "darwin")):
        return "macOS"
    if any(token in normalized for token in ("ios", "iphone", "ipad")):
        return "iOS"
    if "android" in normalized:
        return "Android"
    if any(token in normalized for token in ("linux", "ubuntu", "debian", "rhel", "fedora", "centos")):
        return "Linux"
    if any(token in normalized for token in ("freebsd", "openbsd", "netbsd")):
        return "BSD"
    return None


def _category_signal(
    evidence: ClassificationEvidence,
    *,
    category: AssetCategory,
    weight: float,
    freshness: EvidenceFreshness,
    reason_code: str,
) -> _Signal:
    adjusted = weight * _finite_confidence(evidence.source_confidence) * _freshness_factor(
        freshness,
        revoked=evidence.source_revoked,
    )
    return _Signal(
        attribute="category",
        value=category,
        weight=max(0.0, min(adjusted, 0.99)),
        evidence_id=evidence.evidence_id,
        source_key=evidence.source_key,
        direct=evidence.direct,
        freshness=freshness,
        reason_code=reason_code,
    )


def _attribute_signal(
    evidence: ClassificationEvidence,
    *,
    attribute: str,
    value: str,
    weight: float,
    freshness: EvidenceFreshness,
    reason_code: str,
) -> _Signal:
    adjusted = weight * _finite_confidence(evidence.source_confidence) * _freshness_factor(
        freshness,
        revoked=evidence.source_revoked,
    )
    return _Signal(
        attribute=attribute,
        value=bounded_text(value, limit=160),
        weight=max(0.0, min(adjusted, 0.99)),
        evidence_id=evidence.evidence_id,
        source_key=evidence.source_key,
        direct=evidence.direct,
        freshness=freshness,
        reason_code=reason_code,
    )


def _hostname_category(value: str) -> AssetCategory | None:
    hostname = normalized_text(value, limit=255)
    labels = frozenset(re.split(r"[^a-z0-9]+", hostname))
    if labels & {"printer", "print", "laserjet"}:
        return "printer"
    if labels & {"camera", "cam", "nvr"}:
        return "camera"
    if labels & {"nas", "storage"}:
        return "storage"
    if labels & {"router", "switch", "firewall", "gateway", "ap"}:
        return "network-device"
    if labels & {"tv", "media", "cast"}:
        return "media-device"
    return None


def _signals_for_evidence(
    evidence: ClassificationEvidence,
    *,
    now: datetime,
) -> list[_Signal]:
    kind = normalized_text(evidence.kind, limit=80).replace("_", "-")
    method = normalized_text(evidence.collection_method, limit=64)
    value = bounded_text(evidence.value)
    normalized = value.casefold()
    freshness = evidence_freshness(
        evidence.last_seen_at or evidence.observed_at,
        now=now,
        source_revoked=evidence.source_revoked,
    )
    signals: list[_Signal] = []

    if evidence.direct and kind in {
        "category",
        "asset-category",
        "device-category",
        "device-type",
    }:
        category = category_name(value)
        if category and category != "unknown":
            signals.append(
                _category_signal(
                    evidence,
                    category=category,
                    weight=0.98,
                    freshness=freshness,
                    reason_code="direct-category",
                )
            )

    if evidence.direct and kind in {"role", "device-role", "subtype"}:
        category = category_name(value)
        if category and category != "unknown":
            signals.append(
                _category_signal(
                    evidence,
                    category=category,
                    weight=0.94,
                    freshness=freshness,
                    reason_code="direct-device-role",
                )
            )
        signals.append(
            _attribute_signal(
                evidence,
                attribute="subtype",
                value=value,
                weight=0.9,
                freshness=freshness,
                reason_code="direct-device-role",
            )
        )

    if kind in {"os", "os-family", "platform", "platform-os"}:
        family = _os_family(value)
        if family:
            signals.append(
                _attribute_signal(
                    evidence,
                    attribute="os_family",
                    value=family,
                    weight=0.98 if evidence.direct else 0.55,
                    freshness=freshness,
                    reason_code="direct-endpoint-os" if evidence.direct else "insufficient-category-evidence",
                )
            )
            if evidence.direct:
                if family in {"Windows", "macOS"}:
                    category: AssetCategory = "server" if "server" in normalized else "workstation"
                    signals.append(
                        _category_signal(
                            evidence,
                            category=category,
                            weight=0.91 if category == "workstation" else 0.96,
                            freshness=freshness,
                            reason_code="direct-endpoint-os",
                        )
                    )
                elif family in {"Android", "iOS"}:
                    signals.append(
                        _category_signal(
                            evidence,
                            category="mobile",
                            weight=0.96,
                            freshness=freshness,
                            reason_code="direct-endpoint-os",
                        )
                    )

    if kind in {"os-version", "version", "platform-version"} and evidence.direct:
        signals.append(
            _attribute_signal(
                evidence,
                attribute="os_version_hint",
                value=value,
                weight=0.9,
                freshness=freshness,
                reason_code="direct-endpoint-os",
            )
        )

    if kind in {"manufacturer", "vendor", "hardware-vendor"}:
        signals.append(
            _attribute_signal(
                evidence,
                attribute="manufacturer",
                value=value,
                weight=0.95 if evidence.direct else 0.62,
                freshness=freshness,
                reason_code="manufacturer-only-evidence",
            )
        )
    if kind in {"oui-manufacturer", "mac-vendor"}:
        signals.append(
            _attribute_signal(
                evidence,
                attribute="manufacturer",
                value=value,
                weight=0.72,
                freshness=freshness,
                reason_code="vendor-catalog-match",
            )
        )
    if kind in {"product", "model", "product-model"}:
        signals.append(
            _attribute_signal(
                evidence,
                attribute="product_hint",
                value=value,
                weight=0.92 if evidence.direct else 0.55,
                freshness=freshness,
                reason_code="direct-device-role" if evidence.direct else "insufficient-category-evidence",
            )
        )

    if method == "dhcp" or kind in {"dhcp-vendor-class", "vendor-class"}:
        mappings: tuple[tuple[tuple[str, ...], AssetCategory], ...] = (
            (("printer", "jetdirect"), "printer"),
            (("camera", "ipc"), "camera"),
            (("android", "iphone", "ipad"), "mobile"),
            (("router", "switch", "gateway", "firewall", "accesspoint"), "network-device"),
            (("nas", "storage"), "storage"),
        )
        for needles, category in mappings:
            if any(needle in normalized for needle in needles):
                signals.append(
                    _category_signal(
                        evidence,
                        category=category,
                        weight=0.73,
                        freshness=freshness,
                        reason_code="passive-dhcp-vendor-class",
                    )
                )
                break

    if method == "mdns" or kind in {"mdns-service", "service", "service-name"}:
        mappings = (
            (("_ipp", "_printer", "printer"), "printer"),
            (("_airplay", "_googlecast", "_raop", "mediarenderer"), "media-device"),
            (("_smb", "_afpovertcp", "_nfs"), "storage"),
            (("_axis-video", "_camera", "_rtsp"), "camera"),
        )
        for needles, category in mappings:
            if any(needle in normalized for needle in needles):
                signals.append(
                    _category_signal(
                        evidence,
                        category=category,  # type: ignore[arg-type]
                        weight=0.78,
                        freshness=freshness,
                        reason_code="passive-mdns-service",
                    )
                )
                break

    if method == "ssdp" or kind in {"ssdp-device-type", "device-urn", "ssdp-server"}:
        mappings = (
            (("internetgatewaydevice", "wanconnectiondevice", "router"), "network-device"),
            (("mediarenderer", "mediaserver", "dial", "roku"), "media-device"),
            (("printer", "printbasic"), "printer"),
            (("camera", "digital_security_camera", "networkvideo"), "camera"),
            (("storage", "nas"), "storage"),
        )
        for needles, category in mappings:
            if any(needle in normalized for needle in needles):
                signals.append(
                    _category_signal(
                        evidence,
                        category=category,  # type: ignore[arg-type]
                        weight=0.76,
                        freshness=freshness,
                        reason_code="passive-ssdp-device-type",
                    )
                )
                break

    if method == "nbns" or kind in {"nbns-name", "netbios-name"}:
        category = _hostname_category(value)
        if category:
            signals.append(
                _category_signal(
                    evidence,
                    category=category,
                    weight=0.43,
                    freshness=freshness,
                    reason_code="passive-nbns-name",
                )
            )

    if kind in {"hostname", "host-name", "dns-name", "nbns-name"}:
        category = _hostname_category(value)
        if category:
            signals.append(
                _category_signal(
                    evidence,
                    category=category,
                    weight=0.34,
                    freshness=freshness,
                    reason_code="weak-hostname-pattern",
                )
            )

    return signals


def _evidence_timestamp(item: ClassificationEvidence) -> datetime:
    value = item.last_seen_at or item.observed_at
    if value.tzinfo is None or value.utcoffset() is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _select_effective_evidence(
    evidence: Sequence[ClassificationEvidence],
    *,
    now: datetime,
) -> tuple[tuple[ClassificationEvidence, ...], bool]:
    latest: dict[tuple[str, str, str], ClassificationEvidence] = {}
    future_rejected = False
    for item in evidence[:MAX_CLASSIFICATION_EVIDENCE_INPUT]:
        if _evidence_timestamp(item) > now + MAX_FUTURE_EVIDENCE_SKEW:
            future_rejected = True
            continue
        key = (
            item.source_key,
            normalized_text(item.collection_method, limit=64),
            normalized_text(item.kind, limit=80),
        )
        previous = latest.get(key)
        if previous is None or _evidence_timestamp(item) > _evidence_timestamp(previous):
            latest[key] = item
    strength_priority = {"direct": 2, "medium": 1, "weak": 0}
    ordered = sorted(
        latest.values(),
        key=lambda item: (
            item.direct,
            strength_priority.get(item.strength, 0),
            _finite_confidence(item.source_confidence),
            _evidence_timestamp(item),
            item.evidence_id,
        ),
        reverse=True,
    )
    selected: list[ClassificationEvidence] = []
    per_source: dict[str, int] = {}
    for item in ordered:
        source_count = per_source.get(item.source_key, 0)
        if source_count >= MAX_CLASSIFICATION_EVIDENCE_PER_SOURCE:
            continue
        selected.append(item)
        per_source[item.source_key] = source_count + 1
        if len(selected) >= MAX_CLASSIFICATION_EVIDENCE:
            break
    return tuple(selected), future_rejected


def _best_attribute(
    signals: Sequence[_Signal],
    attribute: str,
) -> tuple[str | None, tuple[str, ...], float]:
    candidates = [signal for signal in signals if signal.attribute == attribute and signal.value]
    if not candidates:
        return None, (), 0.0
    candidates.sort(key=lambda signal: (signal.weight, signal.direct, signal.value), reverse=True)
    selected = candidates[0]
    supporting = tuple(
        signal.evidence_id
        for signal in candidates
        if signal.value.casefold() == selected.value.casefold()
    )[:MAX_CLASSIFICATION_REFERENCES]
    return selected.value, supporting, selected.weight


def _attribute_conflict(
    signals: Sequence[_Signal],
    *,
    attribute: str,
    conflict_type: str,
) -> ClassificationConflict | None:
    """Return one material independent disagreement for a typed attribute."""

    by_value: dict[str, dict[str, _Signal]] = {}
    display_values: dict[str, str] = {}
    for signal in signals:
        if signal.attribute != attribute or not signal.value:
            continue
        normalized = signal.value.casefold()
        display_values.setdefault(normalized, signal.value)
        by_source = by_value.setdefault(normalized, {})
        previous = by_source.get(signal.source_key)
        if previous is None or (signal.weight, signal.direct) > (
            previous.weight,
            previous.direct,
        ):
            by_source[signal.source_key] = signal
    ranked: list[tuple[str, float, bool, tuple[_Signal, ...]]] = []
    for normalized, by_source in by_value.items():
        values = tuple(by_source.values())
        strongest = max((signal.weight for signal in values), default=0.0)
        agreement = min(max(len(values) - 1, 0) * 0.05, 0.10)
        ranked.append(
            (
                normalized,
                min(strongest + agreement, 0.99),
                any(signal.direct for signal in values),
                values,
            )
        )
    ranked.sort(key=lambda item: (item[1], item[2], item[0]), reverse=True)
    if len(ranked) < 2:
        return None
    selected, _selected_score, selected_direct, selected_signals = ranked[0]
    conflicting, conflicting_score, conflicting_direct, conflicting_signals = ranked[1]
    selected_sources = {signal.source_key for signal in selected_signals}
    conflicting_sources = {signal.source_key for signal in conflicting_signals}
    independent = bool(conflicting_sources - selected_sources)
    material = (
        independent
        and (
            (selected_direct and conflicting_direct and conflicting_score >= 0.55)
            or (selected_direct and conflicting_score >= 0.62)
            or (not selected_direct and conflicting_score >= 0.58)
        )
    )
    if not material:
        return None
    return ClassificationConflict(
        conflict_type=conflict_type,
        selected_value=display_values[selected],
        conflicting_value=display_values[conflicting],
        supporting_evidence_ids=tuple(
            signal.evidence_id for signal in selected_signals
        )[:MAX_CLASSIFICATION_REFERENCES],
        conflicting_evidence_ids=tuple(
            signal.evidence_id for signal in conflicting_signals
        )[:MAX_CLASSIFICATION_REFERENCES],
    )


def _category_votes(
    signals: Sequence[_Signal],
) -> dict[str, dict[str, _Signal]]:
    votes: dict[str, dict[str, _Signal]] = {}
    for signal in signals:
        if signal.attribute != "category" or signal.value == "unknown":
            continue
        source_votes = votes.setdefault(signal.value, {})
        previous = source_votes.get(signal.source_key)
        if previous is None or (signal.direct, signal.weight) > (previous.direct, previous.weight):
            source_votes[signal.source_key] = signal
    return votes


def _category_rank(
    votes: Mapping[str, Mapping[str, _Signal]],
) -> list[tuple[str, float, bool, tuple[_Signal, ...]]]:
    ranked: list[tuple[str, float, bool, tuple[_Signal, ...]]] = []
    for category, by_source in votes.items():
        values = tuple(by_source.values())
        strongest = max((signal.weight for signal in values), default=0.0)
        agreement = min(max(len(values) - 1, 0) * 0.05, 0.10)
        ranked.append(
            (
                category,
                min(strongest + agreement, 0.99),
                any(signal.direct for signal in values),
                values,
            )
        )
    return sorted(ranked, key=lambda item: (item[1], item[2], item[0]), reverse=True)


def _overall_freshness(
    evidence: Sequence[ClassificationEvidence],
    *,
    now: datetime,
) -> EvidenceFreshness:
    states = {
        evidence_freshness(
            item.last_seen_at or item.observed_at,
            now=now,
            source_revoked=item.source_revoked,
        )
        for item in evidence
    }
    for state in ("fresh", "aging", "stale", "unknown"):
        if state in states:
            return state  # type: ignore[return-value]
    return "unknown"


def _reason_codes(signals: Sequence[_Signal], extra: Iterable[str]) -> tuple[str, ...]:
    values: list[str] = []
    for code in [signal.reason_code for signal in signals] + list(extra):
        if code in SUPPORTED_REASON_CODES and code not in values:
            values.append(code)
    return tuple(values[:MAX_REASON_CODES])


def classify_asset(
    *,
    site_id: str,
    asset_id: str,
    evidence: Sequence[ClassificationEvidence],
    now: datetime | None = None,
    previous: Mapping[str, Any] | None = None,
) -> ClassificationResult:
    """Classify one asset using a static, deterministic signal hierarchy."""

    evaluated_at = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    bounded_evidence, future_evidence_rejected = _select_effective_evidence(
        evidence,
        now=evaluated_at,
    )
    effective_evidence = bounded_evidence
    signals = tuple(
        signal
        for item in effective_evidence
        for signal in _signals_for_evidence(item, now=evaluated_at)
    )
    votes = _category_votes(signals)
    ranked = _category_rank(votes)
    reasons: list[str] = []
    if future_evidence_rejected:
        reasons.append("future-evidence-rejected")

    category: AssetCategory = "unknown"
    best_score = 0.0
    selected_signals: tuple[_Signal, ...] = ()
    if ranked:
        category = ranked[0][0]  # type: ignore[assignment]
        best_score = ranked[0][1]
        selected_signals = ranked[0][3]

    conflicts: list[ClassificationConflict] = []
    conflicting_signals: tuple[_Signal, ...] = ()
    if len(ranked) > 1:
        second_category, second_score, second_direct, second_signals = ranked[1]
        selected_sources = {signal.source_key for signal in selected_signals}
        conflicting_sources = {signal.source_key for signal in second_signals}
        independent_disagreement = bool(conflicting_sources - selected_sources)
        material = (
            independent_disagreement
            and (
                (ranked[0][2] and second_direct and second_score >= 0.55)
                or (ranked[0][2] and second_score >= 0.62)
                or (not ranked[0][2] and second_score >= 0.58)
            )
        )
        if material:
            conflicting_signals = second_signals
            conflicts.append(
                ClassificationConflict(
                    conflict_type="category",
                    selected_value=category,
                    conflicting_value=second_category,
                    supporting_evidence_ids=tuple(
                        signal.evidence_id for signal in selected_signals
                    )[:MAX_CLASSIFICATION_REFERENCES],
                    conflicting_evidence_ids=tuple(
                        signal.evidence_id for signal in second_signals
                    )[:MAX_CLASSIFICATION_REFERENCES],
                )
            )
            reasons.append("material-evidence-conflict")

    manufacturer, manufacturer_ids, _ = _best_attribute(signals, "manufacturer")
    subtype, subtype_ids, _ = _best_attribute(signals, "subtype")
    product_hint, product_ids, _ = _best_attribute(signals, "product_hint")
    os_family, os_ids, _ = _best_attribute(signals, "os_family")
    os_version_hint, version_ids, _ = _best_attribute(signals, "os_version_hint")
    for attribute, conflict_type in (
        ("subtype", "device-role"),
        ("os_family", "os-family"),
        ("os_version_hint", "os-version"),
    ):
        attribute_conflict = _attribute_conflict(
            signals,
            attribute=attribute,
            conflict_type=conflict_type,
        )
        if attribute_conflict is not None:
            conflicts.append(attribute_conflict)
            reasons.append("material-evidence-conflict")

    supporting_ids: list[str] = []
    for evidence_id in (
        [signal.evidence_id for signal in selected_signals]
        + list(manufacturer_ids)
        + list(subtype_ids)
        + list(product_ids)
        + list(os_ids)
        + list(version_ids)
    ):
        if evidence_id not in supporting_ids:
            supporting_ids.append(evidence_id)
    conflicting_ids = list(
        dict.fromkeys(
            [signal.evidence_id for signal in conflicting_signals]
            + [
                evidence_id
                for conflict in conflicts
                for evidence_id in conflict.conflicting_evidence_ids
            ]
        )
    )[:MAX_CLASSIFICATION_REFERENCES]
    classification_evidence_ids = set(supporting_ids) | set(conflicting_ids)
    freshness_evidence = tuple(
        item
        for item in bounded_evidence
        if item.evidence_id in classification_evidence_ids
    )
    if not freshness_evidence:
        freshness_evidence = bounded_evidence

    independent_sources = len({signal.source_key for signal in selected_signals})
    if independent_sources > 1:
        reasons.append("independent-source-agreement")
    if any(
        evidence_freshness(
            item.last_seen_at or item.observed_at,
            now=evaluated_at,
            source_revoked=item.source_revoked,
        )
        == "stale"
        for item in bounded_evidence
    ):
        reasons.append("stale-evidence-discounted")
    if any(item.source_revoked for item in bounded_evidence):
        reasons.append("revoked-source-discounted")

    completeness_bonus = min(
        0.02
        * sum(bool(value) for value in (manufacturer, subtype, product_hint, os_family)),
        0.08,
    )
    conflict_penalty = 0.22 if conflicts else 0.0
    confidence = max(0.0, min(best_score + completeness_bonus - conflict_penalty, 0.99))
    if conflicts:
        status: ClassificationStatus = "conflicting"
    elif not ranked:
        status = "unknown" if not signals else "insufficient-evidence"
        reasons.append("no-category-evidence" if not signals else "insufficient-category-evidence")
        confidence = min(
            max((signal.weight for signal in signals), default=0.0),
            0.39,
        )
    elif best_score >= 0.72:
        status = "classified"
    elif best_score >= 0.45:
        status = "partially-classified"
    else:
        status = "insufficient-evidence"
        category = "unknown"
        reasons.append("insufficient-category-evidence")
        confidence = min(confidence, 0.44)

    first_classified = evaluated_at
    if previous:
        candidate = previous.get("first_classified_at")
        if isinstance(candidate, datetime) and candidate.tzinfo is not None:
            first_classified = candidate.astimezone(timezone.utc)

    return ClassificationResult(
        classification_id=classification_id_for(site_id, asset_id),
        asset_id=bounded_text(asset_id, limit=160),
        site_id=bounded_text(site_id, limit=128),
        classifier_version=CLASSIFIER_VERSION,
        category=category,
        subtype=subtype,
        manufacturer=manufacturer,
        product_hint=product_hint,
        os_family=os_family,
        os_version_hint=os_version_hint,
        managed_capability=managed_capability_for(category),
        confidence=round(confidence, 4),
        status=status,
        supporting_evidence_ids=tuple(supporting_ids[:MAX_CLASSIFICATION_REFERENCES]),
        conflicting_evidence_ids=tuple(conflicting_ids),
        independent_source_count=independent_sources,
        evidence_count=len(bounded_evidence),
        first_classified_at=first_classified,
        last_classified_at=evaluated_at,
        evaluated_at=evaluated_at,
        superseded_at=None,
        freshness=_overall_freshness(freshness_evidence, now=evaluated_at),
        reason_codes=_reason_codes(signals, reasons),
        conflicts=tuple(conflicts[:MAX_CONFLICTS]),
    )


def classification_changed(
    previous: Mapping[str, Any] | None,
    current: ClassificationResult,
) -> bool:
    if not previous:
        return True
    managed = previous.get("managed_capability")
    if not isinstance(managed, Mapping):
        managed = previous.get("managed_capability_json")
    if isinstance(managed, str):
        managed = None
    return any(
        (
            previous.get("classifier_version") != current.classifier_version,
            previous.get("category") != current.category,
            previous.get("subtype") != current.subtype,
            previous.get("manufacturer") != current.manufacturer,
            previous.get("product_hint") != current.product_hint,
            previous.get("os_family") != current.os_family,
            previous.get("os_version_hint") != current.os_version_hint,
            dict(managed or {}) != current.managed_capability.as_dict(),
            float(previous.get("confidence") or 0.0) != current.confidence,
            previous.get("status") != current.status,
            tuple(previous.get("supporting_evidence_ids") or ())
            != current.supporting_evidence_ids,
            tuple(previous.get("conflicting_evidence_ids") or ())
            != current.conflicting_evidence_ids,
            int(previous.get("independent_source_count") or 0)
            != current.independent_source_count,
            tuple(previous.get("reason_codes") or ()) != current.reason_codes,
        )
    )
