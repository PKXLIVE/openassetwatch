"""Bounded ecosystem-aware version parsing and deterministic comparisons."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering
from typing import Any, Literal

from packaging.version import InvalidVersion, Version

from .component_intelligence import normalize_version_text


VERSION_ENGINE = "oaw.versions.v1"
MAX_VERSION_PARTS = 64
ComparisonStatus = Literal["supported", "unsupported", "invalid"]

_SEMVER_RE = re.compile(
    r"^[vV]?"
    r"(?P<major>0|[1-9]\d*)"
    r"(?:\.(?P<minor>0|[1-9]\d*))?"
    r"(?:\.(?P<patch>0|[1-9]\d*))?"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?"
    r"(?:\+[0-9A-Za-z.-]+)?$"
)
_SAFE_VERSION_RE = re.compile(r"^[0-9A-Za-z.!+:~_-]{1,160}$")


@dataclass(frozen=True)
class VersionComparison:
    status: ComparisonStatus
    order: int | None
    reason: str
    engine_version: str = VERSION_ENGINE


def _trim_release(values: tuple[int, ...]) -> tuple[int, ...]:
    mutable = list(values)
    while len(mutable) > 1 and mutable[-1] == 0:
        mutable.pop()
    return tuple(mutable)


def _prerelease_parts(value: str | None) -> tuple[tuple[int, Any], ...]:
    if value is None:
        return ((2, 0),)
    items = value.split(".")
    if len(items) > MAX_VERSION_PARTS:
        raise ValueError("prerelease has too many identifiers")
    result: list[tuple[int, Any]] = []
    for item in items:
        # SemVer numeric identifiers have lower precedence than non-numeric
        # identifiers. Native tuple prefix ordering also gives a shorter,
        # otherwise-equal prerelease lower precedence than a longer one.
        result.append((0, int(item)) if item.isdigit() else (1, item))
    return tuple(result)


def _compare_tuple(left: Any, right: Any) -> int:
    return -1 if left < right else 1 if left > right else 0


def _semver(value: str) -> tuple[Any, ...] | None:
    match = _SEMVER_RE.fullmatch(value)
    if not match:
        return None
    release = (
        int(match.group("major")),
        int(match.group("minor") or 0),
        int(match.group("patch") or 0),
    )
    return release + (_prerelease_parts(match.group("pre")),)


def _split_epoch(value: str) -> tuple[int, str]:
    if ":" not in value:
        return 0, value
    raw_epoch, remainder = value.split(":", 1)
    if not raw_epoch.isdigit():
        raise ValueError("invalid epoch")
    return int(raw_epoch), remainder


def _debian_non_digit_order(character: str) -> int:
    if character == "~":
        return -1
    if character == "":
        return 0
    if character.isalpha():
        return ord(character)
    return ord(character) + 256


def _debian_part_compare(left: str, right: str) -> int:
    left_index = right_index = 0
    iterations = 0
    while left_index < len(left) or right_index < len(right):
        iterations += 1
        if iterations > MAX_VERSION_PARTS * 4:
            raise ValueError("version has too many segments")
        while (
            (left_index < len(left) and not left[left_index].isdigit())
            or (right_index < len(right) and not right[right_index].isdigit())
        ):
            left_char = left[left_index] if left_index < len(left) and not left[left_index].isdigit() else ""
            right_char = right[right_index] if right_index < len(right) and not right[right_index].isdigit() else ""
            order = _compare_tuple(
                _debian_non_digit_order(left_char),
                _debian_non_digit_order(right_char),
            )
            if order:
                return order
            if left_char:
                left_index += 1
            if right_char:
                right_index += 1
        left_start = left_index
        right_start = right_index
        while left_index < len(left) and left[left_index].isdigit():
            left_index += 1
        while right_index < len(right) and right[right_index].isdigit():
            right_index += 1
        left_number = left[left_start:left_index].lstrip("0") or "0"
        right_number = right[right_start:right_index].lstrip("0") or "0"
        order = _compare_tuple(len(left_number), len(right_number))
        if order:
            return order
        order = _compare_tuple(left_number, right_number)
        if order:
            return order
    return 0


def _debian_compare(left: str, right: str) -> int:
    left_epoch, left_remainder = _split_epoch(left)
    right_epoch, right_remainder = _split_epoch(right)
    epoch_order = _compare_tuple(left_epoch, right_epoch)
    if epoch_order:
        return epoch_order
    left_upstream, left_revision = (
        left_remainder.rsplit("-", 1)
        if "-" in left_remainder
        else (left_remainder, "0")
    )
    right_upstream, right_revision = (
        right_remainder.rsplit("-", 1)
        if "-" in right_remainder
        else (right_remainder, "0")
    )
    upstream_order = _debian_part_compare(left_upstream, right_upstream)
    return upstream_order or _debian_part_compare(left_revision, right_revision)


def _rpm_segments(value: str) -> tuple[tuple[int, Any], ...]:
    epoch, remainder = _split_epoch(value)
    segments: list[tuple[int, Any]] = [(3, epoch)]
    for match in re.finditer(r"~|[A-Za-z]+|\d+", remainder):
        token = match.group(0)
        if token == "~":
            segments.append((-1, ""))
        elif token.isdigit():
            segments.append((2, int(token)))
        else:
            segments.append((1, token.casefold()))
        if len(segments) > MAX_VERSION_PARTS:
            raise ValueError("version has too many segments")
    return tuple(segments)


def _maven(value: str) -> tuple[Any, ...]:
    qualifiers = {
        "alpha": -5,
        "a": -5,
        "beta": -4,
        "b": -4,
        "milestone": -3,
        "m": -3,
        "rc": -2,
        "cr": -2,
        "snapshot": -1,
        "": 0,
        "final": 0,
        "ga": 0,
        "release": 0,
        "sp": 1,
    }
    if re.sub(r"[0-9A-Za-z]+|[._-]", "", value):
        raise ValueError("unsupported Maven punctuation")
    tokens = re.findall(r"\d+|[A-Za-z]+", value)
    if not tokens or len(tokens) > MAX_VERSION_PARTS:
        raise ValueError("unsupported Maven version")
    release: list[int] = []
    qualifier_tokens: list[str] = []
    qualifier_started = False
    for token in tokens:
        if token.isdigit() and not qualifier_started:
            release.append(int(token))
            continue
        qualifier_started = True
        qualifier_tokens.append(token.casefold())
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    if not qualifier_tokens:
        qualifier: tuple[Any, ...] = (0, "", 0, ())
    else:
        name = qualifier_tokens[0]
        known_rank = qualifiers.get(name)
        rank = known_rank if known_rank is not None else 2
        suffix_number = (
            int(qualifier_tokens[1])
            if len(qualifier_tokens) > 1
            and qualifier_tokens[1].isdigit()
            else 0
        )
        qualifier = (
            rank,
            "" if known_rank is not None else name,
            suffix_number,
            tuple(qualifier_tokens[2:]),
        )
    return tuple(release), qualifier


def _generic_numeric(value: str) -> tuple[tuple[int, Any], ...] | None:
    tokens = re.findall(r"\d+|[A-Za-z]+", value)
    if not tokens or len(tokens) > MAX_VERSION_PARTS:
        return None
    return tuple(
        (2, int(token)) if token.isdigit() else (1, token.casefold())
        for token in tokens
    )


def compare_versions(
    ecosystem: str,
    left_value: Any,
    right_value: Any,
) -> VersionComparison:
    left = normalize_version_text(left_value)
    right = normalize_version_text(right_value)
    if left is None or right is None:
        return VersionComparison("invalid", None, "version-missing")
    if not _SAFE_VERSION_RE.fullmatch(left) or not _SAFE_VERSION_RE.fullmatch(right):
        return VersionComparison("invalid", None, "version-contains-unsupported-characters")
    if left == right:
        return VersionComparison("supported", 0, "exact-equality")
    try:
        if ecosystem == "pypi":
            try:
                left_parsed = Version(left)
                right_parsed = Version(right)
            except InvalidVersion:
                return VersionComparison("unsupported", None, "unsupported-pep440-form")
            order = _compare_tuple(left_parsed, right_parsed)
        elif ecosystem in {"npm", "nuget", "golang"}:
            left_parsed = _semver(left)
            right_parsed = _semver(right)
            if left_parsed is None or right_parsed is None:
                return VersionComparison("unsupported", None, "unsupported-semver-form")
            order = _compare_tuple(left_parsed, right_parsed)
        elif ecosystem in {"deb", "alpine"}:
            order = _debian_compare(left, right)
        elif ecosystem == "rpm":
            order = _compare_tuple(_rpm_segments(left), _rpm_segments(right))
        elif ecosystem == "maven":
            order = _compare_tuple(_maven(left), _maven(right))
        elif ecosystem in {"generic", "firmware", "operating-system"}:
            left_parsed = _generic_numeric(left)
            right_parsed = _generic_numeric(right)
            if left_parsed is None or right_parsed is None:
                return VersionComparison("unsupported", None, "unsupported-generic-version")
            order = _compare_tuple(left_parsed, right_parsed)
        else:
            return VersionComparison("unsupported", None, "unsupported-ecosystem")
    except (TypeError, ValueError, OverflowError):
        return VersionComparison("invalid", None, "invalid-version")
    return VersionComparison("supported", order, "ordered-comparison")


def version_satisfies_range(
    *,
    ecosystem: str,
    installed_version: Any,
    introduced: Any = None,
    introduced_inclusive: bool = True,
    fixed: Any = None,
    fixed_inclusive: bool = False,
    last_affected: Any = None,
    last_affected_inclusive: bool = True,
) -> tuple[str, str]:
    """Return affected/not-affected/fixed/unsupported for one reviewed range."""

    installed = normalize_version_text(installed_version)
    if installed is None:
        return "version-unknown", "installed-version-missing"
    if introduced is not None:
        lower = compare_versions(ecosystem, installed, introduced)
        if lower.status != "supported" or lower.order is None:
            return "unsupported-comparison", lower.reason
        if lower.order < 0 or (lower.order == 0 and not introduced_inclusive):
            return "not-affected", "before-introduced-boundary"
    if fixed is not None:
        upper = compare_versions(ecosystem, installed, fixed)
        if upper.status != "supported" or upper.order is None:
            return "unsupported-comparison", upper.reason
        if upper.order > 0 or (upper.order == 0 and not fixed_inclusive):
            return "fixed", "at-or-after-fixed-boundary"
    if last_affected is not None:
        upper = compare_versions(ecosystem, installed, last_affected)
        if upper.status != "supported" or upper.order is None:
            return "unsupported-comparison", upper.reason
        if upper.order > 0 or (upper.order == 0 and not last_affected_inclusive):
            return "not-affected", "after-last-affected-boundary"
    return "affected", "installed-version-in-affected-range"
