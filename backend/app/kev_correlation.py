"""Pure exact-CVE KEV correlation used by tests and bounded projections."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from .kev_catalog import KevRecord, normalize_cve


MAX_BATCH_MATCHES = 200_000
MAX_BATCH_CORRELATIONS = 200_000


@dataclass(frozen=True)
class KevCorrelation:
    match_id: str
    advisory_id: str
    kev_record_id: str
    cve_id: str
    priority_status: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def exact_cve_aliases(values: Sequence[Any]) -> tuple[str, ...]:
    aliases: set[str] = set()
    for value in values[:128]:
        if not isinstance(value, str):
            continue
        try:
            aliases.add(normalize_cve(value))
        except ValueError:
            continue
    return tuple(sorted(aliases))


def correlate_current_affected_match(
    match: Mapping[str, Any],
    records: Sequence[KevRecord],
) -> tuple[KevCorrelation, ...]:
    """Correlate only exact CVE aliases on an authoritative affected match."""

    if match.get("match_status") != "affected":
        return ()
    match_id = str(match.get("match_id") or "")
    advisory_id = str(match.get("advisory_id") or "")
    aliases = match.get("aliases")
    if not match_id or not advisory_id or not isinstance(aliases, list):
        return ()
    exact = set(exact_cve_aliases(aliases))
    by_cve = {record.cve_id: record for record in records}
    output = []
    for cve_id in sorted(exact & set(by_cve)):
        record = by_cve[cve_id]
        output.append(
            KevCorrelation(
                match_id=match_id,
                advisory_id=advisory_id,
                kev_record_id=record.kev_record_id,
                cve_id=cve_id,
                priority_status=(
                    "known_exploited_ransomware"
                    if record.ransomware_campaign_status == "Known"
                    else "known_exploited"
                ),
            )
        )
    return tuple(output)


def correlate_current_affected_matches(
    matches: Sequence[Mapping[str, Any]],
    records: Sequence[KevRecord],
    *,
    maximum_matches: int = MAX_BATCH_MATCHES,
    maximum_correlations: int = MAX_BATCH_CORRELATIONS,
) -> tuple[KevCorrelation, ...]:
    """Correlate a bounded batch with one CVE index and no alias amplification."""

    if not 1 <= maximum_matches <= MAX_BATCH_MATCHES:
        raise ValueError("KEV match batch limit is invalid")
    if not 1 <= maximum_correlations <= MAX_BATCH_CORRELATIONS:
        raise ValueError("KEV correlation batch limit is invalid")
    if len(matches) > maximum_matches:
        raise ValueError("KEV match batch exceeds the reviewed limit")
    by_cve = {record.cve_id: record for record in records}
    available_cves = set(by_cve)
    seen_match_ids: set[str] = set()
    output: list[KevCorrelation] = []
    for match in matches:
        if match.get("match_status") != "affected":
            continue
        match_id = str(match.get("match_id") or "")
        advisory_id = str(match.get("advisory_id") or "")
        aliases = match.get("aliases")
        if not match_id or not advisory_id or not isinstance(aliases, list):
            continue
        if match_id in seen_match_ids:
            raise ValueError("KEV match batch contains a duplicate logical match")
        seen_match_ids.add(match_id)
        for cve_id in sorted(set(exact_cve_aliases(aliases)) & available_cves):
            record = by_cve[cve_id]
            output.append(
                KevCorrelation(
                    match_id=match_id,
                    advisory_id=advisory_id,
                    kev_record_id=record.kev_record_id,
                    cve_id=cve_id,
                    priority_status=(
                        "known_exploited_ransomware"
                        if record.ransomware_campaign_status == "Known"
                        else "known_exploited"
                    ),
                )
            )
            if len(output) > maximum_correlations:
                raise ValueError("KEV correlation batch exceeds the reviewed limit")
    return tuple(output)
