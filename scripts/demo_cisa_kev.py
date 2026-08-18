#!/usr/bin/env python3
"""Run the offline synthetic CISA KEV prioritization lifecycle demonstration."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.ai_advisor import DeterministicDemoProvider, ReadOnlyHubTools, build_tool_context  # noqa: E402
from app.findings import evaluate_rules  # noqa: E402
from app.kev_catalog import normalize_cisa_kev_catalog, parse_cisa_kev_bytes  # noqa: E402
from app.kev_correlation import correlate_current_affected_match  # noqa: E402
from app.risk import calculate_risk  # noqa: E402


NOW = datetime(2099, 1, 4, 12, 0, tzinfo=timezone.utc)
FIXTURES = BACKEND / "tests" / "fixtures" / "cisa-kev"


MATCHES = (
    {
        "match_id": "vmt_" + "1" * 32,
        "site_id": "site-kev-demo",
        "asset_id": "asset-known-ransomware",
        "component_id": "cmp_" + "1" * 32,
        "advisory_id": "adv_" + "1" * 32,
        "match_status": "affected",
        "aliases": ["cve-2099-10001"],
        "component_name": "Synthetic Orbit Service",
    },
    {
        "match_id": "vmt_" + "2" * 32,
        "site_id": "site-kev-demo",
        "asset_id": "asset-unknown-ransomware",
        "component_id": "cmp_" + "2" * 32,
        "advisory_id": "adv_" + "2" * 32,
        "match_status": "affected",
        "aliases": ["CVE-2099-10002"],
        "component_name": "Synthetic Compass Agent",
    },
    {
        "match_id": "vmt_" + "3" * 32,
        "site_id": "site-kev-demo",
        "asset_id": "asset-alias-missing",
        "component_id": "cmp_" + "3" * 32,
        "advisory_id": "adv_" + "3" * 32,
        "match_status": "affected",
        "aliases": ["GHSA-fictional-no-cve"],
        "component_name": "Synthetic Alias-Free Runtime",
    },
    {
        "match_id": "vmt_" + "4" * 32,
        "site_id": "site-kev-demo",
        "asset_id": "asset-fixed-history",
        "component_id": "cmp_" + "4" * 32,
        "advisory_id": "adv_" + "4" * 32,
        "match_status": "fixed",
        "aliases": ["CVE-2099-10001"],
        "component_name": "Synthetic Fixed Service",
    },
)


def _catalog(name: str):
    return normalize_cisa_kev_catalog(parse_cisa_kev_bytes((FIXTURES / name).read_bytes()))


def _phase(name: str, catalog) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    record_by_id = {record.kev_record_id: record for record in catalog.records}
    projected_matches = []
    assets = []
    correlations = []
    for source_match in MATCHES:
        match = dict(source_match)
        match_correlations = correlate_current_affected_match(match, catalog.records)
        records = []
        for correlation in match_correlations:
            record = record_by_id[correlation.kev_record_id]
            correlations.append(correlation.as_dict())
            records.append(
                {
                    **record.model_dump(mode="python"),
                    "priority_status": correlation.priority_status,
                    "source_freshness": "fresh",
                    "adjusted_weight": 18.0 if record.ransomware_campaign_status == "Known" else 12.0,
                    "catalog_version": catalog.catalog_version,
                    "license_identifier": catalog.source.license_identifier,
                }
            )
        match.update(
            {
                "match_confidence": 1.0,
                "installed_version": "1.0.0",
                "fixed_version": "2.0.0",
                "affected_range": "<2.0.0",
                "evaluated_at": NOW,
                "component_freshness": "fresh",
                "severity": "high",
                "known_exploited": False,
                "source": "Synthetic Advisory Laboratory",
                "source_record_id": "OAW-SYNTH-" + match["match_id"][-4:],
                "catalog_version": "synthetic-advisory-2099.1",
                "source_license": "Apache-2.0",
                "provenance": "Fictional offline data.",
                "references": [],
                "reason_codes": ["installed-version-in-affected-range"],
                "kev": {
                    "status": (
                        "not-currently-affected"
                        if match["match_status"] != "affected"
                        else "known_exploited" if records else "alias missing"
                    ),
                    "source_id": "cisa-kev-official",
                    "freshness": "fresh",
                    "catalog_version": catalog.catalog_version,
                    "records": records,
                },
            }
        )
        projected_matches.append(match)
        assets.append(
            {
                "site_id": match["site_id"],
                "asset_id": match["asset_id"],
                "observed_at": NOW,
                "vulnerability_matches": [match],
            }
        )

    snapshot = evaluate_rules(
        sites=[{"site_id": "site-kev-demo"}],
        sensors=[],
        assets=assets,
        now=NOW,
        rule_ids=("vulnerable-component",),
    )
    findings = [asdict(candidate) for candidate in snapshot.candidates]
    for finding in findings:
        finding["evidence"] = list(finding["evidence"])
    risks, _ = calculate_risk(
        sites=[{"site_id": "site-kev-demo"}],
        assets=assets,
        findings=[{**finding, "finding_id": "fnd_" + f"{index:032x}", "status": "active"} for index, finding in enumerate(findings, 1)],
    )
    phase = {
        "phase": name,
        "catalog_version": catalog.catalog_version,
        "correlations": correlations,
        "finding_count": len(findings),
        "finding_titles": [finding["title"] for finding in findings],
        "asset_risk": {risk.asset_id: risk.score for risk in risks},
        "kev_risk": {
            risk.asset_id: round(
                sum(factor.adjusted_weight for factor in risk.factors if factor.factor_type == "kev-priority"),
                4,
            )
            for risk in risks
        },
        "fixed_match_current_kev_risk": next(
            (
                sum(factor.adjusted_weight for factor in risk.factors if factor.factor_type == "kev-priority")
                for risk in risks
                if risk.asset_id == "asset-fixed-history"
            ),
            0.0,
        ),
        "local_compromise_established": False,
        "required_action_execution": "disabled",
        "cisa_due_date_is_local_sla": False,
    }
    return phase, projected_matches, findings


def main() -> int:
    first = _catalog("catalog-v1.json")
    second = _catalog("catalog-v2.json")
    activated, matches, findings = _phase("activate", first)
    updated, _, _ = _phase("update", second)
    rolled_back, _, _ = _phase("rollback", first)
    tools = ReadOnlyHubTools(
        sites=[{"site_id": "site-kev-demo", "name": "Synthetic KEV Demo"}],
        sensors=[],
        assets=[],
        findings=[{**finding, "finding_id": "fnd_" + f"{index:032x}", "status": "active"} for index, finding in enumerate(findings, 1)],
        components=[],
        vulnerability_matches=matches,
        kev_status={
            "status": "available",
            "source_id": "cisa-kev-official",
            "freshness": "fresh",
            "active_catalog": {
                "import_id": "kevimp_" + "9" * 32,
                "catalog_version": first.catalog_version,
                "catalog_date_released": first.catalog_date_released,
                "payload_sha256": "a" * 64,
            },
            "current_factor_count": len(activated["correlations"]),
            "current_match_count": len(activated["correlations"]),
        },
        now=NOW,
    )
    context, selected, evidence = build_tool_context(
        tools,
        question="Explain the KEV ransomware vulnerability and CISA due date",
        site_id="site-kev-demo",
        asset_id="asset-known-ransomware",
    )
    ai = DeterministicDemoProvider().generate(
        question="Explain the KEV ransomware vulnerability and CISA due date",
        context=context,
    )
    output = {
        "schema_version": "oaw.cisa-kev-demo.v1",
        "synthetic_only": True,
        "lifecycle": [activated, updated, rolled_back],
        "update_removed_current_unknown_ransomware_match": (
            updated["kev_risk"].get("asset-unknown-ransomware", 0) == 0
        ),
        "rollback_restored_unknown_ransomware_match": (
            rolled_back["kev_risk"].get("asset-unknown-ransomware", 0) > 0
        ),
        "ai": {
            "answer": ai.answer,
            "evidence_ids": ai.evidence_ids,
            "selected_tools": selected,
            "available_evidence_ids": [item.evidence_id for item in evidence],
            "advisory_only": True,
        },
    }
    if not output["update_removed_current_unknown_ransomware_match"]:
        raise RuntimeError("synthetic KEV update did not remove the expected current factor")
    if not output["rollback_restored_unknown_ransomware_match"]:
        raise RuntimeError("synthetic KEV rollback did not restore the expected current factor")
    if any(phase["fixed_match_current_kev_risk"] for phase in output["lifecycle"]):
        raise RuntimeError("fixed synthetic match retained current KEV risk")
    print(json.dumps(output, ensure_ascii=True, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
