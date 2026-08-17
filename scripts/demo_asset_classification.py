#!/usr/bin/env python3
"""Run the local-only deterministic asset-classification showcase."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.ai_advisor import (  # noqa: E402
    AdvisorQueryRequest,
    ProviderConfig,
    ReadOnlyHubTools,
    run_advisor,
)
from app.classification import (  # noqa: E402
    ClassificationEvidence,
    classify_asset,
    evidence_id_for,
)
from app.classification_service import evaluate_classifications  # noqa: E402
from app.classification_store import InMemoryClassificationStore  # noqa: E402


DEMO_TIME = datetime(2026, 7, 30, 16, 0, tzinfo=timezone.utc)


def demo_evidence(
    *,
    site_id: str,
    asset_id: str,
    source_id: str,
    source_type: str,
    method: str,
    kind: str,
    value: str,
    observed_at: datetime = DEMO_TIME,
    direct: bool = False,
    strength: str = "medium",
    confidence: float = 0.9,
) -> ClassificationEvidence:
    return ClassificationEvidence(
        evidence_id=evidence_id_for(
            site_id=site_id,
            asset_id=asset_id,
            source_type=source_type,
            source_id=source_id,
            collection_method=method,
            kind=kind,
            value=value,
        ),
        site_id=site_id,
        asset_id=asset_id,
        source_id=source_id,
        source_type=source_type,
        collection_method=method,
        kind=kind,
        value=value,
        observed_at=observed_at,
        direct=direct,
        strength=strength,  # type: ignore[arg-type]
        source_confidence=confidence,
        first_seen_at=observed_at,
        last_seen_at=observed_at,
    )


def _evidence_projection(item: ClassificationEvidence) -> dict[str, Any]:
    return {
        "evidence_id": item.evidence_id,
        "site_id": item.site_id,
        "asset_id": item.asset_id,
        "source_id": item.source_id,
        "source_type": item.source_type,
        "collection_method": item.collection_method,
        "kind": item.kind,
        "value": item.value,
        "observed_at": item.observed_at,
        "first_seen_at": item.first_seen_at,
        "last_seen_at": item.last_seen_at,
        "direct": item.direct,
        "strength": item.strength,
        "source_confidence": item.source_confidence,
        "observation_count": item.observation_count,
        "agreement_state": "supporting",
        "classifier_used": True,
        "source_revoked": item.source_revoked,
    }


def build_demo() -> dict[str, Any]:
    """Return a stable synthetic demo spanning classification trust boundaries."""

    office_id = "asset-office-workstation-demo"
    office_evidence = [
        demo_evidence(
            site_id="demo-office",
            asset_id=office_id,
            source_id="agent-office-demo",
            source_type="endpoint-collector",
            method="endpoint-inventory",
            kind="category",
            value="workstation",
            direct=True,
            strength="direct",
            confidence=0.98,
        ),
        demo_evidence(
            site_id="demo-office",
            asset_id=office_id,
            source_id="agent-office-demo",
            source_type="endpoint-collector",
            method="endpoint-inventory",
            kind="os",
            value="Windows 11",
            direct=True,
            strength="direct",
            confidence=0.98,
        ),
    ]
    home_evidence = [
        demo_evidence(
            site_id="demo-home",
            asset_id="asset-home-printer-demo",
            source_id="sensor-home-demo",
            source_type="passive-network-sensor",
            method="mdns",
            kind="mdns-service",
            value="_ipp._tcp.local",
        )
    ]
    lab_evidence = [
        demo_evidence(
            site_id="demo-lab",
            asset_id="asset-lab-conflict-demo",
            source_id="agent-lab-demo",
            source_type="endpoint-collector",
            method="endpoint-inventory",
            kind="category",
            value="server",
            direct=True,
            strength="direct",
            confidence=0.98,
        ),
        demo_evidence(
            site_id="demo-lab",
            asset_id="asset-lab-conflict-demo",
            source_id="sensor-lab-demo",
            source_type="passive-network-sensor",
            method="mdns",
            kind="mdns-service",
            value="_ipp._tcp.local",
            confidence=0.9,
        ),
    ]
    scenario_results = {
        "home": classify_asset(
            site_id="demo-home",
            asset_id="asset-home-printer-demo",
            evidence=home_evidence,
            now=DEMO_TIME,
        ),
        "office": classify_asset(
            site_id="demo-office",
            asset_id=office_id,
            evidence=office_evidence,
            now=DEMO_TIME,
        ),
        "lab": classify_asset(
            site_id="demo-lab",
            asset_id="asset-lab-conflict-demo",
            evidence=lab_evidence,
            now=DEMO_TIME,
        ),
    }

    reclassified_id = "asset-lab-reclassified-demo"
    initial_time = DEMO_TIME - timedelta(days=5)
    initial_passive = demo_evidence(
        site_id="demo-lab",
        asset_id=reclassified_id,
        source_id="sensor-lab-demo",
        source_type="passive-network-sensor",
        method="mdns",
        kind="mdns-service",
        value="_ipp._tcp.local",
        observed_at=initial_time,
    )
    store = InMemoryClassificationStore()
    key = ("demo-lab", reclassified_id)
    store.evidence[key] = [initial_passive]
    evaluate_classifications(
        trigger_type="demo-initial",
        site_id=key[0],
        asset_id=key[1],
        now=initial_time,
        store=store,
        assets=[{"site_id": key[0], "asset_id": key[1]}],
        evidence_by_asset={key: [initial_passive]},
        reevaluate_findings=False,
    )
    initial_category = store.current_records[key]["category"]
    direct_server = demo_evidence(
        site_id=key[0],
        asset_id=key[1],
        source_id="agent-lab-demo",
        source_type="endpoint-collector",
        method="endpoint-inventory",
        kind="category",
        value="server",
        direct=True,
        strength="direct",
        confidence=0.98,
    )
    store.evidence[key] = [initial_passive, direct_server]
    final_run = evaluate_classifications(
        trigger_type="demo-reclassification",
        site_id=key[0],
        asset_id=key[1],
        now=DEMO_TIME,
        store=store,
        assets=[{"site_id": key[0], "asset_id": key[1]}],
        evidence_by_asset={key: [initial_passive, direct_server]},
        reevaluate_findings=False,
    )
    final_classification = store.current_records[key]

    office_classification = scenario_results["office"].as_dict()
    tools = ReadOnlyHubTools(
        sites=[{"site_id": "demo-office", "name": "Office Demo"}],
        sensors=[],
        assets=[
            {
                "site_id": "demo-office",
                "asset_id": office_id,
                "hostname": "office-workstation-demo",
                "observed_at": DEMO_TIME,
                "last_seen_at": DEMO_TIME,
                "observation_source": "endpoint-inventory",
                "delivery_state": "live",
                "confidence": 0.98,
                "evidence_count": len(office_evidence),
                "metadata": {"demo": True},
                "classification": office_classification,
            }
        ],
        classification_evidence=[
            _evidence_projection(item) for item in office_evidence
        ],
        now=DEMO_TIME,
    )
    advisor = run_advisor(
        request=AdvisorQueryRequest(
            question=(
                "Why is asset-office-workstation-demo classified as a workstation?"
            ),
            site_id="demo-office",
            asset_id=office_id,
        ),
        tools=tools,
        config=ProviderConfig("demo", False, None, None, None, 10),
    )

    return {
        "schema_version": "oaw.classification-demo.v1",
        "synthetic_only": True,
        "classifier_version": office_classification["classifier_version"],
        "sites": {
            name: {
                "asset_id": result.asset_id,
                "category": result.category,
                "status": result.status,
                "confidence": result.confidence,
                "freshness": result.freshness,
                "supporting_evidence_ids": list(result.supporting_evidence_ids),
                "conflicting_evidence_ids": list(result.conflicting_evidence_ids),
            }
            for name, result in scenario_results.items()
        },
        "conflict": {
            "asset_id": scenario_results["lab"].asset_id,
            "status": scenario_results["lab"].status,
            "values": [
                {
                    "selected": conflict.selected_value,
                    "conflicting": conflict.conflicting_value,
                }
                for conflict in scenario_results["lab"].conflicts
            ],
        },
        "reclassification": {
            "asset_id": reclassified_id,
            "initial_category": initial_category,
            "final_category": final_classification["category"],
            "history_count": len(store.history),
            "changed_assets": final_run.assets_changed,
        },
        "ai_evidence": {
            "advisory_only": advisor.advisory_only,
            "classification_authority": advisor.classification_authority,
            "tools_used": advisor.tools_used,
            "evidence_ids": [item.evidence_id for item in advisor.evidence],
            "answer": advisor.answer,
        },
    }


def main() -> int:
    print(json.dumps(build_demo(), indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
