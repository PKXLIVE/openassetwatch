#!/usr/bin/env python3
"""Deterministic, offline, no-third-party-data OSV PyPI publisher demonstration."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.advisory_bundle import preview_bundle, verify_bundle  # noqa: E402
from app.advisory_store import advisory_id_for  # noqa: E402
from app.advisory_sync_service import AdvisorySyncService  # noqa: E402
from app.advisory_transport import read_single_link_file  # noqa: E402
from app.ai_advisor import ReadOnlyHubTools, build_tool_context  # noqa: E402
from app.findings import evaluate_rules  # noqa: E402
from app.osv_pypi_adapter import (  # noqa: E402
    SYNTHETIC_DEMO_POLICY,
    canonical_json_bytes,
    format_utc,
)
from app.osv_pypi_publisher import (  # noqa: E402
    DirectoryOsvSource,
    PublishRequest,
    PublisherLimits,
    build_local_verification_registry,
    publish_once,
)
from app.risk import calculate_risk  # noqa: E402
from app.vulnerability_matching import match_component  # noqa: E402


RECORD_ID = "PYSEC-2099-1"
KEY_ID = "oaw-demo-osv-pypi-ed25519-2099-01"
KEY_ENV = "OPENASSETWATCH_DEMO_OSV_SIGNING_KEY"
NOW = datetime(2099, 1, 15, 12, 0, tzinfo=timezone.utc)
SOURCE_URL = (
    "https://github.com/PKXLIVE/openassetwatch/blob/main/"
    "backend/tests/fixtures/osv-pypi/PYSEC-2099-1.yaml"
)


def _synthetic_record(
    *,
    modified: datetime,
    fixed: str,
    versions: list[str],
) -> dict[str, Any]:
    return {
        "schema_version": "1.7.3",
        "id": RECORD_ID,
        "published": "2099-01-01T00:00:00Z",
        "modified": format_utc(modified),
        "aliases": ["CVE-2099-0001"],
        "upstream": [],
        "related": [],
        "summary": "Synthetic demo widget input-validation advisory",
        "details": (
            "OpenAssetWatch-authored synthetic data for the offline publisher demonstration. "
            "No downloaded or third-party advisory content is included."
        ),
        "affected": [
            {
                "package": {
                    "ecosystem": "PyPI",
                    "name": "oaw-demo-widget",
                    "purl": "pkg:pypi/oaw-demo-widget",
                },
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": fixed}],
                    }
                ],
                "versions": versions,
                "ecosystem_specific": {"severity": "HIGH"},
                "database_specific": {"source": SOURCE_URL},
            }
        ],
        "references": [
            {
                "type": "WEB",
                "url": "https://github.com/PKXLIVE/openassetwatch",
            }
        ],
        "credits": [
            {
                "name": "OpenAssetWatch synthetic fixture",
                "type": "OTHER",
                "contact": ["https://github.com/PKXLIVE/openassetwatch"],
            }
        ],
        "database_specific": {},
    }


def _write_fixture(
    root: Path,
    *,
    modified: datetime,
    fixed: str,
    versions: list[str],
) -> None:
    (root / "modified_id.csv").write_bytes(
        f"{format_utc(modified)},{RECORD_ID}\n".encode("utf-8")
    )
    (root / f"{RECORD_ID}.json").write_bytes(
        canonical_json_bytes(
            _synthetic_record(modified=modified, fixed=fixed, versions=versions)
        )
    )


@dataclass(frozen=True)
class _Evaluation:
    run_id: str
    advisory_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "component_count": 1,
            "advisory_count": self.advisory_count,
            "candidate_count": self.advisory_count,
            "affected_count": self.advisory_count,
            "changed_count": self.advisory_count,
        }


class _DemoAdvisoryStore:
    def list_advisories_for_matching(self, *, advisory_ids, **_kwargs):
        return [{"advisory_id": value} for value in advisory_ids]


class _DemoLifecycleStore:
    """Small offline persistence seam that drives the production lifecycle."""

    def __init__(self) -> None:
        self.runs: dict[str, dict[str, Any]] = {}
        self.catalogs: dict[str, dict[str, Any]] = {}
        self.activations: dict[str, dict[str, Any]] = {}
        self.active_catalog_id: str | None = None

    def retain(self, bundle, preview: dict[str, Any]) -> tuple[str, str]:
        run_id = "afrun_" + bundle.manifest_digest[:32]
        catalog_id = "afcat_" + bundle.payload_digest[:32]
        run = {
            "run_id": run_id,
            "source_id": bundle.manifest.source_id,
            "state": "pending_approval",
            "catalog_id": catalog_id,
            "publisher_key_id": bundle.manifest.publisher_key_id,
            "catalog_version": bundle.manifest.catalog_version,
            "catalog_sequence": bundle.manifest.catalog_sequence,
            "manifest_digest": bundle.manifest_digest,
            "payload_digest": bundle.payload_digest,
            "license_identifier": bundle.manifest.license_identifier,
            "preview": preview,
        }
        self.runs[run_id] = run
        self.catalogs[catalog_id] = {
            "catalog_id": catalog_id,
            "run_id": run_id,
            "source_id": bundle.manifest.source_id,
            "publisher_key_id": bundle.manifest.publisher_key_id,
            "catalog_bytes": bundle.catalog_bytes,
            "catalog_checksum": bundle.catalog_checksum,
            "preview": preview,
            "active": False,
        }
        return run_id, catalog_id

    def approve(self, run_id: str, *, actor: str, now: datetime) -> dict[str, Any]:
        run = self.runs[run_id]
        if run["state"] != "pending_approval":
            raise ValueError("demo run is not pending approval")
        run.update(state="approved", approved_by=actor, approved_at=now)
        return dict(run)

    def catalog_for_run(self, run_id: str, *, include_bytes: bool = False) -> dict[str, Any]:
        item = self.catalogs[self.runs[run_id]["catalog_id"]]
        return dict(item)

    def get_catalog(self, catalog_id: str, *, include_bytes: bool = False) -> dict[str, Any]:
        return dict(self.catalogs[catalog_id])

    def activate_run(
        self,
        run_id: str,
        *,
        catalog,
        catalog_checksum: str,
        actor: str,
        now: datetime,
    ) -> dict[str, Any]:
        run = self.runs[run_id]
        if run["state"] != "approved":
            raise ValueError("demo run is not approved")
        catalog_id = run["catalog_id"]
        previous = self.active_catalog_id
        if previous:
            self.catalogs[previous]["active"] = False
        self.catalogs[catalog_id]["active"] = True
        self.active_catalog_id = catalog_id
        run["state"] = "activated"
        activation_id = "afact_" + hashlib.sha256(
            f"{catalog_id}\x00activate\x00{previous or ''}".encode("utf-8")
        ).hexdigest()[:32]
        activation = {
            "activation_id": activation_id,
            "action": "activate",
            "catalog_id": catalog_id,
            "previous_catalog_id": previous,
            "source_id": run["source_id"],
            "actor": actor,
            "created_at": now,
            "reevaluation_status": "pending",
            "preview": run["preview"],
        }
        self.activations[activation_id] = activation
        return dict(activation)

    def rollback_catalog(
        self,
        catalog_id: str,
        *,
        catalog,
        catalog_checksum: str,
        actor: str,
        cooldown_seconds: int,
        now: datetime,
    ) -> dict[str, Any]:
        previous = self.active_catalog_id
        if previous:
            self.catalogs[previous]["active"] = False
        self.catalogs[catalog_id]["active"] = True
        self.active_catalog_id = catalog_id
        activation_id = "afact_" + hashlib.sha256(
            f"{catalog_id}\x00rollback\x00{previous or ''}".encode("utf-8")
        ).hexdigest()[:32]
        activation = {
            "activation_id": activation_id,
            "action": "rollback",
            "catalog_id": catalog_id,
            "previous_catalog_id": previous,
            "source_id": self.catalogs[catalog_id]["source_id"],
            "actor": actor,
            "created_at": now,
            "reevaluation_status": "pending",
            "preview": self.catalogs[catalog_id]["preview"],
        }
        self.activations[activation_id] = activation
        return dict(activation)

    def mark_reevaluation(
        self,
        activation_id: str,
        *,
        status: str,
        run_ids=(),
        error_code=None,
        impact=None,
    ) -> None:
        self.activations[activation_id].update(
            reevaluation_status=status,
            reevaluation_run_ids=list(run_ids),
            reevaluation_error_code=error_code,
            reevaluation_impact=impact,
        )

    def get_activation(self, activation_id: str) -> dict[str, Any]:
        return dict(self.activations[activation_id])


def _component_match(bundle, *, installed_version: str, evaluated_at: datetime):
    record = bundle.catalog.advisories[0]
    affected = record.affected[0]
    advisory_id = advisory_id_for(
        source=bundle.catalog.source.name,
        source_record_id=record.id,
    )
    affected_row = {
        "affected_id": "aff_" + hashlib.sha256(
            f"{advisory_id}\x00{affected.identifier}".encode("utf-8")
        ).hexdigest()[:32],
        "advisory_id": advisory_id,
        "ecosystem": affected.ecosystem,
        "vendor": affected.vendor,
        "normalized_name": affected.name,
        "canonical_identifier": affected.identifier,
        "ranges": [item.model_dump(mode="json") for item in affected.ranges],
        "exact_versions": list(affected.exact_versions),
        "fixed_versions": list(affected.fixed_versions),
        "architectures": [],
        "platforms": [],
        "current": True,
        "withdrawn_at": record.withdrawn_at,
    }
    component = {
        "component_id": "cmp_" + "1" * 32,
        "site_id": "site-demo",
        "asset_id": "asset-demo",
        "component_type": "application",
        "ecosystem": "pypi",
        "vendor": None,
        "normalized_name": affected.name,
        "normalized_version": installed_version,
        "canonical_identifier": affected.identifier,
        "architecture": "amd64",
        "asset_platform": "linux",
        "source_type": "endpoint-collector",
        "freshness": "fresh",
        "confidence": 1.0,
        "active": True,
        "evidence_ids": ["cevd_demo_server_issued"],
    }
    match = match_component(component, affected_row, evaluated_at=evaluated_at)
    if match is None:
        raise RuntimeError("synthetic component did not reach the deterministic matcher")
    return record, component, match


def _finding_and_risk(record, component, match, *, evaluated_at: datetime) -> tuple[int, int, str]:
    match_row = {
        **match.as_dict(),
        "component_name": component["normalized_name"],
        "severity": record.severity,
        "known_exploited": record.known_exploited,
        "component_freshness": "fresh",
        "component_last_seen_at": evaluated_at,
    }
    asset = {
        "site_id": "site-demo",
        "asset_id": "asset-demo",
        "observed_at": evaluated_at,
        "last_seen_at": evaluated_at,
        "metadata": {},
        "vulnerability_matches": [match_row],
    }
    snapshot = evaluate_rules(
        sites=[{"site_id": "site-demo"}],
        sensors=[],
        assets=[asset],
        now=evaluated_at,
        rule_ids=["vulnerable-component"],
    )
    risk_findings = [
        {
            "finding_id": "fnd_" + hashlib.sha256(item.dedupe_key.encode()).hexdigest()[:32],
            "site_id": item.site_id,
            "asset_id": item.asset_id,
            "status": "active",
            "category": item.category,
            "title": item.title,
            "severity": item.severity,
            "confidence": item.confidence,
            "evidence_freshness": item.evidence_freshness,
        }
        for item in snapshot.candidates
    ]
    scores, _ = calculate_risk(
        sites=[{"site_id": "site-demo"}],
        assets=[asset],
        findings=risk_findings,
    )
    score = scores[0].score if scores else 0
    return len(snapshot.candidates), score, match.match_status


def run_demo() -> dict[str, Any]:
    private_key = Ed25519PrivateKey.generate()
    raw_private = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    protected_environment = {KEY_ENV: base64.b64encode(raw_private).decode("ascii")}
    limits = PublisherLimits(
        maximum_records=10,
        maximum_index_rows=20,
        maximum_total_bytes=5 << 20,
        total_timeout_seconds=30,
        retries=0,
        concurrency=2,
    )

    with tempfile.TemporaryDirectory(prefix="oaw-osv-pypi-demo-") as temporary:
        root = Path(temporary)
        fixture = root / "fixture"
        fixture.mkdir(mode=0o700)
        output = root / "output"
        state = root / "state" / "publisher-state.json"
        _write_fixture(
            fixture,
            modified=NOW,
            fixed="2.0.0",
            versions=["1.0.0", "1.5.0"],
        )

        first = publish_once(
            DirectoryOsvSource(fixture),
            PublishRequest(
                state_path=state,
                output_root=output,
                full=True,
                key_id=KEY_ID,
                signing_key_env=KEY_ENV,
            ),
            limits=limits,
            policy=SYNTHETIC_DEMO_POLICY,
            now=lambda: NOW,
            environ=protected_environment,
        )
        if first.bundle_directory is None:
            raise RuntimeError("offline publisher did not produce a bundle")
        registry, source = build_local_verification_registry(
            policy=SYNTHETIC_DEMO_POLICY,
            key_id=KEY_ID,
            private_key=private_key,
        )
        first_bundle = verify_bundle(
            manifest_bytes=read_single_link_file(
                first.bundle_directory / "manifest.json",
                maximum_bytes=64 << 10,
            ),
            signature_bytes=read_single_link_file(
                first.bundle_directory / "manifest.ed25519",
                maximum_bytes=256,
            ),
            payload_bytes=read_single_link_file(
                first.bundle_directory / "catalog.json",
                maximum_bytes=8 << 20,
            ),
            source=source,
            registry=registry,
            now=NOW,
        )
        first_preview = preview_bundle(first_bundle, previous_catalog=None, now=NOW).as_dict()

        store = _DemoLifecycleStore()
        advisory_store = _DemoAdvisoryStore()
        evaluation_counter = {"value": 0}

        def evaluator(**kwargs):
            evaluation_counter["value"] += 1
            return _Evaluation(
                "vrun_" + f"{evaluation_counter['value']:032d}",
                len(kwargs.get("advisory_rows", [])),
            )

        service = AdvisorySyncService(
            registry=registry,
            store=store,
            evaluator=evaluator,
            advisory_store=advisory_store,
            now=lambda: NOW,
        )
        first_run_id, first_catalog_id = store.retain(first_bundle, first_preview)
        approved = service.approve(first_run_id, actor="demo-maintainer")
        activated = service.activate(first_run_id, actor="demo-maintainer")

        record, component, initial_match = _component_match(
            first_bundle,
            installed_version="1.5.0",
            evaluated_at=NOW,
        )
        initial_findings, initial_risk, initial_status = _finding_and_risk(
            record,
            component,
            initial_match,
            evaluated_at=NOW,
        )

        later = NOW + timedelta(hours=2)
        _write_fixture(
            fixture,
            modified=later,
            fixed="1.1.0",
            versions=["1.0.0"],
        )
        second = publish_once(
            DirectoryOsvSource(fixture),
            PublishRequest(
                state_path=state,
                output_root=output,
                key_id=KEY_ID,
                signing_key_env=KEY_ENV,
            ),
            limits=limits,
            policy=SYNTHETIC_DEMO_POLICY,
            now=lambda: later,
            environ=protected_environment,
        )
        if second.bundle_directory is None:
            raise RuntimeError("incremental publisher did not produce a bundle")
        second_bundle = verify_bundle(
            manifest_bytes=read_single_link_file(
                second.bundle_directory / "manifest.json",
                maximum_bytes=64 << 10,
            ),
            signature_bytes=read_single_link_file(
                second.bundle_directory / "manifest.ed25519",
                maximum_bytes=256,
            ),
            payload_bytes=read_single_link_file(
                second.bundle_directory / "catalog.json",
                maximum_bytes=8 << 20,
            ),
            source=source,
            registry=registry,
            now=later,
        )
        second_preview = preview_bundle(
            second_bundle,
            previous_catalog=first_bundle.catalog,
            now=later,
        ).as_dict()
        service.now = lambda: later
        second_run_id, second_catalog_id = store.retain(second_bundle, second_preview)
        service.approve(second_run_id, actor="demo-maintainer")
        second_activation = service.activate(second_run_id, actor="demo-maintainer")
        updated_record, updated_component, updated_match = _component_match(
            second_bundle,
            installed_version="1.5.0",
            evaluated_at=later,
        )
        updated_findings, updated_risk, updated_status = _finding_and_risk(
            updated_record,
            updated_component,
            updated_match,
            evaluated_at=later,
        )
        rollback = service.rollback(first_catalog_id, actor="demo-maintainer")

        advisory_evidence = [
            {
                "run_id": second_run_id,
                "catalog_id": second_catalog_id,
                "source_id": SYNTHETIC_DEMO_POLICY.source_id,
                "state": "activated",
                "catalog_version": second_bundle.manifest.catalog_version,
                "catalog_sequence": second_bundle.manifest.catalog_sequence,
                "publisher_key_id": second_bundle.manifest.publisher_key_id,
                "manifest_digest": second_bundle.manifest_digest,
                "payload_digest": second_bundle.payload_digest,
                "signature_status": "verified",
                "license_identifier": second_bundle.manifest.license_identifier,
                "license_status": "approved",
                "attribution_status": "present",
                "reevaluation_status": second_activation["reevaluation"]["status"],
                "created_at": later,
                "completed_at": later,
                "preview": second_preview,
            }
        ]
        tools = ReadOnlyHubTools(
            sites=[],
            sensors=[],
            assets=[],
            advisory_feed_evidence=advisory_evidence,
            now=later,
        )
        _, selected_tools, evidence = build_tool_context(
            tools,
            question=(
                "Explain the advisory feed status, catalog preview, signature status, "
                "activation impact, and deterministic risk change."
            ),
            site_id=None,
            asset_id=None,
        )

        return {
            "status": "offline-demo-complete",
            "fixture": "openassetwatch-authored-synthetic-no-third-party-data",
            "publisher": {
                "first_mode": first.report["mode"],
                "second_mode": second.report["mode"],
                "first_digest": first_bundle.payload_digest,
                "second_digest": second_bundle.payload_digest,
                "digests_changed": first_bundle.payload_digest != second_bundle.payload_digest,
                "signature_status": "verified",
                "license_identifier": second_bundle.manifest.license_identifier,
            },
            "lifecycle": {
                "approved_state": approved["state"],
                "first_activation": activated["reevaluation"]["status"],
                "second_activation": second_activation["reevaluation"]["status"],
                "rollback": rollback["reevaluation"]["status"],
            },
            "deterministic_outcomes": {
                "initial_match": initial_status,
                "initial_findings": initial_findings,
                "initial_risk": initial_risk,
                "updated_match": updated_status,
                "updated_findings": updated_findings,
                "updated_risk": updated_risk,
            },
            "ai_evidence": {
                "selected_tools": list(selected_tools),
                "evidence_ids": sorted(item.evidence_id for item in evidence),
                "server_issued_run_id": second_run_id,
                "server_issued_catalog_id": second_catalog_id,
            },
        }


def main() -> int:
    print(json.dumps(run_demo(), ensure_ascii=True, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
