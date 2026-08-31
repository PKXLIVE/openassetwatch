#!/usr/bin/env python3
"""Disposable fictional native-software lifecycle demonstration."""

from __future__ import annotations

import json
import os
import re
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, Sequence
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.pool import NullPool


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app import main as backend_main  # noqa: E402
from app.advisory_catalog import load_catalog  # noqa: E402
from app.advisory_store import SqlAdvisoryStore  # noqa: E402
from app.ai_advisor import (  # noqa: E402
    AdvisorQueryRequest,
    ProviderConfig,
    run_advisor,
)
from app.canonical_ingestion import endpoint_envelope, ingest  # noqa: E402
from app.component_store import SqlComponentStore  # noqa: E402
from app.endpoint_agent_contracts import EndpointInventoryRequest  # noqa: E402
from app.endpoint_agent_identity import (  # noqa: E402
    authenticate_agent_request,
    create_agent_enrollment,
    exchange_agent_enrollment,
)
from app.finding_store import SqlFindingStore  # noqa: E402
from app.schema_migrations import migrate_database_schema  # noqa: E402
from app.vulnerability_store import SqlVulnerabilityStore  # noqa: E402


DATABASE_NAME = re.compile(r"^openassetwatch_native_demo_[0-9a-f]{16}$")
SITE_ID = "site-native-demo"
ASSET_ID = "fictional-native-endpoint"
SOURCE_ID = "linux-dpkg"


@contextmanager
def disposable_database(database_url: str) -> Iterator[Engine]:
    parsed = make_url(database_url)
    database_name = f"openassetwatch_native_demo_{uuid4().hex[:16]}"
    if not DATABASE_NAME.fullmatch(database_name):
        raise RuntimeError("refusing unsafe demonstration database name")
    admin_engine = create_engine(
        parsed.set(database="postgres"),
        isolation_level="AUTOCOMMIT",
        poolclass=NullPool,
    )
    database_engine: Engine | None = None
    try:
        with admin_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')
        database_engine = create_engine(
            parsed.set(database=database_name),
            poolclass=NullPool,
        )
        migrate_database_schema(database_engine)
        yield database_engine
    finally:
        if database_engine is not None:
            database_engine.dispose()
        with admin_engine.connect() as connection:
            connection.execute(
                text(
                    """
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = :database_name
                      AND pid <> pg_backend_pid()
                    """
                ),
                {"database_name": database_name},
            )
            connection.exec_driver_sql(
                f'DROP DATABASE IF EXISTS "{database_name}"'
            )
        admin_engine.dispose()


def native_payload(
    *,
    now: datetime,
    batch_id: str,
    status: str,
    packages: Sequence[tuple[str, str]],
    truncated: bool = False,
    error_code: str | None = None,
    limitations: Sequence[str] = (),
) -> EndpointInventoryRequest:
    components = [
        {
            "component_type": "operating-system-package",
            "ecosystem": "deb",
            "name": name,
            "version": version,
            "architecture": "amd64",
            "package_manager": "dpkg",
            "install_scope": "system",
            "collection_source_id": SOURCE_ID,
            "source_record_id": f"{name}:amd64",
            "evidence_method": "dpkg-native-query",
            "observed_at": now.isoformat(),
            "confidence": 0.95,
        }
        for name, version in packages
    ]
    source: dict[str, object] = {
        "source_id": SOURCE_ID,
        "platform": "linux",
        "status": status,
        "observed_at": now.isoformat(),
        "record_count": len(components),
        "truncated": truncated,
    }
    if error_code:
        source["error_code"] = error_code
    if limitations:
        source["limitations"] = list(limitations)
    return EndpointInventoryRequest.model_validate(
        {
            "schema_version": "oaw.endpoint-inventory.v1",
            "inventory_batch_id": batch_id,
            "observed_at": now.isoformat(),
            "inventory_mode": "complete",
            "agent_version": "0.1.0",
            "platform": "linux",
            "architecture": "amd64",
            "software_sources": [source],
            "assets": [
                {
                    "asset_id": ASSET_ID,
                    "hostname": "fictional-native-endpoint.example.test",
                    "os": "Fictional Linux 1",
                    "platform": "linux",
                    "architecture": "amd64",
                    "components": components,
                }
            ],
        }
    )


def enroll_fictional_endpoint(engine: Engine, *, now: datetime):
    with engine.begin() as connection:
        connection.execute(
            text("INSERT INTO sites (site_id, name) VALUES (:site_id, :name)"),
            {"site_id": SITE_ID, "name": "Fictional Native Software Demo"},
        )
    enrollment = create_agent_enrollment(
        site_id=SITE_ID,
        requested_deployment_id="deployment-native-demo",
        requested_display_name="Fictional Native Endpoint",
        requested_agent_type="endpoint-agent",
        expires_in_minutes=30,
        actor="synthetic-demo-admin",
        now=now,
    )
    issued = exchange_agent_enrollment(
        enrollment_token=enrollment["enrollment_token"],
        installation_id="deployment-native-demo",
        display_name="Fictional Native Endpoint",
        agent_version="0.1.0",
        platform="linux",
        architecture="amd64",
        agent_type="endpoint-agent",
        now=now,
    )
    context = authenticate_agent_request(
        provided_token=issued["agent_credential"],
        claimed_site_id=SITE_ID,
        claimed_agent_id=issued["agent_id"],
        claimed_deployment_id="deployment-native-demo",
        claimed_agent_type="endpoint-agent",
        now=now,
    )
    return issued, context


def _counts(engine: Engine) -> dict[str, int]:
    with engine.connect() as connection:
        return {
            table: int(
                connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one()
            )
            for table in (
                "asset_components",
                "component_source_snapshots",
                "component_source_presence",
                "vulnerability_matches",
                "findings",
                "asset_risk_scores",
            )
        }


def _patch_runtime(engine: Engine):
    return (
        patch("app.endpoint_agent_identity.get_engine", return_value=engine),
        patch("app.endpoint_agent_identity.ensure_database_schema"),
        patch("app.database.get_engine", return_value=engine),
        patch("app.database.ensure_database_schema"),
    )


def run_demo(database_url: str) -> dict[str, object]:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    with disposable_database(database_url) as engine:
        runtime_patchers = _patch_runtime(engine)
        with (
            runtime_patchers[0],
            runtime_patchers[1],
            runtime_patchers[2],
            runtime_patchers[3],
        ):
            issued, context = enroll_fictional_endpoint(engine, now=now)
            catalog, checksum = load_catalog(
                BACKEND_ROOT
                / "catalogs"
                / "synthetic-native-software-advisory-catalog.json"
            )
            SqlAdvisoryStore().import_catalog(
                catalog=catalog,
                checksum=checksum,
                imported_at=now,
            )

            initial_envelope = endpoint_envelope(
                payload=native_payload(
                    now=now,
                    batch_id="native-demo-complete-0001",
                    status="complete",
                    packages=(
                        ("fictional-native-library", "1.5.0"),
                        ("fictional-native-helper", "3.0.0"),
                    ),
                ),
                context=context,
                received_at=now,
            )
            initial = ingest(initial_envelope)
            backend_main._run_canonical_inventory_evaluation(
                canonical_collection_id=initial.canonical_collection_id
            )
            component_store = SqlComponentStore()
            vulnerability_store = SqlVulnerabilityStore()
            finding_store = SqlFindingStore()
            initial_components = component_store.list_components(
                site_id=SITE_ID,
                asset_id=ASSET_ID,
                active=None,
            )["items"]
            vulnerable = next(
                item
                for item in initial_components
                if item["name"] == "fictional-native-library"
            )
            initial_matches = vulnerability_store.list_matches(
                site_id=SITE_ID,
                asset_id=ASSET_ID,
            )["items"]
            initial_findings = finding_store.list_findings(
                site_id=SITE_ID,
                asset_id=ASSET_ID,
                rule_id="vulnerable-component",
            )["items"]
            initial_risk = finding_store.get_asset_risk(
                site_id=SITE_ID,
                asset_id=ASSET_ID,
            )
            advisor = run_advisor(
                request=AdvisorQueryRequest(
                    question=(
                        "Explain the native package vulnerability, finding, and "
                        "risk contribution for fictional-native-endpoint."
                    ),
                    site_id=SITE_ID,
                    asset_id=ASSET_ID,
                ),
                tools=backend_main.build_read_only_hub_tools(),
                config=ProviderConfig("demo", False, None, None, None, 10),
            )

            before_replay = _counts(engine)
            replay = ingest(initial_envelope)
            after_replay = _counts(engine)

            partial_time = now + timedelta(seconds=1)
            partial = ingest(
                endpoint_envelope(
                    payload=native_payload(
                        now=partial_time,
                        batch_id="native-demo-partial-0002",
                        status="partial",
                        packages=(("fictional-native-helper", "3.0.0"),),
                        error_code="command-timeout",
                        limitations=("source-timeout",),
                    ),
                    context=context,
                    received_at=partial_time,
                )
            )
            backend_main._run_canonical_inventory_evaluation(
                canonical_collection_id=partial.canonical_collection_id
            )
            after_partial = component_store.list_components(
                site_id=SITE_ID,
                asset_id=ASSET_ID,
                active=None,
            )["items"]
            partial_preserved = next(
                item
                for item in after_partial
                if item["component_id"] == vulnerable["component_id"]
            )["active"]

            complete_time = now + timedelta(seconds=2)
            withdrawn = ingest(
                endpoint_envelope(
                    payload=native_payload(
                        now=complete_time,
                        batch_id="native-demo-complete-0003",
                        status="complete",
                        packages=(("fictional-native-helper", "3.0.0"),),
                    ),
                    context=context,
                    received_at=complete_time,
                )
            )
            backend_main._run_canonical_inventory_evaluation(
                canonical_collection_id=withdrawn.canonical_collection_id
            )
            final_components = component_store.list_components(
                site_id=SITE_ID,
                asset_id=ASSET_ID,
                active=None,
            )["items"]
            historical = next(
                item
                for item in final_components
                if item["component_id"] == vulnerable["component_id"]
            )
            final_matches = vulnerability_store.list_matches(
                site_id=SITE_ID,
                asset_id=ASSET_ID,
            )["items"]
            final_findings = finding_store.list_findings(
                site_id=SITE_ID,
                asset_id=ASSET_ID,
                rule_id="vulnerable-component",
            )["items"]
            final_risk = finding_store.get_asset_risk(
                site_id=SITE_ID,
                asset_id=ASSET_ID,
            )
            evidence_ids = sorted(item.evidence_id for item in advisor.evidence)
            required_ids = {
                vulnerable["component_id"],
                initial_matches[0]["match_id"],
                f"finding:{initial_findings[0]['finding_id']}",
                vulnerable["collection_sources"][0]["source_snapshot_id"],
                initial.canonical_collection_id,
            }
            checks = {
                "bound_agent_identity": bool(issued["agent_id"]),
                "initial_component_current": bool(vulnerable["active"]),
                "initial_match_affected": initial_matches[0]["match_status"] == "affected",
                "initial_finding_active": initial_findings[0]["status"] == "active",
                "initial_risk_present": bool(initial_risk),
                "identical_replay_deduplicated": (
                    replay.status == "duplicate"
                    and replay.canonical_collection_id == initial.canonical_collection_id
                    and before_replay == after_replay
                ),
                "partial_snapshot_preserved_component": bool(partial_preserved),
                "complete_snapshot_withdrew_component": not historical["active"],
                "match_resolved": final_matches[0]["match_status"] == "not-affected",
                "finding_resolved": final_findings[0]["status"] == "resolved",
                "vulnerability_risk_removed": bool(final_risk)
                and not any(
                    factor.get("category") == "vulnerability"
                    for factor in final_risk["factors"]
                ),
                "ai_server_ids_cited": required_ids.issubset(evidence_ids),
            }
            return {
                "schema_version": "oaw.native-software-demo.v1",
                "synthetic_only": True,
                "offline": True,
                "demo_status": "passed" if all(checks.values()) else "failed",
                "checks": checks,
                "canonical_collection_ids": [
                    initial.canonical_collection_id,
                    partial.canonical_collection_id,
                    withdrawn.canonical_collection_id,
                ],
                "server_issued_evidence_ids": evidence_ids,
                "final_counts": _counts(engine),
            }


def main() -> int:
    if os.getenv("OPENASSETWATCH_NATIVE_SOFTWARE_DEMO") != "1" or not os.getenv(
        "DATABASE_URL"
    ):
        print(
            json.dumps(
                {
                    "demo_status": "disabled",
                    "error_code": "explicit-demo-environment-required",
                },
                sort_keys=True,
            )
        )
        return 2
    try:
        result = run_demo(os.environ["DATABASE_URL"])
    except Exception as exc:  # noqa: BLE001 - do not expose database/config details.
        print(
            json.dumps(
                {
                    "demo_status": "failed",
                    "error_code": f"demo-{type(exc).__name__.lower()}"[:80],
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0 if result["demo_status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
