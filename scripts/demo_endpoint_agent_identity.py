#!/usr/bin/env python3
"""Run the synthetic endpoint-agent identity showcase in a disposable database."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from unittest.mock import patch
from uuid import uuid4

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.advisory_catalog import load_catalog  # noqa: E402
from app.advisory_store import SqlAdvisoryStore  # noqa: E402
from app.ai_advisor import (  # noqa: E402
    AdvisorQueryRequest,
    ProviderConfig,
    run_advisor,
)
from app.database import (  # noqa: E402
    EndpointInventoryReplayConflict,
    record_authenticated_endpoint_inventory,
)
from app.endpoint_agent_identity import (  # noqa: E402
    AgentAuthenticationRejected,
    AgentEnrollmentRejected,
    authenticate_agent_request,
    create_agent_enrollment,
    exchange_agent_enrollment,
    record_authenticated_agent_checkin,
    revoke_agent_credential,
    rotate_agent_credential,
)
from app.finding_store import SqlFindingStore  # noqa: E402
from app.main import (  # noqa: E402
    _run_endpoint_inventory_reevaluation,
    build_read_only_hub_tools,
)
from app.schema_migrations import migrate_database_schema  # noqa: E402
from app.vulnerability_store import SqlVulnerabilityStore  # noqa: E402


DATABASE_NAME = re.compile(r"^openassetwatch_agent_demo_[0-9a-f]{16}$")


def _inventory(
    *,
    agent_id: str,
    credential_id: str,
    observed_at: datetime,
    component_count: int,
) -> dict:
    components = [
        {
            "component_type": "application",
            "ecosystem": "pypi",
            "name": "asterion-agent",
            "version": "1.2.0",
            "purl": "pkg:pypi/asterion-agent",
            "confidence": 0.95,
        }
    ]
    components.extend(
        {
            "component_type": "application",
            "ecosystem": "pypi",
            "name": f"fictional-package-{index:04d}",
            "version": f"1.{index % 20}.{index % 100}",
            "purl": f"pkg:pypi/fictional-package-{index:04d}",
            "confidence": 0.95,
        }
        for index in range(1, component_count)
    )
    scale = component_count > 1
    interfaces = [
        {
            "name": f"if{index:02d}",
            "mac_address": f"02:00:00:00:{index // 256:02x}:{index % 256:02x}",
            "ip_addresses": [
                {"address": f"192.0.2.{index + 1}", "family": "ipv4"}
            ],
        }
        for index in range(32 if scale else 1)
    ]
    evidence = [
        {
            "kind": f"synthetic-evidence-{index:02d}",
            "value": f"fictional bounded evidence value {index:02d}",
            "method": "endpoint-inventory",
            "confidence": 0.95,
        }
        for index in range(64 if scale else 1)
    ]
    return {
        "schema_version": "oaw.endpoint-inventory.v1",
        "observation_batch_id": "batch_agent_demo_0001",
        "inventory_batch_id": "batch_agent_demo_0001",
        "observed_at": observed_at.isoformat(),
        "collected_at": observed_at.isoformat(),
        "inventory_mode": "complete",
        "component_inventory_complete": True,
        "agent_id": agent_id,
        "site_id": "site-agent-demo",
        "sensor_type": "endpoint-agent",
        "observation_source": "endpoint-inventory",
        "source_authenticated": True,
        "source_authority": "authenticated-endpoint",
        "credential_id": credential_id,
        "assets": [
            {
                "asset_id": "fictional-endpoint",
                "hostname": "fictional-endpoint.example.test",
                "os": "FictionalOS 1",
                "category": "workstation",
                "primary_interfaces": interfaces,
                "ip_addresses": [
                    address
                    for interface in interfaces
                    for address in interface["ip_addresses"]
                ],
                "mac_addresses": [
                    {"address": interface["mac_address"]}
                    for interface in interfaces
                ],
                "evidence": evidence,
                "components": components,
                "component_inventory_complete": True,
            }
        ],
    }


def build_demo() -> dict:
    if os.getenv("OPENASSETWATCH_ENDPOINT_AGENT_DEMO") != "1":
        raise RuntimeError("set OPENASSETWATCH_ENDPOINT_AGENT_DEMO=1 to use a disposable database")
    source_url = os.environ.get("DATABASE_URL")
    if not source_url:
        raise RuntimeError("DATABASE_URL is required")
    parsed = make_url(source_url)
    component_count = int(
        os.getenv("OPENASSETWATCH_ENDPOINT_AGENT_DEMO_COMPONENTS", "1")
    )
    if not 1 <= component_count <= 2_000:
        raise RuntimeError("demonstration component count must be between 1 and 2000")
    database_name = f"openassetwatch_agent_demo_{uuid4().hex[:16]}"
    if not DATABASE_NAME.fullmatch(database_name):
        raise RuntimeError("refusing unsafe demonstration database name")
    admin_engine = create_engine(
        parsed.set(database="postgres"),
        isolation_level="AUTOCOMMIT",
        poolclass=NullPool,
    )
    database_engine = None
    try:
        with admin_engine.connect() as connection:
            connection.exec_driver_sql(f'CREATE DATABASE "{database_name}"')
        database_engine = create_engine(
            parsed.set(database=database_name),
            poolclass=NullPool,
        )
        migrate_database_schema(database_engine)
        with database_engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO sites (site_id, name) "
                    "VALUES ('site-agent-demo', 'Synthetic Endpoint Agent Demo')"
                )
            )
        now = datetime.now(timezone.utc)
        patchers = [
            patch("app.endpoint_agent_identity.get_engine", return_value=database_engine),
            patch("app.endpoint_agent_identity.ensure_database_schema"),
            patch("app.database.get_engine", return_value=database_engine),
            patch("app.database.ensure_database_schema"),
        ]
        for patcher in patchers:
            patcher.start()
        try:
            enrollment = create_agent_enrollment(
                site_id="site-agent-demo",
                requested_deployment_id="deployment-demo",
                requested_display_name="Fictional Endpoint",
                requested_agent_type="endpoint-agent",
                expires_in_minutes=30,
                actor="synthetic-demo-admin",
                now=now,
            )
            issued = exchange_agent_enrollment(
                enrollment_token=enrollment["enrollment_token"],
                installation_id="deployment-demo",
                display_name="Fictional Endpoint",
                agent_version="0.1.0",
                platform="linux",
                architecture="amd64",
                agent_type="endpoint-agent",
                now=now,
            )
            replay_rejected = False
            try:
                exchange_agent_enrollment(
                    enrollment_token=enrollment["enrollment_token"],
                    installation_id="deployment-demo",
                    display_name="Fictional Endpoint",
                    agent_version="0.1.0",
                    platform="linux",
                    architecture="amd64",
                    agent_type="endpoint-agent",
                    now=now,
                )
            except AgentEnrollmentRejected:
                replay_rejected = True
            context = authenticate_agent_request(
                provided_token=issued["agent_credential"],
                claimed_site_id="site-agent-demo",
                claimed_agent_id=issued["agent_id"],
                claimed_deployment_id="deployment-demo",
                claimed_agent_type="endpoint-agent",
                now=now,
            )
            substitution_rejected = False
            try:
                authenticate_agent_request(
                    provided_token=issued["agent_credential"],
                    claimed_site_id="site-other",
                    now=now,
                )
            except AgentAuthenticationRejected:
                substitution_rejected = True
            record_authenticated_agent_checkin(
                context=context,
                payload={
                    "agent_version": "0.1.0",
                    "platform": "linux",
                    "architecture": "amd64",
                    "hostname": "fictional-endpoint.example.test",
                    "supported_capabilities": ["endpoint-inventory-v1"],
                    "inventory_schema_version": "oaw.endpoint-inventory.v1",
                    "health": "healthy",
                    "observed_at": now.isoformat(),
                },
                received_at=now,
            )
            payload = _inventory(
                agent_id=issued["agent_id"],
                credential_id=issued["credential_id"],
                observed_at=now,
                component_count=component_count,
            )
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            payload_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            catalog, checksum = load_catalog(
                BACKEND_ROOT / "catalogs" / "synthetic-advisory-catalog.json"
            )
            SqlAdvisoryStore().import_catalog(
                catalog=catalog,
                checksum=checksum,
                imported_at=now,
            )
            ingestion_started = perf_counter()
            first = record_authenticated_endpoint_inventory(
                payload=payload,
                payload_sha256=payload_digest,
                site_id="site-agent-demo",
                agent_id=issued["agent_id"],
                credential_id=issued["credential_id"],
                inventory_batch_id="batch_agent_demo_0001",
                inventory_mode="complete",
                observed_at=now,
                received_at=now,
            )
            replay = record_authenticated_endpoint_inventory(
                payload=payload,
                payload_sha256=payload_digest,
                site_id="site-agent-demo",
                agent_id=issued["agent_id"],
                credential_id=issued["credential_id"],
                inventory_batch_id="batch_agent_demo_0001",
                inventory_mode="complete",
                observed_at=now,
                received_at=now,
            )
            conflict_rejected = False
            try:
                record_authenticated_endpoint_inventory(
                    payload=payload,
                    payload_sha256="f" * 64,
                    site_id="site-agent-demo",
                    agent_id=issued["agent_id"],
                    credential_id=issued["credential_id"],
                    inventory_batch_id="batch_agent_demo_0001",
                    inventory_mode="complete",
                    observed_at=now,
                    received_at=now,
                )
            except EndpointInventoryReplayConflict:
                conflict_rejected = True
            _run_endpoint_inventory_reevaluation(
                storage_id=int(first["storage_id"]),
                site_id="site-agent-demo",
                asset_ids=["fictional-endpoint"],
            )
            elapsed_ms = (perf_counter() - ingestion_started) * 1000
            matches = SqlVulnerabilityStore().list_matches(
                site_id="site-agent-demo", asset_id="fictional-endpoint"
            )["items"]
            finding_store = SqlFindingStore()
            findings = finding_store.list_findings(
                site_id="site-agent-demo",
                asset_id="fictional-endpoint",
                status="active",
            )["items"]
            risk = finding_store.get_asset_risk(
                site_id="site-agent-demo", asset_id="fictional-endpoint"
            )
            advisor = run_advisor(
                request=AdvisorQueryRequest(
                    question=(
                        "Explain endpoint agent identity, classification evidence, "
                        "component vulnerability, finding, and deterministic risk "
                        "contribution for fictional-endpoint"
                    ),
                    site_id="site-agent-demo",
                    asset_id="fictional-endpoint",
                ),
                tools=build_read_only_hub_tools(),
                config=ProviderConfig("demo", False, None, None, None, 10),
            )
            rotated = rotate_agent_credential(
                issued["agent_id"], actor="synthetic-demo-admin", now=now
            )
            old_rejected = False
            try:
                authenticate_agent_request(
                    provided_token=issued["agent_credential"], now=now
                )
            except AgentAuthenticationRejected:
                old_rejected = True
            authenticate_agent_request(
                provided_token=rotated["agent_credential"], now=now
            )
            revoke_agent_credential(
                issued["agent_id"],
                rotated["credential_id"],
                actor="synthetic-demo-admin",
                now=now,
            )
            revoked_rejected = False
            try:
                authenticate_agent_request(
                    provided_token=rotated["agent_credential"], now=now
                )
            except AgentAuthenticationRejected:
                revoked_rejected = True
            with database_engine.connect() as connection:
                history_count = int(
                    connection.execute(
                        text(
                            "SELECT COUNT(*) FROM endpoint_agent_identity_audit_events "
                            "WHERE agent_id=:agent_id"
                        ),
                        {"agent_id": issued["agent_id"]},
                    ).scalar_one()
                )
                persisted_component_count = int(
                    connection.execute(
                        text(
                            "SELECT COUNT(*) FROM asset_components "
                            "WHERE site_id='site-agent-demo' "
                            "AND asset_id='fictional-endpoint' AND active=TRUE"
                        )
                    ).scalar_one()
                )
            evidence_ids = [item.evidence_id for item in advisor.evidence]
            return {
                "schema_version": "oaw.endpoint-agent-demo.v1",
                "synthetic_only": True,
                "network_access": False,
                "database_disposable": True,
                "enrollment": {
                    "agent_id": issued["agent_id"],
                    "site_id": issued["site_id"],
                    "replay_rejected": replay_rejected,
                    "site_substitution_rejected": substitution_rejected,
                },
                "inventory": {
                    "storage_id": first["storage_id"],
                    "duplicate_idempotent": replay["storage_id"] == first["storage_id"],
                    "conflicting_replay_rejected": conflict_rejected,
                    "reevaluation_state": "completed",
                    "elapsed_ms": round(elapsed_ms, 3),
                    "interface_count": 32 if component_count > 1 else 1,
                    "evidence_entry_count": 64 if component_count > 1 else 1,
                    "submitted_component_count": component_count,
                    "persisted_component_count": persisted_component_count,
                },
                "deterministic_results": {
                    "component_id": matches[0]["component_id"],
                    "match_id": matches[0]["match_id"],
                    "match_status": matches[0]["match_status"],
                    "finding_id": findings[0]["finding_id"],
                    "risk_score": risk["score"] if risk else None,
                },
                "ai": {
                    "advisory_only": advisor.advisory_only,
                    "evidence_ids": evidence_ids,
                },
                "credential_lifecycle": {
                    "old_rejected_after_rotation": old_rejected,
                    "new_accepted_after_rotation": True,
                    "revoked_rejected": revoked_rejected,
                    "history_event_count": history_count,
                },
            }
        finally:
            for patcher in reversed(patchers):
                patcher.stop()
    finally:
        if database_engine is not None:
            database_engine.dispose()
        if DATABASE_NAME.fullmatch(database_name):
            with admin_engine.connect() as connection:
                connection.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                        "WHERE datname=:database_name AND pid <> pg_backend_pid()"
                    ),
                    {"database_name": database_name},
                )
                connection.exec_driver_sql(f'DROP DATABASE "{database_name}"')
        admin_engine.dispose()


def main() -> int:
    print(json.dumps(build_demo(), indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
