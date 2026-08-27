from __future__ import annotations

import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi import BackgroundTasks, HTTPException
from pydantic import ValidationError

from app.canonical_ingestion import (
    CanonicalAdmissionRejected,
    CanonicalAuthorizationRejected,
    CanonicalIngestionAcknowledgement,
)
from app.database import LegacyAgentIdentityConflict
from app.endpoint_agent_contracts import EndpointInventoryRequest
from app.endpoint_agent_identity import (
    AGENT_CREDENTIAL_PREFIX,
    AGENT_ENROLLMENT_TOKEN_PREFIX,
    AgentAuthenticationRejected,
    AgentAuthContext,
    _public_credential,
    authenticate_agent_request,
    issue_agent_credential,
    issue_agent_enrollment_token,
    parse_agent_token,
)
from app.main import (
    authenticated_endpoint_inventory,
    agent_check_in,
    require_configured_admin_token,
)


def inventory_payload() -> dict[str, object]:
    return {
        "schema_version": "oaw.endpoint-inventory.v1",
        "inventory_batch_id": "batch_0123456789abcdef",
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "inventory_mode": "complete",
        "site_id": "site-a",
        "agent_id": "agent_" + "1" * 32,
        "deployment_id": "deployment-a",
        "agent_type": "endpoint-agent",
        "agent_version": "0.1.0",
        "platform": "linux",
        "architecture": "amd64",
        "supported_capabilities": ["endpoint-inventory-v1"],
        "collection_limitations": [],
        "assets": [
            {
                "asset_id": "host-a",
                "hostname": "host-a.example.test",
                "os": "FictionalOS 1",
                "interfaces": [
                    {
                        "name": "eth0",
                        "mac_address": "02:00:00:00:00:01",
                        "ip_addresses": [{"address": "192.0.2.10", "family": "ipv4"}],
                    }
                ],
                "evidence": [
                    {
                        "kind": "operating-system",
                        "value": "FictionalOS 1",
                        "method": "endpoint-inventory",
                        "confidence": 0.95,
                    }
                ],
                "components": [
                    {
                        "component_type": "application",
                        "ecosystem": "pypi",
                        "name": "fictional-package",
                        "version": "1.0.0",
                    }
                ],
                "management_capabilities": ["software-inventory"],
            }
        ],
    }


def canonical_acknowledgement(
    *, status: str = "accepted"
) -> CanonicalIngestionAcknowledgement:
    return CanonicalIngestionAcknowledgement(
        status=status,
        canonical_collection_id="col_" + "3" * 32,
        canonical_asset_ids=("host-a",) if status == "accepted" else (),
        replay_state="new" if status == "accepted" else "identical-replay",
        evidence_count=1,
        component_count=1,
        evaluation_state="queued",
        warnings=("authenticated identity does not prove every reported fact",),
        adapter_type="endpoint-agent",
        compatibility_status="canonical",
        source_authority="authenticated-endpoint",
        compatibility_collection_id=8,
        endpoint_storage_id=7,
        received_at=datetime.now(timezone.utc),
        observed_asset_count=1,
        normalized_asset_count=1,
    )


class EndpointAgentIdentityTests(unittest.TestCase):
    def test_agent_token_namespaces_are_distinct_from_each_other_and_sensors(self) -> None:
        enrollments = {issue_agent_enrollment_token().raw for _ in range(64)}
        credentials = {issue_agent_credential().raw for _ in range(64)}

        self.assertEqual(len(enrollments), 64)
        self.assertEqual(len(credentials), 64)
        self.assertTrue(all(item.startswith(f"{AGENT_ENROLLMENT_TOKEN_PREFIX}.") for item in enrollments))
        self.assertTrue(all(item.startswith(f"{AGENT_CREDENTIAL_PREFIX}.") for item in credentials))
        self.assertTrue(enrollments.isdisjoint(credentials))
        self.assertIsNone(
            parse_agent_token("oaw_sensor_v1." + "a" * 32 + "." + "b" * 43, AGENT_CREDENTIAL_PREFIX)
        )

    def test_shared_agent_token_is_disabled_unless_explicitly_configured(self) -> None:
        with patch.dict(os.environ, {"OPENASSETWATCH_AGENT_TOKEN": ""}, clear=False):
            with self.assertRaises(AgentAuthenticationRejected):
                authenticate_agent_request(provided_token="development-only")

        with patch.dict(
            os.environ,
            {"OPENASSETWATCH_AGENT_TOKEN": "development-only"},
            clear=False,
        ):
            context = authenticate_agent_request(provided_token="development-only")
        self.assertEqual(context.mode, "development-shared")

    def test_public_credential_projection_never_contains_digest_or_secret(self) -> None:
        projected = _public_credential(
            {
                "credential_id": "acred_" + "2" * 32,
                "agent_id": "agent_" + "1" * 32,
                "site_id": "site-a",
                "credential_digest": "f" * 64,
                "credential": "must-not-appear",
                "status": "active",
            }
        )
        self.assertNotIn("credential_digest", projected)
        self.assertNotIn("credential", projected)

    def test_state_changing_admin_operations_fail_closed_without_configuration(self) -> None:
        with patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": ""}, clear=False):
            with self.assertRaises(HTTPException) as raised:
                require_configured_admin_token(None, capability="endpoint-agent identity administration")
        self.assertEqual(raised.exception.status_code, 503)

    def test_inventory_contract_rejects_server_owned_and_client_evidence_ids(self) -> None:
        server_owned = inventory_payload()
        server_owned["source_authenticated"] = True
        with self.assertRaises(ValidationError):
            EndpointInventoryRequest.model_validate(server_owned)

        supplied_id = inventory_payload()
        supplied_id["assets"][0]["components"][0]["evidence_ids"] = ["invented-id"]  # type: ignore[index]
        with self.assertRaises(ValidationError):
            EndpointInventoryRequest.model_validate(supplied_id)

    def test_authenticated_checkin_uses_only_bound_identity(self) -> None:
        context = AgentAuthContext(
            mode="bound-agent",
            site_id="site-a",
            agent_id="agent_" + "1" * 32,
            deployment_id="deployment-a",
            agent_type="endpoint-agent",
            credential_id="acred_" + "2" * 32,
        )
        payload = {
            "site_id": "site-a",
            "agent_id": "agent_" + "1" * 32,
            "deployment_id": "deployment-a",
            "agent_type": "endpoint-agent",
            "agent_version": "0.1.0",
            "platform": "linux",
            "architecture": "amd64",
        }
        with (
            patch("app.main.authenticate_agent_request", return_value=context) as authenticate,
            patch("app.main.record_authenticated_agent_checkin", return_value=9) as record,
        ):
            response = agent_check_in(payload, agent_credential=issue_agent_credential().raw)
        self.assertEqual(response.site_id, "site-a")
        self.assertEqual(response.source_authority, "authenticated-endpoint")
        self.assertEqual(record.call_args.kwargs["context"], context)
        self.assertEqual(authenticate.call_args.kwargs["claimed_site_id"], "site-a")

    def test_legacy_checkin_rejects_collision_with_bound_identity(self) -> None:
        with patch(
            "app.main.record_agent_checkin",
            side_effect=LegacyAgentIdentityConflict("bound identity"),
        ):
            with self.assertRaises(HTTPException) as raised:
                agent_check_in(
                    {"site_id": "site-a", "agent_id": "agent_" + "1" * 32}
                )
        self.assertEqual(raised.exception.status_code, 409)

    def test_inventory_injects_authority_and_queues_only_new_batches(self) -> None:
        context = AgentAuthContext(
            mode="bound-agent",
            site_id="site-a",
            agent_id="agent_" + "1" * 32,
            deployment_id="deployment-a",
            agent_type="endpoint-agent",
            credential_id="acred_" + "2" * 32,
        )
        payload = EndpointInventoryRequest.model_validate(inventory_payload())
        tasks = BackgroundTasks()
        with (
            patch("app.main.authenticate_agent_request", return_value=context),
            patch(
                "app.main.ingest_canonical_inventory",
                return_value=canonical_acknowledgement(),
            ) as ingest,
        ):
            response = authenticated_endpoint_inventory(
                payload,
                background_tasks=tasks,
                agent_credential=issue_agent_credential().raw,
            )
        envelope = ingest.call_args.args[0]
        self.assertEqual(envelope.site_id, context.site_id)
        self.assertEqual(envelope.bound_identity_id, context.agent_id)
        self.assertTrue(envelope.source_authenticated)
        self.assertEqual(envelope.source_authority, "authenticated-endpoint")
        self.assertEqual(response.canonical_collection_id, "col_" + "3" * 32)
        self.assertEqual(response.reevaluation_state, "queued")
        self.assertEqual(len(tasks.tasks), 1)

    def test_inventory_maps_persistent_admission_and_lifecycle_failures(self) -> None:
        context = AgentAuthContext(
            mode="bound-agent",
            site_id="site-a",
            agent_id="agent_" + "1" * 32,
            deployment_id="deployment-a",
            agent_type="endpoint-agent",
            credential_id="acred_" + "2" * 32,
        )
        payload = EndpointInventoryRequest.model_validate(inventory_payload())
        for failure, status_code in (
            (CanonicalAdmissionRejected("rate"), 429),
            (CanonicalAuthorizationRejected("inactive"), 401),
        ):
            with (
                self.subTest(status_code=status_code),
                patch("app.main.authenticate_agent_request", return_value=context),
                patch(
                    "app.main.ingest_canonical_inventory",
                    side_effect=failure,
                ),
                self.assertRaises(HTTPException) as raised,
            ):
                authenticated_endpoint_inventory(
                    payload,
                    background_tasks=BackgroundTasks(),
                    agent_credential=issue_agent_credential().raw,
                )
            self.assertEqual(raised.exception.status_code, status_code)


if __name__ == "__main__":
    unittest.main()
