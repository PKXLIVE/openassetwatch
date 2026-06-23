from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.database import ensure_database_schema, normalize_local_inventory_assets
from app.main import (
    AgentEnrollmentRequest,
    SiteRequest,
    api_agent_release_status,
    api_control_tower_summary,
    api_create_agent_enrollment,
    api_create_site,
    api_list_agents,
    api_list_sites,
    health,
)


class _FakeBegin:
    def __init__(self, connection: Mock) -> None:
        self.connection = connection

    def __enter__(self) -> Mock:
        return self.connection

    def __exit__(self, *_args: object) -> None:
        return None


class ControlTowerTests(unittest.TestCase):
    def test_health_reports_control_tower_version(self) -> None:
        response = health()

        self.assertEqual(response["status"], "healthy")
        self.assertEqual(response["service"], "openassetwatch-control-tower")
        self.assertTrue(response["version"])

    def test_create_and_list_sites_use_repository(self) -> None:
        saved_site = {
            "site_id": "site-local",
            "name": "Local Lab",
            "description": "Demo site",
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        with patch("app.main.create_site", return_value=saved_site) as create:
            response = api_create_site(SiteRequest(site_id="site-local", name="Local Lab", description="Demo site"))

        self.assertEqual(response["site_id"], "site-local")
        self.assertEqual(create.call_args.kwargs["name"], "Local Lab")

        with patch("app.main.list_sites", return_value=[saved_site]):
            response = api_list_sites()

        self.assertEqual(response["sites"][0]["site_id"], "site-local")

    def test_agent_enrollment_accepts_endpoint_agent_and_network_sensor(self) -> None:
        now = datetime.now(timezone.utc)
        saved_agent = {
            "agent_id": "agent-1",
            "site_id": "site-local",
            "display_name": "Windows Agent",
            "agent_type": "endpoint-agent",
            "platform": "windows",
            "architecture": "amd64",
            "version": None,
            "hostname": None,
            "mode": None,
            "created_at": now,
            "updated_at": now,
            "last_seen_at": None,
        }
        with patch("app.main.create_agent_enrollment", return_value=saved_agent) as create:
            response = api_create_agent_enrollment(
                AgentEnrollmentRequest(
                    agent_id="agent-1",
                    site_id="site-local",
                    display_name="Windows Agent",
                    agent_type="endpoint-agent",
                    platform="windows",
                    architecture="amd64",
                )
            )

        self.assertEqual(response["agent_type"], "endpoint-agent")
        self.assertEqual(create.call_args.kwargs["agent_id"], "agent-1")

        with patch("app.main.list_agent_enrollments", return_value=[saved_agent]):
            response = api_list_agents()

        self.assertEqual(response["agents"][0]["agent_id"], "agent-1")

    def test_agent_enrollment_rejects_unknown_type(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            api_create_agent_enrollment(
                AgentEnrollmentRequest(
                    agent_id="agent-1",
                    site_id="site-local",
                    agent_type="unsupported",
                )
            )

        self.assertEqual(raised.exception.status_code, 400)

    def test_local_inventory_normalization_extracts_basic_asset_record(self) -> None:
        received_at = datetime.now(timezone.utc)
        payload = {
            "site_id": "site-local",
            "agent_id": "agent-1",
            "assets": [
                {
                    "asset_id": "local-host",
                    "hostname": "workstation-01",
                    "platform_info": {"os": "windows", "platform": "windows/amd64"},
                    "primary_interfaces": [
                        {
                            "mac_address": "00-11-22-33-44-55",
                            "ip_addresses": [{"address": "192.0.2.10"}],
                        }
                    ],
                    "network_neighbors": [{"ip_address": "192.0.2.1"}],
                }
            ],
        }

        assets = normalize_local_inventory_assets(payload, site_id="site-local", received_at=received_at)

        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["asset_id"], "local-host")
        self.assertEqual(assets[0]["site_id"], "site-local")
        self.assertEqual(assets[0]["hostname"], "workstation-01")
        self.assertEqual(assets[0]["primary_ip"], "192.0.2.10")
        self.assertEqual(assets[0]["mac"], "00:11:22:33:44:55")
        self.assertEqual(assets[0]["os"], "windows")
        self.assertGreaterEqual(assets[0]["evidence_count"], 3)

    def test_schema_initialization_includes_control_tower_tables(self) -> None:
        connection = Mock()
        fake_engine = Mock()
        fake_engine.begin.return_value = _FakeBegin(connection)

        with patch("app.database.get_engine", return_value=fake_engine):
            ensure_database_schema()

        executed_sql = "\n".join(str(call.args[0]) for call in connection.execute.call_args_list)
        self.assertIn("CREATE TABLE IF NOT EXISTS sites", executed_sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS agent_enrollments", executed_sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS agent_checkins", executed_sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS local_inventory_collections", executed_sql)
        self.assertIn("CREATE TABLE IF NOT EXISTS control_tower_assets", executed_sql)

    def test_release_status_is_metadata_only(self) -> None:
        response = api_agent_release_status()

        self.assertFalse(response["update_available"])
        self.assertEqual(response["update_execution"], "disabled")
        self.assertNotIn("download", response["update_execution"].lower())

    def test_summary_uses_repository_counts(self) -> None:
        with patch(
            "app.main.control_tower_summary",
            return_value={
                "site_count": 1,
                "agent_count": 2,
                "checkin_count": 3,
                "asset_count": 4,
                "evidence_count": 5,
            },
        ):
            response = api_control_tower_summary()

        self.assertEqual(response["site_count"], 1)
        self.assertEqual(response["evidence_count"], 5)

    def test_safe_config_examples_do_not_contain_real_secrets(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        for relative_path in (".env.example", "docker-compose.yml"):
            content = (repo_root / relative_path).read_text(encoding="utf-8")
            lowered = content.lower()
            self.assertNotIn("sk-", lowered)
            self.assertNotIn("api_key=", lowered)
            self.assertNotIn("password123", lowered)
            self.assertNotIn("secret123", lowered)


if __name__ == "__main__":
    unittest.main()
