from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SEED_SCRIPT = REPO_ROOT / "scripts" / "seed_control_tower_demo.py"


def load_seed_module():
    spec = importlib.util.spec_from_file_location("seed_control_tower_demo", SEED_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load seed_control_tower_demo.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class InMemoryDemoSeedStore:
    def __init__(self) -> None:
        self.sites = {}
        self.agents = {}
        self.checkins = []
        self.collections = []
        self.assets = {}
        self.operations = []

    def clear_demo_records(self) -> None:
        self.checkins.clear()
        self.collections.clear()
        self.assets.clear()

    def upsert_site(self, site) -> None:
        self.sites[site.site_id] = site
        self.operations.append(("site", site.site_id))

    def upsert_agent(self, agent, *, last_seen_at) -> None:
        self.agents[agent.agent_id] = (agent, last_seen_at)
        self.operations.append(("agent", agent.agent_id))

    def insert_checkin(self, checkin, *, received_at) -> None:
        self.checkins.append((checkin, received_at))

    def insert_collection(self, *, site_id, source_agent_id, received_at, assets) -> None:
        self.collections.append((site_id, source_agent_id, received_at, tuple(assets)))

    def upsert_asset(self, asset, *, seen_at) -> None:
        self.assets[(asset.site_id, asset.asset_id)] = (asset, seen_at)

    def summary(self) -> dict[str, int]:
        return {
            "site_count": len(self.sites),
            "agent_count": len(self.agents),
            "checkin_count": len(self.checkins),
            "asset_count": len(self.assets),
            "evidence_count": sum(asset.evidence_count for asset, _seen_at in self.assets.values()),
        }


class ControlTowerDemoSeedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.seed = load_seed_module()

    def test_sample_identifiers_are_stable_and_synthetic(self) -> None:
        self.assertEqual([site.site_id for site in self.seed.DEMO_SITES], ["demo-home", "demo-office", "demo-lab"])
        self.assertEqual(
            [agent.agent_id for agent in self.seed.DEMO_AGENTS],
            [
                "sensor-home-demo-01",
                "sensor-office-demo-01",
                "sensor-lab-demo-01",
                "agent-win-home-demo-01",
                "agent-macos-office-demo-01",
                "agent-linux-lab-demo-01",
            ],
        )
        for site in self.seed.DEMO_SITES:
            self.assertTrue(site.site_id.startswith("demo-"))
            self.assertIn("Demo", site.name)
        for asset in self.seed.DEMO_ASSETS:
            with self.subTest(asset=asset.asset_id):
                self.assertTrue(self.seed.documentation_network_ip(asset.primary_ip))
                self.assertTrue(self.seed.locally_administered_mac(asset.mac))
                self.assertIn("demo", asset.asset_id)
        self.assertIn("asset-home-mobile-demo", [asset.asset_id for asset in self.seed.DEMO_ASSETS])
        for site in self.seed.DEMO_SITES:
            sensors = [
                agent
                for agent in self.seed.DEMO_AGENTS
                if agent.site_id == site.site_id and agent.agent_type == "network-sensor"
            ]
            self.assertEqual(len(sensors), 1)

    def test_seed_payloads_do_not_contain_forbidden_terms(self) -> None:
        self.assertIn("exploit payload", self.seed.FORBIDDEN_SEED_TERMS)
        self.assertIn("webshell", self.seed.FORBIDDEN_SEED_TERMS)
        self.seed.validate_seed_payloads()

    def test_running_seed_twice_does_not_duplicate_records(self) -> None:
        store = InMemoryDemoSeedStore()

        first = self.seed.seed_demo_data(store)
        second = self.seed.seed_demo_data(store)

        self.assertEqual(first["summary"], second["summary"])
        self.assertEqual(len(store.sites), 3)
        self.assertEqual(len(store.agents), 6)
        self.assertEqual(len(store.checkins), len(self.seed.DEMO_CHECKINS))
        self.assertEqual(len(store.assets), len(self.seed.DEMO_ASSETS))
        self.assertEqual(first["summary"]["evidence_count"], 62)

    def test_site_metadata_is_reapplied_after_agent_upserts(self) -> None:
        store = InMemoryDemoSeedStore()

        self.seed.seed_demo_data(store)

        last_site_operations = store.operations[9:12]
        self.assertEqual(
            last_site_operations,
            [("site", "demo-home"), ("site", "demo-office"), ("site", "demo-lab")],
        )
        self.assertEqual(store.sites["demo-home"].name, "Home Demo")
        self.assertEqual(store.sites["demo-office"].name, "Office Demo")
        self.assertEqual(store.sites["demo-lab"].name, "Lab Demo")

    def test_demo_inputs_generate_cross_site_deterministic_findings(self) -> None:
        if str(self.seed.BACKEND_ROOT) not in sys.path:
            sys.path.insert(0, str(self.seed.BACKEND_ROOT))
        from app.findings import evaluate_rules

        sensors = [
            {
                "agent_id": agent.agent_id,
                "site_id": agent.site_id,
                "agent_type": agent.agent_type,
                "identity_status": "active",
                "last_seen_at": self.seed.event_time(agent.last_seen_minutes_ago),
            }
            for agent in self.seed.DEMO_AGENTS
        ]
        assets = [
            {
                "asset_id": asset.asset_id,
                "site_id": asset.site_id,
                "source_agent_id": asset.source_agent_id,
                "mac": asset.mac,
                "observed_at": self.seed.event_time(asset.last_seen_minutes_ago),
                "first_seen_at": self.seed.event_time(asset.last_seen_minutes_ago),
                "confidence": asset.confidence,
                "metadata": {
                    "category": asset.category,
                    "security_coverage": asset.security_coverage,
                },
            }
            for asset in self.seed.DEMO_ASSETS
        ]
        snapshot = evaluate_rules(
            sites=[site.__dict__ for site in self.seed.DEMO_SITES],
            sensors=sensors,
            assets=assets,
            now=self.seed.DEMO_BASE_TIME,
        )

        # Home remains the healthy comparison site; Office and Lab carry
        # deterministic review conditions.
        self.assertEqual(
            {finding.site_id for finding in snapshot.candidates},
            {"demo-office", "demo-lab"},
        )
        self.assertIn("sensor-stale", {finding.rule_id for finding in snapshot.candidates})
        self.assertIn("security-coverage-gap", {finding.rule_id for finding in snapshot.candidates})
        self.assertIn("unknown-asset", {finding.rule_id for finding in snapshot.candidates})
        self.assertIn("passive-only-asset", {finding.rule_id for finding in snapshot.candidates})
        self.assertIn("identity-conflict", {finding.rule_id for finding in snapshot.candidates})
        self.assertTrue(all(finding.dedupe_key.startswith("fdk_") for finding in snapshot.candidates))

    def test_non_local_database_url_is_rejected(self) -> None:
        self.assertFalse(
            self.seed.local_database_url(
                "postgresql+psycopg2://openassetwatch:example@db.example.invalid:5432/openassetwatch"
            )
        )
        self.assertTrue(self.seed.local_database_url(self.seed.LOCAL_DATABASE_URL))

    def test_datetime_usage_is_python_310_compatible(self) -> None:
        source = SEED_SCRIPT.read_text(encoding="utf-8")

        self.assertIn("timezone.utc", source)
        self.assertNotIn("from datetime import UTC", source)
        self.assertEqual(self.seed.DEMO_BASE_TIME.tzinfo, self.seed.timezone.utc)

    def test_compose_database_host_requires_explicit_allow(self) -> None:
        compose_url = (
            "postgresql+psycopg2://openassetwatch:"
            "example@postgres:5432/openassetwatch"
        )

        self.assertFalse(self.seed.local_database_url(compose_url))
        self.assertTrue(self.seed.local_database_url(compose_url, allow_compose_host=True))
        self.assertTrue(self.seed.compose_host_allowed("1"))
        self.assertTrue(self.seed.compose_host_allowed("true"))
        self.assertFalse(self.seed.compose_host_allowed(""))

    def test_missing_dependency_error_points_to_compose_seed(self) -> None:
        message = self.seed.dependency_error_message("sqlalchemy")

        self.assertIn("sqlalchemy", message)
        self.assertIn("docker compose --profile demo run --rm demo-seed", message)
        self.assertIn("backend requirements", message)


if __name__ == "__main__":
    unittest.main()
