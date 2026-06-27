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
        self.assertEqual([site.site_id for site in self.seed.DEMO_SITES], ["home-lab", "small-office"])
        self.assertEqual(
            [agent.agent_id for agent in self.seed.DEMO_AGENTS],
            ["agent-win-demo-01", "agent-macos-demo-01", "sensor-passive-demo-01"],
        )
        for site in self.seed.DEMO_SITES:
            self.assertIn("Demo", site.name)
        for asset in self.seed.DEMO_ASSETS:
            with self.subTest(asset=asset.asset_id):
                self.assertTrue(self.seed.documentation_network_ip(asset.primary_ip))
                self.assertTrue(self.seed.locally_administered_mac(asset.mac))
                self.assertIn("demo", asset.asset_id)
        self.assertIn("asset-mobile-demo", [asset.asset_id for asset in self.seed.DEMO_ASSETS])

    def test_seed_payloads_do_not_contain_forbidden_terms(self) -> None:
        self.assertIn("exploit payload", self.seed.FORBIDDEN_SEED_TERMS)
        self.assertIn("webshell", self.seed.FORBIDDEN_SEED_TERMS)
        self.seed.validate_seed_payloads()

    def test_running_seed_twice_does_not_duplicate_records(self) -> None:
        store = InMemoryDemoSeedStore()

        first = self.seed.seed_demo_data(store)
        second = self.seed.seed_demo_data(store)

        self.assertEqual(first["summary"], second["summary"])
        self.assertEqual(len(store.sites), 2)
        self.assertEqual(len(store.agents), 3)
        self.assertEqual(len(store.checkins), len(self.seed.DEMO_CHECKINS))
        self.assertEqual(len(store.assets), len(self.seed.DEMO_ASSETS))
        self.assertEqual(first["summary"]["evidence_count"], 38)

    def test_site_metadata_is_reapplied_after_agent_upserts(self) -> None:
        store = InMemoryDemoSeedStore()

        self.seed.seed_demo_data(store)

        last_site_operations = store.operations[5:7]
        self.assertEqual(last_site_operations, [("site", "home-lab"), ("site", "small-office")])
        self.assertEqual(store.sites["home-lab"].name, "Home Lab Demo")
        self.assertEqual(store.sites["small-office"].name, "Small Office Demo")

    def test_non_local_database_url_is_rejected(self) -> None:
        self.assertFalse(
            self.seed.local_database_url(
                "postgresql+psycopg2://openassetwatch:example@db.example.invalid:5432/openassetwatch"
            )
        )
        self.assertTrue(self.seed.local_database_url(self.seed.LOCAL_DATABASE_URL))


if __name__ == "__main__":
    unittest.main()
