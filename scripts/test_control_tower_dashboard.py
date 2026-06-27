from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
DASHBOARD_FILE = REPO_ROOT / "backend" / "app" / "static" / "index.html"
DOC_FILES = [
    REPO_ROOT / "docs" / "CONTROL_TOWER_DEPLOYMENT.md",
    REPO_ROOT / "web" / "README.md",
]


class ControlTowerDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dashboard = DASHBOARD_FILE.read_text(encoding="utf-8")

    def test_dashboard_references_expected_local_endpoints(self) -> None:
        expected_endpoints = (
            "/health",
            "/api/v1/control-tower/summary",
            "/api/v1/sites",
            "/api/v1/agents",
            "/api/v1/control-tower/check-ins",
            "/api/v1/control-tower/assets",
            "/api/v1/releases/agent",
        )
        self.assertIn('http://127.0.0.1:8000', self.dashboard)
        for endpoint in expected_endpoints:
            with self.subTest(endpoint=endpoint):
                self.assertIn(endpoint, self.dashboard)

    def test_dashboard_contains_required_mvp_sections(self) -> None:
        required_sections = (
            "Control Tower Dashboard",
            "Dashboard",
            "Assets",
            "Collectors",
            "Sites",
            "Evidence",
            "Findings",
            "Policies",
            "Reports",
            "Settings",
            "Total assets",
            "Unknown assets",
            "Unmanaged assets",
            "Active collectors",
            "Stale collectors",
            "Evidence records",
            "Getting Started",
            "Create Site",
            "Asset Mix By Type",
            "Collector Health",
            "Recent Check-ins",
            "Recent Evidence",
            "Top Findings / Attention Items",
            "Sites Overview",
            "Asset Inventory",
            "Asset Detail",
            "Endpoint Agents",
            "Passive Sensors",
            "Evidence Source",
            "Policy Guardrails",
            "Recommended Next Steps",
            "Release Status",
        )
        for section in required_sections:
            with self.subTest(section=section):
                self.assertIn(section, self.dashboard)

    def test_dashboard_contains_asset_filters_and_attention_copy(self) -> None:
        expected_copy = (
            'id="asset-search"',
            'data-filter="unknown"',
            'data-filter="iot"',
            'data-filter="infrastructure"',
            'data-filter="workstation"',
            'data-filter="stale"',
            'data-filter="missing-tooling"',
            "Unknown device observed",
            "Unmanaged IoT device",
            "Missing security tooling sample",
            "Stale collector sample",
            "Printer inventory review",
        )
        for copy in expected_copy:
            with self.subTest(copy=copy):
                self.assertIn(copy, self.dashboard)

    def test_dashboard_documents_safe_read_only_policy_states(self) -> None:
        expected_copy = (
            "Passive-first collection",
            "Active checks disabled",
            "SNMP disabled",
            "Packet capture disabled",
            "Remote commands unavailable",
            "Release metadata only",
        )
        for copy in expected_copy:
            with self.subTest(copy=copy):
                self.assertIn(copy, self.dashboard)

    def test_dashboard_includes_loading_empty_and_error_states(self) -> None:
        expected_copy = (
            "Loading Control Tower data",
            "No sites yet",
            "No agents or sensors yet",
            "No check-ins yet",
            "No matching assets",
            "No evidence yet",
            "No findings yet",
            "API data could not be loaded",
            "Sites unavailable until the API responds.",
        )
        for copy in expected_copy:
            with self.subTest(copy=copy):
                self.assertIn(copy, self.dashboard)

    def test_create_site_form_uses_existing_sites_endpoint(self) -> None:
        self.assertIn('id="site-form"', self.dashboard)
        self.assertIn('name="site_id"', self.dashboard)
        self.assertIn('name="name"', self.dashboard)
        self.assertIn('name="description"', self.dashboard)
        self.assertIn('method: "POST"', self.dashboard)
        self.assertIn("JSON.stringify", self.dashboard)
        self.assertRegex(self.dashboard, r"loadJSON\(endpoints\.sites,\s*\{")

    def test_read_only_api_loads_retry_transient_startup_errors(self) -> None:
        self.assertIn("const attempts = method === \"GET\" ? 3 : 1;", self.dashboard)
        self.assertIn("response.status >= 500", self.dashboard)
        self.assertIn("await delay(350 * attempt)", self.dashboard)

    def test_dashboard_loads_api_sections_in_stable_order(self) -> None:
        self.assertNotIn("Promise.all", self.dashboard)
        expected_order = (
            "const health = await loadJSON(endpoints.health);",
            "const summary = await loadJSON(endpoints.summary);",
            "const sites = await loadJSON(endpoints.sites);",
            "const agents = await loadJSON(endpoints.agents);",
            "const checkins = await loadJSON(endpoints.checkins);",
            "const assets = await loadJSON(endpoints.assets);",
            "const release = await loadJSON(endpoints.release);",
        )
        previous_index = -1
        for statement in expected_order:
            with self.subTest(statement=statement):
                index = self.dashboard.find(statement)
                self.assertGreater(index, previous_index)
                previous_index = index

    def test_dashboard_avoids_external_assets_and_dangerous_actions(self) -> None:
        self.assertNotRegex(self.dashboard, r"https?://(?!127\.0\.0\.1:8000)")
        self.assertNotIn("script src=", self.dashboard)
        self.assertNotIn("link rel=\"stylesheet\"", self.dashboard)
        forbidden_terms = (
            "credential collection",
            "download and execute",
            "exploit payload",
            "webshell",
            "start scan",
            "run command",
            "execute command",
            "open shell",
            "collect credentials",
        )
        lowered = self.dashboard.lower()
        for term in forbidden_terms:
            with self.subTest(term=term):
                self.assertNotIn(term, lowered)

    def test_dashboard_docs_explain_open_and_validate_flow(self) -> None:
        for path in DOC_FILES:
            with self.subTest(path=path):
                content = path.read_text(encoding="utf-8")
                self.assertIn("http://localhost:8080", content)
                self.assertIn("python scripts/test_control_tower_dashboard.py", content)
                self.assertIn("localhost", content)


if __name__ == "__main__":
    unittest.main()
