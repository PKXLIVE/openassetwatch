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
            "Environment Overview",
            "Total assets",
            "Unknown assets",
            "Unmanaged assets",
            "Active collectors",
            "Stale collectors",
            "Findings requiring review",
            "Evidence records",
            "Operating Systems / Platforms",
            "Site Health",
            "Unknown &amp; Unmanaged Assets",
            "Top Assets Needing Review",
            "Recently Discovered Assets",
            "Stale Collectors / Sensors",
            "Site Cards",
            "Getting Started",
            "Create Site",
            "Asset Mix By Type",
            "Collector Health",
            "Recent Check-ins",
            "Recent Evidence",
            "Top Findings / Attention Items",
            "Sites Overview",
            "Catalog",
            "Detailed Inventory",
            "Asset Inventory",
            "Asset Detail",
            "Endpoint Agents",
            "Passive Sensors",
            "Evidence Source",
            "Policy Guardrails",
            "Recommended Next Steps",
            "Release Status",
            "No demo data loaded yet",
            "Demo Seed Command",
            "Backend Health",
            "Collector Guidance",
            "Collector Detail",
            "Local Inventory Guidance",
        )
        for section in required_sections:
            with self.subTest(section=section):
                self.assertIn(section, self.dashboard)

    def test_dashboard_version_marks_visual_composition_pass(self) -> None:
        self.assertIn('const DASHBOARD_VERSION = "control-tower-visual-composition-v5";', self.dashboard)
        self.assertIn("control-tower-visual-composition-v5", self.dashboard)

    def test_dashboard_overview_command_center_sections_are_present(self) -> None:
        expected_markup = (
            'class="view-section dashboard-canvas"',
            'class="view-section asset-canvas"',
            'id="dashboard" class="view-section dashboard-canvas" data-canvas-contract="full"',
            'id="assets" class="view-section asset-canvas" data-canvas-contract="full"',
            'aria-label="Environment summary"',
            'id="environment-summary"',
            'id="overview-last-refreshed"',
            'id="overview-data-posture"',
            'id="findings-review-count"',
            'id="site-count"',
            'id="device-type-mix"',
            'id="device-type-mix-count"',
            'id="platform-mix"',
            'id="platform-mix-count"',
            'id="site-health"',
            'id="site-health-count"',
            'id="review-assets"',
            'id="review-assets-count"',
            'id="assets-needing-review"',
            'id="assets-review-loaded"',
            'id="recent-assets"',
            'id="recent-assets-loaded"',
            'id="stale-collectors-panel"',
            'id="stale-collectors-loaded"',
            'class="topbar-controls"',
            'id="global-dashboard-search"',
            'class="select-like"',
            'class="dashboard-grid"',
            'span-12',
        )
        for markup in expected_markup:
            with self.subTest(markup=markup):
                self.assertIn(markup, self.dashboard)

    def test_dashboard_and_assets_use_full_canvas_layout(self) -> None:
        self.assertIn("max-width: none;", self.dashboard)
        self.assertIn(".dashboard-canvas,\n    .asset-canvas", self.dashboard)
        self.assertIn(".dashboard-grid {", self.dashboard)
        self.assertIn("grid-template-columns: repeat(12, minmax(0, 1fr));", self.dashboard)
        self.assertIn("grid-template-columns: repeat(8, minmax(8.5rem, 1fr));", self.dashboard)
        self.assertNotIn("max-width: 1560px", self.dashboard)
        self.assertNotRegex(self.dashboard, r"\.page\s*\{[^}]*margin:\s*0 auto")
        full_canvas_rule = re.search(r"\.dashboard-canvas,\s*\.asset-canvas\s*\{(?P<body>[^}]+)\}", self.dashboard)
        self.assertIsNotNone(full_canvas_rule)
        full_canvas_body = full_canvas_rule.group("body") if full_canvas_rule else ""
        for declaration in (
            "width: 100%;",
            "min-width: 0;",
            "max-width: none;",
            "justify-self: stretch;",
        ):
            with self.subTest(declaration=declaration):
                self.assertIn(declaration, full_canvas_body)

    def test_chart_panels_use_filled_internal_visual_layouts(self) -> None:
        self.assertIn("grid-template-columns: minmax(13.5rem, 1.05fr) minmax(11.5rem, 0.95fr);", self.dashboard)
        self.assertIn("justify-content: stretch;", self.dashboard)
        self.assertIn("max-width: none;", self.dashboard)
        self.assertIn("className = \"chart-sidecar\"", self.dashboard)
        self.assertIn("className = \"chart-sidecar-summary\"", self.dashboard)
        self.assertIn('chart.className = "chart-shell bar-chart-shell"', self.dashboard)
        self.assertIn("viewBox: `0 0 640", self.dashboard)
        self.assertIn('"font-size": 16', self.dashboard)
        self.assertNotIn("max-width: min(28rem, 100%)", self.dashboard)
        self.assertNotIn("grid-template-columns: 1fr;\n      gap: clamp(1rem, 1vw, 1.35rem);\n      align-items: center;", self.dashboard)

    def test_setup_and_release_content_live_in_settings_not_dashboard(self) -> None:
        dashboard_section = self.dashboard.split('<section id="dashboard"', 1)[1].split('<section id="assets"', 1)[0]
        settings_section = self.dashboard.split('<section id="settings"', 1)[1].split("</main>", 1)[0]
        self.assertNotIn("Getting Started", dashboard_section)
        self.assertNotIn("Release Status", dashboard_section)
        self.assertNotIn('id="demo-seed-cta"', dashboard_section)
        self.assertIn("Getting Started", settings_section)
        self.assertIn("Release Status", settings_section)
        self.assertIn('id="demo-seed-cta"', settings_section)
        self.assertIn("Demo Seed Command", settings_section)
        self.assertIn("Backend Health", settings_section)
        self.assertIn("API URL", settings_section)
        self.assertIn("Release Metadata", settings_section)
        self.assertIn("Copy command", settings_section)

    def test_dashboard_command_center_inventory_is_present(self) -> None:
        dashboard_section = self.dashboard.split('<section id="dashboard"', 1)[1].split('<section id="assets"', 1)[0]
        self.assertEqual(dashboard_section.count('class="metric"'), 8)
        expected_dashboard_targets = (
            'id="asset-mix"',
            'id="device-type-mix"',
            'id="platform-mix"',
            'id="collector-health"',
            'id="site-health"',
            'id="top-findings"',
            'id="attention-banner" class="attention-banner span-12"',
            'id="review-assets"',
            'id="checkins-panel"',
            'id="recent-evidence"',
        )
        for target in expected_dashboard_targets:
            with self.subTest(target=target):
                self.assertIn(target, dashboard_section)

    def test_asset_catalog_grouped_inventory_sections_are_present(self) -> None:
        expected_groups = (
            '{id: "device-type", title: "Device Type / Category"',
            '{id: "site", title: "Site"',
            '{id: "platform", title: "Platform / OS"',
            '{id: "source", title: "Evidence Source / Data Source"',
            '{id: "attention", title: "Attention State"',
        )
        for group in expected_groups:
            with self.subTest(group=group):
                self.assertIn(group, self.dashboard)

    def test_asset_catalog_summary_stats_are_present(self) -> None:
        expected_stats = (
            'class="asset-summary-stats"',
            'id="asset-summary-total"',
            'id="asset-summary-unknown"',
            'id="asset-summary-unmanaged"',
            'id="asset-summary-missing-tooling"',
            'id="asset-summary-stale"',
            'byId("asset-summary-total").textContent = data.assets.length',
            'byId("asset-summary-unknown").textContent = data.unknownAssets.length',
            'byId("asset-summary-unmanaged").textContent = data.unmanagedAssets.length',
            'byId("asset-summary-missing-tooling").textContent = data.assets.filter(isMissingTooling).length',
            'byId("asset-summary-stale").textContent = data.assets.filter(isStaleAsset).length',
        )
        for stat in expected_stats:
            with self.subTest(stat=stat):
                self.assertIn(stat, self.dashboard)

    def test_dashboard_overview_visual_helpers_are_client_side(self) -> None:
        expected_code = (
            "function renderEnvironmentSummary",
            "function renderDeviceTypeMix",
            "function renderPlatformMix",
            "function renderSiteHealth",
            "function renderOverviewPreviews",
            "function renderDonutChart",
            "function renderBarChart",
            "function renderLegend",
            "function renderAttentionSummaryVisual",
            "function assetCatalogIcon",
            "function addIconShape",
            "function platformGroup",
            "function siteBuckets",
            "function compactRow",
            "function assetCatalogSections",
            "function drilldownAssetGroup",
            "document.createElementNS(SVG_NS",
            "classList.add(\"svg-chart\")",
            "classList.add(\"svg-bar-chart\")",
            "className = \"donut\"",
            "className = \"attention-summary-visual\"",
            "className = \"attention-summary-row\"",
            "local synthetic demo data",
            "not measured production performance",
        )
        for code in expected_code:
            with self.subTest(code=code):
                self.assertIn(code, self.dashboard)

    def test_dashboard_contains_asset_filters_and_attention_copy(self) -> None:
        expected_copy = (
            'id="asset-search"',
            'data-filter="unknown"',
            'data-filter="iot"',
            'data-filter="mobile"',
            'data-filter="infrastructure"',
            'data-filter="workstation"',
            'data-filter="stale"',
            'data-filter="missing-tooling"',
            'data-asset-mode="catalog"',
            'data-asset-mode="inventory"',
            'id="asset-catalog"',
            'id="asset-inventory-wrap"',
            'id="asset-drilldown-status"',
            'id="asset-breadcrumb"',
            'id="back-to-catalog"',
            "dataset.catalogSection",
            'catalog-section-grid',
            "Device Type / Category",
            "Evidence Source / Data Source",
            "Attention State",
            'className = "catalog-icon-tile"',
            'className = "catalog-card-copy"',
            'className = "catalog-action"',
            'action.textContent = "View Assets"',
            "white-space: nowrap",
            'data-safe-action="review-findings"',
            'data-safe-action="create-site"',
            'data-safe-action="enroll-collector"',
            'data-safe-action="local-inventory"',
            "Unknown device observed",
            "Unmanaged IoT device",
            "Missing security tooling sample",
            "Stale collector sample",
            "Printer inventory review",
        )
        for copy in expected_copy:
            with self.subTest(copy=copy):
                self.assertIn(copy, self.dashboard)

    def test_asset_catalog_modes_and_drilldowns_are_client_side(self) -> None:
        expected_code = (
            'assetMode: "catalog"',
            'assetDrilldown: null',
            "function assetCategoryDefinitions",
            "function deviceTypeDefinitions",
            "function assetCatalogSections",
            "function activeAssetScopeLabel",
            "function filteredAssets",
            "function renderAssetCatalog",
            "function setAssetMode",
            "function setAssetFilter",
            "function drilldownAssets",
            "function drilldownAssetGroup",
            "function resetAssetCatalog",
            "function drilldownToAsset",
            "function setupGlobalControls",
            ".asset-layout.catalog-mode",
            ".asset-layout.catalog-mode .detail-panel",
            'state.assetMode = "inventory"',
            'state.assetDrilldown = group.scope || null',
            'assetLayout.classList.toggle("catalog-mode", state.assetMode === "catalog")',
            'assetLayout.classList.toggle("inventory-mode", state.assetMode === "inventory")',
            'button.addEventListener("click", () => setAssetMode(button.dataset.assetMode))',
            'button.addEventListener("click", () => setAssetFilter(button.dataset.filter))',
            'byId("back-to-catalog").addEventListener("click", resetAssetCatalog)',
            'navigateTo("assets")',
            'state.assetFilter = filter || "all"',
            'state.assetMode = mode === "inventory" ? "inventory" : "catalog"',
            'state.assetSearch = search || ""',
        )
        for code in expected_code:
            with self.subTest(code=code):
                self.assertIn(code, self.dashboard)

    def test_dashboard_documents_safe_read_only_policy_states(self) -> None:
        expected_copy = (
            "Passive-first collection",
            "Active checks disabled",
            "SNMP disabled",
            "Packet capture disabled",
            "Remote commands unavailable",
            "Release metadata only",
            "docker compose --profile demo run --rm demo-seed",
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

    def test_navigation_and_controls_are_wired_to_safe_client_side_behavior(self) -> None:
        expected_code = (
            "const VIEW_IDS =",
            "function normalizeView",
            "function setNavActive",
            "function navigateTo",
            "window.addEventListener(\"hashchange\"",
            "section.hidden = section.id !== activeId",
            "byId(\"refresh\").addEventListener(\"click\", refresh)",
            "setupSafeActions()",
            "copyDemoSeedCommand",
            "navigator.clipboard.writeText(DEMO_SEED_COMMAND)",
            "const {health, summary, sites, agents, checkins, assets, release} = state.data;",
            "return {health, summary, sites, agents, checkins, assets, release",
            "navigateTo(\"findings\")",
            "navigateTo(\"sites\", \"site-id\")",
            "navigateTo(\"collectors\")",
            "navigateTo(\"evidence\")",
        )
        for code in expected_code:
            with self.subTest(code=code):
                self.assertIn(code, self.dashboard)

    def test_asset_and_collector_rows_update_read_only_detail(self) -> None:
        expected_code = (
            "row.addEventListener(\"click\", () => selectAsset(asset.asset_id))",
            "row.addEventListener(\"click\", () => selectCollector(agent.agent_id))",
            "function renderAssetDetail",
            "function renderCollectorDetail",
            'id="asset-detail"',
            'id="collector-detail"',
        )
        for code in expected_code:
            with self.subTest(code=code):
                self.assertIn(code, self.dashboard)

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
