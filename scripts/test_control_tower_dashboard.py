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
            "/api/v1/ai/status",
            "/api/v1/ai/advisor/query",
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
            "AI Advisor",
            "Ask OpenAssetWatch",
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
            "No demo data loaded yet",
            "Demo Seed Command",
            "Backend Health",
            "Collector Guidance",
            "Collector Detail",
            "Local Inventory Guidance",
            "Structured answer",
            "Provider and data state",
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
            'data-safe-action="review-findings"',
            'data-safe-action="create-site"',
            'data-safe-action="enroll-collector"',
            'data-safe-action="local-inventory"',
            "Authoritative deterministic findings",
            "confidence",
            "evidence freshness",
            "lifecycle state",
            "explainable risk",
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
            "docker compose --profile demo run --rm demo-seed",
        )
        for copy in expected_copy:
            with self.subTest(copy=copy):
                self.assertIn(copy, self.dashboard)

    def test_ai_advisor_showcase_has_scoped_questions_and_structured_output(self) -> None:
        expected_copy = (
            'id="ai-advisor"',
            'id="advisor-form"',
            'id="advisor-question"',
            'maxlength="500"',
            'id="advisor-site"',
            'id="advisor-provider-pill"',
            'id="advisor-fallback-help"',
            'id="advisor-data-state"',
            'id="advisor-confidence"',
            'id="advisor-citation-count"',
            'id="advisor-evidence"',
            'id="advisor-actions"',
            'id="advisor-limitations"',
            'id="advisor-technical-details"',
            "What needs my attention first?",
            "Which site has the highest risk?",
            "Which sensors have stopped checking in?",
            "Compare security posture across sites.",
        )
        for copy in expected_copy:
            with self.subTest(copy=copy):
                self.assertIn(copy, self.dashboard)

    def test_ai_advisor_uses_session_only_token_and_text_safe_rendering(self) -> None:
        self.assertIn('id="advisor-token" type="password" autocomplete="off"', self.dashboard)
        self.assertIn('headers["X-OpenAssetWatch-Admin-Token"] = token', self.dashboard)
        self.assertIn("strong.textContent = item.evidence_type", self.dashboard)
        self.assertIn("summary.textContent = advisorDisplayText(response, item.summary)", self.dashboard)
        self.assertIn("name.textContent = friendlyName(identifier)", self.dashboard)
        self.assertNotIn("localStorage", self.dashboard)
        self.assertNotIn("sessionStorage", self.dashboard)
        self.assertNotIn(".innerHTML", self.dashboard)

    def test_ai_advisor_has_loading_error_and_unsupported_claim_states(self) -> None:
        expected_copy = (
            "Gathering hub evidence",
            "Preparing bounded context",
            "Asking local model",
            "Asking hosted model",
            "Running deterministic advisor",
            "Validating structured response",
            "Reconciling citations",
            'id="advisor-elapsed"',
            "Client-side waiting guide only",
            "AI Advisor request failed safely.",
            "No supporting evidence",
            "Treat this answer as unverified",
            "no action was taken",
            "configured provider mode",
            "Read-only tools",
            "data stays on this machine · no external sharing",
            "OPENASSETWATCH_AI_PROVIDER=demo",
        )
        for copy in expected_copy:
            with self.subTest(copy=copy):
                self.assertIn(copy, self.dashboard)

    def test_ai_advisor_labels_local_identity_and_privacy_without_key_state(self) -> None:
        expected_copy = (
            'id="advisor-local-trust"',
            "Local model",
            "OpenAI-compatible local runtime",
            "Data stays on this machine",
            "No external sharing",
            'id="advisor-local-model"',
            'byId("advisor-local-model").textContent = text(status.model',
        )
        for copy in expected_copy:
            with self.subTest(copy=copy):
                self.assertIn(copy, self.dashboard)
        self.assertNotIn("API key configured", self.dashboard)
        self.assertNotIn("API key missing", self.dashboard)

    def test_ai_advisor_marks_model_confidence_uncalibrated_and_counts_validated_citations(self) -> None:
        expected_copy = (
            "Model-reported confidence",
            "Uncalibrated",
            "Evidence-backed answer",
            "OpenAssetWatch validates cited evidence identifiers",
            "interpretation, confidence, and recommendations remain advisory",
            "validated citation",
            "Evidence confidence:",
        )
        for copy in expected_copy:
            with self.subTest(copy=copy):
                self.assertIn(copy, self.dashboard)
        self.assertNotIn("}% confidence`", self.dashboard)
        self.assertNotIn("100% confidence", self.dashboard)

    def test_ai_advisor_shows_friendly_names_before_collapsed_technical_ids(self) -> None:
        expected_code = (
            "function advisorSiteName",
            "function advisorSensorName",
            "function advisorAssetName",
            "function advisorDisplayText",
            "function advisorDisplayAnswer",
            "sensor.display_name || sensor.hostname",
            "Unknown ${siteName} Device",
            "option.textContent = text(site.name, site.site_id)",
            "renderAdvisorEntities(response)",
            'byId("advisor-answer").textContent = advisorDisplayAnswer(response)',
            "summary.textContent = advisorDisplayText(response, item.summary)",
            "response.recommended_actions.map(value => advisorDisplayText(response, value))",
            'id="advisor-run-id"',
            'id="advisor-site-ids"',
            'id="advisor-sensor-ids"',
            'id="advisor-asset-ids"',
            'id="advisor-evidence-ids"',
        )
        for code in expected_code:
            with self.subTest(code=code):
                self.assertIn(code, self.dashboard)
        self.assertLess(self.dashboard.index("Affected site, sensor, and asset"), self.dashboard.index("Technical details"))
        self.assertIn('<details id="advisor-technical-details"', self.dashboard)
        self.assertNotIn('<details id="advisor-technical-details" open', self.dashboard)

    def test_ai_advisor_distinguishes_local_demo_and_hosted_trust_states(self) -> None:
        expected_copy = (
            'id="advisor-local-trust"',
            'id="advisor-demo-trust"',
            'id="advisor-hosted-trust"',
            "Deterministic demo",
            "Bounded backend logic",
            "Hosted external model",
            "External sharing enabled",
            "Bounded normalized evidence may leave this machine.",
            'status.mode !== "local"',
            'status.mode !== "demo"',
            'status.mode !== "external"',
        )
        for copy in expected_copy:
            with self.subTest(copy=copy):
                self.assertIn(copy, self.dashboard)

    def test_ai_advisor_preserves_mobile_stack_and_collapsible_details(self) -> None:
        expected_copy = (
            'data-mobile-stack="advisor"',
            ".advisor-trust-strip",
            ".advisor-entity-grid",
            ".advisor-progress-line",
            "grid-template-columns: 1fr;",
            ".advisor-technical summary",
            "#ai-advisor .panel-header",
            "white-space: normal;",
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
            "data-dashboard-extra",
            "byId(\"refresh\").addEventListener(\"click\", refresh)",
            "setupSafeActions()",
            "copyDemoSeedCommand",
            "navigator.clipboard.writeText(DEMO_SEED_COMMAND)",
            "const {health, summary, sites, agents, checkins, assets, findings, risk, release} = state.data;",
            "return {health, summary, sites, agents, checkins, assets, risk, release",
            "navigateTo(\"findings\")",
            "navigateTo(\"sites\", \"site-id\")",
            "navigateTo(\"collectors\")",
            "navigateTo(\"evidence\")",
        )
        for code in expected_code:
            with self.subTest(code=code):
                self.assertIn(code, self.dashboard)

    def test_findings_view_uses_persisted_deterministic_authority(self) -> None:
        expected_code = (
            'findings: "/api/v1/findings?status=active&limit=200"',
            'risk: "/api/v1/risk/summary?limit=200"',
            "deterministic finding",
            "Scores are deterministic; AI commentary remains advisory.",
            "finding.finding_id",
            "finding.evidence_freshness",
            "Evidence and score details",
            "finding.recommendation",
            "finding.first_seen_at",
            "finding.risk.factors",
        )
        for code in expected_code:
            with self.subTest(code=code):
                self.assertIn(code, self.dashboard)
        self.assertNotIn("function deriveFindings", self.dashboard)

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
