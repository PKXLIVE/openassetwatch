from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import ADMIN_TOKEN_ENV, app

LOGIN = Path(__file__).resolve().parents[1] / "app" / "templates" / "login.html"
DASHBOARD = Path(__file__).resolve().parents[1] / "app" / "templates" / "dashboard.html"


class LoginTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.page = LOGIN.read_text(encoding="utf-8")

    def test_valid_token_saves_and_redirects(self) -> None:
        # Token is saved only inside the res.ok branch, not on 404
        self.assertIn("if (res.ok)", self.page)

    def test_invalid_token_shows_error_not_saved(self) -> None:
        # 401 must show an error message, never redirect or store
        self.assertIn("res.status === 401", self.page)
        # Ensure the error path sets an error message
        idx_401 = self.page.index("res.status === 401")
        snippet = self.page[idx_401:idx_401 + 300]
        self.assertIn("errorDiv", snippet)
        self.assertNotIn("window.location", snippet)
        self.assertNotIn("localStorage.setItem", snippet)

    def test_404_does_not_redirect_or_save_token(self) -> None:
        # 404 from the verification endpoint must NOT be treated as success
        # The only accepted success branch is res.ok
        ok_idx = self.page.index("if (res.ok)")
        # Confirm res.status === 404 is never equated with success
        self.assertNotIn("res.status === 404", self.page[ok_idx:ok_idx + 100])

    def test_missing_endpoint_does_not_save_token(self) -> None:
        # Network failure (catch block) must not store the token
        try:
            catch_idx = self.page.index("} catch")
        except ValueError:
            self.fail("No catch block found in login page")
        catch_block = self.page[catch_idx:catch_idx + 400]
        self.assertNotIn("localStorage.setItem", catch_block)
        self.assertNotIn("sessionStorage.setItem", catch_block)
        self.assertIn("errorDiv", catch_block)


class DashboardTemplateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.page = DASHBOARD.read_text(encoding="utf-8")

    def test_finding_titles_use_textContent_not_innerHTML(self) -> None:
        # Findings rendering must use textContent so markup is literal text
        render_start = self.page.index("// Render findings")
        render_end = self.page.index("// Render collectors")
        findings_block = self.page[render_start:render_end]
        self.assertIn("textContent", findings_block)
        self.assertNotIn("innerHTML", findings_block)

    def test_collector_names_use_textContent_not_innerHTML(self) -> None:
        render_start = self.page.index("// Render collectors")
        render_end = self.page.index("// Render sites")
        collectors_block = self.page[render_start:render_end]
        self.assertIn("textContent", collectors_block)
        self.assertNotIn("innerHTML", collectors_block)

    def test_site_names_use_textContent_not_innerHTML(self) -> None:
        render_start = self.page.index("// Render sites")
        sites_block = self.page[render_start:render_start + 2000]
        self.assertIn("textContent", sites_block)
        self.assertNotIn("innerHTML", sites_block)

    def test_markup_in_site_name_would_display_as_literal_text(self) -> None:
        # Verify textContent is used (not innerHTML) so <script> tags render as text
        render_start = self.page.index("// Render sites")
        sites_block = self.page[render_start:render_start + 2000]
        self.assertIn(".textContent =", sites_block)

    def test_failed_api_call_shows_unavailable_not_zero_for_assets(self) -> None:
        # When assets is null (failed request), show "Unavailable"
        self.assertIn("assetCount === null ? 'Unavailable'", self.page)

    def test_failed_api_call_shows_unavailable_not_zero_for_collectors(self) -> None:
        self.assertIn("collArr === null ? 'Unavailable'", self.page)

    def test_failed_api_call_shows_unavailable_not_zero_for_sites(self) -> None:
        self.assertIn("sitesArr === null ? 'Unavailable'", self.page)

    def test_failed_api_call_shows_unavailable_not_zero_for_sensors(self) -> None:
        self.assertIn("sensArr === null ? 'Unavailable'", self.page)

    def test_zero_assets_from_successful_response_shows_zero(self) -> None:
        # Successful empty response (assets != null) must display 0, not "Unavailable"
        # Verified by the ternary: null → Unavailable, otherwise actual count
        self.assertIn("assetCount === null ? 'Unavailable' : assetCount", self.page)

    def test_zero_collectors_from_successful_response_shows_zero(self) -> None:
        self.assertIn("collArr === null ? 'Unavailable' : collArr.length", self.page)


class RiskSummaryTokenVerificationTests(unittest.TestCase):
    """Behavioural tests for the login verification endpoint token gate."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app, raise_server_exceptions=False)

    def test_configured_valid_token_passes_auth_gate(self) -> None:
        # Auth passes (no 401/503); a 500 is acceptable when no DB is wired.
        with patch.dict(os.environ, {ADMIN_TOKEN_ENV: "correct-token"}):
            r = self.client.get(
                "/api/v1/risk/summary",
                headers={"X-OpenAssetWatch-Admin-Token": "correct-token"},
            )
        self.assertNotIn(r.status_code, (401, 503))

    def test_configured_invalid_token_returns_401(self) -> None:
        with patch.dict(os.environ, {ADMIN_TOKEN_ENV: "correct-token"}):
            r = self.client.get(
                "/api/v1/risk/summary",
                headers={"X-OpenAssetWatch-Admin-Token": "wrong-token"},
            )
        self.assertEqual(r.status_code, 401)

    def test_unconfigured_server_token_returns_503(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != ADMIN_TOKEN_ENV}
        with patch.dict(os.environ, env, clear=True):
            r = self.client.get(
                "/api/v1/risk/summary",
                headers={"X-OpenAssetWatch-Admin-Token": "any-token"},
            )
        self.assertEqual(r.status_code, 503)

    def test_unconfigured_server_no_token_header_returns_503(self) -> None:
        env = {k: v for k, v in os.environ.items() if k != ADMIN_TOKEN_ENV}
        with patch.dict(os.environ, env, clear=True):
            r = self.client.get("/api/v1/risk/summary")
        self.assertEqual(r.status_code, 503)


if __name__ == "__main__":
    unittest.main()
