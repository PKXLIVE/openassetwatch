from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "advisory-mirror-publish.yml"


class AdvisoryMirrorWorkflowPolicyTests(unittest.TestCase):
    def test_workflow_is_gated_pinned_and_keeps_pull_requests_offline(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("pull_request_target", text)
        self.assertIn("vars.OPENASSETWATCH_ADVISORY_MIRROR_PUBLISH_ENABLED == 'true'", text)
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("environment: advisory-mirror-production", text)
        self.assertIn("concurrency:", text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("--retain-prior 3", text)
        self.assertIn("--sequence-floor \"$OAW_SEQUENCE_FLOOR\"", text)
        self.assertIn("OPENASSETWATCH_ADVISORY_MIRROR_BOOTSTRAP_ENABLED", text)
        self.assertIn("one-time bootstrap enable variable", text)
        self.assertIn("Restore trusted publication checkpoint", text)
        self.assertIn("build_advisory_mirror.py continuity", text)
        self.assertIn("date -u +%s%N", text)
        self.assertIn("Save trusted publication checkpoint", text)
        self.assertIn("permissions:\n  contents: read", text)
        self.assertIn("pages: write", text)
        self.assertIn("id-token: write", text)

        uses = re.findall(r"uses:\s+([^\s#]+)", text)
        self.assertTrue(uses)
        for action in uses:
            self.assertRegex(action, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")

        offline = text.split("  offline-validation:", 1)[1].split("  build-publication:", 1)[0]
        self.assertIn("if: github.event_name == 'pull_request'", offline)
        self.assertIn("demo_advisory_mirror.py", offline)
        self.assertIn("working-directory: backend", offline)
        self.assertIn("tests.test_advisory_mirror", offline)
        self.assertIn("tests.test_advisory_mirror_demo", offline)
        self.assertIn("tests.test_advisory_mirror_workflow", offline)
        self.assertNotIn("backend.tests.test_advisory_mirror", offline)
        self.assertNotIn("secrets.", offline)
        self.assertNotIn("publish_osv_pypi_advisories.py sync", offline)
        self.assertNotIn("deploy-pages", offline)
        self.assertNotIn("actions/cache", offline)

    def test_signing_secret_is_scoped_only_to_first_party_signing_steps(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        secret_references = (
            "secrets.OPENASSETWATCH_ADVISORY_BUNDLE_SIGNING_KEY_BASE64",
            "secrets.OPENASSETWATCH_ADVISORY_INDEX_SIGNING_KEY_BASE64",
        )
        self.assertTrue(all(text.count(value) == 1 for value in secret_references))
        publication_job_header = text.split("  build-publication:", 1)[1].split("    steps:", 1)[0]
        self.assertTrue(all(value not in publication_job_header for value in secret_references))
        self.assertNotIn("--signing-key-env", text)
        self.assertEqual(text.count("key_file=\"$(mktemp"), 2)
        self.assertEqual(text.count("chmod 600 \"$key_file\""), 2)
        self.assertEqual(text.count("trap cleanup_key EXIT HUP INT TERM"), 2)
        self.assertEqual(text.count("trap - EXIT HUP INT TERM"), 2)
        self.assertIn("unset OPENASSETWATCH_OSV_PYPI_SIGNING_KEY", text)
        self.assertIn("unset OPENASSETWATCH_ADVISORY_INDEX_SIGNING_KEY", text)
        self.assertEqual(text.count("--signing-key-file \"$key_file\""), 2)
        upload_block = text.split("Upload static Pages artifact", 1)[1]
        self.assertTrue(all(value not in upload_block for value in secret_references))


if __name__ == "__main__":
    unittest.main()
