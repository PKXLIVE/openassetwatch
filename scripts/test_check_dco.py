#!/usr/bin/env python3
"""Unit tests for the repository-local DCO validator."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_dco import CommitRecord, signoffs, validate  # noqa: E402


class DCOValidationTests(unittest.TestCase):
    def record(
        self,
        message: str,
        *,
        name: str = "Example Contributor",
        email: str = "contributor@example.com",
    ) -> CommitRecord:
        return CommitRecord(
            sha="a" * 40,
            author_name=name,
            author_email=email,
            message=message,
        )

    def test_accepts_matching_signoff(self) -> None:
        valid, reason = validate(
            self.record(
                "feat: example\n\n"
                "Signed-off-by: Example Contributor <contributor@example.com>\n"
            )
        )
        self.assertTrue(valid)
        self.assertEqual(reason, "valid sign-off")

    def test_email_match_is_case_insensitive(self) -> None:
        valid, _ = validate(
            self.record(
                "docs: example\n\n"
                "Signed-off-by: Example Contributor <Contributor@Example.com>\n"
            )
        )
        self.assertTrue(valid)

    def test_rejects_missing_signoff(self) -> None:
        valid, reason = validate(self.record("fix: unsigned commit\n"))
        self.assertFalse(valid)
        self.assertEqual(reason, "missing Signed-off-by trailer")

    def test_rejects_mismatched_email(self) -> None:
        valid, reason = validate(
            self.record(
                "fix: mismatched signoff\n\n"
                "Signed-off-by: Other Person <other@example.com>\n"
            )
        )
        self.assertFalse(valid)
        self.assertIn("does not match commit author email", reason)

    def test_rejects_malformed_trailer(self) -> None:
        self.assertEqual(
            signoffs("Signed-off-by: Example Contributor contributor@example.com\n"),
            [],
        )

    def test_exempts_automation_accounts(self) -> None:
        valid, reason = validate(
            self.record(
                "build: automated update\n",
                name="dependency-update[bot]",
                email="123+dependency-update[bot]@users.noreply.github.com",
            )
        )
        self.assertTrue(valid)
        self.assertEqual(reason, "automation author exempt")


if __name__ == "__main__":
    unittest.main()
