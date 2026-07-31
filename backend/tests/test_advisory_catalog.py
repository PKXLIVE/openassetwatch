from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from app.advisory_catalog import (
    MAX_CATALOG_BYTES,
    CatalogValidationError,
    load_catalog,
    parse_catalog_bytes,
)


CATALOG_PATH = (
    Path(__file__).resolve().parents[1]
    / "catalogs"
    / "synthetic-advisory-catalog.json"
)


class AdvisoryCatalogTests(unittest.TestCase):
    def catalog_payload(self) -> dict:
        return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))

    def test_synthetic_catalog_is_strict_bounded_and_licensed(self) -> None:
        catalog, checksum = load_catalog(CATALOG_PATH)
        self.assertEqual(catalog.schema_version, "oaw.advisory-catalog.v1")
        self.assertEqual(len(catalog.advisories), 4)
        self.assertEqual(catalog.source.license, "Apache-2.0")
        self.assertEqual(len(checksum), 64)
        self.assertIn("Fictional", catalog.source.provenance)

    def test_unknown_fields_and_duplicate_ids_are_rejected(self) -> None:
        payload = self.catalog_payload()
        payload["runtime_url"] = "https://example.invalid/feed"
        with self.assertRaises(CatalogValidationError):
            parse_catalog_bytes(json.dumps(payload).encode())

        payload = self.catalog_payload()
        payload["advisories"].append(payload["advisories"][0])
        with self.assertRaises(CatalogValidationError):
            parse_catalog_bytes(json.dumps(payload).encode())

    def test_duplicate_alias_across_records_is_rejected(self) -> None:
        payload = self.catalog_payload()
        payload["advisories"][1]["aliases"] = payload["advisories"][0][
            "aliases"
        ]
        with self.assertRaises(CatalogValidationError):
            parse_catalog_bytes(json.dumps(payload).encode())

    def test_case_only_duplicate_advisory_ids_are_rejected(self) -> None:
        payload = self.catalog_payload()
        duplicate = json.loads(json.dumps(payload["advisories"][0]))
        duplicate["id"] = duplicate["id"].casefold()
        payload["advisories"].append(duplicate)
        with self.assertRaises(CatalogValidationError):
            parse_catalog_bytes(json.dumps(payload).encode())

    def test_reference_credentials_and_non_http_schemes_are_rejected(self) -> None:
        for value in (
            "https://user:pass@example.invalid/advisory",
            "file:///private/advisory.json",
            "ftp://example.invalid/advisory",
        ):
            payload = self.catalog_payload()
            payload["advisories"][0]["references"][0]["url"] = value
            with self.subTest(value=value):
                with self.assertRaises(CatalogValidationError):
                    parse_catalog_bytes(json.dumps(payload).encode())

    def test_oversized_catalog_is_rejected_before_json_parse(self) -> None:
        with self.assertRaisesRegex(CatalogValidationError, "8 MiB"):
            parse_catalog_bytes(b"{" + b" " * MAX_CATALOG_BYTES)

    def test_hard_link_catalog_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "catalog.json"
            linked = Path(directory) / "linked.json"
            source.write_bytes(CATALOG_PATH.read_bytes())
            os.link(source, linked)
            with self.assertRaisesRegex(
                CatalogValidationError,
                "exactly one link",
            ):
                load_catalog(linked)

    def test_relative_nonregular_and_symlink_paths_are_rejected(self) -> None:
        with self.assertRaisesRegex(CatalogValidationError, "absolute"):
            load_catalog(Path("catalog.json"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(CatalogValidationError, "regular"):
                load_catalog(root)
            source = root / "catalog.json"
            linked = root / "catalog-link.json"
            source.write_bytes(CATALOG_PATH.read_bytes())
            try:
                linked.symlink_to(source)
            except OSError as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")
            with self.assertRaisesRegex(CatalogValidationError, "regular"):
                load_catalog(linked)

    def test_ranges_require_reviewed_identity_and_boundaries(self) -> None:
        payload = self.catalog_payload()
        affected = payload["advisories"][3]["affected"][0]
        affected.pop("vendor")
        with self.assertRaises(CatalogValidationError):
            parse_catalog_bytes(json.dumps(payload).encode())

        payload = self.catalog_payload()
        payload["advisories"][0]["affected"][0]["ranges"] = [{}]
        with self.assertRaises(CatalogValidationError):
            parse_catalog_bytes(json.dumps(payload).encode())

        payload = self.catalog_payload()
        payload["advisories"][0]["affected"][0]["ranges"] = [
            {"introduced": "2.0.0", "fixed": "1.0.0"}
        ]
        with self.assertRaises(CatalogValidationError):
            parse_catalog_bytes(json.dumps(payload).encode())

        payload = self.catalog_payload()
        payload["advisories"][1]["affected"][0]["ranges"] = [
            {"introduced": "1.0.0-alpha.1", "fixed": "1.0.0-alpha"}
        ]
        with self.assertRaises(CatalogValidationError):
            parse_catalog_bytes(json.dumps(payload).encode())


if __name__ == "__main__":
    unittest.main()
