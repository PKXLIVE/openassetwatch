from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.vendor_catalog import (
    CATALOG_SCHEMA_VERSION,
    MAX_CATALOG_BYTES,
    CatalogPathError,
    CatalogValidationError,
    load_catalog,
    normalize_prefix,
    parse_catalog_bytes,
    replace_catalog,
)


def payload(*, entries=None) -> dict:
    return {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "catalog_version": "test-1",
        "source": {
            "name": "OpenAssetWatch fictional test entries",
            "license": "synthetic-test-data",
        },
        "entries": entries
        if entries is not None
        else [{"prefix": "02:AA:BB", "manufacturer": "Example Print Systems"}],
    }


def encoded(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True).encode("utf-8")


class VendorCatalogTests(unittest.TestCase):
    def test_strict_schema_and_normalized_lookup(self) -> None:
        catalog = parse_catalog_bytes(encoded(payload()))

        self.assertEqual(catalog.catalog_version, "test-1")
        self.assertEqual(catalog.entries[0].prefix, "02AABB")
        self.assertEqual(
            catalog.lookup("02:aa:bb:00:11:22"),
            "Example Print Systems",
        )
        self.assertIsNone(catalog.lookup("192.0.2.1"))

    def test_malformed_and_duplicate_prefixes_are_rejected(self) -> None:
        with self.assertRaises(CatalogValidationError):
            normalize_prefix("../../example")
        with self.assertRaisesRegex(CatalogValidationError, "duplicate"):
            parse_catalog_bytes(
                encoded(
                    payload(
                        entries=[
                            {"prefix": "02:AA:BB", "manufacturer": "Example A"},
                            {"prefix": "02AABB", "manufacturer": "Example B"},
                        ]
                    )
                )
            )

    def test_unknown_fields_and_oversized_catalog_are_rejected(self) -> None:
        unknown = payload()
        unknown["download_url"] = "https://example.invalid/catalog"
        with self.assertRaisesRegex(CatalogValidationError, "unsupported"):
            parse_catalog_bytes(encoded(unknown))
        with self.assertRaisesRegex(CatalogValidationError, "maximum"):
            parse_catalog_bytes(b"{" + b" " * MAX_CATALOG_BYTES + b"}")

    def test_optional_checksum_is_verified(self) -> None:
        value = payload()
        material = json.dumps(
            {
                "schema_version": value["schema_version"],
                "catalog_version": value["catalog_version"],
                "source": value["source"],
                "entries": value["entries"],
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        value["checksum"] = "sha256:" + hashlib.sha256(material).hexdigest()

        parsed = parse_catalog_bytes(encoded(value))
        self.assertEqual(parsed.checksum, value["checksum"])

        value["entries"][0]["manufacturer"] = "Poisoned"
        with self.assertRaisesRegex(CatalogValidationError, "checksum"):
            parse_catalog_bytes(encoded(value))

    def test_atomic_replacement_uses_fixed_target_name(self) -> None:
        with tempfile.TemporaryDirectory() as source_directory, tempfile.TemporaryDirectory() as target_directory:
            source = Path(source_directory) / "reviewed.json"
            source.write_bytes(encoded(payload()))

            if os.name != "posix":
                with self.assertRaisesRegex(CatalogPathError, "POSIX"):
                    replace_catalog(
                        source_path=source.resolve(),
                        target_directory=Path(target_directory).resolve(),
                    )
                return
            target = replace_catalog(
                source_path=source.resolve(),
                target_directory=Path(target_directory).resolve(),
            )

            self.assertEqual(target.name, "vendor-catalog.json")
            self.assertEqual(load_catalog(target).catalog_version, "test-1")
            self.assertFalse(any(path.suffix == ".tmp" for path in target.parent.iterdir()))

    def test_relative_and_symlink_sources_are_rejected(self) -> None:
        with self.assertRaises(CatalogPathError):
            load_catalog(Path("relative-catalog.json"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            link = root / "link.json"
            source.write_bytes(encoded(payload()))
            try:
                os.symlink(source, link)
            except (NotImplementedError, OSError):
                self.skipTest("symlink creation is unavailable")
            with self.assertRaises(CatalogPathError):
                load_catalog(link.resolve(strict=False) if False else link)

    def test_hard_link_source_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.json"
            linked = root / "linked.json"
            source.write_bytes(encoded(payload()))
            try:
                os.link(source, linked)
            except OSError:
                self.skipTest("hard-link creation is unavailable")
            with self.assertRaises(CatalogPathError):
                load_catalog(source)

    @unittest.skipUnless(os.name == "posix", "directory descriptor test requires POSIX")
    def test_target_directory_replacement_during_open_is_rejected(self) -> None:
        import app.vendor_catalog as vendor_catalog

        with tempfile.TemporaryDirectory() as root_directory:
            root = Path(root_directory)
            source = root / "reviewed.json"
            target = root / "trusted"
            moved = root / "trusted-original"
            source.write_bytes(encoded(payload()))
            target.mkdir(mode=0o700)
            original_validate = vendor_catalog._validate_target_directory

            def validate_then_replace(directory: Path):
                validated = original_validate(directory)
                directory.rename(moved)
                directory.mkdir(mode=0o700)
                return validated

            with (
                patch(
                    "app.vendor_catalog._validate_target_directory",
                    side_effect=validate_then_replace,
                ),
                self.assertRaisesRegex(CatalogPathError, "changed during open"),
            ):
                replace_catalog(
                    source_path=source.resolve(),
                    target_directory=target.resolve(),
                )

    @unittest.skipUnless(os.name == "posix", "permission test requires POSIX")
    def test_non_sticky_writable_ancestor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as root_directory:
            root = Path(root_directory)
            source = root / "reviewed.json"
            unsafe_parent = root / "unsafe-parent"
            target = unsafe_parent / "trusted"
            source.write_bytes(encoded(payload()))
            unsafe_parent.mkdir(mode=0o777)
            os.chmod(unsafe_parent, 0o777)
            target.mkdir(mode=0o700)

            with self.assertRaisesRegex(CatalogPathError, "unsafe writable ancestor"):
                replace_catalog(
                    source_path=source.resolve(),
                    target_directory=target.resolve(),
                )


if __name__ == "__main__":
    unittest.main()
