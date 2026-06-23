#!/usr/bin/env python3
"""Unit tests for agent release-publication metadata validation."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import validate_agent_release_publication as releasepub


def write_artifact(root: Path, relative: str, contents: bytes = b"artifact") -> tuple[Path, str]:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(contents)
    sha = hashlib.sha256(contents).hexdigest()
    Path(str(path) + ".sha256").write_text(f"{sha}  {path.name}\n", encoding="ascii")
    return path, sha


def write_manifest(root: Path, path: Path, values: dict[str, object]) -> Path:
    manifest = Path(str(path) + ".manifest.json")
    payload = {
        "package_name": "openassetwatch-agent",
        "version": "0.1.0",
        "os": "linux",
        "arch": "amd64",
        "package_type": "deb",
        "package_path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "build_timestamp": "2026-01-01T00:00:00Z",
        "git_commit": "abc123",
        "package_license": "Apache-2.0",
    }
    payload.update(values)
    manifest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return manifest


class ReleasePublicationTests(unittest.TestCase):
    def test_version_normalization_stable(self) -> None:
        value = releasepub.normalize_version("v0.1.0")
        self.assertEqual(value.source_version, "0.1.0")
        self.assertEqual(value.deb_version, "0.1.0")
        self.assertEqual(value.rpm_version, "0.1.0")
        self.assertEqual(value.msi_version, "0.1.0")
        self.assertEqual(value.macos_package_version, "0.1.0")

    def test_version_normalization_release_candidate(self) -> None:
        value = releasepub.normalize_version("v0.1.0-rc.1")
        self.assertEqual(value.source_version, "0.1.0-rc.1")
        self.assertEqual(value.deb_version, "0.1.0~rc.1")
        self.assertEqual(value.rpm_version, "0.1.0_rc.1")
        self.assertEqual(value.msi_version, "0.1.0")

    def test_windows_installer_version_limits(self) -> None:
        releasepub.normalize_version("v255.255.65535")
        for version in ("v256.0.0", "v0.256.0", "v0.0.65536"):
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    releasepub.normalize_version(version)

    def test_validate_release_root_and_write_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            release_root = repo / "dist" / "agent" / "0.1.0"
            package, sha = write_artifact(release_root, "packages/openassetwatch-agent_0.1.0_amd64.deb")
            write_manifest(repo, package, {"package_path": package.relative_to(repo).as_posix(), "sha256": sha})
            with mock.patch.object(releasepub, "get_repo_root", return_value=repo):
                artifacts, warnings = releasepub.validate_release_root(
                    repo,
                    "0.1.0",
                    release_root,
                    {"linux-deb"},
                    "unsigned-release-candidate",
                    require_signed=False,
                )
            self.assertEqual(warnings, [])
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0].release_key, "linux-deb")
            self.assertFalse(artifacts[0].signed)

    def test_checksum_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            release_root = repo / "dist" / "agent" / "0.1.0"
            package, sha = write_artifact(release_root, "packages/openassetwatch-agent_0.1.0_amd64.deb")
            Path(str(package) + ".sha256").write_text("0" * 64 + f"  {package.name}\n", encoding="ascii")
            write_manifest(repo, package, {"package_path": package.relative_to(repo).as_posix(), "sha256": sha})
            with self.assertRaises(ValueError):
                releasepub.validate_release_root(
                    repo,
                    "0.1.0",
                    release_root,
                    {"linux-deb"},
                    "unsigned-release-candidate",
                    require_signed=False,
                )

    def test_missing_license_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            release_root = repo / "dist" / "agent" / "0.1.0"
            package, sha = write_artifact(release_root, "packages/openassetwatch-agent_0.1.0_amd64.deb")
            manifest = write_manifest(repo, package, {"package_path": package.relative_to(repo).as_posix(), "sha256": sha})
            data = json.loads(manifest.read_text(encoding="utf-8"))
            data.pop("package_license")
            manifest.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                releasepub.validate_release_root(
                    repo,
                    "0.1.0",
                    release_root,
                    {"linux-deb"},
                    "unsigned-release-candidate",
                    require_signed=False,
                )

    def test_signed_claim_requires_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            release_root = repo / "dist" / "agent" / "0.1.0"
            package, sha = write_artifact(release_root, "packages/OpenAssetWatchAgent-0.1.0-windows-amd64.msi")
            write_manifest(
                repo,
                package,
                {
                    "os": "windows",
                    "package_type": "msi",
                    "package_path": package.relative_to(repo).as_posix(),
                    "sha256": sha,
                    "signing": {"signed": True},
                },
            )
            with mock.patch.object(releasepub, "get_repo_root", return_value=repo):
                with self.assertRaises(ValueError):
                    releasepub.validate_release_root(
                        repo,
                        "0.1.0",
                        release_root,
                        {"windows-msi"},
                        "signed-production",
                        require_signed=True,
                    )

    def test_notarized_claim_requires_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            release_root = repo / "dist" / "agent" / "0.1.0"
            package, sha = write_artifact(release_root, "packages/OpenAssetWatchAgent-0.1.0-macos-arm64.pkg")
            write_manifest(
                repo,
                package,
                {
                    "os": "darwin",
                    "arch_mode": "arm64",
                    "package_type": "pkg",
                    "path": package.relative_to(repo).as_posix(),
                    "package_path": None,
                    "sha256": sha,
                    "notarized": True,
                },
            )
            with mock.patch.object(releasepub, "get_repo_root", return_value=repo):
                with self.assertRaises(ValueError):
                    releasepub.validate_release_root(
                        repo,
                        "0.1.0",
                        release_root,
                        {"macos-pkg-arm64"},
                        "signed-production",
                        require_signed=False,
                    )

    def test_workflow_policy_rejects_branch_pushes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workflow = Path(tmp) / "agent-release.yml"
            workflow.write_text(
                "\n".join(
                    [
                        "on:",
                        "  pull_request:",
                        "  push:",
                        "    branches:",
                        "      - main",
                        "    tags:",
                        "      - \"v*\"",
                        "jobs:",
                        "  publish:",
                        "    if: github.event_name == 'push' && vars.OAW_AGENT_RELEASE_PUBLICATION_ENABLED == 'true'",
                        "    steps:",
                        "      - run: gh release upload v0.1.0 file",
                    ]
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                releasepub.validate_workflow_policy(workflow)


if __name__ == "__main__":
    unittest.main()
