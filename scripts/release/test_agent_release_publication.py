#!/usr/bin/env python3
"""Unit tests for agent release-publication metadata validation."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
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


def write_binary_artifact(repo: Path, release_root: Path) -> Path:
    artifact, sha = write_artifact(release_root, "linux-amd64/oaw-agent", b"binary")
    manifest = artifact.parent / "oaw-agent.manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "artifact_type": "oaw-agent-binary",
                "artifact_name": artifact.name,
                "version": "0.1.0",
                "os": "linux",
                "arch": "amd64",
                "path": artifact.relative_to(repo).as_posix(),
                "sha256": sha,
                "build_timestamp": "2026-01-01T00:00:00Z",
                "git_commit": "abc123",
                "license": "Apache-2.0",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def write_targz_package(repo: Path, release_root: Path) -> Path:
    package = release_root / "packages" / "openassetwatch-agent-0.1.0-linux-amd64.tar.gz"
    package.parent.mkdir(parents=True, exist_ok=True)
    payload = b"OpenAssetWatch agent package notes\n"
    info = tarfile.TarInfo("README.md")
    info.size = len(payload)
    with tarfile.open(package, "w:gz") as archive:
        archive.addfile(info, io.BytesIO(payload))
    sha = hashlib.sha256(package.read_bytes()).hexdigest()
    Path(str(package) + ".sha256").write_text(f"{sha}  {package.name}\n", encoding="ascii")
    return write_manifest(
        repo,
        package,
        {
            "package_type": "tar.gz",
            "source_artifact_path": (release_root / "linux-amd64" / "oaw-agent").relative_to(repo).as_posix(),
            "package_path": package.relative_to(repo).as_posix(),
            "sha256": sha,
        },
    )


def write_rpm_staging_manifest(release_root: Path) -> Path:
    manifest = release_root / "rpm" / "openassetwatch-agent-0.1.0-1.x86_64.manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps(
            {
                "package_name": "openassetwatch-agent",
                "version": "0.1.0",
                "os": "linux",
                "arch": "amd64",
                "package_type": "rpm",
                "rpm_root": "dist/agent/0.1.0/rpm",
                "spec_path": "dist/agent/0.1.0/rpm/SPECS/openassetwatch-agent.spec",
                "buildroot": "dist/agent/0.1.0/rpm/BUILDROOT/openassetwatch-agent-0.1.0-1.x86_64",
                "build_timestamp": "2026-01-01T00:00:00Z",
                "git_commit": "abc123",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def powershell_executable() -> str:
    for name in ("pwsh", "powershell", "powershell.exe"):
        executable = shutil.which(name)
        if executable:
            return executable
    raise RuntimeError("PowerShell is required to test validate_agent_release.ps1.")


def run_release_validator(repo: Path, dist_root: Path) -> dict[str, object]:
    shell = powershell_executable()
    command = [shell, "-NoProfile"]
    if os.name == "nt":
        command.extend(["-ExecutionPolicy", "Bypass"])
    command.extend(
        [
            "-File",
            str(repo / "scripts" / "release" / "validate_agent_release.ps1"),
            "-Version",
            "0.1.0",
            "-DistRoot",
            dist_root.relative_to(repo).as_posix(),
            "-IncludePackages",
        ]
    )
    result = subprocess.run(command, cwd=repo, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        raise AssertionError(f"validate_agent_release.ps1 exited {result.returncode}: {result.stderr}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"validate_agent_release.ps1 did not emit JSON: {result.stdout}") from exc


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

    def test_generic_release_validator_ignores_rpm_staging_directory(self) -> None:
        repo = Path(__file__).resolve().parents[2]
        dist_parent = repo / "dist"
        dist_parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="release-validator-", dir=dist_parent) as tmp:
            dist_root = Path(tmp)
            release_root = dist_root / "agent" / "0.1.0"
            write_binary_artifact(repo, release_root)
            write_targz_package(repo, release_root)
            write_rpm_staging_manifest(release_root)

            summary = run_release_validator(repo, dist_root)

        self.assertTrue(summary["ok"], json.dumps(summary, indent=2))
        check_text = json.dumps(summary["checks"]).replace("\\", "/")
        self.assertIn("linux-amd64", check_text)
        self.assertNotIn("/rpm/", check_text)
        self.assertNotIn("rpm manifest missing fields", check_text)

    def test_release_publication_uses_packages_rpm_manifest_and_ignores_staging_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            release_root = repo / "dist" / "agent" / "0.1.0"
            write_rpm_staging_manifest(release_root)
            package, sha = write_artifact(release_root, "packages/openassetwatch-agent-0.1.0-1.x86_64.rpm")
            package_manifest = write_manifest(
                repo,
                package,
                {
                    "package_type": "rpm",
                    "rpm_arch": "x86_64",
                    "package_path": package.relative_to(repo).as_posix(),
                    "sha256": sha,
                },
            )
            with mock.patch.object(releasepub, "get_repo_root", return_value=repo):
                artifacts, warnings = releasepub.validate_release_root(
                    repo,
                    "0.1.0",
                    release_root,
                    {"linux-rpm"},
                    "unsigned-release-candidate",
                    require_signed=False,
                )

            self.assertEqual(warnings, [])
            self.assertEqual(len(artifacts), 1)
            self.assertEqual(artifacts[0].release_key, "linux-rpm")
            self.assertEqual(artifacts[0].manifest_path, package_manifest.relative_to(repo).as_posix())

    def test_release_publication_requires_real_rpm_package_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            release_root = repo / "dist" / "agent" / "0.1.0"
            write_binary_artifact(repo, release_root)
            write_rpm_staging_manifest(release_root)
            with mock.patch.object(releasepub, "get_repo_root", return_value=repo):
                with self.assertRaisesRegex(ValueError, "missing expected package types: linux-rpm"):
                    releasepub.validate_release_root(
                        repo,
                        "0.1.0",
                        release_root,
                        {"linux-binary-amd64", "linux-rpm"},
                        "unsigned-release-candidate",
                        require_signed=False,
                    )

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
