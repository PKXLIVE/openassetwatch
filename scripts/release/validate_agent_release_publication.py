#!/usr/bin/env python3
"""Validate OpenAssetWatch agent release-publication metadata.

This script intentionally validates metadata and local artifacts only. It does
not sign, notarize, upload, install, or publish anything by itself.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from release_common import get_repo_root, is_inside, read_json, resolve_repo_path, sha256_file, to_repo_relative


PROJECT_LICENSE = "Apache-2.0"
VERSION_RE = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?P<suffix>[-+._A-Za-z0-9]*)?$")
SECRET_RE = re.compile(
    r"(password|passwd|token|secret|credential|api[_-]?key|private[_-]?key|p12|\.pem)",
    re.IGNORECASE,
)
RELEASE_BINARY_DIR_RE = re.compile(r"^(linux|windows|darwin)-[A-Za-z0-9]+$")
REQUIRED_RELEASE_ARTIFACT_FIELDS = (
    "artifact_filename",
    "package_type",
    "os",
    "architecture",
    "version",
    "git_commit",
    "build_timestamp",
    "sha256",
    "license",
    "signed",
    "notarized",
    "sbom_path",
    "provenance_path",
)


@dataclass(frozen=True)
class NormalizedVersion:
    tag: str
    source_version: str
    deb_version: str
    rpm_version: str
    msi_version: str
    macos_package_version: str


@dataclass
class ReleaseArtifact:
    artifact_filename: str
    package_type: str
    os: str
    architecture: str
    version: str
    git_commit: str
    build_timestamp: str
    sha256: str
    license: str
    signed: bool
    notarized: bool
    sbom_path: str
    provenance_path: str
    path: str
    manifest_path: str
    checksum_path: str
    release_key: str


class Reporter:
    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []

    def check(self, name: str, ok: bool, message: str = "") -> bool:
        self.checks.append({"name": name, "ok": ok, "message": message})
        if not ok and message:
            self.errors.append(message)
        return ok

    def warn(self, message: str) -> None:
        self.warnings.append(message)


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def normalize_version(tag_or_version: str) -> NormalizedVersion:
    tag = tag_or_version.strip()
    if not tag:
        raise ValueError("Release tag or version cannot be empty.")
    source = tag[1:] if tag.startswith("v") else tag
    if any(part in source for part in ("/", "\\", ":", "..")):
        raise ValueError("Release version cannot contain path-like values.")
    match = VERSION_RE.fullmatch(source)
    if not match:
        raise ValueError("Release version must begin with major.minor.patch and use simple prerelease text.")
    major = int(match.group("major"))
    minor = int(match.group("minor"))
    patch = int(match.group("patch"))
    if major > 255:
        raise ValueError("Windows Installer major version must be <= 255.")
    if minor > 255:
        raise ValueError("Windows Installer minor version must be <= 255.")
    if patch > 65535:
        raise ValueError("Windows Installer build version must be <= 65535.")
    deb_version = source.replace("-", "~", 1)
    rpm_version = source.replace("-", "_")
    numeric = f"{major}.{minor}.{patch}"
    normalized_tag = tag if tag.startswith("v") else f"v{source}"
    return NormalizedVersion(
        tag=normalized_tag,
        source_version=source,
        deb_version=deb_version,
        rpm_version=rpm_version,
        msi_version=numeric,
        macos_package_version=numeric,
    )


def checksum_file_for(artifact_path: Path) -> Path:
    return Path(str(artifact_path) + ".sha256")


def manifest_artifact_path(repo_root: Path, manifest_path: Path, manifest: dict[str, Any]) -> Path:
    raw_path = manifest.get("package_path") or manifest.get("path")
    if not raw_path:
        raise ValueError(f"{manifest_path} does not include package_path or path.")
    return resolve_repo_path(repo_root, str(raw_path))


def signed_flag(manifest: dict[str, Any]) -> bool:
    if "signed" in manifest:
        return bool(manifest.get("signed"))
    signing = manifest.get("signing")
    if isinstance(signing, dict):
        return bool(signing.get("signed"))
    return False


def notarized_flag(manifest: dict[str, Any]) -> bool:
    return bool(manifest.get("notarized") or manifest.get("stapled"))


def artifact_package_type(manifest: dict[str, Any]) -> str:
    if manifest.get("artifact_type") == "oaw-agent-binary":
        return "binary"
    value = str(manifest.get("package_type", "")).strip()
    if value:
        return value
    raise ValueError("Artifact manifest does not identify package_type or oaw-agent-binary artifact_type.")


def artifact_architecture(manifest: dict[str, Any]) -> str:
    if manifest.get("arch_mode"):
        return str(manifest["arch_mode"])
    if manifest.get("rpm_arch"):
        return str(manifest["rpm_arch"])
    return str(manifest.get("arch", "")).strip()


def release_key(package_type: str, os_name: str, architecture: str) -> str:
    if package_type == "msi":
        return "windows-msi"
    if package_type == "deb":
        return "linux-deb"
    if package_type == "rpm":
        return "linux-rpm"
    if package_type == "tar.gz":
        return f"{os_name}-targz"
    if package_type == "pkg":
        return f"macos-pkg-{architecture}"
    if package_type == "binary":
        return f"{os_name}-binary-{architecture}"
    return f"{os_name}-{package_type}-{architecture}"


def is_release_artifact_manifest_path(release_root: Path, manifest_path: Path) -> bool:
    try:
        relative_parts = manifest_path.relative_to(release_root).parts
    except ValueError:
        return False
    if len(relative_parts) != 2:
        return False
    parent, _filename = relative_parts
    return parent == "packages" or bool(RELEASE_BINARY_DIR_RE.fullmatch(parent))


def validate_checksum(artifact_path: Path, checksum_path: Path, expected_sha: str) -> None:
    if not artifact_path.is_file():
        raise ValueError(f"Artifact file is missing: {artifact_path}")
    if not checksum_path.is_file():
        raise ValueError(f"Checksum file is missing: {checksum_path}")
    actual = sha256_file(artifact_path).lower()
    checksum_text = checksum_path.read_text(encoding="ascii").strip()
    checksum_value = checksum_text.split()[0].lower() if checksum_text else ""
    if actual != expected_sha.lower():
        raise ValueError(f"Artifact SHA256 does not match manifest for {artifact_path.name}.")
    if actual != checksum_value:
        raise ValueError(f"Artifact SHA256 does not match checksum file for {artifact_path.name}.")


def validate_no_secret_markers(path: Path) -> None:
    if SECRET_RE.search(path.name):
        raise ValueError(f"Release metadata path contains a forbidden sensitive marker: {path.name}")
    if path.suffix.lower() in {".json", ".txt", ".sha256", ".md"} and path.is_file():
        text = path.read_text(encoding="utf-8", errors="ignore")
        if SECRET_RE.search(text):
            raise ValueError(f"Release metadata file contains a forbidden sensitive marker: {path}")


def validate_signing_evidence(artifact_path: Path, manifest_path: Path, manifest: dict[str, Any]) -> None:
    if not signed_flag(manifest):
        return
    evidence = manifest.get("signature_path") or manifest.get("signature")
    signing = manifest.get("signing")
    if isinstance(signing, dict):
        evidence = evidence or signing.get("evidence") or signing.get("signature_path")
    candidates = [Path(str(artifact_path) + ".signature.txt")]
    if evidence:
        candidates.append(resolve_repo_path(get_repo_root(), str(evidence)))
    if not any(candidate.is_file() for candidate in candidates):
        raise ValueError(f"{manifest_path} claims signed=true without signing evidence.")


def validate_notarization_evidence(artifact_path: Path, manifest_path: Path, manifest: dict[str, Any]) -> None:
    if not notarized_flag(manifest):
        return
    evidence = manifest.get("notarization_path") or manifest.get("notarization")
    candidates = [
        Path(str(artifact_path) + ".notarization.json"),
        Path(str(artifact_path) + ".notarization.txt"),
    ]
    if evidence and isinstance(evidence, str):
        candidates.append(resolve_repo_path(get_repo_root(), evidence))
    if not any(candidate.is_file() for candidate in candidates):
        raise ValueError(f"{manifest_path} claims notarized=true without notarization evidence.")


def artifact_from_manifest(repo_root: Path, release_root: Path, manifest_path: Path, version: str) -> ReleaseArtifact:
    manifest = read_json(manifest_path)
    artifact_path = manifest_artifact_path(repo_root, manifest_path, manifest)
    if not is_inside(release_root, artifact_path):
        raise ValueError(f"Artifact path must stay under release root: {manifest_path}")
    package_type = artifact_package_type(manifest)
    os_name = str(manifest.get("os", "")).strip()
    architecture = artifact_architecture(manifest)
    build_timestamp = str(manifest.get("build_timestamp") or manifest.get("generated_at") or "").strip()
    git_commit = str(manifest.get("git_commit", "")).strip()
    sha = str(manifest.get("sha256", "")).strip().lower()
    license_value = str(manifest.get("package_license") or manifest.get("license") or "").strip()
    missing = [
        field
        for field, value in (
            ("package_type", package_type),
            ("os", os_name),
            ("architecture", architecture),
            ("version", manifest.get("version")),
            ("git_commit", git_commit),
            ("build_timestamp", build_timestamp),
            ("sha256", sha),
        )
        if not str(value or "").strip()
    ]
    if missing:
        raise ValueError(f"{manifest_path} missing release metadata fields: {', '.join(missing)}.")
    if str(manifest["version"]) != version:
        raise ValueError(f"{manifest_path} version does not match {version}.")
    if license_value != PROJECT_LICENSE:
        raise ValueError(f"{manifest_path} license metadata must be {PROJECT_LICENSE}.")
    checksum_path = checksum_file_for(artifact_path)
    validate_checksum(artifact_path, checksum_path, sha)
    for metadata_path in (manifest_path, checksum_path):
        validate_no_secret_markers(metadata_path)
    validate_signing_evidence(artifact_path, manifest_path, manifest)
    validate_notarization_evidence(artifact_path, manifest_path, manifest)
    return ReleaseArtifact(
        artifact_filename=artifact_path.name,
        package_type=package_type,
        os=os_name,
        architecture=architecture,
        version=version,
        git_commit=git_commit,
        build_timestamp=build_timestamp,
        sha256=sha,
        license=PROJECT_LICENSE,
        signed=signed_flag(manifest),
        notarized=notarized_flag(manifest),
        sbom_path=str(manifest.get("sbom_path", "") or ""),
        provenance_path=str(manifest.get("provenance_path", "") or ""),
        path=to_repo_relative(repo_root, artifact_path),
        manifest_path=to_repo_relative(repo_root, manifest_path),
        checksum_path=to_repo_relative(repo_root, checksum_path),
        release_key=release_key(package_type, os_name, architecture),
    )


def discover_manifest_paths(release_root: Path) -> list[Path]:
    result: list[Path] = []
    package_types = {"deb", "rpm", "tar.gz", "msi", "pkg"}
    for path in sorted(release_root.rglob("*.manifest.json")):
        if not path.is_file() or "release-publication-manifest" in path.name:
            continue
        if not is_release_artifact_manifest_path(release_root, path):
            continue
        manifest = read_json(path)
        if manifest.get("artifact_type") == "oaw-agent-binary" or manifest.get("package_type") in package_types:
            result.append(path)
    return result


def validate_release_root(
    repo_root: Path,
    version: str,
    release_root: Path,
    expected_keys: set[str],
    classification: str,
    require_signed: bool,
) -> tuple[list[ReleaseArtifact], list[str]]:
    if not is_inside(repo_root / "dist" / "agent", release_root):
        raise ValueError("Release root must resolve under dist/agent/.")
    if not release_root.is_dir():
        raise ValueError(f"Release root does not exist: {release_root}")
    artifacts = [
        artifact_from_manifest(repo_root, release_root, path, version)
        for path in discover_manifest_paths(release_root)
    ]
    if not artifacts:
        raise ValueError("No artifact manifests were found under the release root.")
    found_keys = {artifact.release_key for artifact in artifacts}
    missing = sorted(expected_keys - found_keys)
    if missing:
        raise ValueError(f"Release artifacts missing expected package types: {', '.join(missing)}.")
    if require_signed:
        unsigned = sorted(artifact.artifact_filename for artifact in artifacts if not artifact.signed)
        if unsigned:
            raise ValueError(f"Signed production publication cannot include unsigned artifacts: {', '.join(unsigned)}.")
    warnings: list[str] = []
    if classification.startswith("unsigned"):
        signed = [artifact.artifact_filename for artifact in artifacts if artifact.signed]
        if signed:
            warnings.append(f"{classification} includes signed artifacts: {', '.join(sorted(signed))}.")
    return artifacts, warnings


def build_publication_manifest(
    version_info: NormalizedVersion,
    classification: str,
    artifacts: list[ReleaseArtifact],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "project": "OpenAssetWatch",
        "component": "oaw-agent",
        "classification": classification,
        "release": asdict(version_info),
        "generated_at": utc_timestamp(),
        "artifact_count": len(artifacts),
        "artifacts": [asdict(artifact) for artifact in sorted(artifacts, key=lambda item: item.release_key)],
    }


def validate_workflow_policy(workflow_path: Path) -> None:
    text = workflow_path.read_text(encoding="utf-8")
    if 'tags:' not in text or '"v*"' not in text and "'v*'" not in text:
        raise ValueError("Release workflow must trigger on v* tags.")
    if "pull_request:" not in text:
        raise ValueError("Release workflow must validate on pull_request.")
    if workflow_push_declares_branches(text):
        raise ValueError("Release workflow push trigger must not include arbitrary branches.")
    if "gh release" in text and "github.event_name == 'push'" not in text:
        raise ValueError("GitHub Release publishing must be guarded to tag push events.")
    if "OAW_AGENT_RELEASE_PUBLICATION_ENABLED" not in text:
        raise ValueError("GitHub Release publishing must require an explicit repository variable gate.")
    release_download_path = "path: dist/agent/${{ needs.resolve-release.outputs.version }}"
    if text.count(release_download_path) < 3:
        raise ValueError("Release workflow artifact downloads must target dist/agent/<version>.")


def workflow_push_declares_branches(text: str) -> bool:
    in_push = False
    push_indent = 0
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        if in_push and indent <= push_indent and stripped.endswith(":"):
            in_push = False
        if stripped == "push:":
            in_push = True
            push_indent = indent
            continue
        if in_push and indent > push_indent and stripped.startswith("branches:"):
            return True
    return False


def command_normalize(args: argparse.Namespace) -> int:
    reporter = Reporter()
    try:
        version = normalize_version(args.tag or args.version)
        reporter.check("version normalization", True, "Release version normalization passed.")
        result = {"ok": True, "version": asdict(version), "checks": reporter.checks, "warnings": [], "errors": []}
    except Exception as exc:
        reporter.check("version normalization", False, str(exc))
        result = {"ok": False, "checks": reporter.checks, "warnings": [], "errors": reporter.errors}
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def command_check_workflow(args: argparse.Namespace) -> int:
    reporter = Reporter()
    try:
        validate_workflow_policy(Path(args.workflow))
        reporter.check("release workflow policy", True, "Release workflow trigger and publication guards are valid.")
    except Exception as exc:
        reporter.check("release workflow policy", False, str(exc))
    print(json.dumps({"ok": not reporter.errors, "checks": reporter.checks, "warnings": reporter.warnings, "errors": reporter.errors}, indent=2))
    return 0 if not reporter.errors else 1


def command_validate(args: argparse.Namespace) -> int:
    reporter = Reporter()
    try:
        version_info = normalize_version(args.version)
        repo_root = get_repo_root()
        release_root = resolve_repo_path(repo_root, args.release_root)
        artifacts, warnings = validate_release_root(
            repo_root=repo_root,
            version=version_info.source_version,
            release_root=release_root,
            expected_keys=set(args.expected_package_type),
            classification=args.classification,
            require_signed=args.require_signed,
        )
        for warning in warnings:
            reporter.warn(warning)
        reporter.check("release artifact manifest completeness", True, "Release artifacts include required metadata fields.")
        reporter.check("release artifact checksums", True, "Release artifact checksums match manifest metadata.")
        reporter.check("release artifact signing claims", True, "Signed/notarized claims have required evidence or are false.")
        manifest = build_publication_manifest(version_info, args.classification, artifacts)
        if args.write_manifest:
            output_path = resolve_repo_path(repo_root, args.write_manifest)
            if not is_inside(release_root, output_path):
                raise ValueError("Publication manifest output must stay under the release root.")
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            reporter.check("publication manifest", True, "Release publication manifest was written.")
        result: dict[str, Any] = {
            "ok": True,
            "version": version_info.source_version,
            "release_root": to_repo_relative(repo_root, release_root),
            "artifacts": [asdict(artifact) for artifact in artifacts],
            "checks": reporter.checks,
            "warnings": reporter.warnings,
            "errors": [],
        }
    except Exception as exc:
        reporter.check("release publication validation", False, str(exc))
        result = {
            "ok": False,
            "version": args.version,
            "release_root": args.release_root,
            "artifacts": [],
            "checks": reporter.checks,
            "warnings": reporter.warnings,
            "errors": reporter.errors,
        }
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    normalize = subparsers.add_parser("normalize-version", help="Normalize a release tag or version.")
    normalize.add_argument("--tag", help="Git tag such as v0.1.0 or v0.1.0-rc.1.")
    normalize.add_argument("--version", help="Version without a leading v.")
    normalize.set_defaults(func=command_normalize)

    workflow = subparsers.add_parser("check-workflow", help="Validate release workflow trigger and publication policy.")
    workflow.add_argument("--workflow", required=True)
    workflow.set_defaults(func=command_check_workflow)

    validate = subparsers.add_parser("validate", help="Validate release artifact metadata and checksums.")
    validate.add_argument("--version", required=True)
    validate.add_argument("--release-root", required=True)
    validate.add_argument("--classification", default="unsigned-release-candidate")
    validate.add_argument("--expected-package-type", action="append", default=[])
    validate.add_argument("--write-manifest")
    validate.add_argument("--require-signed", action="store_true")
    validate.set_defaults(func=command_validate)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "normalize-version" and not (args.tag or args.version):
        print(json.dumps({"ok": False, "errors": ["Either --tag or --version is required."]}, indent=2))
        return 2
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
