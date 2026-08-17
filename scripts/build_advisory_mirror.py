#!/usr/bin/env python3
"""Build, verify, or securely snapshot a static OpenAssetWatch advisory mirror."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.advisory_feed_registry import RegistryError, load_reviewed_feed_registry  # noqa: E402
from app.advisory_mirror import (  # noqa: E402
    DEFAULT_RETAIN_PRIOR,
    MirrorSecurityError,
    build_advisory_mirror,
    load_existing_mirror,
    snapshot_advisory_mirror,
    verify_publication_continuity,
)
from app.advisory_transport import read_single_link_file  # noqa: E402
from app.osv_pypi_publisher import OsvPublisherError, load_signing_key  # noqa: E402


def _absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return path


def _timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timestamp must use ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp requires a timezone")
    return parsed.astimezone(timezone.utc)


def _add_registry(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--registry-root",
        type=_absolute,
        default=BACKEND / "advisory_feeds",
        help="Absolute directory containing reviewed sources.json and publishers.json.",
    )
    parser.add_argument("--source", required=True, help="Reviewed mirror source_id.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Operate static signed advisory-mirror artifacts without importing or activating them."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build", help="Build one atomic local static-host snapshot.")
    _add_registry(build)
    build.add_argument("--bundle", type=_absolute, action="append", required=True)
    build.add_argument("--existing-root", type=_absolute)
    build.add_argument("--output", type=_absolute, required=True)
    build.add_argument("--index-key-id", required=True)
    key = build.add_mutually_exclusive_group(required=True)
    key.add_argument("--signing-key-file", type=_absolute)
    key.add_argument("--signing-key-env")
    build.add_argument("--retain-prior", type=int, default=DEFAULT_RETAIN_PRIOR)
    build.add_argument("--published-at", type=_timestamp)

    verify = commands.add_parser("verify", help="Verify every artifact in one local mirror snapshot.")
    _add_registry(verify)
    verify.add_argument("--root", type=_absolute, required=True)
    verify.add_argument("--now", type=_timestamp)

    snapshot = commands.add_parser(
        "snapshot",
        help="Download one complete reviewed mirror snapshot for bounded retention input.",
    )
    _add_registry(snapshot)
    snapshot.add_argument("--output", type=_absolute, required=True)
    snapshot.add_argument("--now", type=_timestamp)

    continuity = commands.add_parser(
        "continuity",
        help="Validate a prior publication checkpoint against a verified snapshot report.",
    )
    continuity.add_argument("--checkpoint", type=_absolute, required=True)
    continuity.add_argument("--snapshot-report", type=_absolute, required=True)
    continuity.add_argument("--time-floor", type=int, required=True)
    return parser


def _emit(value: dict[str, object], *, stream=sys.stdout) -> None:
    data = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    if len(data.encode("utf-8")) > 64 << 10:
        raise MirrorSecurityError("mirror-report-too-large", "mirror command report exceeds its limit")
    print(data, file=stream)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "continuity":
            output = verify_publication_continuity(
                checkpoint_bytes=read_single_link_file(args.checkpoint, maximum_bytes=64 << 10),
                snapshot_report_bytes=read_single_link_file(args.snapshot_report, maximum_bytes=64 << 10),
                time_floor=args.time_floor,
            )
        else:
            registry = load_reviewed_feed_registry(args.registry_root)
            source = registry.source(args.source)
        if args.command == "build":
            key = load_signing_key(
                key_file=args.signing_key_file,
                environment_name=args.signing_key_env,
            )
            result = build_advisory_mirror(
                bundle_directories=args.bundle,
                output_directory=args.output,
                source=source,
                registry=registry,
                index_signing_key_id=args.index_key_id,
                index_signing_key=key,
                published_at=args.published_at,
                retain_prior=args.retain_prior,
                existing_mirror_root=args.existing_root,
            )
            output = result.report()
        elif args.command == "verify":
            bundles = load_existing_mirror(
                args.root,
                source=source,
                registry=registry,
                now=args.now or datetime.now(timezone.utc),
            )
            latest = bundles[-1].bundle.manifest
            output = {
                "schema_version": "oaw.advisory-mirror-verification-report.v1",
                "status": "mirror-verified",
                "source_id": source.source_id,
                "catalog_count": len(bundles),
                "latest_catalog_version": latest.catalog_version,
                "latest_catalog_sequence": latest.catalog_sequence,
            }
        elif args.command == "snapshot":
            output = snapshot_advisory_mirror(
                output_directory=args.output,
                source=source,
                registry=registry,
                now=args.now,
            ).report()
        _emit(output)
        return 0
    except (MirrorSecurityError, OsvPublisherError, RegistryError, ValueError) as exc:
        _emit(
            {
                "status": "failed",
                "code": getattr(exc, "code", "invalid-argument"),
                "summary": getattr(exc, "summary", "mirror operation failed safely"),
            },
            stream=sys.stderr,
        )
        return 2
    except Exception:
        _emit(
            {
                "status": "failed",
                "code": "internal-error",
                "summary": "mirror operation failed safely; consult protected local diagnostics",
            },
            stream=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
