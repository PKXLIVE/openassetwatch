#!/usr/bin/env python3
"""Publish a signed OpenAssetWatch KEV enrichment bundle from official CISA data."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.kev_publisher import (  # noqa: E402
    CisaKevHttpSource,
    FileKevSource,
    KevPublisherError,
    PublishRequest,
    live_source_smoke,
    load_state,
    publish_once,
    publisher_report_bytes,
)


def _absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Publish reviewed CISA KEV prioritization intelligence.")
    commands = parser.add_subparsers(dest="command", required=True)
    sync = commands.add_parser("sync", help="Run one full KEV synchronization.")
    sync.add_argument("--state", type=_absolute, required=True)
    sync.add_argument("--output", type=_absolute)
    sync.add_argument("--fixture-file", type=_absolute)
    sync.add_argument("--signing-key-file", type=_absolute)
    sync.add_argument("--key-id")
    sync.add_argument("--dry-run", action="store_true")
    sync.add_argument("--sequence-floor", type=int, default=0)
    sync.add_argument("--manifest-validity-days", type=int, default=30)
    sync.add_argument("--total-timeout", type=float, default=60)
    sync.add_argument("--json", action="store_true")
    smoke = commands.add_parser("live-smoke", help="Validate the bounded official source without persisting it.")
    smoke.add_argument("--total-timeout", type=float, default=30)
    smoke.add_argument("--json", action="store_true")
    state = commands.add_parser("state", help="Inspect bounded publisher state metadata.")
    state.add_argument("--state", type=_absolute, required=True)
    state.add_argument("--json", action="store_true")
    return parser


def _emit(value: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        sys.stdout.buffer.write(publisher_report_bytes(value))
    else:
        sys.stdout.write("\n".join(f"{key}: {json.dumps(item, default=str, ensure_ascii=True)}" for key, item in value.items()) + "\n")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "sync":
            source = FileKevSource(args.fixture_file) if args.fixture_file else CisaKevHttpSource()
            result = publish_once(
                source,
                PublishRequest(
                    state_path=args.state,
                    output_root=args.output,
                    dry_run=args.dry_run,
                    key_id=args.key_id,
                    signing_key_file=args.signing_key_file,
                    sequence_floor=args.sequence_floor,
                    manifest_validity_days=args.manifest_validity_days,
                ),
                total_timeout_seconds=args.total_timeout,
            )
            output = dict(result.report)
            output["status"] = result.status
            if result.bundle_directory:
                output["bundle_name"] = result.bundle_directory.name
        elif args.command == "live-smoke":
            output = live_source_smoke(total_timeout_seconds=args.total_timeout)
        else:
            state = load_state(args.state)
            output = {"status": "state-absent"} if state is None else {
                "status": "state-valid",
                "source_id": state.source_id,
                "adapter_version": state.adapter_version,
                "run_sequence": state.run_sequence,
                "catalog_version": state.catalog_version,
                "catalog_date_released": state.catalog_date_released,
                "source_digest": state.source_digest,
                "payload_digest": state.payload_digest,
                "last_successful_run_at": state.last_successful_run_at,
            }
        _emit(output, as_json=args.json)
        return 0
    except (KevPublisherError, ValueError) as exc:
        _emit(
            {
                "status": "failed",
                "code": getattr(exc, "code", type(exc).__name__[:80]),
                "summary": getattr(exc, "summary", "KEV publisher input or operation failed safely"),
            },
            as_json=getattr(args, "json", False),
        )
        return 2
    except Exception:
        _emit(
            {"status": "failed", "code": "internal-error", "summary": "KEV publisher failed safely"},
            as_json=getattr(args, "json", False),
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
