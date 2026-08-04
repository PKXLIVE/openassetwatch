#!/usr/bin/env python3
"""One-shot OSV PyPI advisory publisher and bounded live-source smoke CLI."""

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

from app.osv_pypi_adapter import (  # noqa: E402
    OsvPublisherError,
    PRODUCTION_POLICY,
    format_utc,
)
from app.osv_pypi_publisher import (  # noqa: E402
    DirectoryOsvSource,
    OsvHttpClient,
    PublishRequest,
    PublisherLimits,
    live_source_smoke,
    load_publisher_state,
    publish_once,
    publisher_report_bytes,
)


def _absolute(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise argparse.ArgumentTypeError("path must be absolute")
    return path


def _limits(args: argparse.Namespace, *, smoke: bool = False) -> PublisherLimits:
    return PublisherLimits(
        maximum_records=args.max_records,
        maximum_index_bytes=args.max_index_bytes,
        maximum_index_rows=args.max_index_rows,
        maximum_record_bytes=args.max_record_bytes,
        maximum_total_bytes=args.max_total_bytes,
        total_timeout_seconds=args.total_timeout,
        connection_timeout_seconds=args.connect_timeout,
        read_timeout_seconds=args.read_timeout,
        retries=args.retries,
        concurrency=1 if smoke else args.concurrency,
        overlap_seconds=args.overlap_seconds if not smoke else 0,
    )


def _add_bounds(parser: argparse.ArgumentParser, *, smoke: bool = False) -> None:
    parser.add_argument("--max-records", type=int, default=20_000 if smoke else 10_000)
    parser.add_argument("--max-index-bytes", type=int, default=4 << 20)
    parser.add_argument("--max-index-rows", type=int, default=50_000)
    parser.add_argument("--max-record-bytes", type=int, default=512 << 10)
    parser.add_argument("--max-total-bytes", type=int, default=(5 << 20) if smoke else (64 << 20))
    parser.add_argument("--total-timeout", type=float, default=60 if smoke else 300)
    parser.add_argument("--connect-timeout", type=float, default=5)
    parser.add_argument("--read-timeout", type=float, default=15)
    parser.add_argument("--retries", type=int, default=1 if smoke else 3)
    if not smoke:
        parser.add_argument("--concurrency", type=int, default=4)
        parser.add_argument("--overlap-seconds", type=int, default=3_600)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Publish a bounded signed OpenAssetWatch catalog from reviewed "
            "PyPI Advisory Database PYSEC records exported by OSV.dev."
        )
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    sync = subcommands.add_parser("sync", help="Run one full or incremental publisher synchronization.")
    sync.add_argument("--state", type=_absolute, required=True, help="Absolute private cursor/state file.")
    sync.add_argument("--output", type=_absolute, help="Absolute private output root; omitted for dry run.")
    sync.add_argument("--fixture-dir", type=_absolute, help="Absolute offline OSV-format fixture directory.")
    mode = sync.add_mutually_exclusive_group()
    mode.add_argument("--full", action="store_true", help="Rebuild every current PYSEC record.")
    mode.add_argument("--incremental", action="store_true", help="Use cursor plus bounded overlap (default).")
    sync.add_argument("--dry-run", action="store_true", help="Validate and normalize without signing or writes.")
    sync.add_argument("--key-id", help="Reviewed publisher key ID (never a private key).")
    key = sync.add_mutually_exclusive_group()
    key.add_argument("--signing-key-file", type=_absolute, help="Private Ed25519 PEM or raw-base64 key file.")
    key.add_argument(
        "--signing-key-env",
        help="Name of a protected environment variable containing canonical raw-key base64.",
    )
    sync.add_argument("--manifest-validity-days", type=int, default=30)
    sync.add_argument("--json", action="store_true", help="Emit one bounded JSON status object.")
    _add_bounds(sync)

    smoke = subcommands.add_parser(
        "live-smoke",
        help="Retrieve and normalize exactly one indexed PYSEC record without persisting it.",
    )
    smoke.add_argument("--record-id", required=True)
    smoke.add_argument("--json", action="store_true")
    _add_bounds(smoke, smoke=True)

    state = subcommands.add_parser("state", help="Inspect bounded non-secret cursor metadata.")
    state.add_argument("--state", type=_absolute, required=True)
    state.add_argument("--json", action="store_true")
    return parser


def _emit(value: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        sys.stdout.buffer.write(publisher_report_bytes(value))
        return
    rendered: list[str] = []
    for key, item in value.items():
        rendered.append(
            f"{key}: {json.dumps(item, ensure_ascii=True, sort_keys=True, default=str)}"
        )
    data = ("\n".join(rendered) + "\n").encode("utf-8")
    if len(data) > 256 << 10:
        raise OsvPublisherError(
            "publisher-report-too-large",
            "publisher status exceeds the serialized byte limit",
        )
    sys.stdout.buffer.write(data)


def _sync(args: argparse.Namespace) -> dict[str, Any]:
    limits = _limits(args)
    source = (
        DirectoryOsvSource(args.fixture_dir)
        if args.fixture_dir is not None
        else OsvHttpClient(limits=limits)
    )
    request = PublishRequest(
        state_path=args.state,
        output_root=args.output,
        full=args.full,
        dry_run=args.dry_run,
        key_id=args.key_id,
        signing_key_file=args.signing_key_file,
        signing_key_env=args.signing_key_env,
        manifest_validity_days=args.manifest_validity_days,
    )
    result = publish_once(source, request, limits=limits)
    output = dict(result.report)
    output["status"] = result.status
    if result.bundle_directory is not None:
        output["bundle_name"] = result.bundle_directory.name
    return output


def _live_smoke(args: argparse.Namespace) -> dict[str, Any]:
    limits = _limits(args, smoke=True)
    return live_source_smoke(
        OsvHttpClient(limits=limits),
        record_id=args.record_id,
        limits=limits,
    )


def _state(args: argparse.Namespace) -> dict[str, Any]:
    state = load_publisher_state(args.state, policy=PRODUCTION_POLICY)
    if state is None:
        return {"status": "state-absent"}
    return {
        "status": "state-valid",
        "source_id": state.source_id,
        "adapter_version": state.adapter_version,
        "run_sequence": state.run_sequence,
        "cursor_modified_at": format_utc(state.cursor.modified_at),
        "cursor_record_id": state.cursor.record_id,
        "index_sha256": state.cursor.index_sha256,
        "catalog_version": state.catalog_version,
        "payload_digest": state.payload_digest,
        "record_count": len(state.records),
        "last_successful_run_at": format_utc(state.last_successful_run_at),
    }


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "sync":
            output = _sync(args)
        elif args.command == "live-smoke":
            output = _live_smoke(args)
        else:
            output = _state(args)
        _emit(output, as_json=args.json)
        return 0
    except (OsvPublisherError, ValueError) as exc:
        error = {
            "status": "failed",
            "code": getattr(exc, "code", type(exc).__name__[:80]),
            "summary": getattr(exc, "summary", "publisher input or operation failed safely"),
        }
        record_id = getattr(exc, "record_id", None)
        if record_id:
            error["record_id"] = record_id
        _emit(error, as_json=getattr(args, "json", False))
        return 2
    except Exception:
        _emit(
            {
                "status": "failed",
                "code": "internal-error",
                "summary": "publisher operation failed safely; consult protected local diagnostics",
            },
            as_json=getattr(args, "json", False),
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
