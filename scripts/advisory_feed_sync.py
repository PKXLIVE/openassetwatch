#!/usr/bin/env python3
"""One-shot trusted advisory feed administration CLI."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"


def _source_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--source", required=True, help="Reviewed advisory source_id.")


def _actor_argument(parser: argparse.ArgumentParser, name: str = "--actor") -> None:
    parser.add_argument(name, required=True, help="Bounded operator identity for the audit record.")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Retrieve, verify, preview, approve, and activate reviewed signed advisory bundles."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("sources", help="List reviewed sources and status.")

    status = subcommands.add_parser("status", help="Show one reviewed source.")
    _source_argument(status)

    sync = subcommands.add_parser("sync", help="Run one bounded remote synchronization.")
    _source_argument(sync)
    _actor_argument(sync, "--requested-by")

    local = subcommands.add_parser(
        "import-local",
        help="Verify the repository-reviewed signed fixture for one source.",
    )
    _source_argument(local)
    _actor_argument(local, "--requested-by")

    verify = subcommands.add_parser(
        "verify-bundle",
        help="Verify the repository-reviewed signed fixture without database changes.",
    )
    _source_argument(verify)

    inspect = subcommands.add_parser("inspect", help="Inspect a bounded synchronization run.")
    inspect.add_argument("--run", required=True, help="Server-issued afrun_ identifier.")

    preview = subcommands.add_parser("preview", help="Show a verified run preview.")
    preview.add_argument("--run", required=True, help="Server-issued afrun_ identifier.")

    approve = subcommands.add_parser("approve", help="Approve a verified run.")
    approve.add_argument("--run", required=True, help="Server-issued afrun_ identifier.")
    _actor_argument(approve)

    reject = subcommands.add_parser("reject", help="Reject a verified run.")
    reject.add_argument("--run", required=True, help="Server-issued afrun_ identifier.")
    _actor_argument(reject)
    reject.add_argument("--reason", required=True, help="Bounded rejection reason.")

    activate = subcommands.add_parser("activate", help="Atomically activate an approved run.")
    activate.add_argument("--run", required=True, help="Server-issued afrun_ identifier.")
    _actor_argument(activate)

    catalogs = subcommands.add_parser("catalogs", help="List retained rollback targets.")
    _source_argument(catalogs)

    rollback = subcommands.add_parser("rollback", help="Roll back to a retained catalog.")
    rollback.add_argument("--catalog", required=True, help="Server-issued afcat_ identifier.")
    _actor_argument(rollback)

    retry = subcommands.add_parser("retry-reevaluation", help="Retry a failed post-activation evaluation.")
    retry.add_argument("--activation", required=True, help="Server-issued afact_ identifier.")
    _actor_argument(retry)

    cleanup = subcommands.add_parser("cleanup-staging", help="Remove bounded abandoned private staging directories.")
    cleanup.add_argument("--older-than-seconds", type=int, default=3600)
    return parser.parse_args(argv)


def _validate_identifier(value: str, prefix: str) -> str:
    if not value.startswith(prefix) or len(value) != len(prefix) + 32:
        raise ValueError(f"expected a server-issued {prefix} identifier")
    int(value[len(prefix) :], 16)
    return value


def _verify_reviewed_fixture(service, source_id: str) -> dict[str, object]:
    from app.advisory_bundle import verify_bundle
    from app.advisory_transport import read_single_link_file

    source = service.registry.source(source_id)
    fixture = service._fixture_directory(source)  # Reviewed static root; no caller path.
    manifest = read_single_link_file(
        fixture / "manifest.json",
        maximum_bytes=source.limits.maximum_manifest_bytes,
    )
    signature = read_single_link_file(
        fixture / "manifest.ed25519",
        maximum_bytes=source.limits.maximum_signature_bytes,
    )
    payload = read_single_link_file(
        fixture / source.expected_payload_name,
        maximum_bytes=source.limits.maximum_compressed_bytes,
    )
    bundle = verify_bundle(
        manifest_bytes=manifest,
        signature_bytes=signature,
        payload_bytes=payload,
        source=source,
        registry=service.registry,
    )
    return {
        "source_id": source_id,
        "manifest_digest": bundle.manifest_digest,
        "payload_digest": bundle.payload_digest,
        "publisher_key_id": bundle.manifest.publisher_key_id,
        "catalog_version": bundle.manifest.catalog_version,
        "catalog_sequence": bundle.manifest.catalog_sequence,
        "license_identifier": bundle.manifest.license_identifier,
        "advisory_count": len(bundle.catalog.advisories),
        "signature_status": "verified",
        "database_changed": False,
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    sys.path.insert(0, str(BACKEND_ROOT))

    from app.advisory_sync_service import AdvisorySyncError, AdvisorySyncService
    from app.advisory_sync_store import AdvisorySyncStoreError
    from app.advisory_feed_registry import RegistryError
    from app.advisory_transport import StagingSecurityError

    service = AdvisorySyncService()
    try:
        if args.command == "sources":
            output = {"items": service.list_sources()}
        elif args.command == "status":
            output = service.source_status(args.source)
        elif args.command == "sync":
            run = service.request_sync(source_id=args.source, requested_by=args.requested_by)
            output = service.execute_remote_run(run["run_id"])
        elif args.command == "import-local":
            run = service.request_local_bundle(source_id=args.source, requested_by=args.requested_by)
            output = service.execute_local_run(run["run_id"])
        elif args.command == "verify-bundle":
            output = _verify_reviewed_fixture(service, args.source)
        elif args.command == "inspect":
            output = service.store.get_run(_validate_identifier(args.run, "afrun_"))
        elif args.command == "preview":
            output = service.store.get_run(
                _validate_identifier(args.run, "afrun_"),
                include_preview=True,
            )
            output = {"run_id": output["run_id"], "state": output["state"], "preview": output.get("preview")}
        elif args.command == "approve":
            output = service.approve(_validate_identifier(args.run, "afrun_"), actor=args.actor)
        elif args.command == "reject":
            output = service.reject(
                _validate_identifier(args.run, "afrun_"),
                actor=args.actor,
                reason=args.reason,
            )
        elif args.command == "activate":
            output = service.activate(_validate_identifier(args.run, "afrun_"), actor=args.actor)
        elif args.command == "catalogs":
            service.registry.source(args.source, require_enabled=False)
            output = {"items": service.store.list_catalogs(source_id=args.source)}
        elif args.command == "rollback":
            output = service.rollback(_validate_identifier(args.catalog, "afcat_"), actor=args.actor)
        elif args.command == "retry-reevaluation":
            output = service.retry_reevaluation(
                _validate_identifier(args.activation, "afact_"),
                actor=args.actor,
            )
        elif args.command == "cleanup-staging":
            output = {
                "removed_directories": service.staging.cleanup_abandoned(
                    older_than_seconds=args.older_than_seconds
                )
            }
        else:  # pragma: no cover - argparse prevents this branch.
            raise ValueError("unknown command")
    except (AdvisorySyncError, AdvisorySyncStoreError, RegistryError, StagingSecurityError, ValueError) as exc:
        code = getattr(exc, "code", "invalid-argument")
        summary = getattr(exc, "summary", str(exc)[:240])
        print(json.dumps({"error_code": code, "error_summary": summary}, sort_keys=True), file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - never expose a body, token, path, or traceback.
        print(
            json.dumps(
                {
                    "error_code": type(exc).__name__[:80],
                    "error_summary": "advisory feed command failed safely",
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(output, default=str, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
