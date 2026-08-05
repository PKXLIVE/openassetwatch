#!/usr/bin/env python3
"""Offline synthetic publisher-to-mirror-to-hub lifecycle demonstration."""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.advisory_feed_registry import (  # noqa: E402
    FeedRegistryDocument,
    FeedSource,
    MirrorEndpoint,
    PublisherKey,
    PublisherKeyringDocument,
    ReviewedFeedRegistry,
)
from app.advisory_mirror import build_advisory_mirror, load_existing_mirror  # noqa: E402
from app.advisory_sync_service import AdvisorySyncError, AdvisorySyncService  # noqa: E402
from app.advisory_transport import PrivateStagingArea, _valid_mirror_relative_path  # noqa: E402
from app.ai_advisor import ReadOnlyHubTools, build_tool_context  # noqa: E402
from app.osv_pypi_publisher import (  # noqa: E402
    DirectoryOsvSource,
    PublishRequest,
    PublisherLimits,
    publish_once,
)

from demo_osv_pypi_publisher import (  # noqa: E402
    KEY_ENV,
    KEY_ID as BUNDLE_KEY_ID,
    SYNTHETIC_DEMO_POLICY,
    _DemoAdvisoryStore,
    _DemoLifecycleStore,
    _Evaluation,
    _component_match,
    _finding_and_risk,
    _write_fixture,
    build_local_verification_registry,
)


NOW = datetime(2099, 1, 15, 12, 0, tzinfo=timezone.utc)
INDEX_KEY_ID = "oaw-demo-mirror-index-ed25519-2026-01"


def _mirror_registry(
    bundle_registry: ReviewedFeedRegistry,
    direct_source: FeedSource,
    index_key: Ed25519PrivateKey,
) -> tuple[ReviewedFeedRegistry, FeedSource]:
    data = direct_source.model_dump(mode="json")
    data.update(
        retrieval_mode="signed-mirror-index",
        expected_index_schema="oaw.advisory-mirror-index.v1",
        minimum_supported_openassetwatch_version="0.1.0",
        endpoint=None,
        mirror=MirrorEndpoint(
            host="advisories.openassetwatch.invalid",
            index_path="/v1/synthetic/index.json",
            signature_path="/v1/synthetic/index.ed25519",
            trusted_index_key_ids=[INDEX_KEY_ID],
        ).model_dump(mode="json"),
    )
    data["expected_content_types"].update(
        index=["application/json"],
        index_signature=["application/octet-stream"],
    )
    source = FeedSource.model_validate(data)
    public = index_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    index_publisher = PublisherKey(
        key_id=INDEX_KEY_ID,
        publisher_id="openassetwatch-synthetic-mirror-demo",
        publisher_name="OpenAssetWatch Synthetic Mirror Demonstration",
        algorithm="ed25519",
        public_key_base64=base64.b64encode(public).decode("ascii"),
        status="active",
        not_before=NOW - timedelta(days=1),
        not_after=NOW + timedelta(days=30),
    )
    return (
        ReviewedFeedRegistry(
            FeedRegistryDocument(
                schema_version="oaw.advisory-feed-registry.v1",
                registry_version="synthetic-mirror-demo",
                sources=[source],
            ),
            PublisherKeyringDocument(
                schema_version="oaw.advisory-publisher-keyring.v1",
                keyring_version="synthetic-mirror-demo",
                keys=[*bundle_registry.keyring_document.keys, index_publisher],
            ),
        ),
        source,
    )


class _MirrorRequestHandler(http.server.BaseHTTPRequestHandler):
    server_version = "OpenAssetWatchSyntheticMirror/1"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.query or parsed.fragment:
            self.send_error(400)
            return
        if parsed.path == "/v1/synthetic/index.json":
            relative = "index.json"
        elif parsed.path == "/v1/synthetic/index.ed25519":
            relative = "index.ed25519"
        elif parsed.path.startswith("/v1/synthetic/catalogs/"):
            relative = parsed.path.removeprefix("/v1/synthetic/")
        else:
            self.send_error(404)
            return
        if relative not in {"index.json", "index.ed25519"} and not _valid_mirror_relative_path(relative):
            self.send_error(400)
            return
        root = self.server.mirror_root  # type: ignore[attr-defined]
        candidate = root / Path(*relative.split("/"))
        try:
            data = candidate.read_bytes()
        except OSError:
            self.send_error(404)
            return
        content_type = "application/json" if relative.endswith(".json") else "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


class _LoopbackMirrorDownloader:
    """Demo-only fixed loopback adapter; production keeps the hardened HTTPS downloader."""

    def __init__(self, port: int) -> None:
        self.base_url = f"http://127.0.0.1:{port}"
        self.opener = urllib.request.build_opener(_NoRedirect)
        self.calls: list[str] = []

    def _fetch(self, source: FeedSource, kind: str, path: str):
        maximum = {
            "index": source.limits.maximum_mirror_index_bytes,
            "index_signature": source.limits.maximum_signature_bytes,
            "manifest": source.limits.maximum_manifest_bytes,
            "signature": source.limits.maximum_signature_bytes,
            "payload": source.limits.maximum_compressed_bytes,
        }[kind]
        self.calls.append(path)
        request = urllib.request.Request(self.base_url + path, method="GET")
        try:
            with self.opener.open(request, timeout=2) as response:
                body = response.read(maximum + 1)
                if response.status != 200 or len(body) > maximum:
                    raise RuntimeError("synthetic mirror response violated its bound")
                return SimpleNamespace(body=body)
        except (OSError, urllib.error.URLError) as exc:
            raise RuntimeError("synthetic mirror is unavailable") from exc

    def fetch(self, source: FeedSource, kind: str, **_kwargs):
        if source.mirror is None:
            raise RuntimeError("synthetic source has no mirror endpoint")
        path = source.mirror.index_path if kind == "index" else source.mirror.signature_path
        return self._fetch(source, kind, path)

    def fetch_mirror_artifact(self, source: FeedSource, kind: str, relative_path: str, **_kwargs):
        if not _valid_mirror_relative_path(relative_path):
            raise RuntimeError("synthetic mirror path is unsafe")
        expected = {
            "manifest": "manifest.json",
            "signature": "manifest.ed25519",
            "payload": source.expected_payload_name,
        }[kind]
        if relative_path.rsplit("/", 1)[-1] != expected:
            raise RuntimeError("synthetic mirror artifact kind is mismatched")
        if source.mirror is None:
            raise RuntimeError("synthetic source has no mirror endpoint")
        return self._fetch(source, kind, source.mirror.artifact_path(relative_path))


class _MirrorLifecycleStore(_DemoLifecycleStore):
    def create_remote_run(self, source_id: str, ordinal: int) -> str:
        run_id = "afrun_" + hashlib.sha256(f"mirror-sync-{ordinal}".encode()).hexdigest()[:32]
        self.runs[run_id] = {
            "run_id": run_id,
            "source_id": source_id,
            "request_mode": "remote-sync",
            "state": "created",
        }
        return run_id

    def get_run(self, run_id: str, *, include_preview: bool = False):
        result = dict(self.runs[run_id])
        if include_preview and "preview" in self.runs[run_id]:
            result["preview"] = self.runs[run_id]["preview"]
        return result

    def transition(self, run_id: str, *, expected_states, state: str, values=None, now=None) -> None:
        run = self.runs[run_id]
        if run["state"] not in expected_states:
            raise ValueError("synthetic run changed state unexpectedly")
        run.update(values or {})
        run["state"] = state

    def fail_run(self, run_id: str, *, code: str, summary: str, now: datetime) -> None:
        self.runs[run_id].update(
            state="failed",
            error_code=code,
            error_summary=summary,
            completed_at=now,
        )

    def active_catalog(self, source_id: str, *, include_bytes: bool = False):
        if self.active_catalog_id is None:
            return None
        item = self.catalogs[self.active_catalog_id]
        return dict(item) if item["source_id"] == source_id else None

    def save_verified_bundle(self, **values) -> None:
        run_id = values["run_id"]
        catalog_id = "afcat_" + values["payload_digest"][:32]
        self.runs[run_id].update(
            state="pending_approval",
            catalog_id=catalog_id,
            publisher_key_id=values["publisher_key_id"],
            catalog_version=values["catalog_version"],
            catalog_sequence=values["catalog_sequence"],
            manifest_digest=values["manifest_digest"],
            payload_digest=values["payload_digest"],
            license_identifier=values["license_identifier"],
            preview=values["preview"],
        )
        self.catalogs[catalog_id] = {
            "catalog_id": catalog_id,
            "run_id": run_id,
            "source_id": values["source_id"],
            "publisher_key_id": values["publisher_key_id"],
            "catalog_version": values["catalog_version"],
            "catalog_sequence": values["catalog_sequence"],
            "catalog_bytes": values["catalog_bytes"],
            "catalog_checksum": values["catalog_checksum"],
            "preview": values["preview"],
            "active": False,
        }


def run_demo() -> dict[str, object]:
    bundle_key = Ed25519PrivateKey.generate()
    index_key = Ed25519PrivateKey.generate()
    raw_private = bundle_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    protected_environment = {KEY_ENV: base64.b64encode(raw_private).decode("ascii")}
    limits = PublisherLimits(
        maximum_records=10,
        maximum_index_rows=20,
        maximum_total_bytes=5 << 20,
        total_timeout_seconds=30,
        retries=0,
        concurrency=2,
    )

    with tempfile.TemporaryDirectory(prefix="oaw-advisory-mirror-demo-") as temporary:
        root = Path(temporary)
        fixture = root / "fixture"
        fixture.mkdir(mode=0o700)
        publisher_output = root / "publisher-output"
        publisher_state = root / "state" / "publisher-state.json"
        _write_fixture(fixture, modified=NOW, fixed="2.0.0", versions=["1.0.0", "1.5.0"])
        first = publish_once(
            DirectoryOsvSource(fixture),
            PublishRequest(
                state_path=publisher_state,
                output_root=publisher_output,
                full=True,
                key_id=BUNDLE_KEY_ID,
                signing_key_env=KEY_ENV,
            ),
            limits=limits,
            policy=SYNTHETIC_DEMO_POLICY,
            now=lambda: NOW,
            environ=protected_environment,
        )
        if first.bundle_directory is None:
            raise RuntimeError("synthetic first publisher run produced no bundle")
        bundle_registry, direct_source = build_local_verification_registry(
            policy=SYNTHETIC_DEMO_POLICY,
            key_id=BUNDLE_KEY_ID,
            private_key=bundle_key,
        )
        registry, source = _mirror_registry(bundle_registry, direct_source, index_key)
        first_mirror = (root / "mirror-1").absolute()
        first_publication = build_advisory_mirror(
            bundle_directories=[first.bundle_directory.absolute()],
            output_directory=first_mirror,
            source=source,
            registry=registry,
            index_signing_key_id=INDEX_KEY_ID,
            index_signing_key=index_key,
            published_at=NOW + timedelta(minutes=1),
        )

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MirrorRequestHandler)
        server.mirror_root = first_mirror  # type: ignore[attr-defined]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        downloader = _LoopbackMirrorDownloader(server.server_address[1])
        store = _MirrorLifecycleStore()
        advisory_store = _DemoAdvisoryStore()
        current = {"value": NOW + timedelta(minutes=1)}
        evaluation_counter = {"value": 0}

        def evaluator(**kwargs):
            evaluation_counter["value"] += 1
            return _Evaluation(
                "vrun_" + f"{evaluation_counter['value']:032d}",
                len(kwargs.get("advisory_rows", [])),
            )

        service = AdvisorySyncService(
            registry=registry,
            store=store,
            downloader=downloader,
            staging=PrivateStagingArea((root / "private-staging").absolute()),
            evaluator=evaluator,
            advisory_store=advisory_store,
            now=lambda: current["value"],
        )
        try:
            first_run_id = store.create_remote_run(source.source_id, 1)
            first_sync = service.execute_remote_run(first_run_id)
            first_approved = service.approve(first_run_id, actor="demo-maintainer")
            first_activation = service.activate(first_run_id, actor="demo-maintainer")
            first_catalog_id = store.runs[first_run_id]["catalog_id"]
            first_bundle = load_existing_mirror(
                first_mirror,
                source=source,
                registry=registry,
                now=current["value"],
            )[-1].bundle
            record, component, initial_match = _component_match(
                first_bundle,
                installed_version="1.5.0",
                evaluated_at=current["value"],
            )
            initial_findings, initial_risk, initial_status = _finding_and_risk(
                record,
                component,
                initial_match,
                evaluated_at=current["value"],
            )

            later = NOW + timedelta(hours=2)
            _write_fixture(fixture, modified=later, fixed="1.1.0", versions=["1.0.0"])
            second = publish_once(
                DirectoryOsvSource(fixture),
                PublishRequest(
                    state_path=publisher_state,
                    output_root=publisher_output,
                    key_id=BUNDLE_KEY_ID,
                    signing_key_env=KEY_ENV,
                ),
                limits=limits,
                policy=SYNTHETIC_DEMO_POLICY,
                now=lambda: later,
                environ=protected_environment,
            )
            if second.bundle_directory is None:
                raise RuntimeError("synthetic second publisher run produced no bundle")
            second_mirror = (root / "mirror-2").absolute()
            second_publication = build_advisory_mirror(
                bundle_directories=[second.bundle_directory.absolute()],
                existing_mirror_root=first_mirror,
                output_directory=second_mirror,
                source=source,
                registry=registry,
                index_signing_key_id=INDEX_KEY_ID,
                index_signing_key=index_key,
                published_at=later + timedelta(minutes=1),
            )
            server.mirror_root = second_mirror  # type: ignore[attr-defined]
            current["value"] = later + timedelta(minutes=1)
            second_run_id = store.create_remote_run(source.source_id, 2)
            second_sync = service.execute_remote_run(second_run_id)
            service.approve(second_run_id, actor="demo-maintainer")
            second_activation = service.activate(second_run_id, actor="demo-maintainer")
            second_catalog_id = store.runs[second_run_id]["catalog_id"]
            second_bundle = load_existing_mirror(
                second_mirror,
                source=source,
                registry=registry,
                now=current["value"],
            )[-1].bundle
            updated_record, updated_component, updated_match = _component_match(
                second_bundle,
                installed_version="1.5.0",
                evaluated_at=current["value"],
            )
            updated_findings, updated_risk, updated_status = _finding_and_risk(
                updated_record,
                updated_component,
                updated_match,
                evaluated_at=current["value"],
            )

            server.shutdown()
            thread.join(timeout=5)
            offline_run_id = store.create_remote_run(source.source_id, 3)
            try:
                service.execute_remote_run(offline_run_id)
            except AdvisorySyncError:
                offline_sync = store.get_run(offline_run_id)
            else:
                raise RuntimeError("offline mirror synchronization unexpectedly succeeded")
            last_known_good_before_rollback = store.active_catalog_id
            current["value"] = later + timedelta(minutes=2)
            rollback = service.rollback(first_catalog_id, actor="demo-maintainer")

            evidence_rows = [
                {
                    "run_id": second_run_id,
                    "catalog_id": second_catalog_id,
                    "source_id": source.source_id,
                    "state": "activated",
                    "catalog_version": second_bundle.manifest.catalog_version,
                    "catalog_sequence": second_bundle.manifest.catalog_sequence,
                    "publisher_key_id": second_bundle.manifest.publisher_key_id,
                    "manifest_digest": second_bundle.manifest_digest,
                    "payload_digest": second_bundle.payload_digest,
                    "signature_status": "verified",
                    "license_identifier": second_bundle.manifest.license_identifier,
                    "license_status": "approved",
                    "attribution_status": "present",
                    "reevaluation_status": second_activation["reevaluation"]["status"],
                    "created_at": later,
                    "completed_at": later,
                    "preview": second_sync["preview"],
                }
            ]
            tools = ReadOnlyHubTools(
                sites=[],
                sensors=[],
                assets=[],
                advisory_feed_evidence=evidence_rows,
                now=later,
            )
            _, selected_tools, evidence = build_tool_context(
                tools,
                question=(
                    "Explain the advisory feed status, catalog preview, signature status, "
                    "activation impact, fixed-version risk change, and retained rollback evidence."
                ),
                site_id=None,
                asset_id=None,
            )
            return {
                "status": "offline-mirror-demo-complete",
                "fixture": "openassetwatch-authored-synthetic-no-third-party-data",
                "publisher": {
                    "first_mode": first.report["mode"],
                    "second_mode": second.report["mode"],
                    "digests_changed": first_bundle.payload_digest != second_bundle.payload_digest,
                    "license_identifier": second_bundle.manifest.license_identifier,
                },
                "publication": {
                    "first": first_publication.report(),
                    "second": second_publication.report(),
                    "index_signature_status": "verified",
                    "retained_sequences": list(second_publication.retained_catalog_sequences),
                },
                "local_http": {
                    "request_count": len(downloader.calls),
                    "fixed_paths_only": True,
                    "public_network_used": False,
                    "stopped_before_offline_check": True,
                },
                "hub_lifecycle": {
                    "first_sync_state": first_sync["state"],
                    "first_approval_state": first_approved["state"],
                    "first_activation": first_activation["reevaluation"]["status"],
                    "second_sync_state": second_sync["state"],
                    "second_activation": second_activation["reevaluation"]["status"],
                    "offline_sync_state": offline_sync["state"],
                    "last_known_good_preserved": last_known_good_before_rollback == second_catalog_id,
                    "offline_rollback": rollback["reevaluation"]["status"],
                    "rolled_back_catalog_id": store.active_catalog_id,
                },
                "deterministic_outcomes": {
                    "initial_match": initial_status,
                    "initial_findings": initial_findings,
                    "initial_risk": initial_risk,
                    "updated_match": updated_status,
                    "updated_findings": updated_findings,
                    "updated_risk": updated_risk,
                },
                "ai_evidence": {
                    "selected_tools": list(selected_tools),
                    "evidence_ids": sorted(item.evidence_id for item in evidence),
                    "server_issued_run_id": second_run_id,
                    "server_issued_catalog_id": second_catalog_id,
                },
                "private_key_persisted": False,
            }
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


def main() -> int:
    print(json.dumps(run_demo(), ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
