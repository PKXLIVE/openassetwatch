"""One-shot trusted advisory synchronization, activation, and rollback service."""

from __future__ import annotations

import hashlib
import json
import logging
import stat
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from .advisory_bundle import (
    BundleVerificationError,
    VerifiedBundle,
    preview_bundle,
    verify_bundle,
    verify_manifest,
)
from .advisory_catalog import AdvisoryCatalog, CatalogValidationError, parse_catalog_bytes
from .advisory_feed_registry import FeedSource, RegistryError, ReviewedFeedRegistry, load_reviewed_feed_registry
from .advisory_store import SqlAdvisoryStore, advisory_id_for
from .advisory_sync_store import AdvisorySyncStoreError, SqlAdvisorySyncStore
from .advisory_transport import (
    AdvisoryDownloader,
    DownloadSecurityError,
    PrivateStagingArea,
    StagingSecurityError,
    read_single_link_file,
)
from .vulnerability_service import evaluate_vulnerabilities


LOGGER = logging.getLogger(__name__)
MAX_TARGETED_ADVISORIES = 20_000
MAX_CHANGED_ADVISORIES = MAX_TARGETED_ADVISORIES * 2
LOCAL_FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "advisory_feeds" / "fixtures"


class AdvisoryAdapter(Protocol):
    """Extension boundary for reviewed source-specific normalization."""

    adapter_type: str
    adapter_version: str

    def catalog_bytes(self, bundle: VerifiedBundle) -> bytes: ...


class OawCatalogV1Adapter:
    adapter_type = "oaw-catalog-v1"
    adapter_version = "1"

    def catalog_bytes(self, bundle: VerifiedBundle) -> bytes:
        return bundle.catalog_bytes


ADAPTERS: dict[str, AdvisoryAdapter] = {
    OawCatalogV1Adapter.adapter_type: OawCatalogV1Adapter(),
}


class AdvisorySyncError(ValueError):
    def __init__(self, code: str, summary: str) -> None:
        super().__init__(summary)
        self.code = code[:80]
        self.summary = summary[:240]


def _known_error(exc: Exception) -> tuple[str, str]:
    if isinstance(
        exc,
        (
            AdvisorySyncError,
            AdvisorySyncStoreError,
            BundleVerificationError,
            DownloadSecurityError,
            RegistryError,
            StagingSecurityError,
        ),
    ):
        return exc.code, exc.summary
    if isinstance(exc, CatalogValidationError):
        return "catalog-invalid", "advisory catalog validation failed safely"
    return type(exc).__name__[:80], "advisory synchronization failed safely"


def _parse_retained_catalog(item: dict[str, Any]) -> tuple[AdvisoryCatalog, str]:
    data = bytes(item["catalog_bytes"])
    catalog, checksum = parse_catalog_bytes(data)
    if checksum != item["catalog_checksum"] or hashlib.sha256(data).hexdigest() != checksum:
        raise AdvisorySyncError("retained-catalog-digest-invalid", "retained catalog failed digest verification")
    return catalog, checksum


def _record_digest(record: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            record.model_dump(mode="json"),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def changed_record_ids(
    current: AdvisoryCatalog,
    previous: AdvisoryCatalog | None,
) -> list[str]:
    current_records = {record.id.casefold(): record for record in current.advisories}
    previous_records = {
        record.id.casefold(): record for record in (previous.advisories if previous else [])
    }
    changed = set(current_records) ^ set(previous_records)
    changed.update(
        key
        for key in set(current_records) & set(previous_records)
        if _record_digest(current_records[key]) != _record_digest(previous_records[key])
    )
    values = [
        (current_records.get(key) or previous_records[key]).id
        for key in sorted(changed)
    ]
    if len(values) > MAX_CHANGED_ADVISORIES:
        raise AdvisorySyncError("reevaluation-scope-too-large", "changed advisory set exceeds the targeted reevaluation limit")
    return values


class AdvisorySyncService:
    def __init__(
        self,
        *,
        registry: ReviewedFeedRegistry | None = None,
        store: SqlAdvisorySyncStore | None = None,
        downloader: AdvisoryDownloader | None = None,
        staging: PrivateStagingArea | None = None,
        evaluator: Callable[..., Any] = evaluate_vulnerabilities,
        advisory_store: SqlAdvisoryStore | None = None,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] | None = None,
        fixture_root: Path = LOCAL_FIXTURE_ROOT,
    ) -> None:
        self.registry = registry or load_reviewed_feed_registry()
        self.store = store or SqlAdvisorySyncStore()
        self.downloader = downloader or AdvisoryDownloader()
        self.staging = staging or PrivateStagingArea()
        self.evaluator = evaluator
        self.advisory_store = advisory_store or SqlAdvisoryStore()
        self.clock = clock
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.fixture_root = fixture_root.absolute()

    def list_sources(self) -> list[dict[str, Any]]:
        result = []
        for source in self.registry.sources_public():
            result.append({**source, **self.store.source_status(str(source["source_id"]))})
        return result

    def source_status(self, source_id: str) -> dict[str, Any]:
        source = self.registry.source(source_id, require_enabled=False)
        public = next(item for item in self.registry.sources_public() if item["source_id"] == source_id)
        return {**public, **self.store.source_status(source.source_id)}

    def request_sync(self, *, source_id: str, requested_by: str) -> dict[str, Any]:
        source = self.registry.source(source_id)
        return self.store.create_run(
            source_id=source.source_id,
            requested_by=requested_by,
            request_mode="remote-sync",
            minimum_interval_seconds=source.limits.minimum_sync_interval_seconds,
            now=self.now(),
        )

    def request_local_bundle(self, *, source_id: str, requested_by: str) -> dict[str, Any]:
        source = self.registry.source(source_id)
        return self.store.create_run(
            source_id=source.source_id,
            requested_by=requested_by,
            request_mode="local-reviewed-bundle",
            minimum_interval_seconds=source.limits.minimum_sync_interval_seconds,
            now=self.now(),
        )

    def _deadline_check(self, started: float, source: FeedSource) -> None:
        if self.clock() - started > source.limits.total_timeout_seconds:
            raise AdvisorySyncError("sync-timeout", "advisory synchronization exceeded the configured total timeout")

    def _deadline_remaining(self, started: float, source: FeedSource) -> float:
        remaining = source.limits.total_timeout_seconds - (self.clock() - started)
        if remaining <= 0:
            raise AdvisorySyncError("sync-timeout", "advisory synchronization exceeded the configured total timeout")
        return remaining

    def execute_remote_run(self, run_id: str) -> dict[str, Any]:
        run = self.store.get_run(run_id)
        if run["request_mode"] != "remote-sync":
            raise AdvisorySyncError("request-mode-invalid", "run is not a remote synchronization request")
        source = self.registry.source(str(run["source_id"]))
        started = self.clock()
        run_directory: Path | None = None
        try:
            self.store.transition(
                run_id,
                expected_states=("created",),
                state="downloading",
                values={"started_at": self.now()},
                now=self.now(),
            )
            run_directory = self.staging.create_run_directory(run_id)
            manifest = self.downloader.fetch(
                source,
                "manifest",
                total_timeout_seconds=self._deadline_remaining(started, source),
            )
            signature = self.downloader.fetch(
                source,
                "signature",
                total_timeout_seconds=self._deadline_remaining(started, source),
            )
            self._deadline_check(started, source)
            self.store.transition(run_id, expected_states=("downloading",), state="downloaded", now=self.now())
            self.store.transition(run_id, expected_states=("downloaded",), state="verifying", now=self.now())
            # Authenticate exact manifest bytes before retrieving the larger payload.
            verify_manifest(
                manifest_bytes=manifest.body,
                signature_bytes=signature.body,
                source=source,
                registry=self.registry,
                now=self.now(),
            )
            payload = self.downloader.fetch(
                source,
                "payload",
                total_timeout_seconds=self._deadline_remaining(started, source),
            )
            self._deadline_check(started, source)
            return self._verify_and_retain(
                run_id=run_id,
                source=source,
                run_directory=run_directory,
                manifest_bytes=manifest.body,
                signature_bytes=signature.body,
                payload_bytes=payload.body,
            )
        except Exception as exc:
            code, summary = _known_error(exc)
            self.store.fail_run(run_id, code=code, summary=summary, now=self.now())
            raise AdvisorySyncError(code, summary) from exc
        finally:
            if run_directory is not None and run_directory.exists():
                try:
                    self.staging.cleanup(run_directory)
                except StagingSecurityError as cleanup_exc:
                    LOGGER.error("advisory staging cleanup failed safely: %s", cleanup_exc.code)

    def _fixture_directory(self, source: FeedSource) -> Path:
        candidate = self.fixture_root / source.source_id
        try:
            candidate.relative_to(self.fixture_root)
            info = candidate.lstat()
        except (ValueError, OSError) as exc:
            raise AdvisorySyncError("local-bundle-unavailable", "reviewed local signed bundle is unavailable") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise AdvisorySyncError("local-bundle-unsafe", "reviewed local bundle path is not a directory")
        return candidate

    def execute_local_run(self, run_id: str) -> dict[str, Any]:
        run = self.store.get_run(run_id)
        if run["request_mode"] != "local-reviewed-bundle":
            raise AdvisorySyncError("request-mode-invalid", "run is not a reviewed local bundle request")
        source = self.registry.source(str(run["source_id"]))
        started = self.clock()
        run_directory: Path | None = None
        try:
            self.store.transition(
                run_id,
                expected_states=("created",),
                state="downloading",
                values={"started_at": self.now()},
                now=self.now(),
            )
            fixture = self._fixture_directory(source)
            manifest_bytes = read_single_link_file(
                fixture / "manifest.json",
                maximum_bytes=source.limits.maximum_manifest_bytes,
            )
            signature_bytes = read_single_link_file(
                fixture / "manifest.ed25519",
                maximum_bytes=source.limits.maximum_signature_bytes,
            )
            self._deadline_check(started, source)
            self.store.transition(run_id, expected_states=("downloading",), state="downloaded", now=self.now())
            self.store.transition(run_id, expected_states=("downloaded",), state="verifying", now=self.now())
            verify_manifest(
                manifest_bytes=manifest_bytes,
                signature_bytes=signature_bytes,
                source=source,
                registry=self.registry,
                now=self.now(),
            )
            payload_bytes = read_single_link_file(
                fixture / source.expected_payload_name,
                maximum_bytes=source.limits.maximum_compressed_bytes,
            )
            self._deadline_check(started, source)
            run_directory = self.staging.create_run_directory(run_id)
            return self._verify_and_retain(
                run_id=run_id,
                source=source,
                run_directory=run_directory,
                manifest_bytes=manifest_bytes,
                signature_bytes=signature_bytes,
                payload_bytes=payload_bytes,
            )
        except Exception as exc:
            code, summary = _known_error(exc)
            self.store.fail_run(run_id, code=code, summary=summary, now=self.now())
            raise AdvisorySyncError(code, summary) from exc
        finally:
            if run_directory is not None and run_directory.exists():
                try:
                    self.staging.cleanup(run_directory)
                except StagingSecurityError as cleanup_exc:
                    LOGGER.error("advisory staging cleanup failed safely: %s", cleanup_exc.code)

    def _verify_and_retain(
        self,
        *,
        run_id: str,
        source: FeedSource,
        run_directory: Path,
        manifest_bytes: bytes,
        signature_bytes: bytes,
        payload_bytes: bytes,
    ) -> dict[str, Any]:
        self.staging.write_artifact(run_directory, "manifest.json", manifest_bytes)
        self.staging.write_artifact(run_directory, "manifest.ed25519", signature_bytes)
        self.staging.write_artifact(run_directory, "payload.bin", payload_bytes)
        bundle = verify_bundle(
            manifest_bytes=manifest_bytes,
            signature_bytes=signature_bytes,
            payload_bytes=payload_bytes,
            source=source,
            registry=self.registry,
            now=self.now(),
        )
        adapter = ADAPTERS.get(source.adapter_type)
        if adapter is None or adapter.adapter_version != source.adapter_version:
            raise AdvisorySyncError("adapter-unavailable", "reviewed source adapter is unavailable")
        catalog_bytes = adapter.catalog_bytes(bundle)
        previous_item = self.store.active_catalog(source.source_id, include_bytes=True)
        previous_catalog = _parse_retained_catalog(previous_item)[0] if previous_item else None
        preview = preview_bundle(bundle, previous_catalog=previous_catalog, now=self.now()).as_dict()
        # Remove private staging before making the verified run available for approval.
        self.staging.cleanup(run_directory)
        aliases = sum(len(record.aliases) for record in bundle.catalog.advisories)
        references = sum(len(record.references) for record in bundle.catalog.advisories)
        self.store.save_verified_bundle(
            run_id=run_id,
            source_id=source.source_id,
            catalog_version=bundle.manifest.catalog_version,
            catalog_sequence=bundle.manifest.catalog_sequence,
            manifest_digest=bundle.manifest_digest,
            payload_digest=bundle.payload_digest,
            catalog_checksum=bundle.catalog_checksum,
            publisher_key_id=bundle.manifest.publisher_key_id,
            license_identifier=bundle.manifest.license_identifier,
            attribution=bundle.manifest.attribution,
            provenance=bundle.manifest.upstream_provenance.model_dump(mode="json"),
            manifest_created_at=bundle.manifest.created_at,
            manifest_expires_at=bundle.manifest.expires_at,
            manifest_bytes=bundle.manifest_bytes,
            signature_bytes=bundle.signature,
            payload_bytes=bundle.payload_bytes,
            catalog_bytes=catalog_bytes,
            preview=preview,
            advisory_count=len(bundle.catalog.advisories),
            alias_count=aliases,
            reference_count=references,
            now=self.now(),
        )
        return self.store.get_run(run_id, include_preview=True)

    def approve(self, run_id: str, *, actor: str) -> dict[str, Any]:
        return self.store.approve(run_id, actor=actor, now=self.now())

    def reject(self, run_id: str, *, actor: str, reason: str) -> dict[str, Any]:
        return self.store.reject(run_id, actor=actor, reason=reason, now=self.now())

    def _publisher_allows_activation(self, source: FeedSource, key_id: str, *, rollback: bool) -> None:
        try:
            key = self.registry.publisher_key(key_id)
        except RegistryError as exc:
            raise AdvisorySyncError(exc.code, exc.summary) from exc
        if key_id not in source.trusted_publisher_key_ids:
            raise AdvisorySyncError("publisher-substitution", "retained catalog publisher is no longer approved for this source")
        if key.status == "revoked":
            raise AdvisorySyncError("publisher-key-revoked", "catalog publisher key has been revoked")
        if not rollback and key.status != "active":
            raise AdvisorySyncError("publisher-key-retired", "retired publisher keys cannot activate a new remote catalog")
        current = self.now()
        if not rollback and key.not_after and current >= key.not_after:
            raise AdvisorySyncError("publisher-key-expired", "catalog publisher key expired before activation")

    def activate(self, run_id: str, *, actor: str) -> dict[str, Any]:
        retained = self.store.catalog_for_run(run_id, include_bytes=True)
        source = self.registry.source(str(retained["source_id"]))
        self._publisher_allows_activation(source, str(retained["publisher_key_id"]), rollback=False)
        catalog, checksum = _parse_retained_catalog(retained)
        result = self.store.activate_run(
            run_id,
            catalog=catalog,
            catalog_checksum=checksum,
            actor=actor,
            now=self.now(),
        )
        result["reevaluation"] = self._reevaluate_activation(result, actor=actor)
        return result

    def rollback(self, catalog_id: str, *, actor: str) -> dict[str, Any]:
        retained = self.store.get_catalog(catalog_id, include_bytes=True)
        source = self.registry.source(str(retained["source_id"]))
        self._publisher_allows_activation(source, str(retained["publisher_key_id"]), rollback=True)
        catalog, checksum = _parse_retained_catalog(retained)
        result = self.store.rollback_catalog(
            catalog_id,
            catalog=catalog,
            catalog_checksum=checksum,
            actor=actor,
            cooldown_seconds=source.limits.control_action_cooldown_seconds,
            now=self.now(),
        )
        result["reevaluation"] = self._reevaluate_activation(result, actor=actor)
        return result

    def retry_reevaluation(self, activation_id: str, *, actor: str) -> dict[str, Any]:
        activation = self.store.get_activation(activation_id)
        if activation["reevaluation_status"] != "failed":
            raise AdvisorySyncError("reevaluation-state-conflict", "only a failed catalog reevaluation can be retried")
        result = {
            **activation,
            "preview": self.store.get_catalog(str(activation["catalog_id"]))["preview"],
        }
        result["reevaluation"] = self._reevaluate_activation(result, actor=actor)
        return result

    def _reevaluate_activation(self, activation: dict[str, Any], *, actor: str) -> dict[str, Any]:
        activation_id = str(activation["activation_id"])
        run_ids: list[str] = []
        try:
            self.store.mark_reevaluation(activation_id, status="running")
            current_item = self.store.get_catalog(str(activation["catalog_id"]), include_bytes=True)
            current_catalog, _ = _parse_retained_catalog(current_item)
            previous_catalog = None
            if activation.get("previous_catalog_id"):
                previous_item = self.store.get_catalog(str(activation["previous_catalog_id"]), include_bytes=True)
                previous_catalog, _ = _parse_retained_catalog(previous_item)
            record_ids = changed_record_ids(current_catalog, previous_catalog)
            server_ids = [
                advisory_id_for(
                    source=current_catalog.source.name,
                    source_record_id=record_id,
                )
                for record_id in record_ids
            ]
            if server_ids:
                chunks = [
                    server_ids[index : index + MAX_TARGETED_ADVISORIES]
                    for index in range(0, len(server_ids), MAX_TARGETED_ADVISORIES)
                ]
                details = {
                    "trigger_type": f"advisory-catalog-{activation['action']}",
                    "component_count": 0,
                    "advisory_count": 0,
                    "candidate_count": 0,
                    "affected_count": 0,
                    "changed_count": 0,
                    "chunk_count": len(chunks),
                }
                for index, chunk in enumerate(chunks):
                    final_chunk = index == len(chunks) - 1
                    advisory_rows = self.advisory_store.list_advisories_for_matching(
                        advisory_ids=chunk,
                        limit=200_001,
                    )
                    evaluation = self.evaluator(
                        trigger_type=f"advisory-catalog-{activation['action']}",
                        requested_by=actor,
                        advisory_rows=advisory_rows,
                        reconcile_advisory_ids=chunk,
                        update_findings=final_chunk,
                        raise_finding_errors=final_chunk,
                    )
                    run_ids.append(str(evaluation.run_id))
                    chunk_details = evaluation.as_dict()
                    details["component_count"] = max(
                        int(details["component_count"]),
                        int(chunk_details.get("component_count", 0)),
                    )
                    for field in (
                        "advisory_count",
                        "candidate_count",
                        "affected_count",
                        "changed_count",
                    ):
                        details[field] = int(details[field]) + int(chunk_details.get(field, 0))
            else:
                details = {
                    "trigger_type": f"advisory-catalog-{activation['action']}",
                    "component_count": 0,
                    "advisory_count": 0,
                    "candidate_count": 0,
                    "affected_count": 0,
                    "changed_count": 0,
                }
            self.store.mark_reevaluation(
                activation_id,
                status="completed",
                run_ids=run_ids,
                impact=details,
            )
            return {"status": "completed", "run_ids": run_ids, "details": details}
        except Exception as exc:  # Catalog stays active; record a retryable degraded state.
            code, _ = _known_error(exc)
            try:
                self.store.mark_reevaluation(
                    activation_id,
                    status="failed",
                    run_ids=run_ids,
                    error_code=code,
                )
            except Exception as record_exc:  # noqa: BLE001
                LOGGER.error("catalog reevaluation failure could not be recorded safely: %s", type(record_exc).__name__)
            return {"status": "failed", "run_ids": run_ids, "error_code": code}
