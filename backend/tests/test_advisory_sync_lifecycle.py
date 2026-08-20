from __future__ import annotations

import hashlib
import inspect
import os
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException
from pydantic import ValidationError

from app.advisory_feed_registry import load_reviewed_feed_registry
from app.advisory_sync_contracts import AdvisoryApprovalRequest, AdvisorySyncRequest
from app.advisory_sync_service import (
    MAX_TARGETED_ADVISORIES,
    AdvisorySyncError,
    AdvisorySyncService,
    changed_record_ids,
)
from app.advisory_sync_store import (
    ADVISORY_SYNC_SCHEMA_SQL,
    AdvisorySyncStoreError,
    _require_activation_preview_baseline,
)
from app.advisory_transport import DownloadSecurityError, PrivateStagingArea
from app.main import (
    ADVISORY_API_ACTOR,
    ADMIN_TOKEN_ENV,
    admin_approve_advisory_feed_run,
    admin_advisory_feed_runs,
    admin_advisory_feeds,
)


NOW = datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc)
SOURCE_ID = "openassetwatch-synthetic-signed"


class MemoryLifecycleStore:
    """Small deterministic service seam; production coordination remains SQL-backed."""

    def __init__(self) -> None:
        self.runs: dict[str, dict] = {}
        self.catalogs: dict[str, dict] = {}
        self.activations: dict[str, dict] = {}
        self.next_run = 1
        self.next_catalog = 1
        self.next_activation = 1

    def create_run(self, *, source_id, requested_by, request_mode, minimum_interval_seconds, now):
        if any(run["source_id"] == source_id and run["state"] not in {"failed", "rejected", "activated", "activated_degraded"} for run in self.runs.values()):
            raise AdvisorySyncStoreError("sync-already-active", "an advisory synchronization is already active")
        run_id = f"afrun_{self.next_run:032x}"
        self.next_run += 1
        run = {
            "run_id": run_id,
            "source_id": source_id,
            "requested_by": requested_by,
            "request_mode": request_mode,
            "state": "created",
            "created_at": now,
        }
        self.runs[run_id] = run
        return deepcopy(run)

    def get_run(self, run_id, include_preview=False):
        run = deepcopy(self.runs[run_id])
        if not include_preview:
            run.pop("preview", None)
        return run

    def transition(self, run_id, *, expected_states, state, values=None, now=None):
        if self.runs[run_id]["state"] not in expected_states:
            raise AdvisorySyncStoreError("run-state-conflict", "run changed state")
        self.runs[run_id].update(values or {})
        self.runs[run_id]["state"] = state

    def fail_run(self, run_id, *, code, summary, now):
        self.runs[run_id].update(state="failed", error_code=code, error_summary=summary, completed_at=now)

    def active_catalog(self, source_id, include_bytes=False):
        for catalog in self.catalogs.values():
            if catalog["source_id"] == source_id and catalog["active"]:
                return deepcopy(catalog)
        return None

    def save_verified_bundle(self, **values):
        run_id = values.pop("run_id")
        catalog_id = f"afcat_{self.next_catalog:032x}"
        self.next_catalog += 1
        catalog = {"catalog_id": catalog_id, "run_id": run_id, "active": False, "activation_count": 0, **values}
        self.catalogs[catalog_id] = catalog
        self.runs[run_id].update(
            state="pending_approval",
            preview=values["preview"],
            catalog_version=values["catalog_version"],
            publisher_key_id=values["publisher_key_id"],
            signature_status="verified",
            license_status="approved",
            attribution_status="present",
        )
        return deepcopy(catalog)

    def catalog_for_run(self, run_id, include_bytes=False):
        return deepcopy(next(item for item in self.catalogs.values() if item["run_id"] == run_id))

    def get_catalog(self, catalog_id, include_bytes=False):
        return deepcopy(self.catalogs[catalog_id])

    def approve(self, run_id, *, actor, now):
        if self.runs[run_id]["state"] != "pending_approval":
            raise AdvisorySyncStoreError("run-state-conflict", "run is not pending")
        self.runs[run_id].update(state="approved", approved_by=actor, approved_at=now)
        return self.get_run(run_id)

    def reject(self, run_id, *, actor, reason, now):
        if self.runs[run_id]["state"] != "pending_approval":
            raise AdvisorySyncStoreError("run-state-conflict", "run is not pending")
        self.runs[run_id].update(state="rejected", rejected_by=actor, rejection_reason=reason)
        return self.get_run(run_id)

    def activate_run(self, run_id, *, catalog, catalog_checksum, actor, now):
        if self.runs[run_id]["state"] != "approved":
            raise AdvisorySyncStoreError("run-state-conflict", "run is not approved")
        target = next(item for item in self.catalogs.values() if item["run_id"] == run_id)
        if hashlib.sha256(target["catalog_bytes"]).hexdigest() != catalog_checksum:
            raise AdvisorySyncStoreError("retained-catalog-digest-invalid", "digest failed")
        previous = next((item["catalog_id"] for item in self.catalogs.values() if item["active"]), None)
        for item in self.catalogs.values():
            item["active"] = False
        target["active"] = True
        target["activation_count"] += 1
        self.runs[run_id]["state"] = "activated"
        activation_id = f"afact_{self.next_activation:032x}"
        self.next_activation += 1
        result = {
            "activation_id": activation_id,
            "action": "activate",
            "source_id": target["source_id"],
            "catalog_id": target["catalog_id"],
            "previous_catalog_id": previous,
            "preview": target["preview"],
            "reevaluation_status": "pending",
        }
        self.activations[activation_id] = deepcopy(result)
        return result

    def rollback_catalog(self, catalog_id, *, catalog, catalog_checksum, actor, cooldown_seconds, now):
        target = self.catalogs[catalog_id]
        if target["activation_count"] < 1 or target["active"]:
            raise AdvisorySyncStoreError("rollback-target-invalid", "target is not eligible")
        if hashlib.sha256(target["catalog_bytes"]).hexdigest() != catalog_checksum:
            raise AdvisorySyncStoreError("retained-catalog-digest-invalid", "digest failed")
        previous = next(item["catalog_id"] for item in self.catalogs.values() if item["active"])
        for item in self.catalogs.values():
            item["active"] = False
        target["active"] = True
        target["activation_count"] += 1
        activation_id = f"afact_{self.next_activation:032x}"
        self.next_activation += 1
        result = {
            "activation_id": activation_id,
            "action": "rollback",
            "source_id": target["source_id"],
            "catalog_id": catalog_id,
            "previous_catalog_id": previous,
            "preview": target["preview"],
            "reevaluation_status": "pending",
        }
        self.activations[activation_id] = deepcopy(result)
        return result

    def mark_reevaluation(self, activation_id, *, status, run_ids=(), error_code=None, impact=None):
        self.activations[activation_id].update(
            reevaluation_status=status,
            reevaluation_run_ids=list(run_ids),
            error_code=error_code,
            impact=impact or {},
        )

    def get_activation(self, activation_id):
        return deepcopy(self.activations[activation_id])

    def source_status(self, source_id):
        return {"source_id": source_id, "active_catalog": self.active_catalog(source_id), "pending_approval_count": 0}


class _AdvisoryRows:
    def list_advisories_for_matching(self, *, advisory_ids, limit):
        return [{"advisory_id": value} for value in advisory_ids]


class AdvisoryLifecycleTests(unittest.TestCase):
    def make_service(self, store, staging_root):
        def evaluator(**kwargs):
            return SimpleNamespace(run_id="vrun_test", as_dict=lambda: {"changed_count": len(kwargs["advisory_rows"])})

        return AdvisorySyncService(
            registry=load_reviewed_feed_registry(),
            store=store,
            staging=PrivateStagingArea(staging_root),
            evaluator=evaluator,
            advisory_store=_AdvisoryRows(),
            now=lambda: NOW,
        )

    def test_local_signed_preview_approval_activation_reevaluation_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = MemoryLifecycleStore()
            service = self.make_service(store, Path(directory) / "staging")
            run = service.request_local_bundle(source_id=SOURCE_ID, requested_by="unit-test")
            verified = service.execute_local_run(run["run_id"])
            self.assertEqual(verified["state"], "pending_approval")
            self.assertEqual(verified["preview"]["signature_status"], "verified")
            service.approve(run["run_id"], actor="reviewer")
            activated = service.activate(run["run_id"], actor="reviewer")
            self.assertEqual(activated["reevaluation"]["status"], "completed")
            self.assertEqual(store.runs[run["run_id"]]["state"], "activated")
            first_catalog = activated["catalog_id"]

            second_id = "afcat_" + "f" * 32
            store.catalogs[second_id] = {**deepcopy(store.catalogs[first_catalog]), "catalog_id": second_id, "active": True, "activation_count": 1}
            store.catalogs[first_catalog]["active"] = False
            rolled_back = service.rollback(first_catalog, actor="reviewer")
            self.assertEqual(rolled_back["action"], "rollback")
            self.assertEqual(rolled_back["reevaluation"]["status"], "completed")
            self.assertTrue(store.catalogs[first_catalog]["active"])

    def test_rejection_and_failed_sync_leave_last_known_good_active(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = MemoryLifecycleStore()
            service = self.make_service(store, Path(directory) / "staging")
            run = service.request_local_bundle(source_id=SOURCE_ID, requested_by="unit-test")
            service.execute_local_run(run["run_id"])
            service.reject(run["run_id"], actor="reviewer", reason="preview requires correction")
            self.assertEqual(store.runs[run["run_id"]]["state"], "rejected")

            retained = next(iter(store.catalogs.values()))
            retained["active"] = True
            retained["activation_count"] = 1
            failed = service.request_sync(source_id=SOURCE_ID, requested_by="unit-test")
            service.downloader = Mock()
            service.downloader.fetch.side_effect = DownloadSecurityError(
                "offline",
                "synthetic offline test",
            )
            with self.assertRaises(AdvisorySyncError):
                service.execute_remote_run(failed["run_id"])
            self.assertTrue(retained["active"])
            self.assertEqual(store.runs[failed["run_id"]]["state"], "failed")

    def test_service_seam_enforces_single_flight(self) -> None:
        store = MemoryLifecycleStore()
        first = store.create_run(
            source_id=SOURCE_ID,
            requested_by="worker-one",
            request_mode="remote-sync",
            minimum_interval_seconds=0,
            now=NOW,
        )
        self.assertTrue(first["run_id"].startswith("afrun_"))
        with self.assertRaisesRegex(AdvisorySyncStoreError, "active"):
            store.create_run(
                source_id=SOURCE_ID,
                requested_by="worker-two",
                request_mode="remote-sync",
                minimum_interval_seconds=0,
                now=NOW,
            )

    def test_production_schema_has_database_single_flight_replay_and_activation_locks(self) -> None:
        schema = "\n".join(ADVISORY_SYNC_SCHEMA_SQL)
        from app import advisory_sync_store

        source = inspect.getsource(advisory_sync_store.SqlAdvisorySyncStore)
        static_schema = (
            Path(__file__).resolve().parents[1]
            / "app"
            / "migration_sql"
            / "0001_current_schema_baseline.sql"
        ).read_text(encoding="utf-8")
        self.assertIn("idx_advisory_feed_runs_active_source", schema)
        self.assertIn("UNIQUE (source_id, catalog_sequence)", schema)
        self.assertIn("UNIQUE (source_id, manifest_digest)", schema)
        self.assertIn("impact_json JSONB", schema)
        self.assertIn("impact_json JSONB", static_schema)
        self.assertIn("idx_advisory_feed_runs_active_source", static_schema)
        self.assertIn("pg_advisory_xact_lock", source)
        self.assertIn("openassetwatch-advisory-activation", source)
        self.assertIn("catalog-downgrade", source)
        self.assertIn("manifest-replay", source)
        self.assertIn("catalog-retention-limit", source)
        self.assertIn("FROM advisory_catalog_activations", source)

    def test_preview_baseline_must_still_be_active(self) -> None:
        _require_activation_preview_baseline("afcat_" + "a" * 32, "afcat_" + "a" * 32)
        with self.assertRaisesRegex(AdvisorySyncStoreError, "fresh preview") as raised:
            _require_activation_preview_baseline("afcat_" + "a" * 32, "afcat_" + "b" * 32)
        self.assertEqual(raised.exception.code, "activation-preview-stale")

    def test_maximum_catalog_transition_is_chunked_for_reevaluation(self) -> None:
        current = SimpleNamespace(
            source=SimpleNamespace(name="OpenAssetWatch Synthetic Security Advisories"),
            advisories=[SimpleNamespace(id=f"NEW-{index:05d}") for index in range(MAX_TARGETED_ADVISORIES)]
        )
        previous = SimpleNamespace(
            source=SimpleNamespace(name="OpenAssetWatch Synthetic Security Advisories"),
            advisories=[SimpleNamespace(id=f"OLD-{index:05d}") for index in range(MAX_TARGETED_ADVISORIES)]
        )
        record_ids = changed_record_ids(current, previous)
        self.assertEqual(len(record_ids), MAX_TARGETED_ADVISORIES * 2)

        store = Mock()
        store.get_catalog.side_effect = [
            {"catalog_bytes": b"current", "catalog_checksum": "current"},
            {"catalog_bytes": b"previous", "catalog_checksum": "previous"},
        ]
        evaluator = Mock(
            side_effect=lambda **kwargs: SimpleNamespace(
                run_id=f"vrun_{len(kwargs['reconcile_advisory_ids'])}_{kwargs['update_findings']}",
                as_dict=lambda: {
                    "component_count": 7,
                    "advisory_count": len(kwargs["reconcile_advisory_ids"]),
                    "candidate_count": len(kwargs["reconcile_advisory_ids"]),
                    "affected_count": 1,
                    "changed_count": 1,
                },
            )
        )
        service = AdvisorySyncService.__new__(AdvisorySyncService)
        service.store = store
        service.advisory_store = _AdvisoryRows()
        service.evaluator = evaluator
        with (
            patch("app.advisory_sync_service._parse_retained_catalog", side_effect=[(current, "current"), (previous, "previous")]),
            patch("app.advisory_sync_service.changed_record_ids", return_value=record_ids),
        ):
            result = service._reevaluate_activation(
                {
                    "activation_id": "afact_" + "a" * 32,
                    "action": "activate",
                    "catalog_id": "afcat_" + "a" * 32,
                    "previous_catalog_id": "afcat_" + "b" * 32,
                },
                actor="unit-test",
            )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(evaluator.call_count, 2)
        first, second = [call.kwargs for call in evaluator.call_args_list]
        self.assertLessEqual(len(first["reconcile_advisory_ids"]), MAX_TARGETED_ADVISORIES)
        self.assertLessEqual(len(second["reconcile_advisory_ids"]), MAX_TARGETED_ADVISORIES)
        self.assertFalse(first["update_findings"])
        self.assertFalse(first["raise_finding_errors"])
        self.assertTrue(second["update_findings"])
        self.assertTrue(second["raise_finding_errors"])
        self.assertEqual(result["details"]["chunk_count"], 2)


class AdvisorySyncApiTests(unittest.TestCase):
    def test_client_supplied_advisory_audit_actor_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            AdvisorySyncRequest.model_validate({"requested_by": "spoofed-admin"})
        with self.assertRaises(ValidationError):
            AdvisoryApprovalRequest.model_validate({"actor": "spoofed-admin"})

        service = Mock()
        service.approve.return_value = {"state": "approved"}
        with (
            patch.dict(os.environ, {ADMIN_TOKEN_ENV: "configured-secret"}, clear=True),
            patch("app.main._advisory_sync_service", return_value=service),
        ):
            admin_approve_advisory_feed_run(
                payload=AdvisoryApprovalRequest(),
                run_id="afrun_" + "a" * 32,
                admin_token="configured-secret",
            )
        service.approve.assert_called_once_with(
            "afrun_" + "a" * 32,
            actor=ADVISORY_API_ACTOR,
        )

    def test_admin_authentication_fails_closed(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(HTTPException) as raised:
                admin_advisory_feeds(admin_token=None)
        self.assertEqual(raised.exception.status_code, 503)

        with patch.dict(os.environ, {ADMIN_TOKEN_ENV: "configured-secret"}, clear=True):
            with self.assertRaises(HTTPException) as raised:
                admin_advisory_feeds(admin_token="wrong")
        self.assertEqual(raised.exception.status_code, 401)

    def test_source_and_run_responses_are_bounded_and_filtered(self) -> None:
        service = Mock()
        service.list_sources.return_value = [{"source_id": SOURCE_ID, "enabled": True}]
        store = Mock()
        store.list_runs.return_value = {"items": [], "total": 0, "limit": 10, "offset": 0, "truncated": False}
        with (
            patch.dict(os.environ, {ADMIN_TOKEN_ENV: "configured-secret"}, clear=True),
            patch("app.main._advisory_sync_service", return_value=service),
            patch("app.main._advisory_sync_store", return_value=store),
        ):
            feeds = admin_advisory_feeds(admin_token="configured-secret")
            runs = admin_advisory_feed_runs(
                source_id=SOURCE_ID,
                state="pending_approval",
                limit=10,
                offset=0,
                admin_token="configured-secret",
            )
        self.assertEqual(feeds["items"][0]["source_id"], SOURCE_ID)
        self.assertEqual(runs["limit"], 10)
        store.list_runs.assert_called_once_with(source_id=SOURCE_ID, state="pending_approval", limit=10, offset=0)


if __name__ == "__main__":
    unittest.main()
