from __future__ import annotations

import base64
import http.server
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

ENABLED = os.getenv("OPENASSETWATCH_MIRROR_POSTGRES_TEST") == "1"
if ENABLED:
    database_name = os.environ["OPENASSETWATCH_MIRROR_POSTGRES_DATABASE"]
    base_url = os.environ["DATABASE_URL"].rsplit("/", 1)[0]
    os.environ["DATABASE_URL"] = f"{base_url}/{database_name}"

from app.advisory_feed_registry import FeedRegistryDocument, FeedSource, ReviewedFeedRegistry  # noqa: E402
from app.advisory_mirror import build_advisory_mirror  # noqa: E402
from app.advisory_store import SqlAdvisoryStore  # noqa: E402
from app.advisory_sync_service import AdvisorySyncError, AdvisorySyncService  # noqa: E402
from app.advisory_sync_store import SqlAdvisorySyncStore  # noqa: E402
from app.advisory_transport import PrivateStagingArea  # noqa: E402
from app.database import ensure_database_schema  # noqa: E402
from app.osv_pypi_publisher import (  # noqa: E402
    DirectoryOsvSource,
    PublishRequest,
    PublisherLimits,
    publish_once,
)
from demo_advisory_mirror import (  # noqa: E402
    INDEX_KEY_ID,
    NOW,
    _LoopbackMirrorDownloader,
    _MirrorRequestHandler,
    _mirror_registry,
)
from demo_osv_pypi_publisher import (  # noqa: E402
    KEY_ENV,
    KEY_ID,
    SYNTHETIC_DEMO_POLICY,
    _Evaluation,
    _write_fixture,
    build_local_verification_registry,
)


@unittest.skipUnless(ENABLED, "requires an explicitly isolated PostgreSQL validation database")
class AdvisoryMirrorPostgresIntegrationTests(unittest.TestCase):
    def test_remote_mirror_preview_approval_activation_and_offline_lkg_persist(self) -> None:
        ensure_database_schema()
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
        with tempfile.TemporaryDirectory(prefix="oaw-mirror-postgres-test-") as temporary:
            root = Path(temporary)
            fixture = root / "fixture"
            fixture.mkdir(mode=0o700)
            _write_fixture(fixture, modified=NOW, fixed="2.0.0", versions=["1.0.0", "1.5.0"])
            published = publish_once(
                DirectoryOsvSource(fixture),
                PublishRequest(
                    state_path=root / "state" / "publisher-state.json",
                    output_root=root / "publisher-output",
                    full=True,
                    key_id=KEY_ID,
                    signing_key_env=KEY_ENV,
                ),
                limits=limits,
                policy=SYNTHETIC_DEMO_POLICY,
                now=lambda: NOW,
                environ=protected_environment,
            )
            self.assertIsNotNone(published.bundle_directory)
            bundle_registry, direct_source = build_local_verification_registry(
                policy=SYNTHETIC_DEMO_POLICY,
                key_id=KEY_ID,
                private_key=bundle_key,
            )
            registry, source = _mirror_registry(bundle_registry, direct_source, index_key)
            source_data = source.model_dump(mode="json")
            source_data["limits"]["minimum_sync_interval_seconds"] = 0
            source_data["limits"]["control_action_cooldown_seconds"] = 0
            source = FeedSource.model_validate(source_data)
            registry = ReviewedFeedRegistry(
                FeedRegistryDocument(
                    schema_version="oaw.advisory-feed-registry.v1",
                    registry_version="postgres-mirror-test",
                    sources=[source],
                ),
                registry.keyring_document,
            )
            mirror = (root / "mirror").absolute()
            build_advisory_mirror(
                bundle_directories=[published.bundle_directory.absolute()],
                output_directory=mirror,
                source=source,
                registry=registry,
                index_signing_key_id=INDEX_KEY_ID,
                index_signing_key=index_key,
                published_at=NOW,
            )

            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _MirrorRequestHandler)
            server.mirror_root = mirror  # type: ignore[attr-defined]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            counter = {"value": 0}

            def evaluator(**kwargs):
                counter["value"] += 1
                return _Evaluation(
                    "vrun_" + f"{counter['value']:032d}",
                    len(kwargs.get("advisory_rows", [])),
                )

            service = AdvisorySyncService(
                registry=registry,
                store=SqlAdvisorySyncStore(),
                downloader=_LoopbackMirrorDownloader(server.server_address[1]),
                staging=PrivateStagingArea((root / "private-staging").absolute()),
                evaluator=evaluator,
                advisory_store=SqlAdvisoryStore(),
                now=lambda: NOW,
            )
            try:
                requested = service.request_sync(source_id=source.source_id, requested_by="postgres-test")
                synchronized = service.execute_remote_run(requested["run_id"])
                self.assertEqual(synchronized["state"], "pending_approval")
                approved = service.approve(requested["run_id"], actor="postgres-test")
                self.assertEqual(approved["state"], "approved")
                activated = service.activate(requested["run_id"], actor="postgres-test")
                self.assertEqual(activated["reevaluation"]["status"], "completed")

                restarted_store = SqlAdvisorySyncStore()
                status = restarted_store.source_status(source.source_id)
                self.assertEqual(status["active_catalog"]["catalog_sequence"], 1)
                self.assertEqual(status["last_known_good_catalogs"][0]["catalog_sequence"], 1)

                server.shutdown()
                thread.join(timeout=5)
                failed = service.request_sync(source_id=source.source_id, requested_by="postgres-test")
                with self.assertRaises(AdvisorySyncError):
                    service.execute_remote_run(failed["run_id"])
                persisted = SqlAdvisorySyncStore().source_status(source.source_id)
                self.assertEqual(persisted["active_catalog"]["catalog_sequence"], 1)
                self.assertEqual(persisted["last_known_good_catalogs"][0]["catalog_sequence"], 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
