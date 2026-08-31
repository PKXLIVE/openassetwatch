import hashlib
import json
import logging
import os
import secrets
import threading
import time
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import BackgroundTasks, Body, Header, HTTPException, FastAPI, Path as ApiPath, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.exc import SQLAlchemyError

from . import database as database_module
from .ai_advisor import (
    AdvisorQueryRequest,
    AdvisorResponse,
    ProviderOutputError,
    ProviderStatusResponse,
    ProviderUnavailableError,
    ReadOnlyHubTools,
    provider_status,
    run_advisor,
    select_tools,
)

from .database import (
    LegacyAgentIdentityConflict,
    control_tower_summary,
    create_policy_assignment,
    create_agent_enrollment,
    create_site,
    find_assigned_collector_policy,
    get_engine,
    latest_inventory_submission,
    list_agent_checkins,
    list_agent_enrollments,
    list_assets,
    list_collectors,
    list_control_tower_assets,
    list_collector_policies,
    list_policy_assignments,
    list_sites,
    record_agent_checkin,
    record_ai_advisor_run,
    set_endpoint_inventory_reevaluation_state,
    upsert_collector_policy,
    upsert_collector_metadata,
)
from .canonical_ingestion import (
    CanonicalAdmissionRejected,
    CanonicalAuthorizationRejected,
    CanonicalIngestionRejected,
    CanonicalReplayConflict,
    endpoint_envelope,
    ingest as ingest_canonical_inventory,
    legacy_collector_envelope,
    sensor_envelope,
    transitional_envelope,
)
from .canonical_ingestion_store import (
    claim_evaluation_work as claim_canonical_evaluation_work,
    compatibility_status as canonical_compatibility_status,
    requeue_evaluation as requeue_canonical_evaluation,
    set_evaluation_state as set_canonical_evaluation_state,
)
from .endpoint_agent_contracts import (
    AgentCheckInRequest as BoundAgentCheckInRequest,
    AgentCheckInResponse as BoundAgentCheckInResponse,
    AgentCredentialIssueResponse,
    AgentCredentialListResponse,
    AgentEnrollmentCreateRequest as BoundAgentEnrollmentCreateRequest,
    AgentEnrollmentCreateResponse as BoundAgentEnrollmentCreateResponse,
    AgentEnrollmentExchangeRequest,
    AgentEnrollmentExchangeResponse,
    AgentEnrollmentListResponse as BoundAgentEnrollmentListResponse,
    AgentEnrollmentPublic as BoundAgentEnrollmentPublic,
    EndpointInventoryRequest,
    EndpointInventoryResponse,
)
from .endpoint_agent_identity import (
    AgentAuthenticationRejected,
    AgentEnrollmentRejected,
    AgentIdentityConflict as EndpointAgentIdentityConflict,
    AgentIdentityNotFound as EndpointAgentIdentityNotFound,
    authenticate_agent_request,
    create_agent_enrollment as create_bound_agent_enrollment,
    exchange_agent_enrollment,
    get_agent_enrollment as get_bound_agent_enrollment,
    list_agent_credentials,
    list_agent_enrollments as list_bound_agent_enrollments,
    list_agent_identity_audit,
    record_authenticated_agent_checkin,
    revoke_agent as revoke_bound_agent,
    revoke_agent_credential as revoke_bound_agent_credential,
    revoke_agent_enrollment as revoke_bound_agent_enrollment,
    rotate_agent_credential,
)
from .classification_contracts import (
    ClassificationEvaluateRequest,
    ClassificationEvaluationResponse,
    ClassificationEvidenceListResponse,
    ClassificationListResponse,
    ClassificationResponse,
    ClassificationSummaryResponse,
    VendorCatalogStatusResponse,
)
from .classification_service import (
    evaluate_assets_best_effort,
    evaluate_classifications,
)
from .classification_store import SqlClassificationStore
from .finding_contracts import (
    AssetRiskResponse,
    FindingAcknowledgeRequest,
    FindingEvaluateRequest,
    FindingEvaluationResponse,
    FindingListResponse,
    FindingResponse,
    FindingSuppressRequest,
    RiskSummaryResponse,
    RuleRegistryResponse,
    SiteRiskResponse,
)
from .finding_service import evaluate_findings, evaluate_site_best_effort
from .finding_store import SqlFindingStore
from .findings import RULESET_VERSION, rule_registry_public
from .hub_contracts import (
    ObservationBatchRequest,
    ObservationBatchResponse,
    SensorCheckInRequest,
    SensorCheckInResponse,
    SensorCredentialIssueResponse,
    SensorCredentialListResponse,
    SensorEnrollmentCreateRequest,
    SensorEnrollmentCreateResponse,
    SensorEnrollmentExchangeRequest,
    SensorEnrollmentExchangeResponse,
    SensorEnrollmentListResponse,
    SensorEnrollmentPublic,
    SensorSummaryResponse,
    SiteIntelligenceSummaryResponse,
)
from .sensor_identity import (
    SensorAuthenticationRejected,
    SensorEnrollmentRejected,
    SensorIdentityConflict,
    SensorIdentityNotFound,
    authenticate_sensor_request,
    create_sensor_enrollment,
    exchange_sensor_enrollment,
    get_sensor_enrollment,
    list_sensor_credentials,
    list_sensor_enrollments,
    list_sensor_identity_audit,
    record_sensor_checkin,
    revoke_sensor,
    revoke_sensor_credential,
    revoke_sensor_enrollment,
    rotate_sensor_credential,
)
from .vendor_catalog import configured_catalog_status
from .advisory_store import SqlAdvisoryStore
from .advisory_feed_registry import RegistryError
from .advisory_sync_contracts import (
    AdvisoryApprovalRequest,
    AdvisoryReevaluationRetryRequest,
    AdvisoryRejectionRequest,
    AdvisoryRollbackRequest,
    AdvisorySyncRequest,
)
from .advisory_sync_service import AdvisorySyncError, AdvisorySyncService
from .advisory_sync_store import AdvisorySyncStoreError, SqlAdvisorySyncStore
from .component_intelligence import SUPPORTED_ECOSYSTEMS, normalized_token
from .component_store import SqlComponentStore
from .vulnerability_contracts import (
    CatalogStatusResponse,
    ComponentListResponse,
    VulnerabilityEvaluateRequest,
    VulnerabilityEvaluationResponse,
    VulnerabilityListResponse,
)
from .vulnerability_service import (
    evaluate_site_vulnerabilities_best_effort,
    evaluate_vulnerabilities,
)
from .vulnerability_store import SqlVulnerabilityStore
from .kev_store import SqlKevStore
from .schema_migrations import (
    SchemaMigrationError,
    ensure_schema_ready,
    runtime_schema_readiness,
    set_runtime_migration_failure,
)
from .temporal_contracts import (
    METRIC_KEY_PATTERN,
    TemporalDeviationAssessment,
    TemporalExpectation,
    TemporalMetricRegistryResponse,
    TemporalSignalSeriesResponse,
    temporal_registry_public,
)
from .temporal_deviations import TemporalDeviationService
from .temporal_expectations import TemporalExpectationService
from .temporal_projection import (
    TemporalProjectionError,
    TemporalProjectionService,
    TemporalSiteNotFound,
)
from .temporal_store import SqlTemporalStore


LOGGER = logging.getLogger(__name__)


@asynccontextmanager
async def application_lifespan(_application: FastAPI):
    """Establish schema compatibility before the API accepts requests."""

    try:
        ensure_schema_ready(get_engine())
    except SchemaMigrationError as exc:
        LOGGER.error("database schema startup failed: %s", exc.code)
        raise RuntimeError(
            f"database schema startup failed ({exc.code})"
        ) from None
    except Exception as exc:
        code = f"database-{type(exc).__name__.lower()}"[:80]
        set_runtime_migration_failure(code)
        LOGGER.error("database schema startup failed: %s", code)
        raise RuntimeError(
            f"database schema startup failed ({code})"
        ) from None
    yield


app = FastAPI(
    title="OpenAssetWatch API",
    description="Open-source family network asset intelligence platform.",
    version="0.1.0",
    lifespan=application_lifespan,
)


class BoundedRequestBodyMiddleware:
    """Enforce sensitive ingestion limits even for chunked request bodies."""

    LIMITS = {
        "/api/v1/agents/enroll": 8 << 10,
        "/api/v1/agents/check-in": 16 << 10,
        "/api/v1/agents/inventory": 4 << 20,
        "/api/v1/sensors/enroll": 8 << 10,
        "/api/v1/sensors/check-in": 16 << 10,
        "/api/v1/observations/batches": 2 << 20,
        "/api/v1/collections/local-inventory": 4 << 20,
        "/api/v1/collectors/inventory": 4 << 20,
        "/api/v1/admin/classifications/evaluate": 64 << 10,
        "/api/v1/admin/vulnerabilities/evaluate": 64 << 10,
        "/api/v1/admin/vulnerabilities/import": 8 << 20,
        "/api/v1/admin/kev/evaluate": 8 << 10,
    }
    PREFIX_LIMITS = {
        "/api/v1/admin/advisory-feed": 16 << 10,
        "/api/v1/admin/advisory-catalog": 16 << 10,
    }

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path") or "")
        limit = self.LIMITS.get(path)
        if limit is None:
            limit = next(
                (
                    value
                    for prefix, value in self.PREFIX_LIMITS.items()
                    if path.startswith(prefix)
                ),
                None,
            )
        if limit is None:
            await self.app(scope, receive, send)
            return
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length is not None:
            try:
                declared = int(content_length.decode("ascii"), 10)
            except (UnicodeDecodeError, ValueError):
                response = JSONResponse(status_code=400, content={"detail": "invalid request metadata"})
                await response(scope, receive, send)
                return
            if declared < 0 or declared > limit:
                response = JSONResponse(status_code=413, content={"detail": "request body is too large"})
                await response(scope, receive, send)
                return

        buffered = bytearray()
        while True:
            message = await receive()
            if message.get("type") != "http.request":
                async def disconnected_receive() -> dict[str, Any]:
                    return message

                await self.app(scope, disconnected_receive, send)
                return
            buffered.extend(message.get("body", b""))
            if len(buffered) > limit:
                response = JSONResponse(status_code=413, content={"detail": "request body is too large"})
                await response(scope, receive, send)
                return
            if not message.get("more_body", False):
                break
        replayed = False

        async def replay_receive() -> dict[str, Any]:
            nonlocal replayed
            if replayed:
                return {"type": "http.disconnect"}
            replayed = True
            return {"type": "http.request", "body": bytes(buffered), "more_body": False}

        await self.app(scope, replay_receive, send)


app.add_middleware(BoundedRequestBodyMiddleware)


CONTROL_TOWER_VERSION = os.getenv("OPENASSETWATCH_CONTROL_TOWER_VERSION", "0.1.0")
EXPECTED_AGENT_VERSION = os.getenv("OPENASSETWATCH_EXPECTED_AGENT_VERSION", "0.1.0")
AGENT_RELEASE_CHANNEL = os.getenv("OPENASSETWATCH_AGENT_RELEASE_CHANNEL", "local")
UI_STATIC_DIR = Path(__file__).resolve().parent / "static"

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "OPENASSETWATCH_CORS_ORIGINS",
        "http://localhost:8080,http://127.0.0.1:8080,http://localhost:8000,http://127.0.0.1:8000",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=[
        "Content-Type",
        "X-OpenAssetWatch-Collector-Token",
        "X-OpenAssetWatch-Agent-Credential",
        "X-OpenAssetWatch-Admin-Token",
    ],
)

if UI_STATIC_DIR.exists():
    app.mount("/ui/static", StaticFiles(directory=UI_STATIC_DIR), name="control-tower-static")


COLLECTOR_TOKEN_ENV = "OPENASSETWATCH_COLLECTOR_TOKEN"
COLLECTOR_TOKEN_HEADER = "X-OpenAssetWatch-Collector-Token"
AGENT_CREDENTIAL_HEADER = "X-OpenAssetWatch-Agent-Credential"
ADMIN_TOKEN_ENV = "OPENASSETWATCH_ADMIN_TOKEN"
ADMIN_TOKEN_HEADER = "X-OpenAssetWatch-Admin-Token"
ADVISORY_API_ACTOR = "api-admin-token"
MAX_SENSOR_ENROLLMENT_BODY_BYTES = 8 << 10
MAX_LOCAL_INVENTORY_ASSETS = 1_000


def require_collector_token(provided_token: str | None) -> None:
    expected_token = os.getenv(COLLECTOR_TOKEN_ENV)
    if not expected_token:
        return
    if not isinstance(provided_token, str):
        provided_token = None
    if provided_token and secrets.compare_digest(provided_token, expected_token):
        return
    raise HTTPException(status_code=401, detail="valid collector token required")


def require_admin_token(provided_token: str | None) -> None:
    expected_token = os.getenv(ADMIN_TOKEN_ENV)
    if not expected_token:
        return
    if not isinstance(provided_token, str):
        provided_token = None
    if provided_token and secrets.compare_digest(provided_token, expected_token):
        return
    raise HTTPException(status_code=401, detail="valid admin token required")


def require_configured_admin_token(
    provided_token: str | None,
    *,
    capability: str,
) -> None:
    """Require an explicitly configured secret for state-changing admin APIs."""
    expected_token = os.getenv(ADMIN_TOKEN_ENV)
    if not expected_token:
        raise HTTPException(status_code=503, detail=f"{capability} is not configured")
    if isinstance(provided_token, str) and secrets.compare_digest(provided_token, expected_token):
        return
    raise HTTPException(status_code=401, detail="valid admin token required")


def require_sensor_admin_token(provided_token: str | None) -> None:
    require_configured_admin_token(
        provided_token,
        capability="sensor identity administration",
    )


class _EnrollmentAttemptLimiter:
    """Small per-process limiter for the unauthenticated token exchange."""

    def __init__(self, *, limit: int = 20, window_seconds: float = 60.0, max_sources: int = 4096) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_sources = max_sources
        self._lock = threading.Lock()
        self._attempts: OrderedDict[str, deque[float]] = OrderedDict()

    def allow(self, source: str, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            attempts = self._attempts.pop(source, deque())
            cutoff = current - self.window_seconds
            while attempts and attempts[0] <= cutoff:
                attempts.popleft()
            allowed = len(attempts) < self.limit
            if allowed:
                attempts.append(current)
            self._attempts[source] = attempts
            while len(self._attempts) > self.max_sources:
                self._attempts.popitem(last=False)
            return allowed


_sensor_enrollment_attempts = _EnrollmentAttemptLimiter()
_agent_enrollment_attempts = _EnrollmentAttemptLimiter()


def _sensor_request_source(request: Request) -> str:
    if request.client is None or not request.client.host:
        return "unknown"
    return request.client.host[:128]


def _require_bounded_enrollment_request(content_length: str | None) -> None:
    if not isinstance(content_length, str):
        return
    try:
        length = int(content_length, 10)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid request metadata") from exc
    if length < 0 or length > MAX_SENSOR_ENROLLMENT_BODY_BYTES:
        raise HTTPException(status_code=413, detail="sensor enrollment request is too large")


def _raise_sensor_admin_error(exc: SensorIdentityNotFound | SensorIdentityConflict) -> None:
    if isinstance(exc, SensorIdentityNotFound):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    raise HTTPException(status_code=409, detail=str(exc)) from exc


def _raise_endpoint_agent_admin_error(
    exc: EndpointAgentIdentityNotFound | EndpointAgentIdentityConflict,
) -> None:
    if isinstance(exc, EndpointAgentIdentityNotFound):
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    raise HTTPException(status_code=409, detail=str(exc)) from exc


def _run_endpoint_inventory_reevaluation(
    *, storage_id: int, site_id: str, asset_ids: list[str]
) -> None:
    """Run bounded deterministic work without changing ingestion acceptance."""

    try:
        set_endpoint_inventory_reevaluation_state(storage_id=storage_id, state="running")
        if asset_ids:
            evaluate_classifications(
                trigger_type="endpoint-inventory",
                requested_by="endpoint-agent-ingestion",
                site_id=site_id,
                asset_ids=asset_ids,
                reevaluate_findings=False,
            )
            for asset_id in asset_ids:
                evaluate_vulnerabilities(
                    trigger_type="endpoint-inventory",
                    requested_by="endpoint-agent-ingestion",
                    site_id=site_id,
                    asset_id=asset_id,
                    update_findings=False,
                )
                evaluate_findings(
                    trigger_type="endpoint-inventory",
                    requested_by="endpoint-agent-ingestion",
                    site_id=site_id,
                    asset_id=asset_id,
                )
        set_endpoint_inventory_reevaluation_state(storage_id=storage_id, state="completed")
    except Exception as exc:  # noqa: BLE001 - persistence already succeeded.
        LOGGER.warning("endpoint inventory reevaluation failed safely: %s", type(exc).__name__)
        try:
            set_endpoint_inventory_reevaluation_state(
                storage_id=storage_id,
                state="retryable-failure",
                error_code=f"reevaluation-{type(exc).__name__.lower()}"[:80],
            )
        except Exception as state_exc:  # noqa: BLE001 - never surface raw errors.
            LOGGER.warning("endpoint inventory state update failed safely: %s", type(state_exc).__name__)


def _run_canonical_inventory_evaluation(
    *,
    canonical_collection_id: str,
) -> None:
    """Run bounded deterministic work after canonical acceptance commits."""

    try:
        work = claim_canonical_evaluation_work(
            canonical_collection_id=canonical_collection_id
        )
        if work is None:
            return
        site_id = str(work["site_id"])
        asset_ids = list(work["asset_ids"])
        if not database_module._persist_classification_evidence_best_effort(
            normalized_assets=work["normalized_assets"],
            payload=work["payload"],
            source_authenticated=bool(work["source_authenticated"]),
        ) or not database_module._persist_component_inventory_best_effort(
            normalized_assets=work["normalized_assets"],
            payload=work["payload"],
            received_at=work["received_at"],
            source_authenticated=bool(work["source_authenticated"]),
            canonical_collection_id=canonical_collection_id,
        ):
            raise RuntimeError("canonical evidence projection failed")
        if asset_ids:
            evaluate_classifications(
                trigger_type="canonical-inventory",
                requested_by="canonical-ingestion",
                site_id=site_id,
                asset_ids=asset_ids,
                reevaluate_findings=False,
            )
            for asset_id in asset_ids:
                evaluate_vulnerabilities(
                    trigger_type="canonical-inventory",
                    requested_by="canonical-ingestion",
                    site_id=site_id,
                    asset_id=asset_id,
                    update_findings=False,
                )
                evaluate_findings(
                    trigger_type="canonical-inventory",
                    requested_by="canonical-ingestion",
                    site_id=site_id,
                    asset_id=asset_id,
                )
        set_canonical_evaluation_state(
            canonical_collection_id=canonical_collection_id,
            state="completed",
        )
    except Exception as exc:  # noqa: BLE001 - acceptance already committed.
        LOGGER.warning(
            "canonical inventory evaluation failed safely: %s",
            type(exc).__name__,
        )
        try:
            set_canonical_evaluation_state(
                canonical_collection_id=canonical_collection_id,
                state="retryable-failure",
                error_code=f"reevaluation-{type(exc).__name__.lower()}"[:80],
            )
        except Exception as state_exc:  # noqa: BLE001 - never expose raw errors.
            LOGGER.warning(
                "canonical evaluation state update failed safely: %s",
                type(state_exc).__name__,
            )


_canonical_evaluation_lock = threading.Lock()
_canonical_evaluations_pending: set[str] = set()
MAX_PENDING_CANONICAL_EVALUATIONS = 4_096


def _run_coalesced_canonical_evaluation(
    *,
    canonical_collection_id: str,
) -> None:
    try:
        _run_canonical_inventory_evaluation(
            canonical_collection_id=canonical_collection_id,
        )
    finally:
        with _canonical_evaluation_lock:
            _canonical_evaluations_pending.discard(canonical_collection_id)


def _queue_canonical_evaluation(
    background_tasks: BackgroundTasks | None,
    *,
    canonical_collection_id: str,
    has_work: bool,
) -> str:
    if not has_work:
        return "not-required"
    if background_tasks is None:
        # FastAPI always provides BackgroundTasks on the HTTP path. Direct
        # in-process compatibility callers retain the durable queued state for
        # an explicit worker or administrator retry instead of touching the DB.
        return "queued"
    queue_error_code: str | None = None
    with _canonical_evaluation_lock:
        if canonical_collection_id in _canonical_evaluations_pending:
            return "queued"
        if len(_canonical_evaluations_pending) >= MAX_PENDING_CANONICAL_EVALUATIONS:
            queue_error_code = "reevaluation-queue-capacity"
        else:
            _canonical_evaluations_pending.add(canonical_collection_id)
    if queue_error_code is not None:
        try:
            set_canonical_evaluation_state(
                canonical_collection_id=canonical_collection_id,
                state="retryable-failure",
                error_code=queue_error_code,
            )
        except Exception as exc:  # noqa: BLE001 - acceptance is already durable.
            LOGGER.warning(
                "canonical queue failure state update failed safely: %s",
                type(exc).__name__,
            )
        return "retryable-failure"
    try:
        background_tasks.add_task(
            _run_coalesced_canonical_evaluation,
            canonical_collection_id=canonical_collection_id,
        )
    except Exception as exc:  # noqa: BLE001 - acceptance is already durable.
        with _canonical_evaluation_lock:
            _canonical_evaluations_pending.discard(canonical_collection_id)
        try:
            set_canonical_evaluation_state(
                canonical_collection_id=canonical_collection_id,
                state="retryable-failure",
                error_code="reevaluation-queue-error",
            )
        except Exception as state_exc:  # noqa: BLE001 - never expose raw errors.
            LOGGER.warning(
                "canonical queue error state update failed safely: %s",
                type(state_exc).__name__,
            )
        LOGGER.warning(
            "canonical evaluation queue failed safely: %s",
            type(exc).__name__,
        )
        return "retryable-failure"
    return "queued"


def _queue_site_evaluation(
    background_tasks: BackgroundTasks | None,
    *,
    site_id: str,
    sensor_id: str | None = None,
) -> None:
    if background_tasks is not None:
        background_tasks.add_task(
            evaluate_site_best_effort,
            site_id=site_id,
            sensor_id=sensor_id,
        )


def _queue_asset_classification(
    background_tasks: BackgroundTasks | None,
    *,
    site_id: str,
    asset_ids: list[str],
) -> None:
    if background_tasks is not None and asset_ids:
        background_tasks.add_task(
            evaluate_assets_best_effort,
            site_id=site_id,
            asset_ids=asset_ids,
        )


class _VulnerabilityEvaluationCoalescer:
    """Serialize and coalesce bursty ingestion-triggered site evaluations."""

    def __init__(
        self,
        *,
        maximum_passes: int = 3,
        maximum_pending_sites: int = 64,
        cooldown_seconds: float = 30.0,
        maximum_tracked_sites: int = 4_096,
        clock=time.monotonic,
    ) -> None:
        self.maximum_passes = maximum_passes
        self.maximum_pending_sites = maximum_pending_sites
        self.cooldown_seconds = cooldown_seconds
        self.maximum_tracked_sites = maximum_tracked_sites
        self._clock = clock
        self._lock = threading.Lock()
        self._generations: dict[str, int] = {}
        self._last_completed: OrderedDict[str, float] = OrderedDict()

    def schedule(self, site_id: str) -> bool:
        with self._lock:
            already_pending = site_id in self._generations
            current = self._clock()
            last_completed = self._last_completed.get(site_id)
            if (
                not already_pending
                and last_completed is not None
                and current - last_completed < self.cooldown_seconds
            ):
                return False
            if (
                not already_pending
                and len(self._generations) >= self.maximum_pending_sites
            ):
                return False
            generation = self._generations.get(site_id, 0) + 1
            self._generations[site_id] = generation
            return not already_pending

    def cancel(self, site_id: str) -> None:
        with self._lock:
            self._generations.pop(site_id, None)

    def _complete_locked(self, site_id: str) -> None:
        self._generations.pop(site_id, None)
        self._last_completed.pop(site_id, None)
        self._last_completed[site_id] = self._clock()
        while len(self._last_completed) > self.maximum_tracked_sites:
            self._last_completed.popitem(last=False)

    def _complete(self, site_id: str) -> None:
        with self._lock:
            self._complete_locked(site_id)

    def run(
        self,
        *,
        site_id: str,
        trigger_type: str = "component-ingestion",
        requested_by: str = "control-tower",
    ) -> None:
        try:
            for _ in range(self.maximum_passes):
                with self._lock:
                    generation = self._generations.get(site_id)
                if generation is None:
                    return
                evaluate_site_vulnerabilities_best_effort(
                    trigger_type=trigger_type,
                    requested_by=requested_by,
                    site_id=site_id,
                )
                with self._lock:
                    if self._generations.get(site_id) == generation:
                        self._complete_locked(site_id)
                        return
            # Bound continuous spoke-driven work. A later ingestion can queue
            # the next pass after this worker releases the site and cooldown.
            self._complete(site_id)
        except Exception:
            self._complete(site_id)
            raise


_vulnerability_evaluation_coalescer = _VulnerabilityEvaluationCoalescer()


def _queue_vulnerability_evaluation(
    background_tasks: BackgroundTasks | None,
    *,
    site_id: str,
) -> None:
    if (
        background_tasks is not None
        and _vulnerability_evaluation_coalescer.schedule(site_id)
    ):
        try:
            background_tasks.add_task(
                _vulnerability_evaluation_coalescer.run,
                site_id=site_id,
                trigger_type="component-ingestion",
                requested_by="control-tower",
            )
        except Exception:
            _vulnerability_evaluation_coalescer.cancel(site_id)
            raise


class _FullClassificationLimiter:
    """Bound repeated process-local bulk rebuilds without blocking targeted runs."""

    def __init__(self, *, cooldown_seconds: float = 60.0) -> None:
        self.cooldown_seconds = cooldown_seconds
        self._lock = threading.Lock()
        self._last_started = 0.0

    def allow(self, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        with self._lock:
            if current - self._last_started < self.cooldown_seconds:
                return False
            self._last_started = current
            return True


_full_classification_limiter = _FullClassificationLimiter()
_full_vulnerability_limiter = _FullClassificationLimiter(
    cooldown_seconds=60.0
)


class CollectorCheckInRequest(BaseModel):
    collector_id: str = Field(..., min_length=1)
    collector_guid: str | None = None
    collector_name: str | None = None
    hostname: str = Field(..., min_length=1)
    collector_version: str = Field(..., min_length=1)
    mode: str = Field(..., min_length=1)
    platform: dict[str, Any] | None = None
    deployment: dict[str, Any] | None = None
    labels: dict[str, Any] | None = None
    supported_capabilities: list[str] | None = None
    enabled_capabilities: list[str] | None = None
    status: str = "healthy"
    message: str | None = None
    checked_in_at: datetime | None = None


class CollectorCheckInResponse(BaseModel):
    status: str
    collector_id: str
    received_at: datetime
    next_heartbeat_minutes: int
    inventory_interval_hours: int


class CollectorInventoryRequest(BaseModel):
    schema_version: str | None = None
    collector: str | dict[str, Any] | None = None
    collector_guid: str | None = None
    collector_id: str | None = None
    collector_name: str | None = None
    collector_version: str | None = None
    mode: str | None = None
    collected_at: datetime | None = None
    platform: dict[str, Any] | None = None
    deployment: dict[str, Any] | None = None
    labels: dict[str, Any] | None = None
    supported_capabilities: list[str] | None = None
    enabled_capabilities: list[str] | None = None
    device: dict[str, Any] | None = None
    network: list[dict[str, Any]] | dict[str, Any] | None = None
    software: list[dict[str, Any]] | None = None

    class Config:
        extra = "allow"


class CollectorInventoryResponse(BaseModel):
    status: str
    submission_id: int
    canonical_collection_id: str
    received_at: datetime
    collector_guid: str | None = None
    collector_id: str | None = None
    mode: str | None = None
    device_count: int
    network_observation_count: int
    software_count: int
    normalized_asset_count: int
    normalized_software_count: int
    source_authority: str
    adapter_type: str
    compatibility_status: str
    evaluation_state: str
    warnings: list[str] = Field(default_factory=list)


class CollectorInventoryLatestResponse(BaseModel):
    submission_id: int
    collector_guid: str | None = None
    collector_id: str | None = None
    collector_name: str | None = None
    mode: str | None = None
    schema_version: str | None = None
    collector_version: str | None = None
    collected_at: datetime | None = None
    received_at: datetime
    device_count: int
    network_observation_count: int
    software_count: int
    created_at: datetime
    canonical_collection_id: str | None = None
    evaluation_state: str | None = None
    source_authority: str | None = None
    compatibility_status: str | None = None
    payload: dict[str, Any]


class LocalInventoryCollectionResponse(BaseModel):
    status: str
    observation_batch_id: int
    canonical_collection_id: str
    site_id: str
    received_at: datetime
    observed_asset_count: int
    normalized_asset_count: int = 0
    source_authority: str
    adapter_type: str
    compatibility_status: str
    evaluation_state: str
    warnings: list[str] = Field(default_factory=list)
    message: str


class AgentCheckInResponse(BaseModel):
    status: str
    site_id: str
    agent_id: str | None = None
    received_at: datetime
    message: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class ReadinessResponse(BaseModel):
    status: str
    service: str
    schema_state: str
    current_schema_version: int
    latest_schema_version: int
    failure_code: str | None = None


class SiteRequest(BaseModel):
    site_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    description: str | None = None


class SiteResponse(BaseModel):
    site_id: str
    name: str
    description: str | None = None
    created_at: datetime
    updated_at: datetime


class SiteListResponse(BaseModel):
    sites: list[dict[str, Any]]


class AgentEnrollmentRequest(BaseModel):
    agent_id: str = Field(..., min_length=1)
    site_id: str = Field(..., min_length=1)
    display_name: str | None = None
    agent_type: str = Field(default="endpoint-agent")
    platform: str | None = None
    architecture: str | None = None


class AgentEnrollmentResponse(BaseModel):
    agent_id: str
    site_id: str
    display_name: str | None = None
    agent_type: str
    platform: str | None = None
    architecture: str | None = None
    version: str | None = None
    hostname: str | None = None
    mode: str | None = None
    created_at: datetime
    updated_at: datetime
    last_seen_at: datetime | None = None


class AgentListResponse(BaseModel):
    agents: list[dict[str, Any]]


class AgentCheckInRequest(BaseModel):
    agent_id: str | None = None
    site_id: str = Field(..., min_length=1)
    version: str | None = None
    agent_version: str | None = None
    platform: dict[str, Any] | str | None = None
    architecture: str | None = None
    hostname: str | None = None
    mode: str | None = None
    timestamp: datetime | None = None
    check_in_at: datetime | None = None

    class Config:
        extra = "allow"


class ControlTowerSummaryResponse(BaseModel):
    site_count: int
    agent_count: int
    checkin_count: int
    asset_count: int
    evidence_count: int


class ReleaseStatusResponse(BaseModel):
    server_version: str
    expected_agent_version: str
    channel: str
    update_available: bool
    update_execution: str
    message: str


@app.get("/")
def root():
    return {
        "name": "OpenAssetWatch",
        "status": "running",
        "version": CONTROL_TOWER_VERSION,
    }


@app.get("/health", response_model=HealthResponse)
def health():
    return {
        "status": "healthy",
        "service": "openassetwatch-control-tower",
        "version": CONTROL_TOWER_VERSION,
    }


@app.get("/ready", response_model=ReadinessResponse)
def readiness():
    schema = runtime_schema_readiness()
    payload = {
        "status": "ready" if schema["state"] == "ready" else "unready",
        "service": "openassetwatch-control-tower",
        "schema_state": schema["state"],
        "current_schema_version": int(schema["current_version"]),
        "latest_schema_version": int(schema["latest_available_version"]),
        "failure_code": schema["failure_code"],
    }
    if schema["state"] != "ready":
        return JSONResponse(status_code=503, content=payload)
    return payload


@app.get("/ui", include_in_schema=False)
def control_tower_ui():
    index_path = UI_STATIC_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="control tower UI is not installed")
    return FileResponse(index_path)


@app.get("/api/v1/sites", response_model=SiteListResponse)
def api_list_sites():
    try:
        return {"sites": list_sites()}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load sites") from exc


@app.post("/api/v1/sites", response_model=SiteResponse)
def api_create_site(payload: SiteRequest):
    try:
        return create_site(
            site_id=payload.site_id.strip(),
            name=payload.name.strip(),
            description=payload.description.strip() if isinstance(payload.description, str) else None,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to save site") from exc


@app.get("/api/v1/agents", response_model=AgentListResponse)
def api_list_agents():
    try:
        return {"agents": list_agent_enrollments()}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load agents") from exc


@app.post("/api/v1/agents/enrollments", response_model=AgentEnrollmentResponse)
def api_create_agent_enrollment(payload: AgentEnrollmentRequest):
    if payload.agent_type not in {"endpoint-agent", "network-sensor"}:
        raise HTTPException(status_code=400, detail="agent_type must be endpoint-agent or network-sensor")
    try:
        return create_agent_enrollment(
            agent_id=payload.agent_id.strip(),
            site_id=payload.site_id.strip(),
            display_name=payload.display_name.strip() if isinstance(payload.display_name, str) else None,
            agent_type=payload.agent_type,
            platform=payload.platform.strip() if isinstance(payload.platform, str) else None,
            architecture=payload.architecture.strip() if isinstance(payload.architecture, str) else None,
        )
    except LegacyAgentIdentityConflict as exc:
        raise HTTPException(
            status_code=409,
            detail="legacy agent identity conflicts with bound identity",
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to save agent enrollment") from exc


@app.post(
    "/api/v1/admin/agent-enrollments",
    response_model=BoundAgentEnrollmentCreateResponse,
    response_model_exclude_none=True,
)
def admin_create_bound_agent_enrollment(
    payload: BoundAgentEnrollmentCreateRequest,
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="endpoint-agent identity administration")
    try:
        return create_bound_agent_enrollment(
            site_id=payload.site_id,
            requested_deployment_id=payload.requested_deployment_id,
            requested_display_name=payload.requested_display_name,
            requested_agent_type=payload.requested_agent_type,
            expires_in_minutes=payload.expires_in_minutes,
            actor="api-admin-token",
        )
    except (EndpointAgentIdentityNotFound, EndpointAgentIdentityConflict) as exc:
        _raise_endpoint_agent_admin_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to create endpoint-agent enrollment") from exc


@app.get(
    "/api/v1/admin/agent-enrollments",
    response_model=BoundAgentEnrollmentListResponse,
)
def admin_list_bound_agent_enrollments(
    limit: int = Query(default=100, ge=1, le=500),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="endpoint-agent identity administration")
    try:
        return {"enrollments": list_bound_agent_enrollments(limit=limit)}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load endpoint-agent enrollments") from exc


@app.get(
    "/api/v1/admin/agent-enrollments/{enrollment_id}",
    response_model=BoundAgentEnrollmentPublic,
    response_model_exclude_none=True,
)
def admin_get_bound_agent_enrollment(
    enrollment_id: str = ApiPath(..., pattern=r"^aenr_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="endpoint-agent identity administration")
    try:
        return get_bound_agent_enrollment(enrollment_id)
    except (EndpointAgentIdentityNotFound, EndpointAgentIdentityConflict) as exc:
        _raise_endpoint_agent_admin_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load endpoint-agent enrollment") from exc


@app.post(
    "/api/v1/admin/agent-enrollments/{enrollment_id}/revoke",
    response_model=BoundAgentEnrollmentPublic,
    response_model_exclude_none=True,
)
def admin_revoke_bound_agent_enrollment(
    enrollment_id: str = ApiPath(..., pattern=r"^aenr_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="endpoint-agent identity administration")
    try:
        return revoke_bound_agent_enrollment(enrollment_id, actor="api-admin-token")
    except (EndpointAgentIdentityNotFound, EndpointAgentIdentityConflict) as exc:
        _raise_endpoint_agent_admin_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to revoke endpoint-agent enrollment") from exc


@app.get("/api/v1/admin/agents", response_model=AgentCredentialListResponse)
def admin_list_bound_agent_credentials(
    limit: int = Query(default=500, ge=1, le=500),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="endpoint-agent identity administration")
    try:
        return {"credentials": list_agent_credentials(limit=limit)}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load endpoint-agent credentials") from exc


@app.post(
    "/api/v1/admin/agents/{agent_id}/credentials/rotate",
    response_model=AgentCredentialIssueResponse,
)
def admin_rotate_bound_agent_credential(
    agent_id: str = ApiPath(..., pattern=r"^agent_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="endpoint-agent identity administration")
    try:
        return rotate_agent_credential(agent_id, actor="api-admin-token")
    except (EndpointAgentIdentityNotFound, EndpointAgentIdentityConflict) as exc:
        _raise_endpoint_agent_admin_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to rotate endpoint-agent credential") from exc


@app.post("/api/v1/admin/agents/{agent_id}/credentials/{credential_id}/revoke")
def admin_revoke_bound_agent_credential(
    agent_id: str = ApiPath(..., pattern=r"^agent_[0-9a-f]{32}$"),
    credential_id: str = ApiPath(..., pattern=r"^acred_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="endpoint-agent identity administration")
    try:
        return revoke_bound_agent_credential(agent_id, credential_id, actor="api-admin-token")
    except (EndpointAgentIdentityNotFound, EndpointAgentIdentityConflict) as exc:
        _raise_endpoint_agent_admin_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to revoke endpoint-agent credential") from exc


@app.post("/api/v1/admin/agents/{agent_id}/revoke")
def admin_revoke_bound_agent(
    agent_id: str = ApiPath(..., pattern=r"^agent_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="endpoint-agent identity administration")
    try:
        return revoke_bound_agent(agent_id, actor="api-admin-token")
    except (EndpointAgentIdentityNotFound, EndpointAgentIdentityConflict) as exc:
        _raise_endpoint_agent_admin_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to revoke endpoint-agent") from exc


@app.get("/api/v1/admin/agent-identity/audit")
def admin_bound_agent_identity_audit(
    limit: int = Query(default=100, ge=1, le=500),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="endpoint-agent identity administration")
    try:
        return {"events": list_agent_identity_audit(limit=limit)}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load endpoint-agent identity audit") from exc


@app.post("/api/v1/agents/enroll", response_model=AgentEnrollmentExchangeResponse)
def endpoint_agent_enroll(
    payload: AgentEnrollmentExchangeRequest,
    request: Request,
    content_length: str | None = Header(default=None, alias="Content-Length"),
):
    _require_bounded_enrollment_request(content_length)
    if not _agent_enrollment_attempts.allow(_sensor_request_source(request)):
        raise HTTPException(status_code=429, detail="endpoint-agent enrollment temporarily unavailable")
    try:
        return exchange_agent_enrollment(
            enrollment_token=payload.enrollment_token.get_secret_value(),
            installation_id=payload.installation_id,
            display_name=payload.display_name,
            agent_version=payload.agent_version,
            platform=payload.platform,
            architecture=payload.architecture,
            agent_type=payload.agent_type,
        )
    except AgentEnrollmentRejected as exc:
        raise HTTPException(status_code=401, detail="endpoint-agent enrollment failed") from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="endpoint-agent enrollment failed") from exc


@app.post(
    "/api/v1/admin/sensor-enrollments",
    response_model=SensorEnrollmentCreateResponse,
    response_model_exclude_none=True,
)
def admin_create_sensor_enrollment(
    payload: SensorEnrollmentCreateRequest,
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_sensor_admin_token(admin_token)
    try:
        return create_sensor_enrollment(
            site_id=payload.site_id,
            requested_sensor_id=payload.requested_sensor_id,
            requested_sensor_name=payload.requested_sensor_name,
            sensor_type=payload.sensor_type,
            expires_in_minutes=payload.expires_in_minutes,
        )
    except (SensorIdentityNotFound, SensorIdentityConflict) as exc:
        _raise_sensor_admin_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to create sensor enrollment") from exc


@app.get("/api/v1/admin/sensor-enrollments", response_model=SensorEnrollmentListResponse)
def admin_list_sensor_enrollments(
    limit: int = Query(default=100, ge=1, le=500),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_sensor_admin_token(admin_token)
    try:
        return {"enrollments": list_sensor_enrollments(limit=limit)}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load sensor enrollments") from exc


@app.get(
    "/api/v1/admin/sensor-enrollments/{enrollment_id}",
    response_model=SensorEnrollmentPublic,
    response_model_exclude_none=True,
)
def admin_get_sensor_enrollment(
    enrollment_id: str = ApiPath(..., pattern=r"^senr_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_sensor_admin_token(admin_token)
    try:
        return get_sensor_enrollment(enrollment_id)
    except (SensorIdentityNotFound, SensorIdentityConflict) as exc:
        _raise_sensor_admin_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load sensor enrollment") from exc


@app.post(
    "/api/v1/admin/sensor-enrollments/{enrollment_id}/revoke",
    response_model=SensorEnrollmentPublic,
    response_model_exclude_none=True,
)
def admin_revoke_sensor_enrollment(
    enrollment_id: str = ApiPath(..., pattern=r"^senr_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_sensor_admin_token(admin_token)
    try:
        return revoke_sensor_enrollment(enrollment_id)
    except (SensorIdentityNotFound, SensorIdentityConflict) as exc:
        _raise_sensor_admin_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to revoke sensor enrollment") from exc


@app.get("/api/v1/admin/sensors", response_model=SensorCredentialListResponse)
def admin_list_sensor_credentials(
    limit: int = Query(default=500, ge=1, le=500),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_sensor_admin_token(admin_token)
    try:
        return {"credentials": list_sensor_credentials(limit=limit)}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load sensor credentials") from exc


@app.post(
    "/api/v1/admin/sensors/{sensor_id}/credentials/rotate",
    response_model=SensorCredentialIssueResponse,
)
def admin_rotate_sensor_credential(
    sensor_id: str = ApiPath(..., min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_sensor_admin_token(admin_token)
    try:
        return rotate_sensor_credential(sensor_id)
    except (SensorIdentityNotFound, SensorIdentityConflict) as exc:
        _raise_sensor_admin_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to rotate sensor credential") from exc


@app.post("/api/v1/admin/sensors/{sensor_id}/credentials/{credential_id}/revoke")
def admin_revoke_sensor_credential(
    sensor_id: str = ApiPath(..., min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$"),
    credential_id: str = ApiPath(..., pattern=r"^scred_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_sensor_admin_token(admin_token)
    try:
        return revoke_sensor_credential(sensor_id, credential_id)
    except (SensorIdentityNotFound, SensorIdentityConflict) as exc:
        _raise_sensor_admin_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to revoke sensor credential") from exc


@app.post("/api/v1/admin/sensors/{sensor_id}/revoke")
def admin_revoke_sensor(
    sensor_id: str = ApiPath(..., min_length=1, max_length=160, pattern=r"^[A-Za-z0-9._:-]+$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_sensor_admin_token(admin_token)
    try:
        return revoke_sensor(sensor_id)
    except (SensorIdentityNotFound, SensorIdentityConflict) as exc:
        _raise_sensor_admin_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to revoke sensor") from exc


@app.get("/api/v1/admin/sensor-identity/audit")
def admin_sensor_identity_audit(
    limit: int = Query(default=100, ge=1, le=500),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_sensor_admin_token(admin_token)
    try:
        return {"events": list_sensor_identity_audit(limit=limit)}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load sensor identity audit") from exc


@app.post("/api/v1/sensors/enroll", response_model=SensorEnrollmentExchangeResponse)
def sensor_enroll(
    payload: SensorEnrollmentExchangeRequest,
    request: Request,
    content_length: str | None = Header(default=None, alias="Content-Length"),
):
    _require_bounded_enrollment_request(content_length)
    if not _sensor_enrollment_attempts.allow(_sensor_request_source(request)):
        raise HTTPException(status_code=429, detail="sensor enrollment temporarily unavailable")
    try:
        return exchange_sensor_enrollment(
            enrollment_token=payload.enrollment_token.get_secret_value(),
            sensor_id=payload.sensor_id,
            sensor_name=payload.sensor_name,
            sensor_type=payload.sensor_type,
            sensor_version=payload.sensor_version,
            platform=payload.platform,
        )
    except SensorEnrollmentRejected as exc:
        raise HTTPException(status_code=401, detail="sensor enrollment failed") from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="sensor enrollment failed") from exc


@app.post("/api/v1/sensors/check-in", response_model=SensorCheckInResponse)
def sensor_check_in(
    payload: SensorCheckInRequest,
    background_tasks: BackgroundTasks = None,
    collector_token: str | None = Header(default=None, alias=COLLECTOR_TOKEN_HEADER),
):
    try:
        authenticate_sensor_request(
            provided_token=collector_token,
            claimed_site_id=payload.site_id,
            claimed_sensor_id=payload.sensor_id,
            claimed_sensor_type=payload.sensor_type,
        )
    except SensorAuthenticationRejected as exc:
        raise HTTPException(status_code=401, detail="valid sensor credential required") from exc
    received_at = datetime.now(timezone.utc)
    try:
        record_sensor_checkin(
            site_id=payload.site_id,
            sensor_id=payload.sensor_id,
            sensor_name=payload.sensor_name,
            sensor_version=payload.sensor_version,
            status=payload.status,
            received_at=received_at,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to persist sensor check-in") from exc
    _queue_site_evaluation(
        background_tasks,
        site_id=payload.site_id,
        sensor_id=payload.sensor_id,
    )
    return SensorCheckInResponse(
        status="accepted",
        site_id=payload.site_id,
        sensor_id=payload.sensor_id,
        received_at=received_at,
        message="sensor check-in accepted",
    )


@app.get("/api/v1/control-tower/summary", response_model=ControlTowerSummaryResponse)
def api_control_tower_summary():
    try:
        return control_tower_summary()
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load control tower summary") from exc


@app.get("/api/v1/control-tower/check-ins")
def api_control_tower_checkins(limit: int = 25):
    safe_limit = max(1, min(limit, 100))
    try:
        return {"check_ins": list_agent_checkins(limit=safe_limit)}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load check-ins") from exc


@app.get("/api/v1/control-tower/assets")
def api_control_tower_assets():
    try:
        return {"assets": list_control_tower_assets()}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load control tower assets") from exc


@app.get("/api/v1/admin/ingestion/compatibility-status")
def api_ingestion_compatibility_status(
    limit: int = Query(default=20, ge=1, le=100),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    try:
        return canonical_compatibility_status(limit=limit)
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=500,
            detail="failed to load ingestion compatibility status",
        ) from exc


@app.post("/api/v1/admin/ingestion/{canonical_collection_id}/retry")
def api_retry_canonical_ingestion_evaluation(
    background_tasks: BackgroundTasks,
    canonical_collection_id: str = ApiPath(
        ..., pattern=r"^col_[0-9a-f]{32}$"
    ),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(
        admin_token,
        capability="canonical ingestion evaluation retry",
    )
    try:
        # A failing worker records retryable state before its coalescing wrapper
        # removes the process-local pending marker. Refuse that narrow window so
        # the old wrapper cannot discard a newly queued retry task.
        with _canonical_evaluation_lock:
            if canonical_collection_id in _canonical_evaluations_pending:
                raise HTTPException(
                    status_code=409,
                    detail="canonical evaluation is still finalizing",
                )
        if not requeue_canonical_evaluation(
            canonical_collection_id=canonical_collection_id
        ):
            raise HTTPException(
                status_code=409,
                detail="canonical evaluation is not retryable",
            )
        state = _queue_canonical_evaluation(
            background_tasks,
            canonical_collection_id=canonical_collection_id,
            has_work=True,
        )
        return {
            "canonical_collection_id": canonical_collection_id,
            "evaluation_state": state,
            "message": "canonical deterministic evaluation retry accepted",
        }
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=500,
            detail="failed to retry canonical evaluation",
        ) from exc


def _finding_store() -> SqlFindingStore:
    return SqlFindingStore()


def _classification_store() -> SqlClassificationStore:
    return SqlClassificationStore()


def _component_store() -> SqlComponentStore:
    return SqlComponentStore()


def _advisory_store() -> SqlAdvisoryStore:
    return SqlAdvisoryStore()


def _advisory_sync_store() -> SqlAdvisorySyncStore:
    return SqlAdvisorySyncStore()


def _advisory_sync_service() -> AdvisorySyncService:
    return AdvisorySyncService(store=_advisory_sync_store())


def _vulnerability_store() -> SqlVulnerabilityStore:
    return SqlVulnerabilityStore()


def _kev_store() -> SqlKevStore:
    return SqlKevStore()


def _temporal_store() -> SqlTemporalStore:
    return SqlTemporalStore()


def _temporal_service() -> TemporalProjectionService:
    return TemporalProjectionService(store=_temporal_store())


def _temporal_expectation_service() -> TemporalExpectationService:
    return TemporalExpectationService.from_projection_store(store=_temporal_store())


def _temporal_deviation_service() -> TemporalDeviationService:
    return TemporalDeviationService.from_projection_store(store=_temporal_store())


@app.get(
    "/api/v1/temporal/metrics",
    response_model=TemporalMetricRegistryResponse,
)
def api_temporal_metrics(
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(
        admin_token,
        capability="temporal signal access",
    )
    return temporal_registry_public()


@app.get(
    "/api/v1/temporal/signals",
    response_model=TemporalSignalSeriesResponse,
)
def api_temporal_signals(
    metric_key: str = Query(..., pattern=METRIC_KEY_PATTERN, max_length=120),
    site_id: str = Query(..., min_length=1, max_length=128),
    start: datetime = Query(...),
    end: datetime = Query(...),
    granularity: str = Query(default="daily", min_length=1, max_length=16),
    asset_id: str | None = Query(default=None, min_length=1, max_length=160),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(
        admin_token,
        capability="temporal signal access",
    )
    try:
        return _temporal_service().series(
            metric_key=metric_key,
            site_id=site_id,
            start=start,
            end=end,
            granularity=granularity,
            asset_id=asset_id,
        )
    except TemporalSiteNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except TemporalProjectionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=500,
            detail="failed to project temporal signals",
        ) from exc


@app.get(
    "/api/v1/temporal/expectations",
    response_model=TemporalExpectation,
)
def api_temporal_expectation(
    metric_key: str = Query(..., pattern=METRIC_KEY_PATTERN, max_length=120),
    site_id: str = Query(..., min_length=1, max_length=128),
    target_start: datetime = Query(...),
    granularity: str = Query(default="daily", min_length=1, max_length=16),
    asset_id: str | None = Query(default=None, min_length=1, max_length=160),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(
        admin_token,
        capability="temporal expectation access",
    )
    try:
        return _temporal_expectation_service().expectation(
            metric_key=metric_key,
            site_id=site_id,
            target_start=target_start,
            granularity=granularity,
            asset_id=asset_id,
        )
    except TemporalSiteNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except TemporalProjectionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=500,
            detail="failed to calculate temporal expectation",
        ) from exc


@app.get(
    "/api/v1/temporal/deviation-assessments",
    response_model=TemporalDeviationAssessment,
)
def api_temporal_deviation_assessment(
    metric_key: str = Query(..., pattern=METRIC_KEY_PATTERN, max_length=120),
    site_id: str = Query(..., min_length=1, max_length=128),
    target_start: datetime = Query(...),
    granularity: str = Query(default="daily", min_length=1, max_length=16),
    asset_id: str | None = Query(default=None, min_length=1, max_length=160),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(
        admin_token,
        capability="temporal deviation assessment access",
    )
    try:
        return _temporal_deviation_service().assessment(
            metric_key=metric_key,
            site_id=site_id,
            target_start=target_start,
            granularity=granularity,
            asset_id=asset_id,
        )
    except TemporalSiteNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except TemporalProjectionError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=500,
            detail="failed to calculate temporal deviation assessment",
        ) from exc


@app.get("/api/v1/components", response_model=ComponentListResponse)
def api_components(
    site_id: str | None = Query(default=None, min_length=1, max_length=128),
    asset_id: str | None = Query(default=None, min_length=1, max_length=160),
    component_type: str | None = Query(default=None),
    ecosystem: str | None = Query(default=None),
    vendor: str | None = Query(default=None, min_length=1, max_length=160),
    package: str | None = Query(default=None, min_length=1, max_length=240),
    freshness: str | None = Query(default=None),
    active: bool | None = Query(default=True),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=10_000),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    supported_types = {
        "application",
        "operating-system-package",
        "library",
        "runtime",
        "driver",
        "firmware",
        "operating-system",
        "security-tool",
        "unknown",
    }
    if component_type and component_type not in supported_types:
        raise HTTPException(status_code=400, detail="unsupported component type")
    if ecosystem and ecosystem not in SUPPORTED_ECOSYSTEMS:
        raise HTTPException(status_code=400, detail="unsupported component ecosystem")
    if freshness and freshness not in {"fresh", "aging", "stale", "unknown"}:
        raise HTTPException(status_code=400, detail="unsupported component freshness")
    try:
        return _component_store().list_components(
            site_id=site_id,
            asset_id=asset_id,
            component_type=component_type,
            ecosystem=ecosystem,
            vendor=vendor,
            package=normalized_token(package) if package else None,
            freshness=freshness,
            active=active,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load component inventory") from exc


@app.get(
    "/api/v1/components/assets/{asset_id}",
    response_model=ComponentListResponse,
)
def api_asset_components(
    asset_id: str = ApiPath(..., min_length=1, max_length=160),
    site_id: str = Query(..., min_length=1, max_length=128),
    active: bool | None = Query(default=True),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=10_000),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    return api_components(
        site_id=site_id,
        asset_id=asset_id,
        component_type=None,
        ecosystem=None,
        vendor=None,
        package=None,
        freshness=None,
        active=active,
        limit=limit,
        offset=offset,
        admin_token=admin_token,
    )


@app.get("/api/v1/vulnerabilities", response_model=VulnerabilityListResponse)
def api_vulnerabilities(
    site_id: str | None = Query(default=None, min_length=1, max_length=128),
    asset_id: str | None = Query(default=None, min_length=1, max_length=160),
    component_type: str | None = Query(default=None),
    ecosystem: str | None = Query(default=None),
    vendor: str | None = Query(default=None, min_length=1, max_length=160),
    package: str | None = Query(default=None, min_length=1, max_length=240),
    severity: str | None = Query(default=None),
    match_status: str | None = Query(default=None),
    known_exploited: bool | None = Query(default=None),
    fixed_version_available: bool | None = Query(default=None),
    freshness: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=10_000),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    statuses = {
        "affected",
        "not-affected",
        "fixed",
        "version-unknown",
        "identity-uncertain",
        "unsupported-comparison",
        "insufficient-evidence",
        "advisory-withdrawn",
    }
    if match_status and match_status not in statuses:
        raise HTTPException(status_code=400, detail="unsupported vulnerability match status")
    if severity and severity not in {"critical", "high", "medium", "low", "informational"}:
        raise HTTPException(status_code=400, detail="unsupported vulnerability severity")
    if ecosystem and ecosystem not in SUPPORTED_ECOSYSTEMS:
        raise HTTPException(status_code=400, detail="unsupported component ecosystem")
    if freshness and freshness not in {"fresh", "aging", "stale", "unknown"}:
        raise HTTPException(status_code=400, detail="unsupported component freshness")
    try:
        return _vulnerability_store().list_matches(
            site_id=site_id,
            asset_id=asset_id,
            severity=severity,
            match_status=match_status,
            known_exploited=known_exploited,
            fixed_available=fixed_version_available,
            freshness=freshness,
            component_type=component_type,
            ecosystem=ecosystem,
            vendor=vendor,
            package=normalized_token(package) if package else None,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load vulnerability intelligence") from exc


@app.get(
    "/api/v1/vulnerabilities/assets/{asset_id}",
    response_model=VulnerabilityListResponse,
)
def api_asset_vulnerabilities(
    asset_id: str = ApiPath(..., min_length=1, max_length=160),
    site_id: str = Query(..., min_length=1, max_length=128),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=10_000),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    return api_vulnerabilities(
        site_id=site_id,
        asset_id=asset_id,
        component_type=None,
        ecosystem=None,
        vendor=None,
        package=None,
        severity=None,
        match_status=None,
        known_exploited=None,
        fixed_version_available=None,
        freshness=None,
        limit=limit,
        offset=offset,
        admin_token=admin_token,
    )


@app.get(
    "/api/v1/vulnerabilities/advisories/{advisory_id}",
    response_model=VulnerabilityListResponse,
)
def api_advisory_vulnerabilities(
    advisory_id: str = ApiPath(..., pattern=r"^adv_[0-9a-f]{32}$"),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=10_000),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    try:
        return _vulnerability_store().list_matches(
            advisory_id=advisory_id,
            limit=limit,
            offset=offset,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load advisory matches") from exc


@app.get(
    "/api/v1/vulnerabilities/catalog/status",
    response_model=CatalogStatusResponse,
)
def api_vulnerability_catalog_status(
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    try:
        return _advisory_store().catalog_status()
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load advisory catalog status") from exc


@app.get("/api/v1/kev/status")
def api_kev_status(
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="KEV intelligence")
    try:
        return _kev_store().status()
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load KEV catalog status") from exc


@app.get("/api/v1/kev")
def api_kev_records(
    cve: str | None = Query(default=None, min_length=13, max_length=28),
    vendor_project: str | None = Query(default=None, min_length=1, max_length=500),
    ransomware_status: str | None = Query(default=None, max_length=32),
    date_added_from: date | None = Query(default=None),
    due_date_to: date | None = Query(default=None),
    site_id: str | None = Query(default=None, min_length=1, max_length=128),
    asset_id: str | None = Query(default=None, min_length=1, max_length=160),
    currently_affected: bool | None = Query(default=None),
    priority: str | None = Query(default=None, max_length=40),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=100_000),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="KEV intelligence")
    try:
        return _kev_store().list_records(
            cve_id=cve,
            vendor_project=vendor_project,
            ransomware_status=ransomware_status,
            date_added_from=date_added_from,
            due_date_to=due_date_to,
            site_id=site_id,
            asset_id=asset_id,
            currently_affected=currently_affected,
            priority=priority,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load KEV records") from exc


@app.get("/api/v1/kev/summary")
def api_kev_summary(
    site_id: str | None = Query(default=None, min_length=1, max_length=128),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="KEV intelligence")
    try:
        return _kev_store().summary(site_id=site_id)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load KEV summary") from exc


@app.get("/api/v1/kev/assets/{asset_id}")
def api_asset_kev_records(
    asset_id: str = ApiPath(..., min_length=1, max_length=160),
    site_id: str = Query(..., min_length=1, max_length=128),
    limit: int = Query(default=100, ge=1, le=200),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="KEV intelligence")
    try:
        return _kev_store().asset_records(asset_id=asset_id, site_id=site_id, limit=limit)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load asset KEV records") from exc


@app.get("/api/v1/kev/{cve_id}")
def api_kev_record(
    cve_id: str = ApiPath(..., min_length=13, max_length=28),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="KEV intelligence")
    try:
        item = _kev_store().get_record(cve_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load KEV record") from exc
    if item is None:
        raise HTTPException(status_code=404, detail="KEV record not found in active catalog")
    return item


@app.post("/api/v1/admin/kev/evaluate")
def admin_evaluate_kev(
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="KEV administration")
    if not _full_vulnerability_limiter.allow():
        raise HTTPException(status_code=429, detail="KEV reevaluation is temporarily rate limited")
    try:
        result = _kev_store().rebuild_active()
        run_ids = []
        for site_id in result.get("affected_site_ids", [])[:10_000]:
            evaluation = evaluate_findings(
                trigger_type="kev-admin-full-rebuild",
                requested_by="api-admin",
                site_id=str(site_id),
                rule_ids=("vulnerable-component",),
            )
            run_ids.append(evaluation.run_id)
        return {**result, "finding_reevaluation_run_ids": run_ids}
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to reevaluate KEV priority") from exc


@app.post(
    "/api/v1/admin/vulnerabilities/evaluate",
    response_model=VulnerabilityEvaluationResponse,
)
def admin_evaluate_vulnerabilities(
    payload: VulnerabilityEvaluateRequest,
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(
        admin_token,
        capability="vulnerability administration",
    )
    full_rebuild = not any(
        (
            payload.site_id,
            payload.asset_id,
            payload.component_id,
            payload.advisory_id,
        )
    )
    if full_rebuild and not _full_vulnerability_limiter.allow():
        raise HTTPException(
            status_code=429,
            detail="full vulnerability evaluation is temporarily rate limited",
        )
    try:
        return evaluate_vulnerabilities(
            trigger_type="admin-request",
            requested_by=payload.requested_by,
            site_id=payload.site_id,
            asset_id=payload.asset_id,
            component_id=payload.component_id,
            advisory_id=payload.advisory_id,
        ).as_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="deterministic vulnerability evaluation failed") from exc


@app.post("/api/v1/admin/vulnerabilities/import", deprecated=True)
async def admin_import_vulnerability_catalog(
    request: Request,
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(
        admin_token,
        capability="vulnerability catalog administration",
    )
    _ = request
    raise HTTPException(
        status_code=410,
        detail=(
            "unsigned advisory catalog import is disabled; use the reviewed "
            "signed advisory feed synchronization lifecycle"
        ),
    )


def _raise_advisory_sync_api_error(
    exc: RegistryError | AdvisorySyncStoreError | AdvisorySyncError,
) -> None:
    if exc.code in {"source-unknown", "run-not-found", "catalog-not-found", "activation-not-found"}:
        status_code = 404
    elif exc.code in {"sync-rate-limited", "control-action-rate-limited"}:
        status_code = 429
    elif exc.code in {
        "source-disabled",
        "sync-already-active",
        "run-state-conflict",
        "rollback-target-active",
        "reevaluation-state-conflict",
    }:
        status_code = 409
    else:
        status_code = 400
    raise HTTPException(status_code=status_code, detail=exc.summary) from exc


def _run_advisory_sync_background(service: AdvisorySyncService, run_id: str) -> None:
    try:
        service.execute_remote_run(run_id)
    except AdvisorySyncError as exc:
        LOGGER.warning("advisory feed synchronization failed safely: %s", exc.code)


def _activate_advisory_background(
    service: AdvisorySyncService,
    run_id: str,
    actor: str,
) -> None:
    try:
        service.activate(run_id, actor=actor)
    except (AdvisorySyncError, AdvisorySyncStoreError, RegistryError) as exc:
        LOGGER.warning("advisory catalog activation failed safely: %s", exc.code)
    except Exception as exc:  # noqa: BLE001 - response already returned; never log feed text.
        LOGGER.error("advisory catalog activation failed safely: %s", type(exc).__name__)


def _rollback_advisory_background(
    service: AdvisorySyncService,
    catalog_id: str,
    actor: str,
) -> None:
    try:
        service.rollback(catalog_id, actor=actor)
    except (AdvisorySyncError, AdvisorySyncStoreError, RegistryError) as exc:
        LOGGER.warning("advisory catalog rollback failed safely: %s", exc.code)
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("advisory catalog rollback failed safely: %s", type(exc).__name__)


@app.get("/api/v1/admin/advisory-feeds")
def admin_advisory_feeds(
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="advisory feed administration")
    try:
        return {"items": _advisory_sync_service().list_sources()}
    except (RegistryError, AdvisorySyncStoreError) as exc:
        _raise_advisory_sync_api_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load advisory feed status") from exc


@app.get("/api/v1/admin/advisory-feeds/{source_id}")
def admin_advisory_feed_status(
    source_id: str = ApiPath(..., pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="advisory feed administration")
    try:
        return _advisory_sync_service().source_status(source_id)
    except (RegistryError, AdvisorySyncStoreError) as exc:
        _raise_advisory_sync_api_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load advisory feed status") from exc


@app.post("/api/v1/admin/advisory-feeds/{source_id}/sync", status_code=202)
def admin_sync_advisory_feed(
    payload: AdvisorySyncRequest,
    background_tasks: BackgroundTasks,
    source_id: str = ApiPath(..., pattern=r"^[a-z0-9][a-z0-9._-]{2,63}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="advisory feed administration")
    service = _advisory_sync_service()
    try:
        run = service.request_sync(source_id=source_id, requested_by=ADVISORY_API_ACTOR)
        background_tasks.add_task(_run_advisory_sync_background, service, run["run_id"])
        return run
    except (RegistryError, AdvisorySyncStoreError, AdvisorySyncError) as exc:
        _raise_advisory_sync_api_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to request advisory synchronization") from exc


@app.get("/api/v1/admin/advisory-feed-runs")
def admin_advisory_feed_runs(
    source_id: str | None = Query(default=None, min_length=3, max_length=64),
    state: str | None = Query(default=None, min_length=3, max_length=40),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10_000),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="advisory feed administration")
    try:
        return _advisory_sync_store().list_runs(
            source_id=source_id,
            state=state,
            limit=limit,
            offset=offset,
        )
    except AdvisorySyncStoreError as exc:
        _raise_advisory_sync_api_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load advisory synchronization runs") from exc


@app.get("/api/v1/admin/advisory-feed-runs/{run_id}")
def admin_advisory_feed_run(
    run_id: str = ApiPath(..., pattern=r"^afrun_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="advisory feed administration")
    try:
        return _advisory_sync_store().get_run(run_id)
    except AdvisorySyncStoreError as exc:
        _raise_advisory_sync_api_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load advisory synchronization run") from exc


@app.get("/api/v1/admin/advisory-feed-runs/{run_id}/preview")
def admin_advisory_feed_preview(
    run_id: str = ApiPath(..., pattern=r"^afrun_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="advisory feed administration")
    try:
        run = _advisory_sync_store().get_run(run_id, include_preview=True)
        if run.get("preview") is None:
            raise AdvisorySyncStoreError("preview-unavailable", "verified advisory preview is not available")
        return {"run_id": run_id, "state": run["state"], "preview": run["preview"]}
    except AdvisorySyncStoreError as exc:
        _raise_advisory_sync_api_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load advisory preview") from exc


@app.post("/api/v1/admin/advisory-feed-runs/{run_id}/approve")
def admin_approve_advisory_feed_run(
    payload: AdvisoryApprovalRequest,
    run_id: str = ApiPath(..., pattern=r"^afrun_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="advisory feed administration")
    try:
        return _advisory_sync_service().approve(run_id, actor=ADVISORY_API_ACTOR)
    except (AdvisorySyncStoreError, AdvisorySyncError) as exc:
        _raise_advisory_sync_api_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to approve advisory feed run") from exc


@app.post("/api/v1/admin/advisory-feed-runs/{run_id}/reject")
def admin_reject_advisory_feed_run(
    payload: AdvisoryRejectionRequest,
    run_id: str = ApiPath(..., pattern=r"^afrun_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="advisory feed administration")
    try:
        return _advisory_sync_service().reject(run_id, actor=ADVISORY_API_ACTOR, reason=payload.reason)
    except (AdvisorySyncStoreError, AdvisorySyncError) as exc:
        _raise_advisory_sync_api_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to reject advisory feed run") from exc


@app.post("/api/v1/admin/advisory-feed-runs/{run_id}/activate", status_code=202)
def admin_activate_advisory_feed_run(
    payload: AdvisoryApprovalRequest,
    background_tasks: BackgroundTasks,
    run_id: str = ApiPath(..., pattern=r"^afrun_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="advisory feed administration")
    service = _advisory_sync_service()
    try:
        run = service.store.get_run(run_id)
        if run["state"] != "approved":
            raise AdvisorySyncStoreError("run-state-conflict", "only an approved verified run can be activated")
        background_tasks.add_task(_activate_advisory_background, service, run_id, ADVISORY_API_ACTOR)
        return {"run_id": run_id, "state": "approved", "activation_status": "scheduled"}
    except (AdvisorySyncStoreError, AdvisorySyncError) as exc:
        _raise_advisory_sync_api_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to schedule advisory catalog activation") from exc


@app.post("/api/v1/admin/advisory-catalog/rollback", status_code=202)
def admin_rollback_advisory_catalog(
    payload: AdvisoryRollbackRequest,
    background_tasks: BackgroundTasks,
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="advisory feed administration")
    service = _advisory_sync_service()
    try:
        retained = service.store.get_catalog(payload.catalog_id)
        if retained["active"]:
            raise AdvisorySyncStoreError("rollback-target-active", "rollback target is already active")
        background_tasks.add_task(_rollback_advisory_background, service, payload.catalog_id, ADVISORY_API_ACTOR)
        return {"catalog_id": payload.catalog_id, "rollback_status": "scheduled"}
    except (AdvisorySyncStoreError, AdvisorySyncError) as exc:
        _raise_advisory_sync_api_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to schedule advisory catalog rollback") from exc


@app.post("/api/v1/admin/advisory-catalog-activations/{activation_id}/retry-reevaluation")
def admin_retry_advisory_reevaluation(
    payload: AdvisoryReevaluationRetryRequest,
    activation_id: str = ApiPath(..., pattern=r"^afact_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="advisory feed administration")
    try:
        return _advisory_sync_service().retry_reevaluation(activation_id, actor=ADVISORY_API_ACTOR)
    except (AdvisorySyncStoreError, AdvisorySyncError) as exc:
        _raise_advisory_sync_api_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to retry advisory reevaluation") from exc


@app.get("/api/v1/admin/advisory-catalogs")
def admin_advisory_catalogs(
    source_id: str = Query(..., min_length=3, max_length=64),
    limit: int = Query(default=50, ge=1, le=100),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(admin_token, capability="advisory feed administration")
    try:
        _advisory_sync_service().registry.source(source_id, require_enabled=False)
        return {"items": _advisory_sync_store().list_catalogs(source_id=source_id, limit=limit)}
    except (RegistryError, AdvisorySyncStoreError) as exc:
        _raise_advisory_sync_api_error(exc)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load retained advisory catalogs") from exc


@app.get("/api/v1/classifications", response_model=ClassificationListResponse)
def api_classifications(
    site_id: str | None = Query(default=None, min_length=1, max_length=128),
    category: str | None = Query(default=None, min_length=1, max_length=80),
    manufacturer: str | None = Query(default=None, min_length=1, max_length=160),
    os_family: str | None = Query(default=None, min_length=1, max_length=80),
    managed_capability: str | None = Query(default=None),
    status: str | None = Query(default=None),
    minimum_confidence: float | None = Query(default=None, ge=0.0, le=1.0),
    conflict_state: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=10_000),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    supported_categories = {
        "workstation",
        "server",
        "mobile",
        "network-device",
        "printer",
        "camera",
        "media-device",
        "storage",
        "iot",
        "ot-industrial",
        "virtual-machine",
        "unknown",
    }
    supported_statuses = {
        "classified",
        "partially-classified",
        "unknown",
        "conflicting",
        "insufficient-evidence",
    }
    if category and category not in supported_categories:
        raise HTTPException(status_code=400, detail="unsupported classification category")
    if status and status not in supported_statuses:
        raise HTTPException(status_code=400, detail="unsupported classification status")
    if managed_capability and managed_capability not in {
        "expected",
        "not-expected",
        "unknown",
    }:
        raise HTTPException(status_code=400, detail="unsupported managed capability")
    if conflict_state and conflict_state not in {"open", "none"}:
        raise HTTPException(status_code=400, detail="unsupported conflict state")
    try:
        return _classification_store().list_classifications(
            site_id=site_id,
            category=category,
            manufacturer=manufacturer,
            os_family=os_family,
            managed_capability=managed_capability,
            status=status,
            minimum_confidence=minimum_confidence,
            conflict_state=conflict_state,
            limit=limit,
            offset=offset,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load deterministic classifications") from exc


@app.get(
    "/api/v1/classifications/summary",
    response_model=ClassificationSummaryResponse,
)
def api_classification_summary(
    site_id: str | None = Query(default=None, min_length=1, max_length=128),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    try:
        return _classification_store().site_summary(site_id=site_id)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load classification summary") from exc


@app.get(
    "/api/v1/classifications/catalog/status",
    response_model=VendorCatalogStatusResponse,
)
def api_vendor_catalog_status(
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    return configured_catalog_status()


@app.get(
    "/api/v1/classifications/assets/{asset_id}",
    response_model=ClassificationResponse,
)
def api_asset_classification(
    asset_id: str = ApiPath(..., min_length=1, max_length=160),
    site_id: str = Query(..., min_length=1, max_length=128),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    try:
        classification = _classification_store().get_classification(
            site_id=site_id,
            asset_id=asset_id,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load asset classification") from exc
    if classification is None:
        raise HTTPException(
            status_code=404,
            detail="asset classification not found; run deterministic evaluation",
        )
    return classification


@app.get(
    "/api/v1/classifications/assets/{asset_id}/evidence",
    response_model=ClassificationEvidenceListResponse,
)
def api_asset_classification_evidence(
    asset_id: str = ApiPath(..., min_length=1, max_length=160),
    site_id: str = Query(..., min_length=1, max_length=128),
    limit: int = Query(default=100, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=10_000),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    try:
        return _classification_store().list_evidence(
            site_id=site_id,
            asset_id=asset_id,
            limit=limit,
            offset=offset,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load classification evidence") from exc


@app.post(
    "/api/v1/admin/classifications/evaluate",
    response_model=ClassificationEvaluationResponse,
)
def admin_evaluate_classifications(
    payload: ClassificationEvaluateRequest,
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(
        admin_token,
        capability="classification administration",
    )
    bulk_rebuild = payload.asset_id is None and payload.asset_ids is None
    if bulk_rebuild and not _full_classification_limiter.allow():
        raise HTTPException(
            status_code=429,
            detail="bulk classification rebuild is temporarily rate limited",
        )
    try:
        return evaluate_classifications(
            trigger_type="admin-request",
            requested_by=payload.requested_by,
            site_id=payload.site_id,
            asset_id=payload.asset_id,
            asset_ids=payload.asset_ids,
        ).as_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="deterministic classification failed") from exc


@app.get("/api/v1/findings/rules", response_model=RuleRegistryResponse)
def api_finding_rules(
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    return {
        "ruleset_version": RULESET_VERSION,
        "rules": rule_registry_public(),
        "deferred_rules": [
            "VLAN movement is deferred until normalized, durable VLAN history exists; display strings are not evidence.",
        ],
    }


@app.get("/api/v1/findings", response_model=FindingListResponse)
def api_findings(
    site_id: str | None = Query(default=None, min_length=1, max_length=128),
    asset_id: str | None = Query(default=None, min_length=1, max_length=160),
    sensor_id: str | None = Query(default=None, min_length=1, max_length=160),
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    rule_id: str | None = Query(default=None, min_length=1, max_length=64),
    category: str | None = Query(default=None, min_length=1, max_length=64),
    updated_after: datetime | None = Query(default=None),
    updated_before: datetime | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=10_000),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    for value in (updated_after, updated_before):
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise HTTPException(status_code=400, detail="finding time filters must include a timezone")
    if updated_after is not None and updated_before is not None and updated_after > updated_before:
        raise HTTPException(status_code=400, detail="updated_after must not exceed updated_before")
    try:
        return _finding_store().list_findings(
            site_id=site_id,
            asset_id=asset_id,
            sensor_id=sensor_id,
            status=status,
            severity=severity,
            rule_id=rule_id,
            category=category,
            updated_after=updated_after,
            updated_before=updated_before,
            limit=limit,
            offset=offset,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load deterministic findings") from exc


@app.get("/api/v1/findings/{finding_id}", response_model=FindingResponse)
def api_finding(
    finding_id: str = ApiPath(..., pattern=r"^fnd_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    try:
        finding = _finding_store().get_finding(finding_id)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load deterministic finding") from exc
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding


@app.post("/api/v1/admin/findings/evaluate", response_model=FindingEvaluationResponse)
def admin_evaluate_findings(
    payload: FindingEvaluateRequest,
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(
        admin_token,
        capability="finding administration",
    )
    try:
        return evaluate_findings(
            trigger_type="admin-request",
            requested_by=payload.requested_by,
            site_id=payload.site_id,
            asset_id=payload.asset_id,
            sensor_id=payload.sensor_id,
            rule_ids=payload.rule_ids,
        ).as_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="deterministic finding evaluation failed") from exc


@app.post("/api/v1/admin/findings/{finding_id}/acknowledge", response_model=FindingResponse)
def admin_acknowledge_finding(
    payload: FindingAcknowledgeRequest,
    finding_id: str = ApiPath(..., pattern=r"^fnd_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(
        admin_token,
        capability="finding administration",
    )
    store = _finding_store()
    try:
        finding = store.acknowledge(
            finding_id,
            actor=payload.actor,
            at=datetime.now(timezone.utc),
        )
        if finding is not None:
            return finding
        if store.get_finding(finding_id) is None:
            raise HTTPException(status_code=404, detail="finding not found")
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to acknowledge finding") from exc
    raise HTTPException(status_code=409, detail="resolved findings cannot be acknowledged")


@app.post("/api/v1/admin/findings/{finding_id}/suppress", response_model=FindingResponse)
def admin_suppress_finding(
    payload: FindingSuppressRequest,
    finding_id: str = ApiPath(..., pattern=r"^fnd_[0-9a-f]{32}$"),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_configured_admin_token(
        admin_token,
        capability="finding administration",
    )
    store = _finding_store()
    now = datetime.now(timezone.utc)
    if payload.until is not None and payload.until <= now:
        raise HTTPException(status_code=400, detail="suppression expiry must be in the future")
    try:
        finding = store.suppress(
            finding_id,
            actor=payload.actor,
            reason=payload.reason,
            until=payload.until,
            at=now,
        )
        if finding is None:
            if store.get_finding(finding_id) is None:
                raise HTTPException(status_code=404, detail="finding not found")
            raise HTTPException(status_code=409, detail="resolved findings cannot be suppressed")
        evaluate_site_best_effort(
            site_id=finding["site_id"],
            trigger_type="finding-suppression",
            requested_by=payload.actor,
        )
        refreshed = store.get_finding(finding_id)
        return refreshed or finding
    except HTTPException:
        raise
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to suppress finding") from exc


@app.get("/api/v1/risk/summary", response_model=RiskSummaryResponse)
def api_risk_summary(
    site_id: str | None = Query(default=None, min_length=1, max_length=128),
    limit: int = Query(default=100, ge=1, le=200),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    try:
        return _finding_store().risk_summary(site_id=site_id, limit=limit)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load deterministic risk summary") from exc


@app.get("/api/v1/risk/assets/{asset_id}", response_model=AssetRiskResponse)
def api_asset_risk(
    asset_id: str = ApiPath(..., min_length=1, max_length=160),
    site_id: str = Query(..., min_length=1, max_length=128),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    try:
        risk = _finding_store().get_asset_risk(site_id=site_id, asset_id=asset_id)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load deterministic asset risk") from exc
    if risk is None:
        raise HTTPException(status_code=404, detail="asset risk not found; run deterministic evaluation")
    return risk


@app.get("/api/v1/risk/sites/{site_id}", response_model=SiteRiskResponse)
def api_site_risk(
    site_id: str = ApiPath(..., min_length=1, max_length=128),
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    try:
        risk = _finding_store().get_site_risk(site_id=site_id)
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load deterministic site risk") from exc
    if risk is None:
        raise HTTPException(status_code=404, detail="site risk not found; run deterministic evaluation")
    return risk


def build_read_only_hub_tools(*, include_advisory_feed_evidence: bool = False) -> ReadOnlyHubTools:
    store = _finding_store()
    classification_store = _classification_store()
    findings = store.list_findings(limit=200, status="active")["items"]
    findings.extend(store.list_findings(limit=200, status="acknowledged")["items"])
    risk = store.risk_summary(limit=200)
    return ReadOnlyHubTools(
        sites=list_sites(),
        sensors=list_agent_enrollments(),
        assets=list_control_tower_assets(),
        findings=findings,
        asset_risks=risk["assets"],
        site_risks=risk["sites"],
        classification_evidence=classification_store.evidence_snapshot(
            limit=1_000,
        ),
        components=_component_store().component_snapshot(limit=2_000),
        vulnerability_matches=_vulnerability_store().active_match_snapshot(
            limit=20_000,
        ),
        advisory_feed_evidence=(
            _advisory_sync_store().ai_snapshot(limit=20)
            if include_advisory_feed_evidence
            else []
        ),
        kev_status=_kev_store().status(),
    )


@app.get("/api/v1/hub/sites/summary", response_model=SiteIntelligenceSummaryResponse)
def api_hub_site_summaries(
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    try:
        tools = build_read_only_hub_tools()
        return {
            "sites": tools.run("site_summary")["items"],
            "data_as_of": tools.data_as_of(),
        }
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load site intelligence summary") from exc


@app.get("/api/v1/hub/sensors", response_model=SensorSummaryResponse)
def api_hub_sensors(
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    try:
        tools = build_read_only_hub_tools()
        return {"sensors": tools.run("sensor_health")["items"], "data_as_of": tools.data_as_of()}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load sensor intelligence summary") from exc


@app.get("/api/v1/ai/status", response_model=ProviderStatusResponse)
def api_ai_provider_status(
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    return provider_status()


def _record_advisor_audit(
    *,
    run_id: str,
    request: AdvisorQueryRequest,
    provider: str,
    mode: str,
    tool_names: list[str],
    evidence_count: int,
    status: str,
) -> None:
    record_ai_advisor_run(
        run_id=run_id,
        question_sha256=hashlib.sha256(request.question.encode("utf-8")).hexdigest(),
        site_id=request.site_id,
        provider=provider,
        mode=mode,
        tool_names=tool_names,
        evidence_count=evidence_count,
        status=status,
    )


@app.post("/api/v1/ai/advisor/query", response_model=AdvisorResponse)
def api_ai_advisor_query(
    payload: AdvisorQueryRequest,
    admin_token: str | None = Header(default=None, alias=ADMIN_TOKEN_HEADER),
):
    require_admin_token(admin_token)
    status = provider_status()
    try:
        expected_admin_token = os.getenv(ADMIN_TOKEN_ENV)
        include_advisory_feed_evidence = bool(
            expected_admin_token
            and isinstance(admin_token, str)
            and secrets.compare_digest(admin_token, expected_admin_token)
        )
        tools = build_read_only_hub_tools(
            include_advisory_feed_evidence=include_advisory_feed_evidence
        )
        response = run_advisor(request=payload, tools=tools)
        _record_advisor_audit(
            run_id=response.run_id,
            request=payload,
            provider=response.provider,
            mode=response.mode,
            tool_names=response.tools_used,
            evidence_count=len(response.evidence),
            status="completed",
        )
        return response
    except ProviderUnavailableError as exc:
        try:
            _record_advisor_audit(
                run_id=str(uuid4()),
                request=payload,
                provider=status.provider,
                mode=status.mode,
                tool_names=select_tools(payload.question),
                evidence_count=0,
                status="provider-unavailable",
            )
        except SQLAlchemyError:
            pass
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ProviderOutputError as exc:
        try:
            _record_advisor_audit(
                run_id=str(uuid4()),
                request=payload,
                provider=status.provider,
                mode=status.mode,
                tool_names=select_tools(payload.question),
                evidence_count=0,
                status="invalid-provider-output",
            )
        except SQLAlchemyError:
            pass
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load or audit AI Advisor evidence") from exc


@app.get("/api/v1/releases/agent", response_model=ReleaseStatusResponse)
def api_agent_release_status():
    return {
        "server_version": CONTROL_TOWER_VERSION,
        "expected_agent_version": EXPECTED_AGENT_VERSION,
        "channel": AGENT_RELEASE_CHANNEL,
        "update_available": False,
        "update_execution": "disabled",
        "message": "Agent release metadata placeholder only; no download or update execution is performed.",
    }


class CollectorPolicyResponse(BaseModel):
    policy_id: str
    policy_version: int
    policy_hash: str
    assigned_at: str | None = None
    minimum_collector_version: str | None = None
    license_status: str
    assigned_capabilities: list[str]
    denied_capabilities: list[str]
    policy: dict[str, Any]


class CollectorPolicyStatusRequest(BaseModel):
    collector_guid: str | None = None
    collector_id: str | None = None
    policy_id: str = Field(..., min_length=1)
    policy_version: int
    policy_hash: str = Field(..., min_length=1)
    policy_status: str
    policy_error: str | None = None


class CollectorPolicyStatusResponse(BaseModel):
    status: str
    received_at: datetime
    collector_guid: str | None = None
    collector_id: str | None = None
    policy_id: str
    policy_version: int
    policy_status: str


class AdminPolicyRequest(BaseModel):
    policy_id: str = Field(..., min_length=1)
    policy_name: str | None = None
    policy_version: int = 1
    enabled: bool = True
    policy_json: dict[str, Any] | None = None
    minimum_collector_version: str | None = None
    license_status: str = "dev_mode"
    assigned_capabilities: list[str] = Field(default_factory=list)
    denied_capabilities: list[str] = Field(default_factory=list)
    policy: dict[str, Any] | None = None


class AdminPolicyAssignmentRequest(BaseModel):
    assignment_name: str | None = None
    policy_id: str = Field(..., min_length=1)
    enabled: bool = True
    priority: int = 0
    collector_guid: str | None = None
    collector_id: str | None = None
    deployment_id: str | None = None
    platform: str | None = None
    label_selector: dict[str, Any] | None = None


LOCAL_INVENTORY_FORBIDDEN_TOP_LEVEL_FIELDS = frozenset(
    {
        "command",
        "args",
        "additional_args",
        "target",
        "username",
        "password",
        "hash",
        "script_content",
        "source_authenticated",
        "authoritative",
        "risk",
        "finding",
        "severity_override",
        "management_state",
        "tenant_authority",
        "site_authority",
        "agent_authority",
    }
)
AGENT_CHECKIN_FORBIDDEN_TOP_LEVEL_FIELDS = frozenset(
    {
        "command",
        "args",
        "additional_args",
        "password",
        "hash",
        "script_content",
        "source_authenticated",
        "authoritative",
        "risk",
        "finding",
        "severity_override",
        "management_state",
        "tenant_authority",
        "site_authority",
        "agent_authority",
    }
)


def calculate_policy_hash(policy_payload: dict[str, Any]) -> str:
    policy_copy = dict(policy_payload)
    policy_copy.pop("policy_hash", None)
    canonical = json_dumps_canonical(policy_copy).encode("utf-8")
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def json_dumps_canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def default_collector_policy_payload() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "policy_id": "default-local-collector",
        "policy_version": 1,
        "assigned_at": None,
        "minimum_collector_version": None,
        "license_status": "dev_mode",
        "assigned_capabilities": [
            "device_inventory",
            "network_neighbors",
            "open_detector",
        ],
        "denied_capabilities": [],
        "policy": {
            "mode": "hybrid",
            "scheduler": {
                "heartbeat_interval_seconds": 3600,
                "inventory_interval_seconds": 86400,
            },
            "modules": {
                "open_detector": {"enabled": True},
                "reverse_dns": {"enabled": False},
                "mdns": {"enabled": False},
                "ssdp": {"enabled": False},
                "snmp": {"enabled": False},
            },
            "actions": {
                "run_inventory_now": False,
            },
        },
    }
    payload["policy_hash"] = calculate_policy_hash(payload)
    return payload


def policy_json_from_admin_request(payload: AdminPolicyRequest) -> dict[str, Any]:
    if payload.policy_json is not None:
        return payload.policy_json
    return {
        "minimum_collector_version": payload.minimum_collector_version,
        "license_status": payload.license_status,
        "assigned_capabilities": payload.assigned_capabilities,
        "denied_capabilities": payload.denied_capabilities,
        "policy": payload.policy or {},
    }


def assigned_policy_payload(policy_record: dict[str, Any]) -> dict[str, Any]:
    policy_json = policy_record.get("policy_json")
    if not isinstance(policy_json, dict):
        policy_json = {}

    assigned_at = policy_record.get("assigned_at")
    if isinstance(assigned_at, datetime):
        assigned_at = assigned_at.isoformat()

    payload: dict[str, Any] = {
        "policy_id": policy_record["policy_id"],
        "policy_version": int(policy_record.get("policy_version") or 1),
        "assigned_at": assigned_at,
        "minimum_collector_version": policy_json.get("minimum_collector_version"),
        "license_status": policy_json.get("license_status") or "dev_mode",
        "assigned_capabilities": policy_json.get("assigned_capabilities") or [],
        "denied_capabilities": policy_json.get("denied_capabilities") or [],
        "policy": policy_json.get("policy") or {},
    }
    payload["policy_hash"] = calculate_policy_hash(payload)
    return payload


def parse_labels_query(labels: str | None) -> dict[str, Any] | None:
    if not labels:
        return None
    try:
        parsed = json.loads(labels)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="labels must be a JSON object") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="labels must be a JSON object")
    return parsed


@app.post("/api/v1/collectors/checkin", response_model=CollectorCheckInResponse)
def collector_checkin(
    payload: CollectorCheckInRequest,
    collector_token: str | None = Header(default=None, alias=COLLECTOR_TOKEN_HEADER),
):
    require_collector_token(collector_token)
    received_at = datetime.now(timezone.utc)
    try:
        upsert_collector_metadata(
            collector_guid=payload.collector_guid,
            collector_id=payload.collector_id,
            collector_name=payload.collector_name,
            collector_version=payload.collector_version,
            deployment=payload.deployment,
            labels=payload.labels,
            supported_capabilities=payload.supported_capabilities,
            enabled_capabilities=payload.enabled_capabilities,
            mode=payload.mode,
            seen_at=received_at,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to update collector check-in") from exc

    return CollectorCheckInResponse(
        status="accepted",
        collector_id=payload.collector_id,
        received_at=received_at,
        next_heartbeat_minutes=60,
        inventory_interval_hours=24,
    )


@app.get("/api/v1/collectors/policy", response_model=CollectorPolicyResponse)
def collector_policy(
    collector_guid: str | None = None,
    collector_id: str | None = None,
    deployment_id: str | None = None,
    platform: str | None = None,
    labels: str | None = None,
    collector_token: str | None = Header(default=None, alias=COLLECTOR_TOKEN_HEADER),
):
    require_collector_token(collector_token)
    parsed_labels = parse_labels_query(labels)
    try:
        assigned_policy = find_assigned_collector_policy(
            collector_guid=collector_guid,
            collector_id=collector_id,
            deployment_id=deployment_id,
            platform=platform,
            labels=parsed_labels,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to resolve collector policy") from exc
    if assigned_policy is not None:
        return assigned_policy_payload(assigned_policy)
    return default_collector_policy_payload()


@app.get("/api/v1/admin/policies")
def admin_policies():
    # MVP/dev-only endpoint. Add authentication/authorization before production use.
    try:
        return {"policies": list_collector_policies()}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load policies") from exc


@app.post("/api/v1/admin/policies")
def admin_create_policy(payload: AdminPolicyRequest):
    # MVP/dev-only endpoint. Add authentication/authorization before production use.
    if payload.policy_version < 1:
        raise HTTPException(status_code=400, detail="policy_version must be >= 1")
    try:
        policy = upsert_collector_policy(
            policy_id=payload.policy_id,
            policy_name=payload.policy_name,
            policy_version=payload.policy_version,
            policy_json=policy_json_from_admin_request(payload),
            enabled=payload.enabled,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to save policy") from exc
    return {"status": "accepted", "policy": policy}


@app.get("/api/v1/admin/policy-assignments")
def admin_policy_assignments():
    # MVP/dev-only endpoint. Add authentication/authorization before production use.
    try:
        return {"policy_assignments": list_policy_assignments()}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load policy assignments") from exc


@app.post("/api/v1/admin/policy-assignments")
def admin_create_policy_assignment(payload: AdminPolicyAssignmentRequest):
    # MVP/dev-only endpoint. Add authentication/authorization before production use.
    try:
        assignment = create_policy_assignment(
            assignment_name=payload.assignment_name,
            policy_id=payload.policy_id,
            enabled=payload.enabled,
            priority=payload.priority,
            collector_guid=payload.collector_guid,
            collector_id=payload.collector_id,
            deployment_id=payload.deployment_id,
            platform=payload.platform,
            label_selector=payload.label_selector,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to save policy assignment") from exc
    return {"status": "accepted", "policy_assignment": assignment}


@app.post("/api/v1/collectors/policy-status", response_model=CollectorPolicyStatusResponse)
def collector_policy_status(
    payload: CollectorPolicyStatusRequest,
    collector_token: str | None = Header(default=None, alias=COLLECTOR_TOKEN_HEADER),
):
    require_collector_token(collector_token)
    if payload.policy_status not in {"applied", "failed", "held", "ignored"}:
        raise HTTPException(status_code=400, detail="invalid policy_status")
    return CollectorPolicyStatusResponse(
        status="accepted",
        received_at=datetime.now(timezone.utc),
        collector_guid=payload.collector_guid,
        collector_id=payload.collector_id,
        policy_id=payload.policy_id,
        policy_version=payload.policy_version,
        policy_status=payload.policy_status,
    )


def collector_id_from_inventory(payload: CollectorInventoryRequest) -> str | None:
    if payload.collector_id:
        return payload.collector_id
    if isinstance(payload.collector, dict):
        collector_id = payload.collector.get("id")
        if collector_id:
            return str(collector_id)
    return None


def collector_guid_from_inventory(payload: CollectorInventoryRequest) -> str | None:
    if payload.collector_guid:
        return payload.collector_guid
    if isinstance(payload.collector, dict):
        collector_guid = payload.collector.get("guid") or payload.collector.get("collector_guid")
        if collector_guid:
            return str(collector_guid)
    return None


def collector_name_from_inventory(payload: CollectorInventoryRequest) -> str | None:
    if payload.collector_name:
        return payload.collector_name
    if isinstance(payload.collector, dict):
        collector_name = payload.collector.get("name")
        if collector_name:
            return str(collector_name)
    return None


def inventory_fields_present(payload: CollectorInventoryRequest) -> bool:
    fields_set = getattr(payload, "model_fields_set", None)
    if fields_set is None:
        fields_set = getattr(payload, "__fields_set__", set())
    return any(
        field_name in fields_set and getattr(payload, field_name) is not None
        for field_name in ("device", "network", "software")
    )


def network_observation_count(network: list[dict[str, Any]] | dict[str, Any] | None) -> int:
    if isinstance(network, list):
        return len(network)
    if isinstance(network, dict):
        neighbors = network.get("neighbors")
        if isinstance(neighbors, list):
            return len(neighbors)
        observations = network.get("observations")
        if isinstance(observations, list):
            return len(observations)
        return 1 if network else 0
    return 0


def local_inventory_site_id(payload: dict[str, Any]) -> str:
    site_id = payload.get("site_id")
    if not isinstance(site_id, str) or not site_id.strip():
        raise HTTPException(status_code=400, detail="site_id is required")
    return site_id.strip()


def local_inventory_observed_asset_count(payload: dict[str, Any]) -> int:
    assets = payload.get("assets", [])
    if assets is None:
        return 0
    if not isinstance(assets, list):
        raise HTTPException(status_code=400, detail="assets must be a JSON array")
    if any(not isinstance(asset, dict) for asset in assets):
        raise HTTPException(status_code=400, detail="assets must contain JSON objects")
    if len(assets) > MAX_LOCAL_INVENTORY_ASSETS:
        raise HTTPException(
            status_code=400,
            detail="local inventory asset limit exceeded",
        )
    return len(assets)


def forbidden_local_inventory_fields(payload: dict[str, Any]) -> list[str]:
    return sorted(field for field in payload if field in LOCAL_INVENTORY_FORBIDDEN_TOP_LEVEL_FIELDS)


def agent_checkin_site_id(payload: dict[str, Any]) -> str:
    site_id = payload.get("site_id")
    if not isinstance(site_id, str) or not site_id.strip():
        raise HTTPException(status_code=400, detail="site_id is required")
    return site_id.strip()


def agent_checkin_optional_text(payload: dict[str, Any], field_name: str) -> str | None:
    value = payload.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"{field_name} must be a string")
    text_value = value.strip()
    return text_value or None


def forbidden_agent_checkin_fields(payload: dict[str, Any]) -> list[str]:
    return sorted(field for field in payload if field in AGENT_CHECKIN_FORBIDDEN_TOP_LEVEL_FIELDS)


@app.post(
    "/api/v1/agents/check-in",
    response_model=BoundAgentCheckInResponse,
    response_model_exclude_none=True,
)
def agent_check_in(
    raw_payload: Any = Body(...),
    background_tasks: BackgroundTasks = None,
    agent_credential: str | None = Header(default=None, alias=AGENT_CREDENTIAL_HEADER),
):
    if not isinstance(agent_credential, str):
        agent_credential = None
    if not isinstance(raw_payload, dict):
        raise HTTPException(status_code=400, detail="agent check-in payload must be a JSON object")
    if not raw_payload:
        raise HTTPException(status_code=400, detail="agent check-in payload must not be empty")

    forbidden_fields = forbidden_agent_checkin_fields(raw_payload)
    if forbidden_fields:
        raise HTTPException(
            status_code=400,
            detail="agent check-in payload contains forbidden top-level fields: " + ", ".join(forbidden_fields),
        )

    received_at = datetime.now(timezone.utc)
    if agent_credential:
        try:
            if agent_credential.startswith("oaw_agent_v1."):
                payload = BoundAgentCheckInRequest.model_validate(raw_payload)
                auth_context = authenticate_agent_request(
                    provided_token=agent_credential,
                    claimed_site_id=payload.site_id,
                    claimed_agent_id=payload.agent_id,
                    claimed_deployment_id=payload.deployment_id,
                    claimed_agent_type=payload.agent_type,
                )
                record_authenticated_agent_checkin(
                    context=auth_context,
                    payload=payload.model_dump(mode="json", exclude_none=True),
                    received_at=received_at,
                )
                _queue_site_evaluation(
                    background_tasks,
                    site_id=str(auth_context.site_id),
                    sensor_id=str(auth_context.agent_id),
                )
                return BoundAgentCheckInResponse(
                    status="accepted",
                    site_id=str(auth_context.site_id),
                    agent_id=auth_context.agent_id,
                    agent_type="endpoint-agent",
                    credential_id=auth_context.credential_id,
                    identity_status="active",
                    source_authority="authenticated-endpoint",
                    received_at=received_at,
                    message="authenticated endpoint-agent check-in accepted",
                )
            shared_context = authenticate_agent_request(provided_token=agent_credential)
            if shared_context.mode != "development-shared":
                raise AgentAuthenticationRejected("valid agent credential required")
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail="invalid endpoint-agent check-in contract") from exc
        except AgentAuthenticationRejected as exc:
            raise HTTPException(status_code=401, detail="valid endpoint-agent credential required") from exc
        except SQLAlchemyError as exc:
            raise HTTPException(status_code=500, detail="failed to persist agent check-in") from exc

    site_id = agent_checkin_site_id(raw_payload)
    agent_id = agent_checkin_optional_text(raw_payload, "agent_id")
    try:
        record_agent_checkin(
            payload=raw_payload,
            site_id=site_id,
            agent_id=agent_id,
            received_at=received_at,
        )
    except LegacyAgentIdentityConflict as exc:
        raise HTTPException(
            status_code=409,
            detail="legacy agent identity conflicts with bound identity",
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to persist agent check-in") from exc

    _queue_site_evaluation(
        background_tasks,
        site_id=site_id,
        sensor_id=agent_id,
    )
    return BoundAgentCheckInResponse(
        status="accepted",
        site_id=site_id,
        agent_id=agent_id,
        agent_type="endpoint-agent",
        identity_status="legacy",
        source_authority="untrusted-legacy",
        received_at=received_at,
        message="legacy agent check-in accepted as untrusted compatibility metadata",
    )


@app.post("/api/v1/agents/inventory", response_model=EndpointInventoryResponse)
def authenticated_endpoint_inventory(
    payload: EndpointInventoryRequest,
    background_tasks: BackgroundTasks = None,
    agent_credential: str | None = Header(default=None, alias=AGENT_CREDENTIAL_HEADER),
):
    try:
        context = authenticate_agent_request(
            provided_token=agent_credential,
            claimed_site_id=payload.site_id,
            claimed_agent_id=payload.agent_id,
            claimed_deployment_id=payload.deployment_id,
            claimed_agent_type=payload.agent_type,
        )
    except AgentAuthenticationRejected as exc:
        raise HTTPException(status_code=401, detail="valid endpoint-agent credential required") from exc
    if context.mode != "bound-agent" or not all(
        (context.site_id, context.agent_id, context.credential_id)
    ):
        raise HTTPException(status_code=401, detail="bound endpoint-agent credential required")

    received_at = datetime.now(timezone.utc)
    try:
        acknowledgement = ingest_canonical_inventory(
            endpoint_envelope(
                payload=payload,
                context=context,
                received_at=received_at,
            )
        )
    except CanonicalReplayConflict as exc:
        raise HTTPException(status_code=409, detail="inventory batch content conflict") from exc
    except CanonicalAdmissionRejected as exc:
        raise HTTPException(
            status_code=429,
            detail="endpoint-agent inventory admission window exceeded",
        ) from exc
    except CanonicalAuthorizationRejected as exc:
        raise HTTPException(status_code=401, detail="valid endpoint-agent credential required") from exc
    except (CanonicalIngestionRejected, ValidationError) as exc:
        raise HTTPException(status_code=422, detail="invalid canonical endpoint inventory") from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to persist endpoint inventory") from exc
    if acknowledgement.endpoint_storage_id is None:
        raise HTTPException(
            status_code=500,
            detail="canonical endpoint acknowledgement is incomplete",
        )

    response_evaluation_state = acknowledgement.evaluation_state
    if (
        acknowledgement.status == "accepted"
        and acknowledgement.evaluation_state == "queued"
    ):
        response_evaluation_state = _queue_canonical_evaluation(
            background_tasks,
            canonical_collection_id=acknowledgement.canonical_collection_id,
            has_work=bool(acknowledgement.canonical_asset_ids),
        )
    return EndpointInventoryResponse(
        status=acknowledgement.status,
        inventory_batch_id=payload.inventory_batch_id,
        storage_id=acknowledgement.endpoint_storage_id,
        collection_id=acknowledgement.compatibility_collection_id,
        canonical_collection_id=acknowledgement.canonical_collection_id,
        site_id=str(context.site_id),
        agent_id=str(context.agent_id),
        credential_id=str(context.credential_id),
        received_at=acknowledgement.received_at,
        observed_asset_count=acknowledgement.observed_asset_count,
        normalized_asset_count=acknowledgement.normalized_asset_count,
        component_count=acknowledgement.component_count,
        reevaluation_state=response_evaluation_state,
        source_authority="authenticated-endpoint",
        adapter_type="endpoint-agent",
        compatibility_status="canonical",
        warnings=list(acknowledgement.warnings),
        message=(
            "identical inventory delivery already accepted"
            if acknowledgement.status == "duplicate"
            else (
                "authenticated endpoint inventory accepted; deterministic "
                f"reevaluation {response_evaluation_state}"
            )
        ),
    )


@app.post("/api/v1/collections/local-inventory", response_model=LocalInventoryCollectionResponse)
def local_inventory_collection(
    raw_payload: Any = Body(...),
    background_tasks: BackgroundTasks = None,
):
    if not isinstance(raw_payload, dict):
        raise HTTPException(status_code=400, detail="local inventory collection payload must be a JSON object")
    if not raw_payload:
        raise HTTPException(status_code=400, detail="local inventory collection payload must not be empty")

    forbidden_fields = forbidden_local_inventory_fields(raw_payload)
    if forbidden_fields:
        raise HTTPException(
            status_code=400,
            detail=(
                "local inventory collection payload contains forbidden top-level fields: "
                + ", ".join(forbidden_fields)
            ),
        )

    site_id = local_inventory_site_id(raw_payload)
    local_inventory_observed_asset_count(raw_payload)
    received_at = datetime.now(timezone.utc)
    try:
        acknowledgement = ingest_canonical_inventory(
            transitional_envelope(
                payload=raw_payload,
                received_at=received_at,
            )
        )
    except CanonicalReplayConflict as exc:
        raise HTTPException(
            status_code=409,
            detail="local inventory idempotency content conflict",
        ) from exc
    except CanonicalAdmissionRejected as exc:
        raise HTTPException(
            status_code=429,
            detail="local inventory admission window exceeded",
        ) from exc
    except CanonicalIngestionRejected as exc:
        raise HTTPException(
            status_code=400,
            detail="invalid local inventory compatibility payload",
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to persist local inventory collection") from exc

    response_evaluation_state = acknowledgement.evaluation_state
    if (
        acknowledgement.status == "accepted"
        and acknowledgement.evaluation_state == "queued"
    ):
        response_evaluation_state = _queue_canonical_evaluation(
            background_tasks,
            canonical_collection_id=acknowledgement.canonical_collection_id,
            has_work=bool(acknowledgement.canonical_asset_ids),
        )
    return LocalInventoryCollectionResponse(
        status=acknowledgement.status,
        observation_batch_id=acknowledgement.compatibility_collection_id,
        canonical_collection_id=acknowledgement.canonical_collection_id,
        site_id=site_id,
        received_at=acknowledgement.received_at,
        observed_asset_count=acknowledgement.observed_asset_count,
        normalized_asset_count=acknowledgement.normalized_asset_count,
        source_authority=acknowledgement.source_authority,
        adapter_type=acknowledgement.adapter_type,
        compatibility_status=acknowledgement.compatibility_status,
        evaluation_state=response_evaluation_state,
        warnings=list(acknowledgement.warnings),
        message=(
            "identical transitional inventory delivery already accepted"
            if acknowledgement.status == "duplicate"
            else "transitional local inventory accepted as untrusted compatibility input"
        ),
    )


@app.post("/api/v1/observations/batches", response_model=ObservationBatchResponse)
def observation_batch(
    payload: ObservationBatchRequest,
    background_tasks: BackgroundTasks = None,
    collector_token: str | None = Header(default=None, alias=COLLECTOR_TOKEN_HEADER),
):
    try:
        auth_context = authenticate_sensor_request(
            provided_token=collector_token,
            claimed_site_id=payload.site_id,
            claimed_sensor_id=payload.sensor_id,
            claimed_sensor_type=payload.sensor_type,
        )
    except SensorAuthenticationRejected as exc:
        raise HTTPException(status_code=401, detail="valid sensor credential required") from exc
    received_at = datetime.now(timezone.utc)
    try:
        acknowledgement = ingest_canonical_inventory(
            sensor_envelope(
                payload=payload,
                context=auth_context,
                received_at=received_at,
            )
        )
    except CanonicalAuthorizationRejected as exc:
        raise HTTPException(status_code=401, detail="valid sensor credential required") from exc
    except CanonicalReplayConflict as exc:
        raise HTTPException(
            status_code=409,
            detail="observation batch content conflict",
        ) from exc
    except CanonicalAdmissionRejected as exc:
        raise HTTPException(
            status_code=429,
            detail="observation batch admission window exceeded",
        ) from exc
    except CanonicalIngestionRejected as exc:
        raise HTTPException(
            status_code=400,
            detail="invalid canonical observation batch",
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to persist observation batch") from exc
    response_evaluation_state = acknowledgement.evaluation_state
    if (
        acknowledgement.status == "accepted"
        and acknowledgement.evaluation_state == "queued"
    ):
        response_evaluation_state = _queue_canonical_evaluation(
            background_tasks,
            canonical_collection_id=acknowledgement.canonical_collection_id,
            has_work=bool(acknowledgement.canonical_asset_ids),
        )
    return ObservationBatchResponse(
        status=acknowledgement.status,
        observation_batch_id=payload.observation_batch_id,
        storage_id=acknowledgement.compatibility_collection_id,
        canonical_collection_id=acknowledgement.canonical_collection_id,
        site_id=payload.site_id,
        sensor_id=payload.sensor_id,
        received_at=acknowledgement.received_at,
        observed_asset_count=acknowledgement.observed_asset_count,
        normalized_asset_count=acknowledgement.normalized_asset_count,
        source_authority=acknowledgement.source_authority,
        adapter_type="passive-sensor",
        compatibility_status=acknowledgement.compatibility_status,
        evaluation_state=response_evaluation_state,
        warnings=list(acknowledgement.warnings),
        message=(
            "observation batch was already stored; no duplicate asset evidence was added"
            if acknowledgement.status == "duplicate"
            else "normalized outbound observation batch accepted"
        ),
    )


@app.post("/api/v1/collectors/inventory", response_model=CollectorInventoryResponse)
def collector_inventory(
    raw_payload: Any = Body(...),
    background_tasks: BackgroundTasks = None,
    collector_token: str | None = Header(default=None, alias=COLLECTOR_TOKEN_HEADER),
):
    require_collector_token(collector_token)
    if not isinstance(raw_payload, dict):
        raise HTTPException(status_code=400, detail="inventory payload must be a JSON object")

    try:
        payload = CollectorInventoryRequest(**raw_payload)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail="invalid inventory payload") from exc
    if not inventory_fields_present(payload):
        raise HTTPException(
            status_code=400,
            detail="inventory payload must include at least one of: device, network, software",
        )

    received_at = datetime.now(timezone.utc)
    collector_guid = collector_guid_from_inventory(payload)
    collector_id = collector_id_from_inventory(payload)
    collector_name = collector_name_from_inventory(payload)
    device_count = 1 if payload.device is not None else 0
    network_count = network_observation_count(payload.network)
    software_count = len(payload.software) if isinstance(payload.software, list) else 0
    try:
        envelope = legacy_collector_envelope(
            payload=payload,
            received_at=received_at,
            authentication_class=(
                "legacy-shared"
                if os.getenv(COLLECTOR_TOKEN_ENV)
                else "unauthenticated"
            ),
        )
        acknowledgement = ingest_canonical_inventory(envelope)
    except CanonicalReplayConflict as exc:
        raise HTTPException(
            status_code=409,
            detail="collector inventory idempotency content conflict",
        ) from exc
    except CanonicalAdmissionRejected as exc:
        raise HTTPException(
            status_code=429,
            detail="collector inventory admission window exceeded",
        ) from exc
    except CanonicalIngestionRejected as exc:
        raise HTTPException(
            status_code=400,
            detail="invalid collector compatibility payload",
        ) from exc
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to persist inventory submission") from exc
    if acknowledgement.legacy_submission_id is None:
        raise HTTPException(
            status_code=500,
            detail="canonical collector acknowledgement is incomplete",
        )

    response_evaluation_state = acknowledgement.evaluation_state
    if (
        acknowledgement.status == "accepted"
        and acknowledgement.evaluation_state == "queued"
    ):
        response_evaluation_state = _queue_canonical_evaluation(
            background_tasks,
            canonical_collection_id=acknowledgement.canonical_collection_id,
            has_work=bool(acknowledgement.canonical_asset_ids),
        )

    return CollectorInventoryResponse(
        status=acknowledgement.status,
        submission_id=acknowledgement.legacy_submission_id,
        canonical_collection_id=acknowledgement.canonical_collection_id,
        received_at=acknowledgement.received_at,
        collector_guid=collector_guid,
        collector_id=collector_id,
        mode=payload.mode,
        device_count=device_count,
        network_observation_count=network_count,
        software_count=software_count,
        normalized_asset_count=acknowledgement.normalized_asset_count,
        normalized_software_count=acknowledgement.component_count,
        source_authority=acknowledgement.source_authority,
        adapter_type=acknowledgement.adapter_type,
        compatibility_status=acknowledgement.compatibility_status,
        evaluation_state=response_evaluation_state,
        warnings=list(acknowledgement.warnings),
    )


@app.get(
    "/api/v1/collectors/inventory/latest",
    response_model=CollectorInventoryLatestResponse,
)
def latest_collector_inventory():
    try:
        submission = latest_inventory_submission()
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load latest inventory submission") from exc

    if submission is None:
        raise HTTPException(status_code=404, detail="no inventory submissions found")
    return submission


@app.get("/api/v1/assets")
def assets():
    try:
        return {"assets": list_assets()}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load assets") from exc


@app.get("/api/v1/collectors")
def collectors():
    try:
        return {"collectors": list_collectors()}
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to load collectors") from exc
