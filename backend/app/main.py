import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Body, Header, HTTPException, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.exc import SQLAlchemyError

from .database import (
    control_tower_summary,
    create_policy_assignment,
    create_agent_enrollment,
    create_site,
    find_assigned_collector_policy,
    latest_inventory_submission,
    list_agent_checkins,
    list_agent_enrollments,
    list_assets,
    list_collectors,
    list_control_tower_assets,
    list_collector_policies,
    list_policy_assignments,
    list_sites,
    normalize_inventory_submission,
    record_agent_checkin,
    record_local_inventory_collection,
    save_inventory_submission,
    upsert_collector_policy,
    upsert_collector_metadata,
)

app = FastAPI(
    title="OpenAssetWatch API",
    description="Open-source family network asset intelligence platform.",
    version="0.1.0",
)


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
    allow_headers=["Content-Type", "X-OpenAssetWatch-Collector-Token"],
)

if UI_STATIC_DIR.exists():
    app.mount("/ui/static", StaticFiles(directory=UI_STATIC_DIR), name="control-tower-static")


COLLECTOR_TOKEN_ENV = "OPENASSETWATCH_COLLECTOR_TOKEN"
COLLECTOR_TOKEN_HEADER = "X-OpenAssetWatch-Collector-Token"


def require_collector_token(provided_token: str | None) -> None:
    expected_token = os.getenv(COLLECTOR_TOKEN_ENV)
    if not expected_token:
        return
    if not isinstance(provided_token, str):
        provided_token = None
    if provided_token and secrets.compare_digest(provided_token, expected_token):
        return
    raise HTTPException(status_code=401, detail="valid collector token required")


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
    received_at: datetime
    collector_guid: str | None = None
    collector_id: str | None = None
    mode: str | None = None
    device_count: int
    network_observation_count: int
    software_count: int
    normalized_asset_count: int
    normalized_software_count: int


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
    payload: dict[str, Any]


class LocalInventoryCollectionResponse(BaseModel):
    status: str
    observation_batch_id: int
    site_id: str
    received_at: datetime
    observed_asset_count: int
    normalized_asset_count: int = 0
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
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to save agent enrollment") from exc


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
    response_model=AgentCheckInResponse,
    response_model_exclude_none=True,
)
def agent_check_in(raw_payload: Any = Body(...)):
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

    site_id = agent_checkin_site_id(raw_payload)
    agent_id = agent_checkin_optional_text(raw_payload, "agent_id")
    received_at = datetime.now(timezone.utc)
    try:
        record_agent_checkin(
            payload=raw_payload,
            site_id=site_id,
            agent_id=agent_id,
            received_at=received_at,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to persist agent check-in") from exc

    return AgentCheckInResponse(
        status="accepted",
        site_id=site_id,
        agent_id=agent_id,
        received_at=received_at,
        message="agent check-in accepted as identity and health metadata",
    )


@app.post("/api/v1/collections/local-inventory", response_model=LocalInventoryCollectionResponse)
def local_inventory_collection(raw_payload: Any = Body(...)):
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
    observed_asset_count = local_inventory_observed_asset_count(raw_payload)
    received_at = datetime.now(timezone.utc)
    try:
        collection_result = record_local_inventory_collection(
            payload=raw_payload,
            site_id=site_id,
            received_at=received_at,
            observed_asset_count=observed_asset_count,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to persist local inventory collection") from exc

    return LocalInventoryCollectionResponse(
        status="accepted",
        observation_batch_id=collection_result["collection_id"],
        site_id=site_id,
        received_at=received_at,
        observed_asset_count=observed_asset_count,
        normalized_asset_count=collection_result["normalized_asset_count"],
        message="local inventory collection accepted as passive observations",
    )


@app.post("/api/v1/collectors/inventory", response_model=CollectorInventoryResponse)
def collector_inventory(
    raw_payload: Any = Body(...),
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
        submission_id = save_inventory_submission(
            collector_guid=collector_guid,
            collector_id=collector_id,
            collector_name=collector_name,
            mode=payload.mode,
            schema_version=payload.schema_version,
            collector_version=payload.collector_version,
            collected_at=payload.collected_at,
            received_at=received_at,
            device_count=device_count,
            network_observation_count=network_count,
            software_count=software_count,
            payload=raw_payload,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to persist inventory submission") from exc

    try:
        normalization_counts = normalize_inventory_submission(
            submission_id=submission_id,
            payload=raw_payload,
            collector_guid=collector_guid,
            collector_id=collector_id,
            collector_name=collector_name,
            collector_version=payload.collector_version,
            mode=payload.mode,
            received_at=received_at,
            supported_capabilities=payload.supported_capabilities,
            enabled_capabilities=payload.enabled_capabilities,
        )
    except SQLAlchemyError as exc:
        raise HTTPException(status_code=500, detail="failed to normalize inventory submission") from exc

    return CollectorInventoryResponse(
        status="accepted",
        submission_id=submission_id,
        received_at=received_at,
        collector_guid=collector_guid,
        collector_id=collector_id,
        mode=payload.mode,
        device_count=device_count,
        network_observation_count=network_count,
        software_count=software_count,
        normalized_asset_count=normalization_counts["normalized_asset_count"],
        normalized_software_count=normalization_counts["normalized_software_count"],
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
