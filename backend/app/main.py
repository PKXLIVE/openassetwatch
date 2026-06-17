import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import Body, Header, HTTPException, FastAPI
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.exc import SQLAlchemyError

from .database import (
    create_policy_assignment,
    find_assigned_collector_policy,
    latest_inventory_submission,
    list_assets,
    list_collectors,
    list_collector_policies,
    list_policy_assignments,
    normalize_inventory_submission,
    save_inventory_submission,
    upsert_collector_policy,
    upsert_collector_metadata,
)

app = FastAPI(
    title="OpenAssetWatch API",
    description="Open-source family network asset intelligence platform.",
    version="0.1.0",
)


COLLECTOR_TOKEN_ENV = "OPENASSETWATCH_COLLECTOR_TOKEN"
COLLECTOR_TOKEN_HEADER = "X-OpenAssetWatch-Collector-Token"


@app.get("/")
def root():
    return {
        "name": "OpenAssetWatch",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


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
