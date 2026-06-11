from datetime import datetime, timezone
from typing import Any

from fastapi import Body, FastAPI, HTTPException
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy.exc import SQLAlchemyError

from .database import latest_inventory_submission, save_inventory_submission

app = FastAPI(
    title="OpenAssetWatch API",
    description="Open-source family network asset intelligence platform.",
    version="0.1.0",
)


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


class CollectorCheckInRequest(BaseModel):
    collector_id: str = Field(..., min_length=1)
    collector_name: str | None = None
    hostname: str = Field(..., min_length=1)
    collector_version: str = Field(..., min_length=1)
    mode: str = Field(..., min_length=1)
    platform: dict[str, Any] | None = None
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
    collector_id: str | None = None
    collector_name: str | None = None
    collector_version: str | None = None
    mode: str | None = None
    collected_at: datetime | None = None
    platform: dict[str, Any] | None = None
    device: dict[str, Any] | None = None
    network: list[dict[str, Any]] | dict[str, Any] | None = None
    software: list[dict[str, Any]] | None = None

    class Config:
        extra = "allow"


class CollectorInventoryResponse(BaseModel):
    status: str
    submission_id: int
    received_at: datetime
    collector_id: str | None = None
    mode: str | None = None
    device_count: int
    network_observation_count: int
    software_count: int


class CollectorInventoryLatestResponse(BaseModel):
    submission_id: int
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


@app.post("/api/v1/collectors/checkin", response_model=CollectorCheckInResponse)
def collector_checkin(payload: CollectorCheckInRequest):
    return CollectorCheckInResponse(
        status="accepted",
        collector_id=payload.collector_id,
        received_at=datetime.now(timezone.utc),
        next_heartbeat_minutes=60,
        inventory_interval_hours=24,
    )


def collector_id_from_inventory(payload: CollectorInventoryRequest) -> str | None:
    if payload.collector_id:
        return payload.collector_id
    if isinstance(payload.collector, dict):
        collector_id = payload.collector.get("id")
        if collector_id:
            return str(collector_id)
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
def collector_inventory(raw_payload: Any = Body(...)):
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
    collector_id = collector_id_from_inventory(payload)
    collector_name = collector_name_from_inventory(payload)
    device_count = 1 if payload.device is not None else 0
    network_count = network_observation_count(payload.network)
    software_count = len(payload.software) if isinstance(payload.software, list) else 0
    try:
        submission_id = save_inventory_submission(
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

    return CollectorInventoryResponse(
        status="accepted",
        submission_id=submission_id,
        received_at=received_at,
        collector_id=collector_id,
        mode=payload.mode,
        device_count=device_count,
        network_observation_count=network_count,
        software_count=software_count,
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
