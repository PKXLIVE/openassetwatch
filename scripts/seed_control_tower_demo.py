from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import ParseResult, urlparse, urlunparse


REPO_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = REPO_ROOT / "backend"
LOCAL_DATABASE_URL = (
    "postgresql+psycopg2://openassetwatch:"
    "openassetwatch_local_only_change_me@127.0.0.1:5432/openassetwatch"
)
DEMO_BASE_TIME = datetime(2026, 1, 15, 15, 0, tzinfo=timezone.utc)
LOCAL_DATABASE_HOSTS = {"127.0.0.1", "localhost", "::1"}
COMPOSE_DATABASE_HOSTS = {"postgres"}
COMPOSE_SEED_COMMAND = "docker compose --profile demo run --rm demo-seed"
ALLOW_COMPOSE_HOST_ENV = "OPENASSETWATCH_DEMO_SEED_ALLOW_COMPOSE_HOST"
FORBIDDEN_SEED_TERMS = (
    "password",
    "secret",
    "token",
    "command execution",
    "exploit payload",
    "active scan",
    "webshell",
    "credential collection",
)


@dataclass(frozen=True)
class DemoSite:
    site_id: str
    name: str
    description: str


@dataclass(frozen=True)
class DemoAgent:
    agent_id: str
    site_id: str
    display_name: str
    agent_type: str
    platform: str
    architecture: str
    version: str
    hostname: str
    mode: str
    last_seen_minutes_ago: int


@dataclass(frozen=True)
class DemoCheckIn:
    agent_id: str
    site_id: str
    platform: str
    architecture: str
    version: str
    hostname: str
    mode: str
    minutes_ago: int


@dataclass(frozen=True)
class DemoAsset:
    asset_id: str
    site_id: str
    hostname: str
    primary_ip: str
    mac: str
    os: str
    platform: str
    source_agent_id: str
    evidence_count: int
    last_seen_minutes_ago: int
    category: str
    attention: str
    security_coverage: str | None = None
    confidence: float = 0.9


DEMO_SITES = (
    DemoSite("demo-home", "Home Demo", "Synthetic home location for cross-site AI showcase testing."),
    DemoSite("demo-office", "Office Demo", "Synthetic office location with a deliberately stale sensor."),
    DemoSite("demo-lab", "Lab Demo", "Synthetic lab location with server and unmanaged device evidence."),
)

DEMO_AGENTS = (
    DemoAgent(
        "sensor-home-demo-01",
        "demo-home",
        "Home Passive Sensor",
        "network-sensor",
        "Linux",
        "amd64",
        "0.1.0-demo",
        "demo-home-sensor",
        "passive-network-demo",
        4,
    ),
    DemoAgent(
        "sensor-office-demo-01",
        "demo-office",
        "Office Passive Sensor",
        "network-sensor",
        "Linux",
        "amd64",
        "0.1.0-demo",
        "demo-office-sensor",
        "passive-network-demo",
        190,
    ),
    DemoAgent(
        "sensor-lab-demo-01",
        "demo-lab",
        "Lab Passive Sensor",
        "network-sensor",
        "Linux",
        "amd64",
        "0.1.0-demo",
        "demo-lab-sensor",
        "passive-network-demo",
        42,
    ),
    DemoAgent(
        "agent-win-home-demo-01",
        "demo-home",
        "Home Windows Collector",
        "endpoint-agent",
        "Windows",
        "amd64",
        "0.1.0-demo",
        "demo-home-workstation",
        "local-inventory-demo",
        7,
    ),
    DemoAgent(
        "agent-macos-office-demo-01",
        "demo-office",
        "Office macOS Collector",
        "endpoint-agent",
        "macOS",
        "arm64",
        "0.1.0-demo",
        "demo-office-laptop",
        "local-inventory-demo",
        15,
    ),
    DemoAgent(
        "agent-linux-lab-demo-01",
        "demo-lab",
        "Lab Linux Collector",
        "endpoint-agent",
        "Linux",
        "amd64",
        "0.1.0-demo",
        "demo-lab-server",
        "local-inventory-demo",
        12,
    ),
)

DEMO_CHECKINS = tuple(
    DemoCheckIn(agent.agent_id, agent.site_id, agent.platform, agent.architecture, agent.version, agent.hostname, agent.mode, agent.last_seen_minutes_ago)
    for agent in DEMO_AGENTS
)

DEMO_ASSETS = (
    DemoAsset("asset-home-workstation-demo", "demo-home", "demo-home-workstation", "192.0.2.10", "02:00:5e:10:00:10", "Windows 11 Demo", "Windows/amd64", "agent-win-home-demo-01", 7, 4, "workstation", "healthy endpoint sample"),
    DemoAsset("asset-home-smart-tv-demo", "demo-home", "demo-home-smart-tv", "192.0.2.44", "02:00:5e:10:00:44", "Smart TV Demo Firmware", "iot-demo", "sensor-home-demo-01", 3, 8, "iot", "passive-only device sample"),
    DemoAsset("asset-home-mobile-demo", "demo-home", "demo-home-mobile", "192.0.2.66", "02:00:5e:10:00:66", "Mobile Demo OS", "mobile-demo", "sensor-home-demo-01", 3, 11, "mobile", "passive-only mobile sample"),
    DemoAsset("asset-home-router-demo", "demo-home", "demo-home-router", "192.0.2.1", "02:00:5e:10:00:01", "Router Demo Firmware", "network-device-demo", "sensor-home-demo-01", 5, 6, "router", "router inventory sample"),
    DemoAsset("asset-office-laptop-demo", "demo-office", "demo-office-laptop", "198.51.100.20", "02:00:5e:20:00:20", "macOS Demo", "macOS/arm64", "agent-macos-office-demo-01", 6, 13, "laptop", "healthy endpoint sample"),
    DemoAsset("asset-office-printer-demo", "demo-office", "demo-office-printer", "198.51.100.25", "02:00:5e:20:00:25", "Printer Demo Firmware", "embedded-demo", "sensor-office-demo-01", 4, 120, "printer", "passive printer inventory sample"),
    DemoAsset("asset-office-switch-demo", "demo-office", "demo-office-switch", "198.51.100.2", "02:00:5e:20:00:02", "Switch Demo Firmware", "network-device-demo", "sensor-office-demo-01", 5, 130, "network-switch", "passive network switch sample"),
    DemoAsset("asset-office-unknown-demo", "demo-office", "demo-office-unknown", "198.51.100.88", "02:00:5e:20:00:88", "Unknown Demo Device", "unknown-demo", "sensor-office-demo-01", 2, 125, "unknown", "unknown device sample"),
    DemoAsset("asset-lab-server-demo", "demo-lab", "demo-lab-server", "203.0.113.30", "02:00:5e:30:00:30", "Linux Demo", "Linux/amd64", "agent-linux-lab-demo-01", 8, 10, "server", "explicit coverage gap sample", "missing"),
    DemoAsset("asset-lab-runner-demo", "demo-lab", "demo-lab-runner", "203.0.113.31", "02:00:5e:30:00:30", "Linux Demo", "Linux/amd64", "sensor-lab-demo-01", 6, 18, "server", "passive server and identity-conflict sample"),
    DemoAsset("asset-lab-nas-demo", "demo-lab", "demo-lab-nas", "203.0.113.40", "02:00:5e:30:00:40", "NAS Demo Firmware", "storage-demo", "sensor-lab-demo-01", 5, 50, "storage", "passive storage sample"),
    DemoAsset("asset-lab-camera-demo", "demo-lab", "demo-lab-camera", "203.0.113.55", "02:ca:fe:30:00:55", "Camera Demo Firmware", "iot-demo", "sensor-lab-demo-01", 3, 34, "camera", "passive camera sample"),
    DemoAsset("asset-lab-reclassified-demo", "demo-lab", "demo-lab-reclassified", "203.0.113.70", "02:00:5e:30:00:70", "Linux Demo", "Linux/amd64", "agent-linux-lab-demo-01", 5, 9, "server", "stronger direct evidence reclassification sample"),
)

DEMO_PROTOCOL_EVIDENCE: dict[str, tuple[dict[str, Any], ...]] = {
    "asset-home-smart-tv-demo": (
        {"protocol": "mdns", "kind": "mdns-service", "value": "_airplay._tcp.local", "confidence": 0.88},
    ),
    "asset-home-mobile-demo": (
        {"protocol": "dhcp", "kind": "dhcp-vendor-class", "value": "android-demo-client", "confidence": 0.82},
    ),
    "asset-home-router-demo": (
        {"protocol": "ssdp", "kind": "ssdp-device-type", "value": "urn:schemas-upnp-org:device:InternetGatewayDevice:1", "confidence": 0.9},
    ),
    "asset-office-printer-demo": (
        {"protocol": "mdns", "kind": "mdns-service", "value": "_ipp._tcp.local", "confidence": 0.9},
        {"protocol": "ssdp", "kind": "ssdp-device-type", "value": "urn:schemas-upnp-org:device:Printer:1", "confidence": 0.82},
    ),
    "asset-office-switch-demo": (
        {"protocol": "dhcp", "kind": "dhcp-vendor-class", "value": "example-switch-demo", "confidence": 0.78},
    ),
    "asset-office-unknown-demo": (
        {"protocol": "nbns", "kind": "nbns-name", "value": "DEMO-UNKNOWN", "confidence": 0.42},
    ),
    "asset-lab-runner-demo": (
        {"protocol": "mdns", "kind": "mdns-service", "value": "_ipp._tcp.local", "confidence": 0.9},
    ),
    "asset-lab-nas-demo": (
        {"protocol": "mdns", "kind": "mdns-service", "value": "_smb._tcp.local", "confidence": 0.88},
    ),
    "asset-lab-camera-demo": (
        {"protocol": "mdns", "kind": "mdns-service", "value": "_rtsp._tcp.local", "confidence": 0.9},
        {"protocol": "ssdp", "kind": "ssdp-device-type", "value": "urn:example:device:NetworkVideoCamera:1", "confidence": 0.86},
    ),
    "asset-lab-reclassified-demo": (
        {"protocol": "mdns", "kind": "mdns-service", "value": "_ipp._tcp.local", "confidence": 0.84},
    ),
}

LEGACY_DEMO_SITE_IDS = ("home-lab", "small-office")
LEGACY_DEMO_AGENT_IDS = ("agent-win-demo-01", "agent-macos-demo-01", "sensor-passive-demo-01")
LEGACY_DEMO_ASSET_IDS = (
    "asset-win-workstation-demo",
    "asset-macos-laptop-demo",
    "asset-linux-server-demo",
    "asset-printer-demo",
    "asset-switch-demo",
    "asset-smart-tv-demo",
    "asset-mobile-demo",
    "asset-unknown-demo",
)


def event_time(minutes_ago: int, *, base_time: datetime = DEMO_BASE_TIME) -> datetime:
    return base_time - timedelta(minutes=minutes_ago)


def documentation_network_ip(value: str) -> bool:
    return value.startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def locally_administered_mac(value: str) -> bool:
    return value.lower().startswith("02:")


def seed_payloads() -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    for checkin in DEMO_CHECKINS:
        payloads.append(
            {
                "demo": True,
                "sample_data": True,
                "site_id": checkin.site_id,
                "agent_id": checkin.agent_id,
                "version": checkin.version,
                "platform": {"os": checkin.platform, "architecture": checkin.architecture},
                "hostname": checkin.hostname,
                "mode": checkin.mode,
                "timestamp": event_time(checkin.minutes_ago).isoformat(),
            }
        )
    for asset in DEMO_ASSETS:
        payloads.append(
            {
                "demo": True,
                "sample_data": True,
                "asset_id": asset.asset_id,
                "hostname": asset.hostname,
                "category": asset.category,
                "primary_ip": asset.primary_ip,
                "mac": asset.mac,
                "os": asset.os,
                "platform": asset.platform,
                "source_agent_id": asset.source_agent_id,
                "attention": asset.attention,
                "confidence": asset.confidence,
                "security_coverage": asset.security_coverage,
            }
        )
    return payloads


def validate_seed_payloads() -> None:
    payload_text = json.dumps(seed_payloads(), sort_keys=True).lower()
    for term in FORBIDDEN_SEED_TERMS:
        if term in payload_text:
            raise ValueError(f"demo seed payload contains forbidden term: {term}")
    for asset in DEMO_ASSETS:
        if not documentation_network_ip(asset.primary_ip):
            raise ValueError(f"demo asset does not use a documentation IP range: {asset.asset_id}")
        if not locally_administered_mac(asset.mac):
            raise ValueError(f"demo asset does not use a locally administered MAC: {asset.asset_id}")


class DemoSeedStore:
    def clear_demo_records(self) -> None:
        raise NotImplementedError

    def upsert_site(self, site: DemoSite) -> None:
        raise NotImplementedError

    def upsert_agent(self, agent: DemoAgent, *, last_seen_at: datetime) -> None:
        raise NotImplementedError

    def insert_checkin(self, checkin: DemoCheckIn, *, received_at: datetime) -> None:
        raise NotImplementedError

    def insert_collection(self, *, site_id: str, source_agent_id: str, received_at: datetime, assets: list[DemoAsset]) -> None:
        raise NotImplementedError

    def upsert_asset(self, asset: DemoAsset, *, seen_at: datetime) -> None:
        raise NotImplementedError

    def summary(self) -> dict[str, int]:
        raise NotImplementedError

    def evaluate_findings(self, *, evaluated_at: datetime) -> dict[str, Any]:
        return {}

    def evaluate_classifications(self, *, evaluated_at: datetime) -> dict[str, Any]:
        return {}


class SqlDemoSeedStore(DemoSeedStore):
    def __init__(self, database_url: str) -> None:
        if str(BACKEND_ROOT) not in sys.path:
            sys.path.insert(0, str(BACKEND_ROOT))
        os.environ["DATABASE_URL"] = database_url

        from sqlalchemy import bindparam, text
        from app.database import (
            control_tower_summary,
            create_agent_enrollment,
            create_site,
            ensure_database_schema,
            get_engine,
        )

        self.bindparam = bindparam
        self.text = text
        self.control_tower_summary = control_tower_summary
        self.create_agent_enrollment = create_agent_enrollment
        self.create_site = create_site
        self.ensure_database_schema = ensure_database_schema
        self.engine = get_engine()
        self.ensure_database_schema()

    def clear_demo_records(self) -> None:
        site_ids = [site.site_id for site in DEMO_SITES] + list(LEGACY_DEMO_SITE_IDS)
        agent_ids = [agent.agent_id for agent in DEMO_AGENTS] + list(LEGACY_DEMO_AGENT_IDS)
        asset_ids = [asset.asset_id for asset in DEMO_ASSETS] + list(LEGACY_DEMO_ASSET_IDS)
        with self.engine.begin() as connection:
            connection.execute(
                self.text(
                    """
                    DELETE FROM asset_classification_history
                    WHERE site_id IN :site_ids
                    """
                ).bindparams(
                    self.bindparam("site_ids", expanding=True),
                ),
                {"site_ids": site_ids},
            )
            connection.execute(
                self.text(
                    """
                    DELETE FROM agent_checkins
                    WHERE site_id IN :site_ids OR agent_id IN :agent_ids
                    """
                ).bindparams(
                    self.bindparam("site_ids", expanding=True),
                    self.bindparam("agent_ids", expanding=True),
                ),
                {"site_ids": site_ids, "agent_ids": agent_ids},
            )
            connection.execute(
                self.text(
                    """
                    DELETE FROM local_inventory_collections
                    WHERE site_id IN :site_ids OR source_agent_id IN :agent_ids
                    """
                ).bindparams(
                    self.bindparam("site_ids", expanding=True),
                    self.bindparam("agent_ids", expanding=True),
                ),
                {"site_ids": site_ids, "agent_ids": agent_ids},
            )
            connection.execute(
                self.text(
                    """
                    DELETE FROM control_tower_assets
                    WHERE site_id IN :site_ids AND asset_id IN :asset_ids
                    """
                ).bindparams(
                    self.bindparam("site_ids", expanding=True),
                    self.bindparam("asset_ids", expanding=True),
                ),
                {"site_ids": site_ids, "asset_ids": asset_ids},
            )
            connection.execute(
                self.text("DELETE FROM agent_enrollments WHERE site_id IN :site_ids OR agent_id IN :agent_ids").bindparams(
                    self.bindparam("site_ids", expanding=True),
                    self.bindparam("agent_ids", expanding=True),
                ),
                {"site_ids": site_ids, "agent_ids": agent_ids},
            )
            connection.execute(
                self.text("DELETE FROM sites WHERE site_id IN :site_ids").bindparams(
                    self.bindparam("site_ids", expanding=True),
                ),
                {"site_ids": site_ids},
            )
            connection.execute(
                self.text(
                    """
                    DELETE FROM finding_evaluation_runs
                    WHERE requested_by = 'control-tower-demo-seed'
                    """
                )
            )
            connection.execute(
                self.text(
                    """
                    DELETE FROM classification_runs
                    WHERE requested_by = 'control-tower-demo-seed'
                    """
                )
            )

    def upsert_site(self, site: DemoSite) -> None:
        self.create_site(site_id=site.site_id, name=site.name, description=site.description)

    def upsert_agent(self, agent: DemoAgent, *, last_seen_at: datetime) -> None:
        self.create_agent_enrollment(
            agent_id=agent.agent_id,
            site_id=agent.site_id,
            display_name=agent.display_name,
            agent_type=agent.agent_type,
            platform=agent.platform,
            architecture=agent.architecture,
            version=agent.version,
            hostname=agent.hostname,
            mode=agent.mode,
            last_seen_at=last_seen_at,
        )

    def insert_checkin(self, checkin: DemoCheckIn, *, received_at: datetime) -> None:
        payload = {
            "demo": True,
            "sample_data": True,
            "site_id": checkin.site_id,
            "agent_id": checkin.agent_id,
            "version": checkin.version,
            "platform": {"os": checkin.platform, "architecture": checkin.architecture},
            "hostname": checkin.hostname,
            "mode": checkin.mode,
            "timestamp": received_at.isoformat(),
        }
        with self.engine.begin() as connection:
            connection.execute(
                self.text(
                    """
                    INSERT INTO agent_checkins (
                        site_id,
                        agent_id,
                        version,
                        platform,
                        architecture,
                        hostname,
                        mode,
                        checked_in_at,
                        received_at,
                        payload_json
                    )
                    VALUES (
                        :site_id,
                        :agent_id,
                        :version,
                        :platform,
                        :architecture,
                        :hostname,
                        :mode,
                        :checked_in_at,
                        :received_at,
                        CAST(:payload_json AS JSONB)
                    )
                    """
                ),
                {
                    "site_id": checkin.site_id,
                    "agent_id": checkin.agent_id,
                    "version": checkin.version,
                    "platform": checkin.platform,
                    "architecture": checkin.architecture,
                    "hostname": checkin.hostname,
                    "mode": checkin.mode,
                    "checked_in_at": received_at,
                    "received_at": received_at,
                    "payload_json": json.dumps(payload, sort_keys=True),
                },
            )

    def insert_collection(self, *, site_id: str, source_agent_id: str, received_at: datetime, assets: list[DemoAsset]) -> None:
        payload = {
            "demo": True,
            "sample_data": True,
            "schema_version": "oaw.observation-batch.v1",
            "observation_batch_id": f"demo-batch-{site_id}",
            "site_id": site_id,
            "sensor_id": source_agent_id,
            "sensor_name": source_agent_id,
            "sensor_type": "passive-network-sensor",
            "sensor_version": "0.1.0-demo",
            "collected_at": received_at.isoformat(),
            "observed_at": received_at.isoformat(),
            "observation_source": "control-tower-demo-seed",
            "delivery_state": "cached-retry" if site_id == "demo-office" else "live",
            "confidence": 0.9,
            "assets": [
                {
                    "asset_id": asset.asset_id,
                    "hostname": asset.hostname,
                    "primary_ip": asset.primary_ip,
                    "mac": asset.mac,
                    "os": asset.os,
                    "platform": asset.platform,
                    "category": asset.category,
                }
                for asset in assets
            ],
        }
        with self.engine.begin() as connection:
            connection.execute(
                self.text(
                    """
                    INSERT INTO local_inventory_collections (
                        site_id,
                        source_agent_id,
                        schema_version,
                        collected_at,
                        received_at,
                        observed_asset_count,
                        normalized_asset_count,
                        observation_batch_id,
                        observation_source,
                        observed_at,
                        delivery_state,
                        confidence,
                        payload_json
                    )
                    VALUES (
                        :site_id,
                        :source_agent_id,
                        :schema_version,
                        :collected_at,
                        :received_at,
                        :observed_asset_count,
                        :normalized_asset_count,
                        :observation_batch_id,
                        :observation_source,
                        :observed_at,
                        :delivery_state,
                        :confidence,
                        CAST(:payload_json AS JSONB)
                    )
                    """
                ),
                {
                    "site_id": site_id,
                    "source_agent_id": source_agent_id,
                    "schema_version": payload["schema_version"],
                    "collected_at": received_at,
                    "received_at": received_at,
                    "observed_asset_count": len(assets),
                    "normalized_asset_count": len(assets),
                    "observation_batch_id": payload["observation_batch_id"],
                    "observation_source": payload["observation_source"],
                    "observed_at": received_at,
                    "delivery_state": payload["delivery_state"],
                    "confidence": payload["confidence"],
                    "payload_json": json.dumps(payload, sort_keys=True),
                },
            )

    def upsert_asset(self, asset: DemoAsset, *, seen_at: datetime) -> None:
        metadata = {
            "demo": True,
            "sample_data": True,
            "category": asset.category,
            "attention": asset.attention,
            "confidence": asset.confidence,
            "security_coverage": asset.security_coverage,
            "source": "control-tower-demo-seed",
        }
        with self.engine.begin() as connection:
            connection.execute(
                self.text(
                    """
                    INSERT INTO control_tower_assets (
                        asset_key,
                        asset_id,
                        site_id,
                        hostname,
                        primary_ip,
                        mac,
                        os,
                        platform,
                        source_agent_id,
                        first_seen_at,
                        last_seen_at,
                        evidence_count,
                        observation_batch_id,
                        observation_source,
                        observed_at,
                        delivery_state,
                        confidence,
                        metadata_json
                    )
                    VALUES (
                        :asset_key,
                        :asset_id,
                        :site_id,
                        :hostname,
                        :primary_ip,
                        :mac,
                        :os,
                        :platform,
                        :source_agent_id,
                        :first_seen_at,
                        :last_seen_at,
                        :evidence_count,
                        :observation_batch_id,
                        :observation_source,
                        :observed_at,
                        :delivery_state,
                        :confidence,
                        CAST(:metadata_json AS JSONB)
                    )
                    ON CONFLICT (asset_key) DO UPDATE SET
                        hostname = EXCLUDED.hostname,
                        primary_ip = EXCLUDED.primary_ip,
                        mac = EXCLUDED.mac,
                        os = EXCLUDED.os,
                        platform = EXCLUDED.platform,
                        source_agent_id = EXCLUDED.source_agent_id,
                        last_seen_at = EXCLUDED.last_seen_at,
                        evidence_count = EXCLUDED.evidence_count,
                        observation_batch_id = EXCLUDED.observation_batch_id,
                        observation_source = EXCLUDED.observation_source,
                        observed_at = EXCLUDED.observed_at,
                        delivery_state = EXCLUDED.delivery_state,
                        confidence = EXCLUDED.confidence,
                        metadata_json = EXCLUDED.metadata_json,
                        updated_at = NOW()
                    """
                ),
                {
                    "asset_key": f"{asset.site_id}:{asset.asset_id}",
                    "asset_id": asset.asset_id,
                    "site_id": asset.site_id,
                    "hostname": asset.hostname,
                    "primary_ip": asset.primary_ip,
                    "mac": asset.mac,
                    "os": asset.os,
                    "platform": asset.platform,
                    "source_agent_id": asset.source_agent_id,
                    "first_seen_at": seen_at,
                    "last_seen_at": seen_at,
                    "evidence_count": asset.evidence_count,
                    "observation_batch_id": f"demo-batch-{asset.site_id}",
                    "observation_source": "control-tower-demo-seed",
                    "observed_at": seen_at,
                    "delivery_state": "cached-retry" if asset.site_id == "demo-office" else "live",
                    "confidence": asset.confidence,
                    "metadata_json": json.dumps(metadata, sort_keys=True),
                },
            )

    def summary(self) -> dict[str, int]:
        return self.control_tower_summary()

    def evaluate_classifications(self, *, evaluated_at: datetime) -> dict[str, Any]:
        from app.classification_service import evaluate_classifications
        from app.classification_store import (
            SqlClassificationStore,
            classification_evidence_for_asset,
            persist_classification_evidence,
        )
        from app.vendor_catalog import load_configured_catalog

        agents = {agent.agent_id: agent for agent in DEMO_AGENTS}
        catalog = load_configured_catalog()

        def normalized_asset(
            asset: DemoAsset,
            *,
            source_agent_id: str,
            category: str | None,
            os_name: str | None,
            platform: str | None,
            protocol_evidence: tuple[dict[str, Any], ...],
        ) -> dict[str, Any]:
            return {
                "site_id": asset.site_id,
                "asset_id": asset.asset_id,
                "hostname": asset.hostname,
                "primary_ip": asset.primary_ip,
                "mac": asset.mac,
                "os": os_name,
                "platform": platform,
                "source_agent_id": source_agent_id,
                "metadata": {
                    "category": category,
                    "security_coverage": asset.security_coverage,
                    "evidence": list(protocol_evidence),
                },
            }

        def payload_for(source_agent_id: str) -> dict[str, Any]:
            agent = agents[source_agent_id]
            endpoint = agent.agent_type == "endpoint-agent"
            return {
                "site_id": agent.site_id,
                "sensor_id": source_agent_id,
                "sensor_type": (
                    "endpoint-collector"
                    if endpoint
                    else "passive-network-sensor"
                ),
                "observation_source": (
                    "endpoint-inventory"
                    if endpoint
                    else "passive-network"
                ),
                "confidence": 0.9,
            }

        reclassified = next(
            asset
            for asset in DEMO_ASSETS
            if asset.asset_id == "asset-lab-reclassified-demo"
        )
        initial_reclassification_at = evaluated_at - timedelta(hours=100)
        with self.engine.begin() as connection:
            for asset in DEMO_ASSETS:
                if asset.asset_id == reclassified.asset_id:
                    continue
                seen_at = event_time(
                    asset.last_seen_minutes_ago,
                    base_time=evaluated_at,
                )
                projected = normalized_asset(
                    asset,
                    source_agent_id=asset.source_agent_id,
                    category=asset.category,
                    os_name=asset.os,
                    platform=asset.platform,
                    protocol_evidence=DEMO_PROTOCOL_EVIDENCE.get(
                        asset.asset_id,
                        (),
                    ),
                )
                records = classification_evidence_for_asset(
                    asset=projected,
                    payload=payload_for(asset.source_agent_id),
                    observed_at=seen_at,
                    catalog=catalog,
                    source_authenticated=asset.source_agent_id.startswith("agent-"),
                )
                persist_classification_evidence(connection, records=records)

            initial_projected = normalized_asset(
                reclassified,
                source_agent_id="sensor-lab-demo-01",
                category=None,
                os_name=None,
                platform=None,
                protocol_evidence=DEMO_PROTOCOL_EVIDENCE[
                    reclassified.asset_id
                ],
            )
            persist_classification_evidence(
                connection,
                records=classification_evidence_for_asset(
                    asset=initial_projected,
                    payload=payload_for("sensor-lab-demo-01"),
                    observed_at=initial_reclassification_at,
                    catalog=catalog,
                    source_authenticated=True,
                ),
            )

        initial_reclassification = evaluate_classifications(
            trigger_type="demo-reclassification-initial",
            requested_by="control-tower-demo-seed",
            site_id=reclassified.site_id,
            asset_id=reclassified.asset_id,
            now=initial_reclassification_at,
            reevaluate_findings=False,
        )

        with self.engine.begin() as connection:
            final_projected = normalized_asset(
                reclassified,
                source_agent_id="agent-linux-lab-demo-01",
                category="server",
                os_name="Linux Demo",
                platform="Linux/amd64",
                protocol_evidence=(),
            )
            persist_classification_evidence(
                connection,
                records=classification_evidence_for_asset(
                    asset=final_projected,
                    payload=payload_for("agent-linux-lab-demo-01"),
                    observed_at=evaluated_at,
                    catalog=catalog,
                    source_authenticated=True,
                ),
            )
            runner = next(
                asset
                for asset in DEMO_ASSETS
                if asset.asset_id == "asset-lab-runner-demo"
            )
            runner_direct = normalized_asset(
                runner,
                source_agent_id="agent-linux-lab-demo-01",
                category="server",
                os_name="Linux Demo",
                platform="Linux/amd64",
                protocol_evidence=(),
            )
            persist_classification_evidence(
                connection,
                records=classification_evidence_for_asset(
                    asset=runner_direct,
                    payload=payload_for("agent-linux-lab-demo-01"),
                    observed_at=evaluated_at,
                    catalog=catalog,
                    source_authenticated=True,
                ),
            )

        final = evaluate_classifications(
            trigger_type="demo-seed",
            requested_by="control-tower-demo-seed",
            now=evaluated_at,
            reevaluate_findings=False,
        )
        store = SqlClassificationStore()
        reclassified_current = store.get_classification(
            site_id=reclassified.site_id,
            asset_id=reclassified.asset_id,
        )
        conflicts = store.list_classifications(
            status="conflicting",
            limit=50,
        )["items"]
        with self.engine.begin() as connection:
            history_count = int(
                connection.execute(
                    self.text(
                        """
                        SELECT COUNT(*)
                        FROM asset_classification_history
                        WHERE site_id = :site_id AND asset_id = :asset_id
                        """
                    ),
                    {
                        "site_id": reclassified.site_id,
                        "asset_id": reclassified.asset_id,
                    },
                ).scalar_one()
            )
        return {
            "initial_run_id": initial_reclassification.run_id,
            "final_run_id": final.run_id,
            "assets_evaluated": final.assets_evaluated,
            "assets_changed": final.assets_changed,
            "conflicts_found": final.conflicts_found,
            "conflict_classification_ids": [
                item["classification_id"] for item in conflicts
            ],
            "reclassification": {
                "classification_id": (
                    reclassified_current.get("classification_id")
                    if reclassified_current
                    else None
                ),
                "initial_category": "printer",
                "final_category": (
                    reclassified_current.get("category")
                    if reclassified_current
                    else None
                ),
                "history_count": history_count,
            },
        }

    def evaluate_findings(self, *, evaluated_at: datetime) -> dict[str, Any]:
        from app.finding_service import evaluate_findings

        initial = evaluate_findings(
            trigger_type="demo-seed",
            requested_by="control-tower-demo-seed",
            now=evaluated_at,
        )
        return initial.as_dict()


def assets_for_site(site_id: str) -> list[DemoAsset]:
    return [asset for asset in DEMO_ASSETS if asset.site_id == site_id]


def primary_agent_for_site(site_id: str) -> str:
    for agent in DEMO_AGENTS:
        if agent.site_id == site_id and agent.agent_type == "network-sensor":
            return agent.agent_id
    raise ValueError(f"no demo agent configured for site: {site_id}")


def seed_demo_data(store: DemoSeedStore, *, base_time: datetime = DEMO_BASE_TIME) -> dict[str, Any]:
    validate_seed_payloads()
    store.clear_demo_records()
    for site in DEMO_SITES:
        store.upsert_site(site)
    for agent in DEMO_AGENTS:
        store.upsert_agent(agent, last_seen_at=event_time(agent.last_seen_minutes_ago, base_time=base_time))
    # Agent enrollment defensively ensures site records; reapply demo names and
    # descriptions afterward so the visual dashboard keeps friendly labels.
    for site in DEMO_SITES:
        store.upsert_site(site)
    for checkin in DEMO_CHECKINS:
        store.insert_checkin(checkin, received_at=event_time(checkin.minutes_ago, base_time=base_time))
    for site in DEMO_SITES:
        store.insert_collection(
            site_id=site.site_id,
            source_agent_id=primary_agent_for_site(site.site_id),
            received_at=event_time(20, base_time=base_time),
            assets=assets_for_site(site.site_id),
        )
    for asset in DEMO_ASSETS:
        store.upsert_asset(asset, seen_at=event_time(asset.last_seen_minutes_ago, base_time=base_time))
    classification = (
        store.evaluate_classifications(evaluated_at=base_time)
        if hasattr(store, "evaluate_classifications")
        else {}
    )
    evaluation = (
        store.evaluate_findings(evaluated_at=base_time)
        if hasattr(store, "evaluate_findings")
        else {}
    )

    return {
        "sites": len(DEMO_SITES),
        "agents": len(DEMO_AGENTS),
        "check_ins": len(DEMO_CHECKINS),
        "assets": len(DEMO_ASSETS),
        "evidence": sum(asset.evidence_count for asset in DEMO_ASSETS),
        "deterministic_classification": classification,
        "deterministic_evaluation": evaluation,
        "summary": store.summary(),
    }


def database_url_from_args(value: str | None) -> str:
    return value or os.getenv("DATABASE_URL") or LOCAL_DATABASE_URL


def compose_host_allowed(value: str | None = None) -> bool:
    return (value if value is not None else os.getenv(ALLOW_COMPOSE_HOST_ENV, "")).strip().lower() in {"1", "true", "yes"}


def local_database_url(value: str, *, allow_compose_host: bool = False) -> bool:
    parsed = urlparse(value)
    if parsed.hostname in LOCAL_DATABASE_HOSTS:
        return True
    return allow_compose_host and parsed.hostname in COMPOSE_DATABASE_HOSTS


def dependency_error_message(module_name: str) -> str:
    return (
        f"missing Python dependency {module_name!r}; run the Compose seed path with "
        f"`{COMPOSE_SEED_COMMAND}` or install backend requirements in your local Python environment"
    )


def sanitized_database_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.password is None:
        return value
    netloc = parsed.hostname or ""
    if parsed.username:
        netloc = f"{parsed.username}:***@{netloc}"
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse(ParseResult(parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed safe local OpenAssetWatch Control Tower demo data.")
    parser.add_argument("--database-url", help="Local PostgreSQL SQLAlchemy URL. Defaults to the local Compose database.")
    parser.add_argument(
        "--allow-compose-database-host",
        action="store_true",
        help="Allow the Docker Compose-only PostgreSQL service host name 'postgres'. External hosts remain refused.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    database_url = database_url_from_args(args.database_url)
    output: dict[str, Any] = {
        "ok": False,
        "database_url": sanitized_database_url(database_url),
        "seeded": None,
        "next_steps": [COMPOSE_SEED_COMMAND],
        "warnings": [],
        "errors": [],
    }
    allow_compose_host = args.allow_compose_database_host or compose_host_allowed()

    if not local_database_url(database_url, allow_compose_host=allow_compose_host):
        output["errors"].append(
            "refusing to seed a non-local database host; only localhost is allowed by default, "
            "and the Compose host 'postgres' requires --allow-compose-database-host or "
            f"{ALLOW_COMPOSE_HOST_ENV}=1"
        )
        print(json.dumps(output, sort_keys=True))
        return 2

    try:
        store = SqlDemoSeedStore(database_url)
        output["seeded"] = seed_demo_data(store, base_time=datetime.now(timezone.utc))
        output["ok"] = True
    except ModuleNotFoundError as exc:
        output["errors"].append(dependency_error_message(exc.name or "unknown"))
        print(json.dumps(output, sort_keys=True, default=str))
        return 1
    except Exception as exc:  # noqa: BLE001 - script must return JSON diagnostics.
        output["errors"].append(str(exc))
        print(json.dumps(output, sort_keys=True, default=str))
        return 1

    print(json.dumps(output, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
