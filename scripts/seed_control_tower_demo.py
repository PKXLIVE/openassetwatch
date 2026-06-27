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


DEMO_SITES = (
    DemoSite("home-lab", "Home Lab Demo", "Synthetic local demo site for dashboard visual testing."),
    DemoSite("small-office", "Small Office Demo", "Synthetic small office demo site for dashboard visual testing."),
)

DEMO_AGENTS = (
    DemoAgent(
        "agent-win-demo-01",
        "home-lab",
        "Windows Demo Agent 01",
        "endpoint-agent",
        "Windows",
        "amd64",
        "0.1.0-demo",
        "demo-win-workstation",
        "healthy-demo",
        5,
    ),
    DemoAgent(
        "agent-macos-demo-01",
        "home-lab",
        "macOS Demo Agent 01",
        "endpoint-agent",
        "macOS",
        "arm64",
        "0.1.0-demo",
        "demo-macos-laptop",
        "healthy-demo",
        12,
    ),
    DemoAgent(
        "sensor-passive-demo-01",
        "small-office",
        "Passive Sensor Demo 01",
        "network-sensor",
        "Linux",
        "amd64",
        "0.1.0-demo",
        "demo-passive-sensor",
        "passive-demo",
        18,
    ),
)

DEMO_CHECKINS = (
    DemoCheckIn("agent-win-demo-01", "home-lab", "Windows", "amd64", "0.1.0-demo", "demo-win-workstation", "healthy-demo", 5),
    DemoCheckIn("agent-macos-demo-01", "home-lab", "macOS", "arm64", "0.1.0-demo", "demo-macos-laptop", "healthy-demo", 12),
    DemoCheckIn("sensor-passive-demo-01", "small-office", "Linux", "amd64", "0.1.0-demo", "demo-passive-sensor", "passive-demo", 18),
    DemoCheckIn("agent-win-demo-01", "home-lab", "Windows", "amd64", "0.1.0-demo", "demo-win-workstation", "healthy-demo", 65),
    DemoCheckIn("sensor-passive-demo-01", "small-office", "Linux", "amd64", "0.1.0-demo", "demo-passive-sensor", "passive-demo", 82),
)

DEMO_ASSETS = (
    DemoAsset("asset-win-workstation-demo", "home-lab", "demo-win-workstation", "192.0.2.10", "02:00:5e:10:00:10", "Windows 11 Demo", "Windows/amd64", "agent-win-demo-01", 7, 4, "workstation", "healthy endpoint sample"),
    DemoAsset("asset-macos-laptop-demo", "home-lab", "demo-macos-laptop", "192.0.2.20", "02:00:5e:10:00:20", "macOS Demo", "macOS/arm64", "agent-macos-demo-01", 6, 10, "laptop", "missing security tooling sample"),
    DemoAsset("asset-linux-server-demo", "home-lab", "demo-linux-server", "192.0.2.30", "02:00:5e:10:00:30", "Linux Demo", "Linux/amd64", "agent-win-demo-01", 8, 14, "server", "stale collector sample"),
    DemoAsset("asset-printer-demo", "small-office", "demo-printer", "198.51.100.25", "02:00:5e:20:00:25", "Printer Demo Firmware", "embedded-demo", "sensor-passive-demo-01", 4, 16, "printer", "printer inventory sample"),
    DemoAsset("asset-switch-demo", "small-office", "demo-switch", "198.51.100.2", "02:00:5e:20:00:02", "Switch Demo Firmware", "network-device-demo", "sensor-passive-demo-01", 5, 19, "network-switch", "network switch sample"),
    DemoAsset("asset-smart-tv-demo", "small-office", "demo-smart-tv", "203.0.113.44", "02:00:5e:30:00:44", "Smart TV Demo Firmware", "iot-demo", "sensor-passive-demo-01", 3, 23, "iot", "unmanaged IoT device sample"),
    DemoAsset("asset-mobile-demo", "small-office", "demo-mobile-device", "203.0.113.66", "02:00:5e:30:00:66", "Mobile Demo OS", "mobile-demo", "sensor-passive-demo-01", 3, 25, "mobile", "unmanaged mobile device sample"),
    DemoAsset("asset-unknown-demo", "small-office", "demo-unknown-device", "203.0.113.88", "02:00:5e:30:00:88", "Unknown Demo Device", "unknown-demo", "sensor-passive-demo-01", 2, 27, "unknown", "unknown device sample"),
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
        site_ids = [site.site_id for site in DEMO_SITES]
        agent_ids = [agent.agent_id for agent in DEMO_AGENTS]
        asset_ids = [asset.asset_id for asset in DEMO_ASSETS]
        with self.engine.begin() as connection:
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
            "schema_version": "openassetwatch.demo.inventory.v1",
            "site_id": site_id,
            "agent_id": source_agent_id,
            "collected_at": received_at.isoformat(),
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
                    "payload_json": json.dumps(payload, sort_keys=True),
                },
            )

    def upsert_asset(self, asset: DemoAsset, *, seen_at: datetime) -> None:
        metadata = {
            "demo": True,
            "sample_data": True,
            "category": asset.category,
            "attention": asset.attention,
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
                    "metadata_json": json.dumps(metadata, sort_keys=True),
                },
            )

    def summary(self) -> dict[str, int]:
        return self.control_tower_summary()


def assets_for_site(site_id: str) -> list[DemoAsset]:
    return [asset for asset in DEMO_ASSETS if asset.site_id == site_id]


def primary_agent_for_site(site_id: str) -> str:
    for agent in DEMO_AGENTS:
        if agent.site_id == site_id:
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

    return {
        "sites": len(DEMO_SITES),
        "agents": len(DEMO_AGENTS),
        "check_ins": len(DEMO_CHECKINS),
        "assets": len(DEMO_ASSETS),
        "evidence": sum(asset.evidence_count for asset in DEMO_ASSETS),
        "summary": store.summary(),
    }


def database_url_from_args(value: str | None) -> str:
    return value or os.getenv("DATABASE_URL") or LOCAL_DATABASE_URL


def local_database_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.hostname in LOCAL_DATABASE_HOSTS


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
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    database_url = database_url_from_args(args.database_url)
    output: dict[str, Any] = {
        "ok": False,
        "database_url": sanitized_database_url(database_url),
        "seeded": None,
        "warnings": [],
        "errors": [],
    }

    if not local_database_url(database_url):
        output["errors"].append("refusing to seed a non-local database host")
        print(json.dumps(output, sort_keys=True))
        return 2

    try:
        store = SqlDemoSeedStore(database_url)
        output["seeded"] = seed_demo_data(store)
        output["ok"] = True
    except Exception as exc:  # noqa: BLE001 - script must return JSON diagnostics.
        output["errors"].append(str(exc))
        print(json.dumps(output, sort_keys=True, default=str))
        return 1

    print(json.dumps(output, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
