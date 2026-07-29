"""Per-sensor enrollment, credential verification, and audit persistence.

Raw enrollment tokens and sensor credentials exist only in process memory while
being returned once. PostgreSQL stores a SHA-256 digest plus a random,
non-secret lookup identifier so high-entropy bearer values can be verified
without plaintext storage.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from uuid import uuid4

from sqlalchemy import text

from .database import ensure_database_schema, get_engine


ENROLLMENT_TOKEN_PREFIX = "oaw_enroll_v1"
SENSOR_CREDENTIAL_PREFIX = "oaw_sensor_v1"
SENSOR_CREDENTIAL_ENV = "OPENASSETWATCH_SENSOR_CREDENTIAL"
SHARED_DEVELOPMENT_TOKEN_ENV = "OPENASSETWATCH_COLLECTOR_TOKEN"
DEFAULT_ENROLLMENT_MINUTES = 60
MIN_ENROLLMENT_MINUTES = 5
MAX_ENROLLMENT_MINUTES = 24 * 60
DEFAULT_MAX_ATTEMPTS = 10
TOKEN_SECRET_BYTES = 32
_LOOKUP_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_SECRET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_DUMMY_DIGEST = hashlib.sha256(b"openassetwatch-invalid-sensor-credential").hexdigest()


class SensorIdentityError(Exception):
    """Base class for bounded API error mapping."""


class SensorEnrollmentRejected(SensorIdentityError):
    """The enrollment exchange must return one generic rejection."""

    def __init__(
        self,
        message: str,
        *,
        row: dict[str, Any] | None = None,
        reason_code: str = "rejected",
        rejected_at: datetime | None = None,
    ) -> None:
        super().__init__(message)
        self.row = row
        self.reason_code = reason_code
        self.rejected_at = rejected_at


class SensorAuthenticationRejected(SensorIdentityError):
    """The bound credential or claimed identity was not authorized."""


class SensorIdentityNotFound(SensorIdentityError):
    """An administrator referenced a missing site, enrollment, or sensor."""


class SensorIdentityConflict(SensorIdentityError):
    """The requested administrative state transition is not valid."""


@dataclass(frozen=True)
class TokenMaterial:
    raw: str
    lookup_id: str
    digest: str


@dataclass(frozen=True)
class SensorAuthContext:
    mode: Literal["bound-sensor", "development-shared"]
    site_id: str | None
    sensor_id: str | None
    sensor_type: str | None
    credential_id: str | None


def _utc_now(now: datetime | None = None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("security timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _token_digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _issue_token(prefix: str) -> TokenMaterial:
    lookup_id = secrets.token_hex(16)
    secret = secrets.token_urlsafe(TOKEN_SECRET_BYTES)
    raw = f"{prefix}.{lookup_id}.{secret}"
    return TokenMaterial(raw=raw, lookup_id=lookup_id, digest=_token_digest(raw))


def issue_enrollment_token() -> TokenMaterial:
    return _issue_token(ENROLLMENT_TOKEN_PREFIX)


def issue_sensor_credential() -> TokenMaterial:
    return _issue_token(SENSOR_CREDENTIAL_PREFIX)


def parse_token(raw: str, expected_prefix: str) -> tuple[str, str] | None:
    if not isinstance(raw, str) or len(raw) > 256 or raw.strip() != raw:
        return None
    parts = raw.split(".")
    if (
        len(parts) != 3
        or parts[0] != expected_prefix
        or not _LOOKUP_PATTERN.fullmatch(parts[1])
        or not _SECRET_PATTERN.fullmatch(parts[2])
    ):
        return None
    return parts[1], _token_digest(raw)


def _audit(
    connection: Any,
    *,
    event_type: str,
    outcome: Literal["success", "rejected"],
    enrollment_id: str | None = None,
    credential_id: str | None = None,
    sensor_id: str | None = None,
    site_id: str | None = None,
    reason_code: str | None = None,
    metadata: dict[str, Any] | None = None,
    created_at: datetime,
) -> None:
    safe_metadata = metadata or {}
    if len(safe_metadata) > 16:
        raise ValueError("sensor identity audit metadata is too large")
    encoded = json.dumps(safe_metadata, sort_keys=True, separators=(",", ":"))
    if len(encoded) > 4096:
        raise ValueError("sensor identity audit metadata is too large")
    connection.execute(
        text(
            """
            INSERT INTO sensor_identity_audit_events (
                event_type, outcome, enrollment_id, credential_id,
                sensor_id, site_id, reason_code, metadata_json, created_at
            )
            VALUES (
                :event_type, :outcome, :enrollment_id, :credential_id,
                :sensor_id, :site_id, :reason_code,
                CAST(:metadata_json AS JSONB), :created_at
            )
            """
        ),
        {
            "event_type": event_type,
            "outcome": outcome,
            "enrollment_id": enrollment_id,
            "credential_id": credential_id,
            "sensor_id": sensor_id,
            "site_id": site_id,
            "reason_code": reason_code,
            "metadata_json": encoded,
            "created_at": created_at,
        },
    )


def _public_enrollment(row: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "enrollment_id",
        "site_id",
        "requested_sensor_id",
        "requested_sensor_name",
        "sensor_type",
        "status",
        "failed_attempts",
        "max_attempts",
        "created_at",
        "expires_at",
        "used_at",
        "revoked_at",
        "issued_sensor_id",
    }
    return {key: row.get(key) for key in allowed}


def create_sensor_enrollment(
    *,
    site_id: str,
    requested_sensor_id: str | None,
    requested_sensor_name: str | None,
    sensor_type: str,
    expires_in_minutes: int = DEFAULT_ENROLLMENT_MINUTES,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not MIN_ENROLLMENT_MINUTES <= expires_in_minutes <= MAX_ENROLLMENT_MINUTES:
        raise ValueError("expires_in_minutes is outside supported bounds")
    issued_at = _utc_now(now)
    material = issue_enrollment_token()
    enrollment_id = f"senr_{uuid4().hex}"
    ensure_database_schema()
    with get_engine().begin() as connection:
        site_exists = connection.execute(
            text("SELECT 1 FROM sites WHERE site_id = :site_id"),
            {"site_id": site_id},
        ).scalar_one_or_none()
        if site_exists is None:
            raise SensorIdentityNotFound("site not found")
        row = connection.execute(
            text(
                """
                INSERT INTO sensor_enrollments (
                    enrollment_id, site_id, requested_sensor_id,
                    requested_sensor_name, sensor_type, token_lookup_id,
                    token_digest, status, failed_attempts, max_attempts,
                    created_at, expires_at
                )
                VALUES (
                    :enrollment_id, :site_id, :requested_sensor_id,
                    :requested_sensor_name, :sensor_type, :token_lookup_id,
                    :token_digest, 'pending', 0, :max_attempts,
                    :created_at, :expires_at
                )
                RETURNING *
                """
            ),
            {
                "enrollment_id": enrollment_id,
                "site_id": site_id,
                "requested_sensor_id": requested_sensor_id,
                "requested_sensor_name": requested_sensor_name,
                "sensor_type": sensor_type,
                "token_lookup_id": material.lookup_id,
                "token_digest": material.digest,
                "max_attempts": DEFAULT_MAX_ATTEMPTS,
                "created_at": issued_at,
                "expires_at": issued_at + timedelta(minutes=expires_in_minutes),
            },
        ).mappings().one()
        _audit(
            connection,
            event_type="enrollment_created",
            outcome="success",
            enrollment_id=enrollment_id,
            sensor_id=requested_sensor_id,
            site_id=site_id,
            created_at=issued_at,
        )
    result = _public_enrollment(dict(row))
    result["enrollment_token"] = material.raw
    return result


def _expire_pending_enrollments(connection: Any, *, now: datetime) -> None:
    expired = connection.execute(
        text(
            """
            UPDATE sensor_enrollments
            SET status = 'expired'
            WHERE status = 'pending' AND expires_at <= :now
            RETURNING enrollment_id, site_id, requested_sensor_id
            """
        ),
        {"now": now},
    ).mappings().all()
    for row in expired:
        _audit(
            connection,
            event_type="enrollment_expired",
            outcome="rejected",
            enrollment_id=row["enrollment_id"],
            sensor_id=row["requested_sensor_id"],
            site_id=row["site_id"],
            reason_code="expired",
            created_at=now,
        )


def list_sensor_enrollments(*, limit: int = 100, now: datetime | None = None) -> list[dict[str, Any]]:
    current = _utc_now(now)
    safe_limit = max(1, min(limit, 500))
    ensure_database_schema()
    with get_engine().begin() as connection:
        _expire_pending_enrollments(connection, now=current)
        rows = connection.execute(
            text(
                """
                SELECT *
                FROM sensor_enrollments
                ORDER BY created_at DESC, enrollment_id ASC
                LIMIT :limit
                """
            ),
            {"limit": safe_limit},
        ).mappings().all()
    return [_public_enrollment(dict(row)) for row in rows]


def get_sensor_enrollment(enrollment_id: str, *, now: datetime | None = None) -> dict[str, Any]:
    current = _utc_now(now)
    ensure_database_schema()
    with get_engine().begin() as connection:
        _expire_pending_enrollments(connection, now=current)
        row = connection.execute(
            text("SELECT * FROM sensor_enrollments WHERE enrollment_id = :enrollment_id"),
            {"enrollment_id": enrollment_id},
        ).mappings().one_or_none()
    if row is None:
        raise SensorIdentityNotFound("enrollment not found")
    return _public_enrollment(dict(row))


def revoke_sensor_enrollment(enrollment_id: str, *, now: datetime | None = None) -> dict[str, Any]:
    current = _utc_now(now)
    ensure_database_schema()
    with get_engine().begin() as connection:
        row = connection.execute(
            text("SELECT * FROM sensor_enrollments WHERE enrollment_id = :enrollment_id FOR UPDATE"),
            {"enrollment_id": enrollment_id},
        ).mappings().one_or_none()
        if row is None:
            raise SensorIdentityNotFound("enrollment not found")
        if row["status"] == "used":
            raise SensorIdentityConflict("used enrollment cannot be revoked")
        if row["status"] == "pending":
            row = connection.execute(
                text(
                    """
                    UPDATE sensor_enrollments
                    SET status = 'revoked', revoked_at = :now
                    WHERE enrollment_id = :enrollment_id
                    RETURNING *
                    """
                ),
                {"enrollment_id": enrollment_id, "now": current},
            ).mappings().one()
            _audit(
                connection,
                event_type="enrollment_revoked",
                outcome="success",
                enrollment_id=enrollment_id,
                sensor_id=row["requested_sensor_id"],
                site_id=row["site_id"],
                created_at=current,
            )
    return _public_enrollment(dict(row))


def _reject_enrollment(
    connection: Any,
    *,
    row: dict[str, Any] | None,
    reason_code: str,
    now: datetime,
) -> None:
    del connection
    raise SensorEnrollmentRejected(
        "sensor enrollment failed",
        row=row,
        reason_code=reason_code,
        rejected_at=now,
    )


def _persist_enrollment_rejection(rejection: SensorEnrollmentRejected) -> None:
    row = rejection.row
    reason_code = rejection.reason_code
    now = rejection.rejected_at or datetime.now(timezone.utc)
    event_type = "enrollment_replay_rejected" if reason_code == "already_used" else "enrollment_exchange_rejected"
    with get_engine().begin() as connection:
        if row is not None and row["status"] == "pending":
            locked = connection.execute(
                text(
                    """
                    SELECT enrollment_id, status, failed_attempts, max_attempts
                    FROM sensor_enrollments
                    WHERE enrollment_id = :enrollment_id
                    FOR UPDATE
                    """
                ),
                {"enrollment_id": row["enrollment_id"]},
            ).mappings().one_or_none()
            if locked is not None and locked["status"] == "pending":
                if reason_code == "expired":
                    connection.execute(
                        text(
                            """
                            UPDATE sensor_enrollments
                            SET status = 'expired'
                            WHERE enrollment_id = :enrollment_id
                            """
                        ),
                        {"enrollment_id": row["enrollment_id"]},
                    )
                elif reason_code in {"token_mismatch", "identity_mismatch"}:
                    updated = connection.execute(
                        text(
                            """
                            UPDATE sensor_enrollments
                            SET failed_attempts = failed_attempts + 1,
                                status = CASE
                                    WHEN failed_attempts + 1 >= max_attempts THEN 'revoked'
                                    ELSE status
                                END,
                                revoked_at = CASE
                                    WHEN failed_attempts + 1 >= max_attempts THEN :now
                                    ELSE revoked_at
                                END
                            WHERE enrollment_id = :enrollment_id
                            RETURNING status
                            """
                        ),
                        {"enrollment_id": row["enrollment_id"], "now": now},
                    ).mappings().one()
                    if updated["status"] == "revoked":
                        reason_code = "attempt_limit"
        _audit(
            connection,
            event_type=event_type,
            outcome="rejected",
            enrollment_id=row["enrollment_id"] if row else None,
            sensor_id=(row.get("requested_sensor_id") or row.get("issued_sensor_id")) if row else None,
            site_id=row["site_id"] if row else None,
            reason_code=reason_code,
            created_at=now,
        )


def exchange_sensor_enrollment(
    *,
    enrollment_token: str,
    sensor_id: str,
    sensor_name: str,
    sensor_type: str,
    sensor_version: str | None,
    platform: str | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _utc_now(now)
    parsed = parse_token(enrollment_token, ENROLLMENT_TOKEN_PREFIX)
    if parsed is None:
        ensure_database_schema()
        with get_engine().begin() as connection:
            _audit(
                connection,
                event_type="enrollment_exchange_rejected",
                outcome="rejected",
                reason_code="malformed_token",
                created_at=current,
            )
        raise SensorEnrollmentRejected("sensor enrollment failed")
    lookup_id, provided_digest = parsed
    material = issue_sensor_credential()
    credential_id = f"scred_{uuid4().hex}"
    ensure_database_schema()
    connection = get_engine().connect()
    transaction = connection.begin()
    try:
        selected = connection.execute(
            text(
                """
                SELECT *
                FROM sensor_enrollments
                WHERE token_lookup_id = :token_lookup_id
                FOR UPDATE
                """
            ),
            {"token_lookup_id": lookup_id},
        ).mappings().one_or_none()
        row = dict(selected) if selected is not None else None
        expected_digest = row["token_digest"] if row is not None else _DUMMY_DIGEST
        digest_matches = secrets.compare_digest(provided_digest, expected_digest)
        if row is None or not digest_matches:
            _reject_enrollment(connection, row=row, reason_code="token_mismatch", now=current)
        if row["status"] == "used":
            _reject_enrollment(connection, row=row, reason_code="already_used", now=current)
        if row["status"] != "pending":
            _reject_enrollment(connection, row=row, reason_code="inactive", now=current)
        if row["expires_at"] <= current:
            connection.execute(
                text(
                    """
                    UPDATE sensor_enrollments
                    SET status = 'expired'
                    WHERE enrollment_id = :enrollment_id
                    """
                ),
                {"enrollment_id": row["enrollment_id"]},
            )
            _reject_enrollment(connection, row=row, reason_code="expired", now=current)
        if (
            sensor_type != row["sensor_type"]
            or (row["requested_sensor_id"] is not None and sensor_id != row["requested_sensor_id"])
            or (
                row["requested_sensor_name"] is not None
                and not secrets.compare_digest(sensor_name, row["requested_sensor_name"])
            )
        ):
            _reject_enrollment(connection, row=row, reason_code="identity_mismatch", now=current)

        existing = connection.execute(
            text(
                """
                SELECT agent_id, site_id, agent_type, identity_status
                FROM agent_enrollments
                WHERE agent_id = :sensor_id
                FOR UPDATE
                """
            ),
            {"sensor_id": sensor_id},
        ).mappings().one_or_none()
        if existing is not None and (
            existing["site_id"] != row["site_id"] or existing["agent_type"] != "network-sensor"
        ):
            _reject_enrollment(connection, row=row, reason_code="identity_mismatch", now=current)

        active_credentials = connection.execute(
            text(
                """
                SELECT credential_id
                FROM sensor_credentials
                WHERE sensor_id = :sensor_id AND status = 'active'
                ORDER BY created_at DESC
                FOR UPDATE
                """
            ),
            {"sensor_id": sensor_id},
        ).scalars().all()
        predecessor = active_credentials[0] if active_credentials else None
        connection.execute(
            text(
                """
                INSERT INTO agent_enrollments (
                    agent_id, site_id, display_name, agent_type, platform,
                    version, hostname, mode, identity_status, updated_at
                )
                VALUES (
                    :sensor_id, :site_id, :sensor_name, 'network-sensor',
                    :platform, :sensor_version, :sensor_name,
                    'passive-network', 'active', :now
                )
                ON CONFLICT (agent_id) DO UPDATE SET
                    site_id = EXCLUDED.site_id,
                    display_name = EXCLUDED.display_name,
                    agent_type = 'network-sensor',
                    platform = EXCLUDED.platform,
                    version = EXCLUDED.version,
                    hostname = EXCLUDED.hostname,
                    mode = EXCLUDED.mode,
                    identity_status = 'active',
                    updated_at = EXCLUDED.updated_at
                """
            ),
            {
                "sensor_id": sensor_id,
                "site_id": row["site_id"],
                "sensor_name": sensor_name,
                "platform": platform,
                "sensor_version": sensor_version,
                "now": current,
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO sensor_credentials (
                    credential_id, sensor_id, site_id, sensor_type,
                    token_lookup_id, credential_digest, status, created_at,
                    predecessor_credential_id
                )
                VALUES (
                    :credential_id, :sensor_id, :site_id, :sensor_type,
                    :token_lookup_id, :credential_digest, 'active', :now,
                    :predecessor_credential_id
                )
                """
            ),
            {
                "credential_id": credential_id,
                "sensor_id": sensor_id,
                "site_id": row["site_id"],
                "sensor_type": sensor_type,
                "token_lookup_id": material.lookup_id,
                "credential_digest": material.digest,
                "now": current,
                "predecessor_credential_id": predecessor,
            },
        )
        if active_credentials:
            connection.execute(
                text(
                    """
                    UPDATE sensor_credentials
                    SET status = 'rotated', rotated_at = :now,
                        replacement_credential_id = :credential_id
                    WHERE sensor_id = :sensor_id AND status = 'active'
                      AND credential_id <> :credential_id
                    """
                ),
                {"sensor_id": sensor_id, "credential_id": credential_id, "now": current},
            )
        connection.execute(
            text(
                """
                UPDATE sensor_enrollments
                SET status = 'used', used_at = :now, issued_sensor_id = :sensor_id
                WHERE enrollment_id = :enrollment_id
                """
            ),
            {"enrollment_id": row["enrollment_id"], "sensor_id": sensor_id, "now": current},
        )
        _audit(
            connection,
            event_type="enrollment_completed",
            outcome="success",
            enrollment_id=row["enrollment_id"],
            credential_id=credential_id,
            sensor_id=sensor_id,
            site_id=row["site_id"],
            created_at=current,
        )
        transaction.commit()
    except SensorEnrollmentRejected as rejection:
        transaction.rollback()
        connection.close()
        _persist_enrollment_rejection(rejection)
        raise SensorEnrollmentRejected("sensor enrollment failed") from None
    except Exception:
        transaction.rollback()
        raise
    finally:
        connection.close()
    return {
        "status": "enrolled",
        "site_id": row["site_id"],
        "sensor_id": sensor_id,
        "sensor_type": sensor_type,
        "credential_id": credential_id,
        "sensor_credential": material.raw,
        "issued_at": current,
    }


def authenticate_sensor_request(
    *,
    provided_token: str | None,
    claimed_site_id: str,
    claimed_sensor_id: str,
    claimed_sensor_type: str,
    shared_development_token: str | None = None,
    now: datetime | None = None,
) -> SensorAuthContext:
    current = _utc_now(now)
    raw = provided_token if isinstance(provided_token, str) else ""
    if raw.startswith(f"{SENSOR_CREDENTIAL_PREFIX}."):
        parsed = parse_token(raw, SENSOR_CREDENTIAL_PREFIX)
        if parsed is None:
            raise SensorAuthenticationRejected("valid sensor credential required")
        lookup_id, provided_digest = parsed
        ensure_database_schema()
        rejected = False
        with get_engine().begin() as connection:
            selected = connection.execute(
                text(
                    """
                    SELECT *
                    FROM sensor_credentials
                    WHERE token_lookup_id = :token_lookup_id
                    FOR UPDATE
                    """
                ),
                {"token_lookup_id": lookup_id},
            ).mappings().one_or_none()
            row = dict(selected) if selected is not None else None
            expected_digest = row["credential_digest"] if row is not None else _DUMMY_DIGEST
            digest_matches = secrets.compare_digest(provided_digest, expected_digest)
            status_active = row is not None and row["status"] == "active"
            expired = row is not None and row["expires_at"] is not None and row["expires_at"] <= current
            if expired and status_active:
                connection.execute(
                    text(
                        """
                        UPDATE sensor_credentials
                        SET status = 'expired'
                        WHERE credential_id = :credential_id
                        """
                    ),
                    {"credential_id": row["credential_id"]},
                )
                status_active = False
            identity_matches = (
                row is not None
                and secrets.compare_digest(claimed_site_id, row["site_id"])
                and secrets.compare_digest(claimed_sensor_id, row["sensor_id"])
                and secrets.compare_digest(claimed_sensor_type, row["sensor_type"])
            )
            if not digest_matches or not status_active or not identity_matches:
                _audit(
                    connection,
                    event_type="identity_mismatch_rejected" if digest_matches and status_active else "credential_rejected",
                    outcome="rejected",
                    credential_id=row["credential_id"] if row else None,
                    sensor_id=row["sensor_id"] if row else None,
                    site_id=row["site_id"] if row else None,
                    reason_code=(
                        "identity_mismatch"
                        if digest_matches and status_active
                        else "credential_inactive"
                        if digest_matches
                        else "credential_mismatch"
                    ),
                    created_at=current,
                )
                rejected = True
            else:
                connection.execute(
                    text(
                        """
                        UPDATE sensor_credentials
                        SET last_used_at = GREATEST(COALESCE(last_used_at, :now), :now)
                        WHERE credential_id = :credential_id AND status = 'active'
                        """
                    ),
                    {"credential_id": row["credential_id"], "now": current},
                )
                _audit(
                    connection,
                    event_type="credential_used",
                    outcome="success",
                    credential_id=row["credential_id"],
                    sensor_id=row["sensor_id"],
                    site_id=row["site_id"],
                    created_at=current,
                )
        if rejected:
            raise SensorAuthenticationRejected("valid sensor credential required")
        return SensorAuthContext(
            mode="bound-sensor",
            site_id=row["site_id"],
            sensor_id=row["sensor_id"],
            sensor_type=row["sensor_type"],
            credential_id=row["credential_id"],
        )

    expected = (
        shared_development_token
        if shared_development_token is not None
        else os.getenv(SHARED_DEVELOPMENT_TOKEN_ENV)
    )
    if expected and raw and secrets.compare_digest(raw, expected):
        return SensorAuthContext(
            mode="development-shared",
            site_id=None,
            sensor_id=None,
            sensor_type=None,
            credential_id=None,
        )
    raise SensorAuthenticationRejected("valid sensor credential required")


def _public_credential(row: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "credential_id",
        "sensor_id",
        "site_id",
        "sensor_type",
        "status",
        "created_at",
        "last_used_at",
        "rotated_at",
        "revoked_at",
        "expires_at",
        "predecessor_credential_id",
        "replacement_credential_id",
    }
    return {key: row.get(key) for key in allowed}


def list_sensor_credentials(sensor_id: str | None = None, *, limit: int = 500) -> list[dict[str, Any]]:
    ensure_database_schema()
    safe_limit = max(1, min(limit, 500))
    query = """
        SELECT
            c.*, a.display_name AS sensor_name,
            a.identity_status
        FROM sensor_credentials c
        JOIN agent_enrollments a ON a.agent_id = c.sensor_id
    """
    parameters: dict[str, Any] = {}
    if sensor_id is not None:
        query += " WHERE c.sensor_id = :sensor_id"
        parameters["sensor_id"] = sensor_id
    query += " ORDER BY c.created_at DESC, c.credential_id ASC LIMIT :limit"
    parameters["limit"] = safe_limit
    with get_engine().begin() as connection:
        rows = connection.execute(text(query), parameters).mappings().all()
    result = []
    for selected in rows:
        row = dict(selected)
        public = _public_credential(row)
        public["sensor_name"] = row["sensor_name"]
        public["identity_status"] = row["identity_status"]
        result.append(public)
    return result


def rotate_sensor_credential(sensor_id: str, *, now: datetime | None = None) -> dict[str, Any]:
    current = _utc_now(now)
    material = issue_sensor_credential()
    credential_id = f"scred_{uuid4().hex}"
    ensure_database_schema()
    with get_engine().begin() as connection:
        sensor = connection.execute(
            text(
                """
                SELECT agent_id, site_id, agent_type, identity_status
                FROM agent_enrollments
                WHERE agent_id = :sensor_id
                FOR UPDATE
                """
            ),
            {"sensor_id": sensor_id},
        ).mappings().one_or_none()
        if sensor is None or sensor["agent_type"] != "network-sensor":
            raise SensorIdentityNotFound("sensor not found")
        if sensor["identity_status"] != "active":
            raise SensorIdentityConflict("sensor identity is not active")
        active = connection.execute(
            text(
                """
                SELECT *
                FROM sensor_credentials
                WHERE sensor_id = :sensor_id AND status = 'active'
                ORDER BY created_at DESC
                FOR UPDATE
                """
            ),
            {"sensor_id": sensor_id},
        ).mappings().all()
        if not active:
            raise SensorIdentityConflict("sensor has no active credential")
        predecessor = active[0]
        connection.execute(
            text(
                """
                INSERT INTO sensor_credentials (
                    credential_id, sensor_id, site_id, sensor_type,
                    token_lookup_id, credential_digest, status, created_at,
                    predecessor_credential_id
                )
                VALUES (
                    :credential_id, :sensor_id, :site_id, :sensor_type,
                    :token_lookup_id, :credential_digest, 'active', :now,
                    :predecessor_credential_id
                )
                """
            ),
            {
                "credential_id": credential_id,
                "sensor_id": sensor_id,
                "site_id": predecessor["site_id"],
                "sensor_type": predecessor["sensor_type"],
                "token_lookup_id": material.lookup_id,
                "credential_digest": material.digest,
                "now": current,
                "predecessor_credential_id": predecessor["credential_id"],
            },
        )
        connection.execute(
            text(
                """
                UPDATE sensor_credentials
                SET status = 'rotated', rotated_at = :now,
                    replacement_credential_id = :credential_id
                WHERE sensor_id = :sensor_id AND status = 'active'
                  AND credential_id <> :credential_id
                """
            ),
            {"sensor_id": sensor_id, "credential_id": credential_id, "now": current},
        )
        _audit(
            connection,
            event_type="credential_rotated",
            outcome="success",
            credential_id=credential_id,
            sensor_id=sensor_id,
            site_id=predecessor["site_id"],
            metadata={"predecessor_credential_id": predecessor["credential_id"]},
            created_at=current,
        )
    return {
        "status": "rotated",
        "credential_id": credential_id,
        "sensor_id": sensor_id,
        "site_id": predecessor["site_id"],
        "sensor_type": predecessor["sensor_type"],
        "sensor_credential": material.raw,
        "issued_at": current,
    }


def revoke_sensor_credential(
    sensor_id: str,
    credential_id: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _utc_now(now)
    ensure_database_schema()
    with get_engine().begin() as connection:
        selected = connection.execute(
            text(
                """
                SELECT *
                FROM sensor_credentials
                WHERE credential_id = :credential_id AND sensor_id = :sensor_id
                FOR UPDATE
                """
            ),
            {"credential_id": credential_id, "sensor_id": sensor_id},
        ).mappings().one_or_none()
        if selected is None:
            raise SensorIdentityNotFound("credential not found")
        row = dict(selected)
        if row["status"] == "active":
            row = dict(
                connection.execute(
                    text(
                        """
                        UPDATE sensor_credentials
                        SET status = 'revoked', revoked_at = :now
                        WHERE credential_id = :credential_id
                        RETURNING *
                        """
                    ),
                    {"credential_id": credential_id, "now": current},
                ).mappings().one()
            )
            remaining = connection.execute(
                text(
                    """
                    SELECT 1 FROM sensor_credentials
                    WHERE sensor_id = :sensor_id AND status = 'active'
                    LIMIT 1
                    """
                ),
                {"sensor_id": sensor_id},
            ).scalar_one_or_none()
            if remaining is None:
                connection.execute(
                    text(
                        """
                        UPDATE agent_enrollments
                        SET identity_status = 'revoked', updated_at = :now
                        WHERE agent_id = :sensor_id
                        """
                    ),
                    {"sensor_id": sensor_id, "now": current},
                )
            _audit(
                connection,
                event_type="credential_revoked",
                outcome="success",
                credential_id=credential_id,
                sensor_id=sensor_id,
                site_id=row["site_id"],
                created_at=current,
            )
    return _public_credential(row)


def revoke_sensor(sensor_id: str, *, now: datetime | None = None) -> dict[str, Any]:
    current = _utc_now(now)
    ensure_database_schema()
    with get_engine().begin() as connection:
        sensor = connection.execute(
            text(
                """
                SELECT agent_id, site_id, agent_type, identity_status
                FROM agent_enrollments
                WHERE agent_id = :sensor_id
                FOR UPDATE
                """
            ),
            {"sensor_id": sensor_id},
        ).mappings().one_or_none()
        if sensor is None or sensor["agent_type"] != "network-sensor":
            raise SensorIdentityNotFound("sensor not found")
        revoked_count = connection.execute(
            text(
                """
                UPDATE sensor_credentials
                SET status = 'revoked', revoked_at = :now
                WHERE sensor_id = :sensor_id AND status = 'active'
                """
            ),
            {"sensor_id": sensor_id, "now": current},
        ).rowcount
        connection.execute(
            text(
                """
                UPDATE agent_enrollments
                SET identity_status = 'revoked', updated_at = :now
                WHERE agent_id = :sensor_id
                """
            ),
            {"sensor_id": sensor_id, "now": current},
        )
        _audit(
            connection,
            event_type="sensor_revoked",
            outcome="success",
            sensor_id=sensor_id,
            site_id=sensor["site_id"],
            metadata={"revoked_active_credentials": max(int(revoked_count or 0), 0)},
            created_at=current,
        )
    return {
        "status": "revoked",
        "sensor_id": sensor_id,
        "site_id": sensor["site_id"],
        "revoked_at": current,
        "revoked_active_credentials": max(int(revoked_count or 0), 0),
    }


def list_sensor_identity_audit(limit: int = 100) -> list[dict[str, Any]]:
    safe_limit = max(1, min(limit, 500))
    ensure_database_schema()
    with get_engine().begin() as connection:
        rows = connection.execute(
            text(
                """
                SELECT
                    event_id, event_type, outcome, enrollment_id,
                    credential_id, sensor_id, site_id, reason_code,
                    metadata_json, created_at
                FROM sensor_identity_audit_events
                ORDER BY created_at DESC, event_id DESC
                LIMIT :limit
                """
            ),
            {"limit": safe_limit},
        ).mappings().all()
    return [dict(row) for row in rows]


def record_sensor_checkin(
    *,
    site_id: str,
    sensor_id: str,
    sensor_name: str,
    sensor_version: str | None,
    status: str,
    received_at: datetime,
) -> int:
    ensure_database_schema()
    payload = {
        "site_id": site_id,
        "sensor_id": sensor_id,
        "sensor_name": sensor_name,
        "sensor_version": sensor_version,
        "sensor_type": "passive-network-sensor",
        "status": status,
    }
    with get_engine().begin() as connection:
        checkin_id = connection.execute(
            text(
                """
                INSERT INTO agent_checkins (
                    site_id, agent_id, version, hostname, mode,
                    received_at, payload_json
                )
                VALUES (
                    :site_id, :sensor_id, :sensor_version, :sensor_name,
                    'passive-network', :received_at,
                    CAST(:payload_json AS JSONB)
                )
                RETURNING id
                """
            ),
            {
                "site_id": site_id,
                "sensor_id": sensor_id,
                "sensor_version": sensor_version,
                "sensor_name": sensor_name,
                "received_at": received_at,
                "payload_json": json.dumps(payload, sort_keys=True, separators=(",", ":")),
            },
        ).scalar_one()
        connection.execute(
            text(
                """
                UPDATE agent_enrollments
                SET display_name = :sensor_name,
                    version = COALESCE(:sensor_version, version),
                    hostname = :sensor_name,
                    mode = 'passive-network',
                    last_seen_at = :received_at,
                    updated_at = :received_at
                WHERE agent_id = :sensor_id
                  AND site_id = :site_id
                  AND identity_status = 'active'
                """
            ),
            {
                "site_id": site_id,
                "sensor_id": sensor_id,
                "sensor_name": sensor_name,
                "sensor_version": sensor_version,
                "received_at": received_at,
            },
        )
    return int(checkin_id)
