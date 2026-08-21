"""Endpoint-agent enrollment, bound credentials, audit, and authentication.

This module intentionally does not share token prefixes, credential tables, or
authentication context with passive sensors. Raw bearer material exists only
while it is issued or verified; PostgreSQL stores lookup identifiers and
SHA-256 digests.
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


AGENT_ENROLLMENT_TOKEN_PREFIX = "oaw_agent_enroll_v1"
AGENT_CREDENTIAL_PREFIX = "oaw_agent_v1"
SHARED_DEVELOPMENT_TOKEN_ENV = "OPENASSETWATCH_AGENT_TOKEN"
TOKEN_SECRET_BYTES = 32
DEFAULT_MAX_ATTEMPTS = 10
_LOOKUP_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_SECRET_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")
_DUMMY_DIGEST = hashlib.sha256(b"openassetwatch-invalid-endpoint-agent-credential").hexdigest()


class EndpointAgentIdentityError(Exception):
    """Base class for bounded API error mapping."""


class AgentEnrollmentRejected(EndpointAgentIdentityError):
    """One generic enrollment rejection for every invalid exchange."""


class AgentAuthenticationRejected(EndpointAgentIdentityError):
    """A credential or claimed binding is not authorized."""


class AgentIdentityNotFound(EndpointAgentIdentityError):
    """An administrator referenced an unknown object."""


class AgentIdentityConflict(EndpointAgentIdentityError):
    """An administrative state transition is invalid."""


@dataclass(frozen=True)
class TokenMaterial:
    raw: str
    lookup_id: str
    digest: str


@dataclass(frozen=True)
class AgentAuthContext:
    mode: Literal["bound-agent", "development-shared"]
    site_id: str | None
    agent_id: str | None
    deployment_id: str | None
    agent_type: str | None
    credential_id: str | None


def _utc_now(now: datetime | None = None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("security timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _issue_token(prefix: str) -> TokenMaterial:
    lookup_id = secrets.token_hex(16)
    raw = f"{prefix}.{lookup_id}.{secrets.token_urlsafe(TOKEN_SECRET_BYTES)}"
    return TokenMaterial(raw=raw, lookup_id=lookup_id, digest=_digest(raw))


def issue_agent_enrollment_token() -> TokenMaterial:
    return _issue_token(AGENT_ENROLLMENT_TOKEN_PREFIX)


def issue_agent_credential() -> TokenMaterial:
    return _issue_token(AGENT_CREDENTIAL_PREFIX)


def parse_agent_token(raw: str, expected_prefix: str) -> tuple[str, str] | None:
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
    return parts[1], _digest(raw)


def _audit(
    connection: Any,
    *,
    event_type: str,
    outcome: Literal["success", "rejected"],
    actor: str,
    enrollment_id: str | None = None,
    credential_id: str | None = None,
    agent_id: str | None = None,
    site_id: str | None = None,
    reason_code: str | None = None,
    metadata: dict[str, str | int | bool | None] | None = None,
    created_at: datetime,
) -> None:
    safe_actor = actor.strip()[:128]
    if not safe_actor:
        raise ValueError("agent identity audit actor is required")
    safe_metadata = metadata or {}
    if len(safe_metadata) > 16:
        raise ValueError("agent identity audit metadata is too large")
    encoded = json.dumps(safe_metadata, sort_keys=True, separators=(",", ":"))
    if len(encoded) > 4096:
        raise ValueError("agent identity audit metadata is too large")
    connection.execute(
        text(
            """
            INSERT INTO endpoint_agent_identity_audit_events (
                event_type, outcome, actor, enrollment_id, credential_id,
                agent_id, site_id, reason_code, metadata_json, created_at
            ) VALUES (
                :event_type, :outcome, :actor, :enrollment_id, :credential_id,
                :agent_id, :site_id, :reason_code,
                CAST(:metadata_json AS JSONB), :created_at
            )
            """
        ),
        {
            "event_type": event_type[:64],
            "outcome": outcome,
            "actor": safe_actor,
            "enrollment_id": enrollment_id,
            "credential_id": credential_id,
            "agent_id": agent_id,
            "site_id": site_id,
            "reason_code": reason_code[:64] if reason_code else None,
            "metadata_json": encoded,
            "created_at": created_at,
        },
    )


_ENROLLMENT_PUBLIC_FIELDS = {
    "enrollment_id",
    "site_id",
    "requested_deployment_id",
    "requested_display_name",
    "requested_agent_type",
    "status",
    "failed_attempts",
    "max_attempts",
    "created_by",
    "created_at",
    "expires_at",
    "consumed_at",
    "revoked_at",
    "issued_agent_id",
}


def _public_enrollment(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row.get(key) for key in _ENROLLMENT_PUBLIC_FIELDS}


def create_agent_enrollment(
    *,
    site_id: str,
    requested_deployment_id: str | None,
    requested_display_name: str | None,
    requested_agent_type: str,
    expires_in_minutes: int,
    actor: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _utc_now(now)
    material = issue_agent_enrollment_token()
    enrollment_id = f"aenr_{uuid4().hex}"
    ensure_database_schema()
    with get_engine().begin() as connection:
        if connection.execute(
            text("SELECT 1 FROM sites WHERE site_id = :site_id"),
            {"site_id": site_id},
        ).scalar_one_or_none() is None:
            raise AgentIdentityNotFound("site not found")
        row = connection.execute(
            text(
                """
                INSERT INTO endpoint_agent_enrollments (
                    enrollment_id, token_lookup_id, token_digest, site_id,
                    requested_deployment_id, requested_agent_type,
                    requested_display_name, status, failed_attempts,
                    max_attempts, created_by, created_at, expires_at
                ) VALUES (
                    :enrollment_id, :token_lookup_id, :token_digest, :site_id,
                    :requested_deployment_id, :requested_agent_type,
                    :requested_display_name, 'pending', 0, :max_attempts,
                    :created_by, :created_at, :expires_at
                ) RETURNING *
                """
            ),
            {
                "enrollment_id": enrollment_id,
                "token_lookup_id": material.lookup_id,
                "token_digest": material.digest,
                "site_id": site_id,
                "requested_deployment_id": requested_deployment_id,
                "requested_agent_type": requested_agent_type,
                "requested_display_name": requested_display_name,
                "max_attempts": DEFAULT_MAX_ATTEMPTS,
                "created_by": actor[:128],
                "created_at": current,
                "expires_at": current + timedelta(minutes=expires_in_minutes),
            },
        ).mappings().one()
        _audit(
            connection,
            event_type="enrollment_created",
            outcome="success",
            actor=actor,
            enrollment_id=enrollment_id,
            site_id=site_id,
            created_at=current,
        )
    result = _public_enrollment(dict(row))
    result["enrollment_token"] = material.raw
    return result


def _expire_enrollments(connection: Any, *, now: datetime) -> None:
    rows = connection.execute(
        text(
            """
            UPDATE endpoint_agent_enrollments
            SET status = 'expired'
            WHERE status = 'pending' AND expires_at <= :now
            RETURNING enrollment_id, site_id, created_by
            """
        ),
        {"now": now},
    ).mappings().all()
    for row in rows:
        _audit(
            connection,
            event_type="enrollment_expired",
            outcome="rejected",
            actor="system-expiration",
            enrollment_id=row["enrollment_id"],
            site_id=row["site_id"],
            reason_code="expired",
            created_at=now,
        )


def list_agent_enrollments(*, limit: int = 100, now: datetime | None = None) -> list[dict[str, Any]]:
    current = _utc_now(now)
    ensure_database_schema()
    with get_engine().begin() as connection:
        _expire_enrollments(connection, now=current)
        rows = connection.execute(
            text(
                """
                SELECT * FROM endpoint_agent_enrollments
                ORDER BY created_at DESC, enrollment_id ASC
                LIMIT :limit
                """
            ),
            {"limit": max(1, min(limit, 500))},
        ).mappings().all()
    return [_public_enrollment(dict(row)) for row in rows]


def get_agent_enrollment(enrollment_id: str, *, now: datetime | None = None) -> dict[str, Any]:
    current = _utc_now(now)
    ensure_database_schema()
    with get_engine().begin() as connection:
        _expire_enrollments(connection, now=current)
        row = connection.execute(
            text("SELECT * FROM endpoint_agent_enrollments WHERE enrollment_id = :enrollment_id"),
            {"enrollment_id": enrollment_id},
        ).mappings().one_or_none()
    if row is None:
        raise AgentIdentityNotFound("enrollment not found")
    return _public_enrollment(dict(row))


def revoke_agent_enrollment(
    enrollment_id: str,
    *,
    actor: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _utc_now(now)
    ensure_database_schema()
    with get_engine().begin() as connection:
        selected = connection.execute(
            text("SELECT * FROM endpoint_agent_enrollments WHERE enrollment_id = :enrollment_id FOR UPDATE"),
            {"enrollment_id": enrollment_id},
        ).mappings().one_or_none()
        if selected is None:
            raise AgentIdentityNotFound("enrollment not found")
        row = dict(selected)
        if row["status"] == "consumed":
            raise AgentIdentityConflict("consumed enrollment cannot be revoked")
        if row["status"] == "pending":
            row = dict(
                connection.execute(
                    text(
                        """
                        UPDATE endpoint_agent_enrollments
                        SET status = 'revoked', revoked_at = :now
                        WHERE enrollment_id = :enrollment_id
                        RETURNING *
                        """
                    ),
                    {"enrollment_id": enrollment_id, "now": current},
                ).mappings().one()
            )
            _audit(
                connection,
                event_type="enrollment_revoked",
                outcome="success",
                actor=actor,
                enrollment_id=enrollment_id,
                site_id=row["site_id"],
                created_at=current,
            )
    return _public_enrollment(row)


def _record_exchange_rejection(
    *,
    row: dict[str, Any] | None,
    reason_code: str,
    now: datetime,
) -> None:
    with get_engine().begin() as connection:
        if row is not None and row["status"] == "pending":
            locked = connection.execute(
                text(
                    """
                    SELECT enrollment_id, status, failed_attempts, max_attempts
                    FROM endpoint_agent_enrollments
                    WHERE enrollment_id = :enrollment_id
                    FOR UPDATE
                    """
                ),
                {"enrollment_id": row["enrollment_id"]},
            ).mappings().one_or_none()
            if locked is not None and locked["status"] == "pending":
                if reason_code == "expired":
                    connection.execute(
                        text("UPDATE endpoint_agent_enrollments SET status = 'expired' WHERE enrollment_id = :enrollment_id"),
                        {"enrollment_id": row["enrollment_id"]},
                    )
                elif reason_code in {"token_mismatch", "deployment_mismatch"}:
                    updated = connection.execute(
                        text(
                            """
                            UPDATE endpoint_agent_enrollments
                            SET failed_attempts = failed_attempts + 1,
                                status = CASE WHEN failed_attempts + 1 >= max_attempts THEN 'revoked' ELSE status END,
                                revoked_at = CASE WHEN failed_attempts + 1 >= max_attempts THEN :now ELSE revoked_at END
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
            event_type="enrollment_replay_rejected" if reason_code == "already_consumed" else "enrollment_exchange_rejected",
            outcome="rejected",
            actor="endpoint-agent",
            enrollment_id=row["enrollment_id"] if row else None,
            agent_id=row.get("issued_agent_id") if row else None,
            site_id=row["site_id"] if row else None,
            reason_code=reason_code,
            created_at=now,
        )


def exchange_agent_enrollment(
    *,
    enrollment_token: str,
    installation_id: str | None,
    display_name: str | None,
    agent_version: str | None,
    platform: str | None,
    architecture: str | None,
    agent_type: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _utc_now(now)
    parsed = parse_agent_token(enrollment_token, AGENT_ENROLLMENT_TOKEN_PREFIX)
    ensure_database_schema()
    if parsed is None:
        _record_exchange_rejection(row=None, reason_code="malformed_token", now=current)
        raise AgentEnrollmentRejected("agent enrollment failed")
    lookup_id, provided_digest = parsed
    credential = issue_agent_credential()
    credential_id = f"acred_{uuid4().hex}"
    agent_id = f"agent_{uuid4().hex}"
    row: dict[str, Any] | None = None
    reason_code: str | None = None
    connection = get_engine().connect()
    transaction = connection.begin()
    try:
        selected = connection.execute(
            text("SELECT * FROM endpoint_agent_enrollments WHERE token_lookup_id = :lookup_id FOR UPDATE"),
            {"lookup_id": lookup_id},
        ).mappings().one_or_none()
        row = dict(selected) if selected is not None else None
        expected = row["token_digest"] if row is not None else _DUMMY_DIGEST
        if row is None or not secrets.compare_digest(provided_digest, expected):
            reason_code = "token_mismatch"
        elif row["status"] == "consumed":
            reason_code = "already_consumed"
        elif row["status"] != "pending":
            reason_code = "inactive"
        elif row["expires_at"] <= current:
            reason_code = "expired"
        elif row["requested_agent_type"] != agent_type:
            reason_code = "type_mismatch"
        elif row["requested_deployment_id"] and not secrets.compare_digest(
            row["requested_deployment_id"], installation_id or ""
        ):
            reason_code = "deployment_mismatch"
        if reason_code is not None:
            transaction.rollback()
            connection.close()
            _record_exchange_rejection(row=row, reason_code=reason_code, now=current)
            raise AgentEnrollmentRejected("agent enrollment failed")

        deployment_id = row["requested_deployment_id"] or installation_id
        connection.execute(
            text(
                """
                INSERT INTO agent_enrollments (
                    agent_id, site_id, display_name, agent_type, platform,
                    architecture, version, hostname, mode, last_seen_at,
                    identity_status, created_at, updated_at
                ) VALUES (
                    :agent_id, :site_id, :display_name, 'endpoint-agent',
                    :platform, :architecture, :version, :hostname,
                    'endpoint-inventory', NULL, 'active', :now, :now
                )
                """
            ),
            {
                "agent_id": agent_id,
                "site_id": row["site_id"],
                "display_name": display_name or row["requested_display_name"] or agent_id,
                "platform": platform,
                "architecture": architecture,
                "version": agent_version,
                "hostname": display_name,
                "now": current,
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO endpoint_agent_credentials (
                    credential_id, token_lookup_id, credential_digest,
                    agent_id, site_id, deployment_id, agent_type, status,
                    created_at
                ) VALUES (
                    :credential_id, :token_lookup_id, :credential_digest,
                    :agent_id, :site_id, :deployment_id, 'endpoint-agent',
                    'active', :now
                )
                """
            ),
            {
                "credential_id": credential_id,
                "token_lookup_id": credential.lookup_id,
                "credential_digest": credential.digest,
                "agent_id": agent_id,
                "site_id": row["site_id"],
                "deployment_id": deployment_id,
                "now": current,
            },
        )
        connection.execute(
            text(
                """
                UPDATE endpoint_agent_enrollments
                SET status = 'consumed', consumed_at = :now,
                    issued_agent_id = :agent_id
                WHERE enrollment_id = :enrollment_id
                """
            ),
            {"now": current, "agent_id": agent_id, "enrollment_id": row["enrollment_id"]},
        )
        _audit(
            connection,
            event_type="enrollment_completed",
            outcome="success",
            actor="endpoint-agent",
            enrollment_id=row["enrollment_id"],
            credential_id=credential_id,
            agent_id=agent_id,
            site_id=row["site_id"],
            metadata={"deployment_bound": deployment_id is not None},
            created_at=current,
        )
        transaction.commit()
    except AgentEnrollmentRejected:
        raise
    except Exception:
        if transaction.is_active:
            transaction.rollback()
        raise
    finally:
        connection.close()
    return {
        "status": "enrolled",
        "site_id": row["site_id"],
        "agent_id": agent_id,
        "deployment_id": row["requested_deployment_id"] or installation_id,
        "agent_type": "endpoint-agent",
        "credential_id": credential_id,
        "agent_credential": credential.raw,
        "issued_at": current,
    }


def authenticate_agent_request(
    *,
    provided_token: str | None,
    claimed_site_id: str | None = None,
    claimed_agent_id: str | None = None,
    claimed_deployment_id: str | None = None,
    claimed_agent_type: str | None = None,
    shared_development_token: str | None = None,
    now: datetime | None = None,
) -> AgentAuthContext:
    current = _utc_now(now)
    raw = provided_token if isinstance(provided_token, str) else ""
    if raw.startswith(f"{AGENT_CREDENTIAL_PREFIX}."):
        parsed = parse_agent_token(raw, AGENT_CREDENTIAL_PREFIX)
        if parsed is None:
            raise AgentAuthenticationRejected("valid agent credential required")
        lookup_id, provided_digest = parsed
        ensure_database_schema()
        rejected = False
        row: dict[str, Any] | None = None
        with get_engine().begin() as connection:
            selected = connection.execute(
                text(
                    """
                    SELECT c.*, a.identity_status
                    FROM endpoint_agent_credentials c
                    JOIN agent_enrollments a ON a.agent_id = c.agent_id
                    WHERE c.token_lookup_id = :lookup_id
                    FOR UPDATE OF c, a
                    """
                ),
                {"lookup_id": lookup_id},
            ).mappings().one_or_none()
            row = dict(selected) if selected is not None else None
            expected = row["credential_digest"] if row is not None else _DUMMY_DIGEST
            digest_matches = secrets.compare_digest(provided_digest, expected)
            active = row is not None and row["status"] == "active" and row["identity_status"] == "active"
            if row is not None and row["expires_at"] is not None and row["expires_at"] <= current:
                if row["status"] == "active":
                    connection.execute(
                        text("UPDATE endpoint_agent_credentials SET status = 'expired' WHERE credential_id = :credential_id"),
                        {"credential_id": row["credential_id"]},
                    )
                active = False
            claimed_matches = row is not None and all(
                claim is None or secrets.compare_digest(claim, bound or "")
                for claim, bound in (
                    (claimed_site_id, row["site_id"]),
                    (claimed_agent_id, row["agent_id"]),
                    (claimed_deployment_id, row["deployment_id"]),
                    (claimed_agent_type, row["agent_type"]),
                )
            )
            if not digest_matches or not active or not claimed_matches:
                _audit(
                    connection,
                    event_type="identity_mismatch_rejected" if digest_matches and active else "credential_rejected",
                    outcome="rejected",
                    actor="endpoint-agent",
                    credential_id=row["credential_id"] if row else None,
                    agent_id=row["agent_id"] if row else None,
                    site_id=row["site_id"] if row else None,
                    reason_code="identity_mismatch" if digest_matches and active else "credential_inactive" if digest_matches else "credential_mismatch",
                    created_at=current,
                )
                rejected = True
            else:
                connection.execute(
                    text(
                        """
                        UPDATE endpoint_agent_credentials
                        SET last_used_at = GREATEST(COALESCE(last_used_at, :now), :now)
                        WHERE credential_id = :credential_id AND status = 'active'
                        """
                    ),
                    {"credential_id": row["credential_id"], "now": current},
                )
        if rejected or row is None:
            raise AgentAuthenticationRejected("valid agent credential required")
        return AgentAuthContext(
            mode="bound-agent",
            site_id=row["site_id"],
            agent_id=row["agent_id"],
            deployment_id=row["deployment_id"],
            agent_type=row["agent_type"],
            credential_id=row["credential_id"],
        )

    expected_shared = shared_development_token if shared_development_token is not None else os.getenv(SHARED_DEVELOPMENT_TOKEN_ENV)
    if expected_shared and raw and secrets.compare_digest(raw, expected_shared):
        return AgentAuthContext(
            mode="development-shared",
            site_id=None,
            agent_id=None,
            deployment_id=None,
            agent_type=None,
            credential_id=None,
        )
    raise AgentAuthenticationRejected("valid agent credential required")


_CREDENTIAL_PUBLIC_FIELDS = {
    "credential_id",
    "agent_id",
    "site_id",
    "deployment_id",
    "agent_type",
    "status",
    "created_at",
    "expires_at",
    "last_used_at",
    "rotated_at",
    "revoked_at",
    "predecessor_credential_id",
    "replacement_credential_id",
    "identity_status",
}


def _public_credential(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row.get(key) for key in _CREDENTIAL_PUBLIC_FIELDS}


def list_agent_credentials(agent_id: str | None = None, *, limit: int = 500) -> list[dict[str, Any]]:
    ensure_database_schema()
    query = """
        SELECT c.*, a.identity_status
        FROM endpoint_agent_credentials c
        JOIN agent_enrollments a ON a.agent_id = c.agent_id
    """
    parameters: dict[str, Any] = {"limit": max(1, min(limit, 500))}
    if agent_id is not None:
        query += " WHERE c.agent_id = :agent_id"
        parameters["agent_id"] = agent_id
    query += " ORDER BY c.created_at DESC, c.credential_id ASC LIMIT :limit"
    with get_engine().begin() as connection:
        rows = connection.execute(text(query), parameters).mappings().all()
    return [_public_credential(dict(row)) for row in rows]


def rotate_agent_credential(
    agent_id: str,
    *,
    actor: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _utc_now(now)
    material = issue_agent_credential()
    credential_id = f"acred_{uuid4().hex}"
    ensure_database_schema()
    with get_engine().begin() as connection:
        agent = connection.execute(
            text(
                """
                SELECT agent_id, site_id, agent_type, identity_status
                FROM agent_enrollments
                WHERE agent_id = :agent_id
                FOR UPDATE
                """
            ),
            {"agent_id": agent_id},
        ).mappings().one_or_none()
        if agent is None or agent["agent_type"] != "endpoint-agent":
            raise AgentIdentityNotFound("agent not found")
        if agent["identity_status"] != "active":
            raise AgentIdentityConflict("agent identity is not active")
        active = connection.execute(
            text(
                """
                SELECT * FROM endpoint_agent_credentials
                WHERE agent_id = :agent_id AND status = 'active'
                ORDER BY created_at DESC
                FOR UPDATE
                """
            ),
            {"agent_id": agent_id},
        ).mappings().all()
        if not active:
            raise AgentIdentityConflict("agent has no active credential")
        predecessor = dict(active[0])
        connection.execute(
            text(
                """
                UPDATE endpoint_agent_credentials
                SET status = 'rotated', rotated_at = :now
                WHERE agent_id = :agent_id AND status = 'active'
                """
            ),
            {"agent_id": agent_id, "now": current},
        )
        connection.execute(
            text(
                """
                INSERT INTO endpoint_agent_credentials (
                    credential_id, token_lookup_id, credential_digest,
                    agent_id, site_id, deployment_id, agent_type, status,
                    created_at, predecessor_credential_id
                ) VALUES (
                    :credential_id, :token_lookup_id, :credential_digest,
                    :agent_id, :site_id, :deployment_id, 'endpoint-agent',
                    'active', :now, :predecessor_credential_id
                )
                """
            ),
            {
                "credential_id": credential_id,
                "token_lookup_id": material.lookup_id,
                "credential_digest": material.digest,
                "agent_id": agent_id,
                "site_id": predecessor["site_id"],
                "deployment_id": predecessor["deployment_id"],
                "now": current,
                "predecessor_credential_id": predecessor["credential_id"],
            },
        )
        connection.execute(
            text(
                """
                UPDATE endpoint_agent_credentials
                SET replacement_credential_id = :credential_id
                WHERE agent_id = :agent_id
                  AND status = 'rotated'
                  AND replacement_credential_id IS NULL
                """
            ),
            {"agent_id": agent_id, "credential_id": credential_id},
        )
        _audit(
            connection,
            event_type="credential_rotated",
            outcome="success",
            actor=actor,
            credential_id=credential_id,
            agent_id=agent_id,
            site_id=predecessor["site_id"],
            metadata={"predecessor_credential_id": predecessor["credential_id"]},
            created_at=current,
        )
    return {
        "status": "rotated",
        "credential_id": credential_id,
        "agent_id": agent_id,
        "site_id": predecessor["site_id"],
        "deployment_id": predecessor["deployment_id"],
        "agent_type": "endpoint-agent",
        "agent_credential": material.raw,
        "issued_at": current,
    }


def revoke_agent_credential(
    agent_id: str,
    credential_id: str,
    *,
    actor: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _utc_now(now)
    ensure_database_schema()
    with get_engine().begin() as connection:
        selected = connection.execute(
            text(
                """
                SELECT c.*, a.identity_status
                FROM endpoint_agent_credentials c
                JOIN agent_enrollments a ON a.agent_id = c.agent_id
                WHERE c.credential_id = :credential_id AND c.agent_id = :agent_id
                FOR UPDATE OF c, a
                """
            ),
            {"credential_id": credential_id, "agent_id": agent_id},
        ).mappings().one_or_none()
        if selected is None:
            raise AgentIdentityNotFound("credential not found")
        row = dict(selected)
        if row["status"] == "active":
            row.update(
                dict(
                    connection.execute(
                        text(
                            """
                            UPDATE endpoint_agent_credentials
                            SET status = 'revoked', revoked_at = :now
                            WHERE credential_id = :credential_id
                            RETURNING *
                            """
                        ),
                        {"credential_id": credential_id, "now": current},
                    ).mappings().one()
                )
            )
            remaining = connection.execute(
                text("SELECT 1 FROM endpoint_agent_credentials WHERE agent_id = :agent_id AND status = 'active' LIMIT 1"),
                {"agent_id": agent_id},
            ).scalar_one_or_none()
            if remaining is None:
                connection.execute(
                    text("UPDATE agent_enrollments SET identity_status = 'revoked', updated_at = :now WHERE agent_id = :agent_id"),
                    {"agent_id": agent_id, "now": current},
                )
                row["identity_status"] = "revoked"
            _audit(
                connection,
                event_type="credential_revoked",
                outcome="success",
                actor=actor,
                credential_id=credential_id,
                agent_id=agent_id,
                site_id=row["site_id"],
                created_at=current,
            )
    return _public_credential(row)


def revoke_agent(
    agent_id: str,
    *,
    actor: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = _utc_now(now)
    ensure_database_schema()
    with get_engine().begin() as connection:
        agent = connection.execute(
            text(
                """
                SELECT agent_id, site_id, agent_type, identity_status
                FROM agent_enrollments
                WHERE agent_id = :agent_id
                FOR UPDATE
                """
            ),
            {"agent_id": agent_id},
        ).mappings().one_or_none()
        if agent is None or agent["agent_type"] != "endpoint-agent":
            raise AgentIdentityNotFound("agent not found")
        revoked_count = connection.execute(
            text(
                """
                UPDATE endpoint_agent_credentials
                SET status = 'revoked', revoked_at = :now
                WHERE agent_id = :agent_id AND status = 'active'
                """
            ),
            {"agent_id": agent_id, "now": current},
        ).rowcount
        connection.execute(
            text("UPDATE agent_enrollments SET identity_status = 'revoked', updated_at = :now WHERE agent_id = :agent_id"),
            {"agent_id": agent_id, "now": current},
        )
        _audit(
            connection,
            event_type="agent_revoked",
            outcome="success",
            actor=actor,
            agent_id=agent_id,
            site_id=agent["site_id"],
            metadata={"revoked_active_credentials": max(int(revoked_count or 0), 0)},
            created_at=current,
        )
    return {
        "status": "revoked",
        "agent_id": agent_id,
        "site_id": agent["site_id"],
        "revoked_at": current,
        "revoked_active_credentials": max(int(revoked_count or 0), 0),
    }


def list_agent_identity_audit(*, limit: int = 100) -> list[dict[str, Any]]:
    ensure_database_schema()
    with get_engine().begin() as connection:
        rows = connection.execute(
            text(
                """
                SELECT event_id, event_type, outcome, actor, enrollment_id,
                       credential_id, agent_id, site_id, reason_code,
                       metadata_json, created_at
                FROM endpoint_agent_identity_audit_events
                ORDER BY created_at DESC, event_id DESC
                LIMIT :limit
                """
            ),
            {"limit": max(1, min(limit, 500))},
        ).mappings().all()
    return [dict(row) for row in rows]


def record_authenticated_agent_checkin(
    *,
    context: AgentAuthContext,
    payload: dict[str, Any],
    received_at: datetime,
) -> int:
    if context.mode != "bound-agent" or not all(
        (context.site_id, context.agent_id, context.credential_id)
    ):
        raise AgentAuthenticationRejected("valid agent credential required")
    observed_at = payload.get("observed_at")
    if isinstance(observed_at, str):
        observed_at = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    safe_payload = {
        "schema_version": "oaw.agent-check-in.v1",
        "agent_version": payload.get("agent_version"),
        "platform": payload.get("platform"),
        "architecture": payload.get("architecture"),
        "hostname": payload.get("hostname"),
        "supported_capabilities": payload.get("supported_capabilities", []),
        "inventory_schema_version": payload.get("inventory_schema_version"),
        "health": payload.get("health", "healthy"),
        "source_authenticated": True,
        "source_type": "endpoint-agent",
    }
    ensure_database_schema()
    with get_engine().begin() as connection:
        active_binding = connection.execute(
            text(
                """
                SELECT 1
                FROM endpoint_agent_credentials c
                JOIN agent_enrollments a
                  ON a.agent_id = c.agent_id
                 AND a.site_id = c.site_id
                 AND a.agent_type = c.agent_type
                WHERE c.credential_id = :credential_id
                  AND c.agent_id = :agent_id
                  AND c.site_id = :site_id
                  AND c.agent_type = 'endpoint-agent'
                  AND c.status = 'active'
                  AND (c.expires_at IS NULL OR c.expires_at > :received_at)
                  AND a.identity_status = 'active'
                FOR UPDATE OF c, a
                """
            ),
            {
                "credential_id": context.credential_id,
                "agent_id": context.agent_id,
                "site_id": context.site_id,
                "received_at": received_at,
            },
        ).scalar_one_or_none()
        if active_binding is None:
            raise AgentAuthenticationRejected("valid agent credential required")
        checkin_id = connection.execute(
            text(
                """
                INSERT INTO agent_checkins (
                    site_id, agent_id, version, platform, architecture,
                    hostname, mode, checked_in_at, received_at, payload_json
                ) VALUES (
                    :site_id, :agent_id, :version, :platform, :architecture,
                    :hostname, 'endpoint-inventory', :checked_in_at,
                    :received_at, CAST(:payload_json AS JSONB)
                ) RETURNING id
                """
            ),
            {
                "site_id": context.site_id,
                "agent_id": context.agent_id,
                "version": payload.get("agent_version"),
                "platform": payload.get("platform"),
                "architecture": payload.get("architecture"),
                "hostname": payload.get("hostname"),
                "checked_in_at": observed_at,
                "received_at": received_at,
                "payload_json": json.dumps(safe_payload, sort_keys=True, separators=(",", ":")),
            },
        ).scalar_one()
        updated = connection.execute(
            text(
                """
                UPDATE agent_enrollments
                SET display_name = COALESCE(:hostname, display_name),
                    platform = COALESCE(:platform, platform),
                    architecture = COALESCE(:architecture, architecture),
                    version = COALESCE(:version, version),
                    hostname = COALESCE(:hostname, hostname),
                    mode = 'endpoint-inventory',
                    last_seen_at = GREATEST(COALESCE(last_seen_at, :received_at), :received_at),
                    updated_at = GREATEST(updated_at, :received_at)
                WHERE agent_id = :agent_id AND site_id = :site_id
                  AND agent_type = 'endpoint-agent' AND identity_status = 'active'
                """
            ),
            {
                "agent_id": context.agent_id,
                "site_id": context.site_id,
                "hostname": payload.get("hostname"),
                "platform": payload.get("platform"),
                "architecture": payload.get("architecture"),
                "version": payload.get("agent_version"),
                "received_at": received_at,
            },
        ).rowcount
        if updated != 1:
            raise AgentAuthenticationRejected("valid agent credential required")
        _audit(
            connection,
            event_type="check_in_accepted",
            outcome="success",
            actor="endpoint-agent",
            credential_id=context.credential_id,
            agent_id=context.agent_id,
            site_id=context.site_id,
            created_at=received_at,
        )
    return int(checkin_id)
