from __future__ import annotations

import os
import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError

from app.hub_contracts import SensorEnrollmentCreateRequest, SensorEnrollmentExchangeRequest
from app.main import (
    app,
    admin_create_sensor_enrollment,
    require_sensor_admin_token,
    sensor_enroll,
)
from app.sensor_identity import (
    ENROLLMENT_TOKEN_PREFIX,
    SENSOR_CREDENTIAL_PREFIX,
    SensorAuthenticationRejected,
    SensorEnrollmentRejected,
    _public_credential,
    _public_enrollment,
    authenticate_sensor_request,
    create_sensor_enrollment,
    exchange_sensor_enrollment,
    issue_enrollment_token,
    issue_sensor_credential,
    parse_token,
    revoke_sensor_enrollment,
    rotate_sensor_credential,
)


class _FakeBegin:
    def __init__(self, connection: Mock) -> None:
        self.connection = connection

    def __enter__(self) -> Mock:
        return self.connection

    def __exit__(self, *_args: object) -> None:
        return None


def _result(*, scalar: object | None = None, row: dict[str, object] | None = None) -> Mock:
    result = Mock()
    result.scalar_one_or_none.return_value = scalar
    result.mappings.return_value.one.return_value = row
    result.mappings.return_value.one_or_none.return_value = row
    return result


def post_chunked_enrollment(body: bytes) -> int:
    messages: list[dict[str, object]] = []
    chunks = [body[:5000], body[5000:]]

    async def receive() -> dict[str, object]:
        if chunks:
            chunk = chunks.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": bool(chunks)}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, object]) -> None:
        messages.append(message)

    async def call_app() -> None:
        await app(
            {
                "type": "http",
                "asgi": {"version": "3.0", "spec_version": "2.3"},
                "http_version": "1.1",
                "method": "POST",
                "scheme": "http",
                "path": "/api/v1/sensors/enroll",
                "raw_path": b"/api/v1/sensors/enroll",
                "root_path": "",
                "query_string": b"",
                "headers": [(b"content-type", b"application/json")],
                "client": ("body-limit-test", 50000),
                "server": ("testserver", 80),
            },
            receive,
            send,
        )

    asyncio.run(call_app())
    return next(message["status"] for message in messages if message["type"] == "http.response.start")


class SensorIdentityTests(unittest.TestCase):
    def test_tokens_have_distinct_prefixes_256_bit_secrets_and_unique_values(self) -> None:
        enrollments = {issue_enrollment_token().raw for _ in range(64)}
        credentials = {issue_sensor_credential().raw for _ in range(64)}

        self.assertEqual(len(enrollments), 64)
        self.assertEqual(len(credentials), 64)
        self.assertTrue(all(value.startswith(f"{ENROLLMENT_TOKEN_PREFIX}.") for value in enrollments))
        self.assertTrue(all(value.startswith(f"{SENSOR_CREDENTIAL_PREFIX}.") for value in credentials))
        self.assertTrue(all(len(value.rsplit(".", 1)[1]) == 43 for value in enrollments | credentials))
        self.assertTrue(enrollments.isdisjoint(credentials))

    def test_malformed_tokens_are_rejected_without_echoing_values(self) -> None:
        raw = "oaw_sensor_v1.bad.submitted-secret"
        self.assertIsNone(parse_token(raw, SENSOR_CREDENTIAL_PREFIX))
        with (
            patch.dict(os.environ, {"OPENASSETWATCH_COLLECTOR_TOKEN": raw}, clear=False),
            self.assertRaises(SensorAuthenticationRejected) as raised,
        ):
            authenticate_sensor_request(
                provided_token=raw,
                claimed_site_id="site-a",
                claimed_sensor_id="sensor-a",
                claimed_sensor_type="passive-network-sensor",
            )
        self.assertNotIn(raw, str(raised.exception))

    def test_shared_development_token_requires_explicit_configuration_and_constant_time_compare(self) -> None:
        with patch.dict(os.environ, {"OPENASSETWATCH_COLLECTOR_TOKEN": ""}, clear=False):
            with self.assertRaises(SensorAuthenticationRejected):
                authenticate_sensor_request(
                    provided_token="development-only",
                    claimed_site_id="site-a",
                    claimed_sensor_id="sensor-a",
                    claimed_sensor_type="passive-network-sensor",
                )

        with (
            patch.dict(os.environ, {"OPENASSETWATCH_COLLECTOR_TOKEN": "development-only"}, clear=False),
            patch("app.sensor_identity.secrets.compare_digest", return_value=True) as compare,
        ):
            context = authenticate_sensor_request(
                provided_token="development-only",
                claimed_site_id="site-a",
                claimed_sensor_id="sensor-a",
                claimed_sensor_type="passive-network-sensor",
            )
        self.assertEqual(context.mode, "development-shared")
        compare.assert_called_once_with("development-only", "development-only")

    def test_bound_credential_updates_last_used_without_allowing_identity_substitution(self) -> None:
        now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
        material = issue_sensor_credential()
        row = {
            "credential_id": "scred_" + "1" * 32,
            "sensor_id": "sensor-a",
            "site_id": "site-a",
            "sensor_type": "passive-network-sensor",
            "credential_digest": material.digest,
            "status": "active",
            "expires_at": None,
        }
        connection = Mock()
        connection.execute.side_effect = [_result(row=row), Mock(), Mock()]
        engine = Mock()
        engine.begin.return_value = _FakeBegin(connection)
        with (
            patch("app.sensor_identity.ensure_database_schema"),
            patch("app.sensor_identity.get_engine", return_value=engine),
        ):
            context = authenticate_sensor_request(
                provided_token=material.raw,
                claimed_site_id="site-a",
                claimed_sensor_id="sensor-a",
                claimed_sensor_type="passive-network-sensor",
                now=now,
            )
        self.assertEqual(context.mode, "bound-sensor")
        last_used_sql = str(connection.execute.call_args_list[1].args[0])
        self.assertIn("GREATEST", last_used_sql)

        mismatch_connection = Mock()
        mismatch_connection.execute.side_effect = [_result(row=row), Mock()]
        mismatch_engine = Mock()
        mismatch_engine.begin.return_value = _FakeBegin(mismatch_connection)
        with (
            patch("app.sensor_identity.ensure_database_schema"),
            patch("app.sensor_identity.get_engine", return_value=mismatch_engine),
            self.assertRaises(SensorAuthenticationRejected) as raised,
        ):
            authenticate_sensor_request(
                provided_token=material.raw,
                claimed_site_id="site-b",
                claimed_sensor_id="sensor-a",
                claimed_sensor_type="passive-network-sensor",
                now=now,
            )
        self.assertEqual(str(raised.exception), "valid sensor credential required")
        self.assertNotIn(material.raw, str(mismatch_connection.execute.call_args_list))

    def test_expired_bound_credential_is_retired_and_generically_rejected(self) -> None:
        now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
        material = issue_sensor_credential()
        row = {
            "credential_id": "scred_" + "2" * 32,
            "sensor_id": "sensor-a",
            "site_id": "site-a",
            "sensor_type": "passive-network-sensor",
            "credential_digest": material.digest,
            "status": "active",
            "expires_at": now - timedelta(seconds=1),
        }
        connection = Mock()
        connection.execute.side_effect = [_result(row=row), Mock(), Mock()]
        engine = Mock()
        engine.begin.return_value = _FakeBegin(connection)
        with (
            patch("app.sensor_identity.ensure_database_schema"),
            patch("app.sensor_identity.get_engine", return_value=engine),
            self.assertRaises(SensorAuthenticationRejected) as raised,
        ):
            authenticate_sensor_request(
                provided_token=material.raw,
                claimed_site_id="site-a",
                claimed_sensor_id="sensor-a",
                claimed_sensor_type="passive-network-sensor",
                now=now,
            )
        self.assertEqual(str(raised.exception), "valid sensor credential required")
        expired_sql = str(connection.execute.call_args_list[1].args[0])
        self.assertIn("status = 'expired'", expired_sql)

    def test_database_receives_only_digest_and_non_secret_lookup(self) -> None:
        now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
        stored = {
            "enrollment_id": "senr_" + "a" * 32,
            "site_id": "site-a",
            "requested_sensor_id": "sensor-a",
            "requested_sensor_name": "Sensor A",
            "sensor_type": "passive-network-sensor",
            "status": "pending",
            "failed_attempts": 0,
            "max_attempts": 10,
            "created_at": now,
            "expires_at": now + timedelta(hours=1),
            "used_at": None,
            "revoked_at": None,
            "issued_sensor_id": None,
        }
        connection = Mock()
        connection.execute.side_effect = [
            _result(scalar=1),
            _result(row=stored),
            Mock(),
        ]
        engine = Mock()
        engine.begin.return_value = _FakeBegin(connection)
        with (
            patch("app.sensor_identity.ensure_database_schema"),
            patch("app.sensor_identity.get_engine", return_value=engine),
        ):
            response = create_sensor_enrollment(
                site_id="site-a",
                requested_sensor_id="sensor-a",
                requested_sensor_name="Sensor A",
                sensor_type="passive-network-sensor",
                now=now,
            )

        raw = response["enrollment_token"]
        insert_parameters = connection.execute.call_args_list[1].args[1]
        self.assertNotIn(raw, str(insert_parameters))
        self.assertEqual(len(insert_parameters["token_digest"]), 64)
        self.assertEqual(len(insert_parameters["token_lookup_id"]), 32)
        self.assertNotEqual(insert_parameters["token_digest"], raw)

    def test_exchange_database_failure_rolls_back_without_half_enrollment(self) -> None:
        now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
        token = issue_enrollment_token()
        enrollment = {
            "enrollment_id": "senr_" + "d" * 32,
            "site_id": "site-a",
            "requested_sensor_id": "sensor-a",
            "requested_sensor_name": "Sensor A",
            "sensor_type": "passive-network-sensor",
            "token_digest": token.digest,
            "status": "pending",
            "expires_at": now + timedelta(hours=1),
        }
        connection = Mock()
        no_existing = _result(row=None)
        no_active = Mock()
        no_active.scalars.return_value.all.return_value = []
        connection.execute.side_effect = [
            _result(row=enrollment),
            no_existing,
            no_active,
            SQLAlchemyError("synthetic transaction failure"),
        ]
        transaction = Mock()
        connection.begin.return_value = transaction
        engine = Mock()
        engine.connect.return_value = connection
        with (
            patch("app.sensor_identity.ensure_database_schema"),
            patch("app.sensor_identity.get_engine", return_value=engine),
            self.assertRaises(SQLAlchemyError),
        ):
            exchange_sensor_enrollment(
                enrollment_token=token.raw,
                sensor_id="sensor-a",
                sensor_name="Sensor A",
                sensor_type="passive-network-sensor",
                sensor_version="test",
                platform="linux",
                now=now,
            )
        transaction.rollback.assert_called_once()
        transaction.commit.assert_not_called()
        connection.close.assert_called()

    def test_exchange_locks_enrollment_commits_once_and_never_persists_raw_secrets(self) -> None:
        now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
        token = issue_enrollment_token()
        enrollment = {
            "enrollment_id": "senr_" + "e" * 32,
            "site_id": "site-a",
            "requested_sensor_id": "sensor-a",
            "requested_sensor_name": "Sensor A",
            "sensor_type": "passive-network-sensor",
            "token_digest": token.digest,
            "status": "pending",
            "expires_at": now + timedelta(hours=1),
        }
        no_active = Mock()
        no_active.scalars.return_value.all.return_value = []
        connection = Mock()
        connection.execute.side_effect = [
            _result(row=enrollment),
            _result(row=None),
            no_active,
            Mock(),
            Mock(),
            Mock(),
            Mock(),
        ]
        transaction = Mock()
        connection.begin.return_value = transaction
        engine = Mock()
        engine.connect.return_value = connection
        with (
            patch("app.sensor_identity.ensure_database_schema"),
            patch("app.sensor_identity.get_engine", return_value=engine),
        ):
            response = exchange_sensor_enrollment(
                enrollment_token=token.raw,
                sensor_id="sensor-a",
                sensor_name="Sensor A",
                sensor_type="passive-network-sensor",
                sensor_version="test",
                platform="linux",
                now=now,
            )

        self.assertEqual(response["status"], "enrolled")
        self.assertTrue(response["sensor_credential"].startswith(f"{SENSOR_CREDENTIAL_PREFIX}."))
        self.assertIn("FOR UPDATE", str(connection.execute.call_args_list[0].args[0]))
        transaction.commit.assert_called_once()
        transaction.rollback.assert_not_called()
        persisted_calls = str(connection.execute.call_args_list)
        self.assertNotIn(token.raw, persisted_calls)
        self.assertNotIn(response["sensor_credential"], persisted_calls)

    def test_used_enrollment_replay_is_generic_and_audited_without_secret(self) -> None:
        now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
        token = issue_enrollment_token()
        enrollment = {
            "enrollment_id": "senr_" + "f" * 32,
            "site_id": "site-a",
            "requested_sensor_id": "sensor-a",
            "requested_sensor_name": "Sensor A",
            "sensor_type": "passive-network-sensor",
            "token_digest": token.digest,
            "status": "used",
            "expires_at": now + timedelta(hours=1),
            "issued_sensor_id": "sensor-a",
        }
        exchange_connection = Mock()
        exchange_connection.execute.return_value = _result(row=enrollment)
        transaction = Mock()
        exchange_connection.begin.return_value = transaction
        audit_connection = Mock()
        engine = Mock()
        engine.connect.return_value = exchange_connection
        engine.begin.return_value = _FakeBegin(audit_connection)
        with (
            patch("app.sensor_identity.ensure_database_schema"),
            patch("app.sensor_identity.get_engine", return_value=engine),
            self.assertRaises(SensorEnrollmentRejected) as raised,
        ):
            exchange_sensor_enrollment(
                enrollment_token=token.raw,
                sensor_id="sensor-a",
                sensor_name="Sensor A",
                sensor_type="passive-network-sensor",
                sensor_version="test",
                platform="linux",
                now=now,
            )

        self.assertEqual(str(raised.exception), "sensor enrollment failed")
        transaction.rollback.assert_called_once()
        audit_parameters = audit_connection.execute.call_args.args[1]
        self.assertEqual(audit_parameters["event_type"], "enrollment_replay_rejected")
        self.assertEqual(audit_parameters["reason_code"], "already_used")
        self.assertNotIn(token.raw, str(audit_connection.execute.call_args_list))

    def test_rotation_retires_previous_credential_transactionally(self) -> None:
        now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
        sensor = {
            "agent_id": "sensor-a",
            "site_id": "site-a",
            "agent_type": "network-sensor",
            "identity_status": "active",
        }
        predecessor = {
            "credential_id": "scred_" + "7" * 32,
            "sensor_id": "sensor-a",
            "site_id": "site-a",
            "sensor_type": "passive-network-sensor",
        }
        active_result = Mock()
        active_result.mappings.return_value.all.return_value = [predecessor]
        connection = Mock()
        connection.execute.side_effect = [
            _result(row=sensor),
            active_result,
            Mock(),
            Mock(),
            Mock(),
        ]
        engine = Mock()
        engine.begin.return_value = _FakeBegin(connection)
        with (
            patch("app.sensor_identity.ensure_database_schema"),
            patch("app.sensor_identity.get_engine", return_value=engine),
        ):
            response = rotate_sensor_credential("sensor-a", now=now)

        self.assertEqual(response["status"], "rotated")
        self.assertTrue(response["sensor_credential"].startswith(f"{SENSOR_CREDENTIAL_PREFIX}."))
        self.assertIn("status = 'rotated'", str(connection.execute.call_args_list[3].args[0]))
        self.assertIn("replacement_credential_id", str(connection.execute.call_args_list[3].args[0]))
        self.assertNotIn(response["sensor_credential"], str(connection.execute.call_args_list))

    def test_unused_enrollment_revocation_is_atomic_and_secret_free(self) -> None:
        now = datetime(2026, 7, 29, 12, 0, tzinfo=timezone.utc)
        pending = {
            "enrollment_id": "senr_" + "8" * 32,
            "site_id": "site-a",
            "requested_sensor_id": "sensor-a",
            "requested_sensor_name": "Sensor A",
            "sensor_type": "passive-network-sensor",
            "status": "pending",
            "failed_attempts": 0,
            "max_attempts": 10,
            "created_at": now,
            "expires_at": now + timedelta(hours=1),
            "used_at": None,
            "revoked_at": None,
            "issued_sensor_id": None,
            "token_lookup_id": "9" * 32,
            "token_digest": "a" * 64,
        }
        revoked = dict(pending, status="revoked", revoked_at=now)
        connection = Mock()
        connection.execute.side_effect = [
            _result(row=pending),
            _result(row=revoked),
            Mock(),
        ]
        engine = Mock()
        engine.begin.return_value = _FakeBegin(connection)
        with (
            patch("app.sensor_identity.ensure_database_schema"),
            patch("app.sensor_identity.get_engine", return_value=engine),
        ):
            response = revoke_sensor_enrollment(pending["enrollment_id"], now=now)

        self.assertEqual(response["status"], "revoked")
        self.assertNotIn("token_lookup_id", response)
        self.assertNotIn("token_digest", response)
        self.assertIn("FOR UPDATE", str(connection.execute.call_args_list[0].args[0]))

    def test_public_credential_projection_never_contains_secret_material(self) -> None:
        credential = issue_sensor_credential()
        projected = _public_credential(
            {
                "credential_id": "scred_" + "6" * 32,
                "sensor_id": "sensor-a",
                "site_id": "site-a",
                "sensor_type": "passive-network-sensor",
                "token_lookup_id": credential.lookup_id,
                "credential_digest": credential.digest,
                "status": "active",
                "created_at": datetime.now(timezone.utc),
                "last_used_at": None,
                "rotated_at": None,
                "revoked_at": None,
                "expires_at": None,
                "predecessor_credential_id": None,
                "replacement_credential_id": None,
            }
        )
        self.assertNotIn("token_lookup_id", projected)
        self.assertNotIn("credential_digest", projected)
        self.assertNotIn(credential.raw, str(projected))

    def test_public_enrollment_projection_never_contains_secret_material(self) -> None:
        token = issue_enrollment_token()
        projected = _public_enrollment(
            {
                "enrollment_id": "senr_" + "b" * 32,
                "site_id": "site-a",
                "requested_sensor_id": None,
                "requested_sensor_name": None,
                "sensor_type": "passive-network-sensor",
                "token_lookup_id": token.lookup_id,
                "token_digest": token.digest,
                "status": "pending",
                "failed_attempts": 0,
                "max_attempts": 10,
                "created_at": datetime.now(timezone.utc),
                "expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
                "used_at": None,
                "revoked_at": None,
                "issued_sensor_id": None,
            }
        )
        self.assertNotIn("token_lookup_id", projected)
        self.assertNotIn("token_digest", projected)
        self.assertNotIn(token.raw, str(projected))

    def test_admin_issuance_fails_closed_without_configured_admin_token(self) -> None:
        with patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": ""}, clear=False):
            with self.assertRaises(HTTPException) as raised:
                require_sensor_admin_token(None)
        self.assertEqual(raised.exception.status_code, 503)

    def test_admin_create_requires_authorization_and_returns_token_once(self) -> None:
        now = datetime.now(timezone.utc)
        created = {
            "enrollment_id": "senr_" + "c" * 32,
            "site_id": "site-a",
            "requested_sensor_id": "sensor-a",
            "requested_sensor_name": "Sensor A",
            "sensor_type": "passive-network-sensor",
            "status": "pending",
            "failed_attempts": 0,
            "max_attempts": 10,
            "created_at": now,
            "expires_at": now + timedelta(hours=1),
            "used_at": None,
            "revoked_at": None,
            "issued_sensor_id": None,
            "enrollment_token": issue_enrollment_token().raw,
        }
        payload = SensorEnrollmentCreateRequest(
            site_id="site-a",
            requested_sensor_id="sensor-a",
            requested_sensor_name="Sensor A",
        )
        with (
            patch.dict(os.environ, {"OPENASSETWATCH_ADMIN_TOKEN": "admin-only"}, clear=False),
            patch("app.main.create_sensor_enrollment", return_value=created),
        ):
            with self.assertRaises(HTTPException) as raised:
                admin_create_sensor_enrollment(payload, admin_token="wrong")
            response = admin_create_sensor_enrollment(payload, admin_token="admin-only")
        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(response["enrollment_token"], created["enrollment_token"])

    def test_exchange_contract_is_bounded_and_failure_is_generic(self) -> None:
        token = issue_enrollment_token().raw
        payload = SensorEnrollmentExchangeRequest(
            enrollment_token=token,
            sensor_id="sensor-a",
            sensor_name="Sensor A",
        )
        self.assertNotIn(token, repr(payload))
        request = Mock()
        request.client = Mock(host="test-source-generic")
        with patch(
            "app.main.exchange_sensor_enrollment",
            side_effect=SensorEnrollmentRejected("internal-specific-reason"),
        ):
            with self.assertRaises(HTTPException) as raised:
                sensor_enroll(payload, request, content_length="256")
        self.assertEqual(raised.exception.status_code, 401)
        self.assertEqual(raised.exception.detail, "sensor enrollment failed")
        self.assertNotIn(token, str(raised.exception))

    def test_chunked_enrollment_body_is_rejected_at_eight_kib(self) -> None:
        body = b'{"enrollment_token":"' + (b"x" * 9000) + b'"}'
        self.assertEqual(post_chunked_enrollment(body), 413)


if __name__ == "__main__":
    unittest.main()
