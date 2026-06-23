from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.main import agent_check_in, app


def agent_checkin_payload() -> dict[str, object]:
    return {
        "tenant_id": "tenant-example",
        "site_id": "site-local",
        "deployment_id": "11111111-1111-4111-8111-111111111111",
        "agent_id": "22222222-2222-4222-8222-222222222222",
        "agent_version": "0.1.0",
        "hostname": "workstation-01",
        "platform": {
            "os": "windows",
            "architecture": "amd64",
        },
        "check_in_at": "2026-06-17T12:00:00Z",
    }


def post_raw_json(path: str, body: bytes) -> tuple[int, bytes]:
    messages: list[dict[str, object]] = []
    sent_body = False

    async def receive() -> dict[str, object]:
        nonlocal sent_body
        if sent_body:
            return {"type": "http.disconnect"}
        sent_body = True
        return {"type": "http.request", "body": body, "more_body": False}

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
                "path": path,
                "raw_path": path.encode("ascii"),
                "root_path": "",
                "query_string": b"",
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
                "client": ("testclient", 50000),
                "server": ("testserver", 80),
            },
            receive,
            send,
        )

    asyncio.run(call_app())
    status = next(message["status"] for message in messages if message["type"] == "http.response.start")
    response_body = b"".join(
        message.get("body", b"") for message in messages if message["type"] == "http.response.body"
    )
    return int(status), response_body


class AgentCheckInTests(unittest.TestCase):
    def test_valid_checkin_with_site_id_and_agent_id_is_accepted(self) -> None:
        with patch("app.main.record_agent_checkin", return_value=1) as record:
            response = agent_check_in(agent_checkin_payload())

        self.assertEqual(response.status, "accepted")
        self.assertEqual(response.site_id, "site-local")
        self.assertEqual(response.agent_id, "22222222-2222-4222-8222-222222222222")
        self.assertEqual(record.call_args.kwargs["site_id"], "site-local")
        self.assertEqual(record.call_args.kwargs["agent_id"], "22222222-2222-4222-8222-222222222222")

    def test_transitional_checkin_with_site_id_only_is_accepted(self) -> None:
        with patch("app.main.record_agent_checkin", return_value=1) as record:
            response = agent_check_in({"site_id": "site-local"})

        self.assertEqual(response.status, "accepted")
        self.assertEqual(response.site_id, "site-local")
        self.assertIsNone(response.agent_id)
        self.assertIsNone(record.call_args.kwargs["agent_id"])

    def test_malformed_json_is_rejected(self) -> None:
        status, response_body = post_raw_json("/api/v1/agents/check-in", b'{"site_id":')

        self.assertIn(status, {400, 422})
        self.assertIn(b"detail", response_body)

    def test_empty_payload_is_rejected(self) -> None:
        with self.assertRaises(HTTPException) as raised:
            agent_check_in({})

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("must not be empty", raised.exception.detail)

    def test_missing_site_id_is_rejected(self) -> None:
        payload = agent_checkin_payload()
        payload.pop("site_id")

        with self.assertRaises(HTTPException) as raised:
            agent_check_in(payload)

        self.assertEqual(raised.exception.status_code, 400)
        self.assertIn("site_id", raised.exception.detail)

    def test_unsafe_top_level_fields_are_rejected(self) -> None:
        for field in ("command", "args", "additional_args", "password", "hash", "script_content"):
            with self.subTest(field=field):
                payload = agent_checkin_payload()
                payload[field] = "unsafe"

                with self.assertRaises(HTTPException) as raised:
                    agent_check_in(payload)

                self.assertEqual(raised.exception.status_code, 400)
                self.assertIn(field, raised.exception.detail)

    def test_enrollment_token_is_not_returned_or_retained(self) -> None:
        payload = agent_checkin_payload()
        payload["enrollment_token"] = "sensitive-token-value"

        with patch("app.main.record_agent_checkin", return_value=1):
            status, response_body = post_raw_json(
                "/api/v1/agents/check-in",
                json.dumps(payload).encode("utf-8"),
            )

        self.assertEqual(status, 200)
        response = json.loads(response_body)
        self.assertEqual(response["status"], "accepted")
        self.assertNotIn("enrollment_token", response)
        self.assertNotIn("sensitive-token-value", response_body.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
