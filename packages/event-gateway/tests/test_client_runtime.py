"""Exercise private credential loading and the no-redirect HTTPS transport."""

import asyncio
import errno
import os
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
import uuid

from event_gateway.client_runtime import (
    _https_send, _pending_lock, clear_pending_commit, load_cloud_client, load_pending_commit,
    save_pending_commit,
)
from event_gateway.security import SecurityError, load_or_create_signing_key


class ClientRuntimeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.state = self.root / "state"
        load_or_create_signing_key(self.state / "node-key.pem")
        self.config = self.root / "cloud.json"
        self.tokens = self.root / "credentials.json"
        self.write_tokens("access-one", "agent-one")
        self.write_config()

    def write_config(self, **changes):
        value = {
            "version": 1, "origin": "https://events.example.com", "principal": "adam@knitli.com",
            "agent": "codex", "nodeId": str(uuid.uuid4()), "nodeGeneration": 1,
            "credentialsFile": self.tokens.name,
        }
        value.update(changes)
        self.config.write_text(json.dumps(value))
        self.config.chmod(0o600)

    def write_tokens(self, access, agent):
        self.tokens.write_text(json.dumps({"accessToken": access, "agentToken": agent}))
        self.tokens.chmod(0o600)

    async def test_identity_is_immutable_and_credentials_are_read_fresh(self):
        client = load_cloud_client(self.config, self.state)
        first = await client._credentials()
        self.assertEqual((first.access_token, first.agent_token), ("access-one", "agent-one"))
        self.write_tokens("access-two", "agent-two")
        second = await client._credentials()
        self.assertEqual((second.access_token, second.agent_token), ("access-two", "agent-two"))
        self.assertEqual(client.origin, "https://events.example.com")
        self.assertNotIn("access-two", repr(second))

    async def test_config_and_tokens_require_closed_owner_only_files(self):
        for changes in ({"extra": True}, {"version": True}, {"version": False},
                        {"credentialsFile": "../tokens.json"},
                        {"credentialsFile": ".."}):
            with self.subTest(changes=changes):
                self.write_config(**changes)
                with self.assertRaisesRegex(SecurityError, "^invalid_cloud_config$"):
                    load_cloud_client(self.config, self.state)
        self.write_config()
        self.config.chmod(0o644)
        with self.assertRaisesRegex(SecurityError, "^invalid_cloud_config$"):
            load_cloud_client(self.config, self.state)
        self.config.chmod(0o600)
        self.tokens.chmod(0o644)
        client = load_cloud_client(self.config, self.state)
        with self.assertRaisesRegex(SecurityError, "^invalid_credentials$"):
            await client._credentials()

    async def test_missing_node_key_fails_without_creating_one(self):
        state = self.root / "unenrolled"
        with self.assertRaisesRegex(SecurityError, "^invalid_signing_key$"):
            load_cloud_client(self.config, state)
        self.assertFalse((state / "node-key.pem").exists())

    async def test_transport_numeric_options_reject_booleans_before_spawn(self):
        request = dict(method="POST", url="https://events.example.com/v1/runtimes/attach",
                       headers={}, body=b"{}", timeout=1, max_response_bytes=8192,
                       follow_redirects=False)
        with patch("event_gateway.client_runtime.asyncio.create_subprocess_exec") as create:
            for field in ("timeout", "max_response_bytes"):
                for value in (True, False):
                    with self.subTest(field=field, value=value):
                        with self.assertRaisesRegex(ValueError, "invalid_transport_request"):
                            await _https_send(**{**request, field: value})
            create.assert_not_called()

    async def test_https_transport_uses_private_config_and_no_redirects(self):
        process = _FakeCurlProcess(b"HTTP/2 302 Found\r\ncontent-type: application/json\r\nlocation: /elsewhere\r\n\r\nredirect body")
        with patch("event_gateway.client_runtime.asyncio.create_subprocess_exec",
                   new=AsyncMock(return_value=process)) as create:
            result = await _https_send(
                method="POST", url="https://events.example.com/v1/runtimes/attach",
                headers={"content-type": "application/json", "authorization": "Bearer agent-secret",
                         "cf-access-token": "access-secret"}, body=b"{}", timeout=1,
                max_response_bytes=8192, follow_redirects=False,
            )
        self.assertEqual(result, (302, {"content-type": "application/json", "location": "/elsewhere"}, b"redirect body"))
        command = create.call_args.args
        self.assertEqual(command[0], "/usr/bin/curl")
        self.assertIn("-q", command[1:3])
        self.assertNotIn("-L", command)
        self.assertNotIn("--location", command)
        self.assertNotIn("agent-secret", " ".join(command))
        self.assertNotIn("access-secret", " ".join(command))
        self.assertIn("agent-secret", process.stdin.text)
        self.assertIn("access-secret", process.stdin.text)

    async def test_https_transport_kills_owned_process_on_deadline_or_oversized_body(self):
        blocked = _FakeCurlProcess(block=True)
        with patch("event_gateway.client_runtime.asyncio.create_subprocess_exec",
                   new=AsyncMock(return_value=blocked)):
            with self.assertRaisesRegex(TimeoutError, "^https_transport_timeout$"):
                await _https_send(
                    method="POST", url="https://events.example.com/v1/runtimes/attach",
                    headers={}, body=b"{}", timeout=0.01, max_response_bytes=8192,
                    follow_redirects=False,
                )
        self.assertTrue(blocked.killed)

        oversized = _FakeCurlProcess(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n" + b"x" * 8193)
        with patch("event_gateway.client_runtime.asyncio.create_subprocess_exec",
                   new=AsyncMock(return_value=oversized)):
            with self.assertRaisesRegex(ValueError, "^https_response_too_large$"):
                await _https_send(
                    method="POST", url="https://events.example.com/v1/runtimes/attach",
                    headers={}, body=b"{}", timeout=1, max_response_bytes=8192,
                    follow_redirects=False,
                )
        self.assertTrue(oversized.killed)

    async def test_https_transport_kills_and_reaps_owned_process_on_cancellation(self):
        blocked = _FakeCurlProcess(block=True)
        with patch("event_gateway.client_runtime.asyncio.create_subprocess_exec",
                   new=AsyncMock(return_value=blocked)):
            task = asyncio.create_task(_https_send(
                method="POST", url="https://events.example.com/v1/runtimes/attach",
                headers={}, body=b"{}", timeout=5, max_response_bytes=8192,
                follow_redirects=False,
            ))
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertTrue(blocked.killed)
        self.assertEqual(blocked.returncode, -9)

    def test_pending_lock_closes_real_descriptor_on_contention_and_stat_failure(self):
        opened = []
        real_open = os.open
        real_fstat = os.fstat

        def capture_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.append(fd)
            return fd

        owner = _pending_lock(self.state)
        self.addCleanup(os.close, owner)
        self.assertTrue(real_fstat(owner))
        for failure, code in (("contention", "pending_commit_busy"),
                              ("fstat", "invalid_pending_commit")):
            with self.subTest(failure=failure):
                with patch("event_gateway.client_runtime.os.open", side_effect=capture_open):
                    if failure == "fstat":
                        with (patch("event_gateway.client_runtime.os.fstat", side_effect=OSError("stat failed")),
                              self.assertRaisesRegex(SecurityError, "^" + code + "$")):
                            _pending_lock(self.state)
                    else:
                        with self.assertRaisesRegex(SecurityError, "^" + code + "$"):
                            _pending_lock(self.state)
                try:
                    with self.assertRaises(OSError) as error:
                        real_fstat(opened[-1])
                    self.assertEqual(error.exception.errno, errno.EBADF)
                finally:
                    try:
                        os.close(opened[-1])
                    except OSError as error:
                        self.assertEqual(error.errno, errno.EBADF)
                self.assertTrue(real_fstat(owner))

    async def test_pending_commit_is_private_exact_and_never_replaced(self):
        session_id = str(uuid.uuid4())
        artifact = {
            "version": 1, "operation": "attach", "sessionId": session_id,
            "cloudIdentity": {"origin": "https://events.example.com", "principal": "adam@knitli.com",
                              "agent": "codex", "nodeId": str(uuid.uuid4()), "nodeGeneration": 1},
            "intent": {"operation": "attach"},
            "challenge": {"challengeId": str(uuid.uuid4()), "issuedAt": "2026-10-09T12:00:00.000Z",
                          "expiresAt": "2026-10-09T12:00:30.000Z"},
            "evidence": {"observedAt": "2026-10-09T12:00:00.100Z", "witness": {"sequence": 1}},
            "bodyB64": "e30=", "safeExpiryAt": "2026-10-09T12:02:00.000Z",
        }
        for version in (True, False):
            with self.subTest(version=version):
                with self.assertRaisesRegex(SecurityError, "^invalid_pending_commit$"):
                    save_pending_commit(self.state, "attach", session_id, {**artifact, "version": version})
        path = save_pending_commit(self.state, "attach", session_id, artifact)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(load_pending_commit(self.state, "attach", session_id), artifact)
        with self.assertRaisesRegex(SecurityError, "^pending_commit_exists$"):
            save_pending_commit(self.state, "attach", session_id, {**artifact, "bodyB64": "eyJ9"})
        self.assertEqual(load_pending_commit(self.state, "attach", session_id), artifact)
        clear_pending_commit(self.state, "attach", session_id, expected=artifact)
        self.assertIsNone(load_pending_commit(self.state, "attach", session_id))


class _FakeWriter:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, value):
        self.data.extend(value)

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None

    @property
    def text(self):
        return self.data.decode("utf-8")


class _FakeReader:
    def __init__(self, process, response):
        self.process = process
        self.response = response

    async def read(self, limit):
        if self.process.block:
            await self.process.killed_event.wait()
            return b""
        if not self.response:
            self.process.returncode = 0
            return b""
        chunk, self.response = self.response[:limit], self.response[limit:]
        return chunk


class _FakeCurlProcess:
    def __init__(self, response=b"", *, block=False):
        self.stdin = _FakeWriter()
        self.block = block
        self.killed = False
        self.killed_event = asyncio.Event()
        self.stdout = _FakeReader(self, response)
        self.returncode = None

    async def wait(self):
        if self.returncode is None:
            await self.killed_event.wait()
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.killed_event.set()


if __name__ == "__main__":
    unittest.main()
