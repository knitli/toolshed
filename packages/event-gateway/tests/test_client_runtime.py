"""Exercise private credential loading and the no-redirect HTTPS transport."""

import asyncio
import errno
import os
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
import uuid
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from event_gateway.client_runtime import (
    _https_send, _pending_lock, clear_pending_commit, load_cloud_client, load_pending_commit,
    save_pending_commit,
)
from event_gateway.cloud import CloudError
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

    async def test_gateway_helper_renews_each_request_and_after_restart_without_token_file(self):
        settings = {"nodePath": "/absolute/node", "helperPath": "/absolute/knitli-agent.mjs"}
        self.write_config(authMode="gateway", agentTokenProvider=settings)
        config = json.loads(self.config.read_text())
        del config["credentialsFile"]
        self.config.write_text(json.dumps(config))
        self.tokens.unlink()
        provider = AsyncMock(side_effect=["one.jwt.signature", "two.jwt.signature", "three.jwt.signature"])
        with patch("event_gateway.client_runtime.AgentTokenProvider", return_value=provider) as constructor:
            client = load_cloud_client(self.config, self.state)
            first = await client._post_headers("/v1/runtimes/status", b"{}", node_proof=True, before_send=None)
            second = await client._post_headers("/v1/runtimes/status", b"{}", node_proof=True, before_send=None)
            restarted = load_cloud_client(self.config, self.state)
            third = await restarted._post_headers("/v1/runtimes/status", b"{}", node_proof=True, before_send=None)
        self.assertEqual([headers["authorization"] for headers in (first, second, third)],
                         ["Bearer one.jwt.signature", "Bearer two.jwt.signature", "Bearer three.jwt.signature"])
        self.assertTrue(all("cf-access-token" not in headers for headers in (first, second, third)))
        self.assertTrue(all("x-event-node-proof" in headers for headers in (first, second, third)))
        self.assertEqual(provider.await_count, 3)
        self.assertEqual(constructor.call_count, 2)
        constructor.assert_called_with(settings["nodePath"], settings["helperPath"],
                                       origin=config["origin"], agent="codex")
        self.assertFalse(self.tokens.exists())

    async def test_gateway_does_not_fall_back_to_retained_access_credentials(self):
        self.write_config(authMode="gateway", agentTokenProvider={
            "nodePath": "/absolute/node", "helperPath": "/absolute/knitli-agent.mjs",
        })
        provider = AsyncMock(side_effect=OSError("private helper failure"))
        with patch("event_gateway.client_runtime.AgentTokenProvider", return_value=provider):
            client = load_cloud_client(self.config, self.state)
            with self.assertRaisesRegex(CloudError, "^unavailable$"):
                await client._post_headers("/v1/runtimes/status", b"{}", node_proof=True, before_send=None)
        self.assertEqual(json.loads(self.tokens.read_text())["accessToken"], "access-one")

    async def test_explicit_access_mode_preserves_file_credentials(self):
        self.write_config(authMode="access")
        with patch("event_gateway.client_runtime.AgentTokenProvider") as provider:
            client = load_cloud_client(self.config, self.state)
            credentials = await client._credentials()
        self.assertEqual((credentials.access_token, credentials.agent_token), ("access-one", "agent-one"))
        provider.assert_not_called()

    def test_auth_configuration_is_closed_and_requires_explicit_gateway_mode(self):
        valid = {"nodePath": "/absolute/node", "helperPath": "/absolute/knitli-agent.mjs"}
        for changes in (
            {"authMode": "other"}, {"authMode": None}, {"authMode": []},
            {"agentTokenProvider": valid},
            {"authMode": "gateway"},
            {"authMode": "gateway", "agentTokenProvider": None},
            {"authMode": "gateway", "agentTokenProvider": {**valid, "args": []}},
            {"authMode": "gateway", "agentTokenProvider": {**valid, "nodePath": "node"}},
            {"authMode": "gateway", "agentTokenProvider": {**valid, "helperPath": "\x00"}},
        ):
            with self.subTest(changes=changes):
                self.write_config(**changes)
                with self.assertRaisesRegex(SecurityError, "^invalid_cloud_config$"):
                    load_cloud_client(self.config, self.state)

    def test_https_transport_is_gateway_only_and_has_closed_values(self):
        settings = {"nodePath": "/absolute/node", "helperPath": "/absolute/knitli-agent.mjs"}
        for transport in (None, True, 1, [], {}, "warp-local", "https://proxy.example"):
            with self.subTest(mode="gateway", transport=transport):
                self.write_config(authMode="gateway", agentTokenProvider=settings,
                                  httpsTransport=transport)
                with self.assertRaisesRegex(SecurityError, "^invalid_cloud_config$"):
                    load_cloud_client(self.config, self.state)
        for transport in ("direct", "warp-local-proxy"):
            with self.subTest(mode="access", transport=transport):
                self.write_config(authMode="access", httpsTransport=transport)
                with self.assertRaisesRegex(SecurityError, "^invalid_cloud_config$"):
                    load_cloud_client(self.config, self.state)

    async def test_gateway_transport_choice_reaches_cloudclient_send_port(self):
        settings = {"nodePath": "/absolute/node", "helperPath": "/absolute/knitli-agent.mjs"}
        self.write_config(authMode="gateway", agentTokenProvider=settings,
                          httpsTransport="warp-local-proxy")
        provider = AsyncMock(return_value="agent.jwt.signature")
        with (patch("event_gateway.client_runtime.AgentTokenProvider", return_value=provider),
              patch("event_gateway.client_runtime._https_send", new=AsyncMock(
                  return_value=(200, {"content-type": "application/json"}, b"{}"))) as send):
            client = load_cloud_client(self.config, self.state)
            with self.assertRaises(CloudError) as error:
                await client.runtime_status(str(uuid.uuid4()))
        self.assertEqual(error.exception.code, "invalid_response")
        send.assert_awaited_once()
        self.assertEqual(send.await_args.kwargs["https_transport"], "warp-local-proxy")

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
        self.assertIn('noproxy = "*"', process.stdin.text)
        self.assertFalse(any(line.startswith("proxy = ") for line in process.stdin.text.splitlines()))
        self.assertNotIn("--suppress-connect-headers", create.call_args.args)

    async def test_opted_transport_uses_only_fixed_proxy_and_clears_no_proxy(self):
        process = _FakeCurlProcess(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n{}")
        proxy_env = {"HTTP_PROXY": "http://attacker.invalid:81", "https_proxy": "http://attacker.invalid:82",
                     "ALL_PROXY": "http://attacker.invalid:83", "NO_PROXY": "*", "no_proxy": "*"}
        with (patch.dict(os.environ, proxy_env, clear=False),
              patch("event_gateway.client_runtime.asyncio.create_subprocess_exec",
                    new=AsyncMock(return_value=process)) as create):
            result = await _https_send(
                method="POST", url="https://reserved.invalid/v1/runtimes/status",
                headers={}, body=b"{}", timeout=1, max_response_bytes=8192,
                follow_redirects=False, https_transport="warp-local-proxy",
            )
        self.assertEqual(result, (200, {"content-type": "application/json"}, b"{}"))
        self.assertIn('proxy = "http://127.0.0.1:40000"', process.stdin.text)
        self.assertIn('noproxy = ""', process.stdin.text)
        self.assertIn("--suppress-connect-headers", create.call_args.args)
        self.assertNotIn("attacker.invalid", process.stdin.text)
        environment = create.call_args.kwargs["env"]
        self.assertFalse({"HTTP_PROXY", "https_proxy", "ALL_PROXY", "NO_PROXY", "no_proxy"} & set(environment))

    async def test_invalid_transport_fails_before_subprocess(self):
        request = dict(method="POST", url="https://events.example.com/v1/runtimes/attach",
                       headers={}, body=b"{}", timeout=1, max_response_bytes=8192,
                       follow_redirects=False)
        with patch("event_gateway.client_runtime.asyncio.create_subprocess_exec") as create:
            for value in (None, True, 1, [], {}, "proxy"):
                with self.subTest(value=value):
                    with self.assertRaisesRegex(ValueError, "^invalid_transport_request$"):
                        await _https_send(**request, https_transport=value)
            create.assert_not_called()

    async def test_warp_local_proxy_connects_to_fixed_loopback_and_never_falls_back(self):
        requests = []

        async def reject_connect(reader, writer):
            requests.append(await reader.readuntil(b"\r\n\r\n"))
            writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        try:
            server = await asyncio.start_server(reject_connect, "127.0.0.1", 40000)
        except OSError as error:
            if error.errno == errno.EADDRINUSE:
                self.fail("fixed WARP local-proxy port 127.0.0.1:40000 is busy; preserving existing listener")
            raise
        async with server:
            with self.assertRaisesRegex(OSError, "^https_transport_failed$"):
                await _https_send(
                    method="POST", url="https://reserved.invalid/v1/runtimes/status",
                    headers={}, body=b"{}", timeout=1, max_response_bytes=8192,
                    follow_redirects=False, https_transport="warp-local-proxy",
                )
            await asyncio.sleep(0)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].split(b"\r\n", 1)[0], b"CONNECT reserved.invalid:443 HTTP/1.1")

    async def test_warp_local_proxy_success_suppresses_connect_headers(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "reserved.invalid")])
        certificate = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(private_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("reserved.invalid")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
        )
        cert_path = self.root / "ephemeral-test-ca.pem"
        key_path = self.root / "ephemeral-test-key.pem"
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        key_path.chmod(0o600)
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(cert_path, key_path)
        backend_requests = []
        connect_requests = []
        captured_command = []

        async def serve_origin(reader, writer):
            backend_requests.append(await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2))
            body = b'{"ok":true}'
            writer.write(b"HTTP/1.1 201 Created\r\ncontent-type: application/json\r\n"
                         + f"content-length: {len(body)}\r\nconnection: close\r\n\r\n".encode()
                         + body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()

        async def relay(reader, writer):
            try:
                while chunk := await reader.read(16_384):
                    writer.write(chunk)
                    await writer.drain()
            except (ConnectionError, OSError):
                pass
            finally:
                writer.close()

        async def proxy_connect(reader, writer):
            connect_requests.append(await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2))
            upstream_reader, upstream_writer = await asyncio.open_connection(*backend_address)
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            await asyncio.gather(relay(reader, upstream_writer), relay(upstream_reader, writer))

        backend = await asyncio.start_server(serve_origin, "127.0.0.1", 0, ssl=tls_context)
        async with backend:
            backend_address = backend.sockets[0].getsockname()
            try:
                proxy = await asyncio.start_server(proxy_connect, "127.0.0.1", 40000)
            except OSError as error:
                if error.errno == errno.EADDRINUSE:
                    self.fail("fixed WARP local-proxy port 127.0.0.1:40000 is busy; preserving existing listener")
                raise
            async with proxy:
                real_factory = asyncio.create_subprocess_exec

                async def trusted_test_curl(*command, **kwargs):
                    self.assertEqual(command[:2], ("/usr/bin/curl", "-q"))
                    captured_command.extend(command)
                    return await real_factory(*command[:2], "--cacert", str(cert_path),
                                              *command[2:], **kwargs)

                with patch("event_gateway.client_runtime.asyncio.create_subprocess_exec",
                           new=trusted_test_curl):
                    result = await _https_send(
                        method="POST", url="https://reserved.invalid/v1/runtimes/status",
                        headers={"content-type": "application/json"}, body=b"{}", timeout=3,
                        max_response_bytes=8192, follow_redirects=False,
                        https_transport="warp-local-proxy",
                    )
            self.assertEqual(result, (201, {"content-type": "application/json",
                                            "content-length": "11", "connection": "close"},
                                      b'{"ok":true}'))
        command = captured_command
        self.assertEqual(command[0], "/usr/bin/curl")
        self.assertEqual(command[1], "-q")
        self.assertIn("--suppress-connect-headers", command)
        self.assertEqual(len(connect_requests), 1)
        self.assertEqual(connect_requests[0].split(b"\r\n", 1)[0],
                         b"CONNECT reserved.invalid:443 HTTP/1.1")
        self.assertEqual(len(backend_requests), 1)
        self.assertEqual(backend_requests[0].split(b"\r\n", 1)[0],
                         b"POST /v1/runtimes/status HTTP/1.1")

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
