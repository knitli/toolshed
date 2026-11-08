"""Mock-only owner setup and assigned-stock DTO validation."""
import asyncio
import copy
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid
from contextlib import redirect_stdout

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway import cli, daemon
from event_gateway.cloud import CloudClient, CloudError, Credentials, _iso
from event_gateway.gateway import Gateway
from event_gateway import messaging_protocol_v2
from event_gateway.protocol import derive_delivery_id
from event_gateway.security import sign
from event_gateway.store import Store, StoreError


RUNTIME = "12345678-1234-4234-8234-123456789abc"
CONVERSATION = "22345678-1234-4234-8234-123456789abc"
NEW_CONVERSATION = "42345678-1234-4234-8234-123456789abc"
NODE = "32345678-1234-4234-8234-123456789abc"
PROFILE = {"profile": "assigned_stock_client", "client": "codex",
           "conversationId": CONVERSATION}
NOW = 1_791_201_630


def response(status="attached", **changes):
    return {
        "status": status, "runtimeId": RUNTIME, "runtimeProfile": PROFILE,
        "nodeId": NODE, "nodeGeneration": 2, "runtimeGeneration": 1,
        "attachmentGeneration": 1, "leaseUntil": "2026-11-01T00:00:00.000Z",
        **changes,
    }


class StockControlTests(unittest.IsolatedAsyncioTestCase):
    def test_cloud_confirmed_stock_reattach_replaces_stale_messaging_mapping(self):
        now = NOW
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state"
            old = self._messaging_mapping(now + 30)
            with Store(state, clock=lambda: now) as store:
                store.put_messaging_attachment(old)
                store.detach(RUNTIME)

            class FakeCloud:
                principal, agent = "owner@example.com", "codex"
                node_id, node_generation = NODE, 2

                async def assigned_stock(self, request):
                    self.assert_request = request
                    return response(runtimeGeneration=2, attachmentGeneration=2,
                                    runtimeProfile={**PROFILE, "conversationId": NEW_CONVERSATION},
                                    leaseUntil=_iso(now + 120))

            output = io.StringIO()
            with patch.object(cli, "load_cloud_client", return_value=FakeCloud()), \
                    patch.object(cli, "Store", side_effect=lambda path: Store(
                        path, clock=lambda: now)), \
                    redirect_stdout(output):
                code = cli.main([
                    "--state-dir", str(state), "stock-control", "attach",
                    "--runtime-id", RUNTIME, "--conversation-id", NEW_CONVERSATION,
                    "--cloud-config", str(state / "cloud.json"),
                    "--expected-runtime-generation", "1",
                    "--expected-attachment-generation", "1",
                ])
            self.assertEqual(code, 0, output.getvalue())
            with Store(state, clock=lambda: now) as store:
                mapping = store.get_attachment(RUNTIME)
            self.assertEqual((mapping["runtimeGeneration"], mapping["attachmentGeneration"]), (2, 2))
            self.assertNotIn("routingGeneration", mapping)

    def test_plain_stock_reattach_keeps_existing_explicit_generation_path(self):
        now = NOW
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state"
            with Store(state, clock=lambda: now) as store:
                store.put_attachment(self._stock_mapping(now + 30))

            class FakeCloud:
                principal, agent = "owner@example.com", "codex"

                async def assigned_stock(self, _request):
                    return response(runtimeGeneration=2, attachmentGeneration=2,
                                    runtimeProfile={**PROFILE, "conversationId": NEW_CONVERSATION},
                                    leaseUntil=_iso(now + 120))

            output = io.StringIO()
            with patch.object(cli, "load_cloud_client", return_value=FakeCloud()), \
                    patch.object(cli, "Store", side_effect=lambda path: Store(
                        path, clock=lambda: now)), redirect_stdout(output):
                code = cli.main([
                    "--state-dir", str(state), "stock-control", "attach",
                    "--runtime-id", RUNTIME, "--conversation-id", NEW_CONVERSATION,
                    "--cloud-config", str(state / "cloud.json"),
                    "--expected-runtime-generation", "1",
                    "--expected-attachment-generation", "1",
                ])
            self.assertEqual(code, 0, output.getvalue())
            with Store(state, clock=lambda: now) as store:
                current = store.get_attachment(RUNTIME)
            self.assertEqual(current["runtimeProfile"]["conversationId"], NEW_CONVERSATION)

    def test_explicit_stock_attach_without_local_mapping_remains_supported(self):
        now = NOW
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state"

            class FakeCloud:
                principal, agent = "owner@example.com", "codex"

                async def assigned_stock(self, _request):
                    return response(runtimeGeneration=2, attachmentGeneration=2,
                                    runtimeProfile={**PROFILE, "conversationId": NEW_CONVERSATION},
                                    leaseUntil=_iso(now + 120))

            output = io.StringIO()
            with patch.object(cli, "load_cloud_client", return_value=FakeCloud()), \
                    patch.object(cli, "Store", side_effect=lambda path: Store(
                        path, clock=lambda: now)), redirect_stdout(output):
                code = cli.main([
                    "--state-dir", str(state), "stock-control", "attach",
                    "--runtime-id", RUNTIME, "--conversation-id", NEW_CONVERSATION,
                    "--cloud-config", str(state / "cloud.json"),
                    "--expected-runtime-generation", "1",
                    "--expected-attachment-generation", "1",
                ])
            self.assertEqual(code, 0, output.getvalue())

    def test_active_messaging_mapping_is_not_reassigned_by_stock_attach(self):
        now = NOW
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state"
            original = self._messaging_mapping(now + 30)
            with Store(state, clock=lambda: now) as store:
                store.put_messaging_attachment(original)

            class FakeCloud:
                principal, agent = "owner@example.com", "codex"
                called = False

                async def assigned_stock(self, _request):
                    self.called = True
                    return response(runtimeGeneration=2, attachmentGeneration=2)

            cloud = FakeCloud()
            output = io.StringIO()
            with patch.object(cli, "load_cloud_client", return_value=cloud), \
                    patch.object(cli, "Store", side_effect=lambda path: Store(
                        path, clock=lambda: now)), redirect_stdout(output):
                code = cli.main([
                    "--state-dir", str(state), "stock-control", "attach",
                    "--runtime-id", RUNTIME, "--conversation-id", NEW_CONVERSATION,
                    "--cloud-config", str(state / "cloud.json"),
                    "--expected-runtime-generation", "1",
                    "--expected-attachment-generation", "1",
                ])
            self.assertEqual(code, 2)
            self.assertFalse(cloud.called)
            self.assertEqual(json.loads(output.getvalue())["reason"], "stale")

    def test_malformed_local_generation_refuses_before_cloud(self):
        now = NOW
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state"
            with Store(state, clock=lambda: now):
                pass
            (state / "control.sock").touch()
            malformed = {**self._stock_mapping(now + 30), "runtimeGeneration": None}

            class FakeCloud:
                principal, agent = "owner@example.com", "codex"
                called = False

                async def assigned_stock(self, _request):
                    self.called = True
                    return response(runtimeGeneration=2, attachmentGeneration=2)

            cloud = FakeCloud()
            output = io.StringIO()
            with patch.object(cli, "load_cloud_client", return_value=cloud), \
                    patch.object(cli, "request", return_value={"mapping": malformed}), \
                    redirect_stdout(output):
                code = cli.main([
                    "--state-dir", str(state), "stock-control", "attach",
                    "--runtime-id", RUNTIME, "--conversation-id", CONVERSATION,
                    "--cloud-config", str(state / "cloud.json"),
                    "--expected-runtime-generation", "1",
                    "--expected-attachment-generation", "1",
                ])
            self.assertEqual(code, 2)
            self.assertFalse(cloud.called)
            self.assertEqual(json.loads(output.getvalue())["reason"], "stale")

    def test_one_sided_expected_generation_is_invalid_before_local_or_cloud_access(self):
        now = NOW
        for option in ("--expected-runtime-generation", "--expected-attachment-generation"):
            with self.subTest(option=option), tempfile.TemporaryDirectory() as temp:
                state = Path(temp).resolve() / "state"
                with Store(state, clock=lambda: now) as store:
                    stored = self._stock_mapping(now + 30)
                    store.put_attachment(stored)
                (state / "control.sock").touch()

                class FakeCloud:
                    principal, agent = "owner@example.com", "codex"
                    called = False

                    async def assigned_stock(self, _request):
                        self.called = True
                        return response(runtimeGeneration=2, attachmentGeneration=2,
                                        leaseUntil=_iso(now + 120))

                cloud = FakeCloud()
                output = io.StringIO()
                with patch.object(cli, "load_cloud_client", return_value=cloud) as load_cloud, \
                        patch.object(cli, "Store") as local_store, \
                        patch.object(cli, "request", return_value={"mapping": stored}) as control_request, \
                        redirect_stdout(output):
                    code = cli.main([
                        "--state-dir", str(state), "stock-control", "attach",
                        "--runtime-id", RUNTIME, "--conversation-id", CONVERSATION,
                        "--cloud-config", str(state / "cloud.json"), option, "1",
                    ])
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(output.getvalue()),
                                 {"assignment": None, "reason": "invalid_request"})
                load_cloud.assert_not_called()
                local_store.assert_not_called()
                control_request.assert_not_called()
                self.assertFalse(cloud.called)

    def test_cloud_attach_must_advance_both_generations_and_preserves_local_row(self):
        now = NOW
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state"
            original = self._stock_mapping(now + 30)
            with Store(state, clock=lambda: now) as store:
                store.put_attachment(original)

            class FakeCloud:
                principal, agent = "owner@example.com", "codex"

                async def assigned_stock(self, _request):
                    return response(runtimeGeneration=2, attachmentGeneration=1,
                                    runtimeProfile={**PROFILE, "conversationId": NEW_CONVERSATION},
                                    leaseUntil=_iso(now + 120))

            output = io.StringIO()
            with patch.object(cli, "load_cloud_client", return_value=FakeCloud()), \
                    patch.object(cli, "Store", side_effect=lambda path: Store(
                        path, clock=lambda: now)), redirect_stdout(output):
                code = cli.main([
                    "--state-dir", str(state), "stock-control", "attach",
                    "--runtime-id", RUNTIME, "--conversation-id", NEW_CONVERSATION,
                    "--cloud-config", str(state / "cloud.json"),
                    "--expected-runtime-generation", "1",
                    "--expected-attachment-generation", "1",
                ])
            result = json.loads(output.getvalue())
            self.assertEqual(code, 2)
            self.assertEqual(result["assignment"], "cloud_committed_local_mapping_failed")
            self.assertEqual(result["reason"], "invalid_response")
            with Store(state, clock=lambda: now) as store:
                self.assertEqual(store.get_attachment(RUNTIME), original)

    def test_cloud_confirmed_stock_reattach_uses_daemon_writer(self):
        now = NOW
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state"
            with Store(state, clock=lambda: now) as store:
                store.put_messaging_attachment(self._messaging_mapping(now + 30))
                store.detach(RUNTIME)
            daemon_store = Store(state, clock=lambda: now)
            self.addCleanup(daemon_store.close)
            (state / "control.sock").touch()
            commands = []

            class FakeCloud:
                principal, agent = "owner@example.com", "codex"
                node_id, node_generation = NODE, 2

                async def assigned_stock(self, _request):
                    return response(runtimeGeneration=3, attachmentGeneration=3,
                                    runtimeProfile={**PROFILE, "conversationId": NEW_CONVERSATION},
                                    leaseUntil=_iso(now + 120))

            def daemon_request(_state, command):
                commands.append(command)
                return daemon._execute_control_command(daemon_store, command)

            output = io.StringIO()
            with patch.object(cli, "load_cloud_client", return_value=FakeCloud()), \
                    patch.object(cli, "Store", side_effect=lambda path: Store(
                        path, clock=lambda: now)), \
                    patch.object(cli, "request", side_effect=daemon_request), \
                    redirect_stdout(output):
                code = cli.main([
                    "--state-dir", str(state), "stock-control", "attach",
                    "--runtime-id", RUNTIME, "--conversation-id", NEW_CONVERSATION,
                    "--cloud-config", str(state / "cloud.json"),
                    "--expected-runtime-generation", "2",
                    "--expected-attachment-generation", "2",
                ])
            self.assertEqual(code, 0, output.getvalue())
            self.assertEqual([item["command"] for item in commands], [
                "get-attachment", "get-stock-reassignment-source", "put-stock-reassignment",
            ])
            self.assertNotIn("routingGeneration", daemon_store.get_attachment(RUNTIME))

    def test_stock_reassignment_rejects_generic_downgrade_and_stale_identity(self):
        now = NOW
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state"
            old = self._messaging_mapping(now + 30)
            target = {**self._stock_mapping(now + 120), "runtimeGeneration": 2,
                      "attachmentGeneration": 2, "consumerGeneration": 2,
                      "runtimeProfile": {**PROFILE, "conversationId": NEW_CONVERSATION}}
            with Store(state, clock=lambda: now) as store:
                store.put_messaging_attachment(old)
                store.detach(RUNTIME)
                source = store.get_stock_reassignment_source(RUNTIME)
                with self.assertRaisesRegex(StoreError, "invalid_attachment"):
                    store.put_stock_reassignment(
                        target, expected_mapping={**source, "leaseExpiresAt": now + 30},
                        expected_runtime_generation=1, expected_attachment_generation=1,
                    )
                with self.assertRaisesRegex(StoreError, "invalid_attachment"):
                    store.put_stock_reassignment(
                        target, expected_mapping=source,
                        expected_runtime_generation=None, expected_attachment_generation=1,
                    )
                with self.assertRaisesRegex(StoreError, "invalid_attachment"):
                    store.put_stock_reassignment(
                        {**target, "nativeThreadId": str(uuid.uuid4())}, expected_mapping=source,
                        expected_runtime_generation=1, expected_attachment_generation=1,
                    )
                with self.assertRaisesRegex(StoreError, "invalid_attachment"):
                    store.put_attachment(target)
                with self.assertRaisesRegex(StoreError, "invalid_attachment"):
                    store.put_stock_reassignment(
                        {**target, "runtimeGeneration": 1}, expected_mapping=source,
                        expected_runtime_generation=1, expected_attachment_generation=1,
                    )
                with self.assertRaisesRegex(StoreError, "invalid_attachment"):
                    store.put_stock_reassignment(
                        {**target, "principal": "other@example.com"}, expected_mapping=source,
                        expected_runtime_generation=1, expected_attachment_generation=1,
                    )
                with self.assertRaisesRegex(StoreError, "stale"):
                    store.put_stock_reassignment(
                        target, expected_mapping={**source, "namespace": "different/inbox"},
                        expected_runtime_generation=1, expected_attachment_generation=1,
                    )
                self.assertEqual(store.get_stock_reassignment_source(RUNTIME), source)
                store.put_stock_reassignment(
                    target, expected_mapping=source,
                    expected_runtime_generation=1, expected_attachment_generation=1,
                )
                current = store.get_attachment(RUNTIME)
                self.assertEqual(current["runtimeProfile"]["conversationId"], NEW_CONVERSATION)
                self.assertNotIn("routingGeneration", current)

    def test_same_generation_messaging_upgrade_cannot_change_conversation(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state"
            with Store(state, clock=lambda: NOW) as store:
                store.put_attachment(self._stock_mapping(NOW + 30))
                with self.assertRaisesRegex(StoreError, "invalid_attachment"):
                    store.put_messaging_attachment({
                        **self._messaging_mapping(NOW + 30),
                        "runtimeProfile": {**PROFILE, "conversationId": NEW_CONVERSATION},
                    })

    def test_invalid_cloud_config_returns_safe_refusal_without_mutation(self):
        for operation in ("attach", "renew"):
            for invalid in ("missing", "malformed", "permissions"):
                with self.subTest(operation=operation, invalid=invalid), tempfile.TemporaryDirectory() as temp:
                    state = Path(temp).resolve() / "state"
                    original = self._stock_mapping(time.time())
                    with Store(state) as store:
                        store.put_attachment(original)
                    config = Path(temp).resolve() / "cloud.json"
                    if invalid != "missing":
                        config.write_text("{" if invalid == "malformed" else "{}")
                        config.chmod(0o600 if invalid == "malformed" else 0o644)
                    output = io.StringIO()
                    with patch.object(CloudClient, "assigned_stock") as cloud_call, \
                            patch.object(cli, "Store") as local_store, \
                            patch.object(cli, "request") as control_call, redirect_stdout(output):
                        code = cli.stock_main([
                            "--state-dir", str(state), "stock-control", operation,
                            "--runtime-id", RUNTIME, "--conversation-id", CONVERSATION,
                            "--cloud-config", str(config),
                            "--expected-runtime-generation", "1",
                            "--expected-attachment-generation", "1",
                        ])
                    self.assertEqual(code, 2)
                    self.assertEqual(json.loads(output.getvalue()),
                                     {"assignment": None, "reason": "invalid_cloud_config"})
                    cloud_call.assert_not_called()
                    local_store.assert_not_called()
                    control_call.assert_not_called()
                    with Store(state) as store:
                        self.assertEqual(store.get_attachment(RUNTIME), original)

    def _handoff(self, *, namespace="team/inbox", route_generation=1, agent_incarnation=1):
        return {
            "version": 1, "namespace": namespace, "principal": "owner@example.com", "agent": "codex",
            "agentIncarnation": agent_incarnation, "routeGeneration": route_generation,
            "consumer": {"nodeId": NODE, "runtimeId": RUNTIME, "nodeGeneration": 2,
                         "runtimeGeneration": 1, "attachmentGeneration": 1,
                         "consumerGeneration": 1},
            "runtimeProfile": PROFILE,
        }

    def _stock_mapping(self, now):
        return {
            "runtimeId": RUNTIME, "principal": "owner@example.com", "agent": "codex",
            "nodeId": NODE, "nodeGeneration": 2, "runtimeGeneration": 1,
            "attachmentGeneration": 1, "consumerGeneration": 1,
            "leaseExpiresAt": now + 30, "runtimeProfile": PROFILE,
        }

    def _messaging_mapping(self, now):
        return {
            **self._stock_mapping(now), "namespace": "team/inbox", "agentIncarnation": 1,
            "routingGeneration": 1,
        }

    def _stock_renew_args(self, handoff_path):
        return type("Args", (), {
            "operation": "renew", "runtime_id": RUNTIME,
            "conversation_id": CONVERSATION, "cloud_config": Path("cloud.json"),
            "expected_runtime_generation": 1, "expected_attachment_generation": 1,
            "messaging_handoff": handoff_path,
        })()

    def test_owner_handoff_import_makes_real_v2_ingress_usable(self):
        fixture_now = __import__("json").loads(
            (Path(__file__).resolve().parents[1] /
             "contracts/messaging-v2/messaging-protocol-semantics-v2.json").read_text()
        )["nowMs"] / 1000
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state"
            handoff_path = Path(temp).resolve() / "messaging-handoff.json"
            handoff_path.write_text(json.dumps(self._handoff()))
            handoff_path.chmod(0o600)
            with Store(state, clock=lambda: fixture_now) as store:
                store.put_attachment(self._stock_mapping(fixture_now))

            class FakeCloud:
                principal, agent = "owner@example.com", "codex"
                node_id, node_generation = NODE, 2

                async def assigned_stock(self, request):
                    self.assert_request = request
                    return response("renewed", leaseUntil=_iso(fixture_now + 120))

            daemon_store = Store(state, clock=lambda: fixture_now)
            daemon_store.put_attachment(self._stock_mapping(fixture_now))
            (state / "control.sock").touch()
            daemon_commands = []

            def daemon_request(_state, command):
                daemon_commands.append(command)
                return daemon._execute_control_command(daemon_store, command)

            output = io.StringIO()
            with patch.object(cli, "load_cloud_client", return_value=FakeCloud()), \
                    patch.object(cli, "Store", side_effect=lambda path: Store(
                        path, clock=lambda: fixture_now)), \
                    patch.object(cli, "request", side_effect=daemon_request), redirect_stdout(output):
                exit_code = cli.main([
                    "--state-dir", str(state), "stock-control", "renew",
                    "--runtime-id", RUNTIME, "--conversation-id", CONVERSATION,
                    "--cloud-config", str(state / "cloud.json"),
                    "--expected-runtime-generation", "1",
                    "--expected-attachment-generation", "1",
                    "--messaging-handoff", str(handoff_path),
                ])
            self.assertEqual(exit_code, 0, f"{output.getvalue()} {daemon_commands!r}")
            self.assertEqual(json.loads(output.getvalue())["localMapping"], "stored")
            self.assertEqual([item["command"] for item in daemon_commands],
                             ["get-attachment", "put-messaging-attachment"])
            self.assertEqual(daemon_commands[1]["expectedMapping"], self._stock_mapping(fixture_now))
            daemon_store.close()

            event_fixture = json.loads((Path(__file__).resolve().parents[1] /
                                        "contracts/messaging-v2/messaging-protocol-semantics-v2.json").read_text())
            event = copy.deepcopy(event_fixture["envelope"])
            event.update(principal="owner@example.com", agent="codex", nodeId=NODE,
                         runtimeId=RUNTIME, nodeGeneration=2, runtimeGeneration=1,
                         attachmentGeneration=1, consumerGeneration=1, routingGeneration=1,
                         runtimeProfile=PROFILE)
            event["canonicalSubject"].update(namespace="team/inbox", agentIncarnation=1)
            event["deliveryId"] = messaging_protocol_v2.derive_delivery_id(event)
            key = Ed25519PrivateKey.generate()
            body = messaging_protocol_v2._json_bytes(event)
            gateway = Gateway(Store(state, clock=lambda: fixture_now), None, None,
                              audience="local", keys={"owner": key.public_key()},
                              clock=lambda: fixture_now, stock_only=True)
            self.addCleanup(gateway.store.close)
            result = gateway.accept_messaging_v2(
                body, signature=sign(body, key, "local"), audience="local", key_id="owner",
                node_id=NODE, runtime_id=RUNTIME,
            )
            self.assertEqual(result["status"], "held")

    def test_invalid_or_stale_handoff_fails_before_cloud_renew(self):
        for change, source_mapping in (
                ({"runtimeProfile": {**PROFILE, "conversationId": NODE}}, "stock"),
                ({"agentIncarnation": 2}, "messaging"),
                ({"routeGeneration": 2}, "messaging"),
                ({"consumer": {**self._handoff()["consumer"], "runtimeGeneration": 9}}, "stock"),
        ):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                now = 1_791_201_630
                state = Path(temp).resolve() / "state"
                handoff_path = Path(temp).resolve() / "messaging-handoff.json"
                handoff_path.write_text(json.dumps({**self._handoff(), **change}))
                handoff_path.chmod(0o600)
                with Store(state, clock=lambda: now) as store:
                    if source_mapping == "messaging":
                        store.put_messaging_attachment(self._messaging_mapping(now))
                    else:
                        store.put_attachment(self._stock_mapping(now))
                cloud_calls = []

                class FakeCloud:
                    principal, agent = "owner@example.com", "codex"
                    node_id, node_generation = NODE, 2

                    async def assigned_stock(self, _request):
                        cloud_calls.append(True)
                        return response("renewed", leaseUntil=_iso(now + 120))

                output = io.StringIO()
                with patch.object(cli, "load_cloud_client", return_value=FakeCloud()), \
                        patch.object(cli, "Store", side_effect=lambda path: Store(
                            path, clock=lambda: now)), redirect_stdout(output):
                    self.assertEqual(cli._execute_stock_control(
                        self._stock_renew_args(handoff_path), state), 2)
                self.assertEqual(cloud_calls, [])
                self.assertEqual(json.loads(output.getvalue())["reason"], "stale_messaging_handoff")

    def test_messaging_handoff_accepts_zero_incarnation_and_rejects_negative(self):
        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

        with tempfile.TemporaryDirectory() as temp:
            handoff_path = Path(temp).resolve() / "messaging-handoff.json"
            expected = self._stock_mapping(NOW)
            handoff_path.write_text(json.dumps(self._handoff(agent_incarnation=0)))
            handoff_path.chmod(0o600)
            accepted = cli._load_stock_messaging_handoff(
                handoff_path, self._stock_renew_args(handoff_path), FakeCloud(), expected,
            )
            self.assertEqual(accepted["agentIncarnation"], 0)

            handoff_path.write_text(json.dumps(self._handoff(agent_incarnation=-1)))
            handoff_path.chmod(0o600)
            with self.assertRaisesRegex(CloudError, "stale_messaging_handoff"):
                cli._load_stock_messaging_handoff(
                    handoff_path, self._stock_renew_args(handoff_path), FakeCloud(), expected,
                )

    def test_detach_during_cloud_renew_does_not_resurrect_mapping(self):
        fixture_now = __import__("json").loads(
            (Path(__file__).resolve().parents[1] /
             "contracts/messaging-v2/messaging-protocol-semantics-v2.json").read_text()
        )["nowMs"] / 1000
        for daemon_mode in (False, True):
            with self.subTest(daemon_mode=daemon_mode), tempfile.TemporaryDirectory() as temp:
                state = Path(temp).resolve() / "state"
                handoff_path = Path(temp).resolve() / "handoff.json"
                handoff_path.write_text(json.dumps(self._handoff()))
                handoff_path.chmod(0o600)
                daemon_store = None
                with Store(state, clock=lambda: fixture_now) as store:
                    store.put_attachment(self._stock_mapping(fixture_now))
                if daemon_mode:
                    daemon_store = Store(state, clock=lambda: fixture_now)
                    (state / "control.sock").touch()

                class FakeCloud:
                    principal, agent = "owner@example.com", "codex"
                    node_id, node_generation = NODE, 2

                    async def assigned_stock(self, _request):
                        if daemon_store is not None:
                            daemon_store.detach(RUNTIME)
                        else:
                            with Store(state, clock=lambda: fixture_now) as store:
                                store.detach(RUNTIME)
                        return response("renewed", leaseUntil=_iso(fixture_now + 120))

                def daemon_request(_state, command):
                    return daemon._execute_control_command(daemon_store, command)

                args = [
                    "--state-dir", str(state), "stock-control", "renew",
                    "--runtime-id", RUNTIME, "--conversation-id", CONVERSATION,
                    "--cloud-config", str(state / "cloud.json"),
                    "--expected-runtime-generation", "1",
                    "--expected-attachment-generation", "1",
                    "--messaging-handoff", str(handoff_path),
                ]
                output = io.StringIO()
                with patch.object(cli, "load_cloud_client", return_value=FakeCloud()), \
                        patch.object(cli, "request", side_effect=daemon_request), \
                        redirect_stdout(output):
                    exit_code = cli.main(args)
                result = json.loads(output.getvalue())
                self.assertEqual(exit_code, 2)
                self.assertEqual(result["assignment"], "cloud_committed_local_mapping_failed")
                self.assertIn(result["reason"], ("stale", "invalid_attachment"))
                if daemon_store is not None:
                    self.assertIsNone(daemon_store.get_attachment(RUNTIME))
                    daemon_store.close()
                else:
                    with Store(state, clock=lambda: fixture_now) as store:
                        self.assertIsNone(store.get_attachment(RUNTIME))

    def test_repeated_messaging_handoff_renewals_keep_exact_route_tuple(self):
        fixture_now = __import__("json").loads(
            (Path(__file__).resolve().parents[1] /
             "contracts/messaging-v2/messaging-protocol-semantics-v2.json").read_text()
        )["nowMs"] / 1000
        for daemon_mode in (False, True):
            with self.subTest(daemon_mode=daemon_mode), tempfile.TemporaryDirectory() as temp:
                state = Path(temp).resolve() / "state"
                handoff_path = Path(temp).resolve() / "handoff.json"
                handoff_path.write_text(json.dumps(self._handoff()))
                handoff_path.chmod(0o600)
                initial = self._messaging_mapping(fixture_now)
                with Store(state, clock=lambda: fixture_now) as store:
                    store.put_messaging_attachment(initial)
                daemon_store = Store(state, clock=lambda: fixture_now) if daemon_mode else None
                if daemon_mode:
                    (state / "control.sock").touch()

                class FakeCloud:
                    principal, agent = "owner@example.com", "codex"
                    node_id, node_generation = NODE, 2

                    def __init__(self):
                        self.lease = fixture_now + 120

                    async def assigned_stock(self, _request):
                        self.lease += 60
                        return response("renewed", leaseUntil=_iso(self.lease))

                cloud = FakeCloud()

                def daemon_request(_state, command):
                    return daemon._execute_control_command(daemon_store, command)

                for _ in range(2):
                    output = io.StringIO()
                    with patch.object(cli, "load_cloud_client", return_value=cloud), \
                            patch.object(cli, "Store", side_effect=lambda path: Store(
                                path, clock=lambda: fixture_now)), \
                            patch.object(cli, "request", side_effect=daemon_request), \
                            redirect_stdout(output):
                        exit_code = cli.main([
                            "--state-dir", str(state), "stock-control", "renew",
                            "--runtime-id", RUNTIME, "--conversation-id", CONVERSATION,
                            "--cloud-config", str(state / "cloud.json"),
                            "--expected-runtime-generation", "1",
                            "--expected-attachment-generation", "1",
                            "--messaging-handoff", str(handoff_path),
                        ])
                    self.assertEqual(exit_code, 0, output.getvalue())
                    self.assertEqual(json.loads(output.getvalue())["localMapping"], "stored")

                if daemon_store is not None:
                    renewed = daemon_store.get_attachment(RUNTIME)
                    daemon_store.close()
                else:
                    with Store(state, clock=lambda: fixture_now) as store:
                        renewed = store.get_attachment(RUNTIME)
                for key in ("namespace", "agentIncarnation", "routingGeneration", "runtimeProfile",
                            "nodeId", "runtimeId", "nodeGeneration", "runtimeGeneration",
                            "attachmentGeneration", "consumerGeneration"):
                    self.assertEqual(renewed[key], initial[key], key)
                self.assertGreater(renewed["leaseExpiresAt"], initial["leaseExpiresAt"])

    def test_stock_renew_without_handoff_preserves_messaging_tuple(self):
        fixture_now = __import__("json").loads(
            (Path(__file__).resolve().parents[1] /
             "contracts/messaging-v2/messaging-protocol-semantics-v2.json").read_text()
        )["nowMs"] / 1000
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state"
            initial = self._messaging_mapping(fixture_now)
            with Store(state, clock=lambda: fixture_now) as store:
                store.put_messaging_attachment(initial)

            class FakeCloud:
                principal, agent = "owner@example.com", "codex"
                node_id, node_generation = NODE, 2

                async def assigned_stock(self, _request):
                    return response("renewed", leaseUntil=_iso(fixture_now + 180))

            output = io.StringIO()
            args = [
                "--state-dir", str(state), "stock-control", "renew",
                "--runtime-id", RUNTIME, "--conversation-id", CONVERSATION,
                "--cloud-config", str(state / "cloud.json"),
                "--expected-runtime-generation", "1",
                "--expected-attachment-generation", "1",
            ]
            with patch.object(cli, "load_cloud_client", return_value=FakeCloud()), \
                    patch.object(cli, "Store", side_effect=lambda path: Store(
                        path, clock=lambda: fixture_now)), redirect_stdout(output):
                self.assertEqual(cli.main(args), 0, output.getvalue())
            with Store(state, clock=lambda: fixture_now) as store:
                renewed = store.get_attachment(RUNTIME)
            for key in ("namespace", "agentIncarnation", "routingGeneration", "runtimeProfile"):
                self.assertEqual(renewed[key], initial[key], key)
            self.assertGreater(renewed["leaseExpiresAt"], initial["leaseExpiresAt"])

    def test_expired_exact_stock_mapping_renews_via_direct_and_daemon_store(self):
        for daemon_mode in (False, True):
            with self.subTest(daemon_mode=daemon_mode), tempfile.TemporaryDirectory() as temp:
                state = Path(temp).resolve() / "state"
                clock = [time.time()]
                expected = {
                    "runtimeId": RUNTIME, "principal": "owner@example.com", "agent": "codex",
                    "nodeId": NODE, "nodeGeneration": 2, "runtimeGeneration": 1,
                    "attachmentGeneration": 1, "consumerGeneration": 1,
                    "leaseExpiresAt": clock[0] + 5, "runtimeProfile": PROFILE,
                }
                owner_store = Store(state, clock=lambda: clock[0])
                owner_store.put_attachment(expected)
                clock[0] += 6
                if not daemon_mode:
                    owner_store.close()

                class FakeCloud:
                    principal, agent = "owner@example.com", "codex"
                    node_id, node_generation = NODE, 2

                    async def assigned_stock(self, request):
                        self.request = request
                        return response("renewed", leaseUntil=_iso(clock[0] + 120))

                cloud = FakeCloud()
                if daemon_mode:
                    # The mocked control transport invokes the actual single-writer handler.
                    daemon_store = owner_store
                    (state / "control.sock").touch()

                    async def control(_state, value):
                        return daemon._execute_control_command(daemon_store, value)

                    request_patch = patch.object(cli, "request", side_effect=control)
                else:
                    request_patch = patch.object(cli, "request")

                args = type("Args", (), {
                    "operation": "renew", "runtime_id": RUNTIME,
                    "conversation_id": CONVERSATION, "cloud_config": Path("cloud.json"),
                    "expected_runtime_generation": 1, "expected_attachment_generation": 1,
                })()
                output = io.StringIO()
                try:
                    with patch.object(cli, "load_cloud_client", return_value=cloud), \
                            patch.object(cli, "Store", side_effect=lambda path: Store(
                                path, clock=lambda: clock[0])), request_patch, \
                            redirect_stdout(output):
                        self.assertEqual(cli._execute_stock_control(args, state), 0)
                    if daemon_mode:
                        stored = owner_store.get_attachment(RUNTIME)
                    else:
                        with Store(state, clock=lambda: clock[0]) as store:
                            stored = store.get_attachment(RUNTIME)
                    self.assertEqual(
                        {key: value for key, value in stored.items() if key != "leaseExpiresAt"},
                        {key: value for key, value in expected.items() if key != "leaseExpiresAt"},
                    )
                    self.assertGreater(stored["leaseExpiresAt"], clock[0])
                    self.assertEqual(cloud.request["expectedRuntimeGeneration"], 1)
                    self.assertEqual(json.loads(output.getvalue())["localMapping"], "stored")
                finally:
                    if owner_store.db is not None:
                        owner_store.close()

    def test_stock_renewal_mismatch_and_missing_mapping_fail_before_cloud(self):
        changes = (
            {"runtimeProfile": {**PROFILE, "conversationId": RUNTIME}},
            {"runtimeGeneration": 2}, {"attachmentGeneration": 2, "consumerGeneration": 2},
            {"nodeId": "42345678-1234-4234-8234-123456789abc"},
            {"nodeGeneration": 3}, {"principal": "other@example.com"}, {"agent": "other"},
        )
        for change in (*changes, None):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                state = Path(temp).resolve() / "state"
                now = [time.time()]
                cloud_calls = []
                mapping = {
                    "runtimeId": RUNTIME, "principal": "owner@example.com", "agent": "codex",
                    "nodeId": NODE, "nodeGeneration": 2, "runtimeGeneration": 1,
                    "attachmentGeneration": 1, "consumerGeneration": 1,
                    "leaseExpiresAt": now[0] + 100, "runtimeProfile": PROFILE,
                }
                if change is not None:
                    with Store(state, clock=lambda: now[0]) as store:
                        store.put_attachment({**mapping, **change})

                class FakeCloud:
                    principal, agent = "owner@example.com", "codex"
                    node_id, node_generation = NODE, 2

                    async def assigned_stock(self, _request):
                        cloud_calls.append(True)
                        return response("renewed", leaseUntil=_iso(now[0] + 200))

                args = type("Args", (), {
                    "operation": "renew", "runtime_id": RUNTIME,
                    "conversation_id": CONVERSATION, "cloud_config": Path("cloud.json"),
                    "expected_runtime_generation": 1, "expected_attachment_generation": 1,
                })()
                output = io.StringIO()
                with patch.object(cli, "load_cloud_client", return_value=FakeCloud()), \
                        patch.object(cli, "Store", side_effect=lambda path: Store(
                            path, clock=lambda: now[0])), redirect_stdout(output):
                    self.assertEqual(cli._execute_stock_control(args, state), 2)
                self.assertEqual(cloud_calls, [])
                self.assertEqual(json.loads(output.getvalue())["reason"], "stale")

    def test_stock_renewal_cas_preserves_concurrent_reassignment(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve() / "state"
            now = [time.time()]
            expected = {
                "runtimeId": RUNTIME, "principal": "owner@example.com", "agent": "codex",
                "nodeId": NODE, "nodeGeneration": 2, "runtimeGeneration": 1,
                "attachmentGeneration": 1, "consumerGeneration": 1,
                "leaseExpiresAt": now[0] + 100, "runtimeProfile": PROFILE,
            }
            replacement = {
                **expected, "runtimeGeneration": 2, "attachmentGeneration": 2,
                "consumerGeneration": 2,
                "runtimeProfile": {**PROFILE, "conversationId": "42345678-1234-4234-8234-123456789abc"},
            }
            with Store(state, clock=lambda: now[0]) as store:
                store.put_attachment(expected)

            class FakeCloud:
                principal, agent = "owner@example.com", "codex"
                node_id, node_generation = NODE, 2

                async def assigned_stock(self, _request):
                    with Store(state, clock=lambda: now[0]) as store:
                        store.put_attachment(replacement)
                    return response("renewed", leaseUntil=_iso(now[0] + 200))

            args = type("Args", (), {
                "operation": "renew", "runtime_id": RUNTIME,
                "conversation_id": CONVERSATION, "cloud_config": Path("cloud.json"),
                "expected_runtime_generation": 1, "expected_attachment_generation": 1,
            })()
            output = io.StringIO()
            with patch.object(cli, "load_cloud_client", return_value=FakeCloud()), \
                    patch.object(cli, "Store", side_effect=lambda path: Store(
                        path, clock=lambda: now[0])), redirect_stdout(output):
                self.assertEqual(cli._execute_stock_control(args, state), 2)

            with Store(state, clock=lambda: now[0]) as store:
                self.assertEqual(store.get_attachment(RUNTIME), replacement)
            result = json.loads(output.getvalue())
            self.assertEqual(result["assignment"], "cloud_committed_local_mapping_failed")
            self.assertEqual(result["reason"], "stale")

    async def test_assignment_matches_shared_contract_vectors(self):
        fixture_path = Path(__file__).resolve().parents[1] / "contracts/event-control-v1/fixtures.json"
        vectors = json.loads(fixture_path.read_text())["assignedStock"]
        sends = []

        async def send(**request):
            sends.append(request)
            body = copy.deepcopy(vectors["response"])
            if request["body"]:
                submitted = json.loads(request["body"])
                if submitted["operation"] == "renew":
                    body.update(status="renewed",
                                runtimeGeneration=submitted["expectedRuntimeGeneration"],
                                attachmentGeneration=submitted["expectedAttachmentGeneration"])
            return 200, {"content-type": "application/json"}, json.dumps(body).encode()

        expected = vectors["response"]
        client = CloudClient(
            origin="https://events.example.com", principal="owner@example.com", agent="codex",
            node_id=expected["nodeId"], node_generation=expected["nodeGeneration"],
            private_key=Ed25519PrivateKey.generate(),
            credentials=lambda: asyncio.sleep(0, result=Credentials("access", "agent")),
            send=send, clock=lambda: 0,
        )
        self.assertEqual(await client.assigned_stock(copy.deepcopy(vectors["request"])), expected)
        self.assertEqual(len(sends), 1)

        for vector in vectors["requests"]:
            before = len(sends)
            if vector["accepted"]:
                await client.assigned_stock(copy.deepcopy(vector["value"]))
                self.assertEqual(len(sends), before + 1, vector["name"])
            else:
                with self.subTest(vector=vector["name"]), self.assertRaisesRegex(CloudError, "invalid_request"):
                    await client.assigned_stock(copy.deepcopy(vector["value"]))
                self.assertEqual(len(sends), before, vector["name"])

    async def test_assignment_uses_signed_closed_route_and_returns_validated_profile(self):
        sent = []

        async def send(**request):
            sent.append(request)
            return 200, {"content-type": "application/json"}, json.dumps(response()).encode()

        client = CloudClient(
            origin="https://events.example.com", principal="owner@example.com", agent="codex",
            node_id=NODE, node_generation=2, private_key=Ed25519PrivateKey.generate(),
            credentials=lambda: asyncio.sleep(0, result=Credentials("access", "agent")),
            send=send, clock=lambda: NOW,
        )
        result = await client.assigned_stock({
            "operation": "attach", "runtimeId": RUNTIME, "conversationId": CONVERSATION,
            "expectedRuntimeGeneration": None, "expectedAttachmentGeneration": None,
        })
        self.assertEqual(result["runtimeProfile"], PROFILE)
        self.assertEqual(sent[0]["url"], "https://events.example.com/v1/runtimes/assigned-stock")
        self.assertIn("x-event-node-proof", sent[0]["headers"])
        self.assertEqual(json.loads(sent[0]["body"])["conversationId"], CONVERSATION)

    async def test_assignment_preflights_attach_generation_ceiling_but_allows_renew(self):
        safe = 9007199254740991
        sent = []

        async def send(**request):
            sent.append(request)
            submitted = json.loads(request["body"])
            if submitted["operation"] == "renew":
                body = response("renewed", runtimeGeneration=safe, attachmentGeneration=safe)
            else:
                body = response()
            return 200, {"content-type": "application/json"}, json.dumps(body).encode()

        client = CloudClient(
            origin="https://events.example.com", principal="owner@example.com", agent="codex",
            node_id=NODE, node_generation=2, private_key=Ed25519PrivateKey.generate(),
            credentials=lambda: asyncio.sleep(0, result=Credentials("access", "agent")),
            send=send, clock=lambda: NOW,
        )
        for field in ("expectedRuntimeGeneration", "expectedAttachmentGeneration"):
            request = {
                "operation": "attach", "runtimeId": RUNTIME, "conversationId": CONVERSATION,
                "expectedRuntimeGeneration": 1, "expectedAttachmentGeneration": 1,
            }
            request[field] = safe
            with self.subTest(field=field), self.assertRaisesRegex(CloudError, "invalid_request"):
                await client.assigned_stock(request)
            self.assertEqual(sent, [])

        renewed = await client.assigned_stock({
            "operation": "renew", "runtimeId": RUNTIME, "conversationId": CONVERSATION,
            "expectedRuntimeGeneration": safe, "expectedAttachmentGeneration": safe,
        })
        self.assertEqual(renewed["runtimeGeneration"], safe)
        self.assertEqual(len(sent), 1)

    async def test_assignment_rejects_noncanonical_uuid_and_mismatched_response(self):
        async def send(**_):
            return 200, {"content-type": "application/json"}, json.dumps(
                response(runtimeProfile={**PROFILE, "conversationId": RUNTIME})
            ).encode()

        client = CloudClient(
            origin="https://events.example.com", principal="owner@example.com", agent="codex",
            node_id=NODE, node_generation=2, private_key=Ed25519PrivateKey.generate(),
            credentials=lambda: asyncio.sleep(0, result=Credentials("access", "agent")),
            send=send, clock=lambda: NOW,
        )
        with self.assertRaisesRegex(CloudError, "invalid_request"):
            await client.assigned_stock({
                "operation": "attach", "runtimeId": RUNTIME,
                "conversationId": str(uuid.UUID(CONVERSATION)).upper(),
                "expectedRuntimeGeneration": None, "expectedAttachmentGeneration": None,
            })
        with self.assertRaisesRegex(CloudError, "invalid_response"):
            await client.assigned_stock({
                "operation": "attach", "runtimeId": RUNTIME, "conversationId": CONVERSATION,
                "expectedRuntimeGeneration": 4, "expectedAttachmentGeneration": 7,
            })

        async def wrong_generations(**_):
            return 200, {"content-type": "application/json"}, json.dumps(
                response(runtimeGeneration=5, attachmentGeneration=9)
            ).encode()
        client = CloudClient(
            origin="https://events.example.com", principal="owner@example.com", agent="codex",
            node_id=NODE, node_generation=2, private_key=Ed25519PrivateKey.generate(),
            credentials=lambda: asyncio.sleep(0, result=Credentials("access", "agent")),
            send=wrong_generations, clock=lambda: NOW,
        )
        with self.assertRaisesRegex(CloudError, "invalid_response"):
            await client.assigned_stock({
                "operation": "attach", "runtimeId": RUNTIME, "conversationId": CONVERSATION,
                "expectedRuntimeGeneration": 4, "expectedAttachmentGeneration": 7,
            })

    async def test_assignment_post_send_shape_failure_is_outcome_unknown(self):
        async def invalid_success(**_):
            return 200, {"content-type": "application/json"}, json.dumps(
                response(runtimeProfile={**PROFILE, "conversationId": RUNTIME})
            ).encode()

        client = CloudClient(
            origin="https://events.example.com", principal="owner@example.com", agent="codex",
            node_id=NODE, node_generation=2, private_key=Ed25519PrivateKey.generate(),
            credentials=lambda: asyncio.sleep(0, result=Credentials("access", "agent")),
            send=invalid_success, clock=lambda: NOW,
        )
        request = {
            "operation": "attach", "runtimeId": RUNTIME, "conversationId": CONVERSATION,
            "expectedRuntimeGeneration": None, "expectedAttachmentGeneration": None,
        }
        with self.assertRaises(CloudError) as caught:
            await client.assigned_stock(request)
        self.assertEqual(caught.exception.code, "invalid_response")
        self.assertTrue(caught.exception.ambiguous)

        async def refused_credentials():
            raise OSError("private detail")
        client = CloudClient(
            origin="https://events.example.com", principal="owner@example.com", agent="codex",
            node_id=NODE, node_generation=2, private_key=Ed25519PrivateKey.generate(),
            credentials=refused_credentials, send=invalid_success, clock=lambda: NOW,
        )
        with self.assertRaises(CloudError) as caught:
            await client.assigned_stock(request)
        self.assertFalse(caught.exception.ambiguous)

        async def unavailable(**_):
            return 503, {"content-type": "application/json"}, b'{"error":"unavailable"}'
        client = CloudClient(
            origin="https://events.example.com", principal="owner@example.com", agent="codex",
            node_id=NODE, node_generation=2, private_key=Ed25519PrivateKey.generate(),
            credentials=lambda: asyncio.sleep(0, result=Credentials("access", "agent")),
            send=unavailable, clock=lambda: NOW,
        )
        with self.assertRaises(CloudError) as caught:
            await client.assigned_stock(request)
        self.assertTrue(caught.exception.ambiguous)

    async def test_disabled_assignment_refusal_keeps_its_allowlisted_code(self):
        async def disabled(**_):
            return 409, {"content-type": "application/json"}, b'{"error":"assigned_stock_disabled"}'
        client = CloudClient(
            origin="https://events.example.com", principal="owner@example.com", agent="codex",
            node_id=NODE, node_generation=2, private_key=Ed25519PrivateKey.generate(),
            credentials=lambda: asyncio.sleep(0, result=Credentials("access", "agent")),
            send=disabled, clock=lambda: NOW,
        )
        with self.assertRaises(CloudError) as caught:
            await client.assigned_stock({
                "operation": "attach", "runtimeId": RUNTIME, "conversationId": CONVERSATION,
                "expectedRuntimeGeneration": None, "expectedAttachmentGeneration": None,
            })
        self.assertEqual(caught.exception.code, "assigned_stock_disabled")
        self.assertFalse(caught.exception.ambiguous)

    async def test_stock_claim_and_command_accepted_ack_need_no_native_correlation(self):
        fixture_path = Path(__file__).resolve().parents[1] / "contracts/event-v1/protocol-v1.json"
        envelope = copy.deepcopy(json.loads(fixture_path.read_text())["validEnvelopes"][0])
        envelope["runtimeProfile"] = PROFILE
        envelope["consumerGeneration"] = envelope["attachmentGeneration"]
        envelope["deliveryId"] = derive_delivery_id(envelope)
        acknowledgment = {key: envelope[key] for key in (
            "schemaVersion", "eventId", "deliveryId", "attemptId", "principal", "agent",
            "runtimeId", "nodeGeneration", "runtimeGeneration", "attachmentGeneration",
            "consumerGeneration",
        )}
        acknowledgment.update(
            status="command_accepted", runtimeProfile=PROFILE,
            deliveredSourceStateVersion=envelope["sourceStateVersion"],
            acknowledgedAt="2026-10-05T12:00:30.000Z",
        )
        admission = {
            "status": "admitted", "permitId": "42345678-1234-4234-8234-123456789abc",
            "nodeId": NODE, "permitIssuedAt": "2026-10-05T12:00:30.000Z",
            "permitExpiresAt": "2026-10-05T12:00:35.000Z", "envelope": envelope,
        }
        sends = []

        async def send(**request):
            sends.append(request)
            body = admission if len(sends) == 1 else {"status": "command_accepted", "current": True}
            return 200, {"content-type": "application/json"}, json.dumps(body).encode()

        client = CloudClient(
            origin="https://events.example.com", principal=envelope["principal"], agent=envelope["agent"],
            node_id=NODE, node_generation=envelope["nodeGeneration"],
            private_key=Ed25519PrivateKey.generate(),
            credentials=lambda: asyncio.sleep(0, result=Credentials("access", "agent")),
            send=send, clock=lambda: 1791201630,
        )
        admitted = await client.claim(envelope)
        settled = await client.acknowledge(envelope, acknowledgment)
        self.assertEqual(admitted["envelope"]["runtimeProfile"], PROFILE)
        self.assertEqual(settled, {"status": "command_accepted", "current": True})

    def test_owner_setup_persists_generation_bound_profile_without_native_binding(self):
        args = type("Args", (), {
            "operation": "attach", "runtime_id": RUNTIME, "conversation_id": CONVERSATION,
            "expected_runtime_generation": None, "expected_attachment_generation": None,
            "cloud_config": Path("cloud.json"),
        })()
        cloud = type("Cloud", (), {
            "principal": "owner@example.com", "agent": "codex",
            "assigned_stock": None,
        })()

        async def assign(_):
            return response()
        cloud.assigned_stock = assign
        with tempfile.TemporaryDirectory() as temp, \
                patch.object(cli, "load_cloud_client", return_value=cloud), \
                patch.object(cli, "_store_native_mapping", return_value=(True, None)) as persist, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(cli._execute_stock_control(args, Path(temp)), 0)
        mapping = persist.call_args.args[2]
        self.assertEqual(mapping["runtimeProfile"], PROFILE)
        self.assertEqual(mapping["consumerGeneration"], mapping["attachmentGeneration"])
        self.assertNotIn("nativeBinding", mapping)
        self.assertNotIn("nativeThreadId", mapping)

    def test_local_mapping_failure_reports_committed_assignment_tuple(self):
        args = type("Args", (), {
            "operation": "attach", "runtime_id": RUNTIME, "conversation_id": CONVERSATION,
            "expected_runtime_generation": None, "expected_attachment_generation": None,
            "cloud_config": Path("cloud.json"),
        })()
        cloud = type("Cloud", (), {"principal": "owner@example.com", "agent": "codex"})()

        async def assign(_):
            return response()
        cloud.assigned_stock = assign
        output = io.StringIO()
        with patch.object(cli, "load_cloud_client", return_value=cloud), \
                patch.object(cli, "_store_native_mapping", return_value=(False, "writer_locked")), \
                redirect_stdout(output):
            self.assertEqual(cli._execute_stock_control(args, Path(tempfile.gettempdir())), 2)
        result = json.loads(output.getvalue())
        self.assertEqual(result["assignment"], "cloud_committed_local_mapping_failed")
        self.assertEqual(result["runtimeProfile"], PROFILE)
        self.assertEqual((result["runtimeGeneration"], result["attachmentGeneration"]), (1, 1))


if __name__ == "__main__":
    unittest.main()
