"""Mock-only owner setup and assigned-stock DTO validation."""
import asyncio
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid
from contextlib import redirect_stdout

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway import cli
from event_gateway.cloud import CloudClient, CloudError, Credentials
from event_gateway.protocol import derive_delivery_id


RUNTIME = "12345678-1234-4234-8234-123456789abc"
CONVERSATION = "22345678-1234-4234-8234-123456789abc"
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
