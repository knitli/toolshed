import asyncio
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
from threading import Event
import unittest
import uuid
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway.cloud import CloudError, _iso
from event_gateway.gateway import Gateway
from event_gateway import messaging_protocol_v2
from event_gateway.protocol import derive_delivery_id
from event_gateway.store import IDENTITY, Store, StoreError
from event_gateway.stock_codex import StockCodexError, StockCodexPreflightCancelled


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads((ROOT / "contracts/event-v1/protocol-v1.json").read_text())
EVENT = next(event for event in FIXTURES["validEnvelopes"] if "runtimeProfile" in event)
MESSAGING_FIXTURE = json.loads((ROOT / "contracts/messaging-v2/messaging-protocol-semantics-v2.json").read_text())
NOW = 1791201630


class Authority:
    def __init__(self, test):
        """Collect authority calls for gateway tests."""
        self.test = test
        self.claims = []
        self.acks = []
        self.settlements = []
        self.on_claim = None
        self.drop_ack = False
        self.fail_settlement_once = False

    async def claim(self, envelope):
        self.claims.append(copy.deepcopy(envelope))
        if self.on_claim:
            self.on_claim()
        issued = _iso(self.test.now)
        return {
            "status": "admitted", "permitId": str(uuid.uuid4()),
            "nodeId": envelope.get("nodeId", str(uuid.uuid4())), "permitIssuedAt": issued,
            "permitExpiresAt": _iso(self.test.now + 5), "envelope": copy.deepcopy(envelope),
        }

    async def acknowledge(self, envelope, acknowledgment):
        self.acks.append(copy.deepcopy(acknowledgment))
        if self.drop_ack:
            self.drop_ack = False
            raise TimeoutError("lost ACK response")
        return {"status": acknowledgment["status"], "current": False}

    async def settle_no_start(self, admission, evidence):
        self.settlements.append((copy.deepcopy(admission), copy.deepcopy(evidence)))
        if self.fail_settlement_once:
            self.fail_settlement_once = False
            raise TimeoutError("lost settlement response")
        return {"deliveryId": admission["envelope"]["deliveryId"],
                "attemptId": admission["envelope"]["attemptId"],
                "nodeGeneration": admission["envelope"]["nodeGeneration"],
                "status": "not_started", "permitId": admission["permitId"],
                "nodeId": admission["nodeId"], "evidence": evidence}


class StockGatewayTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name).resolve() / "private"
        self.now = NOW
        self.event = copy.deepcopy(EVENT)
        self.mapping = {key: self.event[key] for key in IDENTITY}
        self.mapping.update(consumerGeneration=self.event["consumerGeneration"],
                            runtimeProfile=self.event["runtimeProfile"],
                            leaseExpiresAt=self.now + 3600)
        self.store = Store(self.path, clock=lambda: self.now)
        self.addCleanup(self.close_store)
        self.store.put_attachment(self.mapping)
        self.authority = Authority(self)
        self.executable_check = patch("event_gateway.stock_codex._binary_is_executable", return_value=True)
        self.executable_check.start()
        self.addCleanup(self.executable_check.stop)
        self.gateway = Gateway(self.store, self.authority, lambda _mapping: self,
                               audience="test", keys={"test": Ed25519PrivateKey.generate().public_key()},
                               clock=lambda: self.now, stock_codex_binary="/opt/test/codex")

    def close_store(self):
        self.store.close()

    def accept(self):
        return self.store.accept(copy.deepcopy(self.event))["deliveryId"]

    def restart(self):
        self.store.close()
        self.store = Store(self.path, clock=lambda: self.now)
        self.gateway.store = self.store

    def new_delivery(self):
        """Accept a fresh stock envelope with a new assignment generation."""
        self.event = copy.deepcopy(EVENT)
        self.event["eventId"] = str(uuid.uuid4())
        self.event["attemptId"] = str(uuid.uuid4())
        self.event["runtimeGeneration"] = self.mapping["runtimeGeneration"] + 1
        self.event["attachmentGeneration"] = self.mapping["attachmentGeneration"] + 1
        self.event["consumerGeneration"] = self.mapping["consumerGeneration"] + 1
        self.event["runtimeProfile"]["conversationId"] = str(uuid.uuid4())
        self.event["deliveryId"] = derive_delivery_id(self.event)
        self.mapping = {key: self.event[key] for key in IDENTITY}
        self.mapping.update(consumerGeneration=self.event["consumerGeneration"],
                            runtimeProfile=self.event["runtimeProfile"],
                            leaseExpiresAt=self.now + 3600)
        self.store.put_attachment(self.mapping)
        return self.accept()

    def lose_assignment(self, kind):
        if kind == "detach":
            self.store.detach(self.event["runtimeId"])
        else:
            expired = dict(self.mapping, leaseExpiresAt=self.now + 1)
            self.store.put_attachment(expired)
            self.mapping = expired
            self.now += 2

    def stock_submit_mock(self, *, result=None, error=None):
        """Model a successful preflight, then run the gateway's synchronous fence."""
        async def submit(event_reference, *, before_start=None):
            if isinstance(error, (StockCodexPreflightCancelled,)) or (
                    isinstance(error, StockCodexError) and error.code == "client_not_started"):
                raise error
            if before_start is not None:
                before_start()
            if error is not None:
                raise error
            return result

        return AsyncMock(side_effect=submit)

    def assert_stock_submit_once(self, submit):
        self.assertEqual(submit.await_count, 1)
        self.assertEqual(submit.await_args.args, (self.event["eventReference"],))
        self.assertIn("before_start", submit.await_args.kwargs)

    def setup_messaging_v2_stock(self):
        self.now = MESSAGING_FIXTURE["nowMs"] / 1000
        self.event = copy.deepcopy(MESSAGING_FIXTURE["envelope"])
        self.event["runtimeProfile"] = {
            "profile": "assigned_stock_client", "client": "codex",
            "conversationId": str(uuid.uuid4()),
        }
        self.event["deliveryId"] = messaging_protocol_v2.derive_delivery_id(self.event)
        self.mapping = {key: self.event[key] for key in (
            "principal", "agent", "nodeId", "runtimeId", "nodeGeneration", "runtimeGeneration",
            "attachmentGeneration", "consumerGeneration", "routingGeneration",
        )}
        self.mapping.update(namespace=self.event["canonicalSubject"]["namespace"],
                            agentIncarnation=self.event["canonicalSubject"]["agentIncarnation"],
                            runtimeProfile=copy.deepcopy(self.event["runtimeProfile"]),
                            leaseExpiresAt=self.now + 3600)
        self.store.put_messaging_attachment(self.mapping)

    async def test_v2_stock_uses_existing_durable_queue_and_exact_ack(self):
        self.setup_messaging_v2_stock()
        delivery = self.accept()
        self.assertEqual(self.store.delivery(delivery)["status"], "held")
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(result={"status": "command_accepted"})) as submit:
            result = await self.gateway.dispatch(delivery)
            again = await self.gateway.dispatch(delivery)
        self.assertEqual(result["status"], "command_accepted")
        self.assertEqual(again["status"], "command_accepted")
        self.assert_stock_submit_once(submit)
        attempt = self.store.current_attempt(delivery)
        acknowledgment = attempt["native_ack"]
        self.assertEqual(acknowledgment["schemaVersion"], 2)
        self.assertEqual(acknowledgment["runtimeProfile"], self.event["runtimeProfile"])
        self.assertEqual(acknowledgment["permitId"], attempt["admission"]["permitId"])
        self.assertEqual(acknowledgment["status"], "command_accepted")
        self.assertNotIn("nativeCorrelation", acknowledgment)
        self.assertEqual(attempt["state"], "command_accepted")

    async def test_v2_completed_ack_releases_pending_capacity_and_expires(self):
        self.setup_messaging_v2_stock()
        self.store.max_rows = 1
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(result={"status": "command_accepted"})):
            await self.gateway.dispatch(delivery)
        self.assertEqual(self.store.status()["pending"], 0)
        self.assertIsNone(self.store.status()["blockedReason"])
        next_event = dict(self.event, eventId=str(uuid.uuid4()), attemptId=str(uuid.uuid4()))
        next_event["deliveryId"] = messaging_protocol_v2.derive_delivery_id(next_event)
        self.store.accept(next_event)
        self.assertEqual(self.store.status()["pending"], 1)
        self.now += 8 * 86400
        self.store.cleanup()
        self.assertIsNone(self.store.delivery(delivery))
        self.assertIsNone(self.store.current_attempt(delivery))

    async def test_v2_lost_ack_remains_pending_and_retained_until_exact_retry(self):
        self.setup_messaging_v2_stock()
        self.store.max_rows = 1
        self.authority.drop_ack = True
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(result={"status": "command_accepted"})) as submit:
            await self.gateway.dispatch(delivery)
            self.assertEqual(self.store.status()["pending"], 1)
            self.now += 8 * 86400
            self.store.cleanup()
            self.assertIsNotNone(self.store.delivery(delivery))
            self.assertIsNotNone(self.store.current_attempt(delivery))
            await self.gateway.reconcile(delivery)
        self.assert_stock_submit_once(submit)
        self.assertEqual(self.authority.acks[0], self.authority.acks[1])
        self.assertEqual(self.store.status()["pending"], 0)

    async def test_v2_no_start_retries_settlement_before_any_new_client_submission(self):
        self.setup_messaging_v2_stock()
        delivery = self.accept()
        self.authority.fail_settlement_once = True
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(error=StockCodexError("client_not_started"))) as submit:
            result = await self.gateway.dispatch(delivery)
            self.assertEqual(result["status"], "settlement_pending")
            attempt_id = self.store.current_attempt(delivery)["attempt_id"]
            self.restart()
            recovered = await self.gateway.reconcile(delivery)
        self.assert_stock_submit_once(submit)
        self.assertEqual(recovered["status"], "held")
        self.assertIsNone(self.store.current_attempt(delivery))
        self.assertNotEqual(self.store.delivery_envelope(delivery)["attemptId"], attempt_id)
        self.assertEqual(self.authority.settlements[0], self.authority.settlements[1])
        self.assertEqual(self.authority.acks, [])

    async def test_v2_definitive_claim_refusal_releases_capacity_and_expires(self):
        self.setup_messaging_v2_stock()
        self.store.max_rows = 1
        delivery = self.accept()
        refusal = CloudError("denied", definitive_refusal=True)
        with patch.object(self.authority, "claim", side_effect=refusal):
            self.assertEqual((await self.gateway.dispatch(delivery))["status"], "stale")
        self.assertEqual(self.store.status()["pending"], 0)
        self.assertTrue(self.store.accept(self.event)["duplicate"])
        self.restart()
        self.assertEqual(self.store.status()["pending"], 0)
        self.now += 8 * 86400
        self.assertEqual(self.store.cleanup(), 1)
        self.assertIsNone(self.store.current_attempt(delivery))

    async def test_v2_definitive_refusal_cannot_release_prior_claim_uncertainty(self):
        self.setup_messaging_v2_stock()
        refusal = CloudError("denied", definitive_refusal=True)
        uncertain = self.accept()
        with patch.object(self.authority, "claim", side_effect=TimeoutError()):
            await self.gateway.dispatch(uncertain)
        with patch.object(self.authority, "claim", side_effect=refusal):
            self.assertEqual((await self.gateway.reconcile(uncertain))["status"], "claiming")
        self.now += 8 * 86400
        self.store.cleanup()
        self.assertEqual(self.store.status()["pending"], 1)
        self.assertEqual(self.store.current_attempt(uncertain)["claim_uncertain"], 1)
        self.assertEqual(self.authority.acks, [])
        self.assertEqual(self.authority.settlements, [])

    async def test_v2_claim_refusal_survives_detach_for_capacity_and_retention(self):
        self.setup_messaging_v2_stock()
        self.store.max_rows = 1
        delivery = self.accept()
        refusal = CloudError("denied", definitive_refusal=True)
        with patch.object(self.authority, "claim", side_effect=refusal):
            await self.gateway.dispatch(delivery)
        self.assertEqual(self.store.current_attempt(delivery)["reason"], "claim_refused")
        self.assertEqual(self.store.accept(copy.deepcopy(self.event))["duplicate"], True)
        self.store.detach(self.event["runtimeId"])
        self.assertEqual(self.store.status()["pending"], 0)
        self.assertEqual(self.store.get(delivery)["reason"], "claim_refused")
        self.assertEqual(self.store.current_attempt(delivery)["reason"], "claim_refused")
        self.restart()
        self.assertEqual(self.store.status()["pending"], 0)
        self.now += 8 * 86400
        self.assertEqual(self.store.cleanup(), 1)
        self.assertIsNone(self.store.get(delivery))

    async def test_v2_claim_refusal_survives_attachment_replacement(self):
        self.setup_messaging_v2_stock()
        self.store.max_rows = 1
        delivery = self.accept()
        refusal = CloudError("denied", definitive_refusal=True)
        with patch.object(self.authority, "claim", side_effect=refusal):
            await self.gateway.dispatch(delivery)
        self.assertTrue(self.store.accept(copy.deepcopy(self.event))["duplicate"])

        replacement_profile = dict(self.mapping["runtimeProfile"], conversationId=str(uuid.uuid4()))
        replacement = dict(
            self.mapping,
            runtimeGeneration=self.mapping["runtimeGeneration"] + 1,
            attachmentGeneration=self.mapping["attachmentGeneration"] + 1,
            consumerGeneration=self.mapping["consumerGeneration"] + 1,
            routingGeneration=self.mapping["routingGeneration"] + 1,
            runtimeProfile=replacement_profile,
            leaseExpiresAt=self.now + 3600,
        )
        self.store.put_messaging_attachment(replacement)
        attempt = self.store.current_attempt(delivery)
        self.assertEqual((attempt["state"], attempt["reason"]), ("stale", "claim_refused"))
        self.assertEqual(self.store.status()["pending"], 0)
        self.assertTrue(self.store.get(delivery) is not None)

        next_event = copy.deepcopy(self.event)
        next_event.update(
            eventId=str(uuid.uuid4()),
            attemptId=str(uuid.uuid4()),
            runtimeGeneration=replacement["runtimeGeneration"],
            attachmentGeneration=replacement["attachmentGeneration"],
            consumerGeneration=replacement["consumerGeneration"],
            routingGeneration=replacement["routingGeneration"],
            runtimeProfile=replacement_profile,
        )
        next_event["deliveryId"] = messaging_protocol_v2.derive_delivery_id(next_event)
        self.store.max_rows = 1
        next_delivery = self.store.accept(next_event)["deliveryId"]
        self.assertEqual(self.store.status()["pending"], 1)
        self.assertTrue(self.store.get(delivery) is not None)
        self.restart()
        self.assertEqual(self.store.status()["pending"], 1)
        self.now += 8 * 86400
        self.assertEqual(self.store.cleanup(), 1)
        self.assertIsNone(self.store.get(delivery))
        self.assertIsNotNone(self.store.get(next_delivery))

    async def test_v2_uncertain_claim_remains_an_obligation_after_detach(self):
        self.setup_messaging_v2_stock()
        delivery = self.accept()
        with patch.object(self.authority, "claim", side_effect=TimeoutError()):
            await self.gateway.dispatch(delivery)
        self.store.detach(self.event["runtimeId"])
        self.assertEqual(self.store.current_attempt(delivery)["state"], "claiming")
        self.assertEqual(self.store.current_attempt(delivery)["claim_uncertain"], 1)
        self.assertEqual(self.store.status()["pending"], 1)
        self.now += 8 * 86400
        self.store.cleanup()
        self.assertIsNotNone(self.store.get(delivery))
        self.assertEqual(self.store.status()["pending"], 1)
        self.assertEqual(self.authority.acks, [])
        self.assertEqual(self.authority.settlements, [])

    async def test_v2_stock_unknown_restart_does_not_replay_codex(self):
        self.setup_messaging_v2_stock()
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(error=TimeoutError("lost CLI response"))) as submit:
            self.assertEqual((await self.gateway.dispatch(delivery))["status"], "ambiguous")
            self.restart()
            self.assertEqual((await self.gateway.reconcile(delivery))["status"], "ambiguous")
        submit.assert_awaited_once()
        self.assertEqual(self.authority.acks, [])

    async def test_v2_ambiguous_stock_recovery_survives_restart_and_detach(self):
        self.setup_messaging_v2_stock()
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(error=TimeoutError("lost CLI response"))) as submit:
            self.assertEqual((await self.gateway.dispatch(delivery))["status"], "ambiguous")
            self.restart()
            self.store.detach(self.event["runtimeId"])
            self.assertEqual((await self.gateway.reconcile(delivery))["status"], "ambiguous")
        submit.assert_awaited_once()
        summary = self.store.list_stock_recovery(delivery_id=delivery)
        self.assertEqual(summary["truncated"], False)
        item, = summary["deliveries"]
        self.assertEqual(item["deliveryId"], delivery)
        self.assertEqual(item["attemptId"], self.event["attemptId"])
        self.assertEqual(item["conversationId"], self.event["runtimeProfile"]["conversationId"])
        self.assertEqual(item["machineState"], "unknown")
        self.assertEqual(item["cloudObligation"], "unresolved")

        before = self.store.current_attempt(delivery)
        first = self.store.abandon_stock_delivery(delivery, item["attemptId"], item["expectedIdentitySha256"])
        second = self.store.abandon_stock_delivery(delivery, item["attemptId"], item["expectedIdentitySha256"])
        after = self.store.current_attempt(delivery)
        self.assertEqual(first, second)
        self.assertEqual(first["action"], "abandoned")
        self.assertEqual(first["cloudObligation"], "unresolved")
        self.assertEqual(self.store.get(delivery)["status"], "ambiguous")
        self.assertEqual(after["native_ack"], before["native_ack"])
        self.assertEqual(after["reserved_bytes"], before["reserved_bytes"])
        self.assertEqual(self.authority.acks, [])
        self.assertEqual(self.authority.settlements, [])

    async def test_v2_stock_recovery_identity_binds_all_message_and_destination_fields(self):
        self.setup_messaging_v2_stock()
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(error=TimeoutError("lost CLI response"))):
            await self.gateway.dispatch(delivery)
        attempt = self.store.current_attempt(delivery)
        base = self.store._stock_recovery_identity(
            attempt["envelope"], attempt["admission"], now_ms=self.now * 1000,
        )
        self.assertIsNotNone(base)
        original_digest = base[1]
        changes = (
            ("runtimeProfile", lambda event: event["runtimeProfile"].update(conversationId=str(uuid.uuid4())), None),
            ("namespace", lambda event: event["canonicalSubject"].update(namespace="changed.example"), None),
            ("messageId", lambda event: event["canonicalSubject"].update(messageId=str(uuid.uuid4())), None),
            ("agentIncarnation", lambda event: event["canonicalSubject"].update(agentIncarnation=event["canonicalSubject"]["agentIncarnation"] + 1), None),
            ("sourceStateVersion", lambda event: event.update(sourceStateVersion="msg:" + "b" * 64), None),
            ("routingGeneration", lambda event: event.update(routingGeneration=event["routingGeneration"] + 1), None),
            ("nodeId", lambda event: event.update(nodeId=str(uuid.uuid4())), None),
            ("nodeGeneration", lambda event: event.update(nodeGeneration=event["nodeGeneration"] + 1), None),
            ("runtimeGeneration", lambda event: event.update(runtimeGeneration=event["runtimeGeneration"] + 1), None),
            ("attachmentGeneration", lambda event: event.update(
                attachmentGeneration=event["attachmentGeneration"] + 1,
                consumerGeneration=event["consumerGeneration"] + 1,
            ), None),
            ("permitId", lambda _event: None, lambda admission: admission.update(permitId=str(uuid.uuid4()))),
            ("permitIssuedAt", lambda event: event.update(
                issuedAt=_iso(self.now - 1), expiresAt=_iso(self.now + 59),
            ), lambda admission: (
                admission.update(permitIssuedAt=_iso(self.now - 1), permitExpiresAt=_iso(self.now + 4)),
                admission["envelope"].update(issuedAt=_iso(self.now - 1), expiresAt=_iso(self.now + 59)),
            )),
            ("permitExpiresAt", lambda event: event.update(
                issuedAt=_iso(self.now - 1), expiresAt=_iso(self.now + 59),
            ), lambda admission: (
                admission.update(permitIssuedAt=_iso(self.now - 1), permitExpiresAt=_iso(self.now + 4)),
                admission["envelope"].update(issuedAt=_iso(self.now - 1), expiresAt=_iso(self.now + 59)),
            )),
        )
        for label, change_event, change_admission in changes:
            with self.subTest(field=label):
                changed = copy.deepcopy(attempt["envelope"])
                change_event(changed)
                changed["deliveryId"] = messaging_protocol_v2.derive_delivery_id(changed)
                changed_admission = copy.deepcopy(attempt["admission"])
                changed_admission["nodeId"] = changed["nodeId"]
                changed_admission["envelope"] = copy.deepcopy(changed)
                if change_admission:
                    change_admission(changed_admission)
                identity = self.store._stock_recovery_identity(
                    changed, changed_admission, now_ms=self.now * 1000,
                )
                self.assertIsNotNone(identity)
                self.assertNotEqual(identity[1], original_digest)
                self.store.db.execute(
                    "UPDATE deliveries SET envelope=? WHERE id=?",
                    (json.dumps(changed), delivery),
                )
                self.store.db.execute(
                    "UPDATE attempts SET envelope=?, admission=? WHERE delivery_id=?",
                    (json.dumps(changed), json.dumps(changed_admission), delivery),
                )
                self.store.db.commit()
                with self.assertRaisesRegex(StoreError, "^stale_recovery_identity$"):
                    self.store.abandon_stock_delivery(delivery, attempt["attempt_id"], original_digest)
                self.store.db.execute(
                    "UPDATE deliveries SET envelope=? WHERE id=?",
                    (json.dumps(attempt["envelope"]), delivery),
                )
                self.store.db.execute(
                    "UPDATE attempts SET envelope=?, admission=? WHERE delivery_id=?",
                    (json.dumps(attempt["envelope"]), json.dumps(attempt["admission"]), delivery),
                )
                self.store.db.commit()

    async def test_v2_stock_lost_cloud_ack_retries_exact_ack_after_restart(self):
        self.setup_messaging_v2_stock()
        delivery = self.accept()
        self.authority.drop_ack = True
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(result={"status": "command_accepted"})) as submit:
            self.assertEqual((await self.gateway.dispatch(delivery))["reason"], "stock_ack_pending")
            stored_ack = self.store.current_attempt(delivery)["native_ack"]
            self.restart()
            self.assertEqual((await self.gateway.reconcile(delivery))["status"], "command_accepted")
        submit.assert_awaited_once()
        self.assertEqual(self.authority.acks, [stored_ack, stored_ack])

    async def test_duplicate_and_command_acceptance_never_relaunch(self):
        delivery = self.accept()
        duplicate = self.store.accept(copy.deepcopy(self.event))
        self.assertTrue(duplicate["duplicate"])
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(result={"status": "command_accepted"})) as submit:
            result = await self.gateway.dispatch(delivery)
            again = await self.gateway.dispatch(delivery)
        self.assertEqual(result["status"], "command_accepted")
        self.assertEqual(again["status"], "command_accepted")
        self.assert_stock_submit_once(submit)
        attempt = self.store.current_attempt(delivery)
        self.assertEqual(attempt["state"], "command_accepted")
        self.assertEqual(attempt["native_ack"]["status"], "command_accepted")
        self.assertNotIn("nativeCorrelation", attempt["native_ack"])
        self.assertEqual(self.store.list_pending(), [])

    async def test_stock_only_gateway_delivers_valid_stock_event_once(self):
        delivery = self.accept()
        self.gateway.stock_only = True
        submit_mock = self.stock_submit_mock(result={"status": "command_accepted"})
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit", new=submit_mock):
            result = await self.gateway.dispatch(delivery)
        self.assertEqual(result["status"], "command_accepted")
        self.assert_stock_submit_once(submit_mock)
        self.assertEqual(len(self.authority.acks), 1)
        self.assertEqual(self.authority.acks[0]["status"], "command_accepted")
        self.assertEqual(self.store.current_attempt(delivery)["native_ack"]["status"], "command_accepted")

    async def test_lost_ack_survives_restart_and_retries_only_the_stored_ack(self):
        delivery = self.accept()
        self.authority.drop_ack = True
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(result={"status": "command_accepted"})) as submit:
            self.assertEqual((await self.gateway.dispatch(delivery))["reason"], "stock_ack_pending")
            stored_ack = self.store.current_attempt(delivery)["native_ack"]
            self.restart()
            self.assertEqual((await self.gateway.reconcile(delivery))["status"], "command_accepted")
        submit.assert_awaited_once()
        self.assertEqual(self.authority.acks, [stored_ack, stored_ack])

    async def test_reconcile_does_not_resend_completed_stock_ack(self):
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(result={"status": "command_accepted"})) as submit:
            self.assertEqual((await self.gateway.dispatch(delivery))["status"], "command_accepted")
            self.assertEqual((await self.gateway.reconcile(delivery))["status"], "command_accepted")
        self.assert_stock_submit_once(submit)
        self.assertEqual(len(self.authority.acks), 1)

    async def test_github_stock_event_lost_ack_recovery_launches_once(self):
        github = next(event for event in FIXTURES["validEnvelopes"] if event["source"] == "github")
        self.event = copy.deepcopy(github)
        self.event["runtimeProfile"] = copy.deepcopy(EVENT["runtimeProfile"])
        self.event["consumerGeneration"] = self.event["attachmentGeneration"]
        self.event["deliveryId"] = derive_delivery_id(self.event)
        self.mapping = {key: self.event[key] for key in IDENTITY}
        self.mapping.update(consumerGeneration=self.event["consumerGeneration"],
                            runtimeProfile=self.event["runtimeProfile"],
                            leaseExpiresAt=self.now + 3600)
        self.store.put_attachment(self.mapping)
        delivery = self.accept()
        self.authority.drop_ack = True
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(result={"status": "command_accepted"})) as submit:
            self.assertEqual((await self.gateway.dispatch(delivery))["reason"], "stock_ack_pending")
            stored_ack = self.store.current_attempt(delivery)["native_ack"]
            self.restart()
            self.assertEqual((await self.gateway.reconcile(delivery))["status"], "command_accepted")
        self.assert_stock_submit_once(submit)
        self.assertEqual(self.authority.acks, [stored_ack, stored_ack])

    async def test_timeout_after_launch_is_ambiguous_and_never_replayed_after_restart(self):
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(error=TimeoutError("lost CLI response"))) as submit:
            self.assertEqual((await self.gateway.dispatch(delivery))["status"], "ambiguous")
            self.restart()
            self.assertEqual((await self.gateway.reconcile(delivery))["status"], "ambiguous")
        submit.assert_awaited_once()
        self.assertEqual(self.authority.acks, [])

    async def test_ambiguous_stock_delivery_can_be_locally_abandoned_without_settlement(self):
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(error=TimeoutError("lost CLI response"))) as submit:
            self.assertEqual((await self.gateway.dispatch(delivery))["status"], "ambiguous")
        submit.assert_awaited_once()
        summary = self.store.list_stock_recovery()
        self.assertFalse(summary["truncated"])
        item = summary["deliveries"][0]
        self.assertEqual(item["deliveryId"], delivery)
        self.assertEqual(item["attemptId"], self.event["attemptId"])
        self.assertEqual(item["conversationId"], self.event["runtimeProfile"]["conversationId"])
        self.assertEqual(item["machineState"], "unknown")
        self.assertEqual(item["cloudObligation"], "unresolved")
        attempt_before = self.store.current_attempt(delivery)
        with self.assertRaisesRegex(StoreError, "^stale_recovery_identity$"):
            self.store.abandon_stock_delivery(
                delivery, item["attemptId"], "0" * 64,
            )
        with self.assertRaisesRegex(StoreError, "^not_found$"):
            self.store.abandon_stock_delivery(
                delivery, str(uuid.uuid4()), item["expectedIdentitySha256"],
            )

        first = self.store.abandon_stock_delivery(
            delivery, item["attemptId"], item["expectedIdentitySha256"],
        )
        second = self.store.abandon_stock_delivery(
            delivery, item["attemptId"], item["expectedIdentitySha256"],
        )
        attempt_after = self.store.current_attempt(delivery)
        self.assertEqual(first, second)
        self.assertEqual(first["action"], "abandoned")
        self.assertEqual(first["machineState"], "unknown")
        self.assertEqual(first["cloudObligation"], "unresolved")
        self.assertEqual(self.store.get(delivery)["status"], "ambiguous")
        self.assertEqual(attempt_after["native_request"], attempt_before["native_request"])
        self.assertEqual(attempt_after["evidence"], attempt_before["evidence"])
        self.assertEqual(attempt_after["reserved_bytes"], attempt_before["reserved_bytes"])
        self.assertEqual(len(self.authority.acks), 0)
        self.assertEqual(len(self.authority.settlements), 0)
        listed_again = self.store.list_stock_recovery()["deliveries"][0]
        self.assertEqual(listed_again["operatorDisposition"], first)

    async def test_stock_recovery_listing_skips_malformed_runtime_profile_without_leaking(self):
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(error=TimeoutError("lost CLI response"))):
            self.assertEqual((await self.gateway.dispatch(delivery))["status"], "ambiguous")
        attempt = self.store.current_attempt(delivery)
        malformed = copy.deepcopy(attempt["envelope"])
        malformed_profile = dict(malformed["runtimeProfile"])
        malformed_profile.pop("conversationId")
        malformed["runtimeProfile"] = malformed_profile
        admission = copy.deepcopy(attempt["admission"])
        admission["envelope"]["runtimeProfile"] = malformed_profile
        self.store.db.execute(
            "UPDATE attempts SET envelope=?, admission=? WHERE delivery_id=?",
            (json.dumps(malformed), json.dumps(admission), delivery),
        )

        result = self.store.list_stock_recovery(delivery_id=delivery)

        self.assertEqual(result, {"deliveries": [], "truncated": False})
        self.assertNotIn("conversationId", json.dumps(result))

    async def test_crash_before_and_after_client_send_recover_as_ambiguous(self):
        class Crash(BaseException):
            pass

        for launched in (False, True):
            with self.subTest(launched=launched):
                self.event = copy.deepcopy(EVENT)
                self.event["eventId"] = str(uuid.uuid4())
                self.event["runtimeProfile"]["conversationId"] = str(uuid.uuid4())
                self.event["runtimeGeneration"] = self.mapping["runtimeGeneration"] + 1
                self.event["attachmentGeneration"] = self.mapping["attachmentGeneration"] + 1
                self.event["consumerGeneration"] = self.mapping["consumerGeneration"] + 1
                self.event["deliveryId"] = derive_delivery_id(self.event)
                self.mapping = {key: self.event[key] for key in IDENTITY}
                self.mapping.update(consumerGeneration=self.event["consumerGeneration"],
                                    runtimeProfile=self.event["runtimeProfile"],
                                    leaseExpiresAt=self.now + 3600)
                self.store.put_attachment(self.mapping)
                delivery = self.accept()
                calls = []

                async def crash(_adapter, _reference, *, before_start=None):
                    if before_start is not None:
                        before_start()
                    if launched:
                        calls.append("sent")
                    raise Crash()

                with patch("event_gateway.stock_codex.StockCodexAdapter.submit", new=crash):
                    with self.assertRaises(Crash):
                        await self.gateway.dispatch(delivery)
                self.assertEqual(self.store.get(delivery)["status"], "submitting")
                self.restart()
                self.assertEqual(self.store.get(delivery)["status"], "ambiguous")
                with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                           new=self.stock_submit_mock(result={"status": "command_accepted"})) as submit:
                    await self.gateway.reconcile(delivery)
                submit.assert_not_awaited()
                self.assertEqual(calls, ["sent"] if launched else [])

    async def test_claim_time_assignment_change_prevents_launch(self):
        delivery = self.accept()

        def rotate_assignment():
            changed = dict(self.mapping, runtimeGeneration=self.mapping["runtimeGeneration"] + 1,
                           attachmentGeneration=self.mapping["attachmentGeneration"] + 1,
                           consumerGeneration=self.mapping["consumerGeneration"] + 1,
                           runtimeProfile={**self.mapping["runtimeProfile"],
                                           "conversationId": "12345678-1234-4234-8234-123456789abc"})
            self.store.put_attachment(changed)

        self.authority.on_claim = rotate_assignment
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock()) as submit:
            result = await self.gateway.dispatch(delivery)
        self.assertEqual(result["status"], "stale")
        self.assertEqual(submit.await_count, 1)

    async def test_assignment_change_while_preflight_blocked_prevents_spawn(self):
        for loss in ("detach", "reassign"):
            with self.subTest(loss=loss):
                delivery = self.new_delivery()
                preflight_started, release_preflight = Event(), Event()

                def blocked_preflight(_binary):
                    preflight_started.set()
                    if not release_preflight.wait(timeout=3):
                        raise AssertionError("test did not release binary preflight")
                    return True

                process = type("Process", (), {"wait": AsyncMock(return_value=0)})()
                with patch("event_gateway.stock_codex._binary_is_executable",
                           side_effect=blocked_preflight), \
                        patch("asyncio.create_subprocess_exec",
                              new=AsyncMock(return_value=process)) as spawn:
                    dispatch = asyncio.create_task(self.gateway.dispatch(delivery))
                    try:
                        for _ in range(100):
                            if preflight_started.is_set():
                                break
                            await asyncio.sleep(0.01)
                        self.assertTrue(preflight_started.is_set())
                        if loss == "detach":
                            self.store.detach(self.event["runtimeId"])
                        else:
                            changed = dict(
                                self.mapping,
                                runtimeGeneration=self.mapping["runtimeGeneration"] + 1,
                                attachmentGeneration=self.mapping["attachmentGeneration"] + 1,
                                consumerGeneration=self.mapping["consumerGeneration"] + 1,
                                runtimeProfile={**self.mapping["runtimeProfile"],
                                                "conversationId": str(uuid.uuid4())},
                            )
                            self.store.put_attachment(changed)
                            self.mapping = changed
                    finally:
                        release_preflight.set()
                    result = await dispatch
                spawn.assert_not_awaited()
                self.assertEqual(result["status"], "stale")
                attempt = self.store.current_attempt(delivery)
                self.assertEqual(attempt["state"], "settled")
                self.assertEqual(attempt["settlement"]["status"], "not_started")

    async def test_sqlite_start_fence_failure_settles_admitted_without_spawning(self):
        delivery = self.accept()
        with patch.object(self.store, "begin_stock_submit",
                          side_effect=sqlite3.OperationalError("database is locked")), \
                patch("asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
            result = await self.gateway.dispatch(delivery)
        spawn.assert_not_awaited()
        self.assertEqual(result["status"], "queued")
        self.assertEqual(self.authority.settlements[-1][1], {"type": "local_not_submitted"})
        self.assertIsNone(self.store.current_attempt(delivery))

    async def test_sqlite_start_fence_commit_uncertainty_never_settles_submitting(self):
        delivery = self.accept()
        begin_stock_submit = self.store.begin_stock_submit

        def commit_then_fail(delivery_id, attempt_id):
            begin_stock_submit(delivery_id, attempt_id)
            raise sqlite3.OperationalError("commit result unknown")

        with patch.object(self.store, "begin_stock_submit", side_effect=commit_then_fail), \
                patch("asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
            result = await self.gateway.dispatch(delivery)
            reconciled = await self.gateway.reconcile(delivery)
        spawn.assert_not_awaited()
        self.assertEqual(result["reason"], "client_start_fence_uncertain")
        self.assertEqual(reconciled["status"], "submitting")
        self.assertEqual(self.store.current_attempt(delivery)["state"], "submitting")
        self.assertEqual(self.authority.settlements, [])

    async def test_start_fence_store_error_after_commit_cannot_settle_submitting(self):
        delivery = self.accept()
        begin_stock_submit = self.store.begin_stock_submit

        def commit_then_store_error(delivery_id, attempt_id):
            begin_stock_submit(delivery_id, attempt_id)
            raise StoreError("transition result unknown")

        with patch.object(self.store, "begin_stock_submit", side_effect=commit_then_store_error), \
                patch("asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
            result = await self.gateway.dispatch(delivery)
        spawn.assert_not_awaited()
        self.assertEqual(result["reason"], "local_retirement_pending")
        self.assertEqual(self.store.current_attempt(delivery)["state"], "submitting")
        self.assertEqual(self.authority.settlements, [])

    async def test_sqlite_start_fence_reread_failure_returns_recoverable_diagnostic(self):
        delivery = self.accept()
        begin_stock_submit = self.store.begin_stock_submit
        current_attempt = self.store.current_attempt
        fail_reread = False

        def commit_then_fail(delivery_id, attempt_id):
            nonlocal fail_reread
            begin_stock_submit(delivery_id, attempt_id)
            fail_reread = True
            raise sqlite3.OperationalError("commit result unknown")

        def current_attempt_or_fail(delivery_id):
            if fail_reread:
                raise sqlite3.OperationalError("database is locked")
            return current_attempt(delivery_id)

        with patch.object(self.store, "begin_stock_submit", side_effect=commit_then_fail), \
                patch.object(self.store, "current_attempt", side_effect=current_attempt_or_fail), \
                patch("asyncio.create_subprocess_exec", new=AsyncMock()) as spawn:
            result = await self.gateway.dispatch(delivery)
        spawn.assert_not_awaited()
        self.assertEqual(result, {"deliveryId": delivery, "status": "unknown",
                                  "reason": "client_start_fence_uncertain"})
        self.assertEqual(self.store.current_attempt(delivery)["state"], "submitting")
        self.assertEqual(self.authority.settlements, [])

    async def test_expired_or_detached_persisted_claim_is_resolved_before_mapping_check(self):
        for loss in ("expired", "detach"):
            with self.subTest(loss=loss):
                delivery = self.new_delivery()
                self.assertTrue(self.store.begin_claim(delivery))
                self.restart()
                self.lose_assignment(loss)
                claim_count = len(self.authority.claims)
                settlement_count = len(self.authority.settlements)
                with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                           new=self.stock_submit_mock()) as submit:
                    result = await self.gateway.reconcile(delivery)
                self.assertEqual(submit.await_count, 1)
                self.assertEqual(len(self.authority.claims), claim_count + 1)
                self.assertEqual(len(self.authority.settlements), settlement_count + 1)
                self.assertEqual(self.authority.settlements[-1][1], {"type": "local_not_submitted"})
                attempt = self.store.current_attempt(delivery)
                self.assertEqual(attempt["state"], "settled")
                self.assertEqual(attempt["settlement"]["status"], "not_started")
                self.assertEqual(result["status"], "stale")
                self.assertFalse(any(row["deliveryId"] == delivery for row in self.store.list_reconcilable()))
                self.now = NOW

    async def test_expired_or_detached_persisted_admission_settles_before_mapping_check(self):
        for loss in ("expired", "detach"):
            with self.subTest(loss=loss):
                delivery = self.new_delivery()
                self.assertTrue(self.store.begin_claim(delivery))
                admission = await self.authority.claim(self.event)
                self.store.record_admission(delivery, admission)
                self.restart()
                claim_count = len(self.authority.claims)
                settlement_count = len(self.authority.settlements)
                self.lose_assignment(loss)
                with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                           new=self.stock_submit_mock()) as submit:
                    result = await self.gateway.reconcile(delivery)
                self.assertEqual(submit.await_count, 1)
                self.assertEqual(len(self.authority.claims), claim_count)
                self.assertEqual(len(self.authority.settlements), settlement_count + 1)
                self.assertEqual(self.authority.settlements[-1][1], {"type": "local_not_submitted"})
                attempt = self.store.current_attempt(delivery)
                self.assertEqual(attempt["state"], "settled")
                self.assertEqual(attempt["settlement"]["status"], "not_started")
                self.assertEqual(result["status"], "stale")
                self.assertFalse(any(row["deliveryId"] == delivery for row in self.store.list_reconcilable()))
                self.now = NOW

    async def test_definite_prelaunch_failure_uses_no_start_settlement_and_never_relaunches_pending_attempt(self):
        delivery = self.accept()
        self.authority.fail_settlement_once = True
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(error=StockCodexError("client_not_started"))) as submit:
            result = await self.gateway.dispatch(delivery)
            self.assertEqual(result["status"], "settlement_pending")
            attempt = self.store.current_attempt(delivery)
            self.assertEqual(attempt["state"], "settlement_pending")
            self.assertEqual(attempt["evidence"], {"type": "local_not_submitted"})
            self.assertIsNone(attempt["native_request"])
            self.assertIsNone(attempt["native_ack"])
            self.restart()
            recovered = await self.gateway.reconcile(delivery)
        self.assertEqual(recovered["status"], "queued")
        self.assert_stock_submit_once(submit)
        self.assertEqual([evidence for _, evidence in self.authority.settlements],
                         [{"type": "local_not_submitted"}] * 2)
        self.assertIsNone(self.store.current_attempt(delivery))
        self.assertEqual(self.gateway._row(delivery)["status"], "queued")

    async def test_preflight_cancellation_persists_no_start_without_cloud_wait_and_recovers(self):
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(error=StockCodexPreflightCancelled())) as submit:
            task = asyncio.create_task(self.gateway.dispatch(delivery))
            with self.assertRaises(StockCodexPreflightCancelled):
                await task
            self.assertTrue(task.cancelled())
            attempt = self.store.current_attempt(delivery)
            self.assertEqual(attempt["state"], "settlement_pending")
            self.assertEqual(attempt["evidence"], {"type": "local_not_submitted"})
            self.assertEqual(self.authority.settlements, [])
            self.restart()
            self.authority.fail_settlement_once = True
            pending = await self.gateway.reconcile(delivery)
            self.assertEqual(pending["status"], "settlement_pending")
            settled = await self.gateway.reconcile(delivery)
        self.assert_stock_submit_once(submit)
        self.assertEqual(settled["status"], "queued")
        self.assertEqual(len(self.authority.settlements), 2)
        self.assertTrue(all(evidence == {"type": "local_not_submitted"}
                            for _, evidence in self.authority.settlements))
        self.assertIsNone(self.store.current_attempt(delivery))

    async def test_preflight_cancellation_store_error_leaves_admitted_for_recovery(self):
        delivery = self.accept()
        with patch.object(self.store, "begin_settlement", side_effect=StoreError("store failure")) as begin:
            with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                       new=self.stock_submit_mock(error=StockCodexPreflightCancelled())) as submit:
                task = asyncio.create_task(self.gateway.dispatch(delivery))
                with self.assertRaises(StockCodexPreflightCancelled):
                    await task
        self.assertTrue(task.cancelled())
        begin.assert_called_once()
        self.assert_stock_submit_once(submit)
        attempt = self.store.current_attempt(delivery)
        self.assertEqual(attempt["state"], "admitted")
        self.assertIsNone(attempt["evidence"])
        self.assertEqual(self.authority.settlements, [])

    async def test_generic_stock_cancellation_remains_ambiguous(self):
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(error=asyncio.CancelledError())) as submit:
            with self.assertRaises(asyncio.CancelledError):
                await self.gateway.dispatch(delivery)
        self.assert_stock_submit_once(submit)
        self.assertEqual(self.store.current_attempt(delivery)["state"], "ambiguous")
        self.assertEqual(self.authority.settlements, [])

    async def test_disabled_stock_recovery_resolves_and_retires_persisted_attempts(self):
        for state in ("claiming", "admitted"):
            with self.subTest(state=state):
                delivery = self.new_delivery()
                self.assertTrue(self.store.begin_claim(delivery))
                if state == "admitted":
                    self.store.record_admission(delivery, await self.authority.claim(self.event))
                self.restart()
                self.gateway.stock_codex_binary = None
                claim_count = len(self.authority.claims)
                settlement_count = len(self.authority.settlements)
                with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                           new=self.stock_submit_mock()) as submit:
                    result = await self.gateway.reconcile(delivery)
                submit.assert_not_awaited()
                self.assertEqual(result["status"], "queued")
                self.assertEqual(len(self.authority.settlements), settlement_count + 1)
                self.assertEqual(self.authority.settlements[-1][1], {"type": "local_not_submitted"})
                self.assertEqual(len(self.authority.claims), claim_count + (state == "claiming"))
                self.assertIsNone(self.store.current_attempt(delivery))
                self.gateway.stock_codex_binary = "/opt/test/codex"

    async def test_disabled_stock_does_not_claim_fresh_delivery(self):
        delivery = self.accept()
        self.gateway.stock_codex_binary = None
        result = await self.gateway.dispatch(delivery)
        self.assertEqual(result["status"], "queued")
        self.assertEqual(result["reason"], "stock_client_disabled")
        self.assertEqual(self.authority.claims, [])
        self.assertIsNone(self.store.current_attempt(delivery))

    async def test_reconcile_does_not_dispatch_terminal_stock_row_without_attempt(self):
        delivery = self.accept()
        self.store.finish(delivery, "stale")
        with patch.object(self.gateway, "_dispatch_stock_locked", new=AsyncMock()) as dispatch:
            result = await self.gateway.reconcile(delivery)
        self.assertEqual(result["status"], "stale")
        dispatch.assert_not_awaited()

    async def test_expired_admission_prevents_launch(self):
        delivery = self.accept()
        claim = self.gateway._claim

        async def expire_after_claim(delivery_id):
            result = await claim(delivery_id)
            self.now += 6
            return result

        with patch.object(self.gateway, "_claim", expire_after_claim), \
                patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                      new=self.stock_submit_mock()) as submit:
            result = await self.gateway.dispatch(delivery)
        self.assertEqual(result["status"], "queued")
        self.assertEqual(self.authority.settlements[-1][1], {"type": "local_not_submitted"})
        submit.assert_not_awaited()

    async def test_accepted_result_write_failure_becomes_ambiguous(self):
        delivery = self.accept()
        self.store.db.execute("CREATE TRIGGER fail_stock_result BEFORE UPDATE ON deliveries "
                              "WHEN NEW.state='command_accepted' BEGIN SELECT RAISE(ABORT,'disk fault'); END")
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=self.stock_submit_mock(result={"status": "command_accepted"})) as submit:
            await self.gateway.dispatch(delivery)
            self.restart()
        submit.assert_awaited_once()
        self.assertEqual(self.store.get(delivery)["status"], "ambiguous")
        self.assertEqual((await self.gateway.reconcile(delivery))["status"], "ambiguous")


if __name__ == "__main__":
    unittest.main()
