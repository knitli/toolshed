import copy
import json
from pathlib import Path
import tempfile
import unittest
import uuid
from unittest.mock import AsyncMock, patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from event_gateway.cloud import _iso
from event_gateway.gateway import Gateway
from event_gateway.protocol import derive_delivery_id
from event_gateway.store import IDENTITY, Store


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads((ROOT / "contracts/event-v1/protocol-v1.json").read_text())
EVENT = next(event for event in FIXTURES["validEnvelopes"] if "runtimeProfile" in event)
NOW = 1791201630


class Authority:
    def __init__(self, test):
        self.test = test
        self.claims = []
        self.acks = []
        self.on_claim = None
        self.drop_ack = False

    async def claim(self, envelope):
        self.claims.append(copy.deepcopy(envelope))
        if self.on_claim:
            self.on_claim()
        issued = _iso(self.test.now)
        return {
            "status": "admitted", "permitId": str(uuid.uuid4()),
            "nodeId": str(uuid.uuid4()), "permitIssuedAt": issued,
            "permitExpiresAt": _iso(self.test.now + 5), "envelope": copy.deepcopy(envelope),
        }

    async def acknowledge(self, envelope, acknowledgment):
        self.acks.append(copy.deepcopy(acknowledgment))
        if self.drop_ack:
            self.drop_ack = False
            raise TimeoutError("lost ACK response")
        return {"status": acknowledgment["status"], "current": False}

    async def settle_no_start(self, admission, evidence):
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

    async def test_duplicate_and_command_acceptance_never_relaunch(self):
        delivery = self.accept()
        duplicate = self.store.accept(copy.deepcopy(self.event))
        self.assertTrue(duplicate["duplicate"])
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=AsyncMock(return_value={"status": "command_accepted"})) as submit:
            result = await self.gateway.dispatch(delivery)
            again = await self.gateway.dispatch(delivery)
        self.assertEqual(result["status"], "command_accepted")
        self.assertEqual(again["status"], "command_accepted")
        submit.assert_awaited_once_with(self.event["eventReference"])
        attempt = self.store.current_attempt(delivery)
        self.assertEqual(attempt["state"], "command_accepted")
        self.assertEqual(attempt["native_ack"]["status"], "command_accepted")
        self.assertNotIn("nativeCorrelation", attempt["native_ack"])
        self.assertEqual(self.store.list_pending(), [])

    async def test_lost_ack_survives_restart_and_retries_only_the_stored_ack(self):
        delivery = self.accept()
        self.authority.drop_ack = True
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=AsyncMock(return_value={"status": "command_accepted"})) as submit:
            self.assertEqual((await self.gateway.dispatch(delivery))["reason"], "stock_ack_pending")
            stored_ack = self.store.current_attempt(delivery)["native_ack"]
            self.restart()
            self.assertEqual((await self.gateway.reconcile(delivery))["status"], "command_accepted")
        submit.assert_awaited_once()
        self.assertEqual(self.authority.acks, [stored_ack, stored_ack])

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
                   new=AsyncMock(return_value={"status": "command_accepted"})) as submit:
            self.assertEqual((await self.gateway.dispatch(delivery))["reason"], "stock_ack_pending")
            stored_ack = self.store.current_attempt(delivery)["native_ack"]
            self.restart()
            self.assertEqual((await self.gateway.reconcile(delivery))["status"], "command_accepted")
        submit.assert_awaited_once_with(self.event["eventReference"])
        self.assertEqual(self.authority.acks, [stored_ack, stored_ack])

    async def test_timeout_after_launch_is_ambiguous_and_never_replayed_after_restart(self):
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=AsyncMock(side_effect=TimeoutError("lost CLI response"))) as submit:
            self.assertEqual((await self.gateway.dispatch(delivery))["status"], "ambiguous")
            self.restart()
            self.assertEqual((await self.gateway.reconcile(delivery))["status"], "ambiguous")
        submit.assert_awaited_once()
        self.assertEqual(self.authority.acks, [])

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

                async def crash(_adapter, _reference):
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
                           new=AsyncMock(return_value={"status": "command_accepted"})) as submit:
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
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit", new=AsyncMock()) as submit:
            await self.gateway.dispatch(delivery)
        submit.assert_not_awaited()

    async def test_expired_admission_prevents_launch(self):
        delivery = self.accept()
        claim = self.gateway._claim

        async def expire_after_claim(delivery_id):
            result = await claim(delivery_id)
            self.now += 6
            return result

        with patch.object(self.gateway, "_claim", expire_after_claim), \
                patch("event_gateway.stock_codex.StockCodexAdapter.submit", new=AsyncMock()) as submit:
            await self.gateway.dispatch(delivery)
        submit.assert_not_awaited()

    async def test_accepted_result_write_failure_becomes_ambiguous(self):
        delivery = self.accept()
        self.store.db.execute("CREATE TRIGGER fail_stock_result BEFORE UPDATE ON deliveries "
                              "WHEN NEW.state='command_accepted' BEGIN SELECT RAISE(ABORT,'disk fault'); END")
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=AsyncMock(return_value={"status": "command_accepted"})) as submit:
            await self.gateway.dispatch(delivery)
            self.restart()
        submit.assert_awaited_once()
        self.assertEqual(self.store.get(delivery)["status"], "ambiguous")
        self.assertEqual((await self.gateway.reconcile(delivery))["status"], "ambiguous")


if __name__ == "__main__":
    unittest.main()
