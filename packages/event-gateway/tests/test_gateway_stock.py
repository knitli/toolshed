import asyncio
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
from event_gateway.store import IDENTITY, Store, StoreError
from event_gateway.stock_codex import StockCodexError, StockCodexPreflightCancelled


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = json.loads((ROOT / "contracts/event-v1/protocol-v1.json").read_text())
EVENT = next(event for event in FIXTURES["validEnvelopes"] if "runtimeProfile" in event)
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

    async def test_reconcile_does_not_resend_completed_stock_ack(self):
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=AsyncMock(return_value={"status": "command_accepted"})) as submit:
            self.assertEqual((await self.gateway.dispatch(delivery))["status"], "command_accepted")
            self.assertEqual((await self.gateway.reconcile(delivery))["status"], "command_accepted")
        submit.assert_awaited_once_with(self.event["eventReference"])
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
                           new=AsyncMock()) as submit:
                    result = await self.gateway.reconcile(delivery)
                submit.assert_not_awaited()
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
                           new=AsyncMock()) as submit:
                    result = await self.gateway.reconcile(delivery)
                submit.assert_not_awaited()
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
                   new=AsyncMock(side_effect=StockCodexError("client_not_started"))) as submit:
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
        submit.assert_awaited_once_with(self.event["eventReference"])
        self.assertEqual([evidence for _, evidence in self.authority.settlements],
                         [{"type": "local_not_submitted"}] * 2)
        self.assertIsNone(self.store.current_attempt(delivery))
        self.assertEqual(self.gateway._row(delivery)["status"], "queued")

    async def test_preflight_cancellation_persists_no_start_without_cloud_wait_and_recovers(self):
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=AsyncMock(side_effect=StockCodexPreflightCancelled)) as submit:
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
        submit.assert_awaited_once_with(self.event["eventReference"])
        self.assertEqual(settled["status"], "queued")
        self.assertEqual(len(self.authority.settlements), 2)
        self.assertTrue(all(evidence == {"type": "local_not_submitted"}
                            for _, evidence in self.authority.settlements))
        self.assertIsNone(self.store.current_attempt(delivery))

    async def test_preflight_cancellation_store_error_fails_closed_as_ambiguous(self):
        delivery = self.accept()
        with patch.object(self.store, "begin_settlement", side_effect=StoreError("store failure")) as begin:
            with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                       new=AsyncMock(side_effect=StockCodexPreflightCancelled)) as submit:
                task = asyncio.create_task(self.gateway.dispatch(delivery))
                with self.assertRaises(StockCodexPreflightCancelled):
                    await task
        self.assertTrue(task.cancelled())
        begin.assert_called_once()
        submit.assert_awaited_once_with(self.event["eventReference"])
        attempt = self.store.current_attempt(delivery)
        self.assertEqual(attempt["state"], "ambiguous")
        self.assertEqual(attempt["reason"], "client_outcome_unknown")
        self.assertIsNone(attempt["evidence"])
        self.assertEqual(self.authority.settlements, [])

    async def test_generic_stock_cancellation_remains_ambiguous(self):
        delivery = self.accept()
        with patch("event_gateway.stock_codex.StockCodexAdapter.submit",
                   new=AsyncMock(side_effect=asyncio.CancelledError)) as submit:
            with self.assertRaises(asyncio.CancelledError):
                await self.gateway.dispatch(delivery)
        submit.assert_awaited_once_with(self.event["eventReference"])
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
                           new=AsyncMock()) as submit:
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
