"""Operator recovery for claimed Claude deliveries remains visible and non-replaying."""

import hashlib
import unittest

from event_gateway.store import Store, StoreError


class ClaudeOperatorRecoveryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from test_gateway_claude_channels import ClaudeChannelGatewayTests

        self.gateway_fixture = ClaudeChannelGatewayTests(methodName="runTest")
        self.gateway_fixture.setUp()
        self.addCleanup(self.gateway_fixture.doCleanups)

    async def claim_v2_delivery(self):
        fixture = self.gateway_fixture
        fixture.install_v2()
        delivery_id = await fixture.admit_and_claim()
        payload = fixture.store.claim_claude_handoff(
            fixture.event["runtimeId"], fixture.event["runtimeProfile"]["conversationId"],
        )["delivery"]
        self.assertIsNotNone(payload)
        return fixture, delivery_id, payload

    async def test_lost_claude_poll_is_visible_and_operator_disposition_preserves_receipt(self):
        fixture, delivery_id, payload = await self.claim_v2_delivery()
        store = fixture.store
        token_hash = hashlib.sha256(payload["receiptToken"].encode("ascii")).hexdigest()
        before = store.current_attempt(delivery_id)
        self.assertEqual(before["claude_receipt_hash"], token_hash)
        self.assertNotIn("receiptToken", before["claude_handoff"])
        self.assertEqual(before["claude_handoff"]["runtimeProfile"], fixture.event["runtimeProfile"])
        self.assertEqual(before["claude_handoff"]["messageId"],
                         fixture.event["canonicalSubject"]["messageId"])

        store.close()
        fixture.store = Store(fixture.path, clock=lambda: fixture.now)
        fixture.addCleanup(fixture.store.close)
        fixture.gateway.store = fixture.store
        store = fixture.store
        self.assertIsNone(store.claim_claude_handoff(
            fixture.event["runtimeId"], fixture.event["runtimeProfile"]["conversationId"],
        )["delivery"])

        recovery = store.list_stock_recovery(delivery_id=delivery_id)
        self.assertFalse(recovery["truncated"])
        self.assertNotIn(payload["receiptToken"], str(recovery))
        item, = recovery["deliveries"]
        self.assertEqual(item["expectedIdentitySha256"], store._stock_recovery_identity(
            fixture.event, store.current_attempt(delivery_id)["admission"],
            now_ms=fixture.now * 1000,
        )[1])
        before = store.current_attempt(delivery_id)
        wrong_digest = "0" * 64
        if wrong_digest == item["expectedIdentitySha256"]:
            wrong_digest = "1" * 64
        with self.assertRaisesRegex(StoreError, "^stale_recovery_identity$"):
            store.abandon_stock_delivery(delivery_id, fixture.event["attemptId"], wrong_digest)
        self.assertIsNone(store.current_attempt(delivery_id)["operator_disposition"])

        disposition = store.abandon_stock_delivery(
            delivery_id, fixture.event["attemptId"], item["expectedIdentitySha256"],
        )
        after = store.current_attempt(delivery_id)
        self.assertEqual(disposition["action"], "abandoned")
        self.assertEqual(after["state"], "claude_claimed")
        self.assertEqual(after["claude_receipt_hash"], before["claude_receipt_hash"])
        self.assertEqual(after["claude_handoff"], before["claude_handoff"])
        self.assertEqual(store.get(delivery_id)["status"], "ambiguous")
        self.assertIsNone(store.claim_claude_handoff(
            fixture.event["runtimeId"], fixture.event["runtimeProfile"]["conversationId"],
        )["delivery"])
        self.assertEqual(fixture.authority.acks, [])

    async def test_completed_claude_ack_leaves_reconciliation_queue(self):
        fixture, delivery_id, payload = await self.claim_v2_delivery()
        fixture.store.record_claude_client_reported(
            fixture.event["runtimeId"], fixture.event["runtimeProfile"]["conversationId"],
            delivery_id, fixture.event["attemptId"], payload["receiptToken"],
        )
        fixture.authority.fail_ack = True
        pending = await fixture.gateway.reconcile(delivery_id)
        self.assertEqual(pending["reason"], "client_reported_ack_pending")
        self.assertIn(delivery_id, {row["deliveryId"] for row in fixture.store.list_reconcilable()})

        completed = await fixture.gateway.reconcile(delivery_id)
        self.assertEqual(completed["status"], "client_reported")
        self.assertNotIn(delivery_id, {row["deliveryId"] for row in fixture.store.list_reconcilable()})


if __name__ == "__main__":
    unittest.main()
