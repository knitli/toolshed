"""Claude admission expiry must use the shared durable no-start settlement."""

import copy
import importlib
import unittest

_fixture_module = importlib.import_module("test_gateway_claude_channels")


class ClaudeAdmissionRecoveryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Reuse the existing Claude gateway/store fixture without inheriting its tests.
        self.fixture = _fixture_module.ClaudeChannelGatewayTests(
            "test_v1_claude_callback_is_explicit_and_acknowledged",
        )
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def install_settlement_authority(self, *, fail_once=False):
        fixture = self.fixture
        fixture.authority.settlements = []

        async def settle_no_start(admission, evidence):
            fixture.authority.settlements.append((copy.deepcopy(admission), copy.deepcopy(evidence)))
            if fail_once and len(fixture.authority.settlements) == 1:
                raise TimeoutError("lost settlement response")
            envelope = admission["envelope"]
            return {
                **{key: envelope[key] for key in ("deliveryId", "attemptId", "nodeGeneration")},
                "status": "not_started", "permitId": admission["permitId"],
                "nodeId": admission["nodeId"], "evidence": copy.deepcopy(evidence),
            }

        fixture.authority.settle_no_start = settle_no_start

    async def test_v1_expired_admission_without_handoff_uses_no_start_settlement(self):
        fixture = self.fixture
        self.install_settlement_authority()
        delivery_id = fixture.store.accept(copy.deepcopy(fixture.event))["deliveryId"]
        self.assertTrue(fixture.store.begin_claim(delivery_id))
        admission = await fixture.authority.claim(fixture.event)
        fixture.store.record_admission(delivery_id, admission)
        fixture.now = fixture.authority.now = fixture.now + 5

        result = await fixture.gateway.reconcile(delivery_id)

        self.assertEqual(result["status"], "queued")
        self.assertEqual(len(fixture.authority.settlements), 1)
        self.assertEqual(fixture.authority.settlements[0][1], {"type": "local_not_submitted"})
        self.assertIsNone(fixture.store.current_attempt(delivery_id))

    async def test_v2_expired_pending_handoff_retries_lost_settlement_without_polling(self):
        fixture = self.fixture
        fixture.install_v2()
        self.install_settlement_authority(fail_once=True)
        delivery_id = await fixture.admit_and_claim()
        attempt = fixture.store.current_attempt(delivery_id)
        self.assertEqual(attempt["state"], "admitted")
        self.assertIsNotNone(attempt["claude_handoff"])
        expired_at = attempt["admission"]["permitExpiresAt"]
        from event_gateway.protocol import _timestamp
        fixture.now = fixture.authority.now = _timestamp(expired_at) / 1000

        pending = await fixture.gateway.reconcile(delivery_id)

        self.assertEqual(pending["status"], "settlement_pending")
        self.assertEqual(fixture.store.current_attempt(delivery_id)["state"], "settlement_pending")
        self.assertEqual(len(fixture.authority.settlements), 1)
        self.assertIsNone(fixture.store.claim_claude_handoff(
            fixture.event["runtimeId"], fixture.event["runtimeProfile"]["conversationId"],
        )["delivery"])

        settled = await fixture.gateway.reconcile(delivery_id)

        self.assertEqual(settled["status"], "held")
        self.assertIsNone(fixture.store.current_attempt(delivery_id))
        self.assertEqual(len(fixture.authority.settlements), 2)
        self.assertEqual(fixture.authority.settlements[0], fixture.authority.settlements[1])
        self.assertEqual(fixture.authority.settlements[0][1], {"type": "local_not_submitted"})

    async def test_expired_claimed_claude_attempt_remains_unknown(self):
        fixture = self.fixture
        fixture.install_v2()
        self.install_settlement_authority()
        delivery_id = await fixture.admit_and_claim()
        claimed = fixture.store.claim_claude_handoff(
            fixture.event["runtimeId"], fixture.event["runtimeProfile"]["conversationId"],
        )["delivery"]
        from event_gateway.protocol import _timestamp
        fixture.now = fixture.authority.now = _timestamp(
            fixture.store.current_attempt(delivery_id)["admission"]["permitExpiresAt"],
        ) / 1000

        result = await fixture.gateway.reconcile(delivery_id)

        self.assertEqual(result["reason"], "client_outcome_unknown")
        self.assertEqual(fixture.store.current_attempt(delivery_id)["state"], "claude_claimed")
        self.assertEqual(fixture.authority.settlements, [])
        self.assertIsNotNone(claimed)


if __name__ == "__main__":
    unittest.main()
