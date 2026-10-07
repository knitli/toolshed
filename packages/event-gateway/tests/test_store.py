import copy
import json
from pathlib import Path
import tempfile
import unittest
import uuid

from event_gateway.protocol import derive_delivery_id, ProtocolError
from event_gateway.store import Store, StoreError, IDENTITY, RETENTION

FIXTURES = json.loads(
    (
        Path(__file__).resolve().parents[1] / "contracts/event-v1/protocol-v1.json"
    ).read_text()
)
NOW = 1791201630


class StoreTests(unittest.TestCase):
    def clock(self):
        return self.now

    def close_store(self):
        self.store.close()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name).resolve() / "private"
        self.now = NOW
        self.store = Store(self.path, clock=self.clock)
        self.addCleanup(self.close_store)
        self.event = copy.deepcopy(FIXTURES["validEnvelopes"][0])
        self.mapping = {key: self.event[key] for key in IDENTITY}
        self.mapping.update(
            leaseExpiresAt=NOW + 3600,
            nativeSessionId="secret-session",
            socketPath="/secret/socket",
        )
        self.store.put_attachment(self.mapping)

    def new_event(self):
        event = dict(self.event, eventId=str(uuid.uuid4()), attemptId=str(uuid.uuid4()))
        event["deliveryId"] = derive_delivery_id(event)
        return event

    def admission(self, envelope=None):
        from event_gateway.cloud import _iso
        envelope = copy.deepcopy(envelope or self.event)
        envelope.update(issuedAt=_iso(self.now), expiresAt=_iso(self.now + 60))
        return {"status": "admitted", "permitId": str(uuid.uuid4()), "nodeId": str(uuid.uuid4()),
                "permitIssuedAt": _iso(self.now), "permitExpiresAt": _iso(self.now + 5), "envelope": envelope}

    def admitted(self):
        ident = self.store.accept(self.event)["deliveryId"]
        self.assertTrue(self.store.begin_claim(ident))
        admission = self.admission()
        self.store.record_admission(ident, admission)
        return ident, admission

    def request(self, admission):
        from event_gateway.native import EVENT_FIELDS
        from event_gateway.protocol import _timestamp
        return {"clientId": str(uuid.uuid4()), "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 1,
                "threadId": str(uuid.uuid4()), "generation": 2, "clientUserMessageId": str(uuid.uuid4()),
                "deliveryId": admission["envelope"]["deliveryId"], "attemptId": admission["envelope"]["attemptId"],
                "permitId": admission["permitId"], "permitIssuedAt": _timestamp(admission["permitIssuedAt"]),
                "permitExpiresAt": _timestamp(admission["permitExpiresAt"]),
                "event": {key: admission["envelope"][key] for key in EVENT_FIELDS}}

    def receipt(self, request):
        from event_gateway.native import IDENTITY as NATIVE_IDENTITY
        return {**{key: request[key] for key in NATIVE_IDENTITY},
                "outcome": {"status": "terminalNotStarted", "reason": "busy", "receiptId": str(uuid.uuid4()), "replayed": False}}

    def settlement(self, admission, evidence):
        return {**{key: admission["envelope"][key] for key in ("deliveryId", "attemptId", "nodeGeneration")},
                "status": "not_started", "permitId": admission["permitId"], "nodeId": admission["nodeId"], "evidence": evidence}

    def native_ack(self, admission, receipt, acknowledged_at=None):
        envelope = admission["envelope"]
        acknowledgment = {
            "schemaVersion": 1,
            **{key: envelope[key] for key in ("eventId", "deliveryId", "attemptId", "principal", "agent", "runtimeId",
                                               "nodeGeneration", "runtimeGeneration", "attachmentGeneration")},
            "deliveredSourceStateVersion": envelope["sourceStateVersion"],
            "acknowledgedAt": acknowledged_at or "2026-10-05T12:00:00.000Z",
            "status": "submitted",
            "nativeCorrelation": {"kind": "native_turn_started", "permitId": admission["permitId"],
                                  "turnId": receipt["outcome"]["turnId"]},
        }
        if "consumerGeneration" in envelope:
            acknowledgment["consumerGeneration"] = envelope["consumerGeneration"]
        return acknowledgment

    def test_claim_intent_restarts_exact_and_reserves_capacity(self):
        ident = self.store.accept(self.event)["deliveryId"]
        self.assertTrue(self.store.begin_claim(ident))
        self.assertFalse(self.store.begin_claim(ident))
        pending = self.store.current_attempt(ident)
        self.assertEqual(pending["envelope"], self.event)
        self.assertGreater(pending["reserved_bytes"], 0)
        self.store.close()
        self.store = Store(self.path, clock=self.clock)
        self.assertEqual(self.store.current_attempt(ident), pending)
        self.assertEqual(self.store.get(ident)["status"], "claiming")
        self.assertEqual(self.store.status()["pending"], 1)
        self.assertEqual([row["deliveryId"] for row in self.store.list_reconcilable()], [ident])
        self.store.max_bytes = self.store._size() + pending["reserved_bytes"] + 10000
        with self.assertRaisesRegex(StoreError, "storage_capacity"):
            self.store.put_attachment(dict(self.mapping, leaseExpiresAt=NOW + 7200))
        self.store.record_admission(ident, self.admission())
        self.assertEqual(self.store.get(ident)["status"], "admitted")

    def test_claim_capacity_failure_leaves_original_queued(self):
        ident = self.store.accept(self.event)["deliveryId"]
        self.store.max_bytes = self.store._size() + 10000
        with self.assertRaisesRegex(StoreError, "storage_capacity"):
            self.store.begin_claim(ident)
        self.assertEqual(self.store.get(ident)["status"], "queued")
        self.assertIsNone(self.store.current_attempt(ident))
        self.assertEqual(self.store.delivery_envelope(ident), self.event)

    def test_admission_snapshot_is_validated_immutable_and_historical(self):
        ident = self.store.accept(self.event)["deliveryId"]
        self.store.begin_claim(ident)
        admission = self.admission()
        bad = copy.deepcopy(admission)
        bad["envelope"]["policyRevision"] += 1
        bad["envelope"]["deliveryId"] = derive_delivery_id(bad["envelope"])
        with self.assertRaisesRegex(StoreError, "invalid_admission"):
            self.store.record_admission(ident, bad)
        self.assertEqual(self.store.get(ident)["status"], "claiming")
        self.now += 3600
        self.assertEqual(self.store.record_admission(ident, admission), admission)
        self.assertEqual(self.store.record_admission(ident, admission), admission)
        bad = dict(admission, permitId=str(uuid.uuid4()))
        with self.assertRaisesRegex(StoreError, "admission_conflict"):
            self.store.record_admission(ident, bad)
        detached = self.store.current_attempt(ident)
        detached["admission"]["permitId"] = "mutated"
        self.assertEqual(self.store.current_attempt(ident)["admission"], admission)
        self.assertEqual(self.store.delivery_envelope(ident), admission["envelope"])
        self.assertFalse(self.store.begin_native(ident, self.event["attemptId"], self.request(admission)))

    def test_admission_storage_failure_keeps_durable_claim_for_exact_recovery(self):
        import sqlite3
        ident = self.store.accept(self.event)["deliveryId"]
        self.store.begin_claim(ident)
        before = self.store.current_attempt(ident)
        admission = self.admission()
        self.store.db.execute("CREATE TRIGGER fail_admit BEFORE UPDATE ON deliveries WHEN NEW.state='admitted' BEGIN SELECT RAISE(ABORT,'disk fault'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.record_admission(ident, admission)
        self.assertEqual(self.store.current_attempt(ident), before)
        self.assertEqual(self.store.get(ident)["status"], "claiming")
        self.store.db.execute("DROP TRIGGER fail_admit")
        self.store.close()
        self.store = Store(self.path, clock=self.clock)
        self.now += 120
        self.assertEqual(self.store.record_admission(ident, admission), admission)
        self.assertEqual(self.store.current_attempt(ident)["envelope"], self.event)
        self.assertEqual(self.store.current_attempt(ident)["admission"], admission)

    def test_native_request_is_durable_before_submission_and_restart_ambiguous(self):
        ident, admission = self.admitted()
        request = self.request(admission)
        bad = dict(request, permitId=str(uuid.uuid4()))
        with self.assertRaisesRegex(StoreError, "invalid_native_request"):
            self.store.begin_native(ident, self.event["attemptId"], bad)
        self.assertTrue(self.store.begin_native(ident, self.event["attemptId"], request))
        self.assertEqual(self.store.current_attempt(ident)["native_request"], request)
        self.assertFalse(self.store.begin_native(ident, self.event["attemptId"], request))
        self.store.close()
        self.store = Store(self.path, clock=self.clock)
        self.assertEqual(self.store.current_attempt(ident)["state"], "ambiguous")
        self.assertEqual(self.store.current_attempt(ident)["native_request"], request)
        with self.assertRaisesRegex(StoreError, "invalid_transition"):
            self.store.begin_settlement(ident, self.event["attemptId"], {"type": "local_not_submitted"})
        self.assertFalse(self.store.begin_submit(ident))

    def test_local_settlement_survives_restart_rotates_once_and_fences_old_responses(self):
        ident, admission = self.admitted()
        attempt = self.event["attemptId"]
        evidence = {"type": "local_not_submitted"}
        self.assertTrue(self.store.begin_settlement(ident, attempt, evidence))
        self.assertFalse(self.store.begin_native(ident, attempt, self.request(admission)))
        self.store.close()
        self.store = Store(self.path, clock=self.clock)
        current = self.store.current_attempt(ident)
        self.assertEqual(current["state"], "settlement_pending")
        self.assertEqual(current["evidence"], evidence)
        self.assertEqual(current["admission"], admission)
        self.assertEqual(self.store.status()["pending"], 1)
        result = self.settlement(admission, evidence)
        self.assertTrue(self.store.complete_settlement(ident, attempt, result))
        rotated = self.store.delivery_envelope(ident)
        self.assertNotEqual(rotated["attemptId"], attempt)
        self.assertEqual({k: v for k, v in rotated.items() if k != "attemptId"},
                         {k: v for k, v in admission["envelope"].items() if k != "attemptId"})
        self.assertEqual(self.store.get(ident)["status"], "queued")
        self.assertFalse(self.store.complete_settlement(ident, attempt, result))
        self.assertEqual(self.store.delivery_envelope(ident), rotated)
        self.assertTrue(self.store.begin_claim(ident))
        with self.assertRaisesRegex(StoreError, "invalid_admission"):
            self.store.record_admission(ident, admission)
        with self.assertRaisesRegex(StoreError, "attempt_conflict"):
            self.store.finish(ident, "ambiguous", attempt_id=attempt)
        self.assertFalse(self.store.mark_acknowledged(ident, "observed", attempt_id=attempt))
        old = self.store.db.execute("SELECT state,settlement,reserved_bytes FROM attempts WHERE attempt_id=?", (attempt,)).fetchone()
        self.assertEqual(tuple(old), ("settled", json.dumps(result, sort_keys=True, separators=(",", ":")), 0))

    def test_native_terminal_settlement_requires_exact_receipt_and_no_positive_correlation(self):
        ident, admission = self.admitted()
        attempt = self.event["attemptId"]
        request = self.request(admission)
        self.store.begin_native(ident, attempt, request)
        receipt = self.receipt(request)
        evidence = {"type": "native_terminal_no_start", "receiptId": receipt["outcome"]["receiptId"]}
        for bad in (dict(receipt, permitId=str(uuid.uuid4())), dict(receipt, extra=True),
                    dict(receipt, outcome={"status": "unknown"}),
                    dict(receipt, outcome={"status": "started", "turnId": request["clientUserMessageId"], "replayed": False})):
            with self.subTest(receipt=bad), self.assertRaisesRegex(StoreError, "invalid_receipt"):
                self.store.begin_settlement(ident, attempt, evidence, receipt=bad)
        self.assertTrue(self.store.begin_settlement(ident, attempt, evidence, receipt=receipt))
        self.assertTrue(self.store.begin_settlement(ident, attempt, evidence, receipt=receipt))
        self.assertEqual(self.store.current_attempt(ident)["receipt"], receipt)
        with self.assertRaisesRegex(StoreError, "invalid_transition"):
            self.store.finish(ident, "observed", submission_id="positive", turn_id="positive", attempt_id=attempt)
        # Even a preexisting positive correlation cannot be downgraded by a negative receipt.
        self.store.db.execute("UPDATE deliveries SET submission='positive' WHERE id=?", (ident,))
        self.store.db.commit()
        with self.assertRaisesRegex(StoreError, "receipt_conflict"):
            self.store.begin_settlement(ident, attempt, evidence, receipt=receipt)
        with self.assertRaisesRegex(StoreError, "receipt_conflict"):
            self.store.complete_settlement(ident, attempt, self.settlement(admission, evidence))

    def test_started_receipt_is_preserved_without_queue_alias(self):
        ident, admission = self.admitted()
        attempt = self.event["attemptId"]
        request = self.request(admission)
        self.store.begin_native(ident, attempt, request)
        receipt = self.receipt(request)
        with self.assertRaisesRegex(StoreError, "invalid_receipt"):
            self.store.record_started(ident, attempt, receipt)
        receipt["outcome"] = {"status": "started", "turnId": request["clientUserMessageId"], "replayed": False}
        bad = dict(receipt, permitId=str(uuid.uuid4()))
        with self.assertRaisesRegex(StoreError, "invalid_receipt"):
            self.store.record_started(ident, attempt, bad)
        result = self.store.record_started(ident, attempt, receipt)
        self.assertEqual(result["status"], "submitted")
        self.assertEqual(result["reason"], "native_started_ack_pending")
        self.assertEqual(self.store.current_attempt(ident)["started_receipt"], receipt)
        self.assertEqual(self.store.native_receipt(ident), {"submission_id": None,
                         "turn_id": request["clientUserMessageId"], "ack_pending": True})
        self.store.close()
        self.store = Store(self.path, clock=self.clock)
        self.assertEqual(self.store.current_attempt(ident)["started_receipt"], receipt)
        with self.assertRaisesRegex(StoreError, "receipt_conflict"):
            self.store.begin_settlement(ident, attempt, {"type": "local_not_submitted"})

    def test_native_ack_is_immutable_cas_and_stops_retries_after_restart(self):
        ident, admission = self.admitted()
        attempt = self.event["attemptId"]
        request = self.request(admission)
        self.store.begin_native(ident, attempt, request)
        self.store.finish(ident, "ambiguous", attempt_id=attempt)
        receipt = self.receipt(request)
        receipt["outcome"] = {"status": "started", "turnId": request["clientUserMessageId"], "replayed": True}
        self.store.record_started(ident, attempt, receipt)
        replay = copy.deepcopy(receipt)
        replay["outcome"]["replayed"] = False
        self.store.record_started(ident, attempt, replay)
        self.assertEqual(self.store.current_attempt(ident)["started_receipt"], receipt)
        self.assertIsNone(self.store.native_receipt(ident)["submission_id"])
        self.assertEqual(self.store.delivery(ident)["reason"], "native_started_ack_pending")
        acknowledgment = self.native_ack(admission, receipt)
        saved = self.store.persist_native_ack(ident, attempt, acknowledgment)
        self.assertEqual(saved, acknowledgment)
        changed = dict(acknowledgment, acknowledgedAt="2026-10-05T12:00:01.000Z")
        with self.assertRaisesRegex(StoreError, "acknowledgment_conflict"):
            self.store.persist_native_ack(ident, attempt, changed)
        wrong_permit = copy.deepcopy(acknowledgment)
        wrong_permit["nativeCorrelation"]["permitId"] = str(uuid.uuid4())
        with self.assertRaisesRegex(StoreError, "invalid_native_acknowledgment"):
            self.store.persist_native_ack(ident, attempt, wrong_permit)
        self.assertTrue(self.store.native_receipt(ident)["ack_pending"])
        self.assertTrue(self.store.complete_native_ack(ident, attempt, saved, {"status": "submitted", "current": False}))
        self.assertEqual(self.store.current_attempt(ident)["native_ack"], saved)
        self.assertEqual(self.store.current_attempt(ident)["state"], "submitted")
        self.assertEqual(self.store.native_receipt(ident), {"submission_id": None,
                         "turn_id": request["clientUserMessageId"], "ack_pending": False})
        self.assertEqual(self.store.status()["pending"], 1)
        self.store.close()
        self.store = Store(self.path, clock=self.clock)
        self.assertEqual(self.store.current_attempt(ident)["native_ack"], saved)
        self.assertFalse(self.store.native_receipt(ident)["ack_pending"])
        self.assertFalse(self.store.complete_native_ack(ident, str(uuid.uuid4()), saved,
                                                        {"status": "submitted", "current": False}))
        with self.assertRaisesRegex(StoreError, "invalid_acknowledgment_result"):
            self.store.complete_native_ack(ident, attempt, saved, {"status": "observed", "current": True})

    def test_schema_v2_migration_clears_only_proven_native_turn_aliases(self):
        direct, admission = self.admitted()
        attempt = self.event["attemptId"]
        request = self.request(admission)
        self.store.begin_native(direct, attempt, request)
        receipt = self.receipt(request)
        receipt["outcome"] = {"status": "started", "turnId": request["clientUserMessageId"], "replayed": False}
        self.store.record_started(direct, attempt, receipt)
        self.store.db.execute("UPDATE deliveries SET submission=turn WHERE id=?", (direct,))

        legacy = self.store.accept(self.new_event())["deliveryId"]
        self.store.begin_submit(legacy)
        self.store.finish(legacy, "submitted", submission_id="legacy-queue-id")
        self.store.db.execute("PRAGMA user_version=2")
        self.store.db.commit()
        self.store.close()
        self.store = Store(self.path, clock=self.clock)

        self.assertIsNone(self.store.native_receipt(direct)["submission_id"])
        self.assertEqual(self.store.native_receipt(direct)["turn_id"], request["clientUserMessageId"])
        self.assertEqual(self.store.native_receipt(legacy)["submission_id"], "legacy-queue-id")
        self.assertEqual(self.store.db.execute("PRAGMA user_version").fetchone()[0], 3)

    def test_started_contradiction_cancels_pending_negative_settlement(self):
        ident, admission = self.admitted()
        attempt = self.event["attemptId"]
        request = self.request(admission)
        self.store.begin_native(ident, attempt, request)
        negative = self.receipt(request)
        evidence = {"type": "native_terminal_no_start", "receiptId": negative["outcome"]["receiptId"]}
        self.store.begin_settlement(ident, attempt, evidence, receipt=negative)
        started = dict(negative, outcome={"status": "started", "turnId": request["clientUserMessageId"], "replayed": True})
        result = self.store.record_started(ident, attempt, started)
        self.assertEqual(result["status"], "ambiguous")
        current = self.store.current_attempt(ident)
        self.assertEqual(current["receipt"], negative)
        self.assertEqual(current["started_receipt"], started)
        self.assertFalse(self.store.complete_settlement(ident, attempt, self.settlement(admission, evidence)))
        self.assertEqual(self.store.delivery_envelope(ident)["attemptId"], attempt)
        self.assertEqual(self.store.list_pending(), [])

    def test_settlement_rejects_echo_tampering_and_rolls_back_storage_failure(self):
        import sqlite3
        ident, admission = self.admitted()
        attempt = self.event["attemptId"]
        evidence = {"type": "local_not_submitted"}
        self.store.begin_settlement(ident, attempt, evidence)
        result = self.settlement(admission, evidence)
        for key, value in (("permitId", str(uuid.uuid4())), ("nodeId", str(uuid.uuid4())), ("nodeGeneration", True),
                           ("evidence", {"type": "native_terminal_no_start", "receiptId": str(uuid.uuid4())}), ("extra", True)):
            with self.subTest(key=key), self.assertRaisesRegex(StoreError, "invalid_settlement"):
                self.store.complete_settlement(ident, attempt, {**result, key: value})
        before = self.store.current_attempt(ident)
        self.store.db.execute("CREATE TRIGGER fail_settle BEFORE UPDATE ON deliveries WHEN NEW.state='queued' BEGIN SELECT RAISE(ABORT,'disk fault'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.complete_settlement(ident, attempt, result)
        self.assertEqual(self.store.current_attempt(ident), before)
        self.assertEqual(self.store.get(ident)["status"], "settlement_pending")
        self.store.db.execute("DROP TRIGGER fail_settle")
        self.assertTrue(self.store.complete_settlement(ident, attempt, result))

    def test_detached_claim_keeps_grant_for_settlement_but_never_requeues(self):
        ident = self.store.accept(self.event)["deliveryId"]
        self.store.begin_claim(ident)
        self.store.detach(self.mapping["runtimeId"])
        admission = self.admission()
        self.store.record_admission(ident, admission)
        self.assertEqual(self.store.current_attempt(ident)["admission"], admission)
        self.assertFalse(self.store.begin_native(ident, self.event["attemptId"], self.request(admission)))
        evidence = {"type": "local_not_submitted"}
        self.store.begin_settlement(ident, self.event["attemptId"], evidence)
        self.store.close()
        self.store = Store(self.path, clock=self.clock)
        self.assertTrue(self.store.complete_settlement(ident, self.event["attemptId"], self.settlement(admission, evidence)))
        self.assertEqual(self.store.get(ident)["status"], "stale")
        self.assertEqual(self.store.list_pending(), [])

    def test_pending_settlement_is_retained_and_expired_attachment_cannot_retry(self):
        ident, admission = self.admitted()
        evidence = {"type": "local_not_submitted"}
        self.store.begin_settlement(ident, self.event["attemptId"], evidence)
        self.now += RETENTION * 2
        self.assertEqual(self.store.cleanup(), 0)
        self.assertIsNotNone(self.store.current_attempt(ident))
        self.assertEqual(self.store.current_attempt(ident)["state"], "settlement_pending")
        self.assertEqual(len(self.store.list_reconcilable()), 1)
        self.store.complete_settlement(ident, self.event["attemptId"], self.settlement(admission, evidence))
        self.assertEqual(self.store.get(ident)["status"], "stale")
        self.now += RETENTION + 1
        self.assertEqual(self.store.cleanup(), 1)
        self.assertEqual(self.store.db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0], 0)

    def test_schema_zero_and_one_migrate_without_requeueing_native_work(self):
        ident = self.store.accept(self.event)["deliveryId"]
        self.store.begin_submit(ident)
        for version in (0, 1):
            self.store.db.execute("DROP TABLE attempts")
            self.store.db.execute(f"PRAGMA user_version={version}")
            self.store.db.commit()
            self.store.close()
            self.store = Store(self.path, clock=self.clock)
            self.assertEqual(self.store.db.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertEqual(self.store.get(ident)["status"], "ambiguous")
            self.assertIsNone(self.store.current_attempt(ident))
            self.assertFalse(self.store.begin_claim(ident))
            self.assertEqual(self.store.delivery_envelope(ident), self.event)

    def test_consumer_generation_fences_acceptance_and_transfer(self):
        mapping = dict(
            self.mapping,
            attachmentGeneration=self.mapping["attachmentGeneration"] + 1,
            consumerGeneration=4,
        )
        self.store.put_attachment(mapping)
        event = dict(
            self.event,
            attachmentGeneration=mapping["attachmentGeneration"],
            consumerGeneration=5,
        )
        event["deliveryId"] = derive_delivery_id(event)
        with self.assertRaises(StoreError):
            self.store.accept(event)
        event["consumerGeneration"] = 4
        event["deliveryId"] = derive_delivery_id(event)
        ident = self.store.accept(event)["deliveryId"]
        self.store.put_attachment(dict(mapping, consumerGeneration=5))
        self.assertEqual(self.store.get(ident)["status"], "stale")
        with self.assertRaises(StoreError):
            self.store.accept(event)
        with self.assertRaises(StoreError):
            self.store.put_attachment(mapping)
        self.store.detach(mapping["runtimeId"])
        with self.assertRaises(StoreError):
            self.store.put_attachment(dict(mapping, consumerGeneration=5))
        self.store.put_attachment(dict(mapping, consumerGeneration=6))
        without_consumer = dict(
            mapping, attachmentGeneration=mapping["attachmentGeneration"] + 1
        )
        del without_consumer["consumerGeneration"]
        with self.assertRaises(StoreError):
            self.store.put_attachment(without_consumer)

    def test_optional_consumer_generation_validation(self):
        for value in [True, False, 0, -1, 1.5, None, "1", 2**53]:
            with self.subTest(value=value), self.assertRaises(StoreError):
                self.store.put_attachment(dict(self.mapping, consumerGeneration=value))
        self.store.accept(self.event)
        event = dict(self.new_event(), consumerGeneration=1)
        event["deliveryId"] = derive_delivery_id(event)
        with self.assertRaises(StoreError):
            self.store.accept(event)
        self.store.put_attachment(dict(self.mapping, consumerGeneration=1))
        with self.assertRaises(StoreError):
            self.store.accept(self.event)
        self.store.accept(event)

    def test_durable_dedup_conflict_and_privacy(self):
        first = self.store.accept(self.event)
        again = self.store.accept(dict(self.event, attemptId=str(uuid.uuid4())))
        self.assertEqual(first["deliveryId"], again["deliveryId"])
        self.assertTrue(again["duplicate"])
        with self.assertRaisesRegex(StoreError, "different content"):
            self.store.accept(dict(self.event, sourceStateVersion="different"))
        self.store.close()
        self.store = Store(self.path, clock=self.clock)
        self.assertEqual(self.store.get(first["deliveryId"])["status"], "queued")
        self.assertTrue(self.store.accept(self.event)["duplicate"])
        output = json.dumps(
            [
                self.store.get(first["deliveryId"]),
                self.store.status(),
                self.store.list_pending(),
            ]
        )
        self.assertNotIn("secret", output)
        self.assertEqual(self.store.delivery_envelope(first["deliveryId"]), self.event)
        for file in self.path.glob("ledger.sqlite*"):
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_restart_submitting_is_ambiguous_never_retried(self):
        ident = self.store.accept(self.event)["deliveryId"]
        self.assertTrue(self.store.begin_submit(ident))
        self.assertFalse(self.store.begin_submit(ident))
        self.store.close()
        self.store = Store(self.path, clock=self.clock)
        self.assertEqual(self.store.delivery(ident)["status"], "ambiguous")
        self.assertFalse(self.store.begin_submit(ident))
        self.assertEqual(len(self.store.list_reconcilable()), 1)
        self.now += RETENTION * 2
        self.assertEqual(self.store.cleanup(), 0)
        self.store.finish(
            ident, "observed", submission_id="native-submission", turn_id="native-turn"
        )
        self.now += RETENTION + 1
        self.assertEqual(self.store.cleanup(), 0)
        self.store.mark_acknowledged(ident, "observed")
        self.assertEqual(self.store.cleanup(), 1)

    def test_detach_and_generation_fence(self):
        queued = self.store.accept(self.event)["deliveryId"]
        submitted = self.store.accept(self.new_event())["deliveryId"]
        self.store.begin_submit(submitted)
        self.store.finish(
            submitted,
            "submitted",
            submission_id="secret-submission",
            turn_id="secret-turn",
        )
        self.store.detach(self.mapping["runtimeId"])
        self.assertEqual(self.store.get(queued)["status"], "stale")
        self.assertEqual(self.store.get(submitted)["status"], "ambiguous")
        self.assertNotIn("secret", json.dumps(self.store.list_reconcilable()))
        with self.assertRaises(StoreError):
            self.store.accept(self.new_event())
        self.store.put_attachment(
            dict(
                self.mapping,
                attachmentGeneration=self.mapping["attachmentGeneration"] + 1,
            )
        )
        with self.assertRaises(StoreError):
            self.store.accept(self.new_event())
        with self.assertRaises(StoreError):
            self.store.put_attachment(self.mapping)

    def test_expired_leases_release_slots_and_preserve_generation_tombstones(self):
        expired = dict(self.mapping, leaseExpiresAt=NOW + 1)
        self.store.put_attachment(expired)
        for _ in range(2):
            self.store.put_attachment(dict(expired, runtimeId=str(uuid.uuid4())))
        self.now += 2
        fresh = dict(self.mapping, runtimeId=str(uuid.uuid4()))
        self.store.put_attachment(fresh)
        self.assertEqual(self.store.list_attachments(), [fresh])
        self.assertEqual(self.store.status()["attachments"], 1)
        self.store.close()
        self.store = Store(self.path, clock=self.clock)
        with self.assertRaises(StoreError):
            self.store.put_attachment(self.mapping)
        advanced = dict(
            self.mapping, attachmentGeneration=self.mapping["attachmentGeneration"] + 1
        )
        self.store.put_attachment(advanced)
        third = dict(self.mapping, runtimeId=str(uuid.uuid4()))
        self.store.put_attachment(third)
        with self.assertRaisesRegex(StoreError, "session_capacity"):
            self.store.put_attachment(dict(self.mapping, runtimeId=str(uuid.uuid4())))
        self.store.put_attachment(dict(advanced, leaseExpiresAt=NOW + 7200))
        self.assertEqual(self.store.status()["attachments"], 3)

    def test_session_capacity_is_per_agent_and_fences_transfers(self):
        for _ in range(2):
            self.store.put_attachment(dict(self.mapping, runtimeId=str(uuid.uuid4())))
        other = dict(self.mapping, runtimeId=str(uuid.uuid4()), agent="other-agent")
        self.store.put_attachment(other)
        self.store.put_attachment(dict(self.mapping, leaseExpiresAt=NOW + 7200))
        with self.assertRaisesRegex(StoreError, "session_capacity"):
            self.store.put_attachment(
                dict(
                    other,
                    agent=self.mapping["agent"],
                    attachmentGeneration=other["attachmentGeneration"] + 1,
                )
            )
        moved = dict(
            self.mapping,
            agent="other-agent",
            attachmentGeneration=self.mapping["attachmentGeneration"] + 1,
        )
        self.store.put_attachment(moved)
        self.store.put_attachment(dict(self.mapping, runtimeId=str(uuid.uuid4())))
        self.assertEqual(len(self.store.list_attachments()), 5)
        with self.assertRaisesRegex(StoreError, "session_capacity"):
            self.store.put_attachment(dict(self.mapping, runtimeId=str(uuid.uuid4())))

    def test_capacity_and_pilot_limit(self):
        self.store.max_rows = 1
        ident = self.store.accept(self.event)["deliveryId"]
        with self.assertRaisesRegex(StoreError, "pending_capacity"):
            self.store.accept(self.new_event())
        self.assertEqual(self.store.status()["blockedReason"], "pending_capacity")
        self.assertTrue(self.store.accept(self.event)["duplicate"])
        self.store.begin_submit(ident)
        self.store.finish(
            ident, "observed", submission_id="native-submission", turn_id="native-turn"
        )
        self.store.mark_acknowledged(ident, "observed")
        self.store.accept(self.new_event())
        for _ in range(2):
            self.store.put_attachment(dict(self.mapping, runtimeId=str(uuid.uuid4())))
        with self.assertRaisesRegex(StoreError, "session_capacity"):
            self.store.put_attachment(dict(self.mapping, runtimeId=str(uuid.uuid4())))
        self.store.max_bytes = self.store.status()["bytes"]
        with self.assertRaisesRegex(StoreError, "storage_capacity"):
            self.store.begin_submit(self.store.list_pending()[0]["deliveryId"])

    def test_freshness_is_transport_only_but_lease_is_dispatch_fence(self):
        ident = self.store.accept(self.event)["deliveryId"]
        self.now += 120
        self.assertTrue(self.store.begin_submit(ident))
        self.store.finish(
            ident, "observed", submission_id="native-submission", turn_id="native-turn"
        )
        self.now = NOW
        other = self.store.accept(self.new_event())["deliveryId"]
        self.now += 3601
        self.assertFalse(self.store.begin_submit(other))
        self.assertEqual(self.store.get(other)["status"], "stale")
        with self.assertRaises(ProtocolError):
            self.store.accept(self.new_event())

    def test_invalid_inputs_and_state_transitions(self):
        for change in [
            {"leaseExpiresAt": float("nan")},
            {"nodeGeneration": True},
            {"agent": ""},
            {"leaseExpiresAt": NOW},
        ]:
            with self.subTest(change=change), self.assertRaises(StoreError):
                self.store.put_attachment(dict(self.mapping, **change))
        with self.assertRaises(StoreError):
            self.store.put_attachment(dict(self.mapping, socketPath="/different"))
        ident = self.store.accept(self.event)["deliveryId"]
        with self.assertRaises(StoreError):
            self.store.finish(
                ident,
                "observed",
                submission_id="native-submission",
                turn_id="native-turn",
            )
        with self.assertRaises(StoreError):
            self.store.finish(ident, "stale", reason="/secret/socket")
        with self.assertRaises(StoreError):
            self.store.accept(dict(self.event, deliveryId="dly_" + "0" * 64))

    def test_native_receipts_require_canonical_evidence(self):
        ident = self.store.accept(self.event)["deliveryId"]
        self.store.begin_submit(ident)
        for status, fields in [
            ("submitted", {}),
            ("observed", {}),
            ("observed", {"submission_id": "valid"}),
        ]:
            with (
                self.subTest(status=status, fields=fields),
                self.assertRaises(StoreError),
            ):
                self.store.finish(ident, status, **fields)
        for invalid in ["", "/private/session", "contains space", "a" * 129, 123]:
            with self.subTest(invalid=invalid), self.assertRaises(StoreError):
                self.store.finish(ident, "submitted", submission_id=invalid)
        self.store.finish(ident, "submitted", submission_id="native-queue:1")
        self.assertEqual(
            self.store.native_receipt(ident),
            {"submission_id": "native-queue:1", "turn_id": None, "ack_pending": True},
        )
        self.store.close()
        self.store = Store(self.path, clock=self.clock)
        self.store.finish(ident, "observed", turn_id="native-turn.1")
        self.assertEqual(
            self.store.native_receipt(ident),
            {
                "submission_id": "native-queue:1",
                "turn_id": "native-turn.1",
                "ack_pending": True,
            },
        )
        self.assertNotIn("native-queue", json.dumps(self.store.get(ident)))
        self.assertIsNone(self.store.native_receipt("missing"))
        lost = self.store.accept(self.new_event())["deliveryId"]
        self.store.begin_submit(lost)
        self.store.finish(lost, "ambiguous")
        with self.assertRaises(StoreError):
            self.store.finish(lost, "observed", turn_id="native-turn")
        self.assertEqual(self.store.get(lost)["status"], "ambiguous")

    def test_native_receipt_correlations_are_immutable(self):
        ident = self.store.accept(self.event)["deliveryId"]
        self.store.begin_submit(ident)
        self.store.finish(ident, "submitted", submission_id="queue1")
        with self.assertRaisesRegex(StoreError, "^receipt_conflict$"):
            self.store.finish(
                ident, "observed", submission_id="queue2", turn_id="turn1"
            )
        self.assertEqual(self.store.get(ident)["status"], "submitted")
        self.assertEqual(self.store.native_receipt(ident)["submission_id"], "queue1")
        self.store.finish(ident, "observed", submission_id="queue1", turn_id="turn1")
        with self.assertRaisesRegex(StoreError, "^receipt_conflict$"):
            self.store.finish(ident, "observed", turn_id="turn2")
        self.assertEqual(self.store.native_receipt(ident)["turn_id"], "turn1")
        self.store.finish(ident, "observed", submission_id="queue1", turn_id="turn1")

    def test_ack_progress_is_durable_and_observed_backpressures(self):
        self.store.max_rows = 1
        ident = self.store.accept(self.event)["deliveryId"]
        self.store.begin_submit(ident)
        self.store.finish(ident, "submitted", submission_id="queue1")
        self.assertFalse(self.store.mark_acknowledged(ident, "observed"))
        self.assertTrue(self.store.native_receipt(ident)["ack_pending"])
        self.assertTrue(self.store.mark_acknowledged(ident, "submitted"))
        self.assertFalse(self.store.native_receipt(ident)["ack_pending"])
        self.store.close()
        self.store = Store(self.path, clock=self.clock, max_rows=1)
        self.assertFalse(self.store.native_receipt(ident)["ack_pending"])
        self.store.finish(ident, "observed", turn_id="turn1")
        self.assertFalse(self.store.mark_acknowledged(ident, "submitted"))
        self.assertTrue(self.store.native_receipt(ident)["ack_pending"])
        self.store.close()
        self.store = Store(self.path, clock=self.clock, max_rows=1)
        self.assertEqual(
            [row["deliveryId"] for row in self.store.list_reconcilable()], [ident]
        )
        self.assertEqual(self.store.status()["pending"], 1)
        with self.assertRaises(StoreError):
            self.store.accept(self.new_event())
        self.assertTrue(self.store.mark_acknowledged(ident, "observed"))
        self.assertFalse(self.store.native_receipt(ident)["ack_pending"])
        self.assertEqual(self.store.list_reconcilable(), [])
        self.assertEqual(self.store.status()["pending"], 0)
        self.store.accept(self.new_event())

    def test_duplicate_requires_live_attachment(self):
        self.store.accept(self.event)
        self.store.put_attachment(dict(self.mapping, leaseExpiresAt=NOW + 1))
        self.now += 2
        with self.assertRaises(StoreError):
            self.store.accept(self.event)
        self.now = NOW
        self.store.detach(self.mapping["runtimeId"])
        with self.assertRaises(StoreError):
            self.store.accept(self.event)
        self.store.put_attachment(
            dict(
                self.mapping,
                attachmentGeneration=self.mapping["attachmentGeneration"] + 1,
            )
        )
        with self.assertRaises(StoreError):
            self.store.accept(self.event)

    def test_reopen_reclaims_expired_settled_rows_before_capacity_check(self):
        for _ in range(100):
            ident = self.store.accept(self.new_event())["deliveryId"]
            self.store.finish(ident, "stale")
        ambiguous = self.store.accept(self.new_event())["deliveryId"]
        self.store.begin_submit(ambiguous)
        self.store.finish(ambiguous, "ambiguous")
        unacked = self.store.accept(self.new_event())["deliveryId"]
        self.store.begin_submit(unacked)
        self.store.finish(unacked, "observed", submission_id="queue", turn_id="turn")
        self.store.close()
        self.assertGreater((self.path / "ledger.sqlite").stat().st_size, 131072)
        self.now += RETENTION + 120
        self.store = Store(self.path, clock=self.clock, max_bytes=131072)
        self.assertIsNone(self.store.get(ident))
        self.assertEqual(self.store.get(ambiguous)["status"], "ambiguous")
        self.assertEqual(self.store.get(unacked)["status"], "observed")
        self.assertLessEqual(self.store.status()["bytes"], 131072)

    def test_nested_state_directories_are_private(self):
        nested = Path(self.tmp.name).resolve() / "new-parent" / "inner" / "state"
        with Store(nested):
            for directory in (nested, nested.parent, nested.parent.parent):
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_private_directory_single_writer_and_symlinks(self):
        with self.assertRaisesRegex(StoreError, "writer_locked"):
            Store(self.path)
        unsafe = Path(self.tmp.name).resolve() / "unsafe"
        unsafe.mkdir(mode=0o755)
        with self.assertRaisesRegex(StoreError, "unsafe_state"):
            Store(unsafe)
        link = Path(self.tmp.name).resolve() / "link"
        link.symlink_to(self.path)
        with self.assertRaisesRegex(StoreError, "unsafe_state"):
            Store(link)
        self.store.close()
        (self.path / "ledger.sqlite").chmod(0o644)
        with self.assertRaisesRegex(StoreError, "unsafe_state"):
            Store(self.path)


if __name__ == "__main__":
    unittest.main()
