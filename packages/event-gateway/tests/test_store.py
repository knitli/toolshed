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
