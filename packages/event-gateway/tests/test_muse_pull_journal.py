"""Offline crash/replay proofs, not Muse ownership or wake qualification."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from event_gateway.muse_pull import MusePullJournal
from event_gateway.store import Store, StoreError

U = ["00000000-0000-4000-8000-" + str(n).zfill(12) for n in range(1, 5)]


class MusePullJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name).resolve() / "state"
        self.now = 1000.0
        self.store = Store(self.path, clock=lambda: self.now, max_rows=8)
        self.addCleanup(lambda: self.store.close())
        self.j = MusePullJournal(self.store)
        self.b = dict(
            slotId="owner-muse",
            bindingGeneration=1,
            principal="owner@example.com",
            nodeId=U[0],
            runtimeId=U[1],
            sessionId=U[2],
            nodeGeneration=1,
            runtimeGeneration=1,
            attachmentGeneration=1,
            consumerGeneration=1,
            leaseExpiresAt=2000.0,
        )
        self.a = dict(notificationId="one", eventReference="ref_one")
        self.z = dict(notificationId="two", eventReference="ref_two")
        self.j.put_binding(self.b)

    def reopen(self):
        self.store.close()
        self.store = Store(self.path, clock=lambda: self.now, max_rows=8)
        self.j = MusePullJournal(self.store)

    def snapshot(self):
        return tuple(self.store.db.iterdump())

    def test_lost_read_and_ack_response_after_abrupt_process_exit(self):
        self.store.close()
        script = """import json,os,sys
from event_gateway.store import Store
from event_gateway.muse_pull import MusePullJournal
s=Store(sys.argv[1],clock=lambda:1000.0); j=MusePullJournal(s)
b=json.loads(sys.argv[2]); n=json.loads(sys.argv[3])
if sys.argv[4]=='read':
 j.enqueue(b,n)
 assert j.read(b)==n
else: j.ack(b,n['notificationId'])
os._exit(0)
"""
        for mode in ("read", "ack"):
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    script,
                    str(self.path),
                    json.dumps(self.b),
                    json.dumps(self.a),
                    mode,
                ],
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.reopen()
            if mode == "read":
                self.assertEqual(self.j.read(self.b), self.a)
                self.assertEqual(self.j.read(self.b), self.a)
                self.j.enqueue(self.b, self.z)
                self.store.close()
            else:
                self.assertEqual(
                    self.j.ack(self.b, "one"),
                    {"notificationId": "one", "status": "acked"},
                )
                self.assertEqual(self.j.read(self.b), self.z)

    def test_full_journal_allows_duplicates_and_ack_without_page_growth(self):
        self.store.max_rows = 3
        self.j.enqueue(self.b, self.a)
        self.j.enqueue(self.b, self.z)
        pages = self.store.db.execute("PRAGMA page_count").fetchone()[0]
        with patch.object(self.store, "_capacity", side_effect=StoreError("capacity")):
            self.assertEqual(self.j.put_binding(self.b), self.b)
            self.assertEqual(self.j.enqueue(self.b, self.a), self.a)
            self.j.ack(self.b, "one")
            self.j.ack(self.b, "one")
            self.assertEqual(self.j.enqueue(self.b, self.a), self.a)
        self.assertEqual(
            self.store.db.execute("PRAGMA page_count").fetchone()[0], pages
        )
        self.reopen()
        self.store.max_rows = 3
        before = self.snapshot()
        with self.assertRaises(StoreError):
            self.j.enqueue(
                self.b, dict(notificationId="three", eventReference="ref_three")
            )
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.j.read(self.b), self.z)

    def test_unknown_out_of_order_and_conflicting_replays_are_atomic(self):
        self.j.enqueue(self.b, self.a)
        self.j.enqueue(self.b, self.z)
        for item in ("missing", "two"):
            before = self.snapshot()
            with self.assertRaises(StoreError):
                self.j.ack(self.b, item)
            self.assertEqual(self.snapshot(), before)
        for acknowledged in (False, True):
            if acknowledged:
                self.j.ack(self.b, "one")
            before = self.snapshot()
            with self.assertRaises(StoreError):
                self.j.enqueue(self.b, dict(self.a, eventReference="different"))
            self.assertEqual(self.snapshot(), before)

    def test_rotation_fences_old_tuple_and_preserves_old_pending(self):
        self.j.enqueue(self.b, self.a)
        for key, value in self.b.items():
            if key in ("slotId", "bindingGeneration", "leaseExpiresAt"):
                continue
            changed = (
                value + 1
                if type(value) is int
                else ("other@example.com" if key == "principal" else U[3])
            )
            with self.subTest(key=key), self.assertRaises(StoreError):
                self.j.put_binding(dict(self.b, **{key: changed}))
        new = dict(self.b, bindingGeneration=2, sessionId=U[3], runtimeId=U[3])
        self.j.put_binding(new)
        self.reopen()
        for operation in (
            lambda: self.j.read(self.b),
            lambda: self.j.enqueue(self.b, self.z),
            lambda: self.j.ack(self.b, "one"),
            lambda: self.j.put_binding(self.b),
        ):
            with self.assertRaises(StoreError):
                operation()
        self.assertIsNone(self.j.read(new))
        self.assertEqual(
            self.store.db.execute(
                "SELECT COUNT(*) FROM muse_pull_notifications_v1"
            ).fetchone()[0],
            1,
        )
        self.j.enqueue(new, self.a)
        self.assertEqual(self.j.read(new), self.a)

    def test_lease_extension_and_expiry_do_not_revive_old_generation(self):
        self.j.enqueue(self.b, self.a)
        renewed = dict(self.b, leaseExpiresAt=3000.0)
        self.j.put_binding(renewed)
        self.assertEqual(self.j.read(renewed), self.a)
        with self.assertRaises(StoreError):
            self.j.read(self.b)
        with self.assertRaises(StoreError):
            self.j.put_binding(self.b)
        self.now = 3001
        with self.assertRaises(StoreError):
            self.j.put_binding(dict(renewed, leaseExpiresAt=4000.0))
        with self.assertRaises(StoreError):
            self.j.ack(renewed, "one")
        fresh = dict(renewed, bindingGeneration=2, leaseExpiresAt=4000.0)
        self.j.put_binding(fresh)
        self.assertIsNone(self.j.read(fresh))

    def test_slots_are_independent_and_not_session_authentication(self):
        self.j.enqueue(self.b, self.a)
        other = dict(self.b, slotId="another-host-slot")
        self.j.put_binding(other)
        self.assertIsNone(self.j.read(other))
        with self.assertRaises(StoreError):
            self.j.ack(other, "one")
        self.assertEqual(self.j.read(self.b), self.a)

    def test_invalid_inputs_and_capacity_failure_leave_no_residue(self):
        before = self.snapshot()
        for changes in (
            {"bindingGeneration": True},
            {"consumerGeneration": 1.0},
            {"leaseExpiresAt": float("inf")},
            {"leaseExpiresAt": 10**400},
            {"leaseExpiresAt": self.now},
            {"sessionId": "bad"},
            {"slotId": "../other"},
            {"extra": "authority"},
        ):
            with self.subTest(changes=changes), self.assertRaises(StoreError):
                self.j.put_binding(dict(self.b, **changes))
            self.assertEqual(self.snapshot(), before)
        for item in (
            {},
            dict(self.a, body="execute"),
            dict(self.a, eventReference="é" * 3000),
            dict(self.a, eventReference="line\nbreak"),
        ):
            with self.assertRaises(StoreError):
                self.j.enqueue(self.b, item)
            self.assertEqual(self.snapshot(), before)
        with patch.object(self.store, "_capacity", side_effect=StoreError("capacity")):
            with self.assertRaises(StoreError):
                self.j.enqueue(self.b, self.a)
        self.assertEqual(self.snapshot(), before)

    def test_aborted_database_writes_rollback_enqueue_and_ack(self):
        self.store.db.execute(
            "CREATE TRIGGER abort_enqueue AFTER INSERT ON muse_pull_notifications_v1 BEGIN SELECT RAISE(ABORT,'injected'); END"
        )
        before = self.snapshot()
        with self.assertRaises(StoreError):
            self.j.enqueue(self.b, self.a)
        self.assertEqual(self.snapshot(), before)
        self.store.db.execute("DROP TRIGGER abort_enqueue")
        self.j.enqueue(self.b, self.a)
        self.store.db.execute(
            "CREATE TRIGGER abort_ack AFTER UPDATE ON muse_pull_notifications_v1 BEGIN SELECT RAISE(ABORT,'injected'); END"
        )
        before = self.snapshot()
        with self.assertRaises(StoreError):
            self.j.ack(self.b, "one")
        self.assertEqual(self.snapshot(), before)
        self.reopen()
        self.assertEqual(self.j.read(self.b), self.a)

    def test_native_state_and_dispatch_are_untouched_and_lock_reused(self):
        tables = ("deliveries", "attempts", "attachments")
        before = [
            tuple(self.store.db.execute(f"SELECT * FROM {name}")) for name in tables
        ]
        self.j.enqueue(self.b, self.a)
        self.j.ack(self.b, "one")
        self.assertEqual(self.store.list_pending(), [])
        self.assertEqual(self.store.list_reconcilable(), [])
        self.assertEqual(
            [tuple(self.store.db.execute(f"SELECT * FROM {name}")) for name in tables],
            before,
        )
        with self.assertRaises(StoreError):
            Store(self.path)
        self.assertEqual(self.store.db.execute("PRAGMA user_version").fetchone()[0], 4)


if __name__ == "__main__":
    unittest.main()
