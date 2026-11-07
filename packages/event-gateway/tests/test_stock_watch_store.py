"""Capacity reclamation for durable stock watch associations."""
from pathlib import Path
import tempfile
import time
import unittest
import uuid

from event_gateway.store import Store, StoreError


def stock_mapping(runtime, lease_expires_at):
    return {
        "runtimeId": runtime, "principal": "owner@example.com", "agent": "codex",
        "nodeId": "32345678-1234-4234-8234-123456789abc",
        "nodeGeneration": 2, "runtimeGeneration": 3,
        "attachmentGeneration": 4, "consumerGeneration": 4,
        "leaseExpiresAt": lease_expires_at,
        "runtimeProfile": {"profile": "assigned_stock_client", "client": "codex",
                           "conversationId": "22345678-1234-4234-8234-123456789abc"},
    }


def stock_watch(runtime, subject, incarnation=1):
    return {
        "subject": subject, "incarnation": incarnation, "routingRevision": 7,
        "lifecycleEpoch": 8, "state": "attached",
        "attachment": {"holder": {"runtimeId": runtime}, "leaseRevision": 6},
    }


class StockWatchStoreCapacityTests(unittest.TestCase):
    def test_capacity_reclaims_only_settled_rows_from_inactive_runtimes(self):
        now = [time.time()]
        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            detached_runtime, expired_runtime = str(uuid.uuid4()), str(uuid.uuid4())
            for runtime in (detached_runtime, expired_runtime):
                store.put_attachment(stock_mapping(runtime, now[0] + 100))

            pending_request = {"operation": "watch_renew", "operationId": str(uuid.uuid4())}
            for index in range(32):
                runtime = detached_runtime if index < 16 else expired_runtime
                subject = {"repositoryId": 17, "prNumber": index + 1}
                current = stock_watch(runtime, subject)
                store.remember_stock_watch(stock_mapping(runtime, now[0] + 100), current)
                if index == 0:
                    store.save_stock_watch_request(runtime, subject, 1, pending_request)
            self.assertEqual(store.db.execute(
                "SELECT COUNT(*) FROM stock_watches").fetchone()[0], 32)

            pending_before = next(row for row in store.stock_watch_rows(detached_runtime)
                                  if row["pending"] is not None)
            store.detach(detached_runtime)
            now[0] += 101
            active_runtime = str(uuid.uuid4())
            active_mapping = stock_mapping(active_runtime, now[0] + 100)
            store.put_attachment(active_mapping)
            store.remember_stock_watch(active_mapping, stock_watch(
                active_runtime, {"repositoryId": 99, "prNumber": 1}))

            self.assertEqual(len(store.stock_watch_rows(detached_runtime)), 1)
            self.assertEqual(len(store.stock_watch_rows(expired_runtime)), 0)
            self.assertEqual(store.stock_watch_rows(detached_runtime)[0], pending_before)
            self.assertEqual(len(store.stock_watch_rows(active_runtime)), 1)

    def test_active_rows_and_inactive_pending_rows_still_enforce_capacity(self):
        now = [time.time()]
        for inactive, pending in ((False, False), (True, True)):
            with self.subTest(inactive=inactive, pending=pending), tempfile.TemporaryDirectory() as directory:
                with Store(Path(directory).resolve(), clock=lambda: now[0]) as store:
                    old_runtime = str(uuid.uuid4())
                    old_mapping = stock_mapping(old_runtime, now[0] + 100)
                    store.put_attachment(old_mapping)
                    for index in range(32):
                        subject = {"repositoryId": 17, "prNumber": index + 1}
                        store.remember_stock_watch(old_mapping, stock_watch(old_runtime, subject))
                        if pending:
                            store.save_stock_watch_request(old_runtime, subject, 1,
                                                           {"operationId": str(uuid.uuid4())})
                    before = store.stock_watch_rows(old_runtime)
                    if inactive:
                        store.detach(old_runtime)
                    new_mapping = stock_mapping(str(uuid.uuid4()), now[0] + 100)
                    store.put_attachment(new_mapping)
                    with self.assertRaises(StoreError) as caught:
                        store.remember_stock_watch(new_mapping, stock_watch(
                            new_mapping["runtimeId"], {"repositoryId": 99, "prNumber": 1}))
                    self.assertEqual(caught.exception.code, "capacity")
                    self.assertEqual(str(caught.exception), "stock_watch_capacity")
                    self.assertEqual(store.stock_watch_rows(old_runtime), before)


if __name__ == "__main__":
    unittest.main()
