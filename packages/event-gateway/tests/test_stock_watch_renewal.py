"""Durable, owner-listed Gateway watch renewal tests."""
import asyncio
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from event_gateway import daemon
from event_gateway.cloud import (
    CloudClient, CloudError, Credentials, _iso, _stock_watch_request, _stock_watch_view,
)
from event_gateway.store import Store, StoreError


RUNTIME = "12345678-1234-4234-8234-123456789abc"
CONVERSATION = "22345678-1234-4234-8234-123456789abc"
NODE = "32345678-1234-4234-8234-123456789abc"
SUBJECT = {"repositoryId": 17, "prNumber": 42}


def mapping(now):
    return {
        "runtimeId": RUNTIME, "principal": "owner@example.com", "agent": "codex",
        "nodeId": NODE, "nodeGeneration": 2, "runtimeGeneration": 3,
        "attachmentGeneration": 4, "consumerGeneration": 4,
        "leaseExpiresAt": now + 100,
        "runtimeProfile": {"profile": "assigned_stock_client", "client": "codex",
                           "conversationId": CONVERSATION},
    }


def watch(now_ms, *, lease_revision=6, subject=None, incarnation=5, lease_seconds=90):
    subject = dict(SUBJECT if subject is None else subject)
    return {
        "subject": subject, "incarnation": incarnation, "routingRevision": 7,
        "lifecycleEpoch": 8, "state": "attached",
        "source": {"installationId": 9, "grantRevision": 10, "mappingRevision": "m11",
                   "policyRevision": "p12", "sourceIncarnation": 13},
        "attachment": {
            "holder": {"runtimeId": RUNTIME, "runtimeGeneration": 3,
                       "attachmentGeneration": 4, "nodeId": NODE, "nodeGeneration": 2},
            "leaseRevision": lease_revision, "leaseUntil": now_ms + lease_seconds * 1000,
        },
        "sourceControl": {"mode": "watch", "status": "acknowledged",
                           "operationId": "42345678-1234-4234-8234-123456789abc",
                           "obligationId": "52345678-1234-4234-8234-123456789abc",
                           "reason": None},
    }


def runtime_response(mapping_value):
    return {"runtimeProfile": mapping_value["runtimeProfile"],
            "runtimeId": mapping_value["runtimeId"],
            "runtimeGeneration": mapping_value["runtimeGeneration"],
            "nodeId": mapping_value["nodeId"],
            "nodeGeneration": mapping_value["nodeGeneration"],
            "attachmentGeneration": mapping_value["attachmentGeneration"],
            "leaseUntil": _iso(mapping_value["leaseExpiresAt"])}


class StockWatchRenewalTests(unittest.IsolatedAsyncioTestCase):
    def test_watch_request_carries_assigned_client_and_defaults_old_mappings_to_codex(self):
        legacy = mapping(1)
        del legacy["runtimeProfile"]["client"]
        self.assertEqual(daemon._watch_request(legacy, "watch_list")["client"], "codex")

        claude = deepcopy(legacy)
        claude["runtimeProfile"]["client"] = "claude"
        self.assertEqual(daemon._watch_request(claude, "watch_list")["client"], "claude")

    def test_watch_factory_copies_default_subject(self):
        first = watch(1)
        second = watch(2)
        self.assertIsNot(first["subject"], second["subject"])
        self.assertIsNot(first["subject"], SUBJECT)

    def test_same_stock_mapping_rejects_missing_current_attachment(self):
        class MissingStore:
            @staticmethod
            def get_attachment(_runtime):
                return None

            @staticmethod
            def clock():
                return 1

        class CloudIdentity:
            principal, agent, node_id, node_generation = "owner@example.com", "codex", NODE, 2

        self.assertFalse(daemon._same_stock_mapping(
            MissingStore(), mapping(1), CloudIdentity()))

    def test_watch_receipt_match_rejects_missing_or_detached_attachments(self):
        original = watch(1000)
        renewed = watch(2000, lease_revision=7)
        self.assertTrue(daemon._watch_receipt_matches(original, renewed))
        for value in (None, "missing"):
            with self.subTest(side="original", attachment=value):
                candidate = deepcopy(original)
                if value == "missing":
                    del candidate["attachment"]
                else:
                    candidate["attachment"] = value
                self.assertFalse(daemon._watch_receipt_matches(candidate, renewed))
            with self.subTest(side="renewed", attachment=value):
                candidate = deepcopy(renewed)
                if value == "missing":
                    del candidate["attachment"]
                else:
                    candidate["attachment"] = value
                self.assertFalse(daemon._watch_receipt_matches(original, candidate))

    async def test_closed_watch_list_response_and_page_bound(self):
        now = time.time()
        attached = mapping(now)
        current = watch(int(now * 1000), lease_revision=6)

        async def run(watches):
            async def send(**_request):
                value = {"runtime": runtime_response(attached),
                         "outcome": {"status": "list", "watches": watches,
                                     "nextSubject": None}}
                return 200, {"content-type": "application/json"}, json.dumps(value).encode()

            client = CloudClient(
                origin="https://events.example.com", principal="owner@example.com",
                agent="codex", node_id=NODE, node_generation=2,
                private_key=Ed25519PrivateKey.generate(),
                credentials=lambda: asyncio.sleep(0, result=Credentials(None, "agent-token")), send=send,
                auth_mode="gateway", clock=lambda: now,
            )
            request = {"operation": "watch_list", "runtimeId": RUNTIME,
                       "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                       "expectedAttachmentGeneration": 4, "afterSubject": None}
            return await client.stock_watch(request)

        self.assertEqual((await run([current]))["outcome"]["watches"], [current])
        with self.assertRaisesRegex(CloudError, "invalid_response"):
            await run([watch(int(now * 1000), lease_seconds=121)])
        with self.assertRaisesRegex(CloudError, "invalid_response"):
            await run([watch(int(now * 1000), subject={"repositoryId": 17, "prNumber": pr})
                       for pr in range(1, 4)])

    async def test_watch_source_revisions_are_bounded_nonempty_strings(self):
        now = time.time()
        attached = mapping(now)
        current = watch(int(now * 1000))

        async def run(view):
            async def send(**_request):
                value = {"runtime": runtime_response(attached),
                         "outcome": {"status": "list", "watches": [view],
                                     "nextSubject": view["subject"]}}
                return 200, {"content-type": "application/json"}, json.dumps(value).encode()

            client = CloudClient(
                origin="https://events.example.com", principal="owner@example.com",
                agent="codex", node_id=NODE, node_generation=2,
                private_key=Ed25519PrivateKey.generate(),
                credentials=lambda: asyncio.sleep(0, result=Credentials(None, "agent-token")), send=send,
                auth_mode="gateway", clock=lambda: now,
            )
            request = {"operation": "watch_list", "runtimeId": RUNTIME,
                       "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                       "expectedAttachmentGeneration": 4, "afterSubject": None}
            return await client.stock_watch(request)

        for key in ("mappingRevision", "policyRevision"):
            valid_boundary = deepcopy(current)
            valid_boundary["source"][key] = "x" * 128
            await run(valid_boundary)
            for invalid in (0, "", "x" * 129):
                with self.subTest(field=key, value=invalid):
                    malformed = deepcopy(current)
                    malformed["source"][key] = invalid
                    with self.assertRaisesRegex(CloudError, "invalid_response"):
                        await run(malformed)

    async def test_watch_renew_response_requires_new_lease_revision_and_exact_holder(self):
        now = time.time()
        local = mapping(now)
        request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                   "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                   "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                   "subject": SUBJECT, "expectedWatchIncarnation": 5,
                   "expectedRoutingRevision": 7, "expectedLeaseRevision": 6, "leaseMs": 90000}

        async def call(view):
            async def send(**_request):
                value = {"runtime": runtime_response(local),
                         "outcome": {"status": "committed", "operationId": request["operationId"],
                                     "watch": view}}
                return 200, {"content-type": "application/json"}, json.dumps(value).encode()

            client = CloudClient(
                origin="https://events.example.com", principal="owner@example.com",
                agent="codex", node_id=NODE, node_generation=2,
                private_key=Ed25519PrivateKey.generate(),
                credentials=lambda: asyncio.sleep(0, result=Credentials(None, "agent-token")),
                send=send, auth_mode="gateway", clock=lambda: now,
            )
            return await client.stock_watch(request)

        current = watch(int(now * 1000), lease_revision=7, lease_seconds=80)
        self.assertEqual((await call(current))["outcome"]["watch"], current)
        stale = deepcopy(current)
        stale["attachment"]["leaseRevision"] = 6
        with self.assertRaisesRegex(CloudError, "invalid_response"):
            await call(stale)
        wrong_holder = deepcopy(current)
        wrong_holder["attachment"]["holder"]["runtimeGeneration"] = 4
        with self.assertRaisesRegex(CloudError, "invalid_response"):
            await call(wrong_holder)
        expired = deepcopy(current)
        expired["attachment"]["leaseUntil"] = int((now - 1) * 1000)
        with self.assertRaisesRegex(CloudError, "invalid_response"):
            await call(expired)

    async def test_durable_pending_request_survives_reopen_and_prunes_only_when_settled(self):
        now = [time.time()]
        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory).resolve(), clock=lambda: now[0]) as store:
                local = mapping(now[0])
                initial = watch(int(now[0] * 1000))
                store.remember_stock_watch(local, initial)
                request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                           "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                           "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                           "subject": SUBJECT, "expectedWatchIncarnation": 5,
                           "expectedRoutingRevision": 7, "expectedLeaseRevision": 6,
                           "leaseMs": 90000}
                store.save_stock_watch_request(RUNTIME, SUBJECT, 5, request)
            with Store(Path(directory).resolve(), clock=lambda: now[0]) as store:
                row, = store.stock_watch_rows(RUNTIME)
                self.assertEqual(row["pending"]["request"], request)
                self.assertEqual(store.prune_stock_watches(RUNTIME, set()), 0)
                renewed = watch(int(now[0] * 1000), lease_revision=7)
                self.assertTrue(store.finish_stock_watch_request(
                    RUNTIME, SUBJECT, 5, request, watch=renewed))
                self.assertEqual(store.prune_stock_watches(RUNTIME, set()), 1)

    async def test_settled_incarnation_churn_stays_within_existing_watch_quota(self):
        now = time.time()
        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now) as store:
            local = mapping(now)
            store.put_attachment(local)
            for incarnation in range(1, 42):
                current = watch(int(now * 1000), incarnation=incarnation)
                store.remember_stock_watch(local, current)
                self.assertEqual(store.prune_stock_watches(
                    RUNTIME, {(json.dumps(SUBJECT, sort_keys=True, separators=(",", ":")),
                               incarnation)}),
                    1 if incarnation > 1 else 0)
            rows = store.stock_watch_rows(RUNTIME)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["watch"]["incarnation"], 41)
            self.assertFalse(store.status()["stockWatchRenewal"]["capacity"])

    async def test_two_view_pages_recompute_expiry_before_renewal(self):
        now = [time.time()]
        local = mapping(now[0])
        started = now[0]
        views = [watch(int(now[0] * 1000),
                       subject={"repositoryId": 17, "prNumber": pr},
                       incarnation=1, lease_revision=6,
                       lease_seconds=74 if pr == 1 else 90)
                 for pr in range(1, 33)]
        list_requests = []
        renew_requests = []

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, request):
                if request["operation"] == "watch_list":
                    list_requests.append(deepcopy(request))
                    now[0] += 2
                    cursor = request["afterSubject"]
                    offset = 0 if cursor is None else next(
                        index + 1 for index, view in enumerate(views)
                        if view["subject"] == cursor)
                    page = views[offset:offset + 2]
                    next_subject = page[-1]["subject"] if offset + 2 < len(views) else None
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "list", "watches": page,
                                        "nextSubject": next_subject}}
                if request["operation"] == "watch_readback":
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "unresolved", "operationId": request["operationId"]}}
                renew_requests.append(deepcopy(request))
                renewed_at = int(now[0] * 1000)
                renewed = watch(renewed_at, subject=request["subject"],
                                incarnation=request["expectedWatchIncarnation"],
                                lease_revision=request["expectedLeaseRevision"] + 1,
                                lease_seconds=max(1, int(local["leaseExpiresAt"] - renewed_at / 1000)))
                return {"runtime": runtime_response(local),
                        "outcome": {"status": "committed", "operationId": request["operationId"],
                                    "watch": renewed}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
            self.assertEqual(len(list_requests), 16)
            self.assertTrue(all(
                len(list_requests[index]) == 7 and list_requests[index]["client"] == "codex"
                for index in range(16)))
            self.assertEqual(now[0], started + 32)
            self.assertEqual(len(store.stock_watch_rows(RUNTIME)), 32)
            self.assertEqual(len(renew_requests), 1)
            self.assertEqual(renew_requests[0]["subject"], views[0]["subject"])
            self.assertEqual(list_requests[-1]["afterSubject"], views[-3]["subject"])
            first = next(row for row in store.stock_watch_rows(RUNTIME)
                         if row["watch"]["subject"] == views[0]["subject"])
            self.assertEqual(first["watch"]["attachment"]["leaseRevision"], 7)

    async def test_over_quota_listing_does_not_prune_existing_pending_association(self):
        now = [time.time()]
        local = mapping(now[0])
        existing = watch(int(now[0] * 1000), subject={"repositoryId": 1, "prNumber": 1})
        request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                   "conversationId": CONVERSATION, "expectedRuntimeGeneration": 2,
                   "expectedAttachmentGeneration": 3, "operationId": str(uuid.uuid4()),
                   "subject": existing["subject"], "expectedWatchIncarnation": 5,
                   "expectedRoutingRevision": 7, "expectedLeaseRevision": 6, "leaseMs": 90000}
        views = [watch(int(now[0] * 1000),
                       subject={"repositoryId": 17, "prNumber": pr}, incarnation=1)
                 for pr in range(1, 34)]
        list_requests = []

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, value):
                if value["operation"] != "watch_list":
                    raise AssertionError("over-quota response must not renew a watch")
                list_requests.append(deepcopy(value))
                cursor = value["afterSubject"]
                offset = 0 if cursor is None else next(
                    index + 1 for index, view in enumerate(views)
                    if view["subject"] == cursor)
                page = views[offset:offset + 2]
                next_subject = page[-1]["subject"] if offset + 2 < len(views) else None
                return {"runtime": runtime_response(local),
                        "outcome": {"status": "list", "watches": page,
                                    "nextSubject": next_subject}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, existing)
            store.save_stock_watch_request(RUNTIME, existing["subject"], 5, request)
            before, = store.stock_watch_rows(RUNTIME)
            await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
            after, = store.stock_watch_rows(RUNTIME)
            self.assertEqual(len(list_requests), 16)
            self.assertEqual(after["pending"]["request"], before["pending"]["request"])
            self.assertEqual(after["watch"], before["watch"])
            self.assertEqual(after["failure"], "watch_list_over_quota")
            self.assertEqual(store.status()["stockWatchRenewal"]["associations"], 1)

    async def test_pending_watch_recovery_is_concurrent_and_bounded(self):
        now = [time.time()]
        local = mapping(now[0])
        watches = [watch(int(now[0] * 1000),
                         subject={"repositoryId": 17, "prNumber": pr},
                         lease_seconds=40)
                   for pr in range(1, 17)]
        in_flight = maximum_in_flight = 0
        completed = {}

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, request):
                nonlocal in_flight, maximum_in_flight
                if request["operation"] == "watch_readback":
                    in_flight += 1
                    maximum_in_flight = max(maximum_in_flight, in_flight)
                    try:
                        await asyncio.sleep(0.002)
                    finally:
                        in_flight -= 1
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "unresolved",
                                        "operationId": request["operationId"]}}
                if request["operation"] == "watch_renew":
                    original = next(item for item in watches
                                    if item["subject"] == request["subject"])
                    renewed = deepcopy(original)
                    renewed["attachment"]["leaseRevision"] += 1
                    renewed["attachment"]["leaseUntil"] = int(min(
                        local["leaseExpiresAt"], now[0] + 90) * 1000)
                    completed[request["subject"]["prNumber"]] = renewed
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "committed",
                                        "operationId": request["operationId"],
                                        "watch": renewed}}
                return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                        "outcome": {"status": "list", "watches": list(completed.values()),
                                    "nextSubject": None}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            for current in watches:
                store.remember_stock_watch(local, current)
                request = daemon._watch_request(local, "watch_renew", watch=current)
                store.save_stock_watch_request(RUNTIME, current["subject"],
                                               current["incarnation"], request)
            await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
            self.assertGreater(maximum_in_flight, 1)
            self.assertLessEqual(maximum_in_flight, daemon.STOCK_RENEW_PENDING_LIMIT)
            self.assertEqual(len(completed), len(watches))
            self.assertTrue(all(row["pending"] is None
                                for row in store.stock_watch_rows(RUNTIME)))

    async def test_slow_pending_watch_does_not_block_new_due_page_recovery(self):
        now = [time.time()]
        local = mapping(now[0])
        watch_a = watch(int(now[0] * 1000),
                        subject={"repositoryId": 17, "prNumber": 1}, lease_seconds=40)
        watch_b = watch(int(now[0] * 1000),
                        subject={"repositoryId": 17, "prNumber": 2}, lease_seconds=40)
        request_a = daemon._watch_request(local, "watch_renew", watch=watch_a)
        entered_a, release_a, renewed_b = asyncio.Event(), asyncio.Event(), asyncio.Event()
        views = {1: watch_a, 2: watch_b}

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, request):
                pr = request["subject"]["prNumber"] if "subject" in request else None
                if request["operation"] == "watch_list":
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "list", "watches": [watch_a, watch_b],
                                        "nextSubject": None}}
                if request["operation"] == "watch_readback" and pr == 1:
                    entered_a.set()
                    await release_a.wait()
                    receipt = deepcopy(watch_a)
                    receipt["attachment"]["leaseRevision"] += 1
                    receipt["attachment"]["leaseUntil"] = int(min(
                        local["leaseExpiresAt"], now[0] + 90) * 1000)
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "known",
                                        "operationId": request_a["operationId"],
                                        "watch": receipt}}
                if request["operation"] == "watch_readback":
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "unresolved",
                                        "operationId": request["operationId"]}}
                receipt = deepcopy(views[2])
                receipt["attachment"]["leaseRevision"] += 1
                receipt["attachment"]["leaseUntil"] = int(min(
                    local["leaseExpiresAt"], now[0] + 90) * 1000)
                views[2] = receipt
                renewed_b.set()
                return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                        "outcome": {"status": "committed",
                                    "operationId": request["operationId"],
                                    "watch": receipt}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, watch_a)
            store.save_stock_watch_request(RUNTIME, watch_a["subject"],
                                           watch_a["incarnation"], request_a)
            worker = asyncio.create_task(daemon._renew_stock_watches(
                store, FakeCloud(), asyncio.Event(), local))
            try:
                await asyncio.wait_for(entered_a.wait(), 1)
                await asyncio.wait_for(renewed_b.wait(), 1)
            finally:
                release_a.set()
                await asyncio.wait_for(worker, 1)
            rows = {row["watch"]["subject"]["prNumber"]: row
                    for row in store.stock_watch_rows(RUNTIME)}
            self.assertEqual(rows[1].get("receipt", {}).get("operationId"),
                             request_a["operationId"], rows)
            self.assertIsNone(rows[1]["pending"])
            self.assertIsNone(rows[2]["pending"])
            self.assertEqual(rows[2]["receipt"]["request"]["subject"], watch_b["subject"])

    async def test_late_stale_page_cannot_regress_settled_pending_receipt(self):
        now = [time.time()]
        local = mapping(now[0])
        stale = watch(int(now[0] * 1000),
                      subject={"repositoryId": 17, "prNumber": 3}, lease_seconds=40)
        request = daemon._watch_request(local, "watch_renew", watch=stale)
        settled = deepcopy(stale)
        settled["attachment"]["leaseRevision"] += 1
        settled["attachment"]["leaseUntil"] = int(min(
            local["leaseExpiresAt"], now[0] + 90) * 1000)
        readback_entered, release_readback = asyncio.Event(), asyncio.Event()
        listing_started, release_listing = asyncio.Event(), asyncio.Event()
        operations = []

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, value):
                operations.append(deepcopy(value))
                if value["operation"] == "watch_readback":
                    if value["operationId"] != request["operationId"]:
                        raise AssertionError("stale page must not create another operation")
                    readback_entered.set()
                    await release_readback.wait()
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "known",
                                        "operationId": request["operationId"],
                                        "watch": settled}}
                if value["operation"] == "watch_list":
                    listing_started.set()
                    await release_listing.wait()
                    # A server snapshot from before the pending receipt settles.
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "list", "watches": [stale],
                                        "nextSubject": None}}
                raise AssertionError("a stale page must not start a watch renewal")

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, stale)
            store.save_stock_watch_request(RUNTIME, stale["subject"],
                                           stale["incarnation"], request)
            worker = asyncio.create_task(daemon._renew_stock_watches(
                store, FakeCloud(), asyncio.Event(), local))
            try:
                await asyncio.wait_for(readback_entered.wait(), 1)
                await asyncio.wait_for(listing_started.wait(), 1)
                release_readback.set()
                for _ in range(100):
                    row, = store.stock_watch_rows(RUNTIME)
                    if row["pending"] is None:
                        break
                    await asyncio.sleep(0)
                self.assertIsNone(row["pending"])
                self.assertEqual(row["watch"], settled)
                self.assertTrue(daemon._stock_watch_page_is_stale(store, RUNTIME, stale))

                newer_route = deepcopy(stale)
                newer_route["routingRevision"] += 1
                self.assertFalse(daemon._stock_watch_page_is_stale(
                    store, RUNTIME, newer_route))
                newer_lease = deepcopy(stale)
                newer_lease["attachment"]["leaseRevision"] += 2
                self.assertFalse(daemon._stock_watch_page_is_stale(
                    store, RUNTIME, newer_lease))
                release_listing.set()
                await asyncio.wait_for(worker, 1)
            finally:
                release_readback.set()
                release_listing.set()
                if not worker.done():
                    await asyncio.wait_for(worker, 1)

            row, = store.stock_watch_rows(RUNTIME)
            self.assertEqual(row["watch"], settled)
            self.assertIsNone(row["pending"])
            self.assertEqual(row["receipt"]["operationId"], request["operationId"])
            self.assertEqual([value["operation"] for value in operations],
                             ["watch_readback", "watch_list"])

    async def test_expected_store_failure_during_recovery_isolated_per_watch(self):
        now = [time.time()]
        local = mapping(now[0])
        watches = [watch(int(now[0] * 1000),
                         subject={"repositoryId": 17, "prNumber": pr},
                         lease_seconds=40)
                   for pr in (1, 2)]
        listed = []
        failed_subject = []

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, request):
                if request["operation"] == "watch_readback":
                    current = next(value for value in watches
                                   if value["subject"] == request["subject"])
                    receipt = deepcopy(current)
                    receipt["attachment"]["leaseRevision"] += 1
                    receipt["attachment"]["leaseUntil"] = int(min(
                        local["leaseExpiresAt"], now[0] + 90) * 1000)
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "known", "watch": receipt}}
                return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                        "outcome": {"status": "list", "watches": listed,
                                    "nextSubject": None}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            for current in watches:
                store.remember_stock_watch(local, current)
                request = daemon._watch_request(local, "watch_renew", watch=current)
                store.save_stock_watch_request(RUNTIME, current["subject"],
                                               current["incarnation"], request)
                visible = deepcopy(current)
                visible["attachment"]["leaseUntil"] = int(min(
                    local["leaseExpiresAt"], now[0] + 90) * 1000)
                listed.append(visible)

            finish = store.finish_stock_watch_request

            def fail_once(runtime, subject, incarnation, request, **kwargs):
                if not failed_subject:
                    failed_subject.append(subject)
                    raise sqlite3.OperationalError("database is locked")
                return finish(runtime, subject, incarnation, request, **kwargs)

            store.finish_stock_watch_request = fail_once
            await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
            rows = {row["watch"]["subject"]["prNumber"]: row
                    for row in store.stock_watch_rows(RUNTIME)}
            self.assertEqual(len(failed_subject), 1)
            failed_pr = failed_subject[0]["prNumber"]
            self.assertIsNotNone(rows[failed_pr]["pending"])
            succeeded = rows[3 - failed_pr]
            self.assertIsNone(succeeded["pending"])
            self.assertIsNotNone(succeeded["receipt"])

    async def test_expected_store_failure_preparing_page_does_not_cancel_pending_recovery(self):  # noqa: MC0001
        now = [time.time()]
        local = mapping(now[0])
        pending = watch(int(now[0] * 1000),
                        subject={"repositoryId": 17, "prNumber": 1}, lease_seconds=40)
        failing = watch(int(now[0] * 1000),
                        subject={"repositoryId": 17, "prNumber": 2}, lease_seconds=40)
        healthy = watch(int(now[0] * 1000),
                        subject={"repositoryId": 17, "prNumber": 3}, lease_seconds=40)
        request = daemon._watch_request(local, "watch_renew", watch=pending)
        readback_entered, release_readback = asyncio.Event(), asyncio.Event()
        readback_cancelled = asyncio.Event()
        failed_page_persistence = asyncio.Event()
        listing_requests = []
        healthy_requests = []

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, value):
                if value["operation"] == "watch_readback":
                    if value["subject"] == healthy["subject"]:
                        healthy_requests.append(deepcopy(value))
                        return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                                "outcome": {"status": "unresolved",
                                            "operationId": value["operationId"]}}
                    readback_entered.set()
                    try:
                        await release_readback.wait()
                    except asyncio.CancelledError:
                        readback_cancelled.set()
                        raise
                    receipt = deepcopy(pending)
                    receipt["attachment"]["leaseRevision"] += 1
                    receipt["attachment"]["leaseUntil"] = int(min(
                        local["leaseExpiresAt"], now[0] + 90) * 1000)
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "known",
                                        "operationId": request["operationId"],
                                        "watch": receipt}}
                if value["operation"] == "watch_list":
                    listing_requests.append(deepcopy(value))
                    page = ([pending, failing] if value["afterSubject"] is None
                            else [healthy])
                    next_subject = failing["subject"] if value["afterSubject"] is None else None
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "list", "watches": page,
                                        "nextSubject": next_subject}}
                if value["operation"] == "watch_renew":
                    healthy_requests.append(deepcopy(value))
                    renewed = deepcopy(healthy)
                    renewed["attachment"]["leaseRevision"] += 1
                    renewed["attachment"]["leaseUntil"] = int(min(
                        local["leaseExpiresAt"], now[0] + 90) * 1000)
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "committed",
                                        "operationId": value["operationId"],
                                        "watch": renewed}}
                raise AssertionError(f"unexpected watch operation: {value['operation']}")

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, pending)
            store.save_stock_watch_request(RUNTIME, pending["subject"],
                                           pending["incarnation"], request)
            remember = store.remember_stock_watch

            def fail_second(mapping_value, watch_value):
                if watch_value["subject"] == failing["subject"]:
                    failed_page_persistence.set()
                    raise StoreError("storage_unavailable")
                return remember(mapping_value, watch_value)

            store.remember_stock_watch = fail_second
            worker = asyncio.create_task(daemon._renew_stock_watches(
                store, FakeCloud(), asyncio.Event(), local))
            try:
                await asyncio.wait_for(readback_entered.wait(), 1)
                await asyncio.wait_for(failed_page_persistence.wait(), 1)
                healthy_row = None
                for _ in range(1000):
                    healthy_row = next((entry for entry in store.stock_watch_rows(RUNTIME)
                                        if entry["watch"]["subject"] == healthy["subject"]), None)
                    if healthy_row is not None and healthy_row["pending"] is None:
                        break
                    await asyncio.sleep(0.001)
                self.assertIsNotNone(healthy_row)
                self.assertIsNone(healthy_row["pending"])
                for _ in range(100):
                    if worker.done() or readback_cancelled.is_set():
                        break
                    await asyncio.sleep(0.001)
                self.assertFalse(readback_cancelled.is_set())
                self.assertFalse(worker.done())
                rows = {entry["watch"]["subject"]["prNumber"]: entry
                        for entry in store.stock_watch_rows(RUNTIME)}
                self.assertEqual(rows[3]["receipt"]["operationId"],
                                 healthy_requests[-1]["operationId"])
                self.assertEqual(rows[3]["watch"]["attachment"]["leaseRevision"],
                                 healthy["attachment"]["leaseRevision"] + 1)
                self.assertEqual([value["afterSubject"] for value in listing_requests],
                                 [None, failing["subject"]])
                self.assertEqual([value["operation"] for value in healthy_requests],
                                 ["watch_readback", "watch_renew"])
                release_readback.set()
                await asyncio.wait_for(worker, 1)
                rows = {entry["watch"]["subject"]["prNumber"]: entry
                        for entry in store.stock_watch_rows(RUNTIME)}
                self.assertIsNone(rows[1]["pending"])
                self.assertEqual(rows[1]["receipt"]["operationId"], request["operationId"])
                self.assertEqual(rows[1]["watch"]["attachment"]["leaseRevision"],
                                 pending["attachment"]["leaseRevision"] + 1)
            finally:
                release_readback.set()
                await asyncio.gather(worker, return_exceptions=True)

    async def test_expected_prune_failure_does_not_cancel_pending_recovery(self):  # noqa: MC0001
        now = [time.time()]
        local = mapping(now[0])
        pending = watch(int(now[0] * 1000), lease_seconds=40)
        obsolete = watch(int(now[0] * 1000),
                         subject={"repositoryId": 17, "prNumber": 99}, lease_seconds=40)
        request = daemon._watch_request(local, "watch_renew", watch=pending)
        readback_entered, release_readback = asyncio.Event(), asyncio.Event()
        readback_cancelled = asyncio.Event()

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, value):
                if value["operation"] == "watch_readback":
                    readback_entered.set()
                    try:
                        await release_readback.wait()
                    except asyncio.CancelledError:
                        readback_cancelled.set()
                        raise
                    receipt = deepcopy(pending)
                    receipt["attachment"]["leaseRevision"] += 1
                    receipt["attachment"]["leaseUntil"] = int(min(
                        local["leaseExpiresAt"], now[0] + 90) * 1000)
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "known",
                                        "operationId": request["operationId"],
                                        "watch": receipt}}
                return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                        "outcome": {"status": "list", "watches": [],
                                    "nextSubject": None}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, pending)
            store.remember_stock_watch(local, obsolete)
            store.save_stock_watch_request(RUNTIME, pending["subject"],
                                           pending["incarnation"], request)

            def fail_prune(_runtime, _active_keys):
                raise StoreError("storage_unavailable")

            store.prune_stock_watches = fail_prune
            worker = asyncio.create_task(daemon._renew_stock_watches(
                store, FakeCloud(), asyncio.Event(), local))
            try:
                await asyncio.wait_for(readback_entered.wait(), 1)
                for _ in range(100):
                    if worker.done() or readback_cancelled.is_set():
                        break
                    await asyncio.sleep(0.001)
                self.assertFalse(readback_cancelled.is_set())
                self.assertFalse(worker.done())
                release_readback.set()
                await asyncio.wait_for(worker, 1)
                row = next(entry for entry in store.stock_watch_rows(RUNTIME)
                           if entry["watch"]["subject"] == pending["subject"])
                self.assertIsNone(row["pending"])
                self.assertIsNotNone(row["receipt"])
                self.assertEqual(row["receipt"]["operationId"], request["operationId"])
                self.assertEqual(row["watch"]["attachment"]["leaseRevision"],
                                 pending["attachment"]["leaseRevision"] + 1)
                self.assertEqual({entry["watch"]["subject"]["prNumber"]
                                  for entry in store.stock_watch_rows(RUNTIME)}, {42, 99})
            finally:
                release_readback.set()
                await asyncio.gather(worker, return_exceptions=True)

    async def test_expected_stale_query_failure_does_not_cancel_pending_recovery(self):  # noqa: MC0001
        now = [time.time()]
        local = mapping(now[0])
        pending = watch(int(now[0] * 1000), lease_seconds=40)
        obsolete = watch(int(now[0] * 1000),
                         subject={"repositoryId": 17, "prNumber": 99}, lease_seconds=40)
        request = daemon._watch_request(local, "watch_renew", watch=pending)
        readback_entered, release_readback = asyncio.Event(), asyncio.Event()
        readback_cancelled = asyncio.Event()

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, value):
                if value["operation"] == "watch_readback":
                    readback_entered.set()
                    try:
                        await release_readback.wait()
                    except asyncio.CancelledError:
                        readback_cancelled.set()
                        raise
                    receipt = deepcopy(pending)
                    receipt["attachment"]["leaseRevision"] += 1
                    receipt["attachment"]["leaseUntil"] = int(min(
                        local["leaseExpiresAt"], now[0] + 90) * 1000)
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "known",
                                        "operationId": request["operationId"],
                                        "watch": receipt}}
                return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                        "outcome": {"status": "list", "watches": [pending],
                                    "nextSubject": None}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, pending)
            store.remember_stock_watch(local, obsolete)
            store.save_stock_watch_request(RUNTIME, pending["subject"],
                                           pending["incarnation"], request)
            rows = store.stock_watch_rows
            queries = 0

            def fail_stale_query(runtime):
                nonlocal queries
                queries += 1
                if queries == 2:
                    raise StoreError("storage_unavailable")
                return rows(runtime)

            store.stock_watch_rows = fail_stale_query
            worker = asyncio.create_task(daemon._renew_stock_watches(
                store, FakeCloud(), asyncio.Event(), local))
            try:
                await asyncio.wait_for(readback_entered.wait(), 1)
                for _ in range(100):
                    if worker.done() or readback_cancelled.is_set():
                        break
                    await asyncio.sleep(0.001)
                self.assertFalse(readback_cancelled.is_set())
                self.assertFalse(worker.done())
                release_readback.set()
                await asyncio.wait_for(worker, 1)
                row = next(entry for entry in rows(RUNTIME)
                           if entry["watch"]["subject"] == pending["subject"])
                self.assertIsNone(row["pending"])
                self.assertEqual(row["receipt"]["operationId"], request["operationId"])
                self.assertEqual({entry["watch"]["subject"]["prNumber"]
                                  for entry in rows(RUNTIME)}, {42, 99})
            finally:
                release_readback.set()
                await asyncio.gather(worker, return_exceptions=True)

    async def test_all_32_fresh_due_watches_renew_before_their_45_second_expiry(self):
        base_now = time.time()
        now = [base_now]

        def virtual_clock():
            return now[0]

        local = mapping(base_now)
        watches = [watch(int(base_now * 1000),
                         subject={"repositoryId": 17, "prNumber": pr},
                         lease_seconds=45)
                   for pr in range(1, 33)]
        renewed = {}
        in_flight = maximum_in_flight = 0

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, request):
                nonlocal in_flight, maximum_in_flight
                deadline = now[0] + 1
                in_flight += 1
                maximum_in_flight = max(maximum_in_flight, in_flight)
                try:
                    await asyncio.sleep(0)
                    now[0] = max(now[0], deadline)
                finally:
                    in_flight -= 1
                if request["operation"] == "watch_list":
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "list", "watches": watches,
                                        "nextSubject": None}}
                if request["operation"] == "watch_readback":
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "unresolved",
                                        "operationId": request["operationId"]}}
                initial = next(value for value in watches
                               if value["subject"] == request["subject"])
                current = deepcopy(initial)
                current["attachment"]["leaseRevision"] += 1
                current["attachment"]["leaseUntil"] = int(min(
                    local["leaseExpiresAt"], now[0] + 90) * 1000)
                renewed[request["subject"]["prNumber"]] = current
                return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                        "outcome": {"status": "committed",
                                    "operationId": request["operationId"],
                                    "watch": current}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=virtual_clock) as store:
            store.put_attachment(local)
            await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
            self.assertEqual(len(renewed), 32)
            self.assertGreater(maximum_in_flight, 1)
            self.assertLessEqual(maximum_in_flight, daemon.STOCK_RENEW_PENDING_LIMIT)
            self.assertLess(now[0] - base_now, 45)

    async def test_due_watches_renew_during_paged_listing_before_cloud_expiry_filter(self):
        base_now = time.time()
        now = [base_now]
        local = mapping(base_now)
        views = {
            pr: watch(int(base_now * 1000),
                      subject={"repositoryId": 17, "prNumber": pr}, lease_seconds=45)
            for pr in range(1, 33)
        }
        list_pages = []
        renewed = []
        maximum_in_flight = in_flight = 0

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, request):
                nonlocal in_flight, maximum_in_flight
                in_flight += 1
                maximum_in_flight = max(maximum_in_flight, in_flight)
                try:
                    deadline = now[0] + (3 if request["operation"] == "watch_list" else 0)
                    await asyncio.sleep(0)
                    if request["operation"] == "watch_list":
                        await asyncio.sleep(0)
                        await asyncio.sleep(0)
                    now[0] = max(now[0], deadline)
                finally:
                    in_flight -= 1
                if request["operation"] == "watch_list":
                    active = [value for value in views.values()
                              if value["attachment"]["leaseUntil"] > now[0] * 1000]
                    after = request["afterSubject"]
                    if after is not None:
                        active = [value for value in active
                                  if value["subject"]["prNumber"] > after["prNumber"]]
                    active.sort(key=lambda value: value["subject"]["prNumber"])
                    page = active[:2]
                    next_subject = (page[-1]["subject"]
                                    if len(active) > 2 else None)
                    list_pages.append((request["afterSubject"], len(page), len(renewed)))
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "list", "watches": page,
                                        "nextSubject": next_subject}}
                if request["operation"] == "watch_readback":
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "unresolved",
                                        "operationId": request["operationId"]}}
                original = views[request["subject"]["prNumber"]]
                current = deepcopy(original)
                current["attachment"]["leaseRevision"] += 1
                current["attachment"]["leaseUntil"] = int(min(
                    local["leaseExpiresAt"], now[0] + 90) * 1000)
                views[request["subject"]["prNumber"]] = current
                renewed.append(request["subject"]["prNumber"])
                return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                        "outcome": {"status": "committed",
                                    "operationId": request["operationId"],
                                    "watch": current}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
            self.assertEqual(len(list_pages), 15)
            # Four unrenewed watches expire before their pages can arrive; Cloud
            # filters them. Every still-live page result is renewed while paging.
            self.assertEqual(len(renewed), 28)
            self.assertEqual(set(renewed), set(range(1, 29)))
            self.assertEqual(sum(page[1] for page in list_pages), 28)
            self.assertEqual(32 - len(renewed), 4)
            self.assertTrue(any(page[2] > 0 for page in list_pages[1:]))
            self.assertLessEqual(maximum_in_flight, daemon.STOCK_RENEW_PENDING_LIMIT)

    async def test_list_retains_settled_receipt_and_prunes_obsolete_watch(self):
        now = [time.time()]
        local = mapping(now[0])
        current = watch(int(now[0] * 1000), lease_seconds=90)
        obsolete = watch(int(now[0] * 1000),
                         subject={"repositoryId": 17, "prNumber": 99}, lease_seconds=90)

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, request):
                self.assert_operation = request["operation"]
                return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                        "outcome": {"status": "list", "watches": [current],
                                    "nextSubject": None}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            for value in (current, obsolete):
                store.remember_stock_watch(local, value)
                request = daemon._watch_request(local, "watch_renew", watch=value)
                store.save_stock_watch_request(RUNTIME, value["subject"],
                                               value["incarnation"], request)
                store.finish_stock_watch_request(
                    RUNTIME, value["subject"], value["incarnation"], request,
                    watch=value, failure="watch_unavailable")
            await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
            rows = store.stock_watch_rows(RUNTIME)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["watch"], current)
            self.assertIsNotNone(rows[0]["receipt"])
            self.assertEqual(rows[0]["failure"], "watch_unavailable")

    async def test_watch_capacity_exhaustion_does_not_terminate_worker(self):
        now = [time.time()]
        local = mapping(now[0])
        other_runtime = "42345678-1234-4234-8234-123456789abc"
        other = dict(mapping(now[0]), runtimeId=other_runtime)
        due = watch(int(now[0] * 1000),
                    subject={"repositoryId": 99, "prNumber": 1}, lease_seconds=40)
        listed = asyncio.Event()
        cloud_requests = []

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, request):
                cloud_requests.append(deepcopy(request))
                if request["operation"] != "watch_list":
                    raise AssertionError("capacity must prevent a new watch operation")
                listed.set()
                return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                        "outcome": {"status": "list", "watches": [due],
                                    "nextSubject": None}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.put_attachment(other)
            for pr in range(1, 33):
                existing = watch(int(now[0] * 1000),
                                 subject={"repositoryId": 17, "prNumber": pr})
                existing["attachment"]["holder"]["runtimeId"] = other_runtime
                store.remember_stock_watch(other, existing)
                if pr == 1:
                    pending = {"operation": "watch_renew", "runtimeId": other_runtime,
                               "operationId": str(uuid.uuid4()), "subject": existing["subject"]}
                    store.save_stock_watch_request(other_runtime, existing["subject"],
                                                   existing["incarnation"], pending)
            before = store.stock_watch_rows(other_runtime)
            ready, event, stop = {RUNTIME: local}, asyncio.Event(), asyncio.Event()
            event.set()
            worker = asyncio.create_task(daemon._stock_watch_worker(
                store, FakeCloud(), stop, ready, event))
            try:
                await asyncio.wait_for(listed.wait(), 1)
                for _ in range(20):
                    await asyncio.sleep(0.001)
                self.assertFalse(worker.done())
                self.assertEqual(store.stock_watch_rows(other_runtime), before)
                self.assertEqual(store.stock_watch_rows(RUNTIME), [])
                self.assertEqual([value["operation"] for value in cloud_requests],
                                 ["watch_list"])
            finally:
                stop.set()
                await asyncio.gather(worker, return_exceptions=True)

    async def test_deferred_capacity_refusal_does_not_cancel_existing_recovery(self):  # noqa: MC0001
        now = [time.time()]
        local = mapping(now[0])
        other_runtime = "42345678-1234-4234-8234-123456789abc"
        other = dict(mapping(now[0]), runtimeId=other_runtime)
        existing = watch(int(now[0] * 1000),
                         subject={"repositoryId": 99, "prNumber": 1}, lease_seconds=40)
        untracked = watch(int(now[0] * 1000),
                          subject={"repositoryId": 99, "prNumber": 2}, lease_seconds=40)
        request = daemon._watch_request(local, "watch_renew", watch=existing)
        receipt = deepcopy(existing)
        receipt["attachment"]["leaseRevision"] += 1
        receipt["attachment"]["leaseUntil"] = int(min(
            local["leaseExpiresAt"], now[0] + 90) * 1000)
        readback_entered, release_readback = asyncio.Event(), asyncio.Event()
        readback_cancelled = asyncio.Event()
        listing_seen, fallback_attempted = asyncio.Event(), asyncio.Event()
        cloud_requests = []

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, value):
                cloud_requests.append(deepcopy(value))
                if value["operation"] == "watch_list":
                    listing_seen.set()
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "list", "watches": [existing, untracked],
                                        "nextSubject": None}}
                if value["operation"] == "watch_readback":
                    if value["operationId"] != request["operationId"]:
                        raise AssertionError("deferred capacity row must not create a request")
                    readback_entered.set()
                    try:
                        await release_readback.wait()
                    except asyncio.CancelledError:
                        readback_cancelled.set()
                        raise
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "known",
                                        "operationId": request["operationId"],
                                        "watch": receipt}}
                raise AssertionError("capacity refusal must not send a new renewal")

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.put_attachment(other)
            store.remember_stock_watch(local, existing)
            store.save_stock_watch_request(RUNTIME, existing["subject"],
                                           existing["incarnation"], request)
            for pr in range(1, 32):
                current = watch(int(now[0] * 1000),
                                subject={"repositoryId": 17, "prNumber": pr})
                current["attachment"]["holder"]["runtimeId"] = other_runtime
                store.remember_stock_watch(other, current)
                if pr == 1:
                    pending = {"operation": "watch_renew", "runtimeId": other_runtime,
                               "operationId": str(uuid.uuid4()), "subject": current["subject"]}
                    store.save_stock_watch_request(other_runtime, current["subject"],
                                                   current["incarnation"], pending)
            other_before = store.stock_watch_rows(other_runtime)
            target_before = store.stock_watch_rows(RUNTIME)
            self.assertEqual(store.db.execute(
                "SELECT COUNT(*) FROM stock_watches").fetchone()[0], 32)
            remember = store.remember_stock_watch
            deferred_attempts = 0

            def track_deferred_attempt(mapping_value, watch_value):
                nonlocal deferred_attempts
                if (mapping_value["runtimeId"] == RUNTIME
                        and watch_value["subject"] == untracked["subject"]):
                    deferred_attempts += 1
                try:
                    return remember(mapping_value, watch_value)
                except StoreError:
                    if deferred_attempts >= 3:
                        fallback_attempted.set()
                    raise

            store.remember_stock_watch = track_deferred_attempt
            ready, event, stop = {RUNTIME: local}, asyncio.Event(), asyncio.Event()
            event.set()
            worker = asyncio.create_task(daemon._stock_watch_worker(
                store, FakeCloud(), stop, ready, event))
            try:
                await asyncio.wait_for(readback_entered.wait(), 1)
                await asyncio.wait_for(listing_seen.wait(), 1)
                for _ in range(100):
                    if fallback_attempted.is_set():
                        break
                    await asyncio.sleep(0.001)
                self.assertTrue(fallback_attempted.is_set(),
                                (deferred_attempts, worker.done(),
                                 worker.exception() if worker.done() else None,
                                 store.stock_watch_rows(RUNTIME)))
                await asyncio.sleep(0.01)
                self.assertFalse(worker.done())
                self.assertFalse(readback_cancelled.is_set())
                self.assertEqual(store.stock_watch_rows(other_runtime), other_before)
                self.assertEqual(store.stock_watch_rows(RUNTIME), target_before)
                self.assertEqual([value["operation"] for value in cloud_requests],
                                 ["watch_readback", "watch_list"])
                release_readback.set()
                for _ in range(100):
                    rows = store.stock_watch_rows(RUNTIME)
                    if rows[0]["pending"] is None:
                        break
                    await asyncio.sleep(0.001)
                self.assertIsNone(rows[0]["pending"])
                self.assertEqual(rows[0]["watch"], receipt)
                self.assertEqual(rows[0]["receipt"]["operationId"], request["operationId"])
                self.assertEqual(store.stock_watch_rows(other_runtime), other_before)
                self.assertFalse(worker.done())
            finally:
                release_readback.set()
                stop.set()
                await asyncio.gather(worker, return_exceptions=True)

    async def test_runtime_cas_precedes_watch_list_and_renewal(self):
        now = [time.time()]
        local = mapping(now[0])
        initial = watch(int(now[0] * 1000), lease_revision=6, lease_seconds=20)
        renewed_watch = watch(int(now[0] * 1000), lease_revision=7, lease_seconds=90)
        order = []
        stop = asyncio.Event()

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def assigned_stock(self, request):
                order.append(("runtime", deepcopy(request)))
                return {"leaseUntil": _iso(now[0] + 180)}

            async def stock_watch(self, request):
                order.append((request["operation"], deepcopy(request)))
                if request["operation"] == "watch_list":
                    current = store.get_attachment(RUNTIME)
                    self.assert_runtime_lease = current["leaseExpiresAt"]
                    return {"runtime": runtime_response(current),
                            "outcome": {"status": "list", "watches": [initial],
                                        "nextSubject": None}}
                if request["operation"] == "watch_readback":
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "unresolved", "operationId": request["operationId"]}}
                stop.set()
                return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                        "outcome": {"status": "committed", "operationId": request["operationId"],
                                    "watch": renewed_watch}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            await asyncio.wait_for(daemon._stock_renewal_worker(store, FakeCloud(), stop), 1)
            self.assertEqual([item[0] for item in order], [
                "runtime", "watch_list", "watch_readback", "watch_renew"])
            self.assertGreater(order[1][1]["expectedRuntimeGeneration"], 0)
            self.assertEqual(store.stock_watch_rows(RUNTIME)[0]["watch"], renewed_watch)

    async def test_persistence_retry_dispatches_watch_before_next_cloud_poll(self):
        now = [time.time()]
        local = mapping(now[0])
        stop = asyncio.Event()
        ready, event = {}, asyncio.Event()

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def assigned_stock(self, _request):
                return {"leaseUntil": _iso(now[0] + 180)}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)

            renew_attachment = store.renew_stock_attachment
            attempts = 0

            def fail_once(expected, lease_expires_at):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise StoreError("storage_unavailable")
                return renew_attachment(expected, lease_expires_at)

            store.renew_stock_attachment = fail_once
            with patch.object(daemon, "STOCK_RENEW_INTERVAL", 30), \
                    patch.object(daemon, "STOCK_RENEW_RETRY_INITIAL", 0.01), \
                    patch.object(daemon, "STOCK_RENEW_RETRY_MAX", 0.01):
                worker = asyncio.create_task(daemon._stock_renewal_worker(
                    store, FakeCloud(), stop, (ready, event)))
                try:
                    await asyncio.wait_for(event.wait(), 1)
                    self.assertEqual(list(ready), [RUNTIME])
                    self.assertEqual(attempts, 2)
                    self.assertGreater(store.get_attachment(RUNTIME)["leaseExpiresAt"],
                                       now[0] + 179.9)
                finally:
                    stop.set()
                    await asyncio.wait_for(worker, 1)

    async def test_watch_worker_runs_runtimes_independently_coalesces_and_stops(self):
        first = mapping(time.time())
        second = dict(first, runtimeId="42345678-1234-4234-8234-123456789abc")
        first_newer = dict(first, attachmentGeneration=5)
        ready, event, stop = {RUNTIME: first}, asyncio.Event(), asyncio.Event()
        entered_a, entered_b = asyncio.Event(), asyncio.Event()
        release_a = asyncio.Event()
        calls = []

        async def renew(_store, _cloud, _stop, value):
            calls.append(value)
            if value["runtimeId"] == RUNTIME and value["attachmentGeneration"] == 4:
                entered_a.set()
                await release_a.wait()
            elif value["runtimeId"] == RUNTIME:
                await asyncio.Future()
            else:
                entered_b.set()
                await asyncio.Future()

        with patch.object(daemon, "_renew_stock_watches", renew):
            worker = asyncio.create_task(daemon._stock_watch_worker(
                None, None, stop, ready, event))
            try:
                await asyncio.wait_for(entered_a.wait(), 1)
                ready[RUNTIME] = first_newer
                ready[second["runtimeId"]] = second
                event.set()
                await asyncio.wait_for(entered_b.wait(), 1)
                self.assertEqual(sum(value["runtimeId"] == RUNTIME for value in calls), 1)
                release_a.set()
                for _ in range(100):
                    if any(value.get("attachmentGeneration") == 5 for value in calls):
                        break
                    await asyncio.sleep(0.001)
                self.assertEqual([value.get("attachmentGeneration") for value in calls
                                  if value["runtimeId"] == RUNTIME], [4, 5])
            finally:
                stop.set()
                await asyncio.wait_for(worker, 1)
        self.assertTrue(worker.done())

    async def test_slow_watch_list_does_not_delay_runtime_heartbeat(self):
        now = time.time()
        stop = asyncio.Event()
        watch_entered = asyncio.Event()
        runtime_renewals = []

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def assigned_stock(self, _request):
                runtime_renewals.append(True)
                if len(runtime_renewals) == 2:
                    stop.set()
                return {"leaseUntil": _iso(time.time() + 180)}

            async def stock_watch(self, _request):
                watch_entered.set()
                await asyncio.Future()

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve()) as store:
            store.put_attachment(mapping(now))
            ready, event = {}, asyncio.Event()
            with patch.object(daemon, "STOCK_RENEW_INTERVAL", 0.01):
                heartbeat = asyncio.create_task(daemon._stock_renewal_worker(
                    store, FakeCloud(), stop, (ready, event)))
                watch_worker = asyncio.create_task(daemon._stock_watch_worker(
                    store, FakeCloud(), stop, ready, event))
                try:
                    await asyncio.wait_for(stop.wait(), 1)
                    await asyncio.wait_for(watch_entered.wait(), 1)
                    self.assertGreaterEqual(len(runtime_renewals), 2)
                finally:
                    heartbeat.cancel()
                    watch_worker.cancel()
                    await asyncio.gather(heartbeat, watch_worker, return_exceptions=True)

    async def test_restart_reads_back_then_retries_exact_operation_id(self):
        now = [time.time()]
        local = mapping(now[0])
        initial = watch(int(now[0] * 1000), lease_revision=6, lease_seconds=20)
        renewed_watch = watch(int(now[0] * 1000), lease_revision=7, lease_seconds=90)
        request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                   "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                   "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                   "subject": SUBJECT, "expectedWatchIncarnation": 5,
                   "expectedRoutingRevision": 7, "expectedLeaseRevision": 6, "leaseMs": 90000}
        order = []
        stop = asyncio.Event()

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, value):
                order.append(deepcopy(value))
                if value["operation"] == "watch_readback":
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "unresolved", "operationId": request["operationId"]}}
                stop.set()
                return {"runtime": runtime_response(local),
                        "outcome": {"status": "committed", "operationId": request["operationId"],
                                    "watch": renewed_watch}}

        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory).resolve(), clock=lambda: now[0]) as store:
                store.put_attachment(local)
                store.remember_stock_watch(local, initial)
                store.save_stock_watch_request(RUNTIME, SUBJECT, 5, request)
            with Store(Path(directory).resolve(), clock=lambda: now[0]) as store:
                await daemon._renew_stock_watches(store, FakeCloud(), stop, local)
                self.assertEqual([value["operation"] for value in order], ["watch_readback", "watch_renew"])
                self.assertEqual(order[1], request)
                self.assertEqual(store.stock_watch_rows(RUNTIME)[0]["watch"], renewed_watch)

    async def test_unresolved_old_renew_is_retained_unknown_then_higher_owner_resume_renews_new_op(self):
        now = [time.time()]
        local = mapping(now[0])
        initial = watch(int(now[0] * 1000), lease_revision=37, lease_seconds=20)
        resumed = watch(int(now[0] * 1000), lease_revision=38, lease_seconds=40)
        initial["source"].update(mappingRevision="😀" * 128, policyRevision="🚀" * 128)
        resumed["source"] = deepcopy(initial["source"])
        started_at = now[0]
        old_request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                       "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                       "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                       "subject": SUBJECT, "expectedWatchIncarnation": 5,
                       "expectedRoutingRevision": 7, "expectedLeaseRevision": 37,
                       "leaseMs": 90000}
        operations = []
        stop = asyncio.Event()

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, request):
                operations.append(deepcopy(request))
                if request["operation"] == "watch_readback":
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "unresolved", "operationId": request["operationId"]}}
                if request["operation"] == "watch_list":
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "list", "watches": [resumed], "nextSubject": None}}
                stop.set()
                return {"runtime": runtime_response(local),
                        "outcome": {"status": "committed", "operationId": request["operationId"],
                                    "watch": {**resumed, "attachment": {
                                        **resumed["attachment"], "leaseRevision": 39,
                                        "leaseUntil": resumed["attachment"]["leaseUntil"] + 90000}}}}

        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory).resolve(), clock=lambda: now[0]) as store:
                store.put_attachment(local)
                store.remember_stock_watch(local, initial)
                store.save_stock_watch_request(RUNTIME, SUBJECT, 5, old_request)
                now[0] += 21
            with Store(Path(directory).resolve(), clock=lambda: now[0]) as store:
                await daemon._renew_stock_watches(store, FakeCloud(), stop, local)
                row, = store.stock_watch_rows(RUNTIME)
                self.assertIsNone(row["pending"])
                self.assertEqual(row["watch"]["attachment"]["leaseRevision"], 39)
                self.assertEqual(len(row["indeterminate"]), 1)
                old = row["indeterminate"][0]
                self.assertEqual(old["request"], old_request)
                self.assertEqual(old["startedAt"], started_at)
                self.assertEqual(old["status"], "indeterminate")
                self.assertEqual(old["authoritativeWatch"], resumed)
                renewals = [request for request in operations if request["operation"] == "watch_renew"]
                self.assertEqual(len(renewals), 1)
                self.assertNotEqual(renewals[0]["operationId"], old_request["operationId"])
                self.assertEqual(renewals[0]["expectedLeaseRevision"], 38)
                self.assertEqual(store.status()["stockWatchRenewal"]["indeterminate"], 1)

    async def test_unresolved_resume_reconciliation_rejects_changed_identity_and_nonhigher_lease(self):
        for change in ("lease", "holder", "source", "routing"):
            with self.subTest(change=change):
                now = [time.time()]
                local = mapping(now[0])
                initial = watch(int(now[0] * 1000), lease_revision=37, lease_seconds=20)
                projection = watch(int(now[0] * 1000), lease_revision=38, lease_seconds=90)
                if change == "lease":
                    projection["attachment"]["leaseRevision"] = 36
                elif change == "holder":
                    projection["attachment"]["holder"]["runtimeGeneration"] += 1
                elif change == "source":
                    projection["source"]["grantRevision"] += 1
                else:
                    projection["routingRevision"] += 1
                request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                           "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                           "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                           "subject": SUBJECT, "expectedWatchIncarnation": 5,
                           "expectedRoutingRevision": 7, "expectedLeaseRevision": 37,
                           "leaseMs": 90000}

                class FakeCloud:
                    principal, agent = "owner@example.com", "codex"
                    node_id, node_generation = NODE, 2

                    async def stock_watch(self, value):
                        if value["operation"] == "watch_readback":
                            return {"runtime": runtime_response(local),
                                    "outcome": {"status": "unresolved", "operationId": request["operationId"]}}
                        if value["operation"] == "watch_list":
                            return {"runtime": runtime_response(local),
                                    "outcome": {"status": "list", "watches": [projection], "nextSubject": None}}
                        raise AssertionError("unmatched listing must not start another renewal")

                with tempfile.TemporaryDirectory() as directory, Store(
                        Path(directory).resolve(), clock=lambda: now[0]) as store:
                    store.put_attachment(local)
                    store.remember_stock_watch(local, initial)
                    store.save_stock_watch_request(RUNTIME, SUBJECT, 5, request)
                    now[0] += 21
                    await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
                    row, = store.stock_watch_rows(RUNTIME)
                    self.assertEqual(row["pending"]["request"], request)
                    self.assertFalse(row.get("indeterminate"))

    async def test_unresolved_resume_history_survives_pruning_and_capacity_refuses_archive(self):
        now = [time.time()]
        local = mapping(now[0])
        initial = watch(int(now[0] * 1000), lease_revision=37, lease_seconds=20)
        resumed = watch(int(now[0] * 1000), lease_revision=38, lease_seconds=90)
        request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                   "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                   "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                   "subject": SUBJECT, "expectedWatchIncarnation": 5,
                   "expectedRoutingRevision": 7, "expectedLeaseRevision": 37,
                   "leaseMs": 90000}
        next_request = {**request, "operationId": str(uuid.uuid4()),
                        "expectedLeaseRevision": 38, "client": "codex"}
        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, initial)
            store.save_stock_watch_request(RUNTIME, SUBJECT, 5, request)
            self.assertTrue(store.reconcile_stock_watch_resume(
                RUNTIME, SUBJECT, 5, request, resumed, next_request=next_request))
            self.assertEqual(store.prune_stock_watches(RUNTIME, set()), 0)
            row, = store.stock_watch_rows(RUNTIME)
            self.assertEqual(row["indeterminate"][0]["request"], request)
            replacement = {**request, "operationId": str(uuid.uuid4())}
            self.assertFalse(store.reconcile_stock_watch_resume(
                RUNTIME, SUBJECT, 5, replacement, resumed, next_request=next_request))

            store.save_stock_watch_request(RUNTIME, SUBJECT, 5, next_request)
            data = json.loads(store.db.execute(
                "SELECT data FROM stock_watches WHERE runtime=?", (RUNTIME,),
            ).fetchone()[0])
            data["indeterminate"][0]["padding"] = "x" * 14000
            with store.db:
                store.db.execute("UPDATE stock_watches SET data=? WHERE runtime=?",
                                 (json.dumps(data, sort_keys=True, separators=(",", ":")), RUNTIME))
            too_large = watch(int(now[0] * 1000), lease_revision=39, lease_seconds=30)
            next_next_request = {**next_request, "operationId": str(uuid.uuid4()),
                                 "expectedLeaseRevision": 39}
            with self.assertRaisesRegex(StoreError, "invalid_stock_watch"):
                store.reconcile_stock_watch_resume(
                    RUNTIME, SUBJECT, 5, next_request, too_large,
                    next_request=next_next_request,
                )
            row, = store.stock_watch_rows(RUNTIME)
            self.assertEqual(row["pending"]["request"], next_request)
            self.assertEqual(row["watch"]["attachment"]["leaseRevision"], 38)
            self.assertEqual(len(row["indeterminate"]), 1)

    async def test_expired_unresolved_readback_timeout_does_not_archive_higher_listing(self):
        now = [time.time()]
        local = mapping(now[0])
        initial = watch(int(now[0] * 1000), lease_revision=37, lease_seconds=20)
        resumed = watch(int(now[0] * 1000), lease_revision=38, lease_seconds=40)
        request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                   "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                   "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                   "subject": SUBJECT, "expectedWatchIncarnation": 5,
                   "expectedRoutingRevision": 7, "expectedLeaseRevision": 37,
                   "leaseMs": 90000}

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, value):
                if value["operation"] == "watch_readback":
                    raise TimeoutError
                if value["operation"] == "watch_list":
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "list", "watches": [resumed], "nextSubject": None}}
                raise AssertionError("a timeout must not authorize archive or a replacement operation")

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, initial)
            store.save_stock_watch_request(RUNTIME, SUBJECT, 5, request)
            now[0] += 21
            await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
            row, = store.stock_watch_rows(RUNTIME)
            self.assertEqual(row["pending"]["request"], request)
            self.assertFalse(row.get("indeterminate"))
            self.assertEqual(row["failure"], "watch_unavailable")

    async def test_resume_history_reserves_room_for_new_request_and_receipt(self):
        self.assertEqual(
            len(json.dumps(-float("1.7976931348623157e308")).encode()), 24,
        )
        now = [time.time()]
        local = mapping(now[0])
        initial = watch(int(now[0] * 1000), lease_revision=37, lease_seconds=20)
        resumed = watch(int(now[0] * 1000), lease_revision=38, lease_seconds=40)
        request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                   "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                   "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                   "subject": SUBJECT, "expectedWatchIncarnation": 5,
                   "expectedRoutingRevision": 7, "expectedLeaseRevision": 37,
                   "leaseMs": 90000}
        next_request = {**request, "operationId": str(uuid.uuid4()),
                        "expectedLeaseRevision": 38, "client": "codex"}
        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, initial)
            row, = store.stock_watch_rows(RUNTIME)
            row["indeterminate"] = [{"status": "indeterminate", "padding": "😀" * 1257}]
            store.db.execute("UPDATE stock_watches SET data=? WHERE runtime=?",
                             (json.dumps(row, sort_keys=True, separators=(",", ":")), RUNTIME))
            store.save_stock_watch_request(RUNTIME, SUBJECT, 5, request)
            pending, = store.stock_watch_rows(RUNTIME)
            pending_bytes = len(json.dumps(pending, sort_keys=True,
                                           separators=(",", ":")).encode())
            self.assertGreaterEqual(pending_bytes, 16 * 1024 - 128)
            self.assertLessEqual(pending_bytes, 16 * 1024)
            now[0] += 21
            with self.assertRaisesRegex(StoreError, "invalid_stock_watch"):
                store.reconcile_stock_watch_resume(
                    RUNTIME, SUBJECT, 5, request, resumed, next_request=next_request,
                )
            row, = store.stock_watch_rows(RUNTIME)
            self.assertEqual(row["pending"]["request"], request)
            self.assertEqual(row["watch"], initial)
            self.assertEqual(row["indeterminate"][0]["padding"], "😀" * 1257)

    async def test_resume_reserve_covers_maximum_valid_watch_and_renewal_receipt(self):
        now = [time.time()]
        maximum = 2**53 - 1
        local = mapping(now[0])
        subject = {"repositoryId": maximum, "prNumber": maximum}
        source = {"installationId": maximum, "grantRevision": maximum,
                  "mappingRevision": "😀" * 128, "policyRevision": "🚀" * 128,
                  "sourceIncarnation": maximum}
        initial = watch(int(now[0] * 1000), lease_revision=maximum - 3,
                        subject=subject, lease_seconds=20)
        resumed = watch(int(now[0] * 1000), lease_revision=maximum - 2,
                        subject=subject, lease_seconds=40)
        for value in (initial, resumed):
            value.update(incarnation=maximum, routingRevision=maximum, lifecycleEpoch=maximum,
                         source=deepcopy(source))
            value["attachment"]["holder"].update(
                runtimeGeneration=maximum, attachmentGeneration=maximum,
                nodeGeneration=maximum,
            )
            value["sourceControl"].update(status="acknowledged", reason="authority_unavailable")
        request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                   "conversationId": CONVERSATION, "client": "claude",
                   "expectedRuntimeGeneration": maximum,
                   "expectedAttachmentGeneration": maximum,
                   "operationId": str(uuid.uuid4()), "subject": subject,
                   "expectedWatchIncarnation": maximum,
                   "expectedRoutingRevision": maximum,
                   "expectedLeaseRevision": maximum - 3, "leaseMs": 90000}
        next_request = {**request, "operationId": str(uuid.uuid4()),
                        "expectedLeaseRevision": maximum - 2}
        future_receipt = deepcopy(resumed)
        future_receipt["attachment"].update(
            leaseRevision=maximum - 1, leaseUntil=maximum - 1,
        )
        steady_request = {**next_request, "operationId": str(uuid.uuid4()),
                          "expectedLeaseRevision": maximum - 1}
        steady_receipt = deepcopy(resumed)
        steady_receipt["attachment"].update(
            leaseRevision=maximum, leaseUntil=maximum,
        )
        self.assertEqual(_stock_watch_request(next_request), next_request)
        self.assertEqual(_stock_watch_request(steady_request), steady_request)
        for value in (initial, resumed, future_receipt, steady_receipt):
            self.assertEqual(_stock_watch_view(value), value)
        self.assertEqual(daemon._watch_receipt_matches(resumed, future_receipt), True)
        self.assertEqual(daemon._watch_receipt_matches(future_receipt, steady_receipt), True)
        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, initial)
            store.save_stock_watch_request(RUNTIME, subject, maximum, request)
            now[0] += 21
            self.assertTrue(store.reconcile_stock_watch_resume(
                RUNTIME, subject, maximum, request, resumed, next_request=next_request))
            archived, = store.stock_watch_rows(RUNTIME)
            archived_bytes = len(json.dumps(archived, sort_keys=True,
                                             separators=(",", ":")).encode())
            self.assertLessEqual(archived_bytes, 16 * 1024)
            store.save_stock_watch_request(RUNTIME, subject, maximum, next_request)
            self.assertTrue(store.finish_stock_watch_request(
                RUNTIME, subject, maximum, next_request, watch=future_receipt,
            ))
            store.save_stock_watch_request(RUNTIME, subject, maximum, steady_request)
            steady_pending_bytes = len(json.dumps(
                store.stock_watch_rows(RUNTIME)[0], sort_keys=True,
                separators=(",", ":"),
            ).encode())
            self.assertTrue(store.finish_stock_watch_request(
                RUNTIME, subject, maximum, steady_request, watch=steady_receipt,
            ))
            completed, = store.stock_watch_rows(RUNTIME)
            completed_bytes = len(json.dumps(completed, sort_keys=True,
                                              separators=(",", ":")).encode())
            self.assertLessEqual(max(steady_pending_bytes, completed_bytes), 16 * 1024)

    async def test_fast_resume_reconciles_while_unrelated_readback_is_slow(self):
        now = [time.time()]
        local = mapping(now[0])
        slow_subject = {"repositoryId": 17, "prNumber": 41}
        resumed_subject = {"repositoryId": 17, "prNumber": 42}
        slow_watch = watch(int(now[0] * 1000), lease_revision=6,
                           subject=slow_subject, lease_seconds=20)
        old_resumed_watch = watch(int(now[0] * 1000), lease_revision=37,
                                  subject=resumed_subject, lease_seconds=20)
        resumed_watch = watch(int(now[0] * 1000), lease_revision=38,
                              subject=resumed_subject, lease_seconds=40)

        def request_for(watch_value):
            return {"operation": "watch_renew", "runtimeId": RUNTIME,
                    "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                    "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                    "subject": watch_value["subject"],
                    "expectedWatchIncarnation": watch_value["incarnation"],
                    "expectedRoutingRevision": watch_value["routingRevision"],
                    "expectedLeaseRevision": watch_value["attachment"]["leaseRevision"],
                    "leaseMs": 90000}

        slow_request, old_request = request_for(slow_watch), request_for(old_resumed_watch)
        slow_readback, release_slow, new_renewal = asyncio.Event(), asyncio.Event(), asyncio.Event()

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, value):
                if value["operation"] == "watch_list":
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "list",
                                        "watches": [slow_watch, resumed_watch],
                                        "nextSubject": None}}
                if value["operation"] == "watch_readback":
                    if value["operationId"] == slow_request["operationId"]:
                        slow_readback.set()
                        await release_slow.wait()
                        return {"runtime": runtime_response(local),
                                "outcome": {"status": "unresolved",
                                            "operationId": slow_request["operationId"]}}
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "unresolved",
                                        "operationId": value["operationId"]}}
                if (value["operation"] == "watch_renew"
                        and value["expectedLeaseRevision"] == 38):
                    new_renewal.set()
                    renewed = {**resumed_watch, "attachment": {
                        **resumed_watch["attachment"], "leaseRevision": 39,
                        "leaseUntil": resumed_watch["attachment"]["leaseUntil"] + 90000}}
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "committed",
                                        "operationId": value["operationId"], "watch": renewed}}
                raise AssertionError("unrelated expired request must not be replayed")

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, slow_watch)
            store.save_stock_watch_request(RUNTIME, slow_subject, 5, slow_request)
            store.remember_stock_watch(local, old_resumed_watch)
            store.save_stock_watch_request(RUNTIME, resumed_subject, 5, old_request)
            now[0] += 21
            worker = asyncio.create_task(daemon._renew_stock_watches(
                store, FakeCloud(), asyncio.Event(), local,
            ))
            try:
                await asyncio.wait_for(slow_readback.wait(), 1)
                await asyncio.wait_for(new_renewal.wait(), 1)
                self.assertFalse(release_slow.is_set())
                resumed_row = next(row for row in store.stock_watch_rows(RUNTIME)
                                   if row["watch"]["subject"] == resumed_subject)
                self.assertEqual(resumed_row["watch"]["attachment"]["leaseRevision"], 39)
                self.assertEqual(resumed_row["indeterminate"][0]["request"], old_request)
            finally:
                release_slow.set()
                await asyncio.wait_for(worker, 2)


    async def test_pending_receipt_ignores_source_control_health_but_pins_identity(self):
        for identity_change in (None, "operationId", "obligationId", "mode"):
            with self.subTest(identity_change=identity_change):
                now = [time.time()]
                local = mapping(now[0])
                original = watch(int(now[0] * 1000), lease_revision=6, lease_seconds=20)
                receipt = watch(int(now[0] * 1000), lease_revision=7, lease_seconds=90)
                receipt["sourceControl"]["status"] = "blocked"
                receipt["sourceControl"]["reason"] = "host_unavailable"
                if identity_change:
                    receipt["sourceControl"][identity_change] = (
                        "stopped" if identity_change == "mode"
                        else "62345678-1234-4234-8234-123456789abc")
                request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                           "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                           "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                           "subject": SUBJECT, "expectedWatchIncarnation": 5,
                           "expectedRoutingRevision": 7, "expectedLeaseRevision": 6,
                           "leaseMs": 90000}
                calls = []
                stop = asyncio.Event()

                class FakeCloud:
                    principal, agent = "owner@example.com", "codex"
                    node_id, node_generation = NODE, 2

                    async def stock_watch(self, value):
                        calls.append(value["operation"])
                        if value["operation"] != "watch_readback":
                            raise AssertionError("known receipt must not start another operation")
                        stop.set()
                        return {"runtime": runtime_response(local),
                                "outcome": {"status": "known", "operationId": request["operationId"],
                                            "watch": receipt}}

                with tempfile.TemporaryDirectory() as directory, Store(
                        Path(directory).resolve(), clock=lambda: now[0]) as store:
                    store.put_attachment(local)
                    store.remember_stock_watch(local, original)
                    store.save_stock_watch_request(RUNTIME, SUBJECT, 5, request)
                    await daemon._renew_stock_watches(store, FakeCloud(), stop, local)
                    row, = store.stock_watch_rows(RUNTIME)
                    self.assertEqual(calls, ["watch_readback"])
                    if identity_change is None:
                        self.assertIsNone(row["pending"])
                        self.assertEqual(row["watch"], receipt)
                    else:
                        self.assertEqual(row["pending"]["request"], request)
                        self.assertEqual(row["failure"], "watch_changed")

    async def test_detached_known_receipt_keeps_pending_request_for_replay(self):
        now = [time.time()]
        local = mapping(now[0])
        original = watch(int(now[0] * 1000), lease_revision=6)
        detached = watch(int(now[0] * 1000), lease_revision=7)
        detached["attachment"] = None
        request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                   "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                   "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                   "subject": SUBJECT, "expectedWatchIncarnation": 5,
                   "expectedRoutingRevision": 7, "expectedLeaseRevision": 6,
                   "leaseMs": 90000}
        stop = asyncio.Event()
        calls = []

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, value):
                calls.append(value["operation"])
                stop.set()
                return {"runtime": runtime_response(local),
                        "outcome": {"status": "known", "operationId": request["operationId"],
                                    "watch": detached}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, original)
            store.save_stock_watch_request(RUNTIME, SUBJECT, 5, request)
            await daemon._renew_stock_watches(store, FakeCloud(), stop, local)
            row, = store.stock_watch_rows(RUNTIME)
            self.assertEqual(calls, ["watch_readback"])
            self.assertEqual(row["pending"]["request"], request)
            self.assertEqual(row["failure"], "watch_changed")

    async def test_expired_exact_known_receipt_is_settled_with_expired_failure(self):
        now = [time.time()]
        local = mapping(now[0])
        original = watch(int(now[0] * 1000), lease_revision=6, lease_seconds=-10)
        receipt = watch(int(now[0] * 1000), lease_revision=7, lease_seconds=-5)
        request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                   "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                   "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                   "subject": SUBJECT, "expectedWatchIncarnation": 5,
                   "expectedRoutingRevision": 7, "expectedLeaseRevision": 6,
                   "leaseMs": 90000}
        stop = asyncio.Event()
        calls = []

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, value):
                calls.append(value["operation"])
                stop.set()
                return {"runtime": runtime_response(local),
                        "outcome": {"status": "known", "operationId": request["operationId"],
                                    "watch": receipt}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(local)
            store.remember_stock_watch(local, original)
            store.save_stock_watch_request(RUNTIME, SUBJECT, 5, request)
            await daemon._renew_stock_watches(store, FakeCloud(), stop, local)
            self.assertEqual(calls, ["watch_readback"])
            row, = store.stock_watch_rows(RUNTIME)
            self.assertIsNone(row["pending"])
            self.assertEqual(row["failure"], "watch_expired")
            self.assertEqual(row["receipt"], {"operationId": request["operationId"],
                                               "request": request, "watch": receipt})

    async def test_changed_mapping_never_reuses_old_pending_request(self):
        now = [time.time()]
        local = mapping(now[0])
        changed = {**local, "runtimeGeneration": 4, "attachmentGeneration": 5,
                   "consumerGeneration": 5}
        initial = watch(int(now[0] * 1000))
        request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                   "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                   "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                   "subject": SUBJECT, "expectedWatchIncarnation": 5,
                   "expectedRoutingRevision": 7, "expectedLeaseRevision": 6, "leaseMs": 90000}

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, _request):
                raise AssertionError("stale mapping must not reach Cloud")

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve(), clock=lambda: now[0]) as store:
            store.put_attachment(changed)
            store.remember_stock_watch(local, initial)
            store.save_stock_watch_request(RUNTIME, SUBJECT, 5, request)
            await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
            self.assertEqual(store.stock_watch_rows(RUNTIME)[0]["pending"]["request"], request)

    async def test_expired_watch_stops_with_visible_failure_and_no_new_operation(self):
        now = [time.time()]
        local = mapping(now[0])
        initial = watch(int(now[0] * 1000), lease_seconds=10)
        request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                   "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                   "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                   "subject": SUBJECT, "expectedWatchIncarnation": 5,
                   "expectedRoutingRevision": 7, "expectedLeaseRevision": 6, "leaseMs": 90000}
        calls = []

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, value):
                calls.append(value["operation"])
                if value["operation"] == "watch_readback":
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "unresolved", "operationId": request["operationId"]}}
                return {"runtime": runtime_response(local),
                        "outcome": {"status": "list", "watches": [], "nextSubject": None}}

        with tempfile.TemporaryDirectory() as directory:
            with Store(Path(directory).resolve(), clock=lambda: now[0]) as store:
                store.put_attachment(local)
                store.remember_stock_watch(local, initial)
                store.save_stock_watch_request(RUNTIME, SUBJECT, 5, request)
                now[0] += 11
                await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
                status = store.status()["stockWatchRenewal"]
                self.assertEqual(status["failures"], {"watch_expired": 1})
                self.assertEqual(status["pending"], 1)
                self.assertEqual(calls, ["watch_readback", "watch_list"])

    async def test_watch_request_rejects_lease_above_cloud_limit(self):
        request = {"operation": "watch_renew", "runtimeId": RUNTIME,
                   "conversationId": CONVERSATION, "expectedRuntimeGeneration": 3,
                   "expectedAttachmentGeneration": 4, "operationId": str(uuid.uuid4()),
                   "subject": SUBJECT, "expectedWatchIncarnation": 5,
                   "expectedRoutingRevision": 7, "expectedLeaseRevision": 6,
                   "leaseMs": 90001}
        with self.assertRaisesRegex(CloudError, "invalid_request"):
            _stock_watch_request(request)

    async def test_changed_routing_cas_is_visible_and_original_request_stays_pinned(self):
        now = time.time()
        local = mapping(now)
        initial = watch(int(now * 1000), lease_revision=6, lease_seconds=20)
        changed = {**watch(int(now * 1000), lease_revision=7, lease_seconds=90),
                   "routingRevision": 8}
        operations = []
        stop = asyncio.Event()

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, request):
                operations.append(deepcopy(request))
                if request["operation"] == "watch_list":
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "list", "watches": [initial],
                                        "nextSubject": None}}
                if request["operation"] == "watch_readback":
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "unresolved", "operationId": request["operationId"]}}
                return {"runtime": runtime_response(local),
                        "outcome": {"status": "committed", "operationId": request["operationId"],
                                    "watch": changed}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve()) as store:
            store.put_attachment(local)
            await daemon._renew_stock_watches(store, FakeCloud(), stop, local)
            row, = store.stock_watch_rows(RUNTIME)
            self.assertEqual(row["failure"], "watch_changed")
            self.assertEqual(row["pending"]["request"], operations[-1])
            self.assertEqual(operations[-1]["operation"], "watch_renew")

    async def test_runtime_lease_only_extension_during_rpc_does_not_break_watch_cas(self):
        now = time.time()
        local = mapping(now)
        initial = watch(int(now * 1000), lease_revision=6, lease_seconds=20)
        renewed = watch(int(now * 1000), lease_revision=7, lease_seconds=90)

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, request):
                if request["operation"] == "watch_list":
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "list", "watches": [initial], "nextSubject": None}}
                if request["operation"] == "watch_readback":
                    return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                            "outcome": {"status": "unresolved", "operationId": request["operationId"]}}
                current = store.get_attachment(RUNTIME)
                store.renew_stock_attachment(current, current["leaseExpiresAt"] + 120)
                return {"runtime": runtime_response(store.get_attachment(RUNTIME)),
                        "outcome": {"status": "committed", "operationId": request["operationId"],
                                    "watch": renewed}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve()) as store:
            store.put_attachment(local)
            await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
            row, = store.stock_watch_rows(RUNTIME)
            self.assertIsNone(row["pending"])
            self.assertEqual(row["watch"], renewed)

    async def test_runtime_assignment_drift_during_rpc_refuses_watch_receipt(self):
        now = time.time()
        local = mapping(now)
        initial = watch(int(now * 1000), lease_revision=6, lease_seconds=20)
        renewed = watch(int(now * 1000), lease_revision=7, lease_seconds=90)
        changed = {**local, "runtimeGeneration": 4, "attachmentGeneration": 5,
                   "consumerGeneration": 5}

        class FakeCloud:
            principal, agent = "owner@example.com", "codex"
            node_id, node_generation = NODE, 2

            async def stock_watch(self, request):
                if request["operation"] == "watch_list":
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "list", "watches": [initial], "nextSubject": None}}
                if request["operation"] == "watch_readback":
                    return {"runtime": runtime_response(local),
                            "outcome": {"status": "unresolved", "operationId": request["operationId"]}}
                store.put_attachment(changed)
                return {"runtime": runtime_response(changed),
                        "outcome": {"status": "committed", "operationId": request["operationId"],
                                    "watch": renewed}}

        with tempfile.TemporaryDirectory() as directory, Store(
                Path(directory).resolve()) as store:
            store.put_attachment(local)
            await daemon._renew_stock_watches(store, FakeCloud(), asyncio.Event(), local)
            row, = store.stock_watch_rows(RUNTIME)
            self.assertEqual(row["failure"], "runtime_changed")
            self.assertIsNotNone(row["pending"])

