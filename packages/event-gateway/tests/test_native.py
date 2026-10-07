import copy
import json
from pathlib import Path
import unittest
import uuid

from event_gateway.native import (
    EVENT_FIELDS, IDENTITY, NativeBridgeAdapter, NativeError,
    validate_receipt, validate_request,
)
from event_gateway.protocol import _timestamp

ADMISSION = json.loads((Path(__file__).resolve().parents[1]
                       / "contracts/event-control-v1/fixtures.json").read_text())["admitted"]


def request():
    envelope = ADMISSION["envelope"]
    return {
        "clientId": str(uuid.uuid4()), "serverInstanceId": str(uuid.uuid4()), "serverGeneration": 1,
        "threadId": str(uuid.uuid4()), "generation": 2, "clientUserMessageId": str(uuid.uuid4()),
        "attemptId": envelope["attemptId"], "deliveryId": envelope["deliveryId"], "permitId": ADMISSION["permitId"],
        "permitIssuedAt": _timestamp(ADMISSION["permitIssuedAt"]),
        "permitExpiresAt": _timestamp(ADMISSION["permitExpiresAt"]),
        "event": {key: copy.deepcopy(envelope[key]) for key in EVENT_FIELDS},
    }


def receipt(item, outcome=None):
    return {**{key: item[key] for key in IDENTITY}, "outcome": outcome or {"status": "unknown"}}


class Bridge:
    def __init__(self, item):
        """Initialize a recording bridge with the supplied request identity."""
        self.witness = {**{key: item[key] for key in (
            "clientId", "generation", "serverInstanceId", "serverGeneration", "threadId",
        )}, "eligible": True}
        self.outcome = {"status": "unknown"}
        self.calls = []

    def challenge(self):
        self.calls.append(("challenge", None))
        return self.witness

    def start(self, item):
        self.calls.append(("start", copy.deepcopy(item)))
        return self.outcome

    def restore_attempt(self, item):
        self.calls.append(("restore", copy.deepcopy(item)))

    def receipt(self, item):
        self.calls.append(("receipt", copy.deepcopy(item)))
        return self.outcome


class NativeValidationTests(unittest.TestCase):
    def test_receipt_v3_generation_is_exact_and_legacy_shape_stays_valid(self):
        item = request()
        legacy = receipt(item)
        bound = {**legacy, "generation": item["generation"]}
        self.assertEqual(validate_receipt(item, legacy), {"status": "unknown"})
        with self.assertRaises(NativeError):
            validate_receipt(item, bound)
        item["receiptVersion"] = 3
        with self.assertRaises(NativeError):
            validate_receipt(item, legacy)
        self.assertEqual(validate_receipt(item, bound), {"status": "unknown"})
        for generation in (True, float(item["generation"]), str(item["generation"]),
                           None, -1, 2**64, item["generation"] + 1):
            with self.subTest(generation=generation), self.assertRaises(NativeError):
                validate_receipt(item, {**bound, "generation": generation})
        with self.assertRaises(NativeError):
            validate_receipt(item, {**bound, "clientGeneration": item["generation"]})
        for invalid_request in ({key: value for key, value in item.items() if key != "generation"},
                                {**item, "generation": True}):
            with self.subTest(request=invalid_request), self.assertRaises(NativeError):
                validate_receipt(invalid_request, bound)

    def test_request_receipt_version_metadata_is_strict_and_retained(self):
        item = request()
        for version in (2, 3):
            local = {**item, "receiptVersion": version}
            self.assertEqual(validate_request(local, ADMISSION), local)
        for version in (None, True, False, "3", 2.0, 3.0, 0, 4, {}, []):
            with self.subTest(version=version), self.assertRaises(NativeError):
                validate_request({**item, "receiptVersion": version}, ADMISSION)
            with self.subTest(receipt_version=version), self.assertRaises(NativeError):
                validate_receipt({**item, "receiptVersion": version}, receipt(item))
        self.assertEqual(validate_request(item, ADMISSION), item)
        self.assertNotIn("receiptVersion", item)

    def test_request_closed_shape_types_and_admission_identity(self):
        item = request()
        self.assertEqual(validate_request(item, ADMISSION), item)
        for bad in (None, [], {}, {**item, "extra": True}):
            with self.subTest(bad=bad), self.assertRaises(NativeError):
                validate_request(bad, ADMISSION)
        for field, value in (("generation", True), ("serverGeneration", -1), ("generation", 2**64),
                             ("clientId", "not-uuid"), ("threadId", 1), ("attemptId", str(uuid.uuid4())),
                             ("clientUserMessageId", str(uuid.uuid1())),
                             ("deliveryId", "dly_" + "0" * 64), ("permitId", str(uuid.uuid4())),
                             ("permitExpiresAt", item["permitExpiresAt"] + 1),
                             ("event", {**item["event"], "eventReference": "changed"})):
            with self.subTest(field=field, value=value), self.assertRaises(NativeError):
                validate_request({**item, field: value}, ADMISSION)
        v7_turn_id = "018e2c70-7c6a-7a06-8000-000000000001"
        self.assertEqual(validate_request({**item, "clientUserMessageId": v7_turn_id}, ADMISSION)
                         ["clientUserMessageId"], v7_turn_id)
        for admission in (None, {}, {**ADMISSION, "permitIssuedAt": None}):
            with self.subTest(admission=admission), self.assertRaises(NativeError):
                validate_request(item, admission)

    def test_request_is_detached_bounded_and_json_safe(self):
        item = request()
        copied = validate_request(item, ADMISSION)
        copied["event"]["canonicalSubject"]["subjectId"] = "changed"
        self.assertNotEqual(copied, item)
        admission = copy.deepcopy(ADMISSION)
        admission["envelope"]["eventReference"] = "x" * 4096
        item["event"]["eventReference"] = admission["envelope"]["eventReference"]
        with self.assertRaises(NativeError):
            validate_request(item, admission)
        for value in (float("nan"), object()):
            with self.subTest(value=type(value).__name__), self.assertRaises(NativeError):
                validate_request({**request(), "generation": value}, ADMISSION)
        recursive = request()
        recursive["event"] = recursive
        with self.assertRaises(NativeError):
            validate_request(recursive, ADMISSION)

    def test_receipt_echo_is_closed_and_type_exact(self):
        item = request()
        valid = receipt(item)
        self.assertEqual(validate_receipt(item, valid), {"status": "unknown"})
        for bad in (None, [], {}, {**valid, "extra": True}, {**valid, "outcome": None}):
            with self.subTest(bad=bad), self.assertRaises(NativeError):
                validate_receipt(item, bad)
        for field in IDENTITY:
            value = not item[field] if isinstance(item[field], int) else str(uuid.uuid4())
            with self.subTest(field=field), self.assertRaises(NativeError):
                validate_receipt(item, {**valid, field: value})
        with self.assertRaises(NativeError):
            validate_receipt(item, {**valid, "serverGeneration": True})
        for outcome in ({"status": "unknown", "extra": True}, {"status": "unrecognized"},
                        {"status": "notStarted", "reason": "secret detail"}):
            with self.subTest(outcome=outcome), self.assertRaises(NativeError):
                validate_receipt(item, receipt(item, outcome))
        detached = validate_receipt(item, valid)
        detached["status"] = "changed"
        self.assertEqual(valid["outcome"], {"status": "unknown"})

    def test_terminal_receipt_excludes_nonretained_refusals(self):
        item = request()
        terminal = {"status": "terminalNotStarted", "reason": "busy", "receiptId": str(uuid.uuid4()), "replayed": True}
        self.assertEqual(validate_receipt(item, receipt(item, terminal)), terminal)
        for reason in ("permitInvalid", "duplicateConflict", "receiptCapacity"):
            with self.subTest(reason=reason), self.assertRaises(NativeError):
                validate_receipt(item, receipt(item, {**terminal, "reason": reason}))
            unretained = {"status": "notStarted", "reason": reason}
            self.assertEqual(validate_receipt(item, receipt(item, unretained)), unretained)
        for mutation in ({"receiptId": "bad"}, {"replayed": 1}, {"extra": True}, {"reason": []}):
            with self.subTest(mutation=mutation), self.assertRaises(NativeError):
                validate_receipt(item, receipt(item, {**terminal, **mutation}))

    def test_started_requires_exact_turn_correlation_and_replay_boolean(self):
        item = request()
        started = {"status": "started", "turnId": item["clientUserMessageId"], "replayed": False}
        self.assertEqual(validate_receipt(item, receipt(item, started)), started)
        for mutation in ({"turnId": str(uuid.uuid4())}, {"turnId": "bad"}, {"replayed": 0}, {"extra": True}):
            with self.subTest(mutation=mutation), self.assertRaises(NativeError):
                validate_receipt(item, receipt(item, {**started, **mutation}))

    def test_input_recorded_requires_opt_in_and_exact_observed_identity(self):
        item = request()
        observed = {"status": "inputRecorded", "turnId": item["clientUserMessageId"],
                    "itemId": str(uuid.uuid4()), "replayed": True}
        with self.assertRaises(NativeError):
            validate_receipt(item, receipt(item, observed))
        for item_id in (observed["itemId"], "018e2c70-7c6a-7a06-8000-000000000001"):
            outcome = {**observed, "itemId": item_id}
            self.assertEqual(validate_receipt(item, receipt(item, outcome), allow_input_recorded=True), outcome)
        for mutation in ({"extra": True}, {"turnId": str(uuid.uuid4())},
                         {"itemId": item["clientUserMessageId"]}, {"itemId": str(uuid.uuid1())},
                         {"itemId": observed["itemId"].upper()}, {"itemId": None},
                         {"replayed": False}, {"replayed": 1}):
            with self.subTest(mutation=mutation), self.assertRaises(NativeError):
                validate_receipt(item, receipt(item, {**observed, **mutation}), allow_input_recorded=True)
        for field in observed:
            incomplete = {key: value for key, value in observed.items() if key != field}
            with self.subTest(missing=field), self.assertRaises(NativeError):
                validate_receipt(item, receipt(item, incomplete), allow_input_recorded=True)
        for turn_id in (str(uuid.uuid1()), observed["turnId"].upper(), "bad"):
            invalid_request = {**item, "clientUserMessageId": turn_id}
            with self.subTest(turn_id=turn_id), self.assertRaises(NativeError):
                validate_receipt(invalid_request, receipt(invalid_request, {**observed, "turnId": turn_id}),
                                 allow_input_recorded=True)
        for field in IDENTITY:
            invalid_receipt = {**receipt(item, observed), field: None}
            with self.subTest(identity=field), self.assertRaises(NativeError):
                validate_receipt(item, invalid_receipt, allow_input_recorded=True)


class NativeAdapterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.item = request()
        self.bridge = Bridge(self.item)
        self.adapter = NativeBridgeAdapter({"nativeThreadId": self.item["threadId"]}, self.bridge)

    async def test_check_requires_eligible_selected_thread_and_clears_old_witness(self):
        self.assertEqual(await self.adapter.check(), "available")
        for witness in (None, {}, {**self.bridge.witness, "eligible": 1},
                        {**self.bridge.witness, "threadId": str(uuid.uuid4())}):
            self.bridge.witness = witness
            self.assertEqual(await self.adapter.check(), "unavailable")
            with self.assertRaisesRegex(NativeError, "^native_unavailable$"):
                await self.adapter.prepare(ADMISSION)
        for mapping in ({}, {"nativeThreadId": "bad"}):
            with self.assertRaisesRegex(NativeError, "^invalid_native_mapping$"):
                NativeBridgeAdapter(mapping, self.bridge)
        self.assertTrue(all(call[0] == "challenge" for call in self.bridge.calls))

    async def test_invalid_mapping_and_incomplete_witness_are_bounded(self):
        for mapping in (None, [], "private detail"):
            with self.subTest(mapping=mapping), self.assertRaisesRegex(NativeError, "^invalid_native_mapping$"):
                NativeBridgeAdapter(mapping, self.bridge)
        valid = dict(self.bridge.witness)
        for witness in ({"eligible": True, "threadId": self.item["threadId"]},
                        {**valid, "clientId": "bad"}, {**valid, "serverInstanceId": None},
                        {**valid, "generation": True}, {**valid, "serverGeneration": -1}):
            self.bridge.witness = witness
            with self.subTest(witness=witness):
                self.assertEqual(await self.adapter.check(), "unavailable")
                self.assertIsNone(self.adapter.witness)
        self.bridge.witness = dict(valid)
        self.assertEqual(await self.adapter.check(), "available")
        self.bridge.witness["threadId"] = str(uuid.uuid4())
        self.assertEqual((await self.adapter.prepare(ADMISSION))["threadId"], valid["threadId"])

    async def test_check_sanitizes_bridge_errors_and_invalidates_old_witness(self):
        self.assertEqual(await self.adapter.check(), "available")
        for exception in (ValueError, RuntimeError):
            def fail():
                raise exception("private bridge connection detail")
            self.bridge.challenge = fail
            with self.subTest(exception=exception), self.assertRaisesRegex(NativeError, "^native_unavailable$") as caught:
                await self.adapter.check()
            self.assertEqual(caught.exception.code, "native_unavailable")
            self.assertIsNone(self.adapter.witness)
            with self.assertRaisesRegex(NativeError, "^native_unavailable$"):
                await self.adapter.prepare(ADMISSION)

    async def test_prepare_binds_witness_and_admission_without_starting(self):
        with self.assertRaisesRegex(NativeError, "^native_unavailable$"):
            await self.adapter.prepare(ADMISSION)
        await self.adapter.check()
        prepared = await self.adapter.prepare(ADMISSION)
        self.assertEqual(validate_request(prepared, ADMISSION), prepared)
        for key in ("clientId", "generation", "serverInstanceId", "serverGeneration", "threadId"):
            self.assertEqual(prepared[key], self.bridge.witness[key])
        self.assertEqual(prepared["event"], self.item["event"])
        self.assertEqual(prepared["permitId"], self.item["permitId"])
        second = await self.adapter.prepare(ADMISSION)
        self.assertNotEqual(prepared["clientUserMessageId"], second["clientUserMessageId"])
        self.assertEqual(self.bridge.calls, [("challenge", None)])

    async def test_prepare_pins_receipt_mode_and_wire_operations_strip_local_metadata(self):
        for mode in (2, 3):
            with self.subTest(mode=mode):
                bridge = Bridge(self.item)
                bridge.receipt_version = mode
                adapter = NativeBridgeAdapter({"nativeThreadId": self.item["threadId"]}, bridge)
                self.assertEqual(await adapter.check(), "available")
                local = await adapter.prepare(ADMISSION)
                self.assertEqual(local.get("receiptVersion", 2), mode)
                self.assertEqual("receiptVersion" in local, mode == 3)
                wire = {key: value for key, value in local.items() if key != "receiptVersion"}
                result = await adapter.submit(local)
                self.assertEqual("generation" in result, mode == 3)
                self.assertEqual(await adapter.reconcile(local), result)
                self.assertEqual(bridge.calls[1:], [("start", wire), ("restore", wire), ("receipt", wire)])
                before = list(bridge.calls)
                for incompatible in ({**local, "receiptVersion": 5 - mode},
                                     {**local, "receiptVersion": True}):
                    with self.assertRaises(NativeError):
                        await adapter.submit(incompatible)
                    with self.assertRaises(NativeError):
                        await adapter.reconcile(incompatible)
                bridge.receipt_version = 5 - mode
                with self.assertRaises(NativeError):
                    await adapter.reconcile(local)
                self.assertEqual(bridge.calls, before)

    async def test_submit_uses_exact_request_and_validates_outcome(self):
        self.bridge.outcome = {"status": "started", "turnId": self.item["clientUserMessageId"], "replayed": False}
        result = await self.adapter.submit(self.item)
        self.assertEqual(result, receipt(self.item, self.bridge.outcome))
        self.assertEqual(self.bridge.calls, [("start", self.item)])
        self.bridge.outcome = {"status": "started", "turnId": str(uuid.uuid4()), "replayed": False}
        with self.assertRaises(NativeError):
            await self.adapter.submit(self.item)

    async def test_reconcile_restores_exact_request_and_only_reads_receipt(self):
        self.bridge.outcome = {"status": "terminalNotStarted", "reason": "busy", "receiptId": str(uuid.uuid4()), "replayed": True}
        result = await self.adapter.reconcile(self.item)
        self.assertEqual(result, receipt(self.item, self.bridge.outcome))
        self.assertEqual(self.bridge.calls, [("restore", self.item), ("receipt", self.item)])
        self.assertIsNone(self.adapter.witness)

    async def test_input_recorded_is_reconcile_only(self):
        self.bridge.outcome = {"status": "inputRecorded", "turnId": self.item["clientUserMessageId"],
                               "itemId": str(uuid.uuid4()), "replayed": True}
        with self.assertRaises(NativeError):
            await self.adapter.submit(self.item)
        self.bridge.calls.clear()
        self.assertEqual(await self.adapter.reconcile(self.item), receipt(self.item, self.bridge.outcome))
        self.assertEqual(self.bridge.calls, [("restore", self.item), ("receipt", self.item)])

    async def test_reconcile_rejects_nonreplayed_terminal_outcomes(self):
        for outcome in ({"status": "started", "turnId": self.item["clientUserMessageId"], "replayed": False},
                        {"status": "terminalNotStarted", "reason": "busy", "receiptId": str(uuid.uuid4()), "replayed": False}):
            self.bridge.outcome = outcome
            with self.subTest(outcome=outcome), self.assertRaises(NativeError):
                await self.adapter.reconcile(self.item)
        self.bridge.outcome = {"status": "unknown"}
        self.assertEqual(await self.adapter.reconcile(self.item), receipt(self.item))
        self.assertTrue(all(call[0] in ("restore", "receipt") for call in self.bridge.calls))


class LegacyStoredReceiptRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_schema4_v2_receipt_bytes_and_pending_ack_survive_restart(self):
        from test_gateway import GatewayTests

        fixture = GatewayTests(methodName="runTest")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        delivery_id = fixture.accept()["deliveryId"]
        fixture.drop_acknowledgment = True
        await fixture.gateway.dispatch(delivery_id)
        attempt = fixture.store.current_attempt(delivery_id)
        self.assertNotIn("generation", attempt["started_receipt"])
        self.assertTrue(fixture.store.native_receipt(delivery_id)["ack_pending"])
        # Seed existing v2 JSON with noncanonical whitespace to detect any rewrite.
        legacy_bytes = json.dumps(attempt["started_receipt"], indent=2).encode()
        with fixture.store.db:
            fixture.store.db.execute(
                "UPDATE attempts SET started_receipt=? WHERE delivery_id=?",
                (legacy_bytes.decode(), delivery_id),
            )
        query = "SELECT CAST(started_receipt AS BLOB), CAST(native_ack AS BLOB) FROM attempts WHERE delivery_id=?"
        before = tuple(fixture.store.db.execute(query, (delivery_id,)).fetchone())
        schema = fixture.store.db.execute("SELECT sql FROM sqlite_master ORDER BY name").fetchall()
        self.assertEqual(fixture.store.db.execute("PRAGMA user_version").fetchone()[0], 4)

        fixture.restart()
        self.assertEqual(fixture.store.db.execute("PRAGMA user_version").fetchone()[0], 4)
        self.assertEqual(fixture.store.db.execute("SELECT sql FROM sqlite_master ORDER BY name").fetchall(), schema)
        self.assertEqual(tuple(fixture.store.db.execute(query, (delivery_id,)).fetchone()), before)
        self.assertEqual(validate_receipt(attempt["native_request"],
                                          fixture.store.current_attempt(delivery_id)["started_receipt"]),
                         attempt["started_receipt"]["outcome"])
        fixture.recovered_outcome = "started"
        await fixture.gateway.reconcile(delivery_id)
        self.assertFalse(fixture.store.native_receipt(delivery_id)["ack_pending"])
        self.assertEqual(fixture.acknowledgments, [attempt["native_ack"], attempt["native_ack"]])
        self.assertEqual(fixture.lookups, fixture.submissions)
        self.assertEqual(len(fixture.submissions), 1)
        self.assertEqual(fixture.settlements, [])
        after = tuple(fixture.store.db.execute(query, (delivery_id,)).fetchone())
        self.assertEqual(after, before)
        self.assertEqual(after[0], legacy_bytes)
        self.assertNotIn("generation", json.loads(after[0]))


if __name__ == "__main__":
    unittest.main()
