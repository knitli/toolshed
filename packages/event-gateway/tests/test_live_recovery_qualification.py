import asyncio
import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from uuid import uuid4
from contextlib import closing

TOOL = (
    Path(__file__).resolve().parents[1]
    / "docs/native-bridge/live_recovery_qualification/journal.py"
)
SPEC = importlib.util.spec_from_file_location("live_recovery_journal", TOOL)
JOURNAL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(JOURNAL)
Journal, TransportFault, Refused, encoded = (
    JOURNAL.Journal,
    JOURNAL.TransportFault,
    JOURNAL.Refused,
    JOURNAL.encoded,
)


class Crashed(BaseException):
    pass


PHASE_ORDER = JOURNAL.CASE_ORDER


def manifest():
    node, attempt, permit, turn, item, receipt = [str(uuid4()) for _ in range(6)]
    base = {"deliveryId": "dly_" + "a" * 64, "attemptId": attempt, "nodeGeneration": 1}
    targets = {}
    for action in ("submitted", "observed"):
        correlation = {
            "kind": "native_input_recorded"
            if action == "observed"
            else "native_turn_started",
            "permitId": permit,
            "turnId": turn,
        }
        if action == "observed":
            correlation["itemId"] = item
        targets[action] = {
            "subject": "exact-subject",
            "nodeId": node,
            "request": {
                **base,
                "status": action,
                "nativeCorrelation": correlation,
                "eventId": str(uuid4()),
                "runtimeId": str(uuid4()),
                "schemaVersion": 1,
                "principal": "fixture@example.invalid",
                "agent": "fixture-agent",
                "runtimeGeneration": 1,
                "attachmentGeneration": 1,
                "deliveredSourceStateVersion": "version-1",
                "acknowledgedAt": "2026-10-13T00:00:00.000Z",
            },
        }
    targets["settle"] = {
        "subject": "exact-subject",
        "nodeId": node,
        "request": {
            **base,
            "permitId": permit,
            "evidence": {"type": "native_terminal_no_start", "receiptId": receipt},
        },
    }
    return {
        "version": 1,
        "origin": "https://example.invalid",
        "subjects": ["exact-subject"] + ["case-" + str(i) for i in range(1, 7)],
        "targets": targets,
        "claims": [
            {
                "subject": "exact-subject",
                "request": {k: base[k] for k in ("deliveryId", "attemptId")},
            }
        ],
    }


def phase_fixture():
    config = manifest()
    subjects = [f"native-mesh-recovery-20261013-{case.lower()}" for case in PHASE_ORDER]
    config["subjects"] = subjects
    config["targets"]["settle"]["subject"] = subjects[0]
    config["targets"]["submitted"]["subject"] = subjects[0]
    config["targets"]["observed"]["subject"] = subjects[0]
    claims = []
    cases = {}
    for index, case_id in enumerate(PHASE_ORDER):
        subject = subjects[index]
        request = {
            "deliveryId": "dly_" + format(index + 1, "064x"),
            "attemptId": str(uuid4()),
        }
        if case_id not in ("C2", "C3"):
            claims.append({"subject": subject, "request": request})
        binding = {
            "clientId": str(uuid4()),
            "connectionId": str(uuid4()),
            "backendPid": 5000 + index,
            "threadId": str(uuid4()),
            "generation": 2,
            "serverInstanceId": str(uuid4()),
            "serverGeneration": 4,
        }
        if case_id == "C3":
            binding = None
        cases[case_id] = {
            "subject": subject,
            "eventSha256": None
            if case_id == "C3"
            else JOURNAL.digest(case_id.encode()),
            "publicationSha256": None
            if case_id == "C3"
            else JOURNAL.digest((case_id + "-publication").encode()),
            "claimSha256": None
            if case_id in ("C2", "C3")
            else JOURNAL.digest(encoded(request)),
            "startSha256": (
                JOURNAL.digest((case_id + "-start").encode())
                if case_id in ("A1", "B1", "C1")
                else None
            ),
            "binding": binding,
            "nodeGeneration": 1,
            "runtimeGeneration": None if case_id == "C3" else index + 10,
            "attachmentGeneration": None if case_id == "C3" else index + 20,
        }
    config["claims"] = claims
    plan = {
        "version": 1,
        "order": list(PHASE_ORDER),
        "cases": cases,
        "faultTargets": {"submitted": "A1", "observed": "A1"},
        "nativeBusySignal": None,
    }
    return config, plan


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.now = 1000.0
        self.config = manifest()
        self.journal = self.open(create=True)
        self.journal.reserve("publication", "exact-subject")
        self.calls = []
        self.holds = []

    def tearDown(self):
        self.temp.cleanup()

    def open(self, config=None, create=False):
        return Journal(
            self.root, config or self.config, clock=lambda: self.now, create=create
        )

    def request(self, action="settle", **changes):
        body = (
            self.config["targets"][action]["request"]
            if action
            else self.config["claims"][0]["request"]
        )
        route = (
            "/v1/dispatch/settle-no-start"
            if action == "settle"
            else "/v1/ack"
            if action
            else "/v1/dispatch/claim"
        )
        request = {
            "method": "POST",
            "url": self.config["origin"] + route,
            "body": encoded(body),
            "headers": {
                "x-event-node-proof": json.dumps(
                    {"nonce": str(uuid4()), "signature": "DO-NOT-LOG"}
                ),
                "authorization": "DO-NOT-LOG",
            },
            "timeout": 5,
            "max_response_bytes": 8192,
            "follow_redirects": False,
        }
        request.update(changes)
        return request

    def response(self, action):
        target = self.config["targets"][action]
        value = (
            {**target["request"], "nodeId": target["nodeId"], "status": "not_started"}
            if action == "settle"
            else {"status": action, "current": action == "observed"}
        )
        return 200, {"content-type": "application/json"}, encoded(value)

    def durable(self, action, target, sha):
        return {
            "action": action,
            "subject": target["subject"],
            "requestSha256": sha,
            "committed": True,
        }

    async def hold(self, action, deadline):
        # Simulated abrupt process boundary; no native/process calls.
        reopened = self.open().snapshot()
        self.assertIn(action, reopened["witnesses"])
        self.assertIn(action, reopened["held"])
        self.assertEqual(deadline, 1008.0)
        self.holds.append(action)
        raise Crashed()

    def invoke(self, hook, action="settle", replay=False, request=None):
        return asyncio.run(
            hook.send(
                action=action,
                replay=replay,
                subject="exact-subject",
                operation_started_at=1000.0,
                **(request or self.request(action)),
            )
        )

    def hook(self, action="settle", response=None):
        async def send(**request):
            self.calls.append(request)
            # Reservation is durable before the injected effect port.
            self.assertEqual(self.open().snapshot()["sends"], len(self.calls))
            return response if response is not None else self.response(action)

        return TransportFault(
            self.journal, send, self.durable, self.hold, monotonic=lambda: self.now
        )

    def test_each_action_one_hold_then_exact_replay_after_reopen(self):
        for action in ("submitted", "observed", "settle"):
            hook = self.hook(action)
            with self.assertRaises(Crashed):
                self.invoke(hook, action)
            self.journal = self.open()
            self.assertEqual(
                self.invoke(self.hook(action), action, replay=True),
                self.response(action),
            )
        state = self.open().snapshot()
        self.assertEqual(state["sends"], 6)
        self.assertEqual(state["held"], {"submitted", "observed", "settle"})
        self.assertNotIn("DO-NOT-LOG", self.journal.path.read_text())

    def test_wrong_request_ids_or_route_refused_before_original(self):
        body = copy.deepcopy(self.config["targets"]["settle"]["request"])
        body["attemptId"] = str(uuid4())
        for request in (
            self.request(body=encoded(body)),
            self.request(url="https://other.invalid/v1/dispatch/settle-no-start"),
        ):
            with self.assertRaises(Refused):
                self.invoke(self.hook(), request=request)
        self.assertEqual(self.calls, [])

    def test_wrong_response_identity_not_a_commit(self):
        response = json.loads(self.response("settle")[2])
        response["nodeId"] = str(uuid4())
        with self.assertRaises(Refused):
            self.invoke(
                self.hook(
                    response=(
                        200,
                        {"content-type": "application/json"},
                        encoded(response),
                    )
                )
            )
        self.assertEqual(self.holds, [])
        self.assertEqual(self.open_snapshot()["witnesses"], {})

    def open_snapshot(self):
        return self.journal.snapshot()

    def test_malformed_success_responses_fail_closed(self):
        for raw in (
            b"{}",
            b'{"status":"observed","current":true,"current":true}',
            b'{"status":"observed","current":1}',
            b'{"status":"submitted","current":false}',
            b'{"status":"observed","current":false,"extra":1}',
            b"NaN",
        ):
            with self.subTest(raw=raw), tempfile.TemporaryDirectory() as directory:
                path = Path(directory).resolve()
                path.chmod(0o700)
                journal = Journal(
                    path, self.config, clock=lambda: self.now, create=True
                )
                journal.reserve("publication", "exact-subject")

                async def send(**_request):
                    return 200, {"content-type": "application/json"}, raw

                hook = TransportFault(
                    journal, send, self.durable, self.hold, monotonic=lambda: self.now
                )
                with self.assertRaises((Refused, ValueError)):
                    self.invoke(hook, "observed")
                self.assertEqual(journal.snapshot()["witnesses"], {})

    def test_transport_timeout_never_becomes_commit_and_send_stays_charged(self):
        async def send(**_request):
            raise TimeoutError("before response")

        with self.assertRaises(TimeoutError):
            self.invoke(
                TransportFault(
                    self.journal,
                    send,
                    self.durable,
                    self.hold,
                    monotonic=lambda: self.now,
                )
            )
        state = self.journal.snapshot()
        self.assertEqual(state["sends"], 1)
        self.assertEqual(state["witnesses"], {})
        with self.assertRaises(Refused):
            self.open()

    def test_expired_abort_write_preserves_original_transport_exception_identity(self):
        original = TimeoutError("original ambiguous transport timeout")

        async def send(**_request):
            self.now = 2200.0
            raise original

        hook = TransportFault(
            self.journal, send, self.durable, self.hold, monotonic=lambda: self.now
        )
        with self.assertRaises(TimeoutError) as got:
            self.invoke(hook)
        self.assertIs(got.exception, original)
        state = self.journal.snapshot()
        self.assertEqual(state["sends"], 1)
        self.assertEqual(state["witnesses"], {})
        with self.assertRaises(Refused):
            self.open()

    def test_duplicate_fault_and_duplicate_replay_refused(self):
        with self.assertRaises(Crashed):
            self.invoke(self.hook())
        with self.assertRaises(Refused):
            self.invoke(self.hook())
        self.assertEqual(len(self.calls), 1)
        self.invoke(self.hook(), replay=True)
        with self.assertRaises(Refused):
            self.invoke(self.hook(), replay=True)
        self.assertEqual(len(self.calls), 2)

    def test_replacement_claim_fenced_before_network(self):
        with self.assertRaises(Crashed):
            self.invoke(self.hook())
        with self.assertRaisesRegex(Refused, "replacement_claim_fenced"):
            self.invoke(self.hook(), action=None)
        self.assertEqual(len(self.calls), 1)

    def test_uncommitted_local_witness_refused_before_send(self):
        hook = self.hook()
        hook.durable_before_send = lambda *_args: {"committed": False}
        with self.assertRaises(Refused):
            self.invoke(hook)
        self.assertEqual(self.calls, [])

    def test_eighth_publication_fifth_start_fourth_restart_refused_persistently(self):
        for counter, limit in [("publication", 7), ("nativeStart", 4), ("restart", 3)]:
            for i in range(1 if counter == "publication" else 0, limit):
                self.open().reserve(counter, self.config["subjects"][i])
            with self.assertRaisesRegex(Refused, "budget_exhausted"):
                self.open().reserve(counter, "exact-subject")
            self.assertEqual(self.open().snapshot()["counts"][counter], limit)

    def test_reservation_survives_ambiguous_caller_effect(self):
        self.journal.reserve("publication", "case-1")
        # Crash/uncertain effect has no completion; reservation cannot replenish.
        self.assertEqual(self.open().snapshot()["counts"]["publication"], 2)
        with self.assertRaises(Refused):
            self.open().reserve("publication", "different-subject")

    def test_duplicate_subject_publication_or_start_is_never_reissued(self):
        for counter in ("publication", "nativeStart"):
            if counter != "publication":
                self.journal.reserve(counter, "exact-subject")
            with self.assertRaisesRegex(Refused, "duplicate_subject_reservation"):
                self.open().reserve(counter, "exact-subject")
            self.assertEqual(self.open().snapshot()["counts"][counter], 1)

    def test_missing_journal_on_reopen_never_creates_fresh_window(self):
        self.journal.path.unlink()
        with self.assertRaises(FileNotFoundError):
            self.open()
        self.assertFalse(self.journal.path.exists())

    def test_origin_and_closed_ack_schema_rejected(self):
        for origin in (
            "https://user@example.invalid",
            "https://example.invalid:443",
            "https://example.invalid/path",
            "https://example.invalid?x=1",
            "https://example.invalid#x",
        ):
            changed = copy.deepcopy(self.config)
            changed["origin"] = origin
            with self.assertRaises(Refused):
                self.open(changed)
        changed = copy.deepcopy(self.config)
        changed["targets"]["observed"]["request"]["extra"] = True
        with self.assertRaises(Refused):
            self.open(changed)

    def test_concurrent_reservations_have_one_durable_winner_per_case(self):
        from concurrent.futures import ThreadPoolExecutor

        def reserve(subject):
            try:
                self.open().reserve("publication", subject)
                return True
            except Refused:
                return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(reserve, self.config["subjects"] * 2))
        self.assertEqual(sum(results), 6)
        self.assertEqual(self.open().snapshot()["counts"]["publication"], 7)

    def test_unreserved_case_send_refused_before_original(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            root.chmod(0o700)
            journal = Journal(root, self.config, clock=lambda: self.now, create=True)

            async def forbidden(**_request):
                self.fail("unreserved network effect")

            hook = TransportFault(
                journal, forbidden, self.durable, self.hold, monotonic=lambda: self.now
            )
            with self.assertRaisesRegex(Refused, "publication_not_reserved"):
                self.invoke(hook)

    def test_valid_hash_but_invalid_record_schema_or_order_rejected(self):
        digest = JOURNAL.digest
        raw = self.journal.path.read_bytes()
        rows = [json.loads(line) for line in raw.splitlines()]
        for kind, value in [
            (
                "returned",
                {
                    "action": "settle",
                    "responseSha256": "a" * 64,
                    "response": json.loads(self.response("settle")[2]),
                    "at": 1000.0,
                },
            ),
            (
                "reserve",
                {
                    "counter": "publication",
                    "subject": "case-1",
                    "at": 1000.0,
                    "extra": True,
                },
            ),
        ]:
            payload = {
                "sequence": len(rows),
                "previous": rows[-1]["sha256"],
                "kind": kind,
                "value": value,
            }
            self.journal.path.write_bytes(
                raw + encoded({**payload, "sha256": digest(encoded(payload))}) + b"\n"
            )
            with self.assertRaises(Refused):
                self.open()
        self.journal.path.write_bytes(raw)

    def test_returned_hold_aborts_and_cannot_be_replayed(self):
        hook = self.hook()

        async def returned(_action, _deadline):
            return None

        hook.hold_reply = returned
        with self.assertRaisesRegex(Refused, "reply_hold_returned"):
            self.invoke(hook)
        with self.assertRaisesRegex(Refused, "run_aborted"):
            self.open()

    def test_fixed_expiry_never_reset_by_reopen(self):
        self.now = 2199.0
        self.assertEqual(self.open().snapshot()["expiresAt"], 2200.0)
        self.now = 2200.0
        with self.assertRaises(Refused):
            self.open()
        with self.assertRaises(Refused):
            self.journal.reserve("publication", "exact-subject")

    def test_changed_manifest_truncated_malformed_or_corrupt_tail_refused(self):
        changed = copy.deepcopy(self.config)
        changed["origin"] = "https://changed.invalid"
        with self.assertRaises(Refused):
            self.open(changed)
        original = self.journal.path.read_bytes()
        for raw in (
            original[:-1],
            b"not-json\n",
            original.replace(b"header", b"headeX"),
        ):
            self.journal.path.write_bytes(raw)
            with self.assertRaises((Refused, ValueError)):
                self.open()
        self.journal.path.write_bytes(original)

    def test_original_eight_second_clock_not_reset_after_response(self):
        async def send(**_request):
            self.now = 1007.0
            return self.response("settle")

        with self.assertRaisesRegex(Refused, "insufficient_crash_margin"):
            self.invoke(
                TransportFault(
                    self.journal,
                    send,
                    self.durable,
                    self.hold,
                    monotonic=lambda: self.now,
                )
            )
        self.assertEqual(self.holds, [])

    def test_observed_replay_current_can_change_but_body_cannot(self):
        with self.assertRaises(Crashed):
            self.invoke(self.hook("observed"), "observed")
        self.invoke(
            self.hook(
                "observed",
                (
                    200,
                    {"content-type": "application/json"},
                    b'{"status":"observed","current":false}',
                ),
            ),
            "observed",
            replay=True,
        )
        self.assertEqual(self.calls[0]["body"], self.calls[1]["body"])

    def test_submitted_true_is_not_accepted_observed_or_submitted_commit(self):
        with self.assertRaises(Refused):
            self.invoke(
                self.hook(
                    "submitted",
                    (
                        200,
                        {"content-type": "application/json"},
                        b'{"status":"submitted","current":true}',
                    ),
                ),
                "submitted",
            )
        self.assertEqual(self.holds, [])


class PhaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.now = 1000.0
        self.config, self.plan = phase_fixture()
        self.journal = Journal(
            self.root,
            self.config,
            clock=lambda: self.now,
            create=True,
            phase_plan=self.plan,
        )
        self.orchestrator = JOURNAL.RecoveryOrchestrator(self.journal)

    def reopen(self):
        return Journal(
            self.root, self.config, clock=lambda: self.now, phase_plan=self.plan
        )

    def test_ambiguous_publication_intent_survives_reopen_without_retry(self):
        self.orchestrator.begin_case("A1")
        self.orchestrator.publication_intent("A1", b"A1-publication")
        self.orchestrator.publication_result("A1", "ambiguous")
        resumed = self.reopen()
        self.assertEqual(resumed.snapshot()["phase"]["publications"], 1)
        self.assertEqual(resumed.snapshot()["counts"]["publication"], 1)
        self.assertEqual(
            resumed.snapshot()["phase"]["cases"]["A1"]["publicationOutcome"],
            "ambiguous",
        )
        with self.assertRaisesRegex(Refused, "invalid_publication_intent"):
            JOURNAL.RecoveryOrchestrator(resumed).publication_intent(
                "A1", b"A1-publication"
            )
        self.assertEqual(self.reopen().snapshot()["counts"]["publication"], 1)

    def test_native_start_attempt_and_accepted_outcome_budgets_are_separate(self):
        self.orchestrator.begin_case("A1")
        self.orchestrator.publication_intent("A1", b"A1-publication")
        self.orchestrator.publication_result("A1", "accepted", b"accepted")
        claim = self.config["claims"][0]["request"]
        self.orchestrator.claim_intent("A1", claim)
        self.orchestrator.claim_result("A1", "accepted", b"permit")
        start = b"A1-start"
        self.orchestrator.start_intent("A1", start)
        self.orchestrator.start_outcome("A1", start, "unknown", {"outcome": "unknown"})
        state = self.reopen().snapshot()
        self.assertEqual(state["counts"]["nativeStart"], 1)
        self.assertEqual(state["phase"]["startAttempts"], 1)
        self.assertEqual(state["phase"]["acceptedStarts"], 0)
        with self.assertRaisesRegex(Refused, "invalid_native_start_intent"):
            JOURNAL.RecoveryOrchestrator(self.reopen()).start_intent("A1", start)
        self.assertEqual(self.reopen().snapshot()["counts"]["nativeStart"], 1)

    def test_c2_fails_closed_without_reviewed_native_busy_signal(self):
        status = self.orchestrator.readiness()
        self.assertFalse(status["ready"])
        self.assertIn("native_core_busy_signal_not_promoted", status["blockers"])
        state = JOURNAL._new_phase_state()
        state["nextIndex"] = 3
        for case_id in ("A1", "B1", "C1"):
            state["cases"][case_id]["complete"] = True
        with self.assertRaisesRegex(Refused, "native_busy_signal_unqualified"):
            JOURNAL._apply_phase(
                self.plan,
                state,
                {"op": "begin_case", "caseId": "C2", "at": self.now},
                self.config,
            )
        self.assertEqual(state["nextIndex"], 3)
        self.assertIsNone(state["active"])
        fake_busy = copy.deepcopy(self.plan)
        fake_busy["nativeBusySignal"] = {
            "source": "caller",
            "evidenceSha256": "a" * 64,
            "bindingSha256": JOURNAL.digest(
                encoded(self.plan["cases"]["C1"]["binding"])
            ),
        }
        with self.assertRaisesRegex(
            Refused, "native_busy_signal_requires_reviewed_bridge_proof"
        ):
            JOURNAL.phase_plan_checked(fake_busy, self.config)

    def test_reattach_accepts_only_exact_counter_successor_and_preserves_old_event(
        self,
    ):
        old_case = self.plan["cases"]["C2"]
        new_binding = copy.deepcopy(old_case["binding"])
        new_binding["generation"] += 1
        new_event = "f" * 64
        result = JOURNAL.validate_reattach(
            self.plan,
            "C2",
            "C3",
            old_event_sha256=old_case["eventSha256"],
            new_event_sha256=new_event,
            old_binding=old_case["binding"],
            new_binding=new_binding,
            runtime_generation=old_case["runtimeGeneration"] + 1,
            attachment_generation=old_case["attachmentGeneration"] + 1,
        )
        self.assertEqual(result["oldEventSha256"], old_case["eventSha256"])
        self.assertEqual(result["newEventSha256"], new_event)
        self.assertEqual(result["oldBinding"], old_case["binding"])
        self.assertEqual(result["newBinding"], new_binding)
        self.assertEqual(
            result["newBinding"]["serverGeneration"],
            old_case["binding"]["serverGeneration"],
        )
        self.assertIsNone(self.plan["cases"]["C3"]["binding"])
        with self.assertRaisesRegex(Refused, "reattach_identity_mismatch"):
            lowered = copy.deepcopy(new_binding)
            lowered["generation"] -= 2
            JOURNAL.validate_reattach(
                self.plan,
                "C2",
                "C3",
                old_event_sha256=old_case["eventSha256"],
                new_event_sha256=new_event,
                old_binding=old_case["binding"],
                new_binding=lowered,
                runtime_generation=old_case["runtimeGeneration"] + 1,
                attachment_generation=old_case["attachmentGeneration"] + 1,
            )


class ProductionRecoveryIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_gateway_cloudclient_store_ack_survives_transport_reply_loss_and_replay(
        self,
    ):
        # Reuse the repository's production Gateway/Store/CloudClient fixture and
        # insert the fault wrapper at the injected CloudClient.send port.
        from test_gateway_integration import GatewayIntegrationTests as GatewayFixture
        from event_gateway.cloud import _json
        from event_gateway.native import IDENTITY as native_identity

        fixture = GatewayFixture(
            "test_real_clients_retire_terminal_no_start_then_ack_started_receipt"
        )
        fixture.setUp()
        try:
            fixture.bridge.outcome = "started"
            fixed_item = str(uuid4())
            setup = {"journal": None, "hook": None, "startedAt": None, "targets": None}
            original_ack = fixture.gateway._ack_native

            def durable_readback(action, target, request_sha256):
                attempt_id = target["request"]["attemptId"]
                column = "native_observed_ack" if action == "observed" else "native_ack"
                with closing(
                    sqlite3.connect(fixture.store.path / "ledger.sqlite")
                ) as reader:
                    reader.row_factory = sqlite3.Row
                    row = reader.execute(
                        "SELECT a.*,d.ack_state FROM attempts a JOIN deliveries d ON d.id=a.delivery_id "
                        "WHERE a.delivery_id=? AND a.attempt_id=?",
                        (fixture.ident, attempt_id),
                    ).fetchone()
                self.assertIsNotNone(row)
                stored_ack = row[column]
                self.assertIsNotNone(stored_ack)
                self.assertEqual(JOURNAL.digest(stored_ack.encode()), request_sha256)
                self.assertEqual(json.loads(stored_ack), target["request"])
                receipt_text = (
                    row["input_recorded_receipt"]
                    if action == "observed"
                    else row["started_receipt"]
                )
                self.assertIsNotNone(receipt_text)
                receipt = json.loads(receipt_text)
                self.assertEqual(
                    receipt["outcome"]["turnId"],
                    target["request"]["nativeCorrelation"]["turnId"],
                )
                self.assertEqual(
                    row["ack_state"], "submitted" if action == "observed" else None
                )
                return {
                    "action": action,
                    "subject": target["subject"],
                    "requestSha256": request_sha256,
                    "committed": True,
                }

            async def hold_after_commit(action, deadline):
                self.assertLess(time.monotonic(), deadline)
                snapshot = setup["journal"].snapshot()
                self.assertIn(action, snapshot["held"])
                raise Crashed()

            async def send_through_fault(**request):
                if setup["hook"] is None or request["url"].endswith(
                    "/v1/dispatch/claim"
                ):
                    return await fixture.send(**request)
                body = JOURNAL.decode(request["body"])
                action = body.get("status")
                state = setup["journal"].snapshot()
                replay = action in state["held"] and action not in state["returned"]
                return await setup["hook"].send(
                    action=action,
                    replay=replay,
                    subject="recovery-a1",
                    operation_started_at=setup["startedAt"],
                    **request,
                )

            async def wrapped_ack(delivery_id, attempt_id):
                setup["startedAt"] = time.monotonic()
                attempt = fixture.store.current_attempt(delivery_id)
                if setup["hook"] is None:
                    submitted = fixture.gateway._native_acknowledgment(attempt)
                    input_receipt = {
                        **{
                            key: attempt["native_request"][key]
                            for key in native_identity
                        },
                        "outcome": {
                            "status": "inputRecorded",
                            "turnId": attempt["native_request"]["clientUserMessageId"],
                            "itemId": fixed_item,
                            "replayed": True,
                        },
                    }
                    observed_attempt = {
                        **attempt,
                        "input_recorded_receipt": input_receipt,
                    }
                    observed = fixture.gateway._native_acknowledgment(
                        observed_attempt, observed=True
                    )
                    # Store serializes immutable ACK DTOs with sorted keys and
                    # returns that parsed object to CloudClient for wire encoding.
                    submitted = JOURNAL.decode(encoded(submitted))
                    observed = JOURNAL.decode(encoded(observed))
                    base = manifest()
                    base["origin"] = fixture.client.origin
                    base["subjects"] = [
                        "recovery-a1",
                        "recovery-b1",
                        "recovery-c1",
                        "recovery-c2",
                        "recovery-c3",
                        "recovery-b2",
                        "recovery-a2",
                    ]
                    base["claims"] = [
                        {
                            "subject": "recovery-a1",
                            "request": {
                                "deliveryId": attempt["envelope"]["deliveryId"],
                                "attemptId": attempt["attempt_id"],
                            },
                        }
                    ]
                    for action, acknowledgment in (
                        ("submitted", submitted),
                        ("observed", observed),
                    ):
                        base["targets"][action] = {
                            "subject": "recovery-a1",
                            "nodeId": fixture.client.node_id,
                            "request": acknowledgment,
                            "wireSha256": JOURNAL.digest(_json(acknowledgment)),
                        }
                    base["targets"]["settle"]["subject"] = "recovery-a1"
                    setup["targets"] = base["targets"]
                    journal_dir = (
                        Path(fixture.tmp.name) / "transport-fault-journal"
                    ).resolve()
                    journal_dir.mkdir(mode=0o700)
                    journal_dir.chmod(0o700)
                    setup["journal"] = Journal(
                        journal_dir, base, clock=lambda: fixture.now, create=True
                    )
                    setup["journal"].reserve("publication", "recovery-a1")
                    setup["hook"] = TransportFault(
                        setup["journal"],
                        fixture.send,
                        durable_readback,
                        hold_after_commit,
                        monotonic=time.monotonic,
                    )
                    fixture.client._send = send_through_fault
                return await original_ack(delivery_id, attempt_id)

            fixture.gateway._ack_native = wrapped_ack
            with self.assertRaises(Crashed):
                await fixture.gateway.dispatch(fixture.ident)
            pending = fixture.store.current_attempt(fixture.ident)
            self.assertEqual(pending["state"], "submitted")
            self.assertIsNotNone(pending["native_ack"])
            self.assertIsNone(pending["ack_state"])
            first_wire = fixture.requests[-1]["body"]
            first_proof = fixture.requests[-1]["headers"]["x-event-node-proof"]
            first_credentials = fixture.requests[-1]["headers"]["authorization"]

            # Reopen the actual SQLite Store as a process-boundary surrogate.
            # This does not exercise daemon PID ownership or an OS restart.
            store_path = fixture.store.path
            fixture.store.close()
            from event_gateway.store import Store

            fixture.store = Store(store_path, clock=lambda: fixture.now)
            fixture.gateway.store = fixture.store
            replayed = await fixture.gateway.reconcile(fixture.ident)
            self.assertEqual(replayed["status"], "submitted")
            self.assertEqual(fixture.requests[-1]["body"], first_wire)
            self.assertNotEqual(
                fixture.requests[-1]["headers"]["x-event-node-proof"], first_proof
            )
            self.assertNotEqual(
                fixture.requests[-1]["headers"]["authorization"], first_credentials
            )
            self.assertIn("submitted", setup["journal"].snapshot()["returned"])

            attempt = fixture.store.current_attempt(fixture.ident)
            fixture.bridge.retained[attempt["attempt_id"]] = {
                "status": "inputRecorded",
                "turnId": attempt["native_request"]["clientUserMessageId"],
                "itemId": fixed_item,
                "replayed": True,
            }
            with self.assertRaises(Crashed):
                await fixture.gateway.reconcile(fixture.ident)
            pending_observed = fixture.store.current_attempt(fixture.ident)
            self.assertEqual(pending_observed["ack_state"], "submitted")
            self.assertIsNotNone(pending_observed["native_observed_ack"])
            observed_wire = fixture.requests[-1]["body"]
            observed_proof = fixture.requests[-1]["headers"]["x-event-node-proof"]
            observed_credentials = fixture.requests[-1]["headers"]["authorization"]

            store_path = fixture.store.path
            fixture.store.close()
            fixture.store = Store(store_path, clock=lambda: fixture.now)
            fixture.gateway.store = fixture.store
            completed = await fixture.gateway.reconcile(fixture.ident)
            self.assertEqual(completed["status"], "observed")
            self.assertEqual(fixture.requests[-1]["body"], observed_wire)
            self.assertNotEqual(
                fixture.requests[-1]["headers"]["x-event-node-proof"], observed_proof
            )
            self.assertNotEqual(
                fixture.requests[-1]["headers"]["authorization"], observed_credentials
            )
            self.assertEqual(
                fixture.store.current_attempt(fixture.ident)["ack_state"], "observed"
            )
            self.assertEqual(
                set(setup["journal"].snapshot()["returned"]), {"submitted", "observed"}
            )
            self.assertNotIn("authorization", setup["journal"].path.read_text())
            self.assertNotIn("cf-access-token", setup["journal"].path.read_text())
        finally:
            fixture.doCleanups()


if __name__ == "__main__":
    unittest.main()
