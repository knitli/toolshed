"""Provider-free regression coverage for the disposable Busy reattachment gate."""
import asyncio
import copy
from contextlib import ExitStack, asynccontextmanager
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
import threading
import tempfile
from uuid import uuid4
from event_gateway import cli as gateway_cli, launcher
from event_gateway.store import Store, StoreError
from unittest.mock import AsyncMock, Mock, patch


SCRIPT = Path(__file__).resolve().parents[1] / "docs/native-bridge/three-session-workerd.py"
SPEC = importlib.util.spec_from_file_location("busy_reattach_fixture", SCRIPT)
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
F.launcher = launcher


def history():
    return {"localDelivery": {"state": "observed", "ack_state": "observed"},
            "localAttempts": [{"state": "observed", "native_observed_ack": "ack", "reserved_bytes": 0}],
            "workerdAttempts": [{"state": "observed"}], "workerdClaims": [{}],
            "receiptStatuses": ["inputRecorded"], "nativeStarts": [{"attemptId": "c1"}],
            "cloudHistory": {"native_correlations": [{"attemptId": "c1", "state": "observed"}],
                             "slot_intents": [{"attemptId": "c1", "state": "released"}]},
            "slots": [{"used": 0}], "budget": {"used": 0}}


def attachment_history(changed_history):
    first, last = history(), history()
    if changed_history == "ack":
        last["localAttempts"][0]["native_observed_ack"] = "different-ack"
    elif changed_history == "slots":
        last["slots"][0]["used"] = 1
    elif changed_history in ("native_correlations", "slot_intents"):
        last["cloudHistory"][changed_history][0]["state"] = "changed"
    elif changed_history:
        last["budget"]["used"] = 1
    return first, last


def busy_response(binding, challenge_id, nonce, deadline, *, eligible=True, turn_state="busy"):
    return {"challengeId": challenge_id, "observedAt": "2026-10-15T08:00:00.000Z",
            "validUntilMonotonic": deadline,
            "witness": {**binding, "version": 2, "nonce": nonce, "sequence": nonce,
                        "cause": "heartbeat", "leaseMs": 750, "eligible": eligible,
                        "nativeCoreTurnState": turn_state}}


class AttachmentReadbackTests(unittest.TestCase):
    def test_readback_uses_committed_snapshot_while_writer_lock_is_held(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            with Store(state) as owner:
                mapping = {"runtimeId": "fixture-runtime", "leaseExpiresAt": 1, "value": "committed"}
                owner.db.execute("INSERT INTO attachments VALUES (?,?)", ("fixture-runtime", json.dumps(mapping)))
                owner.db.commit()
                with self.assertRaisesRegex(StoreError, "writer_locked"):
                    Store(state)
                owner.db.execute("UPDATE attachments SET data=? WHERE runtime=?", (
                    json.dumps({**mapping, "value": "uncommitted"}), "fixture-runtime"))
                self.assertEqual(F.db_attachment(state, "fixture-runtime"), mapping)
                self.assertIsNone(F.db_attachment(state, "absent-runtime"))
                owner.db.rollback()
                self.assertEqual(owner.get_attachment("fixture-runtime"), mapping)
                with self.assertRaisesRegex(StoreError, "writer_locked"):
                    Store(state)

    def test_revoked_and_empty_mapping_keep_store_null_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory).resolve()
            with Store(state) as owner:
                for value in ({"leaseExpiresAt": 0}, {}, None):
                    with self.subTest(value=value):
                        owner.db.execute("INSERT OR REPLACE INTO attachments VALUES (?,?)", (
                            "fixture-runtime", json.dumps(value)))
                        owner.db.commit()
                        self.assertIsNone(owner.get_attachment("fixture-runtime"))
                        self.assertIsNone(F.db_attachment(state, "fixture-runtime"))


class BusyReattachTests(unittest.IsolatedAsyncioTestCase):
    async def test_settlement_reads_run_off_event_loop(self):
        loop_thread = threading.get_ident()
        ctx = SimpleNamespace(sessions={"C": {"provider": SimpleNamespace(
            hold_deadline=asyncio.get_running_loop().time() + 1)}}, c_busy_nonces=set())

        def read(context):
            self.assertNotEqual(threading.get_ident(), loop_thread,
                                "settlement I/O blocked the daemon event loop")
            return history()

        with patch.object(F, "require_model_held"), \
                patch.object(F, "c1_busy_history", side_effect=read), \
                patch.object(F, "wait_busy_session_binding", side_effect=RuntimeError("settled")):
            with self.assertRaisesRegex(RuntimeError, "settled"):
                await F.attach_busy_session(ctx)

    async def test_unsettled_c1_has_its_own_bounded_failure(self):
        ctx = SimpleNamespace(sessions={"C": {"provider": SimpleNamespace(
            hold_deadline=asyncio.get_running_loop().time() + 0.02)}})
        unsettled = history()
        unsettled["localDelivery"]["state"] = "queued"
        with patch.object(F, "require_model_held"), \
                patch.object(F, "c1_busy_history", return_value=unsettled):
            with self.assertRaises((AssertionError, TimeoutError)) as raised:
                await asyncio.wait_for(F.attach_busy_session(ctx), timeout=0.2)
        self.assertIsInstance(raised.exception, AssertionError, "only the external test timeout stopped settlement")
        self.assertIn("C1 settlement did not complete before busy attach deadline", str(raised.exception))

    async def test_timeout_and_cancellation_keep_structured_diagnostics_when_archive_fails(self):
        for failure in (TimeoutError("held stage expired"), asyncio.CancelledError("shutdown")):
            with self.subTest(failure=type(failure).__name__):
                hold = SimpleNamespace(hold_lock=threading.Lock(), hold_started=threading.Event(),
                                       release_hold=threading.Event(), hold_deadline=asyncio.get_running_loop().time() + 1,
                                       requests=[], errors=[])
                ctx = SimpleNamespace(runtime_ids={"C": "runtime-c"}, node_id="node", transport_key=Mock(),
                                      sessions={"C": {"provider": hold}}, dispatch_labels={}, listen_port=1,
                                      fixture=Mock(return_value={"envelope": {"deliveryId": "c1"}, "signedDelivery": "c1"}))
                ctx.transport_key.private_bytes.return_value = b"test-key"
                with patch.object(F, "serialization", Mock()), patch.object(F, "require_model_held"), \
                        patch.object(F, "listener_delivery", return_value=(202, None)), \
                        patch.object(F, "wait_until", new=AsyncMock()), \
                        patch.object(F, "run_held_busy_stage", side_effect=failure), \
                        patch.object(F, "record_evidence", side_effect=OSError("archive unavailable")):
                    with self.assertRaises(type(failure)) as raised:
                        await F.run_busy_stage(ctx)
                self.assertIs(raised.exception, failure)
                notes = getattr(failure, "__notes__", [])
                self.assertTrue(notes, "deadline/cancellation lost structured Busy diagnostics")
                diagnostic = json.loads(notes[-1].split("bounded diagnostic=", 1)[1])
                self.assertEqual(diagnostic["failureType"], type(failure).__name__)
                self.assertFalse(diagnostic["cSecondCreated"])
                self.assertFalse(hold.release_hold.is_set())

    async def test_real_dispatch_observer_archive_passes_hosted_verifier(self):
        from test_hosted_native_qualification import HOSTED, attach_archive, busy_attach_evidence, c2_proof
        result, attach, identities = busy_attach_evidence()
        binding = attach['mapping']['nativeBinding']
        session_id = attach['mapping']['sessionId']
        delivery_id = 'dly_' + 'a' * 64
        records = [json.loads(line) for line in attach_archive(attach).splitlines()]
        ctx = SimpleNamespace(dispatch_labels={delivery_id: 'C-busy-second'}, dispatch_calls=[],
                              dispatch_errors=[], dispatch_results=[], c_challenges=[], c_busy_nonces={1, 2, 3, 4, 5},
                              c_busy_binding=binding, session_labels={session_id: 'C'}, challenge_calls={'C': 0},
                              receipt_errors={}, receipt_calls={})
        nonce = 6

        def raw_exchange(state, session, request, **kwargs):
            return busy_response(binding, request['challengeId'], nonce, F.time.monotonic() + 0.5)

        ctx.original_session_request = raw_exchange

        async def dispatch(*args):
            # The real launcher validates the raw echo and returns its normalized three-field value.
            response = launcher.session_challenge(Path('/fixture'), session_id, str(uuid4()), binding)
            self.assertNotIn('challengeId', response)
            return {'status': 'queued', 'reason': 'client_unavailable_or_busy'}

        ctx.original_dispatch = dispatch

        def record(context, kind, value):
            records.append({'kind': kind, 'value': copy.deepcopy(value)})

        with patch.object(F, 'record_evidence', side_effect=record), \
                patch.object(launcher, '_session_request', side_effect=lambda *a, **kw: F.record_session_request(ctx, *a, **kw)):
            with patch.object(F.time, 'monotonic', return_value=6.1):
                await F.observe_dispatch(None, ctx, delivery_id)
            records.append({'kind': 'c2BusyRestart', 'value': {'deliveryId': delivery_id, 'binding': binding,
                            'checkedAt': 6.5, 'evidenceError': None}})
            ctx.busy_result_count = len(ctx.dispatch_results)
            nonce = 7
            with patch.object(F.time, 'monotonic', return_value=7.1):
                await F.observe_dispatch(None, ctx, delivery_id)
        proof = c2_proof(result, identities)
        proof['privateEvidence']['coreBusyNonces'] = len(ctx.c_busy_nonces)
        try:
            HOSTED.verify_busy_attach(proof, '\n'.join(json.dumps(row) for row in records).encode())
        except ValueError as error:
            self.fail('Actual C2 observer archive must qualify: ' + str(error))
        self.assertEqual([row['value']['phase'] for row in records if row['kind'] == 'c2CoreBusy'],
                         ['initial', 'post-restart'])
        self.assertEqual(ctx.challenge_calls['C'], 2)
        for row in records:
            if row['kind'] == 'c2CoreBusy':
                row['value']['observations'][0]['response']['witness']['nonce'] = 4
                break
        with self.assertRaisesRegex(ValueError, 'Busy attach evidence mismatch'):
            HOSTED.verify_busy_attach(proof, '\n'.join(json.dumps(row) for row in records).encode())

    async def test_read_accepts_real_launcher_normalized_challenge_and_rejects_bad_echo(self):
        binding = {key: str(uuid4()) for key in ('clientId', 'connectionId', 'threadId', 'serverInstanceId')}
        binding.update(backendPid=42, generation=1, serverGeneration=1)
        session = {'state': Path('/fixture'), 'sessionId': 'C', 'provider': object()}
        seen = set()

        def raw_exchange(state, session_id, request):
            return busy_response(binding, request['challengeId'], 7, F.time.monotonic() + 0.5)

        with patch.object(launcher, '_session_request', side_effect=raw_exchange), patch.object(F, 'require_model_held'):
            row = await F.read_busy_binding(session, binding, seen)
        self.assertEqual(row['response']['challengeId'], row['request']['challengeId'])
        self.assertEqual(seen, {7})
        self.assertTrue(F.core_busy_observation(row, binding, F.time.monotonic(), set()))
        wrong_echo = busy_response(binding, str(uuid4()), 8, F.time.monotonic() + 0.5)
        with patch.object(launcher, '_session_request', return_value=wrong_echo), patch.object(F, 'require_model_held'):
            with self.assertRaisesRegex(launcher.LaunchError, 'invalid_client_challenge'):
                await F.read_busy_binding(session, binding, seen)
        self.assertEqual(seen, {7})

    async def test_read_requires_valid_busy_evidence_and_unreleased_hold(self):
        session = {"state": Path("/fixture"), "sessionId": "C", "provider": object()}
        response = {"witness": {"nonce": 7}}
        with patch.object(F.launcher, "session_challenge", return_value=response), \
                patch.object(F, "core_busy_observation", return_value=False), \
                patch.object(F, "require_model_held"):
            with self.assertRaisesRegex(AssertionError, "fresh eligible Core-busy"):
                await F.read_busy_binding(session, {}, set())
        seen = set()
        with patch.object(F.launcher, "session_challenge", return_value=response), \
                patch.object(F, "core_busy_observation", return_value=True) as check, \
                patch.object(F, "require_model_held", side_effect=AssertionError("hold released")):
            with self.assertRaisesRegex(AssertionError, "hold released"):
                await F.read_busy_binding(session, {}, seen)
            self.assertEqual(seen, {7})
            self.assertEqual(check.call_args.args[0]["response"]["witness"], response["witness"])

    async def test_binding_needs_three_consecutive_observations_after_churn(self):
        session = {"state": Path("/fixture"), "sessionId": "C",
                   "provider": SimpleNamespace(hold_deadline=asyncio.get_running_loop().time() + 10)}
        bindings = [{"generation": n} for n in [1, 1, 2, 2, 2]]
        with patch.object(F.launcher, "session_binding", side_effect=bindings) as select, \
                patch.object(F, "require_model_held"), \
                patch.object(F, "read_busy_binding", new=AsyncMock(return_value={"fresh": True})) as read, \
                patch.object(F.asyncio, "sleep", new=AsyncMock()):
            binding, evidence = await F.wait_busy_session_binding(session, set())
        self.assertEqual(binding, {"generation": 2})
        self.assertEqual(evidence, {"fresh": True})
        self.assertEqual(select.call_count, 5)
        self.assertEqual(read.await_count, 5)

    def test_c1_requires_observed_ack_released_reservation_and_sole_start(self):
        F.assert_c1_busy_settled(history())
        for field, value in [("ack_state", "pending"), ("native_observed_ack", None),
                             ("reserved_bytes", 1), ("nativeStarts", [{}, {}])]:
            with self.subTest(field=field):
                bad = history()
                if field == "ack_state":
                    bad["localDelivery"][field] = value
                elif field == "nativeStarts":
                    bad[field] = value
                else:
                    bad["localAttempts"][0][field] = value
                with self.assertRaises(AssertionError):
                    F.assert_c1_busy_settled(bad)

    def test_snapshot_retains_cloud_charges_and_copies_native_starts(self):
        h = history()
        remote = {"cloud": h["cloudHistory"], "slots": h["slots"], "budget": h["budget"]}
        ctx = SimpleNamespace(state=Path("/fixture"), c_first_envelope={"deliveryId": "d", "attemptId": "a"},
                              fixture=Mock(return_value=remote), receipt_calls={"C": h["receiptStatuses"]},
                              start_calls={"C": h["nativeStarts"]})
        with patch.object(F, "db_delivery_history", return_value={"delivery": h["localDelivery"], "attempts": h["localAttempts"]}), \
                patch.object(F, "attempts_for", return_value=h["workerdAttempts"]), \
                patch.object(F, "native_claims_for", return_value=h["workerdClaims"]):
            actual = F.c1_busy_history(ctx)
        self.assertEqual(actual, h)
        ctx.start_calls["C"][0]["attemptId"] = "changed"
        self.assertEqual(actual["nativeStarts"][0]["attemptId"], "c1")

    async def attach(self, *, changed_history=False, wrong_mapping=False, witness_nonces=None,
                     native_generations=(2, 1), cli_witness="busy"):
        old = dict(clientId=str(uuid4()), connectionId=str(uuid4()), backendPid=1,
                   threadId=str(uuid4()), serverInstanceId=str(uuid4()),
                   generation=1, serverGeneration=1)
        binding = dict(old, generation=native_generations[0], serverGeneration=native_generations[1])
        session_id = str(uuid4())
        before = dict(status="present", storedQualified=True, nativeBinding=old, runtimeGeneration=3, attachmentGeneration=4)
        after = dict(before, nativeBinding=binding, runtimeGeneration=4, attachmentGeneration=5)
        mapping = dict(nativeBinding=binding, nativeThreadId=binding["threadId"], sessionId=session_id,
                       runtimeId="runtime-c", principal="fixture-principal", agent="fixture-agent",
                       nodeGeneration=2, runtimeGeneration=4, attachmentGeneration=5, leaseExpiresAt=2_000_000_000)
        Store._validate_attachment(None, mapping, None)
        if wrong_mapping:
            mapping["attachmentGeneration"] = 4
        provider = SimpleNamespace(hold_deadline=asyncio.get_running_loop().time() + 10)
        ctx = SimpleNamespace(state=Path("/fixture"),
                              sessions={"C": {"state": Path("/native"), "sessionId": session_id, "provider": provider, "binding": old}},
                              runtime_ids={"C": "runtime-c"}, c_busy_nonces=set(),
                              admission_cloud=SimpleNamespace(runtime_status=AsyncMock(side_effect=[before, after])))
        ctx.session_labels = {session_id: "C", "B": "B"}
        ctx.challenge_calls, ctx.receipt_errors, ctx.receipt_calls = {"C": 0}, {"C": []}, {"C": []}
        ctx.c_challenges = []

        def cli_challenge(state_dir, session_id, message, **kwargs):
            nonce = 7 if cli_witness == "replayed" else 11
            deadline = F.time.monotonic() + (-1 if cli_witness == "expired" else 0.5)
            turn_state = cli_witness if cli_witness in ("idle", "unknown") else "busy"
            return busy_response(binding, message["challengeId"], nonce, deadline, turn_state=turn_state)

        ctx.original_session_request = cli_challenge

        def cli_call(argv):
            if cli_witness == "production":
                challenge_id = str(uuid4())

                async def commit(intent, challenge, evidence, **kwargs):
                    self.assertEqual(ctx.busy_attach_capture["threadId"], threading.get_ident())
                    self.assertEqual(len(ctx.busy_attach_capture["rows"]), 1)
                    self.assertEqual(ctx.busy_attach_capture["rows"][0]["request"]["challengeId"], challenge_id)
                    self.assertEqual(evidence["witness"]["nonce"], 11)
                    return {"remoteStatus": "attached", "localStatus": "current"}

                cloud = SimpleNamespace(native_challenge=AsyncMock(return_value={"challengeId": challenge_id}),
                                        attach=commit)
                with patch.object(launcher, "_session_request", side_effect=lambda *a, **kw: F.record_session_request(ctx, *a, **kw)):
                    result = gateway_cli._commit_native_call(
                        SimpleNamespace(session_id=session_id), ctx.state, "attach", {}, None, cloud, binding, {},
                    )
                return 0, result
            if cli_witness != "missing":
                expected = dict(binding, generation=binding["generation"] + 1) if cli_witness == "wrong-binding" else binding
                message = {
                    "command": "challenge", "challengeId": str(uuid4()), "expectedBinding": expected,
                }
                request_session = "B" if cli_witness == "wrong-session" else session_id
                if cli_witness == "wrong-thread":
                    observer = threading.Thread(target=F.record_session_request, args=(ctx, ctx.state, request_session, message))
                    observer.start()
                    observer.join()
                else:
                    F.record_session_request(ctx, ctx.state, request_session, message)
            return 0, {"remoteStatus": "attached", "localStatus": "current"}
        first, last = attachment_history(changed_history)
        with ExitStack() as stack:
            ctx.state = Path(stack.enter_context(tempfile.TemporaryDirectory())).resolve()
            owner = stack.enter_context(Store(ctx.state))
            owner.put_attachment(mapping)
            # Match the live daemon's exclusive writer ownership throughout readback.
            with self.assertRaisesRegex(StoreError, "writer_locked"):
                Store(ctx.state)
            stack.enter_context(patch.object(F, "require_model_held"))
            stack.enter_context(patch.object(F, "c1_busy_history", side_effect=[first, copy.deepcopy(first), last]))
            if witness_nonces is None:

                async def stabilized(session, seen):
                    seen.update({7, 8, 9})
                    return binding, {"response": {"witness": {"nonce": 9}}}

                stack.enter_context(patch.object(F, "wait_busy_session_binding", side_effect=stabilized))
                fresh = stack.enter_context(patch.object(F, "read_busy_binding", new=AsyncMock(return_value={"response": {"witness": {"nonce": 10}}})))
            else:
                nonces = iter(witness_nonces)

                def challenge(state, session_id, request):
                    try:
                        nonce = next(nonces)
                    except StopIteration:
                        self.fail("Busy attachment exhausted the supplied native witnesses")
                    return busy_response(binding, request["challengeId"], nonce, F.time.monotonic() + 0.5)

                stack.enter_context(patch.object(F.launcher, "session_binding", return_value=binding))
                stack.enter_context(patch.object(F.launcher, "_session_request", side_effect=challenge))
                stack.enter_context(patch.object(F.asyncio, "sleep", new=AsyncMock()))
                fresh = None
            cli = stack.enter_context(patch.object(F, "run_cli_capture", side_effect=cli_call))
            stack.enter_context(patch.object(F, "record_evidence"))
            await F.attach_busy_session(ctx)
        return ctx, cli, fresh, binding

    async def test_post_attach_rejects_an_earlier_stabilization_nonce(self):
        with self.assertRaisesRegex(F.BusyObservationRefused, "fresh eligible Core-busy"):
            await self.attach(witness_nonces=[7, 8, 9, 7])

    async def test_c2_rejects_nonces_spent_during_stabilization_and_post_attach(self):
        for replayed_nonce in (7, 10, 11):
            with self.subTest(replayed_nonce=replayed_nonce):
                ctx, _, _, binding = await self.attach(witness_nonces=[7, 8, 9, 10])
                ctx.dispatch_labels = {"c2": "C-busy-second"}
                ctx.dispatch_calls, ctx.dispatch_results, ctx.dispatch_errors, ctx.c_challenges = [], [], [], []

                async def dispatch(*args):
                    challenge_id = str(uuid4())
                    ctx.c_challenges.append({
                        "request": {"command": "challenge", "challengeId": challenge_id, "expectedBinding": binding},
                        "receivedAt": F.time.monotonic(),
                        "response": busy_response(binding, challenge_id, replayed_nonce, F.time.monotonic() + 0.5),
                    })
                    return {"status": "queued", "reason": "client_unavailable_or_busy"}

                ctx.original_dispatch = dispatch
                with patch.object(F, "record_evidence"):
                    await F.observe_dispatch(None, ctx, "c2")
                self.assertEqual(ctx.dispatch_results, [], "C2 accepted a nonce already consumed by Busy qualification")
                self.assertEqual(ctx.c_busy_nonces, {7, 8, 9, 10, 11})
                self.assertIn("fresh authoritative", ctx.c_busy_evidence_error)

    async def test_actual_attach_challenge_requires_fresh_busy_exact_binding(self):
        for violation in ("idle", "unknown", "expired", "replayed", "wrong-binding",
                          "wrong-session", "wrong-thread", "missing"):
            with self.subTest(violation=violation), self.assertRaises(AssertionError):
                await self.attach(cli_witness=violation)

    async def test_production_cli_commit_challenge_is_captured_before_attach_send(self):
        ctx, _, _, _ = await self.attach(cli_witness="production")
        self.assertEqual(ctx.challenge_calls["C"], 1)
        self.assertIn(11, ctx.c_busy_nonces)
        self.assertIsNone(ctx.busy_attach_capture)

    async def test_native_generation_rollback_cannot_qualify_busy_reattach(self):
        for counters in ((0, 2), (2, 0), (0, 0), (1, 1)):
            with self.subTest(counters=counters), self.assertRaisesRegex(AssertionError, "current changed binding"):
                await self.attach(native_generations=counters)

    async def test_attach_uses_production_cli_cas_and_fresh_post_commit_busy_proof(self):
        ctx, cli, fresh, binding = await self.attach()
        args = cli.call_args.args[0]
        self.assertIn("attach", args)
        self.assertEqual(args[args.index("--expected-runtime-generation") + 1], "3")
        self.assertEqual(args[args.index("--expected-attachment-generation") + 1], "4")
        fresh.assert_awaited_once_with(ctx.sessions["C"], binding, {7, 8, 9, 11})
        self.assertIs(fresh.call_args.args[2], ctx.c_busy_nonces)
        self.assertEqual(ctx.c_busy_binding, binding)
        self.assertTrue(ctx.c_busy_attach_proof["c1HistoryAndChargesUnchanged"])

    async def test_attach_rejects_cloud_charge_mutation(self):
        for mutation in ("charge", "ack", "slots", "native_correlations", "slot_intents"):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(AssertionError, "C1 history changed"):
                await self.attach(changed_history=mutation)

    async def test_attach_rejects_store_cloud_generation_mismatch(self):
        with self.assertRaisesRegex(AssertionError, "cloud and Store generations"):
            await self.attach(wrong_mapping=True)

    async def test_read_rejects_idle_expired_ineligible_and_replayed_native_witness(self):
        binding = dict(clientId=str(uuid4()), connectionId=str(uuid4()), backendPid=42,
                       threadId=str(uuid4()), serverInstanceId=str(uuid4()), generation=2, serverGeneration=1)
        session = {"state": Path("/fixture"), "sessionId": "C", "provider": object()}
        for mutation in ("valid", "idle", "expired", "ineligible", "replayed"):
            def challenge(state, session_id, request):
                return busy_response(binding, request["challengeId"], 7, 9.0 if mutation == "expired" else 10.5,
                                     eligible=mutation != "ineligible",
                                     turn_state="idle" if mutation == "idle" else "busy")
            with self.subTest(mutation=mutation), \
                    patch.object(F.launcher, "_session_request", side_effect=challenge), \
                    patch.object(F.time, "monotonic", return_value=10.0), \
                    patch.object(F, "require_model_held"):
                seen = {7} if mutation == "replayed" else set()
                if mutation == "valid":
                    await F.read_busy_binding(session, binding, seen)
                    self.assertEqual(seen, {7})
                elif mutation in ("expired", "ineligible"):
                    with self.assertRaisesRegex(launcher.LaunchError, "invalid_client_challenge"):
                        await F.read_busy_binding(session, binding, seen)
                else:
                    with self.assertRaisesRegex(AssertionError, "fresh eligible Core-busy"):
                        await F.read_busy_binding(session, binding, seen)

    async def test_dispatch_uses_busy_binding_and_requires_fresh_nonce_each_time(self):
        old = {"generation": 1}
        current = {"generation": 2}
        ctx = SimpleNamespace(dispatch_labels={"c2": "C-busy-second"}, dispatch_calls=[],
                              dispatch_errors=[], dispatch_results=[], c_challenges=[], c_busy_nonces=set(),
                              c_busy_binding=current, sessions={"C": {"binding": old}})
        nonces = iter([7, 7, 8])

        async def dispatch(*args):
            ctx.c_challenges.append({"response": {"witness": {"nonce": next(nonces)}}})
            return {"status": "queued", "reason": "client_unavailable_or_busy"}
        ctx.original_dispatch = dispatch

        def valid(row, binding, now, seen):
            return binding == current and row["response"]["witness"]["nonce"] not in seen
        with patch.object(F, "core_busy_observation", side_effect=valid), patch.object(F, "record_evidence"):
            await F.observe_dispatch(None, ctx, "c2")
            self.assertEqual(len(ctx.dispatch_results), 1)
            await F.observe_dispatch(None, ctx, "c2")
            self.assertEqual(len(ctx.dispatch_results), 1)
            self.assertIn("fresh authoritative", ctx.c_busy_evidence_error)
            await F.observe_dispatch(None, ctx, "c2")
            self.assertEqual(len(ctx.dispatch_results), 2)
            self.assertEqual(ctx.c_busy_nonces, {7, 8})

    async def test_stage_attaches_under_hold_deadline_before_creating_c2_with_new_generations(self):
        class StopAfterC2(Exception):
            pass
        events = []
        stale_c2 = False
        hold = SimpleNamespace(hold_lock=threading.Lock(), hold_started=threading.Event(),
                               release_hold=threading.Event(), hold_deadline=asyncio.get_running_loop().time() + 60)
        mapping = dict(runtimeId="runtime-c", nodeGeneration=2, runtimeGeneration=4, attachmentGeneration=5)
        ctx = SimpleNamespace(runtime_ids={"C": "runtime-c"}, node_id="node", transport_key=Mock(),
                              sessions={"C": {"provider": hold}}, dispatch_labels={}, start_calls={"C": []}, listen_port=1)
        ctx.transport_key.private_bytes.return_value = b"test-key"

        def fixture(path, body=None):
            if path == "/fixture/read":
                return {}
            label = "c1" if body["subjectId"].endswith("first") else "c2"
            if label == "c2":
                self.assertEqual(events, ["c1", "hold-deadline", "attached"])
                self.assertEqual(ctx.c_busy_mapping, mapping)
            events.append(label)
            envelope = {**mapping, "deliveryId": label, "attemptId": label}
            if label == "c2" and stale_c2:
                envelope["attachmentGeneration"] -= 1
            return {"envelope": envelope, "signedDelivery": label}
        ctx.fixture = fixture

        async def attach(context):
            self.assertEqual(events, ["c1", "hold-deadline"])
            context.c_busy_mapping = mapping
            context.start_calls["C"].append({"attemptId": "c1"})
            events.append("attached")

        def listener(port, signed):
            if signed == "c2":
                self.assertFalse(stale_c2, "stale C2 reached the production listener")
                raise StopAfterC2()
            hold.hold_started.set()
            return 202, None

        @asynccontextmanager
        async def deadline(value):
            self.assertEqual(value, hold.hold_deadline)
            events.append("hold-deadline")
            yield

        async def wait(predicate, *args, **kwargs):
            self.assertTrue(predicate())
        baseline = dict(state="created", reservation_state="none", transport_status="sending",
                        permit_id=None, submission_id=None, turn_id=None)
        with ExitStack() as stack:
            stack.enter_context(patch.object(F, "serialization", Mock()))
            stack.enter_context(patch.object(F, "require_model_held"))
            stack.enter_context(patch.object(F, "attach_busy_session", side_effect=attach))
            stack.enter_context(patch.object(F, "listener_delivery", side_effect=listener))
            stack.enter_context(patch.object(F, "wait_until", side_effect=wait))
            stack.enter_context(patch.object(F.asyncio, "timeout_at", side_effect=deadline))
            stack.enter_context(patch.object(F, "attempts_for", return_value=[]))
            stack.enter_context(patch.object(F, "transport_attempt_snapshot", return_value=baseline))
            with self.assertRaises(StopAfterC2):
                await F.run_busy_stage(ctx)
            self.assertEqual(events, ["c1", "hold-deadline", "attached", "c2"])
            stale_c2 = True
            events.clear()
            ctx.start_calls["C"].clear()
            with self.assertRaisesRegex(AssertionError, "C2 was not created from the committed busy attachment"):
                await F.run_busy_stage(ctx)
        self.assertEqual(events, ["c1", "hold-deadline", "attached", "c2"])

    async def test_hold_deadline_cancels_attach_before_c2_without_releasing_turn(self):
        hold = SimpleNamespace(hold_lock=threading.Lock(), hold_started=threading.Event(),
                               release_hold=threading.Event(), hold_deadline=asyncio.get_running_loop().time() + 0.02)
        ctx = SimpleNamespace(runtime_ids={"C": "runtime-c"}, node_id="node", transport_key=Mock(),
                              sessions={"C": {"provider": hold}}, dispatch_labels={}, listen_port=1)
        ctx.transport_key.private_bytes.return_value = b"test-key"
        setup_subjects = []
        attach_cancelled = asyncio.Event()

        def fixture(path, body=None):
            setup_subjects.append(body["subjectId"])
            return {"envelope": {"deliveryId": "c1", "attemptId": "c1"}, "signedDelivery": "c1"}
        ctx.fixture = fixture

        def listener(*args):
            hold.hold_started.set()
            return 202, None

        async def attach(context):
            try:
                await asyncio.sleep(0.1)
            except asyncio.CancelledError:
                attach_cancelled.set()
                raise
            self.fail("attach exceeded the original hold deadline without cancellation")

        async def wait(predicate, *args, **kwargs):
            self.assertTrue(predicate())
        with patch.object(F, "serialization", Mock()), \
                patch.object(F, "require_model_held"), \
                patch.object(F, "attach_busy_session", side_effect=attach), \
                patch.object(F, "listener_delivery", side_effect=listener), \
                patch.object(F, "wait_until", side_effect=wait):
            with self.assertRaises(TimeoutError) as raised:
                await asyncio.wait_for(F.run_busy_stage(ctx), timeout=0.5)
        self.assertIn('"failureType": "TimeoutError"', raised.exception.__notes__[-1])
        self.assertTrue(attach_cancelled.is_set())
        self.assertEqual(setup_subjects, ["three-session-c-busy-first"])
        self.assertTrue(hold.hold_started.is_set())
        self.assertFalse(hold.release_hold.is_set())

    async def test_refused_busy_witness_resets_stability_without_recycling_nonces(self):
        binding = dict(clientId=str(uuid4()), connectionId=str(uuid4()), backendPid=42,
                       threadId=str(uuid4()), serverInstanceId=str(uuid4()), generation=2, serverGeneration=1)
        session = {"state": Path("/fixture"), "sessionId": "C",
                   "provider": SimpleNamespace(hold_deadline=asyncio.get_running_loop().time() + 5)}
        samples = iter([(1, False), (2, False), (3, True), (1, False), (4, False), (5, False), (6, False)])
        observed_nonces = []

        def challenge(state, session_id, request):
            try:
                nonce, expired = next(samples)
            except StopIteration:
                self.fail("Busy selection exhausted all fresh samples without settling")
            observed_nonces.append(nonce)
            now = F.time.monotonic()
            return busy_response(binding, request["challengeId"], nonce, now - 1 if expired else now + 0.5)
        with patch.object(F.launcher, "session_binding", return_value=binding), \
                patch.object(F.launcher, "_session_request", side_effect=challenge), \
                patch.object(F, "require_model_held"), \
                patch.object(F.asyncio, "sleep", new=AsyncMock()):
            result, evidence = await F.wait_busy_session_binding(session, set())
        self.assertEqual(result, binding)
        self.assertEqual(evidence["response"]["witness"]["nonce"], 6)
        self.assertEqual(observed_nonces, [1, 2, 3, 1, 4, 5, 6])

    async def test_persistent_busy_refusals_expire_at_original_hold_deadline(self):
        binding = dict(clientId=str(uuid4()), connectionId=str(uuid4()), backendPid=42,
                       threadId=str(uuid4()), serverInstanceId=str(uuid4()), generation=2, serverGeneration=1)
        started = asyncio.get_running_loop().time()
        session = {"state": Path("/fixture"), "sessionId": "C",
                   "provider": SimpleNamespace(hold_deadline=started + 0.03)}

        def challenge(state, session_id, request):
            return busy_response(binding, request["challengeId"], 1, F.time.monotonic() - 1)
        with patch.object(F.launcher, "session_binding", return_value=binding), \
                patch.object(F.launcher, "_session_request", side_effect=challenge) as challenged, \
                patch.object(F, "require_model_held"):
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(F.wait_busy_session_binding(session, set()), timeout=0.5)
        self.assertGreaterEqual(challenged.call_count, 1)
        self.assertLess(asyncio.get_running_loop().time() - started, 0.25,
                        "witness refusals extended the original model hold deadline")
