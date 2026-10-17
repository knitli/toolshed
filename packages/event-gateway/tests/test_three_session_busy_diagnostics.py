"""Bounded private failure diagnostics; no native CLI or model execution."""
from contextlib import closing, contextmanager
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import asyncio
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4

from event_gateway import launcher

SCRIPT = Path(__file__).resolve().parents[1] / "docs/native-bridge/three-session-workerd.py"
SPEC = importlib.util.spec_from_file_location("busy_diagnostic_fixture", SCRIPT)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)
FIXTURE.launcher = launcher


@contextmanager
def native_home():
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        home = root / "codex-home"
        home.mkdir(mode=0o700)
        session = {"root": root, "rootIdentity": (root.stat().st_dev, root.stat().st_ino),
                   "homeIdentity": (home.stat().st_dev, home.stat().st_ino)}
        yield session, home


def database(home, rows=(), *, wal=False):
    connection = sqlite3.connect(home / "logs_2.sqlite")
    if wal:
        connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE logs (ts INTEGER, ts_nanos INTEGER, feedback_log_body TEXT, target TEXT)")
    connection.executemany("INSERT INTO logs VALUES (?,?,?,?)", rows)
    connection.commit()
    return connection


def row(body=None, *, target="codex_selection_witness", stamp=100):
    return (stamp, 0, body or 'native selection revocation trigger category="thread-event" generation=5 server_generation=3', target)


class NativeRevocationDiagnosticsTests(unittest.TestCase):
    def test_reuses_digest_bound_parser_and_rejects_source_tampering(self):
        parser = FIXTURE.load_revocation_parser()
        self.assertEqual(parser(100, row()[2])["category"], "thread-event")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "native-metadata-launcher-smoke.py").write_text("raise RuntimeError('executed tampered source')")
            with patch.object(FIXTURE, "HERE", directory), self.assertRaisesRegex(AssertionError, "digest mismatch"):
                FIXTURE.load_revocation_parser()

    def test_parser_source_fifo_and_symlink_refuse_without_read(self):
        for kind in ("fifo", "symlink", "oversized"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                source = directory / "native-metadata-launcher-smoke.py"
                if kind == "fifo":
                    os.mkfifo(source)
                elif kind == "symlink":
                    source.symlink_to(SCRIPT.parent / source.name)
                else:
                    with source.open("wb") as stream:
                        stream.truncate(262_145)
                with patch.object(FIXTURE, "HERE", directory), self.assertRaises((AssertionError, OSError)):
                    FIXTURE.load_revocation_parser()

    def test_only_parsed_categories_escape_and_wal_is_read(self):
        with native_home() as (session, home):
            connection = database(home, [row(), row("private owner text", target="unrelated"),
                row('native selection authority changed category="client-revoke" generation=4',
                    target="codex_native_selection")], wal=True)
            try:
                result = FIXTURE.collect_native_revocations(session, 99, 101)
            finally:
                connection.close()
            self.assertEqual(result["status"], "available")
            self.assertEqual([r["category"] for r in result["records"]], ["thread-event", "client-revoke"])
            self.assertNotIn("private owner text", json.dumps(result))
            self.assertTrue(result["diagnosticOnly"])
            self.assertFalse(result["exactRejectedWitnessAvailable"])

    def test_readonly_snapshot_reconstructs_shm_without_copying_live_shm(self):
        with native_home() as (session, home):
            source = database(home, [row()], wal=True)
            connect = sqlite3.connect
            observations = []

            def inspect_snapshot(database_uri, **kwargs):
                self.assertTrue(database_uri.endswith("?mode=ro"))
                self.assertTrue(kwargs["uri"])
                snapshot = Path(database_uri.removeprefix("file:").removesuffix("?mode=ro"))
                self.assertNotEqual(snapshot.parent, home)
                before = {path.name for path in snapshot.parent.iterdir()}
                self.assertEqual(before, {"logs_2.sqlite", "logs_2.sqlite-wal"})
                connection = connect(database_uri, **kwargs)
                self.assertEqual(connection.execute("SELECT count(*) FROM logs").fetchone(), (1,))
                self.assertTrue(snapshot.with_name("logs_2.sqlite-shm").is_file())
                observations.append("readonly SQLite reconstructed snapshot SHM")
                return connection

            try:
                self.assertTrue((home / "logs_2.sqlite-shm").is_file())
                with closing(connect((home / "logs_2.sqlite").as_uri() + "?immutable=1", uri=True)) as main_only:
                    with self.assertRaises(sqlite3.OperationalError):
                        main_only.execute("SELECT count(*) FROM logs")
                with patch.object(FIXTURE.sqlite3, "connect", side_effect=inspect_snapshot):
                    result = FIXTURE.collect_native_revocations(session, 99, 101)
            finally:
                source.close()
            self.assertEqual(result["status"], "available")
            self.assertEqual(len(result["records"]), 1)
            self.assertEqual(observations, ["readonly SQLite reconstructed snapshot SHM"])

    def test_full_busy_budget_keeps_older_than_sixty_second_trace_with_fixed_upper_bound(self):
        with native_home() as (session, home):
            database(home, [row(stamp=160)]).close()
            for end in (175, 340):
                with self.subTest(end=end):
                    result = FIXTURE.collect_native_revocations(session, 100, end)
                    self.assertEqual(result["status"], "available")
                    self.assertEqual(len(result["records"]), 1)
            self.assertEqual(FIXTURE.collect_native_revocations(session, 100, 341)["status"], "unavailable")

    def test_missing_corrupt_and_unparseable_are_not_absence_proof(self):
        with native_home() as (session, home):
            self.assertEqual(FIXTURE.collect_native_revocations(session, 99, 101)["status"], "unavailable")
            (home / "logs_2.sqlite").write_text("not sqlite")
            self.assertEqual(FIXTURE.collect_native_revocations(session, 99, 101)["status"], "unavailable")
            (home / "logs_2.sqlite").unlink()
            database(home, [row("secret malformed category"), row("x" * 4097)]).close()
            result = FIXTURE.collect_native_revocations(session, 99, 101)
            self.assertEqual((result["status"], result["rejectedRows"], result["records"]), ("partial", 2, []))
            self.assertNotIn("secret", json.dumps(result))

    def test_row_byte_and_file_caps(self):
        with native_home() as (session, home):
            database(home, [row()] * 257).close()
            result = FIXTURE.collect_native_revocations(session, 99, 101)
            self.assertTrue(result["truncated"])
            self.assertEqual(len(result["records"]), 256)
            with patch.object(FIXTURE, "NATIVE_DIAGNOSTIC_BYTES", 1):
                result = FIXTURE.collect_native_revocations(session, 99, 101)
            self.assertEqual(result["status"], "partial")
            self.assertEqual(result["records"], [])
            with (home / "logs_2.sqlite").open("r+b") as stream:
                stream.truncate(FIXTURE.NATIVE_DIAGNOSTIC_FILE_BYTES + 1)
            self.assertEqual(FIXTURE.collect_native_revocations(session, 99, 101)["status"], "unavailable")

    def test_identity_and_symlinks_refuse_before_sqlite_reads(self):
        for mutation in ("root_identity", "home_identity", "home_link", "db_link", "wal_link", "db_fifo"):
            with self.subTest(mutation=mutation), native_home() as (session, home):
                database(home, [row()]).close()
                outside = session["root"] / "not-a-native-file"
                outside.write_text("private owner text")
                if mutation == "root_identity":
                    session["rootIdentity"] = (0, 0)
                elif mutation == "home_identity":
                    session["homeIdentity"] = (0, 0)
                elif mutation == "home_link":
                    moved = home.with_name("moved")
                    home.rename(moved)
                    home.symlink_to(moved, target_is_directory=True)
                elif mutation == "db_link":
                    (home / "logs_2.sqlite").unlink()
                    (home / "logs_2.sqlite").symlink_to(outside)
                elif mutation == "wal_link":
                    (home / "logs_2.sqlite-wal").symlink_to(outside)
                else:
                    (home / "logs_2.sqlite").unlink()
                    os.mkfifo(home / "logs_2.sqlite")
                with patch.object(FIXTURE.sqlite3, "connect") as connect:
                    result = FIXTURE.collect_native_revocations(session, 99, 101)
                connect.assert_not_called()
                self.assertEqual(result["status"], "unavailable")
                self.assertNotIn("private owner text", json.dumps(result))

    def test_query_deadline_and_invalid_interval_are_unavailable(self):
        with native_home() as (session, home):
            database(home, [row()]).close()
            with patch.object(FIXTURE.time, "monotonic", side_effect=[0, 0, 3]):
                self.assertEqual(FIXTURE.collect_native_revocations(session, 99, 101)["status"], "unavailable")
            for start, end in [(float("nan"), 101), (102, 101), (1, 242)]:
                self.assertEqual(FIXTURE.collect_native_revocations(session, start, end)["status"], "unavailable")


class SubsequentObservationTests(unittest.TestCase):
    def setUp(self):
        self.binding = {"clientId": str(uuid4()), "connectionId": str(uuid4()), "backendPid": 123,
            "threadId": str(uuid4()), "generation": 7, "serverInstanceId": str(uuid4()), "serverGeneration": 5}

    def response(self, request):
        if request["command"] == "status":
            return {"selection": "selected", "private": "never copy me", "nativeObservation": {
                "binding": self.binding, "eligible": True, "cause": "never copy me"}}
        if request["command"] == "binding":
            return self.binding
        return {"challengeId": request["challengeId"], "observedAt": "2026-10-17T00:00:00.000Z",
            "validUntilMonotonic": 200, "witness": {**self.binding, "version": 2, "nonce": 10,
                "eligible": True, "sequence": 10, "cause": "never copy me", "leaseMs": 500,
                "nativeCoreTurnState": "busy"}}

    def test_status_preserves_production_selection_and_rejects_unknown_states(self):
        for selection in ("selected", "unavailable"):
            self.assertEqual(FIXTURE.diagnostic_native_response("status", {"selection": selection}),
                             {"status": "observed", "selection": selection})
        for response in ({}, {"selection": "unselected"}, {"selection": "other"}, {"selection": None}):
            self.assertEqual(FIXTURE.diagnostic_native_response("status", response), {"status": "malformed"})
        for eligible in (True, False, 0, 1, "true", None):
            response = {"selection": "unavailable", "nativeObservation": {"binding": self.binding, "eligible": eligible}}
            result = FIXTURE.diagnostic_native_response("status", response)
            self.assertEqual("eligible" in result, isinstance(eligible, bool))
            if isinstance(eligible, bool):
                self.assertIs(result["eligible"], eligible)

    def test_followup_busy_witness_never_satisfies_failed_busy_gate(self):
        request = Mock(side_effect=lambda state, session, message: self.response(message))
        ctx = SimpleNamespace(sessions={"C": {"state": "/fixed-fixture-state", "sessionId": "fixed-session"}},
            original_session_request=request, c_challenges=[], c_busy_nonces=set(), dispatch_results=[],
            c_busy_evidence_error="C2 busy disposition lacks fresh authoritative Core-busy evidence")
        with patch.object(FIXTURE, "collect_native_revocations", return_value={"status": "unavailable"}), \
                patch.object(FIXTURE, "record_evidence") as record, \
                patch.object(launcher, "_session_request", side_effect=AssertionError("normal observer used")):
            FIXTURE.capture_busy_failure(ctx, 100)
        self.assertEqual(request.call_count, 3)
        self.assertTrue(all(call.args[:2] == ("/fixed-fixture-state", "fixed-session") for call in request.call_args_list))
        evidence = record.call_args.args[2]
        self.assertEqual(record.call_args.args[1], "busyFailureDiagnostics")
        self.assertTrue(evidence["diagnosticOnly"])
        self.assertFalse(evidence["exactRejectedWitnessAvailable"])
        self.assertEqual(evidence["subsequentObservations"][-1]["result"]["witness"]["nativeCoreTurnState"], "busy")
        self.assertNotIn("never copy me", json.dumps(evidence))
        self.assertEqual((ctx.c_challenges, ctx.c_busy_nonces, ctx.dispatch_results), ([], set(), []))
        with self.assertRaisesRegex(AssertionError, "authoritative Core-busy"):
            FIXTURE.c_second_busy_dispositions(ctx)

    def test_failed_probe_remains_unavailable_and_does_not_attempt_challenge(self):
        ctx = SimpleNamespace(sessions={"C": {"state": "state", "sessionId": "session"}},
            original_session_request=Mock(side_effect=TimeoutError("do not print")))
        with patch.object(FIXTURE, "collect_native_revocations", return_value={"status": "unavailable"}), \
                patch.object(FIXTURE, "record_evidence") as record:
            FIXTURE.capture_busy_failure(ctx, 100)
        self.assertEqual(ctx.original_session_request.call_count, 2)
        self.assertNotIn("do not print", json.dumps(record.call_args.args[2]))

    def test_challenge_crossbinding_and_unknown_error_text_are_redacted(self):
        request = {"command": "challenge", "challengeId": str(uuid4())}
        response = self.response(request)
        for mutation in ("challenge", "binding", "lease", "lease_true", "lease_false", "extra"):
            value = json.loads(json.dumps(response))
            if mutation == "challenge":
                value["challengeId"] = str(uuid4())
            elif mutation == "binding":
                value["witness"]["generation"] += 1
            elif mutation == "lease":
                value["validUntilMonotonic"] = float("nan")
            elif mutation in ("lease_true", "lease_false"):
                value["validUntilMonotonic"] = mutation == "lease_true"
            else:
                value["unexpectedDiagnosticField"] = "omitted diagnostic marker"
            self.assertEqual(FIXTURE.diagnostic_native_response("challenge", value,
                expected_binding=self.binding, challenge_id=request["challengeId"]), {"status": "malformed"})
        self.assertEqual(FIXTURE.diagnostic_native_response("binding", {"reason": "private error details"}),
                         {"status": "refused", "reason": "other"})

    def test_diagnostic_failure_preserves_original_busy_failure(self):
        provider = SimpleNamespace(hold_lock=threading.Lock(), hold_started=threading.Event(),
            release_hold=threading.Event(), requests=[], errors=[])
        envelope = {"deliveryId": "delivery", "attemptId": "attempt"}
        ctx = SimpleNamespace(fixture=Mock(return_value={"envelope": envelope, "signedDelivery": {}}),
            runtime_ids={"C": "runtime"}, node_id="node", transport_key=Mock(),
            sessions={"C": {"provider": provider}}, dispatch_labels={}, listen_port=1234,
            state="state", start_calls={"C": [{}]}, dispatch_calls=[], dispatch_results=[],
            daemon_task=SimpleNamespace(done=lambda: False), c_second_busy_dispositions=lambda: [])
        ctx.transport_key.private_bytes.return_value = b"fixture-key"
        serializer = SimpleNamespace(Encoding=SimpleNamespace(DER="der"),
            PrivateFormat=SimpleNamespace(PKCS8="pkcs8"), NoEncryption=lambda: None)
        baseline = {"state": "created", "reservation_state": "none", "transport_status": "sending",
                    "permit_id": None, "submission_id": None, "turn_id": None}
        with patch.object(FIXTURE, "serialization", serializer), \
                patch.object(FIXTURE, "listener_delivery", return_value=(202, {})), \
                patch.object(FIXTURE, "wait_until", new=AsyncMock(side_effect=[None, None, None, AssertionError("original busy failure")])), \
                patch.object(FIXTURE, "require_model_held"), \
                patch.object(FIXTURE, "attempts_for", return_value=[]), \
                patch.object(FIXTURE, "native_claims_for", return_value=[]), \
                patch.object(FIXTURE, "transport_attempt_snapshot", return_value=baseline), \
                patch.object(FIXTURE, "has_attempt_state", return_value=True), \
                patch.object(FIXTURE, "db_delivery", return_value={"state": "queued", "attemptState": None}), \
                patch.object(FIXTURE, "db_delivery_envelope_sha256", return_value="digest"), \
                patch.object(FIXTURE, "capture_busy_failure", side_effect=RuntimeError("private diagnostic failure")) as capture, \
                self.assertRaisesRegex(AssertionError, "^original busy failure; bounded diagnostic="):
            asyncio.run(FIXTURE.run_busy_stage(ctx))
        capture.assert_called_once()
        self.assertFalse(provider.release_hold.is_set())


if __name__ == "__main__":
    unittest.main()
