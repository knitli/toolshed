"""Fail-closed boundaries for the disposable three-session acceptance fixture."""

import copy
import asyncio
from contextlib import closing
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess  # nosec B404 - Fixed Git executable and disposable test-owned repositories, no shell.
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SCRIPT = Path(__file__).resolve().parents[1] / "docs/native-bridge/three-session-workerd.py"
SPEC = importlib.util.spec_from_file_location("three_session_fixture", SCRIPT)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class ThreeSessionModelTests(unittest.TestCase):
    def provider(self):
        qualifier = FIXTURE.load_module('test_host_qualifier', SCRIPT.with_name('native-host-launcher-qualification.py'))
        qualifier.CALL_ID = 'session-specific-call'
        return SimpleNamespace(requests=[], main_requests=[], turn_main_requests=[],
            turn_title_count=0, phase='initial', errors=[], request_lock=threading.Lock(),
            active_requests=0, hold_lock=threading.Lock(), hold_next=True,
            hold_started=threading.Event(), release_hold=Mock(wait=Mock(return_value=True)),
            hold_state='idle', hold_deadline=0, qualifier=qualifier,
            nonce='fresh-nonce', program='read source', turn_verified=False)

    def respond(self, server, request):
        raw = json.dumps(request).encode()
        handler = SimpleNamespace(server=server, path='/v1/responses',
            headers={'Content-Length': str(len(raw))}, rfile=io.BytesIO(raw),
            wfile=io.BytesIO(), send_response=Mock(), send_header=Mock(),
            end_headers=Mock(), send_error=Mock())
        with patch.object(FIXTURE, 'host_qualifier', server.qualifier):
            FIXTURE.ModelProvider._respond(handler)
        return handler

    def test_title_cannot_consume_primary_hold(self):
        server = self.provider()
        self.respond(server, {'tools': [], 'text': {'format': {'schema': {
            'required': ['title'], 'properties': {'title': {}}}}},
            'input': 'Generate a concise, single-line task title'})
        server.release_hold.wait.assert_not_called()
        self.assertTrue(server.hold_next)
        self.assertFalse(server.hold_started.is_set())

    def test_extra_main_request_refuses_instead_of_starting_another_tool(self):
        server = self.provider()
        server.hold_next = False
        server.turn_main_requests = [{}, {}]
        handler = self.respond(server, {'tools': [{'name': 'exec'}]})
        handler.send_response.assert_not_called()
        self.assertTrue(server.errors)

    def test_expired_hold_cannot_prove_busy_even_if_event_remains_set(self):
        server = self.provider()
        server.hold_started.set()
        server.hold_state = 'held'
        server.hold_deadline = time.monotonic() - 1
        server.release_hold = threading.Event()
        with self.assertRaisesRegex(AssertionError, 'held'):
            FIXTURE.require_model_held(server)

    def test_completion_requires_success_idle_and_exact_request_count(self):
        server = self.provider()
        server.turn_main_requests = [{}, {}]
        server.turn_verified = True
        FIXTURE.require_model_turn_complete(server)
        for field, value in (('turn_verified', False), ('active_requests', 1),
                             ('turn_main_requests', [{}, {}, {}]), ('errors', ['late error'])):
            original = getattr(server, field)
            setattr(server, field, value)
            with self.subTest(field=field), self.assertRaises(AssertionError):
                FIXTURE.require_model_turn_complete(server)
            setattr(server, field, original)

    def test_source_read_requires_this_sessions_call_and_fresh_nonce(self):
        for call_id in ('session-specific-call', 'another-session-call'):
            with self.subTest(call_id=call_id):
                server = self.provider()
                server.hold_next = False
                self.respond(server, {'tools': [{'name': 'exec'}]})
                self.respond(server, {'tools': [{'name': 'exec'}], 'input': [{
                    'type': 'custom_tool_call_output', 'call_id': call_id,
                    'output': [{'text': json.dumps({'exit_code': 0, 'output': 'fresh-nonce\n'})}]}]})
                self.assertEqual(server.turn_verified, call_id == 'session-specific-call')
                self.assertEqual(bool(server.errors), call_id != 'session-specific-call')

    def test_providers_have_independent_verifier_call_ids(self):
        host = self.provider().qualifier
        with patch.object(FIXTURE, 'host_qualifier', host), \
                patch.object(FIXTURE, 'ThreadingHTTPServer', side_effect=lambda *_: SimpleNamespace(serve_forever=Mock())), \
                patch.object(FIXTURE.threading, 'Thread'):
            first = FIXTURE.make_model(Mock())
            second = FIXTURE.make_model(Mock())
        first_id = first.qualifier.CALL_ID
        self.assertNotEqual(first_id, second.qualifier.CALL_ID)
        second.qualifier.CALL_ID = 'next-turn'
        self.assertEqual(first.qualifier.CALL_ID, first_id)
        self.assertEqual(host.CALL_ID, 'session-specific-call')

    def test_temp_root_is_explicit_private_and_ancestry_checked(self):
        helper = FIXTURE.load_module('test_installed_helper', SCRIPT.with_name('qualification-installed.py'))
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(FIXTURE, 'installed_helper', helper):
            root = Path(directory).resolve()
            with patch.dict(os.environ, {'TMPDIR': str(root)}):
                self.assertEqual(FIXTURE.private_temp_root(), root)
                root.chmod(0o777)
                with self.assertRaisesRegex(AssertionError, 'private'):
                    FIXTURE.private_temp_root()
                root.chmod(0o700)
                with patch.object(helper, '_ancestors', side_effect=ValueError('unsafe ancestor')):
                    with self.assertRaisesRegex(ValueError, 'unsafe ancestor'):
                        FIXTURE.private_temp_root()

    def test_invalid_temp_root_refuses_before_starting_broker(self):
        with patch.object(FIXTURE, 'private_temp_root', side_effect=ValueError('unsafe TMPDIR')), \
                patch.object(FIXTURE, 'start_broker') as broker:
            with self.assertRaisesRegex(ValueError, 'unsafe TMPDIR'):
                asyncio.run(FIXTURE.run_scenario())
            broker.assert_not_called()


class ThreeSessionProcessTests(unittest.TestCase):
    def test_ps_selects_only_exact_group_with_fixed_bounded_command(self):
        result = SimpleNamespace(stdout="  410 411\n  41 412\n  410\t413\n  0 1\n")
        with patch.object(FIXTURE.subprocess, "run", return_value=result) as run:
            self.assertEqual(FIXTURE.process_group_members(410), [411, 413])
        run.assert_called_once_with(["/bin/ps", "-axo", "pgid=,pid="], check=True,
                                    capture_output=True, text=True, timeout=5)

    def test_malformed_ps_output_cannot_prove_group_absent(self):
        vectors = ("", "\n", "PGID PID\n", "410\n", "410 411 extra\n", "410 nope\n",
                   "nope 411\n", "410 -1\n", "410 0\n", "-1 411\n", "٤١٠ 411\n",
                   "410 411\ncorrupted\n", "999 invalid\n")
        for raw in vectors:
            with self.subTest(raw=raw), patch.object(FIXTURE.subprocess, "run",
                                                    return_value=SimpleNamespace(stdout=raw)):
                with self.assertRaises((AssertionError, ValueError)):
                    FIXTURE.process_group_members(410)

    def test_ps_failure_or_timeout_cannot_prove_group_absent(self):
        for error in (subprocess.CalledProcessError(1, "ps"), subprocess.TimeoutExpired("ps", 5)):
            with self.subTest(error=type(error).__name__), \
                    patch.object(FIXTURE.subprocess, "run", side_effect=error), self.assertRaises(type(error)):
                FIXTURE.process_group_members(410)

    def test_invalid_group_ids_rejected_before_subprocess(self):
        for group in (True, False, None, "410", 410.0, 0, 1, -1):
            with self.subTest(group=group), patch.object(FIXTURE.subprocess, "run") as run:
                with self.assertRaises((AssertionError, ValueError)):
                    FIXTURE.process_group_members(group)
                run.assert_not_called()

    def test_process_probe_never_signals_boolean_or_invalid_pid(self):
        for pid in (True, False, None, "410", 410.0, 0, 1, -1):
            with self.subTest(pid=pid), patch.object(FIXTURE.os, "kill") as kill:
                self.assertFalse(FIXTURE.process_is_running(pid))
                kill.assert_not_called()
        for error, expected in ((None, True), (ProcessLookupError(), False), (PermissionError(), True)):
            with self.subTest(error=type(error).__name__), patch.object(FIXTURE.os, "kill", side_effect=error) as kill:
                self.assertEqual(FIXTURE.process_is_running(410), expected)
                kill.assert_called_once_with(410, 0)

    def test_native_cleanup_requires_valid_backend_and_owned_removed_socket(self):
        process = Mock(pid=410)
        process.poll.return_value = 0
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state"
            state.mkdir()
            socket = state / "c-owned.sock"
            with patch.object(FIXTURE, "process_group_members", return_value=[]), \
                    patch.object(FIXTURE, "process_is_running", return_value=False):
                result = {}
                FIXTURE.verify_native_cleanup(process, state, {"backendPid": 411, "socketPath": socket}, result)
                self.assertTrue(result["backendStopped"] and result["controlSocketRemoved"])
                for backend in (True, False, None, "411", 0, 1, -1):
                    with self.subTest(backend=backend), self.assertRaises(AssertionError):
                        FIXTURE.verify_native_cleanup(process, state,
                                                      {"backendPid": backend, "socketPath": socket}, {})
                outside = Path(directory) / "unowned.sock"
                with self.assertRaises(AssertionError):
                    FIXTURE.verify_native_cleanup(process, state, {"backendPid": 411, "socketPath": outside}, {})
                socket.symlink_to(outside)
                with self.assertRaises(AssertionError):
                    FIXTURE.verify_native_cleanup(process, state, {"backendPid": 411, "socketPath": socket}, {})

    def test_emergency_child_cleanup_does_not_turn_failed_cleanup_into_pass(self):
        process = Mock(pid=410)
        process.poll.return_value = 0
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            result = {}
            with patch.object(FIXTURE, "process_group_members", side_effect=[[411], [], [], [], []]), \
                    patch.object(FIXTURE.os, "killpg") as killpg, \
                    patch.object(FIXTURE, "process_is_running", return_value=False):
                with self.assertRaisesRegex(AssertionError, "native CLI cleanup failed"):
                    FIXTURE.verify_native_cleanup(process, state,
                                                  {"backendPid": 411, "socketPath": state / "c.sock"}, result)
                killpg.assert_called_once_with(410, signal.SIGTERM)
                self.assertTrue(result["boundedGroupCleanupUsed"])


class ThreeSessionBrokerTests(unittest.TestCase):
    def test_invalid_port_cannot_open_socket(self):
        for port in (True, False, None, "49734", 49734.0, 0, -1, 65536):
            with self.subTest(port=port), patch.object(FIXTURE.socket, "socket") as socket:
                with self.assertRaises((AssertionError, ValueError)):
                    FIXTURE.port_is_closed(port)
                socket.assert_not_called()

    def test_port_probe_only_connection_refusal_proves_closed(self):
        for error, expected in ((None, False), (ConnectionRefusedError(), True), (TimeoutError(), False)):
            probe = Mock()
            probe.connect.side_effect = error
            with self.subTest(error=type(error).__name__), \
                    patch.object(FIXTURE.socket, "socket", return_value=probe):
                self.assertEqual(FIXTURE.port_is_closed(49734), expected)
                probe.connect.assert_called_once_with(("127.0.0.1", 49734))
                probe.close.assert_called_once_with()

    def test_invalid_broker_handshake_rejected_and_child_cleaned(self):
        vectors = ((True, "fixture-only"), (False, "fixture-only"),
                   (49735, "fixture-only"), (49734, ""))
        for port, secret in vectors:
            with self.subTest(port=port, secret=secret), tempfile.TemporaryDirectory() as directory:
                parsed = SimpleNamespace(esbuild=directory, miniflare=directory,
                                         entry_port=49732, loopback_port=49733, broker_port=49734)
                process = Mock(pid=410)
                process.stdout = io.StringIO(json.dumps({"port": port, "secret": secret}) + "\n")
                broker_log = io.BytesIO()
                with patch.object(FIXTURE, "args", parsed), \
                        patch.object(FIXTURE.tempfile, "TemporaryFile", return_value=broker_log), \
                        patch.object(FIXTURE.subprocess, "Popen", return_value=process), \
                        patch.object(FIXTURE.select, "select", return_value=([process.stdout], [], [])), \
                        patch.object(FIXTURE.os, "killpg") as killpg:
                    with self.assertRaisesRegex(RuntimeError, "workerd fixture startup failed"):
                        FIXTURE.start_broker()
                    killpg.assert_called_once_with(410, signal.SIGTERM)
                    process.wait.assert_called_once_with(timeout=10)
                    self.assertTrue(broker_log.closed)


class ThreeSessionSourceTests(unittest.TestCase):
    def inputs(self, root):
        package = root / "package/src/event_gateway"
        package.mkdir(parents=True)
        binary = root / "codex"
        binary.write_bytes(b"not executed")
        node = root / "node"
        node.write_bytes(b"not executed")
        cloud = root / "checkout/apps/os/packages/event-runtime/src"
        cloud.mkdir(parents=True)
        parsed = SimpleNamespace(package_source=str(package), binary=str(binary), node=str(node),
                                 cloud_source=str(cloud), cloud_commit="a" * 40,
                                 output=str(root / "proof.json"), entry_port=True,
                                 loopback_port=49733, broker_port=49734)
        helper = Mock()
        helper.verified_executable.return_value = str(node)
        return parsed, helper, cloud

    def test_occupied_or_symlink_sidecar_rejected_before_subprocess(self):
        for kind in ("file", "directory", "dangling-symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parsed, helper, cloud = self.inputs(root)
                (cloud.parents[4] / ".git").write_text("gitdir: unused mocked path")
                sidecar = root / "proof.private-causal.json"
                if kind == "file":
                    sidecar.write_text("preserve prior evidence")
                elif kind == "directory":
                    sidecar.mkdir()
                else:
                    sidecar.symlink_to(root / "missing")
                with patch.object(FIXTURE, "load_module", return_value=helper), \
                        patch.object(FIXTURE.subprocess, "run") as run, \
                        patch.object(FIXTURE.subprocess, "Popen") as popen:
                    with self.assertRaisesRegex(AssertionError, "sidecar|causal"):
                        FIXTURE.configure(parsed)
                    run.assert_not_called()
                    popen.assert_not_called()
                if kind == "file":
                    self.assertEqual(sidecar.read_text(), "preserve prior evidence")

    def test_inherited_git_repository_overrides_cannot_change_validated_head(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            parsed, helper, cloud = self.inputs(root)
            checkout = cloud.parents[4]
            other = root / "other-repository"
            environment = {"PATH": "/usr/bin:/bin", "HOME": str(root),
                           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": FIXTURE.os.devnull}
            heads = []
            for repository in (checkout, other):
                subprocess.run(  # nosec B603 - Fixed Git and private tempfile path; no external input or shell.
                    ["/usr/bin/git", "init", "--quiet", "--initial-branch=main", str(repository)],
                    check=True, capture_output=True, timeout=10, env=environment)
                subprocess.run(  # nosec B603 - Fixed Git, literal commit options, and test-owned repo; hooks disabled.
                    ["/usr/bin/git", "-C", str(repository), "-c", "user.name=Fixture",
                     "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null",
                     "commit", "--quiet", "--allow-empty", "-m", repository.name],
                    check=True, capture_output=True, timeout=10, env=environment)
                heads.append(subprocess.run(  # nosec B603 - Fixed Git reading HEAD from a private test-owned repo.
                    ["/usr/bin/git", "-C", str(repository), "rev-parse", "HEAD"],
                    check=True, capture_output=True, text=True, timeout=10,
                    env=environment).stdout.strip())
            self.assertNotEqual(heads[0], heads[1])
            parsed.cloud_commit = heads[0]
            hostile = {"GIT_DIR": str(other / ".git"), "GIT_WORK_TREE": str(other)}
            with patch.object(FIXTURE, "load_module", return_value=helper), \
                    patch.dict(FIXTURE.os.environ, hostile):
                # Reaching the later invalid-port gate proves the actual Git
                # subprocess checked the selected checkout and its own HEAD.
                with self.assertRaisesRegex(AssertionError, "port outside range"):
                    FIXTURE.configure(parsed)

    def test_cloud_path_must_be_directory_in_exact_checkout_layout_before_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parsed, helper, cloud = self.inputs(root)
            wrong = root / "elsewhere/event-runtime/src"
            wrong.mkdir(parents=True)
            for path in (wrong, cloud):
                parsed.cloud_source = str(path)
                with self.subTest(path=path), patch.object(FIXTURE, "load_module", return_value=helper), \
                        patch.object(FIXTURE.subprocess, "run") as run:
                    with self.assertRaises(AssertionError):
                        FIXTURE.configure(parsed)
                    run.assert_not_called()
            cloud.rmdir()
            cloud.write_text("not a directory")
            parsed.cloud_source = str(cloud)
            with patch.object(FIXTURE, "load_module", return_value=helper), \
                    patch.object(FIXTURE.subprocess, "run") as run, self.assertRaises(AssertionError):
                FIXTURE.configure(parsed)
            run.assert_not_called()

    def test_git_readback_binds_checkout_root_and_commit_with_closed_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            parsed, helper, cloud = self.inputs(root)
            checkout = cloud.parents[4]
            (checkout / ".git").write_text("gitdir: unused mocked path")
            outputs = [(str(root) + "\n" + parsed.cloud_commit + "\n", "supplied Git checkout"),
                       (str(checkout) + "\n" + "b" * 40 + "\n", "commit differs"),
                       (str(checkout) + "\n", "readback was malformed"),
                       (str(checkout) + "\n" + parsed.cloud_commit + "\n", "port outside range")]
            for stdout, message in outputs:
                with self.subTest(message=message), patch.object(FIXTURE, "load_module", return_value=helper), \
                        patch.object(FIXTURE.subprocess, "run", return_value=SimpleNamespace(stdout=stdout)) as run:
                    with self.assertRaisesRegex(AssertionError, message):
                        FIXTURE.configure(parsed)
                    self.assertEqual(run.call_args.args[0],
                                     ["/usr/bin/git", "-C", str(checkout), "rev-parse",
                                      "--show-toplevel", "--verify", "HEAD"])
                    environment = run.call_args.kwargs["env"]
                    self.assertEqual(environment["PATH"], "/usr/bin:/bin")
                    self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
                    self.assertEqual(environment["GIT_CONFIG_GLOBAL"], FIXTURE.os.devnull)
                    self.assertNotIn("GIT_DIR", environment)
                    self.assertEqual(run.call_args.kwargs["timeout"], 10)


class ThreeSessionHistoricalReceiptTests(unittest.TestCase):
    def test_history_readback_keeps_full_original_rows_and_filters_delivery(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            database = state / "ledger.sqlite"
            with closing(sqlite3.connect(database)) as db:
                db.execute("CREATE TABLE deliveries (id TEXT, state TEXT, envelope TEXT)")
                db.execute("CREATE TABLE attempts (delivery_id TEXT, attempt_id TEXT, state TEXT, native_request TEXT)")
                db.executemany("INSERT INTO deliveries VALUES (?, ?, ?)",
                               [("c1", "observed", "original envelope"), ("other", "submitted", "unrelated")])
                db.executemany("INSERT INTO attempts VALUES (?, ?, ?, ?)",
                               [("c1", "b", "observed", "request b"),
                                ("other", "c", "submitted", "unrelated request"),
                                ("c1", "a", "observed", "request a")])
                db.commit()
            original_bytes = database.read_bytes()
            history = FIXTURE.db_delivery_history(state, "c1")
            self.assertEqual(history["delivery"],
                             {"id": "c1", "state": "observed", "envelope": "original envelope"})
            self.assertEqual(history["attempts"], [
                {"delivery_id": "c1", "attempt_id": "a", "state": "observed", "native_request": "request a"},
                {"delivery_id": "c1", "attempt_id": "b", "state": "observed", "native_request": "request b"},
            ])
            self.assertEqual(FIXTURE.db_delivery_history(state, "absent"), {"delivery": None, "attempts": []})
            self.assertEqual(database.read_bytes(), original_bytes)

    def settled(self):
        return ({"id": "c1-delivery", "state": "observed", "envelope": "original envelope"},
                [{"delivery_id": "c1-delivery", "state": "observed", "request": "original request"}],
                [{"attempt_id": "c1-attempt", "state": "observed", "turn_id": "original turn"}],
                [{"attempt_id": "c1-attempt", "claim_id": "original claim"}],
                ["inputRecorded"])

    def test_only_settled_local_and_remote_c1_allows_rotation(self):
        valid = self.settled()
        FIXTURE.assert_c1_settled(*valid)
        vectors = []
        for state in ("submitted", "ambiguous", "submitting", "queued"):
            values = copy.deepcopy(valid)
            values[0]["state"] = state
            vectors.append(values)
            values = copy.deepcopy(valid)
            values[1][0]["state"] = state
            vectors.append(values)
            values = copy.deepcopy(valid)
            values[2][0]["state"] = state
            vectors.append(values)
        for index in (1, 2, 3):
            for replacement in ([], [valid[index][0], valid[index][0]]):
                values = list(copy.deepcopy(valid))
                values[index] = replacement
                vectors.append(values)
        for receipts in ([], ["unknown"], ["rejected"], ["started"]):
            values = list(copy.deepcopy(valid))
            values[4] = receipts
            vectors.append(values)
        for index, values in enumerate(vectors):
            with self.subTest(index=index), self.assertRaises(AssertionError):
                FIXTURE.assert_c1_settled(*values)

    def test_attach_preserves_entire_historical_rows_not_only_terminal_states(self):
        delivery, attempts, remote_attempts, claims, receipts = self.settled()
        before = {"localDelivery": delivery, "localAttempts": attempts,
                  "workerdAttempts": remote_attempts, "workerdClaims": claims,
                  "receiptStatuses": receipts}
        FIXTURE.assert_c1_history_unchanged(before, copy.deepcopy(before))
        mutations = [("localDelivery", None, "envelope", "retargeted envelope"),
                     ("localAttempts", 0, "request", "new request"),
                     ("workerdAttempts", 0, "turn_id", "new turn"),
                     ("workerdClaims", 0, "claim_id", "new claim")]
        for key, index, field, value in mutations:
            after = copy.deepcopy(before)
            target = after[key] if index is None else after[key][index]
            target[field] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                FIXTURE.assert_c1_history_unchanged(before, after)
        after = copy.deepcopy(before)
        after["receiptStatuses"].append("unknown")
        with self.assertRaises(AssertionError):
            FIXTURE.assert_c1_history_unchanged(before, after)
