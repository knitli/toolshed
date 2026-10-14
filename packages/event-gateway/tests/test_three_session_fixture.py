"""Fail-closed boundaries for the disposable three-session acceptance fixture."""

import copy
import asyncio
from contextlib import ExitStack, closing
from concurrent.futures import ThreadPoolExecutor
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
from unittest.mock import AsyncMock, Mock, patch
from uuid import uuid4


SCRIPT = Path(__file__).resolve().parents[1] / "docs/native-bridge/three-session-workerd.py"
SPEC = importlib.util.spec_from_file_location("three_session_fixture", SCRIPT)
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class ThreeSessionContainmentTests(unittest.TestCase):
    def test_kernel_checks_require_active_denials_and_writable_positive_control(self):
        for fault in (None, 'unsandboxed', 'owner', 'outside', 'network', 'scratch', 'invalid', 'errno', 'missing'):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as directory:
                scratch = Path(directory)
                calls = []

                def check(pid, operation, filter_type, *values):
                    self.assertEqual(pid, os.getpid())
                    if operation is None:
                        self.assertEqual(filter_type, 0)
                        return 0 if fault == 'unsandboxed' else 1
                    path = os.fsdecode(values[0].value) if values else None
                    self.assertEqual(filter_type, 1024 | (1 if path is not None else 0))
                    calls.append((operation, path))
                    owned = path is not None and Path(path).is_relative_to(scratch)
                    if fault == 'invalid':
                        return -1
                    if fault == 'errno':
                        FIXTURE.ctypes.set_errno(5)
                    if owned:
                        self.assertTrue(Path(path).is_file(), 'positive control must exist')
                        return 1 if fault == 'scratch' else 0
                    if fault == 'owner' and operation == b'file-read-data':
                        return 0
                    if fault == 'outside' and operation == b'file-write-create' and path != '/private/tmp':
                        return 0
                    if fault == 'network' and operation.startswith(b'network-'):
                        return 0
                    return 1

                library = SimpleNamespace(sandbox_check=Mock(side_effect=check))
                with patch.object(FIXTURE.sys, 'platform', 'darwin'), \
                        patch.object(Path, 'is_dir', return_value=fault != 'missing'), \
                        patch.object(FIXTURE.ctypes, 'CDLL', return_value=library), \
                        patch.object(FIXTURE.ctypes.c_int, 'in_dll', return_value=SimpleNamespace(value=1024)):
                    if fault is None:
                        proof = FIXTURE.verify_outer_containment(scratch)
                        self.assertEqual(proof['mode'], 'verified-outer-sandbox')
                        self.assertTrue(proof['addressSpecificPolicyRequiresIndependentAudit'])
                        self.assertEqual(len(calls), 9)
                        outside = [Path(path) for operation, path in calls
                                   if operation == b'file-write-create' and not Path(path).is_relative_to(scratch)]
                        self.assertEqual(len(outside), 1)
                        self.assertEqual(outside[0].parent, Path('/private/tmp'))
                        self.assertTrue(outside[0].name.startswith('event-three-denied-'))
                        self.assertFalse(outside[0].exists())
                    else:
                        with self.assertRaises(AssertionError):
                            FIXTURE.verify_outer_containment(scratch)
                self.assertEqual(list(scratch.iterdir()), [], 'positive control must be removed')

    def test_outer_mode_refuses_unsupported_platform_and_before_broker(self):
        with patch.object(FIXTURE.sys, 'platform', 'linux'), patch.object(FIXTURE.ctypes, 'CDLL') as load:
            with self.assertRaisesRegex(AssertionError, 'macOS'):
                FIXTURE.verify_outer_containment(Path('/fixture'))
            load.assert_not_called()
        with patch.object(FIXTURE, 'args', SimpleNamespace(outer_contained=True), create=True), \
                patch.object(FIXTURE, 'private_temp_root', return_value=Path('/fixture')), \
                patch.object(FIXTURE, 'verify_outer_containment', side_effect=AssertionError('unsafe outer')), \
                patch.object(FIXTURE, 'start_broker') as broker:
            with self.assertRaisesRegex(AssertionError, 'unsafe outer'):
                asyncio.run(FIXTURE.run_scenario())
            broker.assert_not_called()

    def test_default_keeps_native_profile_and_outer_mode_requires_recheck(self):
        profile = Path('/fixture/offline.sb')
        original = ['/usr/bin/sandbox-exec', '-f', str(profile), FIXTURE.sys.executable, '-I', '-m', 'event_gateway.cli']
        qualifier = SimpleNamespace(launch_argv=Mock(return_value=original))
        with patch.object(FIXTURE, 'host_qualifier', qualifier, create=True), \
                patch.object(FIXTURE, 'binary', Path('/fixture/codex'), create=True), \
                patch.object(FIXTURE, 'private_temp_root', return_value=Path('/fixture')), \
                patch.object(FIXTURE, 'verify_outer_containment') as verify, \
                patch.object(FIXTURE, 'args', SimpleNamespace(outer_contained=False), create=True):
            self.assertEqual(FIXTURE.native_launch_argv(profile, 'cache', 'state', 'root'), original)
            verify.assert_not_called()
            FIXTURE.args.outer_contained = True
            self.assertEqual(FIXTURE.native_launch_argv(profile, 'cache', 'state', 'root'), original[3:])
            verify.assert_called_once_with(Path('/fixture'))
            verify.side_effect = AssertionError('unsafe outer')
            with self.assertRaisesRegex(AssertionError, 'unsafe outer'):
                FIXTURE.native_launch_argv(profile, 'cache', 'state', 'root')
            verify.side_effect = None
            qualifier.launch_argv.return_value = ['changed-prefix', *original[1:]]
            with self.assertRaisesRegex(AssertionError, 'prefix changed'):
                FIXTURE.native_launch_argv(profile, 'cache', 'state', 'root')


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

    @patch.object(FIXTURE.sys, "platform", "linux")
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

    @patch.object(FIXTURE.sys, "platform", "darwin")
    def test_darwin_temp_root_byte_limit_precedes_broker_in_both_modes(self):
        self.assertEqual(FIXTURE.DARWIN_TEMP_ROOT_BYTES, 30)
        info = SimpleNamespace(st_mode=0o40700, st_uid=os.getuid())
        for outer in (False, True):
            for tail, allowed in (("a" * 29, True), ("a" * 30, False),
                                  ("é" * 14 + "a", True), ("é" * 15, False)):
                root = Path("/" + tail)
                with self.subTest(outer=outer, root=str(root)), \
                        patch.dict(os.environ, {"TMPDIR": str(root)}), \
                        patch.object(Path, 'resolve', return_value=root), \
                        patch.object(Path, 'lstat', return_value=info), \
                        patch.object(FIXTURE, 'installed_helper', SimpleNamespace(_ancestors=Mock())), \
                        patch.object(FIXTURE, 'args', SimpleNamespace(outer_contained=outer)), \
                        patch.object(FIXTURE, 'verify_outer_containment') as containment, \
                        patch.object(FIXTURE, 'start_broker') as broker:
                    if allowed:
                        self.assertEqual(FIXTURE.private_temp_root(), root)
                    else:
                        with self.assertRaisesRegex(AssertionError, 'at most 30 bytes'):
                            asyncio.run(FIXTURE.run_scenario())
                        broker.assert_not_called()
                        containment.assert_not_called()

    def test_invalid_temp_root_refuses_before_starting_broker(self):
        with patch.object(FIXTURE, 'private_temp_root', side_effect=ValueError('unsafe TMPDIR')), \
                patch.object(FIXTURE, 'start_broker') as broker:
            with self.assertRaisesRegex(ValueError, 'unsafe TMPDIR'):
                asyncio.run(FIXTURE.run_scenario())
            broker.assert_not_called()


class ThreeSessionProcessTests(unittest.TestCase):
    @patch.object(FIXTURE.sys, "platform", "linux")
    def test_ps_selects_only_exact_group_with_fixed_bounded_command(self):
        result = SimpleNamespace(stdout="  410 411\n  41 412\n  410\t413\n  0 1\n")
        with patch.object(FIXTURE.subprocess, "run", return_value=result) as run:
            self.assertEqual(FIXTURE.process_group_members(410), [411, 413])
        run.assert_called_once_with(["/bin/ps", "-axo", "pgid=,pid="], check=True,
                                    capture_output=True, text=True, timeout=5)

    @patch.object(FIXTURE.sys, "platform", "linux")
    def test_malformed_ps_output_cannot_prove_group_absent(self):
        vectors = ("", "\n", "PGID PID\n", "410\n", "410 411 extra\n", "410 nope\n",
                   "nope 411\n", "410 -1\n", "410 0\n", "-1 411\n", "٤١٠ 411\n",
                   "410 411\ncorrupted\n", "999 invalid\n")
        for raw in vectors:
            with self.subTest(raw=raw), patch.object(FIXTURE.subprocess, "run",
                                                    return_value=SimpleNamespace(stdout=raw)):
                with self.assertRaises((AssertionError, ValueError)):
                    FIXTURE.process_group_members(410)

    @patch.object(FIXTURE.sys, "platform", "linux")
    def test_ps_failure_or_timeout_cannot_prove_group_absent(self):
        for error in (subprocess.CalledProcessError(1, "ps"), subprocess.TimeoutExpired("ps", 5)):
            with self.subTest(error=type(error).__name__), \
                    patch.object(FIXTURE.subprocess, "run", side_effect=error), self.assertRaises(type(error)):
                FIXTURE.process_group_members(410)

    @patch.object(FIXTURE.sys, "platform", "darwin")
    def test_darwin_lists_exact_group_without_ps_and_tolerates_only_exit_race(self):
        def listing(buffer, size):
            if buffer is None:
                return 4
            self.assertEqual(size, FIXTURE.ctypes.sizeof(buffer))
            buffer[:5] = [0, 411, 412, 413, 414]
            return 5

        library = SimpleNamespace(proc_listallpids=Mock(side_effect=listing))
        with patch.object(FIXTURE.ctypes, "CDLL", return_value=library) as load, \
                patch.object(FIXTURE.os, "getpid", return_value=411), \
                patch.object(FIXTURE.os, "getpgid", side_effect=[410, 41, ProcessLookupError(), 410]), \
                patch.object(FIXTURE.subprocess, "run") as run:
            self.assertEqual(FIXTURE.process_group_members(410), [411, 414])
        load.assert_called_once_with("/usr/lib/libproc.dylib", use_errno=True)
        run.assert_not_called()
        self.assertEqual(library.proc_listallpids.argtypes, [FIXTURE.ctypes.c_void_p, FIXTURE.ctypes.c_int])
        self.assertEqual(library.proc_listallpids.restype, FIXTURE.ctypes.c_int)

    @patch.object(FIXTURE.sys, "platform", "darwin")
    def test_darwin_rejects_bad_counts_truncation_and_incomplete_rows(self):
        cases = [(0, None), (-1, None), (100000, None), (1, 0), (1, -1),
                 (1, 130), (1, "saturated"), (1, [412]), (1, [-1, 411]), (1, [411, 411])]
        for estimate, result in cases:
            def listing(buffer, size):
                if buffer is None:
                    return estimate
                if result == "saturated":
                    return len(buffer)
                if isinstance(result, list):
                    buffer[:len(result)] = result
                    return len(result)
                return result
            library = SimpleNamespace(proc_listallpids=Mock(side_effect=listing))
            with self.subTest(estimate=estimate, result=result), \
                    patch.object(FIXTURE.ctypes, "CDLL", return_value=library), \
                    patch.object(FIXTURE.os, "getpid", return_value=411), \
                    patch.object(FIXTURE.os, "getpgid") as getpgid:
                with self.assertRaises((AssertionError, ValueError)):
                    FIXTURE.process_group_members(410)
                getpgid.assert_not_called()
                self.assertLessEqual(library.proc_listallpids.call_count, 4)

    @patch.object(FIXTURE.sys, "platform", "darwin")
    def test_darwin_retries_saturated_snapshot_before_claiming_absence(self):
        capacities = []

        def listing(buffer, size):
            if buffer is None:
                return 1
            capacities.append(len(buffer))
            if len(capacities) == 1:
                return len(buffer)
            buffer[:2] = [411, 412]
            return 2
        library = SimpleNamespace(proc_listallpids=Mock(side_effect=listing))
        with patch.object(FIXTURE.ctypes, "CDLL", return_value=library), \
                patch.object(FIXTURE.os, "getpid", return_value=411), \
                patch.object(FIXTURE.os, "getpgid", side_effect=[41, 410]):
            self.assertEqual(FIXTURE.process_group_members(410), [412])
        self.assertEqual(capacities, [129, 258])

    @patch.object(FIXTURE.sys, "platform", "darwin")
    def test_darwin_permission_error_cannot_prove_group_absent(self):
        def listing(buffer, size):
            if buffer is not None:
                buffer[0] = 411
            return 1
        library = SimpleNamespace(proc_listallpids=Mock(side_effect=listing))
        with patch.object(FIXTURE.ctypes, "CDLL", return_value=library), \
                patch.object(FIXTURE.os, "getpid", return_value=411), \
                patch.object(FIXTURE.os, "getpgid", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
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


class ThreeSessionPrivateEvidenceTests(unittest.TestCase):
    def test_failed_stage_retains_database_before_resource_and_state_cleanup(self):
        self.run_retention_scenario("stage-failure")

    def test_partial_database_preserves_original_failure_and_missing_table_diagnostics(self):
        self.run_retention_scenario("partial-failure")

    def test_partial_database_cannot_produce_success(self):
        self.run_retention_scenario("partial-success")

    def test_final_archive_hash_includes_exit_snapshot_and_late_handler_write(self):
        self.run_retention_scenario("success")

    def test_evidence_write_failure_still_cleans_owned_resources(self):
        self.run_retention_scenario("write-failure")

    def test_evidence_fsync_failure_still_closes_resources_and_descriptors(self):
        self.run_retention_scenario("fsync-failure")

    def run_retention_scenario(self, outcome):
        with tempfile.TemporaryDirectory() as directory, ExitStack() as patches:
            root = Path(directory)
            output = root / "proof.json"
            key = Mock()
            key.public_key.return_value.public_bytes_raw.return_value = b"key"
            key.sign.return_value = b"signature"
            globals_ = {
                "args": SimpleNamespace(output=str(output), outer_contained=False),
                "private_key_type": SimpleNamespace(generate=lambda: key),
                "launcher": Mock(), "Store": Mock(), "daemon": Mock(),
                "SessionNativeBridge": Mock(), "client_runtime": Mock(), "CloudClient": Mock(),
            }
            for name, value in globals_.items():
                patches.enter_context(patch.object(FIXTURE, name, value))
            patches.enter_context(patch.object(FIXTURE, "private_temp_root", return_value=root))
            patches.enter_context(patch.object(FIXTURE, "start_broker", return_value=(None, None, {"secret": uuid4().hex, "port": 12345})))
            stop = patches.enter_context(patch.object(FIXTURE, "stop_broker", return_value={}))
            patches.enter_context(patch.object(FIXTURE, "post", return_value=(200, {}, b'{"challengeId":"id","signingPayload":"payload"}')))
            state_roots = []
            descriptors = []
            resource_closed = []
            if outcome == "fsync-failure":
                patches.enter_context(patch.object(FIXTURE.os, "fsync", side_effect=OSError("fsync failed")))
            for name in ("run_ab_routes", "run_busy_stage", "run_fixture_attach", "run_post_attach_c3"):
                patches.enter_context(patch.object(FIXTURE, name, AsyncMock()))
            patches.enter_context(patch.object(FIXTURE, "build_proof", return_value=({}, None)))

            async def fail(ctx, resources):
                self.prepare_retention_stage(ctx, resources, outcome, state_roots, descriptors, resource_closed)

            patches.enter_context(patch.object(FIXTURE, "initialize_runtime", side_effect=fail))
            proof = None
            if outcome == "success":
                proof = asyncio.run(FIXTURE.run_scenario())
            else:
                error, message = {
                    "stage-failure": (RuntimeError, "injected stage failure"),
                    "partial-failure": (ValueError, "original partial ledger failure"),
                    "partial-success": (AssertionError, "checkpoint ledger is incomplete"),
                    "write-failure": (AssertionError, "bounded archive"),
                    "fsync-failure": (OSError, "fsync failed"),
                }[outcome]
                with self.assertRaisesRegex(error, message):
                    asyncio.run(FIXTURE.run_scenario())
            self.assert_retention_archive(outcome, output, proof)
            self.assertEqual(resource_closed, [True])
            self.assertFalse(output.exists(), "failed stages must not produce PASS proof")
            self.assertTrue(all(not path.exists() for path in state_roots))
            stop.assert_called_once()
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def prepare_retention_stage(self, ctx, resources, outcome, state_roots, descriptors, resource_closed):
        state_roots.append(ctx.state_root)
        descriptors.extend((ctx.evidence.fd, ctx.evidence.directory_fd))
        with closing(sqlite3.connect(ctx.state / "ledger.sqlite")) as db:
            for create, insert in (
                ("CREATE TABLE attachments (evidence TEXT)", "INSERT INTO attachments VALUES (?)"),
                ("CREATE TABLE deliveries (evidence TEXT)", "INSERT INTO deliveries VALUES (?)"),
                ("CREATE TABLE attempts (evidence TEXT)", "INSERT INTO attempts VALUES (?)"),
            ):
                if outcome.startswith("partial") and "attachments" not in create:
                    continue
                db.execute(create)
                db.execute(insert, ("before-failure",))
            db.commit()

        def verify_archive_before_cleanup():
            records = [json.loads(line) for line in ctx.evidence_path.read_text().splitlines()]
            if outcome != "write-failure":
                self.assertTrue(any(row.get("kind") == "database" for row in records))
                FIXTURE.record_evidence(ctx, "lateProviderResponse", {"joined": True})
            resource_closed.append(True)
        resources.callback(verify_archive_before_cleanup)
        FIXTURE.record_evidence(ctx, "nativeExchange", {"outcome": {"status": "inputRecorded"}})
        if outcome == "stage-failure":
            raise RuntimeError("injected stage failure")
        if outcome == "partial-failure":
            raise ValueError("original partial ledger failure")
        if outcome == "write-failure":
            ctx.evidence.size = 64 * 1024 * 1024

    def assert_retention_archive(self, outcome, output, proof):
        archive = output.with_suffix(".private-evidence.jsonl")
        records = [json.loads(line) for line in archive.read_text().splitlines()]
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        if outcome != "write-failure":
            self.assertEqual({row["value"]["table"] for row in records if row["kind"] == "database"},
                             {"attachments"} if outcome.startswith("partial")
                             else {"attachments", "deliveries", "attempts"})
        if outcome.startswith("partial"):
            self.assertEqual({row["value"]["table"] for row in records
                              if row["kind"] == "missingLedgerTable"}, {"deliveries", "attempts"})
        if outcome == "success":
            self.assertEqual(proof["privateEvidence"]["sha256"], FIXTURE.digest(archive.read_bytes()))
            self.assertEqual(proof["privateEvidence"]["bytes"], archive.stat().st_size)
            self.assertEqual(records[-1]["kind"], "lateProviderResponse")
            self.assertIn("exit:c3", [row["value"] for row in records if row["kind"] == "checkpoint"])
        self.assertTrue(any(row["kind"] == "nativeExchange" for row in records))
        self.assertTrue(any(row["kind"] == "cloudFixture" for row in records))

    def test_archive_bound_and_replacement_refuse_without_overwriting_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            with FIXTURE.evidence_archive(path) as evidence:
                original = path.read_bytes()
                ctx = SimpleNamespace(evidence=evidence)
                evidence.size = 64 * 1024 * 1024
                with self.assertRaisesRegex(AssertionError, "bounded archive"):
                    FIXTURE.record_evidence(ctx, "new", {})
                self.assertEqual(path.read_bytes(), original)
                evidence.size = 0
                with self.assertRaisesRegex(AssertionError, "evidence changed"):
                    FIXTURE.record_evidence(ctx, "new", {})
                self.assertEqual(path.read_bytes(), original)

    def test_fifth_start_refuses_before_forwarding_to_native(self):
        forward = Mock()
        ctx = SimpleNamespace(session_labels={"session": "C"}, start_calls={"A": [{}], "B": [{}], "C": [{}, {}]},
                              original_session_request=forward,
                              evidence=SimpleNamespace(lock=threading.Condition(), closing=False, sealed=False))
        with self.assertRaisesRegex(AssertionError, "four native Start attempt cap"):
            FIXTURE.observe_session_request(ctx, None, "session", {"command": "nativeStart"})
        forward.assert_not_called()


    def observer_context(self, evidence, forward):
        return SimpleNamespace(evidence=evidence, original_session_request=forward,
                               session_labels={"session": "C"}, start_calls={"A": [], "B": [], "C": []},
                               challenge_calls={"C": 0}, receipt_errors={"C": []}, receipt_calls={"C": []})

    def test_same_size_replacement_and_hardlink_never_receive_records_or_seal(self):
        for replacement in ("same-size", "hardlink", "mode"):
            with self.subTest(replacement=replacement), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "evidence.jsonl"
                with FIXTURE.evidence_archive(path) as evidence:
                    ctx = SimpleNamespace(evidence=evidence)
                    original = path.read_bytes()
                    if replacement == "same-size":
                        path.rename(path.with_suffix(".original"))
                        path.write_bytes(b"x" * len(original))
                        path.chmod(0o600)
                    elif replacement == "hardlink":
                        os.link(path, path.with_suffix(".link"))
                    else:
                        path.chmod(0o644)
                    before = path.read_bytes()
                    with self.assertRaisesRegex(AssertionError, "evidence changed"):
                        FIXTURE.record_evidence(ctx, "must-not-write", {})
                    self.assertEqual(path.read_bytes(), before)
                    evidence.drained = True
                    with self.assertRaises(AssertionError):
                        FIXTURE.seal_evidence(ctx)
                with self.assertRaises(OSError):
                    os.fstat(evidence.fd)

    def test_concurrent_fourth_and_fifth_start_reserve_once_even_when_forward_fails(self):
        with tempfile.TemporaryDirectory() as directory, FIXTURE.evidence_archive(Path(directory) / "evidence") as evidence:
            entered, release = threading.Event(), threading.Event()
            barrier = threading.Barrier(2)

            def forward(*args, **kwargs):
                entered.set()
                self.assertTrue(release.wait(5))
                raise OSError("ambiguous native outcome")

            ctx = self.observer_context(evidence, Mock(side_effect=forward))
            ctx.start_calls = {"A": [{}], "B": [{}], "C": [{}]}

            def attempt():
                barrier.wait(5)
                try:
                    FIXTURE.observe_session_request(ctx, None, "session", {"command": "nativeStart"})
                except (OSError, AssertionError) as error:
                    return str(error)

            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(attempt) for _ in range(2)]
                try:
                    self.assertTrue(entered.wait(5))
                finally:
                    release.set()
                outcomes = [future.result(5) for future in futures]
            self.assertEqual(ctx.original_session_request.call_count, 1)
            self.assertEqual(sum(map(len, ctx.start_calls.values())), 4)
            self.assertIn("ambiguous native outcome", outcomes)
            self.assertIn("four native Start attempt cap exhausted", outcomes)
            self.assertEqual(evidence.active, 0)

    def test_cancelled_to_thread_finishes_before_seal_and_new_operations_refuse(self):
        with tempfile.TemporaryDirectory() as directory, FIXTURE.evidence_archive(Path(directory) / "evidence") as evidence:
            entered, release = threading.Event(), threading.Event()
            outer_finished = threading.Event()

            def forward(*args, **kwargs):
                entered.set()
                self.assertTrue(release.wait(5))
                return {"outcome": {"status": "inputRecorded"}}

            ctx = self.observer_context(evidence, Mock(side_effect=forward))

            def outer_observer():
                FIXTURE.observe_session_request(ctx, None, "session", {"command": "nativeReceipt"})
                FIXTURE.record_evidence(ctx, "outerObserverFinished", {})
                outer_finished.set()

            async def scenario():
                asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=1))
                worker = asyncio.create_task(asyncio.to_thread(outer_observer))
                while not entered.is_set():
                    await asyncio.sleep(0)
                queued = asyncio.create_task(asyncio.to_thread(
                    FIXTURE.observe_session_request, ctx, None, "session", {"command": "nativeStart"}))
                await asyncio.sleep(0)
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)
                drain = asyncio.create_task(FIXTURE.drain_native_observers(ctx))
                await asyncio.sleep(0)
                self.assertFalse(drain.done())
                with self.assertRaisesRegex(AssertionError, "observers are closed"):
                    FIXTURE.observe_session_request(ctx, None, "session", {"command": "nativeStart"})
                release.set()
                await drain
                queued_result, = await asyncio.gather(queued, return_exceptions=True)
                self.assertIsInstance(queued_result, AssertionError)
                self.assertIn("observers are closed", str(queued_result))
                self.assertTrue(outer_finished.is_set())
                sealed = FIXTURE.seal_evidence(ctx)
                self.assertEqual(sealed["sha256"], FIXTURE.digest(evidence.path.read_bytes()))
                with self.assertRaisesRegex(AssertionError, "sealed"):
                    FIXTURE.record_evidence(ctx, "late", {})

            try:
                asyncio.run(scenario())
            finally:
                release.set()
            self.assertEqual(ctx.original_session_request.call_count, 1)
            records = [json.loads(line) for line in evidence.path.read_text().splitlines()]
            self.assertEqual(records[-1]["kind"], "outerObserverFinished")

    def test_fsync_file_then_parent_precedes_hash_and_failure_closes_descriptor(self):
        for failing_call in (None, 1, 2):
            with self.subTest(failing_call=failing_call), tempfile.TemporaryDirectory() as directory:
                calls = []
                real_fsync, real_read = os.fsync, os.read
                with FIXTURE.evidence_archive(Path(directory) / "evidence") as evidence:
                    ctx = SimpleNamespace(evidence=evidence)
                    evidence.drained = True

                    def sync(fd):
                        calls.append("file" if fd == evidence.fd else "parent")
                        if len(calls) == failing_call:
                            raise OSError("fsync failed")
                        real_fsync(fd)

                    def read(fd, size):
                        calls.append("hash-read")
                        return real_read(fd, size)

                    with patch.object(FIXTURE.os, "fsync", side_effect=sync), \
                            patch.object(FIXTURE.os, "read", side_effect=read):
                        if failing_call:
                            with self.assertRaisesRegex(OSError, "fsync failed"):
                                FIXTURE.seal_evidence(ctx)
                            self.assertNotIn("hash-read", calls)
                        else:
                            proof = FIXTURE.seal_evidence(ctx)
                            self.assertEqual(calls[:3], ["file", "parent", "hash-read"])
                            self.assertEqual(proof["bytes"], evidence.path.stat().st_size)
                with self.assertRaises(OSError):
                    os.fstat(evidence.fd)


    def test_broker_setup_failure_closes_both_archive_descriptors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_close = os.close
            with patch.object(FIXTURE, "args", SimpleNamespace(output=str(root / "proof.json"), outer_contained=False)), \
                    patch.object(FIXTURE, "private_temp_root", return_value=root), \
                    patch.object(FIXTURE, "start_broker", side_effect=RuntimeError("broker failed")), \
                    patch.object(FIXTURE.os, "close", wraps=real_close) as close:
                with self.assertRaisesRegex(RuntimeError, "broker failed"):
                    asyncio.run(FIXTURE.run_scenario())
            self.assertEqual(close.call_count, 2)
            for call in close.call_args_list:
                with self.assertRaises(OSError):
                    os.fstat(call.args[0])


    def test_provider_last_record_is_synced_before_native_scratch_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with FIXTURE.evidence_archive(root / "evidence") as evidence:
                ctx = SimpleNamespace(evidence=evidence)
                order = []
                real_sync = FIXTURE.sync_evidence

                def model(stack, **kwargs):
                    def finish():
                        FIXTURE.record_evidence(ctx, "providerLastResponse", {})
                        order.append("provider-joined")
                    stack.callback(finish)
                    return SimpleNamespace()

                def sync(context):
                    self.assertTrue(list(root.glob("three-native-*")))
                    real_sync(context)
                    order.append("durable")

                with patch.object(FIXTURE, "private_temp_root", return_value=root), \
                        patch.object(FIXTURE, "make_model", side_effect=model), \
                        patch.object(FIXTURE, "host_qualifier", SimpleNamespace(
                            source_program=Mock(side_effect=RuntimeError("setup failure")))), \
                        patch.object(FIXTURE, "sync_evidence", side_effect=sync):
                    with self.assertRaisesRegex(RuntimeError, "setup failure"), ExitStack() as resources:
                        FIXTURE.native_session(resources, "C", ctx)
                self.assertEqual(order, ["provider-joined", "durable"])
                self.assertFalse(list(root.glob("three-native-*")))
