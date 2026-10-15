"""Fail-closed boundaries for the disposable three-session acceptance fixture."""

import copy
import asyncio
from contextlib import ExitStack, closing, contextmanager
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import io
import json
from itertools import product
import os
from pathlib import Path
import signal
import socket
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

    def test_provider_failure_is_archived_before_scratch_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence"
            with FIXTURE.evidence_archive(path) as evidence:
                server = self.provider()
                ctx = SimpleNamespace(evidence=evidence)
                server.evidence = lambda kind, value: FIXTURE.record_evidence(ctx, kind, {"session": "C", **value})
                server.qualifier.request_kind = Mock(side_effect=ValueError("bad request " + "x" * 500))
                handler = self.respond(server, {})
                handler.send_error.assert_called_once_with(500)
                records = [json.loads(line) for line in path.read_text().splitlines()]
                self.assertEqual(records[-1]["kind"], "providerError")
                self.assertEqual(records[-1]["value"], {"session": "C", **server.errors[0]})
                self.assertEqual(len(records[-1]["value"]["message"]), 160)
                self.assertEqual(records[-1]["value"]["type"], "ValueError")
                self.assertEqual(records[-1]["value"]["phase"], "initial")

    def test_stalled_model_socket_io_times_out_and_joins_before_sealing(self):
        for stall in ("upload", "download"):
            with self.subTest(stall=stall), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "evidence"
                with FIXTURE.evidence_archive(path) as evidence, ExitStack() as resources:
                    ctx = SimpleNamespace(evidence=evidence)
                    with patch.object(FIXTURE, "host_qualifier", self.provider().qualifier), \
                            patch.object(FIXTURE.ModelProvider, "timeout", 0.15):
                        server = FIXTURE.make_model(resources)
                        server.handle_error = Mock()
                        server.evidence = lambda kind, value: FIXTURE.record_evidence(ctx, kind, value)
                        server.program = "x" * 3_000_000
                        client = socket.socket()
                        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                        client.settimeout(2)
                        client.connect(("127.0.0.1", server.server_port))
                        raw = json.dumps({"tools": [{"name": "exec"}]}).encode()
                        size = len(raw) + 1 if stall == "upload" else len(raw)
                        client.sendall(b"POST /v1/responses HTTP/1.0\r\nContent-Length: "
                                       + str(size).encode() + b"\r\n\r\n" + raw)
                        deadline = time.monotonic() + 2
                        while not server.active_requests and time.monotonic() < deadline:
                            time.sleep(0.01)
                        while not server.errors and time.monotonic() < deadline:
                            time.sleep(0.01)
                        errors = []

                        def close():
                            try:
                                resources.close()
                            except Exception as error:
                                errors.append(error)

                        cleanup = threading.Thread(target=close, daemon=True)
                        cleanup.start()
                        cleanup.join(3)
                        bounded = not cleanup.is_alive()
                        client.close()
                        cleanup.join(3)
                        self.assertTrue(bounded, "provider shutdown waited for the stalled client")
                        self.assertFalse(cleanup.is_alive())
                        self.assertEqual(errors, [])
                        self.assertEqual(server.active_requests, 0)
                    records = [json.loads(line) for line in path.read_text().splitlines()]
                    self.assertTrue(any(row["kind"] == "providerError" and row["value"]["type"] == "TimeoutError"
                                        for row in records))
                    evidence.drained = True
                    sealed = FIXTURE.seal_evidence(ctx)
                    self.assertEqual(sealed["sha256"], FIXTURE.digest(path.read_bytes()))

    def test_model_shutdown_closes_header_body_and_response_stalls_before_join(self):
        for stall in ("header", "body", "response", "busy-hold"):
            with self.subTest(stall=stall), tempfile.TemporaryDirectory() as directory:
                with FIXTURE.evidence_archive(Path(directory) / "evidence") as evidence, ExitStack() as resources:
                    ctx = SimpleNamespace(evidence=evidence)
                    with patch.object(FIXTURE, "host_qualifier", self.provider().qualifier), \
                            patch.object(FIXTURE.ModelProvider, "timeout", 30):
                        server = FIXTURE.make_model(resources, hold=stall == "busy-hold")
                        server.handle_error = Mock()
                        server.evidence = lambda kind, value: FIXTURE.record_evidence(ctx, kind, value)
                        server.program = "x" * 3_000_000
                        client = socket.socket()
                        client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                        client.settimeout(2)
                        client.connect(("127.0.0.1", server.server_port))
                        raw = json.dumps({"tools": [{"name": "exec"}]}).encode()
                        request = (b"POST /v1/responses HTTP/1.0\r\nContent-Length: "
                                   + str(3_999_999 if stall == "body" else len(raw)).encode() + b"\r\n\r\n" + raw)
                        client.sendall(b"POST /v1/responses HTTP/1.0\r\nX-Stall: " if stall == "header" else request)
                        deadline = time.monotonic() + 2
                        while not server.connections and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertTrue(server.connections)
                        if stall == "busy-hold":
                            self.assertTrue(server.hold_started.wait(2))
                            self.assertFalse(server.release_hold.is_set())
                        trickle_stop = threading.Event()
                        trickle = threading.Thread(target=self.trickle_model_request,
                                                   args=(client, trickle_stop), daemon=True)
                        if stall in ("header", "body"):
                            trickle.start()
                        try:
                            self.assert_model_cleanup_bounded(resources, client, server)
                        finally:
                            trickle_stop.set()
                            if trickle.ident is not None:
                                trickle.join(2)
                    self.assertEqual(server.connections, set())
                    self.assertEqual(server.active_requests, 0)
                    evidence.drained = True
                    FIXTURE.seal_evidence(ctx)

    def trickle_model_request(self, client, stop):
        while not stop.wait(0.02):
            try:
                client.sendall(b" ")
            except OSError:
                return

    def test_model_shutdown_closes_connection_before_handler_starts(self):
        with ExitStack() as resources, patch.object(FIXTURE, "host_qualifier", self.provider().qualifier):
            server = FIXTURE.make_model(resources)
            server.handle_error = Mock()
            accepted, release = threading.Event(), threading.Event()
            original = server.finish_request

            def delayed(request, address):
                accepted.set()
                release.wait(3)
                original(request, address)

            server.finish_request = delayed
            client = socket.create_connection(("127.0.0.1", server.server_port), timeout=2)
            cleanup = threading.Thread(target=resources.close, daemon=True)
            try:
                self.assertTrue(accepted.wait(2))
                cleanup.start()
                self.assertEqual(client.recv(1), b"")
                self.assertTrue(cleanup.is_alive(), "cleanup must still join the delayed handler")
            finally:
                release.set()
                client.close()
                if cleanup.ident is not None:
                    cleanup.join(3)
            self.assertFalse(cleanup.is_alive())
            self.assertEqual(server.connections, set())

    def assert_model_cleanup_bounded(self, resources, client, server):
        errors = []

        def close():
            try:
                resources.close()
            except Exception as error:
                errors.append(error)

        cleanup = threading.Thread(target=close, daemon=True)
        cleanup.start()
        cleanup.join(3)
        bounded = not cleanup.is_alive()
        client.close()
        cleanup.join(3)
        self.assertTrue(bounded, "provider shutdown waited for client I/O or busy hold")
        self.assertFalse(cleanup.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(server.active_requests, 0)

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
                patch.object(FIXTURE, 'ModelServer', side_effect=lambda *_: SimpleNamespace(serve_forever=Mock())), \
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


class ThreeSessionArtifactFailureTests(unittest.TestCase):
    def test_attach_diagnostic_failure_preserves_original_attach_error(self):
        original = RuntimeError("attach failed")
        sessions = [{"sessionId": str(uuid4()), "initiallySelectedIdle": True,
                     "binding": {"clientId": str(uuid4()), "threadId": str(uuid4())}} for _ in range(3)]
        with tempfile.TemporaryDirectory() as directory, \
                FIXTURE.evidence_archive(Path(directory) / "evidence.jsonl") as evidence:
            evidence.size = 64 * 1024 * 1024
            ctx = SimpleNamespace(sessions={}, session_labels={}, admission_cloud=Mock(), evidence=evidence)
            ctx.fixture = lambda path: FIXTURE.fixture(ctx, path)
            with patch.object(FIXTURE, "native_session", side_effect=sessions), \
                    patch.object(FIXTURE, "admit_runtime", AsyncMock(side_effect=original)), \
                    patch.object(FIXTURE, "post") as post:
                with self.assertRaises(Exception) as caught:
                    asyncio.run(FIXTURE.initialize_runtime(ctx, Mock()))
                self.assertIs(caught.exception, original)
                self.assertTrue(evidence.failed)
                post.assert_not_called()

    def test_private_json_detects_postwrite_mutation(self):
        for mutation in ("replace", "hardlink", "overwrite", "mode"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory, ExitStack() as resources:
                path = Path(directory) / "causal.json"
                directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                resources.callback(os.close, directory_fd)
                original_fdopen = os.fdopen

                @contextmanager
                def fdopen(fd, *args, **kwargs):
                    with original_fdopen(fd, *args, **kwargs) as stream:
                        yield stream
                        stream.flush()
                        if mutation == "replace":
                            path.rename(path.with_suffix(".original"))
                            path.write_bytes(b"replacement")
                        elif mutation == "hardlink":
                            os.link(path, path.with_suffix(".link"))
                        elif mutation == "overwrite":
                            path.write_bytes(b"X" * path.stat().st_size)
                        else:
                            path.chmod(0o644)

                with patch.object(FIXTURE.os, "fdopen", side_effect=fdopen):
                    with self.assertRaises((AssertionError, OSError)):
                        FIXTURE.private_json(path, {"nonce": "private"}, directory_fd=directory_fd)

    def test_retained_private_json_wrapper_failure_closes_owned_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "causal.json"
            failure = OSError("wrapper unavailable")
            descriptors = []

            def fdopen(fd, *_args, **_kwargs):
                descriptors.append(fd)
                raise failure

            with patch.object(FIXTURE.os, "fdopen", side_effect=fdopen):
                with self.assertRaises(OSError) as caught, ExitStack() as publication:
                    FIXTURE.private_json(path, {}, publication_stack=publication)
            self.assertIs(caught.exception, failure)
            for fd in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_causal_sidecar_stays_pinned_until_pass(self):
        for mutation in ("rename", "replace", "disappear", "bytes", "mode", "hardlink", "parent-mode", None):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target, sidecar = root / "proof.json", root / "proof.private-causal.json"
                descriptors = []
                original_open = os.open

                async def scenario(directory_fd, publication_stack):
                    evidence = publication_stack.enter_context(FIXTURE.evidence_archive(
                        target.with_suffix(".private-evidence.jsonl"), directory_fd))
                    evidence.drained = True
                    proof = {"privateEvidence": FIXTURE.seal_evidence(SimpleNamespace(evidence=evidence))}
                    # Exercise the real scenario cleanup path that publishes the sidecar.
                    state = root / "state"
                    state.mkdir()
                    ctx = SimpleNamespace(evidence=evidence, broker=None, broker_log=None, proof=proof,
                                          private_nonce_record={"nonReuse": True}, state_root=state,
                                          args=SimpleNamespace(output=str(target)), publication_stack=publication_stack)
                    with patch.object(FIXTURE, "stop_broker", return_value={}):
                        FIXTURE.finish_scenario_cleanup(ctx)
                    return proof, evidence

                def opened(path, *args, **kwargs):
                    if path == target.name:
                        if mutation in ("rename", "replace"):
                            sidecar.rename(root / "owned-sidecar")
                        if mutation == "replace":
                            sidecar.write_bytes(b'{"nonReuse":true}\n')
                            sidecar.chmod(0o600)
                        elif mutation == "disappear":
                            sidecar.unlink()
                        elif mutation == "bytes":
                            sidecar.write_bytes(b"x" * sidecar.stat().st_size)
                        elif mutation == "mode":
                            sidecar.chmod(0o644)
                        elif mutation == "hardlink":
                            os.link(sidecar, root / "sidecar-link")
                        elif mutation == "parent-mode":
                            root.chmod(0o755)
                    fd = original_open(path, *args, **kwargs)
                    descriptors.append(fd)
                    return fd

                with patch.object(FIXTURE, "cli", return_value=SimpleNamespace(output=str(target))), \
                        patch.object(FIXTURE, "configure"), \
                        patch.object(FIXTURE, "run_scenario", side_effect=scenario), \
                        patch.object(FIXTURE.os, "open", side_effect=opened), patch("builtins.print") as output:
                    if mutation is not None:
                        with self.assertRaises((AssertionError, OSError)):
                            FIXTURE.main()
                        output.assert_not_called()
                        self.assertFalse(target.exists())
                    else:
                        FIXTURE.main()
                        self.assertEqual(json.loads(output.call_args.args[0])["result"], "PASS")
                if mutation == "replace":
                    self.assertEqual(sidecar.read_bytes(), b'{"nonReuse":true}\n')
                for fd in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(fd)

    def test_proof_fdopen_failure_closes_descriptor_and_removes_owned_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "proof.json"
            descriptors = []
            failure = OSError("fdopen failed")

            async def scenario(directory_fd, publication_stack):
                evidence = publication_stack.enter_context(FIXTURE.evidence_archive(
                    target.with_suffix(".private-evidence.jsonl"), directory_fd))
                evidence.drained = True
                return {"privateEvidence": FIXTURE.seal_evidence(SimpleNamespace(evidence=evidence))}, evidence

            def fdopen(fd, *_args, **_kwargs):
                descriptors.append(fd)
                raise failure

            with patch.object(FIXTURE, "cli", return_value=SimpleNamespace(output=str(target))), \
                    patch.object(FIXTURE, "configure"), \
                    patch.object(FIXTURE, "run_scenario", side_effect=scenario), \
                    patch.object(FIXTURE.os, "fdopen", side_effect=fdopen), patch("builtins.print") as output:
                with self.assertRaises(OSError) as caught:
                    FIXTURE.main()
                self.assertIs(caught.exception, failure)
                output.assert_not_called()
            self.assertFalse(target.exists())
            for fd in descriptors:
                try:
                    with self.assertRaises(OSError):
                        os.fstat(fd)
                finally:
                    try:
                        os.close(fd)
                    except OSError:
                        pass


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

    def test_output_directory_must_be_private_and_owned_before_subprocess(self):
        for mode, foreign_owner in ((0o755, False), (0o770, False), (0o700, True)):
            with self.subTest(mode=mode, foreign_owner=foreign_owner), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parsed, _, _ = self.inputs(root)
                root.chmod(mode)
                actual_uid = os.getuid()
                with patch.object(FIXTURE.os, "getuid", return_value=actual_uid + int(foreign_owner)), \
                        patch.object(FIXTURE, "load_module") as load, \
                        patch.object(FIXTURE.subprocess, "run") as run, \
                        patch.object(FIXTURE.subprocess, "Popen") as popen:
                    with self.assertRaisesRegex(AssertionError, "owned mode 0700"):
                        FIXTURE.configure(parsed)
                    load.assert_not_called()
                    run.assert_not_called()
                    popen.assert_not_called()

    def test_evidence_suffix_output_has_distinct_archive_checked_before_subprocess(self):
        for name in ("proof.private-evidence.jsonl", ".private-evidence.jsonl"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                parsed, _, _ = self.inputs(root)
                output = root / name
                parsed.output = str(output)
                archive = output.with_suffix(".private-evidence.jsonl")
                sidecar = output.with_name(output.stem + ".private-causal.json")
                self.assertEqual(len({output, archive, sidecar}), 3)
                self.assertEqual(archive.name, output.stem + ".private-evidence.jsonl")
                with patch.object(FIXTURE, "load_module", side_effect=RuntimeError("past output validation")):
                    with self.assertRaisesRegex(RuntimeError, "past output validation"):
                        FIXTURE.configure(parsed)
                self.assertFalse(any(path.exists() for path in (output, archive, sidecar)))
                archive.write_bytes(b"prior evidence")
                with patch.object(FIXTURE, "load_module") as load, \
                        patch.object(FIXTURE.subprocess, "run") as run, \
                        patch.object(FIXTURE.subprocess, "Popen") as popen:
                    with self.assertRaisesRegex(AssertionError, "private evidence must be new"):
                        FIXTURE.configure(parsed)
                    load.assert_not_called()
                    run.assert_not_called()
                    popen.assert_not_called()
                self.assertEqual(archive.read_bytes(), b"prior evidence")
                self.assertFalse(output.exists())

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
    def test_direct_fixture_transport_failure_retains_sanitized_attempt_and_original_error(self):
        for archive_fails in (False, True):
            with self.subTest(archive_fails=archive_fails), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "evidence"
                with FIXTURE.evidence_archive(path) as evidence:
                    ctx = SimpleNamespace(evidence=evidence, address={"port": 12345}, fixture_secret=uuid4().hex)
                    failure = TimeoutError("transport failed with PRIVATE contents")

                    def post(*args):
                        records = [json.loads(line) for line in path.read_text().splitlines()]
                        self.assertEqual(records[-1], {"kind": "cloudFixtureAttempt", "value": {"path": "/fixture/setup"}})
                        if archive_fails:
                            evidence.size = 64 * 1024 * 1024
                        raise failure

                    with patch.object(FIXTURE, "post", side_effect=post):
                        with self.assertRaises(TimeoutError) as raised:
                            FIXTURE.fixture(ctx, "/fixture/setup", {"transportPrivateKey": "PRIVATE"})
                    self.assertIs(raised.exception, failure)
                    self.assertNotIn("PRIVATE", path.read_text())
                    self.assertNotIn("transportPrivateKey", path.read_text())
                    if archive_fails:
                        self.assertTrue(evidence.failed)
                        evidence.drained = True
                        with self.assertRaisesRegex(AssertionError, "observers are not settled"):
                            FIXTURE.seal_evidence(ctx)
                    else:
                        records = [json.loads(line) for line in path.read_text().splitlines()]
                        self.assertEqual(records[-1], {"kind": "cloudFixtureError", "value": {
                            "path": "/fixture/setup", "error": "TimeoutError"}})

    def test_fixture_archives_failure_responses_without_request_secrets(self):
        for status, raw, error in ((503, b"unavailable\xff", AssertionError),
                                   (200, b"not json", json.JSONDecodeError)):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "evidence"
                with FIXTURE.evidence_archive(path) as evidence:
                    ctx = SimpleNamespace(evidence=evidence, address={"port": 12345}, fixture_secret=uuid4().hex)
                    with patch.object(FIXTURE, "post", return_value=(status, {}, raw)):
                        with self.assertRaises(error):
                            FIXTURE.fixture(ctx, "/fixture/setup", {"transportPrivateKey": "PRIVATE"})
                    records = [json.loads(line) for line in path.read_text().splitlines()]
                    self.assertEqual(records[-1], {"kind": "cloudFixture", "value": {
                        "path": "/fixture/setup", "status": status,
                        "response": raw.decode("utf-8", errors="replace"),
                    }})
                    self.assertNotIn("PRIVATE", path.read_text())
                    self.assertNotIn("transportPrivateKey", path.read_text())

    def test_native_error_survives_failed_archive_and_retains_receipt_bookkeeping(self):
        for failure_kind in ("bound", "sealed", "serialization"):
            with self.subTest(failure_kind=failure_kind), tempfile.TemporaryDirectory() as directory:
                with FIXTURE.evidence_archive(Path(directory) / "evidence") as evidence:
                    failure = RuntimeError("original native failure")

                    def native(*args, **kwargs):
                        if failure_kind == "bound":
                            evidence.size = 64 * 1024 * 1024
                        if failure_kind == "sealed":
                            evidence.sealed = True
                        raise failure

                    ctx = SimpleNamespace(evidence=evidence, session_labels={"session": "A"},
                                          receipt_errors={"A": []}, original_session_request=native)
                    request = {"unencodable": object()} if failure_kind == "serialization" else None
                    with self.assertRaises(RuntimeError) as raised:
                        FIXTURE.observe_session_request(ctx, None, "session", {"command": "nativeReceipt"},
                                                        native_request=request)
                    self.assertIs(raised.exception, failure)
                    self.assertEqual(ctx.receipt_errors["A"], [str(failure)])
                    self.assertEqual(evidence.active, 0)
                    self.assertTrue(evidence.failed)
                    evidence.drained = True
                    with self.assertRaisesRegex(AssertionError, "observers are not settled"):
                        FIXTURE.seal_evidence(ctx)


    def test_successful_native_receipt_survives_failed_archive_and_cannot_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            with FIXTURE.evidence_archive(Path(directory) / "evidence") as evidence:
                result = {"outcome": {"status": "inputRecorded"}}

                def native(*args, **kwargs):
                    evidence.size = 64 * 1024 * 1024
                    return result

                ctx = self.observer_context(evidence, native)
                diagnostic = io.StringIO()
                sinks = [diagnostic, Mock(write=Mock(side_effect=OSError("sink full"))),
                         Mock(write=Mock(side_effect=ValueError("sink closed")))]
                for sink in sinks:
                    with self.subTest(sink=type(sink).__name__), patch.object(FIXTURE.sys, "stderr", sink):
                        returned = FIXTURE.observe_session_request(ctx, None, "session", {"command": "nativeReceipt"})
                    self.assertIs(returned, result)
                self.assertEqual(diagnostic.getvalue(), "native exchange evidence unavailable: AssertionError\n")
                self.assertEqual(ctx.receipt_calls["C"], ["inputRecorded"] * 3)
                self.assertEqual(evidence.active, 0)
                self.assertTrue(evidence.failed)
                evidence.drained = True
                with self.assertRaisesRegex(AssertionError, "observers are not settled"):
                    FIXTURE.seal_evidence(ctx)

    def test_secondary_sidecar_assertion_preserves_active_error_and_owned_cleanup(self):
        for broker_fails in (False, True):
            with self.subTest(broker_fails=broker_fails), tempfile.TemporaryDirectory() as directory:
                state = Path(directory) / "state"
                state.mkdir()
                original = RuntimeError("original scenario failure")
                ctx = SimpleNamespace(broker=None, broker_log=None, proof=None, private_nonce_record={},
                                      state_root=state, args=SimpleNamespace(output=str(Path(directory) / "proof")),
                                      evidence=SimpleNamespace())
                with patch.object(FIXTURE, "stop_broker", side_effect=AssertionError("broker cleanup failed") if broker_fails else None, return_value={}), \
                        patch.object(FIXTURE, "verify_evidence", side_effect=AssertionError("directory changed")), \
                        patch("builtins.print") as diagnostic:
                    with self.assertRaises(RuntimeError) as raised:
                        try:
                            raise original
                        finally:
                            FIXTURE.finish_scenario_cleanup(ctx)
                self.assertIs(raised.exception, original)
                self.assertFalse(state.exists())
                self.assertEqual(diagnostic.call_count, 2 if broker_fails else 1)

    def test_parent_replacement_cleanup_removes_owned_state_and_preserves_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent, moved, state = root / "output", root / "original", root / "state"
            parent.mkdir()
            state.mkdir()
            (state / "private-key").write_text("private")
            with FIXTURE.evidence_archive(parent / "evidence") as evidence:
                ctx = SimpleNamespace(evidence=evidence, broker=None, broker_log=None, proof={},
                                      private_nonce_record={}, state_root=state,
                                      args=SimpleNamespace(output=str(parent / "proof.json")))
                parent.rename(moved)
                parent.mkdir()
                with patch.object(FIXTURE, "stop_broker", return_value={}):
                    with self.assertRaisesRegex(AssertionError, "private evidence directory changed"):
                        FIXTURE.finish_scenario_cleanup(ctx)
                self.assertFalse(state.exists())
                self.assertEqual(list(parent.iterdir()), [])

    def test_executor_deadline_retains_all_resources_until_real_worker_joins(self):
        self.run_retention_scenario("drain-timeout")


    def test_cleanup_sync_failure_preserves_original_error_and_removes_state(self):
        for failure_at in ("fixture", "drain", "none"):
            with self.subTest(failure_at=failure_at), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state = root / "state"
                state.mkdir()
                with FIXTURE.evidence_archive(root / "evidence") as evidence:
                    ctx = SimpleNamespace(evidence=evidence, daemon_task=None, sessions={},
                                          broker=None, broker_log=None, proof=None,
                                          private_nonce_record=None, state_root=state)
                    original = RuntimeError("original " + failure_at)
                    fsync_failure = OSError("fsync failed")
                    drain = AsyncMock(side_effect=original if failure_at == "drain" else None)

                    def fail_sync(fd):
                        drain.assert_awaited_once_with(ctx)
                        self.assertTrue(state.is_dir())
                        raise fsync_failure

                    async def scenario():
                        try:
                            if failure_at == "fixture":
                                raise original
                        finally:
                            await FIXTURE.cleanup_scenario(ctx)

                    with patch.object(FIXTURE, "drain_native_observers", drain), \
                            patch.object(FIXTURE, "restore_observers") as restore, \
                            patch.object(FIXTURE, "stop_broker", return_value={}) as stop, \
                            patch.object(FIXTURE.os, "fsync", side_effect=fail_sync), \
                            patch("builtins.print"):
                        with self.assertRaises((RuntimeError, OSError)) as raised:
                            asyncio.run(scenario())
                    self.assertIs(raised.exception, fsync_failure if failure_at == "none" else original)
                    restore.assert_called_once_with(ctx)
                    stop.assert_called_once()
                    self.assertFalse(state.exists())
                    self.assertTrue(evidence.failed)
                    evidence.drained = True
                    with self.assertRaisesRegex(AssertionError, "observers are not settled"):
                        FIXTURE.seal_evidence(ctx)

    def test_final_published_proof_size_is_checked_before_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "proof.json"
            proof = {"metadata": "x" * 32650}
            self.assertLess(len(json.dumps(proof).encode()), 32768)
            proof.update(privateEvidence={"sha256": "a" * 64, "bytes": 100},
                         brokerCleanup={"closed": True, "ports": [49732, 49733, 49734]})
            with patch.object(FIXTURE, "cli", return_value=SimpleNamespace(output=str(target))), \
                    patch.object(FIXTURE, "configure"), \
                    patch.object(FIXTURE, "run_scenario", AsyncMock(return_value=(proof, None))), \
                    patch("builtins.print") as output:
                with self.assertRaisesRegex(AssertionError, "proof exceeds fixed metadata bound"):
                    FIXTURE.main()
                self.assertFalse(target.exists())
                output.assert_not_called()

    def test_early_fixture_failure_flushes_archive_and_parent_before_close(self):
        for failed_path in ("/fixture/challenge", "/v1/nodes/complete"):
            with self.subTest(path=failed_path), tempfile.TemporaryDirectory() as directory, ExitStack() as patches:
                root = Path(directory)
                key = Mock()
                key.public_key.return_value.public_bytes_raw.return_value = b"key"
                key.sign.return_value = b"signature"
                for name, value in {
                    "args": SimpleNamespace(output=str(root / "proof.json"), outer_contained=False),
                    "private_key_type": SimpleNamespace(generate=lambda: key),
                    "launcher": Mock(), "Store": Mock(), "daemon": Mock(),
                    "SessionNativeBridge": Mock(), "client_runtime": Mock(), "CloudClient": Mock(),
                }.items():
                    patches.enter_context(patch.object(FIXTURE, name, value))
                patches.enter_context(patch.object(FIXTURE, "private_temp_root", return_value=root))
                patches.enter_context(patch.object(FIXTURE, "start_broker", return_value=(None, None, {"secret": uuid4().hex, "port": 12345})))
                stop = patches.enter_context(patch.object(FIXTURE, "stop_broker", return_value={}))

                def post(port, secret, path, body):
                    return (503 if path == failed_path else 200), {}, b'{"challengeId":"id","signingPayload":"payload"}'

                patches.enter_context(patch.object(FIXTURE, "post", side_effect=post))
                initialize = patches.enter_context(patch.object(FIXTURE, "initialize_runtime", AsyncMock()))
                real_fsync = os.fsync

                def sync_before_cleanup(fd):
                    self.assertEqual(bool(list(root.glob(FIXTURE.GATEWAY_TEMP_PREFIX + "*"))), not stop.called)
                    real_fsync(fd)

                sync = patches.enter_context(patch.object(FIXTURE.os, "fsync", side_effect=sync_before_cleanup))
                with self.assertRaisesRegex(AssertionError, "fixture rejected " + failed_path):
                    asyncio.run(FIXTURE.run_scenario())
                initialize.assert_not_called()
                stop.assert_called_once()
                self.assertEqual(sync.call_count, 4)
                for call in sync.call_args_list:
                    with self.assertRaises(OSError):
                        os.fstat(call.args[0])
                self.assertEqual([p.name for p in root.iterdir()], ["proof.private-evidence.jsonl"])
                records = [json.loads(line) for line in (root / "proof.private-evidence.jsonl").read_text().splitlines()]
                self.assertEqual(records[-1]["value"]["status"], 503)

    def test_transport_failure_is_archived_before_real_cloud_retry(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from event_gateway.cloud import CloudClient, Credentials

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            with FIXTURE.evidence_archive(path) as evidence:
                ctx = SimpleNamespace(evidence=evidence, address={"port": 12345},
                                      fixture_secret=uuid4().hex, wire_evidence=[])
                failure = TimeoutError("response lost after commit")
                calls = []

                def post(*args, **kwargs):
                    calls.append(args)
                    records = [json.loads(line) for line in path.read_text().splitlines()]
                    self.assertEqual(records[-1]["kind"], "cloudAttempt")
                    if len(calls) == 1:
                        raise failure
                    self.assertEqual([row["kind"] for row in records[-3:]],
                                     ["cloudAttempt", "cloudError", "cloudAttempt"])
                    self.assertEqual(records[-2]["value"]["error"], "TimeoutError")
                    return 200, {"content-type": "application/json"}, b'{"status":"attached"}'

                async def send(**request):
                    return await FIXTURE.send(ctx, **request)

                async def credentials():
                    return Credentials(uuid4().hex, uuid4().hex)

                client = CloudClient(origin=FIXTURE.ORIGIN, principal=FIXTURE.PRINCIPAL,
                                     agent=FIXTURE.AGENT, node_id=str(uuid4()), node_generation=1,
                                     private_key=Ed25519PrivateKey.generate(),
                                     credentials=credentials, send=send)
                with patch.object(FIXTURE, "post", side_effect=post):
                    result = asyncio.run(client._retry_native_commit(
                        "/v1/runtimes/attach", {}, b"{}", lambda *args, **kwargs: None, lambda value: value,
                    ))
                self.assertEqual(result, {"status": "attached"})
                self.assertEqual(len(calls), 2)
                records = [json.loads(line) for line in path.read_text().splitlines()]
                attempts = [row["value"] for row in records if row["kind"] == "cloudAttempt"]
                self.assertNotEqual(attempts[0]["proof"]["nonce"], attempts[1]["proof"]["nonce"])
                self.assertEqual(attempts[0]["request"], attempts[1]["request"])

    def test_transport_error_survives_failed_error_record_and_archive_cannot_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            with FIXTURE.evidence_archive(Path(directory) / "evidence") as evidence:
                ctx = SimpleNamespace(evidence=evidence, address={"port": 12345},
                                      fixture_secret=uuid4().hex, wire_evidence=[])
                failure = TimeoutError("original transport error")

                def fail(*args, **kwargs):
                    evidence.size = 64 * 1024 * 1024
                    raise failure

                with patch.object(FIXTURE, "post", side_effect=fail):
                    with self.assertRaises(TimeoutError) as raised:
                        asyncio.run(FIXTURE.send(
                            ctx, method="POST", url=FIXTURE.ORIGIN + "/v1/runtimes/attach",
                            timeout=5, max_response_bytes=8192, follow_redirects=False,
                            body=b"{}", headers={"x-event-node-proof": '{"nonce":"nonce"}'},
                        ))
                self.assertIs(raised.exception, failure)
                self.assertTrue(evidence.failed)
                evidence.drained = True
                with self.assertRaisesRegex(AssertionError, "observers are not settled"):
                    FIXTURE.seal_evidence(ctx)

    def mutate_publication_archive(self, mutation, root, target, archive):
        raw = archive.read_bytes()
        if mutation in ("rename", "replace"):
            archive.rename(root / "original")
        if mutation == "recreate":
            archive.unlink()
        if mutation in ("replace", "recreate"):
            archive.write_bytes(raw)
            archive.chmod(0o600)
        if mutation in ("overwrite", "proof-replaced"):
            archive.write_bytes(raw.replace(b"archive", b"ARCHIVE"))
        if mutation == "proof-replaced" and target.exists():
            target.rename(root / "owned-proof")
            target.write_text("replacement proof")

    def test_archive_remains_bound_through_proof_publication_and_descriptors_close(self):
        mutations = ("rename", "replace", "recreate", "overwrite", "proof-replaced", "scenario-error", None)
        for mutation, phase in product(mutations, ("proof-open", "proof-fsync")):
            with self.subTest(mutation=mutation, phase=phase), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target, archive = root / "proof.json", root / "proof.private-evidence.jsonl"
                descriptors = []
                real_open, real_fsync = os.open, os.fsync
                changed = False

                async def scenario(directory_fd, publication_stack):
                    evidence = publication_stack.enter_context(FIXTURE.evidence_archive(archive, directory_fd))
                    descriptors.extend((directory_fd, evidence.fd, evidence.directory_fd))
                    evidence.drained = True
                    proof = {"privateEvidence": FIXTURE.seal_evidence(SimpleNamespace(evidence=evidence))}
                    evidence.causal = FIXTURE.private_json(target.with_name("proof.private-causal.json"), {},
                                                            directory_fd=directory_fd,
                                                            publication_stack=publication_stack)
                    if mutation == "scenario-error":
                        raise RuntimeError("scenario failed")
                    return proof, evidence

                def mutate():
                    nonlocal changed
                    if changed or mutation is None:
                        return
                    changed = True
                    self.mutate_publication_archive(mutation, root, target, archive)

                proof_fd = None

                def open_proof(path, *args, **kwargs):
                    nonlocal proof_fd
                    if path == target.name and kwargs.get("dir_fd") is not None:
                        for fd in descriptors:
                            os.fstat(fd)
                        if phase == "proof-open":
                            mutate()
                        proof_fd = real_open(path, *args, **kwargs)
                        return proof_fd
                    return real_open(path, *args, **kwargs)

                def sync(fd):
                    if fd == proof_fd and phase == "proof-fsync":
                        mutate()
                    real_fsync(fd)

                with patch.object(FIXTURE, "cli", return_value=SimpleNamespace(output=str(target))), \
                        patch.object(FIXTURE, "configure"), \
                        patch.object(FIXTURE, "run_scenario", side_effect=scenario), \
                        patch.object(FIXTURE.os, "open", side_effect=open_proof), \
                        patch.object(FIXTURE.os, "fsync", side_effect=sync), \
                        patch("builtins.print") as output:
                    if mutation:
                        with self.assertRaises((AssertionError, OSError, RuntimeError)):
                            FIXTURE.main()
                        output.assert_not_called()
                        if mutation == "proof-replaced" and phase == "proof-fsync":
                            self.assertEqual(target.read_text(), "replacement proof")
                        else:
                            self.assertFalse(target.exists())
                    else:
                        FIXTURE.main()
                        self.assertEqual(json.loads(output.call_args.args[0])["result"], "PASS")
                for fd in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(fd)

    def test_proof_only_mutation_refuses_pass_and_preserves_unknown_replacement(self):
        for mutation in ("rename", "replace", "overwrite", None):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target, archive = root / "proof.json", root / "proof.private-evidence.jsonl"
                descriptors = []
                real_fsync = os.fsync
                mutated = False
                removal_synced = []
                original_archive = None
                removed = False
                real_unlink = os.unlink

                def unlink(path, *args, **kwargs):
                    nonlocal removed
                    result = real_unlink(path, *args, **kwargs)
                    if path == target.name and kwargs.get("dir_fd") == descriptors[0]:
                        removed = True
                    return result

                async def scenario(directory_fd, publication_stack):
                    nonlocal original_archive
                    evidence = publication_stack.enter_context(FIXTURE.evidence_archive(archive, directory_fd))
                    descriptors.extend((directory_fd, evidence.fd, evidence.directory_fd))
                    evidence.drained = True
                    proof = {"privateEvidence": FIXTURE.seal_evidence(SimpleNamespace(evidence=evidence))}
                    evidence.causal = FIXTURE.private_json(target.with_name("proof.private-causal.json"), {},
                                                            directory_fd=directory_fd,
                                                            publication_stack=publication_stack)
                    original_archive = archive.read_bytes()
                    return proof, evidence

                def sync(fd):
                    nonlocal mutated
                    if descriptors and fd == descriptors[0] and target.exists() and not mutated:
                        mutated = True
                        raw = target.read_bytes()
                        if mutation in ("rename", "replace"):
                            target.rename(root / "original-proof")
                        if mutation == "replace":
                            target.write_bytes(raw)
                            target.chmod(0o600)
                        if mutation == "overwrite":
                            target.write_bytes(raw.replace(b"sha256", b"SHA256"))
                    if removed and fd == descriptors[0]:
                        removal_synced.append(True)
                    real_fsync(fd)

                real_fdopen = os.fdopen

                def fdopen(fd, *args, **kwargs):
                    descriptors.append(fd)
                    return real_fdopen(fd, *args, **kwargs)

                with patch.object(FIXTURE, "cli", return_value=SimpleNamespace(output=str(target))), \
                        patch.object(FIXTURE, "configure"), \
                        patch.object(FIXTURE, "run_scenario", side_effect=scenario), \
                        patch.object(FIXTURE.os, "fsync", side_effect=sync), \
                        patch.object(FIXTURE.os, "unlink", side_effect=unlink), \
                        patch.object(FIXTURE.os, "fdopen", side_effect=fdopen), \
                        patch("builtins.print") as output:
                    if mutation:
                        with self.assertRaises((AssertionError, OSError)):
                            FIXTURE.main()
                        output.assert_not_called()
                        self.assertEqual(target.exists(), mutation == "replace")
                    else:
                        FIXTURE.main()
                        self.assertEqual(json.loads(output.call_args.args[0])["result"], "PASS")
                self.assertEqual(archive.read_bytes(), original_archive)
                self.assertEqual(bool(removal_synced), mutation == "overwrite")
                for fd in descriptors:
                    with self.assertRaises(OSError):
                        os.fstat(fd)

    def test_proof_parent_replacement_refuses_pass_and_never_writes_in_replacement(self):
        for replace_at in ("scenario", "proof-open", "sidecar-open", None):
            with self.subTest(replace_at=replace_at), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                parent, moved = root / "output", root / "original"
                parent.mkdir(mode=0o700)
                target = parent / "proof.json"
                parsed = SimpleNamespace(output=str(target))
                original_open = os.open
                seen_fds = []

                def replace():
                    parent.rename(moved)
                    parent.mkdir(mode=0o700)

                async def scenario(directory_fd, publication_stack):
                    seen_fds.append(directory_fd)
                    evidence = publication_stack.enter_context(FIXTURE.evidence_archive(
                        target.with_suffix(".private-evidence.jsonl"), directory_fd))
                    evidence.drained = True
                    proof = {"privateEvidence": FIXTURE.seal_evidence(SimpleNamespace(evidence=evidence))}
                    evidence.causal = FIXTURE.private_json(parent / "proof.private-causal.json", {},
                                                            directory_fd=evidence.directory_fd,
                                                            publication_stack=publication_stack)
                    FIXTURE.verify_evidence(evidence)
                    if replace_at == "scenario":
                        replace()
                    return proof, evidence

                def open_proof(path, *args, **kwargs):
                    if kwargs.get("dir_fd") is not None and (
                            (path == target.name and replace_at == "proof-open")
                            or (path == "proof.private-causal.json" and replace_at == "sidecar-open")):
                        replace()
                    return original_open(path, *args, **kwargs)

                with patch.object(FIXTURE, "cli", return_value=parsed), \
                        patch.object(FIXTURE, "configure"), \
                        patch.object(FIXTURE, "run_scenario", side_effect=scenario), \
                        patch.object(FIXTURE.os, "open", side_effect=open_proof), \
                        patch("builtins.print") as output:
                    if replace_at:
                        with self.assertRaisesRegex(AssertionError, "directory changed"):
                            FIXTURE.main()
                        output.assert_not_called()
                        self.assertEqual(list(parent.iterdir()), [])
                        self.assertTrue((moved / "proof.private-evidence.jsonl").is_file())
                    else:
                        FIXTURE.main()
                        self.assertEqual(json.loads(output.call_args.args[0])["result"], "PASS")
                        proof = json.loads(target.read_text())
                        self.assertEqual(proof["privateEvidence"]["sha256"],
                                         FIXTURE.digest((parent / "proof.private-evidence.jsonl").read_bytes()))
                with self.assertRaises(OSError):
                    os.fstat(seen_fds[0])

    def test_invalid_utf8_cloud_response_is_recorded_without_changing_exchange(self):
        for status in (200, 502):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "evidence.jsonl"
                with FIXTURE.evidence_archive(path) as evidence:
                    ctx = SimpleNamespace(evidence=evidence, address={"port": 12345},
                                          fixture_secret=uuid4().hex, wire_evidence=[])
                    response = (status, {"content-type": "application/json"}, b'{"error":"bad \xff"}')
                    with patch.object(FIXTURE, "post", return_value=response):
                        actual = asyncio.run(FIXTURE.send(
                            ctx, method="POST", url=FIXTURE.ORIGIN + "/v1/runtimes/status",
                            timeout=5, max_response_bytes=8192, follow_redirects=False,
                            body=b"{}", headers={"x-event-node-proof": '{"nonce":"nonce"}'},
                        ))
                    self.assertIs(actual, response)
                    self.assertEqual(ctx.wire_evidence[-1]["responseSummary"], {"parse": "failed"})
                    records = [json.loads(line) for line in path.read_text().splitlines()]
                    self.assertEqual(records[-1]["kind"], "cloudWire")
                    self.assertEqual(records[-1]["value"]["response"], '{"error":"bad \ufffd"}')
                    self.assertEqual(records[-1]["value"]["status"], status)

    def test_cancelled_cloud_exchange_records_worker_completion_before_drain_and_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            with FIXTURE.evidence_archive(path) as evidence:
                entered, release, completed = threading.Event(), threading.Event(), threading.Event()
                ctx = SimpleNamespace(evidence=evidence, address={"port": 12345},
                                      fixture_secret=uuid4().hex, wire_evidence=[])
                response = (200, {}, b'{"status":"committed"}')

                def post(*args, **kwargs):
                    entered.set()
                    self.assertTrue(release.wait(5))
                    completed.set()
                    return response

                async def scenario():
                    exchange = asyncio.create_task(FIXTURE.send(
                        ctx, method="POST", url=FIXTURE.ORIGIN + "/v1/runtimes/attach",
                        timeout=5, max_response_bytes=8192, follow_redirects=False,
                        body=b'{"runtimeId":"runtime"}',
                        headers={"x-event-node-proof": '{"nonce":"nonce"}'},
                    ))
                    while not entered.is_set():
                        await asyncio.sleep(0)
                    exchange.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await exchange
                    self.assertFalse(completed.is_set())
                    drain = asyncio.create_task(FIXTURE.drain_native_observers(ctx))
                    await asyncio.sleep(0)
                    self.assertFalse(drain.done())
                    with self.assertRaisesRegex(AssertionError, "observers are not settled"):
                        FIXTURE.seal_evidence(ctx)
                    release.set()
                    await drain
                    self.assertTrue(completed.is_set())
                    proof = FIXTURE.seal_evidence(ctx)
                    self.assertEqual(proof["sha256"], FIXTURE.digest(path.read_bytes()))
                    records = [json.loads(line) for line in path.read_text().splitlines()]
                    self.assertEqual(records[-1], {"kind": "cloudWire", "value": {
                        "path": "/v1/runtimes/attach", "request": {"runtimeId": "runtime"},
                        "proof": {"nonce": "nonce"}, "status": 200,
                        "response": response[2].decode(),
                    }})
                    with self.assertRaisesRegex(AssertionError, "sealed"):
                        FIXTURE.record_evidence(ctx, "late", {})

                with patch.object(FIXTURE, "post", side_effect=post):
                    try:
                        asyncio.run(scenario())
                    finally:
                        release.set()

    def test_failed_drain_restores_all_observers_without_sealing_or_masking_error(self):
        for error in (AssertionError("native observers did not drain"), TimeoutError("executor timeout")):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as directory, ExitStack() as patches:
                evidence = patches.enter_context(FIXTURE.evidence_archive(Path(directory) / "evidence"))
                ctx = SimpleNamespace(evidence=evidence, daemon_task=None, sessions={})
                for name in ("client_runtime", "launcher", "Store", "daemon", "SessionNativeBridge"):
                    patches.enter_context(patch.object(FIXTURE, name, Mock()))
                targets = (
                    (FIXTURE.client_runtime, "_send_https", "original_send_https"),
                    (FIXTURE.launcher, "_session_request", "original_session_request"),
                    (FIXTURE.Store, "list_pending", "original_list_pending"),
                    (FIXTURE.Store, "list_reconcilable", "original_list_reconcilable"),
                    (FIXTURE.daemon.Gateway, "dispatch", "original_dispatch"),
                    (FIXTURE.daemon.Gateway, "reconcile", "original_reconcile"),
                    (FIXTURE.daemon.NativeBridgeAdapter, "check", "original_adapter_check"),
                    (FIXTURE.daemon.NativeBridgeAdapter, "reconcile", "original_adapter_reconcile"),
                    (FIXTURE.SessionNativeBridge, "challenge", "original_bridge_challenge"),
                )
                for module, attribute, original in targets:
                    setattr(ctx, original, object())
                    setattr(module, attribute, Mock())
                patches.enter_context(patch.object(FIXTURE, "drain_native_observers", AsyncMock(side_effect=error)))
                finish = patches.enter_context(patch.object(FIXTURE, "finish_scenario_cleanup"))
                with self.assertRaises(type(error)) as raised:
                    asyncio.run(FIXTURE.cleanup_scenario(ctx))
                self.assertIs(raised.exception, error)
                finish.assert_called_once_with(ctx)
                for module, attribute, original in targets:
                    self.assertIs(getattr(module, attribute), getattr(ctx, original))
                self.assertFalse(evidence.drained)
                self.assertFalse(evidence.sealed)
                with self.assertRaisesRegex(AssertionError, "observers are not settled"):
                    FIXTURE.seal_evidence(ctx)

    def test_stage_failure_survives_secondary_drain_snapshot_and_sync_failures(self):
        for operation in ("drain", "snapshot", "sync"):
            with self.subTest(operation=operation):
                self.run_retention_scenario("stage-" + operation + "-failure")

    def test_stage_failure_survives_secondary_daemon_stop_failure(self):
        self.run_retention_scenario("stage-stop-failure")

    def test_daemon_stop_failure_refuses_success_and_survives_later_sync_failure(self):
        for outcome in ("stop-failure", "stop-sync-failure"):
            with self.subTest(outcome=outcome):
                self.run_retention_scenario(outcome)

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
            inspections = []
            failures = {name: RuntimeError("original stage failure") for name in (
                "stage-stop-failure", "stage-drain-failure", "stage-snapshot-failure", "stage-sync-failure")}
            failures["stop-failure"] = AssertionError("daemon stop failed")
            failures["stop-sync-failure"] = failures["stop-failure"]
            if outcome == "drain-timeout":
                real_wait = asyncio.wait

                async def short_wait(tasks, **kwargs):
                    return await real_wait(tasks, timeout=0.01)

                patches.enter_context(patch.object(FIXTURE.asyncio, "wait", side_effect=short_wait))
            if outcome == "fsync-failure":
                patches.enter_context(patch.object(FIXTURE.os, "fsync", side_effect=OSError("fsync failed")))
            for name in ("run_ab_routes", "run_busy_stage", "run_fixture_attach", "run_post_attach_c3"):
                patches.enter_context(patch.object(FIXTURE, name, AsyncMock()))
            patches.enter_context(patch.object(FIXTURE, "build_proof", return_value=({}, None)))

            async def fail(ctx, resources):
                self.prepare_retention_stage(ctx, resources, outcome, state_roots, descriptors, resource_closed)
                self.prepare_stage_cleanup_failure(ctx, outcome, patches, failures)
                if outcome == "drain-timeout":
                    await self.hold_worker_through_drain_deadline(ctx, resource_closed, inspections)

            patches.enter_context(patch.object(FIXTURE, "initialize_runtime", side_effect=fail))
            proof = None
            if outcome == "success":
                proof, _ = asyncio.run(FIXTURE.run_scenario())
            else:
                error, message = {
                    "stage-failure": (RuntimeError, "injected stage failure"),
                    "stage-stop-failure": (RuntimeError, "original stage failure"),
                    "stage-drain-failure": (RuntimeError, "original stage failure"),
                    "stage-snapshot-failure": (RuntimeError, "original stage failure"),
                    "stage-sync-failure": (RuntimeError, "original stage failure"),
                    "stop-failure": (AssertionError, "daemon stop failed"),
                    "stop-sync-failure": (AssertionError, "daemon stop failed"),
                    "partial-failure": (ValueError, "original partial ledger failure"),
                    "partial-success": (AssertionError, "checkpoint ledger is incomplete"),
                    "write-failure": (AssertionError, "bounded archive"),
                    "fsync-failure": (OSError, "fsync failed"),
                    "drain-timeout": (TimeoutError, "drain exceeded 30 seconds"),
                }[outcome]
                with self.assertRaisesRegex(error, message) as raised:
                    asyncio.run(FIXTURE.run_scenario())
                if outcome in failures:
                    self.assertIs(raised.exception, failures[outcome])
            self.assert_retention_archive(outcome, output, proof)
            if outcome == "drain-timeout":
                self.assertEqual(inspections, ["retained", "joined"])
            self.assertEqual(resource_closed, [True])
            self.assertFalse(output.exists(), "failed stages must not produce PASS proof")
            self.assertTrue(all(not path.exists() for path in state_roots))
            stop.assert_called_once()
            for descriptor in descriptors:
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

    def prepare_stage_cleanup_failure(self, ctx, outcome, patches, failures):
        if outcome in failures:
            if "stop" in outcome:
                ctx.daemon_task = asyncio.create_task(asyncio.sleep(60))
                ctx.stop_daemon = AsyncMock(side_effect=failures["stop-failure"])
            else:
                self.inject_stage_cleanup_failure(outcome, patches)
            if outcome == "stop-sync-failure":
                self.inject_stage_cleanup_failure("stage-sync-failure", patches)
            if outcome.startswith("stage-"):
                raise failures[outcome]

    def inject_stage_cleanup_failure(self, outcome, patches):
        name = {"stage-drain-failure": "drain_native_observers", "stage-snapshot-failure": "snapshot_evidence",
                "stage-sync-failure": "sync_evidence"}[outcome]
        original = getattr(FIXTURE, name)
        failed = False

        def fail_once():
            nonlocal failed
            if not failed:
                failed = True
                raise OSError("secondary " + name + " failure")

        async def drain(ctx):
            await original(ctx)
            fail_once()

        def diagnostic(*args):
            fail_once()
            return original(*args)

        patches.enter_context(patch.object(FIXTURE, name, side_effect=drain if name == "drain_native_observers" else diagnostic))

    async def hold_worker_through_drain_deadline(self, ctx, resource_closed, inspections):
        entered, release = threading.Event(), threading.Event()
        scenario_task = asyncio.current_task()

        def worker():
            entered.set()
            self.assertTrue(release.wait(5))
            self.assertTrue(ctx.state.is_dir())
            FIXTURE.record_evidence(ctx, "lateExecutorRecord", {})
            inspections.append("joined")

        task = asyncio.create_task(asyncio.to_thread(worker))
        while not entered.is_set():
            await asyncio.sleep(0)
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

        async def inspect_before_release():
            try:
                while ctx.evidence.drain_error is None:
                    await asyncio.sleep(0)
                scenario_task.cancel()
                await asyncio.sleep(0)
                self.assertTrue(ctx.state.is_dir())
                self.assertEqual(resource_closed, [])
                self.assertFalse(ctx.evidence.drained)
                self.assertFalse(ctx.evidence.sealed)
                self.assertEqual(ctx.evidence.active, 0)
                os.fstat(ctx.evidence.fd)
                os.fstat(ctx.evidence.directory_fd)
                with self.assertRaisesRegex(AssertionError, "observers are not settled"):
                    FIXTURE.seal_evidence(ctx)
                inspections.append("retained")
            finally:
                release.set()

        asyncio.create_task(inspect_before_release())

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
            if outcome not in ("write-failure", "stage-snapshot-failure"):
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
        if outcome not in ("write-failure", "stage-snapshot-failure"):
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
                              evidence=SimpleNamespace(lock=threading.Condition(), closing=False, sealed=False, active=0))
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

    def test_hash_read_failure_closes_writes_and_latches_failed_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            with FIXTURE.evidence_archive(Path(directory) / "evidence") as evidence:
                ctx = SimpleNamespace(evidence=evidence)
                evidence.drained = True
                failure = OSError("hash read failed")
                with patch.object(FIXTURE.os, "read", side_effect=failure):
                    with self.assertRaises(OSError) as raised:
                        FIXTURE.seal_evidence(ctx)
                self.assertIs(raised.exception, failure)
                self.assertTrue(evidence.failed)
                self.assertTrue(evidence.sealed)
                with self.assertRaisesRegex(AssertionError, "sealed"):
                    FIXTURE.record_evidence(ctx, "late", {})
                with self.assertRaisesRegex(AssertionError, "observers are not settled"):
                    FIXTURE.seal_evidence(ctx)

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
                            self.assertTrue(evidence.sealed)
                            self.assertTrue(evidence.failed)
                            with self.assertRaisesRegex(AssertionError, "observers are not settled"):
                                FIXTURE.seal_evidence(ctx)
                            with self.assertRaisesRegex(AssertionError, "sealed"):
                                FIXTURE.record_evidence(ctx, "late", {})
                        else:
                            proof = FIXTURE.seal_evidence(ctx)
                            self.assertEqual(calls[:3], ["file", "parent", "hash-read"])
                            self.assertEqual(proof["bytes"], evidence.path.stat().st_size)
                with self.assertRaises(OSError):
                    os.fstat(evidence.fd)


    def test_broker_setup_failure_closes_both_archive_descriptors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_close, real_archive, real_fsync = os.close, FIXTURE.evidence_archive, os.fsync
            archive_fds, closed, synced = {}, [], []

            @contextmanager
            def archive(path, directory_fd=None):
                with real_archive(path, directory_fd) as evidence:
                    for fd in (evidence.fd, evidence.directory_fd):
                        info = os.fstat(fd)
                        archive_fds[fd] = (info.st_dev, info.st_ino)
                    yield evidence

            def sync(fd):
                self.assertNotIn(fd, closed)
                synced.append(fd)
                real_fsync(fd)

            def close(fd):
                info = os.fstat(fd)
                if archive_fds.get(fd) == (info.st_dev, info.st_ino):
                    closed.append(fd)
                real_close(fd)

            with patch.object(FIXTURE, "args", SimpleNamespace(output=str(root / "proof.json"), outer_contained=False)), \
                    patch.object(FIXTURE, "private_temp_root", return_value=root), \
                    patch.object(FIXTURE, "start_broker", side_effect=RuntimeError("broker failed")), \
                    patch.object(FIXTURE, "evidence_archive", side_effect=archive), \
                    patch.object(FIXTURE.os, "close", side_effect=close), \
                    patch.object(FIXTURE.os, "fsync", side_effect=sync):
                with self.assertRaisesRegex(RuntimeError, "broker failed"):
                    asyncio.run(FIXTURE.run_scenario())
                # Event-loop cleanup may close unrelated or reused descriptor numbers.
                unrelated = os.open(root / "unrelated", os.O_CREAT | os.O_RDWR, 0o600)
                reused = next(fd for fd in archive_fds if fd != unrelated)
                os.dup2(unrelated, reused)
                os.close(reused)
                os.close(unrelated)
            self.assertEqual(len(archive_fds), 2)
            self.assertCountEqual(closed, archive_fds)
            self.assertCountEqual(synced, archive_fds)


    def test_broker_failure_survives_early_persistence_failure_with_either_archive_owner(self):
        for publication_owned, sink_error in product((False, True), (OSError, ValueError)):
            with self.subTest(publication_owned=publication_owned, sink_error=sink_error), tempfile.TemporaryDirectory() as directory, \
                    ExitStack() as publication:
                root = Path(directory)
                failure = RuntimeError("broker startup failed")
                real_archive = FIXTURE.evidence_archive
                retained = []

                @contextmanager
                def archive(path, directory_fd=None):
                    with real_archive(path, directory_fd) as evidence:
                        retained.append(evidence)
                        yield evidence

                with patch.object(FIXTURE, "args", SimpleNamespace(output=str(root / "proof.json"), outer_contained=False)), \
                        patch.object(FIXTURE, "private_temp_root", return_value=root), \
                        patch.object(FIXTURE, "start_broker", side_effect=failure), \
                        patch.object(FIXTURE, "evidence_archive", side_effect=archive), \
                        patch.object(FIXTURE.os, "fsync", side_effect=OSError("sync failed")) as sync, \
                        patch.object(FIXTURE.sys, "stderr", Mock(write=Mock(side_effect=sink_error("sink failed")))):
                    with self.assertRaises(Exception) as caught:
                        asyncio.run(FIXTURE.run_scenario(publication_stack=publication if publication_owned else None))
                self.assertIs(caught.exception, failure)
                sync.assert_called_once_with(retained[0].fd)
                self.assertTrue(retained[0].failed)
                self.assertFalse((root / "proof.json").exists())


    def test_snapshot_stays_consistent_when_writer_commits_between_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "ledger?query#fragment"
            root.mkdir()
            database = root / "ledger.sqlite"
            with closing(sqlite3.connect(database)) as writer:
                writer.execute("PRAGMA journal_mode=WAL")
                for query in (
                    "CREATE TABLE attachments (version INTEGER)", "INSERT INTO attachments VALUES (0)",
                    "CREATE TABLE deliveries (version INTEGER)", "INSERT INTO deliveries VALUES (0)",
                    "CREATE TABLE attempts (version INTEGER)", "INSERT INTO attempts VALUES (0)",
                ):
                    writer.execute(query)
                writer.commit()
                records = []

                def record(ctx, kind, value):
                    if kind != "database":
                        return
                    records.append(value)
                    if value["table"] == "attachments":
                        for query in ("UPDATE attachments SET version = 1",
                                      "UPDATE deliveries SET version = 1",
                                      "UPDATE attempts SET version = 1"):
                            writer.execute(query)
                        writer.commit()

                real_connect = sqlite3.connect

                def connect(*args, **kwargs):
                    db = real_connect(*args, **kwargs)
                    with self.assertRaisesRegex(sqlite3.OperationalError, "readonly"):
                        db.execute("CREATE TABLE should_not_exist (value TEXT)")
                    return db

                ctx = SimpleNamespace(state=root, fixture=Mock())
                with patch.object(FIXTURE, "record_evidence", side_effect=record), \
                        patch.object(FIXTURE.sqlite3, "connect", side_effect=connect):
                    self.assertEqual(FIXTURE.snapshot_evidence(ctx, "concurrent-write"), [])
                self.assertEqual([row["rows"] for row in records], [[{"version": 0}]] * 3)
                self.assertEqual(writer.execute("SELECT version FROM attempts").fetchone()[0], 1)
                ctx.fixture.assert_called_once_with("/fixture/read")
                self.assertFalse((root.parent / "ledger").exists())


    def test_native_cleanup_persistent_sync_failure_preserves_setup_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with FIXTURE.evidence_archive(root / "evidence") as evidence:
                ctx = SimpleNamespace(evidence=evidence, state=root)
                original = RuntimeError("setup failure")
                with patch.object(FIXTURE, "private_temp_root", return_value=root), \
                        patch.object(FIXTURE, "make_model", return_value=SimpleNamespace()), \
                        patch.object(FIXTURE, "host_qualifier", SimpleNamespace(source_program=Mock(side_effect=original))), \
                        patch.object(FIXTURE.os, "fsync", side_effect=OSError("persistent fsync failure")) as sync:
                    with self.assertRaises(RuntimeError) as raised, ExitStack() as resources:
                        FIXTURE.native_session(resources, "C", ctx)
                self.assertIs(raised.exception, original)
                sync.assert_called_once_with(evidence.fd)
                self.assertTrue(evidence.failed)
                self.assertFalse(list(root.glob("three-native-*")))

    def test_failed_record_prefix_is_synced_without_allowing_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence"
            with FIXTURE.evidence_archive(path) as evidence:
                ctx = SimpleNamespace(evidence=evidence)
                prefix = path.read_bytes()
                with self.assertRaisesRegex(AssertionError, "bounded archive"):
                    FIXTURE.record_evidence(ctx, "oversized", "x" * 4_100_001)
                with patch.object(FIXTURE.os, "fsync", wraps=os.fsync) as sync:
                    FIXTURE.persist_evidence(ctx)
                self.assertEqual([call.args[0] for call in sync.call_args_list], [evidence.fd, evidence.directory_fd])
                self.assertEqual(path.read_bytes(), prefix)
                self.assertTrue(evidence.failed)
                evidence.drained = True
                with self.assertRaisesRegex(AssertionError, "observers are not settled"):
                    FIXTURE.seal_evidence(ctx)

    def test_provider_last_record_is_synced_before_native_scratch_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with FIXTURE.evidence_archive(root / "evidence") as evidence:
                ctx = SimpleNamespace(evidence=evidence, state=root)
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
