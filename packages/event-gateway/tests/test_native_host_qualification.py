"""Failure boundaries for the offline native host qualifier."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

PATH = Path(__file__).parents[1] / "docs/native-bridge/native-host-launcher-qualification.py"
SPEC = importlib.util.spec_from_file_location("native_host_qualification", PATH)
QUALIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFIER)


class NativeHostQualificationTests(unittest.TestCase):
    def test_only_correlated_tool_output_counts(self):
        nonce = "unique-source-nonce"
        output = {"type": "custom_tool_call_output", "call_id": QUALIFIER.CALL_ID,
                  "output": [{"type": "text", "text": json.dumps({"exit_code": 0, "output": nonce + "\n"})}]}
        requests = [{"input": []}, {"input": [output]}]
        self.assertEqual(QUALIFIER.verify_output(requests, nonce), output)
        for changed in (
            [{"input": [nonce]}, requests[1]],
            [requests[0], {"input": [{**output, "call_id": "other"}]}],
            [requests[0], {"input": [output, output]}],
            [requests[0], {"input": [{**output, "output": [{"text": "missing"}]}]}],
            [requests[0], {"input": [{**output, "output": [{"text": json.dumps({
                "exit_code": 1, "output": nonce + "\n"})}]}]}],
            requests + [{"input": []}],
        ):
            with self.subTest(changed=changed), self.assertRaises(AssertionError):
                QUALIFIER.verify_output(changed, nonce)

    def test_concurrent_title_request_is_distinct_from_tool_turn(self):
        title = {"tools": [], "text": {"format": {"schema": {
            "required": ["title"], "properties": {"title": {"type": "string"}}}}},
            "input": [{"text": "Generate a concise, single-line task title"}]}
        self.assertEqual(QUALIFIER.request_kind(title), "title")
        self.assertEqual(QUALIFIER.request_kind({"tools": [{"name": "exec"}]}), "main")
        for request in ({"tools": []}, {**title, "input": []},
                        {**title, "tools": [{"name": "other"}]}):
            with self.subTest(request=request), self.assertRaises(AssertionError):
                QUALIFIER.request_kind(request)

    def test_program_reads_path_without_embedding_file_contents(self):
        program = QUALIFIER.source_program(Path("/private/tmp/a ' quoted.txt"))
        self.assertTrue(program.startswith("text(await tools.exec_command("))
        arguments = json.loads(program[len("text(await tools.exec_command("):-3])
        self.assertEqual(arguments["cmd"], "/bin/cat '/private/tmp/a '\"'\"' quoted.txt'")
        self.assertFalse(arguments["login"])

    def test_frozen_helper_is_verified_before_execution(self):
        helper = QUALIFIER.verified_helper("qualification-installed.py")
        try:
            self.assertTrue(callable(helper.verify_installed))
            snapshot = Path(helper.__file__)
            self.assertNotEqual(snapshot.parent, PATH.parent)
            self.assertEqual(hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                             QUALIFIER.HELPERS["qualification-installed.py"])
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
        finally:
            helper._private_helper.cleanup()
        with patch.object(Path, "read_bytes", return_value=b"raise RuntimeError('executed')"):
            with self.assertRaisesRegex(AssertionError, "digest mismatch"):
                QUALIFIER.verified_helper("qualification-installed.py")

    def test_start_has_five_second_permit_and_exact_binding(self):
        from event_gateway.native_reader import validate_start
        from uuid import uuid4
        binding = {"clientId": str(uuid4()), "serverInstanceId": str(uuid4()),
                   "serverGeneration": 3, "threadId": str(uuid4()), "generation": 4}
        request = QUALIFIER.start_request(binding)
        validate_start(request)
        self.assertEqual({key: request[key] for key in binding}, binding)
        self.assertEqual(request["permitExpiresAt"] - request["permitIssuedAt"], 5000)

    def test_config_snapshots_preserve_native_changes_even_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            initial, final = b'model="initial"\n', b'model="updated"\n'
            path.write_bytes(initial)
            trace = QUALIFIER.config_snapshot(path, "initial")
            with self.assertRaisesRegex(RuntimeError, "later failure"):
                with QUALIFIER.preserve_final_config(trace, path):
                    path.write_bytes(final)
                    raise RuntimeError("later failure")
            for phase, data in (("initial", initial), ("final", final)):
                self.assertEqual(trace[phase + "Config"].encode(), data)
                self.assertEqual(trace[phase + "ConfigSha256"], hashlib.sha256(data).hexdigest())

    def test_launch_always_wraps_inner_unsandboxed_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            profile, cache, state, binary = (root / name for name in ("profile.sb", "cache", "state", "codex"))
            argv = QUALIFIER.launch_argv(profile, cache, state, binary, root)
            self.assertEqual(argv[:3], ["/usr/bin/sandbox-exec", "-f", str(profile)])
            self.assertIn("-I", argv)
            self.assertIn(f"pycache_prefix={cache}", argv)
            for flag, value in (("--state-dir", state), ("--codex-binary", binary), ("--cwd", root)):
                self.assertEqual(argv[argv.index(flag) + 1], str(value))
            self.assertEqual(argv[argv.index("--binary-sha256") + 1], QUALIFIER.CLI_SHA)

    def test_profile_denies_external_network_and_protects_real_home(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve() / "test-user"
            codex_home = Path(directory).resolve() / 'custom "codex"'
            with patch.object(Path, "home", return_value=home), \
                    patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
                profile = QUALIFIER.sandbox_profile(43210)
            self.assertIn('(deny network*)', profile)
            self.assertIn('(remote ip "localhost:43210")', profile)
            self.assertIn("(subpath " + json.dumps(str(home / ".codex")) + ")", profile)
            self.assertIn("(subpath " + json.dumps(str(codex_home)) + ")", profile)
            self.assertNotIn('(allow network-outbound)', profile)



class ForegroundOperationTests(unittest.TestCase):
    def test_single_operation_completes_only_when_foreground_is_drained(self):
        import threading
        from types import SimpleNamespace
        released = threading.Event()
        calls = []
        drained = []

        def operation(*args):
            calls.append(args)
            if not released.wait(0.2):
                raise TimeoutError('foreground output was not consumed')
            return {'outcome': {'status': 'inputRecorded'}}

        def drain(master, tail):
            drained.append((master, tail))
            released.set()

        launcher = SimpleNamespace(session_native_operation=operation, NATIVE_OPERATION_SECONDS=1)
        smoke = SimpleNamespace(drain=drain)
        process = SimpleNamespace(poll=lambda: None)
        tail = bytearray()
        result = QUALIFIER.foreground_operation(launcher, smoke, process, 7, tail, 'one-request')
        self.assertEqual(result, {'outcome': {'status': 'inputRecorded'}})
        self.assertEqual(calls, [('one-request',)])
        self.assertTrue(drained)
        self.assertTrue(all(master == 7 and seen is tail for master, seen in drained))

    def test_operation_exception_propagates_without_retry(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        failure = ValueError('native failure')
        operation = Mock(side_effect=failure)
        with self.assertRaises(ValueError) as raised:
            QUALIFIER.foreground_operation(
                SimpleNamespace(session_native_operation=operation, NATIVE_OPERATION_SECONDS=1),
                SimpleNamespace(drain=lambda *_: None), SimpleNamespace(poll=lambda: None),
                7, bytearray(), 'one-request')
        self.assertIs(raised.exception, failure)
        operation.assert_called_once_with('one-request')

    def test_process_exit_and_deadline_fail_closed(self):
        import threading
        from types import SimpleNamespace
        from unittest.mock import Mock
        for exited in (True, False):
            with self.subTest(exited=exited):
                operation = Mock(side_effect=lambda *_: threading.Event().wait(0.02))
                launcher = SimpleNamespace(session_native_operation=operation, NATIVE_OPERATION_SECONDS=1)
                process = SimpleNamespace(poll=lambda: 1 if exited else None)
                with patch.object(QUALIFIER.time, 'monotonic', side_effect=[0, 2]), \
                        self.assertRaisesRegex(AssertionError, 'launcher exited|native operation timed out'):
                    QUALIFIER.foreground_operation(launcher, SimpleNamespace(drain=lambda *_: None),
                                                   process, 7, bytearray(), 'one-request')
                operation.assert_called_once_with('one-request')

    def test_failure_returns_while_native_worker_is_still_blocked(self):
        import threading
        from types import SimpleNamespace
        for failure in ('deadline', 'process-exit', 'drain-error'):
            with self.subTest(failure=failure):
                release, entered, returned = (threading.Event() for _ in range(3))
                workers, calls, errors = [], [], []
                def operation(*args):
                    workers.append(threading.current_thread())
                    calls.append(args)
                    entered.set()
                    release.wait()
                def drain(*_):
                    if failure == 'drain-error':
                        raise OSError('drain failed')
                    returned.wait(0.001)
                def invoke():
                    try:
                        QUALIFIER.foreground_operation(
                            SimpleNamespace(session_native_operation=operation, NATIVE_OPERATION_SECONDS=0.03),
                            SimpleNamespace(drain=drain),
                            SimpleNamespace(poll=lambda: 1 if failure == 'process-exit' else None),
                            7, bytearray(), 'one-request')
                    except BaseException as error:
                        errors.append(error)
                    finally:
                        returned.set()
                caller = threading.Thread(target=invoke, daemon=True)
                caller.start()
                try:
                    self.assertTrue(entered.wait(0.5), 'native worker never started')
                    self.assertTrue(returned.wait(0.5), 'foreground failure waited for blocked worker')
                    self.assertTrue(workers[0].is_alive())
                    self.assertTrue(workers[0].daemon)
                    self.assertEqual(calls, [('one-request',)])
                    self.assertEqual(len(errors), 1)
                    self.assertRegex(str(errors[0]), {
                        'deadline': 'timed out', 'process-exit': 'launcher exited',
                        'drain-error': 'drain failed'}[failure])
                finally:
                    release.set()
                    caller.join(1)
                    for worker in workers:
                        worker.join(1)
                    self.assertFalse(caller.is_alive())
                    self.assertTrue(all(not worker.is_alive() for worker in workers))

    def test_only_esrch_proves_owned_process_group_is_empty(self):
        for outcome, error in ((ProcessLookupError(), None), (None, AssertionError),
                               (PermissionError(), PermissionError)):
            with self.subTest(outcome=outcome), patch.object(QUALIFIER.os, 'killpg', side_effect=outcome) as probe:
                if error:
                    with self.assertRaises(error):
                        QUALIFIER.require_process_group_stopped(123)
                else:
                    QUALIFIER.require_process_group_stopped(123)
                probe.assert_called_once_with(123, 0)


class GitHubQualificationWiringTests(unittest.TestCase):
    def test_github_prepare_and_verified_output_reach_final_proof(self):
        from contextlib import contextmanager
        from types import SimpleNamespace
        from unittest.mock import Mock
        from uuid import uuid4
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            binary, host = root / 'codex', root / 'codex-code-mode-host'
            binary.write_bytes(b'candidate fixture')
            host.write_bytes(b'host fixture')
            args = SimpleNamespace(binary=binary, package_source=root / 'src/event_gateway')
            process = Mock(pid=123)
            process.poll.return_value = None
            binding = {key: str(uuid4()) for key in ('clientId', 'serverInstanceId', 'threadId')}
            binding.update(serverGeneration=1, generation=1, backendPid=456)
            server = SimpleNamespace(server_port=1234, requests=[], main_requests=[],
                                     title_requests=[], errors=[], trace={})
            selected = (root / ('c-' + str(uuid4()) + '.sock'), {}, binding, {})
            def config(root, _port):
                home = root / 'codex-home'
                home.mkdir()
                (home / 'config.toml').write_text('model="mock-astra"\n')
                return home
            @contextmanager
            def foreground(*_):
                yield process, 7
            def operation(_state, _session, _binding, command, request):
                turn = request['clientUserMessageId']
                if command == 'nativeStart':
                    metadata = {'client_metadata': {'turn_id': turn, 'thread_id': binding['threadId']}}
                    server.main_requests.extend([metadata, metadata])
                    server.requests.extend(server.main_requests)
                    return {'outcome': {'status': 'started', 'turnId': turn}}
                self.assertEqual(command, 'nativeReceipt')
                return {'outcome': {'status': 'inputRecorded', 'turnId': turn}}
            def prepare(source, nonce, package_source, installed_helper):
                self.assertEqual(package_source, args.package_source)
                self.assertEqual(installed_helper, 'verified-installed-helper')
                source.write_text('retained:' + nonce)
                return 'synthetic-github-program'
            def verify(requests, nonce, source, base_verify):
                self.assertIs(requests, server.main_requests)
                self.assertIs(base_verify, QUALIFIER.verify_output)
                self.assertEqual(source.read_text(), 'retained:' + nonce)
                return {'correlated': 'validated-github-output'}
            github = SimpleNamespace(prepare=Mock(side_effect=prepare), verify_output=Mock(side_effect=verify))
            launcher = SimpleNamespace(session_native_operation=Mock(side_effect=operation),
                                       NATIVE_OPERATION_SECONDS=1)
            smoke = SimpleNamespace(write_config=config, foreground_process=foreground,
                                    wait_selection=Mock(return_value=selected), check_selection=Mock(),
                                    drain=Mock(), quit_foreground=Mock(return_value=0))
            with patch.object(QUALIFIER, 'CLI_SHA', hashlib.sha256(binary.read_bytes()).hexdigest()), \
                    patch.object(QUALIFIER, 'HOST_SHA', hashlib.sha256(host.read_bytes()).hexdigest()), \
                    patch.object(QUALIFIER, 'require_process_group_stopped') as cleanup:
                proof = QUALIFIER.qualify(args, launcher, smoke, server, github, 'verified-installed-helper')
            self.assertEqual(proof['result'], 'PASS')
            self.assertEqual(proof['sourceProgram'], 'synthetic-github-program')
            self.assertEqual(server.trace['sourceProgram'], proof['sourceProgram'])
            self.assertEqual(proof['toolOutput'], {'correlated': 'validated-github-output'})
            self.assertEqual(proof['sourceSha256'], hashlib.sha256(('retained:' + proof['sourceNonce']).encode()).hexdigest())
            github.prepare.assert_called_once()
            github.verify_output.assert_called_once()
            self.assertEqual([call.args[3] for call in launcher.session_native_operation.call_args_list],
                             ['nativeStart', 'nativeReceipt'])
            cleanup.assert_called_once_with(process.pid)


if __name__ == "__main__":
    unittest.main()
