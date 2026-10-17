"""Offline subprocess fixtures only: no DNS, sockets, listeners or credentials."""
import os
import json
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'artifact-transport'))
import transport
import adapter


class AdapterTests(unittest.TestCase):
    def test_composed_transport_accepts_actual_adapter_response(self):
        policy = dict(repository='knitli/knitli-site', repositoryId=1058277548,
                      runId='123', runAttempt='2', sourceHeadSha='d' * 40,
                      workflowSha='711e265cc280cad7c4a44ba6d2d72f40a1378fec')
        metadata = json.dumps({'status': 200, 'headers': {}}).encode()
        frame = struct.pack('!I', len(metadata)) + metadata + b'{}'
        # Exercise real pin checks using an inert fixture runtime and its test
        # digest. No fixture executable is launched; only _run is faked.
        with tempfile.TemporaryDirectory() as directory:
            node = Path(directory).resolve() / 'node'
            node.write_bytes(b'offline-inert-runtime')
            digest = hashlib.sha256(node.read_bytes()).hexdigest()
            with patch.object(adapter, 'NODE_SHA256', digest), patch.object(adapter, '_run', return_value=frame) as child:
                client = transport._Transport(policy, 'offline-token', adapter.bind(node))
                result = client.call('https://api.github.com/repos/knitli/knitli-site/actions/runs/123')
        self.assertIs(adapter.Response, transport.Response)
        self.assertEqual(result, (b'{}', {}))
        payload = json.loads(child.call_args.args[1])
        self.assertEqual(payload['headers']['Authorization'], 'Bearer offline-token')
        self.assertEqual(child.call_args.args[3], client.deadline)

    def run_child(self, source, maximum=8, seconds=2):
        return adapter._run([sys.executable, '-I', '-c', source], b'{}', maximum, time.monotonic() + seconds)

    def test_success_closed_environment_private_cwd_and_frame(self):
        source = """import os,sys,json,struct
assert not any(k in os.environ for k in ('NODE_OPTIONS','NODE_EXTRA_CA_CERTS','HTTPS_PROXY','GH_TOKEN','SECRET'))
assert os.environ['HOME']==os.getcwd()
assert os.stat(os.getcwd()).st_mode & 0o777 == 0o700
assert sys.stdin.buffer.read()==b'{}'
m=json.dumps({'status':302,'headers':{'location':'https://storage.invalid/?secret=SIGNED'}}).encode()
sys.stdout.buffer.write(struct.pack('!I',len(m))+m+b'ok')
"""
        with patch.dict(os.environ, {'SECRET': 'SECRET', 'GH_TOKEN': 'SECRET', 'HTTPS_PROXY': 'http://localhost:1', 'NODE_OPTIONS': '--bad'}):
            result = adapter._decode(self.run_child(source), 'https://api.github.com/', 8)
        self.assertEqual((result.status, result.body), (302, b'ok'))

    def test_deadline_before_spawn(self):
        with patch.object(adapter.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(adapter.Refused, 'https_deadline'):
                adapter._run([], b'{}', 8, time.monotonic())
            spawn.assert_not_called()

    def test_hung_child_killed_reaped_pipes_and_scratch_closed(self):
        real = adapter.subprocess.Popen
        children = []
        def spawn(*args, **kwargs):
            child = real(*args, **kwargs)
            children.append((child, kwargs['cwd']))
            return child
        start = time.monotonic()
        with patch.object(adapter.subprocess, 'Popen', side_effect=spawn):
            with self.assertRaisesRegex(adapter.Refused, 'https_deadline'):
                self.run_child('import time; time.sleep(60)', seconds=1.3)
        self.assertLess(time.monotonic() - start, 1.3)
        for child, cwd in children:
            self.assertIsNotNone(child.returncode)
            self.assertTrue(all(p.closed for p in (child.stdin, child.stdout, child.stderr)))
            self.assertFalse(Path(cwd).exists())
            with self.assertRaises(ProcessLookupError):
                os.kill(child.pid, 0)

    def test_closed_pipes_live_child_still_deadline(self):
        with self.assertRaisesRegex(adapter.Refused, 'https_deadline'):
            self.run_child('import os,time; os.close(0); os.close(1); os.close(2); time.sleep(60)', seconds=1.3)

    def test_header_and_body_stalls_use_same_deadline(self):
        for prefix in [b'\x00', struct.pack('!I', 2) + b'{}']:
            with self.subTest(prefix=prefix), self.assertRaisesRegex(adapter.Refused, 'https_deadline'):
                self.run_child(f'import os,time; os.write(1,{prefix!r}); time.sleep(60)', seconds=1.2)

    def test_private_input_backpressure_is_bounded(self):
        with self.assertRaisesRegex(adapter.Refused, 'https_deadline'):
            adapter._run([sys.executable, '-I', '-c', 'import time; time.sleep(60)'], b'x' * 16384, 8, time.monotonic() + 1.2)

    def test_output_metadata_body_and_stderr_limits(self):
        cases = [
            ('import os; os.write(1,b"\\xff"*4)', 'https_metadata_limit'),
            ('import os,struct; os.write(1,struct.pack("!I",2)+b"{}"+b"x"*9)', 'https_body_limit'),
            ('import os; os.write(2,b"SECRET"*1000)', 'https_stderr_limit'),
        ]
        for source, code in cases:
            with self.subTest(code=code), self.assertRaisesRegex(adapter.Refused, code) as caught:
                self.run_child(source)
            self.assertNotIn('SECRET', str(caught.exception))

    def test_child_error_redacted(self):
        with self.assertRaisesRegex(adapter.Refused, '^https_child$'):
            self.run_child('import sys; sys.stderr.write("SECRET signed-url"); sys.exit(2)')

    def test_bad_frames(self):
        for value in [b'', struct.pack('!I', 10) + b'{}', struct.pack('!I', 2) + b'{}', struct.pack('!I', 29) + b'{"status":200,"status":200}']:
            with self.subTest(value=value), self.assertRaises(adapter.Refused):
                adapter._decode(value, 'secret-url', 8)

    def test_cleanup_signal_precedes_reap(self):
        calls = []
        class Child:
            pid = 123456
            def wait(self, timeout):
                calls.append('wait')
                return 0
        with patch.object(adapter.os, 'killpg', side_effect=lambda *_: calls.append('kill')):
            self.assertEqual(adapter._stop(Child(), time.monotonic() + 1), 0)
        self.assertEqual(calls, ['kill', 'wait'])

    def test_cleanup_failure_cannot_report_success(self):
        class Child:
            pid = 123456
            def wait(self, timeout):
                raise subprocess.TimeoutExpired('private-child', timeout)
        with patch.object(adapter.os, 'killpg'):
            with self.assertRaisesRegex(adapter.Refused, '^https_cleanup$'):
                adapter._stop(Child(), time.monotonic() + 1)

    def test_primary_deadline_retained_when_cleanup_reports_failure(self):
        real_stop = adapter._stop
        def failed_stop(child, deadline):
            real_stop(child, deadline)
            raise adapter.Refused('https_cleanup')
        with patch.object(adapter, '_stop', side_effect=failed_stop):
            with self.assertRaisesRegex(adapter.Refused, '^https_deadline$') as caught:
                self.run_child('import time; time.sleep(60)', seconds=1.2)
        self.assertEqual(caught.exception.__notes__, ['https_cleanup_failed'])

    def test_public_request_download_origin_refused_without_spawn(self):
        with patch.object(adapter.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(adapter.Refused, '^https_origin$'):
                adapter.bind('/unused/physical/node')('https://storage.invalid/?SECRET', {'Authorization': 'SECRET'}, 8, time.monotonic() + 10)
            spawn.assert_not_called()

    def test_runtime_binding_rejects_relative_symlink_and_wrong_digest(self):
        with self.assertRaisesRegex(adapter.Refused, '^https_pin$'):
            adapter.bind('node')
        with tempfile.TemporaryDirectory() as directory:
            node = Path(directory).resolve() / 'node'
            node.write_bytes(b'offline-inert-runtime')
            alias = node.with_name('alias')
            alias.symlink_to(node)
            for candidate in (node, alias):
                with patch.object(adapter, '_run') as child:
                    with self.assertRaisesRegex(adapter.Refused, '^https_pin$'):
                        adapter.bind(candidate)('https://api.github.com/', {}, 8, time.monotonic() + 10)
                    child.assert_not_called()


if __name__ == '__main__':
    unittest.main()
