"""Offline subprocess fixtures only: no DNS, sockets, listeners or credentials."""
import os
import json
from pathlib import Path
import struct
import subprocess  # nosec B404 - offline child fixtures only
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'artifact-transport'))
import transport
import adapter


class AdapterTests(unittest.TestCase):
    def test_private_fixture_response_composes_with_transport(self):
        policy = dict(repository='knitli/knitli-site', repositoryId=1058277548,
                      runId='123', runAttempt='2', sourceHeadSha='d' * 40,
                      workflowSha='711e265cc280cad7c4a44ba6d2d72f40a1378fec')
        metadata = json.dumps({'status': 200, 'headers': {}}).encode()
        frame = struct.pack('!I', len(metadata)) + metadata + b'{}'
        # Explicit fixture seam, not a successful public adapter binding.
        def fixture_request(url, headers, maximum, deadline):
            self.assertEqual(headers['Authorization'], 'Bearer offline-token')
            self.assertGreater(deadline, time.monotonic())
            return adapter._decode(frame, url, maximum)
        client = transport._Transport(policy, 'offline-token', fixture_request)
        result = client.call('https://api.github.com/repos/knitli/knitli-site/actions/runs/123')
        self.assertIs(adapter.Response, transport.Response)
        self.assertEqual(result, (b'{}', {}))

    def run_child(self, source, maximum=8, seconds=2):
        return adapter._run([sys.executable, '-I', '-c', source], b'{}', maximum, time.monotonic() + seconds)

    def test_success_closed_environment_private_cwd_and_frame(self):
        source = """import os,sys,json,struct
assert not any(k in os.environ for k in ('NODE_OPTIONS','NODE_EXTRA_CA_CERTS','HTTPS_PROXY','GH_TOKEN','ISOLATION_SENTINEL'))
assert os.environ['HOME']==os.getcwd()
assert os.stat(os.getcwd()).st_mode & 0o777 == 0o700
assert sys.stdin.buffer.read()==b'{}'
m=json.dumps({'status':302,'headers':{'location':'https://storage.invalid/?secret=SIGNED'}}).encode()
sys.stdout.buffer.write(struct.pack('!I',len(m))+m+b'ok')
"""
        inherited = {
            'ISOLATION_SENTINEL': 'offline-fixture',
            'GH_TOKEN': 'offline-fixture',  # nosec B105 - dummy credential isolation sentinel
            'HTTPS_PROXY': 'http://localhost:1', 'NODE_OPTIONS': '--bad',
        }
        with patch.dict(os.environ, inherited):
            result = adapter._decode(self.run_child(source), 'https://api.github.com/', 8)
        self.assertEqual((result.status, result.body), (302, b'ok'))

    def test_deadline_before_spawn(self):
        with patch.object(adapter.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(adapter.Refused, 'https_deadline'):
                adapter._run([], b'{}', 8, time.monotonic())
            spawn.assert_not_called()

    def test_partial_input_writes_preserve_frame(self):
        real_write = os.write
        with patch.object(adapter.os, 'write', side_effect=lambda fd, data: real_write(fd, data[:1])) as write:
            result = self.run_child('import sys,struct; assert sys.stdin.buffer.read()==b"{}"; sys.stdout.buffer.write(struct.pack("!I",2)+b"{}")')
        self.assertEqual(result, struct.pack('!I', 2) + b'{}')
        self.assertEqual(write.call_count, 2)

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

    def test_public_binding_always_refuses_without_path_access(self):
        class UntrustedPath:
            def __fspath__(self):
                raise AssertionError('path inspected')
        with patch.object(adapter, '_run') as run, patch.object(adapter.subprocess, 'Popen') as spawn:
            for candidate in ('node', '/physical/pinned/node', UntrustedPath(), None):
                with self.subTest(candidate=type(candidate).__name__):
                    with self.assertRaisesRegex(adapter.Refused, '^https_runtime_authority_unavailable$'):
                        adapter.bind(candidate)
            run.assert_not_called()
            spawn.assert_not_called()

    def test_direct_request_refuses_before_secrets_or_manifest_are_processed(self):
        with (
            patch.object(adapter.json, 'dumps', side_effect=AssertionError('serialized')) as serialize,
            patch.object(Path, 'read_text', side_effect=AssertionError('manifest read')) as manifest,
            patch.object(Path, 'open', side_effect=AssertionError('path opened')) as opened,
            patch.object(adapter, '_run') as run,
            patch.object(adapter.subprocess, 'Popen') as spawn,
        ):
            for url in ('https://api.github.com/', 'https://storage.invalid/?SECRET'):
                with self.assertRaisesRegex(adapter.Refused, '^https_runtime_authority_unavailable$') as caught:
                    adapter._request('/physical/node', url, {'Authorization': 'SECRET'}, 8, time.monotonic() + 10)
                self.assertNotIn('SECRET', str(caught.exception))
            for operation in (serialize, manifest, opened, run, spawn):
                operation.assert_not_called()

    def test_environment_cannot_enable_public_requests(self):
        with patch.dict(os.environ, {'NODE_OPTIONS': '--eval=BAD', 'GH_TOKEN': 'SECRET',
                                    'REVIEWER_HTTPS_ENABLED': '1', 'REVIEWER_NATIVE_HELPER': '/tmp/helper'}):
            with self.assertRaisesRegex(adapter.Refused, '^https_runtime_authority_unavailable$'):
                adapter.bind('/physical/node')
            with self.assertRaisesRegex(adapter.Refused, '^https_runtime_authority_unavailable$'):
                adapter._request('/physical/node', 'https://api.github.com/', {}, 8, time.monotonic() + 10)

    def test_public_binding_has_no_fixture_callback_override(self):
        with self.assertRaises(TypeError):
            adapter.bind('/physical/node', fixture=lambda: None)


if __name__ == '__main__':
    unittest.main()
