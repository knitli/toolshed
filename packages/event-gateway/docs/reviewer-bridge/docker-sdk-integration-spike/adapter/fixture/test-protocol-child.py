"""Local synthetic-child tests; no SDK, Docker, provider, or network."""
import importlib.util
import io
import json
from pathlib import Path
import sys
import subprocess  # nosec B404 - Fixed interpreter and owned offline child, no shell.
import tempfile
import unittest
from unittest.mock import patch

CHILD = Path(__file__).with_name('protocol-child.py')
SESSION = '12345678-1234-1234-1234-123456789abc'
DIGEST = 'a' * 64
INITIALIZE = {'type': 'control_request', 'request_id': 'host-1', 'request': {
    'subtype': 'initialize', 'sdkMcpServers': ['frozen']}}
USER = {'type': 'user', 'message': {'role': 'user', 'content':
    f'Review frozen snapshot {DIGEST}. Read all 3 pages, then return the report.'}}


def response(number, body):
    return {'type': 'control_response', 'response': {'subtype': 'success',
            'request_id': f'offline-{number}', 'response': {'mcp_response': body}}}


def frames():
    result = [INITIALIZE, USER, response(1, {'result': {}}), response(2, {})]
    for index, unit in enumerate(['manifest', 'diff', 'file:0:after']):
        result.append(response(index + 3, {'result': {'content': [{'type': 'text', 'text':
            json.dumps({'snapshotSha256': DIGEST, 'unit': unit, 'remaining': 2 - index,
                        'text': 'synthetic café'})}]}}))
    return result


def encode(values):
    return b''.join((json.dumps(value) + '\n').encode() for value in values)


class ProtocolTests(unittest.TestCase):
    def launch(self, mode, raw, session=SESSION):
        with tempfile.TemporaryDirectory() as scratch:
            return subprocess.run(  # nosec B603 - Fixed interpreter and private child, no shell.
                [sys.executable, '-I', '-B', str(CHILD), mode, session],
                input=raw, capture_output=True, timeout=3, cwd=scratch,
                env={'HOME': scratch, 'TMPDIR': scratch, 'PATH': '/usr/bin:/bin'})

    def test_success(self):
        completed = self.launch('success', encode(frames()))
        self.assertEqual(completed.returncode, 0, completed.stderr)
        output = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(len(output), 8)
        self.assertEqual(output[0]['response']['request_id'], 'host-1')
        self.assertEqual(output[1]['session_id'], SESSION)
        requests = [frame['request']['message'] for frame in output if frame['type'] == 'control_request']
        self.assertEqual([frame['method'] for frame in requests],
                         ['initialize', 'notifications/initialized'] + ['tools/call'] * 3)
        self.assertTrue(all(frame['params'] == {'name': 'read_next', 'arguments': {}} for frame in requests[2:]))
        report = json.loads(output[-1]['result'])
        self.assertEqual(report, {'schema': 'knitli-review-report:v1', 'snapshotSha256': DIGEST,
            'findings': [], 'limitations': ['Synthetic in-memory process; not a provider review']})
        self.assertNotIn(b'synthetic caf', completed.stdout)

    def test_early_terminal_and_eof(self):
        early = self.launch('early-terminal', encode(frames()[:4]))
        self.assertEqual(early.returncode, 0)
        output = [json.loads(line) for line in early.stdout.splitlines()]
        self.assertEqual(output[-1]['type'], 'result')
        self.assertNotIn(b'tools/call', early.stdout)
        eof = self.launch('eof', encode([INITIALIZE, USER]))
        self.assertEqual(eof.returncode, 0)
        self.assertEqual([json.loads(line)['type'] for line in eof.stdout.splitlines()], ['control_response', 'system'])

    def test_digest_fallback(self):
        values = frames()
        values[1] = {'type': 'user', 'message': {'content': 'Synthetic prompt without digest'}}
        completed = self.launch('success', encode(values))
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(json.loads(json.loads(completed.stdout.splitlines()[-1])['result'])['snapshotSha256'], DIGEST)

    def test_abort_waits_after_eof_and_terminates(self):
        with tempfile.TemporaryDirectory() as scratch:
            child = subprocess.Popen(  # nosec B603 - Fixed interpreter and private child, no shell.
                [sys.executable, '-I', '-B', str(CHILD), 'abort', SESSION],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=scratch, env={'HOME': scratch, 'TMPDIR': scratch, 'PATH': '/usr/bin:/bin'})
            try:
                child.stdin.write(encode([INITIALIZE, USER]))
                child.stdin.close()
                self.assertEqual(json.loads(child.stdout.readline())['type'], 'control_response')
                self.assertEqual(json.loads(child.stdout.readline())['type'], 'system')
                with self.assertRaises(subprocess.TimeoutExpired):
                    child.wait(timeout=0.1)
                child.terminate()
                self.assertEqual(child.wait(timeout=2), -15)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                child.stdout.close()
                child.stderr.close()

    def test_invalid_arguments(self):
        for mode, session in [('unknown', SESSION), ('success', '../bad'), ('success', SESSION.upper())]:
            self.assertEqual(self.launch(mode, b'', session).returncode, 2)

    def test_invalid_frames(self):
        cases = [b'{"type":"user","type":"user"}\n', b'\xff\n', b'{}', b'\n',
                 b'[]\n', b'{"x":NaN}\n', b' ' * (64 * 1024) + b'\n',
                 encode([USER]), encode([INITIALIZE, INITIALIZE]),
                 encode([INITIALIZE, USER, response(99, {})])]
        wrong_page = frames()
        wrong_page[-1] = response(5, {'result': {'content': [{'type': 'text', 'text': json.dumps({
            'snapshotSha256': 'b' * 64, 'unit': 'file:0:after', 'remaining': 0})}]}})
        cases.append(encode(wrong_page))
        for raw in cases:
            with self.subTest(size=len(raw)):
                completed = self.launch('success', raw)
                self.assertEqual(completed.returncode, 2)
                self.assertEqual(completed.stderr, b'synthetic protocol refused\n')

    def test_remaining_rejects_booleans_and_accepts_integers(self):
        for remaining, page_index, expected_code in [(False, 2, 2), (True, 1, 2), (0, 2, 0), (1, 1, 0)]:
            with self.subTest(remaining=remaining, value_type=type(remaining).__name__):
                values = frames()
                content = values[4 + page_index]['response']['response']['mcp_response']['result']['content'][0]
                page = json.loads(content['text'])
                page['remaining'] = remaining
                content['text'] = json.dumps(page)
                completed = self.launch('success', encode(values))
                self.assertEqual(completed.returncode, expected_code, completed.stderr)
                if expected_code:
                    self.assertEqual(completed.stderr, b'synthetic protocol refused\n')
                    self.assertNotIn(b'"type":"result"', completed.stdout)
                else:
                    self.assertEqual(json.loads(completed.stdout.splitlines()[-1])['type'], 'result')

    def test_total_input_bound(self):
        values = frames()
        for value in values:
            value['padding'] = 'x' * 44000
        completed = self.launch('success', encode(values))
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn(b'"type":"result"', completed.stdout)

    def test_output_bounds(self):
        spec = importlib.util.spec_from_file_location('protocol_child', CHILD)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        child = module.Child('success', SESSION)

        class Output:
            buffer = io.BytesIO()
        with patch.object(module.sys, 'stdout', Output()):
            with self.assertRaises(ValueError):
                child.emit({'value': 'x' * module.LINE})
            child.output_bytes = module.LIMIT - 1
            with self.assertRaises(ValueError):
                child.emit({})


if __name__ == '__main__':
    unittest.main()
