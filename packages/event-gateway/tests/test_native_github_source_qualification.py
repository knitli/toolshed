"""Offline native GitHub qualification failure boundaries."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

DOCS = Path(__file__).parents[1] / 'docs/native-bridge'


def load(name):
    spec = importlib.util.spec_from_file_location(name, DOCS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FIXTURE = load('native-github-source-qualification')
HOST = load('native-host-launcher-qualification')


class NativeGitHubQualificationTests(unittest.TestCase):
    def test_actual_cli_and_signed_client_return_validated_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / 'source.json'
            source.write_text(json.dumps(FIXTURE.page('fresh-identity')))
            with redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(FIXTURE.run_cli(source), 0)
            self.assertEqual(json.loads(stdout.getvalue()), FIXTURE.page('fresh-identity'))
            witness = json.loads(source.with_suffix('.witness.json').read_text())
            self.assertTrue(witness['signatureVerified'])
            self.assertEqual(witness['syntheticTransportCalls'], 1)
            self.assertEqual(witness['realCloudCalls'], 0)

    def test_invalid_node_signature_cannot_produce_success_witness(self):
        from event_gateway.cloud import CloudClient
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / 'source.json'
            source.write_text(json.dumps(FIXTURE.page('fresh-identity')))
            with patch.object(CloudClient, '_sign', return_value='A' * 86), redirect_stdout(io.StringIO()), \
                    self.assertRaisesRegex(AssertionError, 'CLI source read failed'):
                FIXTURE.run_cli(source)
            self.assertFalse(source.with_suffix('.witness.json').exists())

    def test_invalid_response_cannot_produce_success_witness(self):
        for mutation in ('subject', 'range', 'metadata'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                source = Path(directory).resolve() / 'source.json'
                page = FIXTURE.page('fresh-identity')
                if mutation == 'subject':
                    page['subject'] = {**page['subject'], 'prNumber': 9}
                elif mutation == 'range':
                    page['requestedRange']['toVersion'] = 4
                else:
                    page['items'][0]['value']['untrusted'] = True
                source.write_text(json.dumps(page))
                with redirect_stdout(io.StringIO()), self.assertRaisesRegex(AssertionError, 'CLI source read failed'):
                    FIXTURE.run_cli(source)
                self.assertFalse(source.with_suffix('.witness.json').exists())

    def test_exact_correlated_output_and_no_initial_nonce(self):
        nonce = 'fresh-identity'
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory).resolve() / 'source.json'
            source.write_text(json.dumps(FIXTURE.page(nonce)))
            with redirect_stdout(io.StringIO()):
                FIXTURE.run_cli(source)
            output = {'type': 'custom_tool_call_output', 'call_id': HOST.CALL_ID, 'output': [
                {'text': json.dumps({'exit_code': 0, 'output': json.dumps(FIXTURE.page(nonce)) + '\n'})}]}
            requests = [{'input': []}, {'input': [output]}]
            self.assertEqual(FIXTURE.verify_output(requests, nonce, source, HOST.verify_output), output)
            requests[0]['input'] = [nonce]
            with self.assertRaises(AssertionError):
                FIXTURE.verify_output(requests, nonce, source, HOST.verify_output)

    def test_prepared_program_uses_isolated_installed_python_and_frozen_helper(self):
        helper = HOST.verified_helper('native-github-source-qualification.py')
        try:
            with tempfile.TemporaryDirectory() as directory:
                source = Path(directory).resolve() / 'source.json'
                program = helper.prepare(source, 'fresh-identity', Path('/trusted/src/event_gateway'),
                                         DOCS / 'qualification-installed.py')
                self.assertNotIn('fresh-identity', program)
                self.assertIn('-I -B', program)
                self.assertEqual(json.loads(source.read_text()), FIXTURE.page('fresh-identity'))
                bad = source.parent / 'bad.py'
                bad.write_text('raise RuntimeError()')
                with self.assertRaisesRegex(AssertionError, 'digest mismatch'):
                    helper.prepare(source, 'fresh-identity', Path('/trusted/src/event_gateway'), bad)
        finally:
            helper._private_helper.cleanup()
