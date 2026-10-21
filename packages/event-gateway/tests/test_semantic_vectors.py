import json
from pathlib import Path
import subprocess  # nosec B404 - Fixed interpreter and owned semantic fixture, no shell.
import sys
import tempfile
import unittest


def run_synthetic_corpus(document):
    script = Path(__file__).resolve().parents[1] / 'scripts/check_semantic_vectors.py'
    with tempfile.TemporaryDirectory() as directory:
        corpus = Path(directory) / 'vectors.json'
        corpus.write_text(json.dumps(document))
        return subprocess.run(  # nosec B603 - Fixed interpreter and synthetic corpus path.
            [sys.executable, '-O', str(script), str(corpus)],
            capture_output=True, text=True, timeout=10)


class SemanticVectorScriptTests(unittest.TestCase):
    def test_synthetic_stock_ack_binding_rejects_observed_status(self):
        profile = {'profile': 'assigned_stock_client', 'client': 'codex',
                   'conversationId': '12345678-1234-4234-8234-123456789abc'}
        envelope = {
            'eventId': 'event', 'deliveryId': 'delivery', 'attemptId': 'attempt',
            'principal': 'principal', 'agent': 'agent', 'runtimeId': 'runtime',
            'nodeGeneration': 1, 'runtimeGeneration': 2, 'attachmentGeneration': 3,
            'consumerGeneration': 3, 'runtimeProfile': profile, 'sourceStateVersion': 'source',
        }
        acknowledgment = {
            **{key: envelope[key] for key in (
                'eventId', 'deliveryId', 'attemptId', 'principal', 'agent', 'runtimeId',
                'nodeGeneration', 'runtimeGeneration', 'attachmentGeneration',
                'consumerGeneration', 'runtimeProfile',
            )},
            'status': 'command_accepted', 'deliveredSourceStateVersion': 'source',
        }
        vectors = {
            'schemaVersion': 1, 'rawCases': [], 'digestCases': [],
            'bindingCases': [
                {'case': 'stock-command-accepted', 'envelope': envelope,
                 'acknowledgment': acknowledgment, 'currentSourceStateVersion': 'source',
                 'matches': True, 'advances': True},
                {'case': 'stock-observed-status', 'envelope': envelope,
                 'acknowledgment': dict(acknowledgment, status='observed'),
                 'currentSourceStateVersion': 'source', 'matches': False, 'advances': False},
            ],
        }
        result = run_synthetic_corpus(vectors)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'PASS: 2 canonical semantic verdicts')

    def test_optimized_driver_rejects_wrong_verdict(self):
        vectors = {'schemaVersion': 1, 'rawCases': [
            {'case': 'invalid-json', 'kind': 'envelope', 'raw': '{', 'nowMs': 0, 'expectedError': None},
        ], 'digestCases': [], 'bindingCases': []}
        for document in (vectors, {'semanticVectors': vectors}):
            with self.subTest(embedded='semanticVectors' in document):
                result = run_synthetic_corpus(document)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('invalid-json', result.stderr)

    def test_vendored_protocol_executes_all_45_semantic_vectors(self):
        package = Path(__file__).resolve().parents[1]
        corpus = package / 'contracts/event-v1/protocol-v1.json'
        document = json.loads(corpus.read_text())
        self.assertIn('semanticVectors', document, 'Vendored protocol fixture must include the shared semantic corpus')
        vectors = document['semanticVectors']
        self.assertEqual(sum(len(vectors[key]) for key in ('rawCases', 'digestCases', 'bindingCases')), 45)
        result = subprocess.run(  # nosec B603 - Fixed interpreter and owned vendored fixture.
            [sys.executable, str(package / 'scripts/check_semantic_vectors.py'), str(corpus)],
            capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'PASS: 45 canonical semantic verdicts')

    def test_malformed_embedded_corpus_does_not_fall_back_to_outer_vectors(self):
        for embedded in (None, [], 'invalid', True, {}, {'schemaVersion': 2}):
            with self.subTest(embedded=embedded):
                document = {'schemaVersion': 1, 'rawCases': [], 'digestCases': [],
                            'bindingCases': [], 'semanticVectors': embedded}
                result = run_synthetic_corpus(document)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn('PASS:', result.stdout)
                self.assertIn('ValueError: unsupported semantic corpus version', result.stderr)


if __name__ == '__main__':
    unittest.main()
