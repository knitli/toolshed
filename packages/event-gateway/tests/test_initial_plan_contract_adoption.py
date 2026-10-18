"""Bind the live consumer snapshot to the authorized initial-plan archive family."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import runpy
import unittest
import zipfile


PACKAGE = Path(__file__).resolve().parents[1]
FAMILY = 'github-initial-plan-material'
REVISION = '5d3c326677bab6cb8ac3115dcbc65e7956676ba9'


class InitialPlanContractAdoptionTests(unittest.TestCase):
    def test_live_snapshot_matches_the_complete_trusted_family(self):
        policy = runpy.run_path(str(PACKAGE / 'tests/test_contract_workflow.py'))['POLICY']
        families = [entry for entry in policy['FAMILIES'] if entry['name'] == FAMILY]
        self.assertEqual(len(families), 1)
        with zipfile.ZipFile(PACKAGE / 'tests/fixtures/trusted-contract-families.zip') as archive:
            metadata = json.loads(archive.read('metadata.json'))
            self.assertIn(families[0], metadata['families'])
            for path in policy['PATHS']:
                with self.subTest(path=path):
                    live = (PACKAGE / 'contracts' / path).read_bytes()
                    self.assertEqual(live, archive.read(f'snapshots/{FAMILY}/{path}'))
                    self.assertEqual(hashlib.sha256(live).hexdigest(), families[0]['hashes'][path])

    def test_live_control_pin_contains_the_two_new_selected_sources(self):
        control = json.loads((PACKAGE / 'contracts/event-control-v1/manifest.json').read_bytes())
        self.assertEqual(control['repository'], 'knitli/knitli-site')
        self.assertEqual(control['revision'], REVISION)
        self.assertEqual(control['zodVersion'], '4.6.5')
        self.assertEqual(len(control['sources']), 57)
        with zipfile.ZipFile(PACKAGE / 'tests/fixtures/trusted-contract-families.zip') as archive:
            previous = json.loads(archive.read('snapshots/github-initial-custody/event-control-v1/manifest.json'))
            additions = {f'apps/os/packages/event-runtime/src/github/{name}' for name in (
                'reconciliation-planner.ts', 'initial-plan-material-read.ts')}
            self.assertEqual(set(control['sources']), set(previous['sources']) | additions)
            for path, expected in control['sources'].items():
                with self.subTest(source=path):
                    self.assertEqual(hashlib.sha256(archive.read(f'sources/{REVISION}/{path}')).hexdigest(), expected)

    def test_adoption_preserves_fixture_bytes_and_executes_45_semantic_verdicts(self):
        with zipfile.ZipFile(PACKAGE / 'tests/fixtures/trusted-contract-families.zip') as archive:
            for path in ('event-control-v1/fixtures.json', 'event-v1/protocol-v1.json'):
                with self.subTest(fixture=path):
                    self.assertEqual((PACKAGE / 'contracts' / path).read_bytes(),
                                     archive.read(f'snapshots/github-initial-custody/{path}'))
        corpus = PACKAGE / 'contracts/event-v1/protocol-v1.json'
        vectors = json.loads(corpus.read_bytes())['semanticVectors']
        self.assertEqual(sum(len(vectors[key]) for key in ('rawCases', 'digestCases', 'bindingCases')), 45)
        check = runpy.run_path(str(PACKAGE / 'scripts/check_semantic_vectors.py'))['check']
        with contextlib.redirect_stdout(io.StringIO()) as output:
            check(corpus)
        self.assertEqual(output.getvalue().strip(), 'PASS: 45 canonical semantic verdicts')


if __name__ == '__main__':
    unittest.main()
