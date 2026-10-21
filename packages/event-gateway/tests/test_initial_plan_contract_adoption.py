"""Keep the historical initial-plan/material contract adoption assertions immutable."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
import zipfile


PACKAGE = Path(__file__).resolve().parents[1]
ARCHIVE = PACKAGE / 'tests/fixtures/trusted-contract-families.zip'
INITIAL_CUSTODY = 'github-initial-custody'
INITIAL_PLAN = 'github-initial-plan-material'
MATERIAL_PARITY = 'github-material-page-parity'
MATERIAL_REVISION = '5d3c326677bab6cb8ac3115dcbc65e7956676ba9'


class InitialPlanContractAdoptionTests(unittest.TestCase):
    def test_historical_material_page_parity_matches_its_archived_authorization(self):
        policy = runpy.run_path(str(PACKAGE / 'tests/test_contract_workflow.py'))['POLICY']
        families = [entry for entry in policy['FAMILIES'] if entry['name'] == MATERIAL_PARITY]
        self.assertEqual(len(families), 1)
        with zipfile.ZipFile(ARCHIVE) as archive:
            metadata = json.loads(archive.read('metadata.json'))
            self.assertIn(families[0], metadata['families'])
            for path in policy['PATHS']:
                with self.subTest(path=path):
                    snapshot = archive.read(f'snapshots/{MATERIAL_PARITY}/{path}')
                    self.assertEqual(hashlib.sha256(snapshot).hexdigest(), families[0]['hashes'][path])

    def test_historical_initial_plan_control_pin_and_source_provenance(self):
        with zipfile.ZipFile(ARCHIVE) as archive:
            control = json.loads(archive.read(
                f'snapshots/{INITIAL_PLAN}/event-control-v1/manifest.json'))
            previous = json.loads(archive.read(
                f'snapshots/{INITIAL_CUSTODY}/event-control-v1/manifest.json'))
            self.assertEqual(control['repository'], 'knitli/knitli-site')
            self.assertEqual(control['revision'], MATERIAL_REVISION)
            self.assertEqual(control['zodVersion'], '4.6.5')
            self.assertEqual(len(control['sources']), 57)
            additions = {f'apps/os/packages/event-runtime/src/github/{name}' for name in (
                'reconciliation-planner.ts', 'initial-plan-material-read.ts')}
            self.assertEqual(set(control['sources']), set(previous['sources']) | additions)
            for path, expected in control['sources'].items():
                with self.subTest(source=path):
                    source = archive.read(f'sources/{MATERIAL_REVISION}/{path}')
                    self.assertEqual(hashlib.sha256(source).hexdigest(), expected)
            fixtures = archive.read(f'snapshots/{INITIAL_PLAN}/event-control-v1/fixtures.json')
            self.assertEqual(hashlib.sha256(fixtures).hexdigest(), control['fixturesSha256'])

    def test_historical_initial_plan_material_vectors_and_semantic_verdicts(self):
        with zipfile.ZipFile(ARCHIVE) as archive:
            initial_plan_fixtures = json.loads(archive.read(
                f'snapshots/{INITIAL_PLAN}/event-control-v1/fixtures.json'))
            initial_custody_fixtures = json.loads(archive.read(
                f'snapshots/{INITIAL_CUSTODY}/event-control-v1/fixtures.json'))
            parity = json.loads(archive.read(
                f'snapshots/{MATERIAL_PARITY}/event-control-v1/fixtures.json'))
            material = parity.pop('githubMaterialRead')
            self.assertEqual(parity, initial_plan_fixtures)
            self.assertEqual(initial_plan_fixtures, initial_custody_fixtures)
            self.assertEqual(tuple(len(material[key]) for key in ('requests', 'results', 'bindings')),
                             (11, 15, 7))
            corpus_bytes = archive.read(f'snapshots/{INITIAL_CUSTODY}/event-v1/protocol-v1.json')
            initial_plan_corpus = archive.read(f'snapshots/{INITIAL_PLAN}/event-v1/protocol-v1.json')
            parity_corpus = archive.read(f'snapshots/{MATERIAL_PARITY}/event-v1/protocol-v1.json')
        self.assertEqual(corpus_bytes, initial_plan_corpus)
        self.assertEqual(parity_corpus, corpus_bytes)
        vectors = json.loads(corpus_bytes)['semanticVectors']
        self.assertEqual(sum(len(vectors[key]) for key in ('rawCases', 'digestCases', 'bindingCases')), 45)
        check = runpy.run_path(str(PACKAGE / 'scripts/check_semantic_vectors.py'))['check']
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'protocol-v1.json'
            corpus.write_bytes(corpus_bytes)
            with contextlib.redirect_stdout(io.StringIO()) as output:
                check(corpus)
        self.assertEqual(output.getvalue().strip(), 'PASS: 45 canonical semantic verdicts')


if __name__ == '__main__':
    unittest.main()
