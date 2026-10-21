"""Bind the live assigned-stock contract family to its authorized immutable archive."""
import hashlib
import json
from pathlib import Path
import runpy
import unittest
import zipfile


PACKAGE = Path(__file__).resolve().parents[1]
FAMILY = 'assigned-stock-github-delivery'
REVISION = '9503b8e2a99fbe099a4b90cb576a17dcf4b786aa'
ARCHIVE = PACKAGE / 'tests/fixtures/assigned-stock-contract-family.zip'
EVENT_ONLY_SOURCES = {
    'apps/os/packages/event-runtime/src/protocol.schema.json',
    'apps/os/packages/event-runtime/__tests__/fixtures/protocol-v1.json',
}


class StockContractAdoptionTests(unittest.TestCase):
    def test_live_contract_family_and_merged_source_map_are_authorized(self):
        policy = runpy.run_path(str(PACKAGE / 'tests/test_contract_workflow.py'))['POLICY']
        authorized = [entry for entry in policy['FAMILIES'] if entry['name'] == FAMILY]
        self.assertEqual(len(authorized), 1)
        family = authorized[0]
        self.assertEqual(family['eventRevision'], REVISION)
        self.assertEqual(family['controlRevision'], REVISION)

        with zipfile.ZipFile(ARCHIVE) as archive:
            names = archive.namelist()
            self.assertEqual(len(names), 118)
            self.assertEqual(len(set(names)), len(names))
            metadata = json.loads(archive.read('metadata.json'))
            self.assertEqual(metadata['families'], [family])
            self.assertEqual(metadata['snapshots'], {
                FAMILY: f'prepared-export:{REVISION}',
            })

            control = json.loads(archive.read(
                f'snapshots/{FAMILY}/event-control-v1/manifest.json'))
            event = json.loads(archive.read(
                f'snapshots/{FAMILY}/event-v1/manifest.json'))
            self.assertEqual(control['revision'], REVISION)
            self.assertEqual(control['repository'], 'knitli/knitli-site')
            self.assertEqual(control['zodVersion'], '4.6.5')
            self.assertEqual(len(control['sources']), 108)
            self.assertEqual(event['commit'], REVISION)

            source_map = metadata['sources'][REVISION]
            self.assertEqual(len(source_map), 110)
            self.assertEqual(set(source_map), set(control['sources']) | EVENT_ONLY_SOURCES)
            for path, expected in source_map.items():
                with self.subTest(source=path):
                    source = archive.read(f'sources/{REVISION}/{path}')
                    self.assertEqual(hashlib.sha256(source).hexdigest(), expected)
                    if path in control['sources']:
                        self.assertEqual(control['sources'][path], expected)

            for path, expected in family['hashes'].items():
                with self.subTest(snapshot=path):
                    live = (PACKAGE / 'contracts' / path).read_bytes()
                    archived = archive.read(f'snapshots/{FAMILY}/{path}')
                    self.assertEqual(live, archived)
                    self.assertEqual(hashlib.sha256(live).hexdigest(), expected)


if __name__ == '__main__':
    unittest.main()
