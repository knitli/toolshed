"""Bind the live assigned-stock contract family to its authorized immutable archive."""
import hashlib
import json
from pathlib import Path
import runpy
import unittest
import zipfile


PACKAGE = Path(__file__).resolve().parents[1]
FAMILY = 'assigned-stock-claude-family'
EVENT_REVISION = '39c888d07c9556ce4e0bf9cc3fb54faa3fa3a939'
CONTROL_REVISION = 'cf74332d0d9544f64a3c8bfac6ae27fbbe17ba49'
ARCHIVE = PACKAGE / 'tests/fixtures/assigned-stock-claude-family.zip'
EVENT_ONLY_SOURCES = {
    'apps/os/packages/event-runtime/src/protocol.schema.json',
    'apps/os/packages/event-runtime/__tests__/fixtures/protocol-v1.json',
}
EVENT_SNAPSHOT_SOURCES = EVENT_ONLY_SOURCES | {
    'apps/os/packages/event-runtime/src/policy.ts',
    'apps/os/packages/event-runtime/src/protocol.ts',
}


class StockContractAdoptionTests(unittest.TestCase):
    def test_live_contract_family_and_merged_source_map_are_authorized(self):
        policy = runpy.run_path(str(PACKAGE / 'tests/test_contract_workflow.py'))['POLICY']
        authorized = [entry for entry in policy['FAMILIES'] if entry['name'] == FAMILY]
        self.assertEqual(len(authorized), 1)
        family = authorized[0]
        self.assertEqual(family['eventRevision'], EVENT_REVISION)
        self.assertEqual(family['controlRevision'], CONTROL_REVISION)

        with zipfile.ZipFile(ARCHIVE) as archive:
            names = archive.namelist()
            self.assertEqual(len(names), 121)
            self.assertEqual(len(set(names)), len(names))
            metadata = json.loads(archive.read('metadata.json'))
            self.assertEqual(metadata['families'], [family])
            self.assertEqual(metadata['snapshots'], {
                FAMILY: f'prepared-export:{CONTROL_REVISION}',
            })

            control = json.loads(archive.read(
                f'snapshots/{FAMILY}/event-control-v1/manifest.json'))
            event = json.loads(archive.read(
                f'snapshots/{FAMILY}/event-v1/manifest.json'))
            self.assertEqual(control['revision'], CONTROL_REVISION)
            self.assertEqual(control['repository'], 'knitli/knitli-site')
            self.assertEqual(control['zodVersion'], '4.6.5')
            self.assertEqual(len(control['sources']), 109)
            self.assertEqual(event['commit'], EVENT_REVISION)

            source_maps = metadata['sources']
            self.assertEqual(set(source_maps), {EVENT_REVISION, CONTROL_REVISION})
            self.assertEqual(len(source_maps[CONTROL_REVISION]), 109)
            self.assertEqual(set(source_maps[CONTROL_REVISION]), set(control['sources']))
            self.assertEqual(len(source_maps[EVENT_REVISION]), 4)
            self.assertEqual(set(source_maps[EVENT_REVISION]), EVENT_SNAPSHOT_SOURCES)
            for revision, source_map in source_maps.items():
                for path, expected in source_map.items():
                    with self.subTest(revision=revision, source=path):
                        source = archive.read(f'sources/{revision}/{path}')
                        self.assertEqual(hashlib.sha256(source).hexdigest(), expected)
                        if revision == CONTROL_REVISION:
                            self.assertEqual(control['sources'][path], expected)

            control_fixtures = archive.read(
                f'snapshots/{FAMILY}/event-control-v1/fixtures.json')
            self.assertEqual(hashlib.sha256(control_fixtures).hexdigest(),
                             control['fixturesSha256'])

            for path, expected in family['hashes'].items():
                with self.subTest(snapshot=path):
                    live = (PACKAGE / 'contracts' / path).read_bytes()
                    archived = archive.read(f'snapshots/{FAMILY}/{path}')
                    self.assertEqual(live, archived)
                    self.assertEqual(hashlib.sha256(live).hexdigest(), expected)


if __name__ == '__main__':
    unittest.main()
