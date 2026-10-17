"""Keep the installed-client investigation reproducible from a fresh checkout."""
import gzip
import hashlib
import json
from pathlib import Path
import unittest


class MuseEvidenceTests(unittest.TestCase):
    def test_committed_schema_matches_inspected_evidence(self):
        root = Path(__file__).resolve().parents[1] / 'docs/muse-ingress'
        proof = json.loads((root / 'qualification.json').read_bytes())
        raw = gzip.decompress((root / 'msp.schema.json.gz').read_bytes())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), proof['schemaSha256'])
        schema = json.loads(raw)
        self.assertIn('subagent/sendMessage', schema['methods'])
        self.assertFalse(proof['liveWakeProven'])
        self.assertEqual(proof['nativePeerList']['reason'], 'external_agent_ingress_closed')


if __name__ == '__main__':
    unittest.main()
