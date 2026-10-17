"""Keep the installed-client investigation reproducible from a fresh checkout."""
import hashlib
import json
from pathlib import Path
import unittest


class MuseEvidenceTests(unittest.TestCase):
    def test_committed_schema_matches_inspected_evidence(self):
        root = Path(__file__).resolve().parents[1] / 'docs/muse-ingress'
        proof = json.loads((root / 'qualification.json').read_bytes())
        raw = (root / 'msp.schema.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), proof['schemaSha256'])
        self.assertEqual(proof['schemaSha256'], '0eb3ef3ec63341b6b1f6f52ab61116e37cc59aaa6d69e9b6c265e2011e3e5931')
        manifest_raw = (root / 'schema-manifest.json').read_bytes()
        self.assertEqual(hashlib.sha256(manifest_raw).hexdigest(), proof['schemaManifestSha256'])
        self.assertFalse(proof['schemaManifestFingerprintAuthoritative'])
        schema = json.loads(raw)
        method = schema['methods']['subagent/sendMessage']
        self.assertEqual(method['description'],
                         "Queue a user note into a running child; admission-only ack, "
                         "the note settles on the child session's view stream (SS3.16).")
        self.assertEqual(method['params']['$ref'], '#/$defs/SubagentInputParams')
        self.assertEqual(method['result']['$ref'], '#/$defs/CommandAcceptedResult')
        self.assertFalse(proof['liveWakeProven'])
        self.assertEqual(proof['nativePeerList']['reason'], 'external_agent_ingress_closed')


if __name__ == '__main__':
    unittest.main()
