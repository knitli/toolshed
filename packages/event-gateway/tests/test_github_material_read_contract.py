"""Screened GitHub material fixtures are adopted by the Python wire client."""
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from event_gateway.cloud import CloudClient, CloudError, Credentials

CORPUS = json.loads((Path(__file__).resolve().parents[1] /
    'contracts/event-control-v1/fixtures.json').read_text())['githubMaterialRead']


class ScreenedMaterialContractTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.result = {'status': 'unavailable'}

        async def send(**request):
            return 200, {'content-type': 'application/json'}, json.dumps(self.result).encode()

        self.credentials = AsyncMock(return_value=Credentials('access', 'agent'))
        self.client = CloudClient(origin='https://events.example.com', principal='user@example.com',
            agent='codex', node_id='12345678-1234-4123-8123-123456789012', node_generation=1,
            private_key=Ed25519PrivateKey.generate(), credentials=self.credentials, send=send)

    async def test_producer_screened_request_verdicts(self):
        for vector in CORPUS['screenedRequests']:
            with self.subTest(vector=vector['name']):
                if vector['accepted']:
                    await self.client.github_source_material(vector['value'])
                else:
                    self.credentials.reset_mock()
                    with self.assertRaisesRegex(CloudError, '^invalid_request$'):
                        await self.client.github_source_material(vector['value'])
                    self.credentials.assert_not_called()

    async def test_producer_screened_response_verdicts(self):
        for vector in CORPUS['screenedResults']:
            self.result = vector['value']
            with self.subTest(vector=vector['name']):
                if vector['accepted']:
                    self.assertEqual(await self.client.github_source_material(CORPUS['screenedRequest']), vector['value'])
                else:
                    with self.assertRaisesRegex(CloudError, '^invalid_response$'):
                        await self.client.github_source_material(CORPUS['screenedRequest'])

    async def test_producer_screened_page_binding_verdicts(self):
        for vector in CORPUS['screenedBindings']:
            self.result = vector['result']
            with self.subTest(vector=vector['name']):
                if vector['accepted']:
                    self.assertEqual(await self.client.github_source_material(vector['request']), vector['result'])
                else:
                    with self.assertRaisesRegex(CloudError, '^invalid_response$'):
                        await self.client.github_source_material(vector['request'])


if __name__ == '__main__':
    unittest.main()
