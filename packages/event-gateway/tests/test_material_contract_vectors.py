"""Producer-exported DTO and page-binding verdicts match the material client."""
import json
from pathlib import Path
import unittest
from unittest.mock import AsyncMock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from event_gateway.cloud import CloudClient, CloudError, Credentials, canonical_node_proof

CORPUS = json.loads((Path(__file__).resolve().parents[1] /
    'contracts/event-control-v1/fixtures.json').read_text())['githubMaterialRead']


class MaterialContractVectors(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.result = {'status': 'unavailable'}
        self.sent = []

        async def send(**request):
            self.sent.append(request)
            return 200, {'content-type': 'application/json'}, json.dumps(self.result).encode()

        self.credentials = AsyncMock(return_value=Credentials('access', 'agent'))
        self.client = CloudClient(origin='https://events.example.com', principal='user@example.com',
            agent='codex', node_id='12345678-1234-4123-8123-123456789012', node_generation=1,
            private_key=Ed25519PrivateKey.generate(), credentials=self.credentials, send=send)

    async def test_producer_request_verdicts(self):
        for vector in CORPUS['requests']:
            with self.subTest(vector=vector['name']):
                if vector['accepted']:
                    await self.client.github_source_material(vector['value'])
                else:
                    self.credentials.reset_mock()
                    with self.assertRaisesRegex(CloudError, '^invalid_request$'):
                        await self.client.github_source_material(vector['value'])
                    self.credentials.assert_not_called()

    async def test_producer_response_verdicts(self):
        for vector in CORPUS['results']:
            self.result = vector['value']
            with self.subTest(vector=vector['name']):
                if vector['accepted']:
                    self.assertEqual(await self.client.github_source_material(CORPUS['request']), vector['value'])
                else:
                    with self.assertRaisesRegex(CloudError, '^invalid_response$'):
                        await self.client.github_source_material(CORPUS['request'])

    async def test_producer_page_binding_verdicts(self):
        self.assertEqual((len(CORPUS['requests']), len(CORPUS['results']), len(CORPUS['bindings'])),
                         (11, 15, 7))
        for vector in CORPUS['bindings']:
            self.result = vector['result']
            with self.subTest(vector=vector['name']):
                if vector['accepted']:
                    self.assertEqual(await self.client.github_source_material(vector['request']), vector['result'])
                else:
                    with self.assertRaisesRegex(CloudError, '^invalid_response$'):
                        await self.client.github_source_material(vector['request'])

    async def test_exact_producer_signed_path(self):
        vector = CORPUS['nodeProof']
        binding = vector['binding']
        self.assertEqual(binding['path'], '/v1/github/source/material')
        self.assertEqual(canonical_node_proof(vector['principal'], binding['audience'],
            binding['path'], vector['body'].encode(), vector['proof']).decode(), vector['canonical'])
