"""Exercise exported assigned-stock watch schema vectors against the Gateway client."""
from copy import deepcopy
from datetime import datetime
import asyncio
import json
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from event_gateway.cloud import CloudClient, CloudError, Credentials, _stock_watch_request
from event_gateway.daemon import _watch_receipt_matches


PACKAGE = Path(__file__).resolve().parents[1]
FIXTURES = json.loads((PACKAGE / 'contracts/event-control-v1/fixtures.json').read_text())


class StockWatchContractAdoptionTests(unittest.IsolatedAsyncioTestCase):
    async def test_exported_watch_vectors_match_gateway_request_and_response_validation(self):
        contract = FIXTURES['assignedStockWatch']
        requests = {vector['name']: vector for vector in contract['requests']}
        for vector in contract['requests']:
            with self.subTest(request=vector['name']):
                if vector['accepted']:
                    self.assertEqual(_stock_watch_request(vector['value']), vector['value'])
                else:
                    with self.assertRaisesRegex(CloudError, '^invalid_request$'):
                        _stock_watch_request(vector['value'])

        by_operation = {}
        for vector in contract['requests']:
            if vector['accepted']:
                by_operation.setdefault(vector['value']['operation'], vector['value'])
        responses = {vector['name']: vector['value']['outcome']
                     for vector in contract['responses']}
        listed = responses['watch-list-page-limit']['watches']
        committed = responses['watch-renew-committed']
        known = responses['watch-readback-known']
        self.assertTrue(all(watch['attachment']['leaseRevision'] == 1 for watch in listed))
        self.assertTrue(_watch_receipt_matches(listed[0], committed['watch']))
        self.assertTrue(_watch_receipt_matches(listed[0], known['watch']))
        self.assertEqual(committed['watch'], known['watch'])
        self.assertEqual(committed['operationId'], known['operationId'])
        initial_control_operation = listed[0]['sourceControl']['operationId']
        self.assertNotEqual(initial_control_operation, committed['operationId'])
        self.assertEqual(committed['watch']['sourceControl']['operationId'], initial_control_operation)
        self.assertEqual(known['watch']['sourceControl']['operationId'], initial_control_operation)
        self.assertEqual(known['watch']['attachment']['leaseRevision'],
                         committed['watch']['attachment']['leaseRevision'])
        self.assertEqual(committed['watch']['attachment']['leaseRevision'], 2)
        self.assertIs(type(committed['watch']['attachment']['leaseUntil']), int)
        for vector in contract['responses']:
            name = vector['name']
            request = by_operation['watch_list' if name.startswith('watch-list-')
                                   else 'watch_renew' if name.startswith('watch-renew-')
                                   else 'watch_readback']
            with self.subTest(response=name):
                sent = []
                client = self.client(vector['value'], sent, vector['value'])
                if vector['accepted']:
                    self.assertEqual(await client.stock_watch(request), vector['value'])
                else:
                    with self.assertRaisesRegex(CloudError, '^invalid_response$'):
                        await client.stock_watch(request)

        # The exported unknown-field request and a response mutation pin both closed wire boundaries.
        self.assertEqual(requests['watch-unknown-field']['accepted'], False)
        with self.assertRaisesRegex(CloudError, '^invalid_response$'):
            await self.client({**contract['responses'][0]['value'], 'extra': True}, [],
                              contract['responses'][0]['value']).stock_watch(
                                  by_operation['watch_list'])
        for key in ('mappingRevision', 'policyRevision'):
            for invalid in (0, '', 'x' * 129):
                with self.subTest(revision=key, value=invalid):
                    list_response = deepcopy(contract['responses'][0]['value'])
                    malformed = list_response['outcome']['watches'][0]
                    malformed['source'][key] = invalid
                    with self.assertRaisesRegex(CloudError, '^invalid_response$'):
                        await self.client(list_response, [], list_response).stock_watch(
                            by_operation['watch_list'])

        known_value = next(vector['value'] for vector in contract['responses']
                           if vector['name'] == 'watch-readback-known')
        expired = deepcopy(known_value)
        runtime_until = datetime.fromisoformat(
            expired['runtime']['leaseUntil'].replace('Z', '+00:00')).timestamp()
        expired['outcome']['watch']['attachment']['leaseUntil'] = int(runtime_until * 1000) - 61000
        self.assertEqual(await self.client(expired, [], expired).stock_watch(
            by_operation['watch_readback']), expired)

        for mutate in ('lease', 'holder'):
            malformed = deepcopy(known_value)
            attachment = malformed['outcome']['watch']['attachment']
            if mutate == 'lease':
                attachment['leaseUntil'] += 1
            else:
                attachment['holder']['nodeGeneration'] += 1
            with self.subTest(known_receipt=mutate):
                with self.assertRaisesRegex(CloudError, '^invalid_response$'):
                    await self.client(malformed, [], malformed).stock_watch(
                        by_operation['watch_readback'])

    async def test_watch_deadlines_allow_bounded_client_clock_skew(self):
        contract = FIXTURES['assignedStockWatch']
        requests = {}
        for vector in contract['requests']:
            if vector['accepted']:
                requests.setdefault(vector['value']['operation'], vector['value'])
        # The fixtures put the watch deadline 100 seconds ahead of the client clock.
        for operation, name in (('watch_list', 'watch-list-page-limit'),
                                ('watch_renew', 'watch-renew-committed'),
                                ('watch_readback', 'watch-readback-known')):
            response = next(vector['value'] for vector in contract['responses']
                            if vector['name'] == name)
            with self.subTest(operation=operation):
                self.assertEqual(await self.client(response, [], response, clock_lag_seconds=100).stock_watch(
                    requests[operation]), response)

        response = next(vector['value'] for vector in contract['responses']
                        if vector['name'] == 'watch-readback-known')
        with self.assertRaisesRegex(CloudError, '^invalid_response$'):
            await self.client(response, [], response, clock_lag_seconds=121).stock_watch(
                requests['watch_readback'])

        past_runtime = deepcopy(response)
        past_runtime['outcome']['watch']['attachment']['leaseUntil'] += 1
        with self.assertRaisesRegex(CloudError, '^invalid_response$'):
            await self.client(past_runtime, [], past_runtime).stock_watch(requests['watch_readback'])

    async def test_renewal_and_readback_require_attached_watch_state(self):
        contract = FIXTURES['assignedStockWatch']
        requests = {}
        for vector in contract['requests']:
            if vector['accepted']:
                requests.setdefault(vector['value']['operation'], vector['value'])
        for operation, name in (('watch_renew', 'watch-renew-committed'),
                                ('watch_readback', 'watch-readback-known')):
            response = next(vector['value'] for vector in contract['responses']
                            if vector['name'] == name)
            for field, value in (('state', 'detached'), ('sourceControl', 'stopped')):
                malformed = deepcopy(response)
                watch = malformed['outcome']['watch']
                if field == 'state':
                    watch[field] = value
                else:
                    watch[field]['mode'] = value
                with self.subTest(operation=operation, field=field):
                    with self.assertRaisesRegex(CloudError, '^invalid_response$'):
                        await self.client(malformed, [], malformed).stock_watch(requests[operation])

    @staticmethod
    def client(response, sent, runtime_value, clock_lag_seconds=60):
        runtime = runtime_value['runtime']
        runtime_until = datetime.fromisoformat(runtime['leaseUntil'].replace('Z', '+00:00'))

        async def send(**kwargs):
            sent.append(kwargs)
            return 200, {'content-type': 'application/json'}, json.dumps(response).encode()

        return CloudClient(
            origin='https://events.example.com', principal='owner@example.com', agent='codex',
            node_id=runtime['nodeId'], node_generation=runtime['nodeGeneration'],
            private_key=Ed25519PrivateKey.generate(),
            credentials=lambda: asyncio.sleep(0, result=Credentials(None, 'agent-token')),
            send=send, auth_mode='gateway',
            clock=lambda: runtime_until.timestamp() - clock_lag_seconds,
        )


if __name__ == '__main__':
    unittest.main()
