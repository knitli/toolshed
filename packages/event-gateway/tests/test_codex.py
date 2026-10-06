import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from websockets.asyncio.server import unix_serve
from websockets.exceptions import ConnectionClosed

from event_gateway.codex import CodexAdapter, CodexError, CodexRpc, MAX_MESSAGE, _native_id


class CodexTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # mkdtemp creates a private 0700 directory; short paths fit Unix sockets.
        temporary_root = '/private/tmp' if Path('/private/tmp').is_dir() else '/tmp'  # nosec B108
        self.temp = tempfile.TemporaryDirectory(dir=temporary_root)
        self.path = str(Path(self.temp.name) / 'native.sock')
        self.requests = []
        self.responses = {}
        self.delay = 0
        self.malformed = False
        self.server_action = False
        self.action_reply = None
        self.handler_errors = []
        self.boolean_response_id = False
        self.user_agent = 'knitli_event_gateway/0.160.1'
        self.server = await unix_serve(self.handler, self.path, max_size=MAX_MESSAGE, close_timeout=0)
        os.chmod(self.path, 0o600)

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.temp.cleanup()
        self.assertEqual(self.handler_errors, [], "unexpected native fixture handler error")

    async def handler(self, ws):
        try:
            async for raw in ws:
                request = json.loads(raw)
                self.requests.append(request)
                if 'method' not in request:
                    self.action_reply = request
                    continue
                if 'id' not in request:
                    continue
                await asyncio.sleep(self.delay)
                if request['method'] == 'initialize':
                    result = {'userAgent': self.user_agent}
                else:
                    if self.server_action:
                        await ws.send(json.dumps({'id': 77, 'method': 'item/commandExecution/requestApproval', 'params': {}}))
                    result = self.responses.get(request['method'], {})
                if self.malformed:
                    await ws.send('[]')
                else:
                    if self.boolean_response_id:
                        await ws.send(json.dumps({'id': True, 'error': {'code': -1}}))
                    await ws.send(json.dumps({'id': request['id'], 'result': result}))
        except ConnectionClosed:
            # Fault fixtures intentionally disconnect or time out the peer.
            return
        except Exception as exc:
            self.handler_errors.append(exc)

    def adapter(self, verifier=None):
        return CodexAdapter({'nativeSocket': self.path, 'nativeThreadId': 'thread-A'},
                            test_presence_verifier=verifier)

    async def present(self, mapping):
        return True

    async def test_native_id_rule_matches_receipt_boundaries(self):
        for value in ('A', 'receipt.part:1-2_3', 'a' * 128):
            with self.subTest(valid=value):
                self.assertEqual(_native_id(value), value)
        for value in ('_receipt', '-receipt', 'a' * 129, '', 'a b', None, True):
            with self.subTest(invalid=value):
                with self.assertRaisesRegex(CodexError, 'invalid_native_response'):
                    _native_id(value)

    async def test_invalid_mapping_has_bounded_error(self):
        mappings = [None, [], {}, {'nativeSocket': self.path},
                    {'nativeThreadId': 'thread-A'},
                    {'nativeSocket': None, 'nativeThreadId': 'thread-A'},
                    {'nativeSocket': 42, 'nativeThreadId': 'thread-A'},
                    {'nativeSocket': 'relative.sock', 'nativeThreadId': 'thread-A'},
                    {'nativeSocket': self.path, 'nativeThreadId': None},
                    {'nativeSocket': self.path, 'nativeThreadId': '_thread'}]
        for mapping in mappings:
            with self.subTest(mapping=mapping):
                with self.assertRaisesRegex(CodexError, 'invalid_native_mapping'):
                    CodexAdapter(mapping)
        self.assertEqual(self.requests, [])

    async def test_initialize_read_and_refuse_actions(self):
        self.server_action = True
        self.responses['server/diagnostics'] = {'process': {'id': 123}}
        result = await CodexRpc(self.path).call('server/diagnostics', {})
        await asyncio.sleep(0.01)
        self.assertEqual(result['process']['id'], 123)
        self.assertEqual([r.get('method') for r in self.requests[:3]],
                         ['initialize', 'initialized', 'server/diagnostics'])
        self.assertEqual(self.action_reply['error']['code'], -32601)

    async def test_boolean_response_id_is_not_initialize_id(self):
        self.boolean_response_id = True
        self.assertEqual(await CodexRpc(self.path).call('server/diagnostics', {}), {})

    async def test_user_agent_admits_only_probed_gateway_versions(self):
        for version in ('0.160.0', '0.160.1'):
            self.user_agent = f'knitli_event_gateway/{version} (Mac OS)'
            self.assertEqual(await CodexRpc(self.path).call('server/diagnostics', {}), {})
        for agent in ('codex/0.160.1', 'knitli_event_gateway/0.160.10'):
            self.user_agent = agent
            with self.assertRaisesRegex(CodexError, 'unsupported_native_version'):
                await CodexRpc(self.path).call('server/diagnostics', {})

    async def test_production_presence_blocks_before_connection(self):
        adapter = self.adapter()
        self.assertEqual(await adapter.check(), 'unavailable')
        with self.assertRaisesRegex(CodexError, 'unproven_client_presence'):
            await adapter.submit({'deliveryId': 'delivery-A'})
        self.assertEqual(self.requests, [])

    async def test_presence_loss_after_read(self):
        calls = 0

        async def presence(mapping):
            nonlocal calls
            calls += 1
            return calls == 1

        self.responses['thread/read'] = {'thread': {'id': 'thread-A', 'status': {'type': 'idle'}}}
        self.assertEqual(await self.adapter(presence).check(), 'unavailable')
        self.assertEqual(calls, 2)

    async def test_states_and_wrong_thread(self):
        adapter = self.adapter(self.present)
        for state, expected in [('idle', 'available'), ('active', 'busy'), ('notLoaded', 'unavailable')]:
            self.responses['thread/read'] = {'thread': {'id': 'thread-A', 'status': {'type': state}}}
            self.assertEqual(await adapter.check(), expected)
        self.responses['thread/read']['thread']['id'] = 'thread-B'
        self.assertEqual(await adapter.check(), 'unavailable')

    async def test_submit_metadata_and_correlation(self):
        self.responses['thread/queue/add'] = {'queuedSubmission': {'id': 'submission-A', 'clientUserMessageId': 'delivery-A'}}
        result = await self.adapter(self.present).submit({'deliveryId': 'delivery-A', 'eventId': 'event-A',
            'prompt': 'UNTRUSTED BODY', 'eventReference': 'ref-A'})
        self.assertEqual(result, {'submission_id': 'submission-A'})
        params = self.requests[-1]['params']
        self.assertEqual(params['clientUserMessageId'], 'delivery-A')
        self.assertNotIn('UNTRUSTED BODY', params['input'][0]['text'])
        self.responses['thread/queue/add']['queuedSubmission']['clientUserMessageId'] = 'other'
        with self.assertRaisesRegex(CodexError, 'invalid_native_response'):
            await self.adapter(self.present).submit({'deliveryId': 'delivery-A'})

    async def test_reconcile_queue_and_completed_without_final(self):
        adapter = self.adapter(self.present)
        self.responses['thread/queue/list'] = {'data': [{'id': 'submission-A', 'clientUserMessageId': 'delivery-A'}]}
        self.assertEqual((await adapter.reconcile('delivery-A'))['status'], 'submitted')
        self.responses['thread/queue/list'] = {'data': []}
        self.responses['thread/turns/list'] = {'data': [{'id': 'turn-A', 'status': 'completed',
            'items': [{'type': 'userMessage', 'clientId': 'other'}]}]}
        self.assertEqual(await adapter.reconcile('delivery-A'), {'status': 'unknown'})
        self.responses['thread/turns/list']['data'][0]['items'][0]['clientId'] = 'delivery-A'
        self.assertEqual(await adapter.reconcile('delivery-A'), {'status': 'unknown', 'turn_id': 'turn-A'})
        self.assertEqual(await adapter.reconcile('delivery-A', known_submission_id='submission-A'),
                         {'status': 'observed', 'turn_id': 'turn-A', 'submission_id': 'submission-A'})
        self.responses['thread/turns/list']['data'][0]['items'][0]['clientId'] = 'other'
        self.assertEqual(await adapter.reconcile('delivery-A', known_submission_id='submission-A'),
                         {'status': 'unknown'})

    async def test_pagination_bounded_and_no_retry(self):
        self.responses['thread/queue/list'] = {'data': [], 'nextCursor': 'again'}
        self.responses['thread/turns/list'] = {'data': [], 'nextCursor': 'again'}
        self.assertEqual(await self.adapter(self.present).reconcile('delivery-A'), {'status': 'unknown'})
        methods = [r.get('method') for r in self.requests]
        self.assertEqual(methods.count('thread/turns/list'), 10)
        self.assertEqual(methods.count('thread/queue/list'), 10)
        self.assertNotIn('thread/queue/add', methods)

    async def test_deadline_includes_initialize(self):
        self.delay = 0.04
        with patch('event_gateway.codex.RPC_SECONDS', 0.06):
            with self.assertRaisesRegex(CodexError, 'native_timeout'):
                await CodexRpc(self.path).call('server/diagnostics', {})

    async def test_malformed_response_and_oversize(self):
        self.malformed = True
        with self.assertRaisesRegex(CodexError, 'invalid_native_response'):
            await CodexRpc(self.path).call('server/diagnostics', {})
        self.malformed = False
        self.responses['server/diagnostics'] = {'data': 'x' * MAX_MESSAGE}
        with self.assertRaisesRegex(CodexError, 'native_transport_failed'):
            await CodexRpc(self.path).call('server/diagnostics', {})

    async def test_socket_permissions_symlink_and_method_rejection(self):
        # Deliberately insecure negative fixture: production must reject it.
        os.chmod(self.path, 0o666)  # nosec B103
        with self.assertRaisesRegex(CodexError, 'unsafe_native_socket'):
            await CodexRpc(self.path).call('server/diagnostics', {})
        os.chmod(self.path, 0o600)
        link = str(Path(self.temp.name) / 'alias.sock')
        os.symlink(self.path, link)
        with self.assertRaisesRegex(CodexError, 'unsafe_native_socket'):
            await CodexRpc(link).call('server/diagnostics', {})
        with self.assertRaisesRegex(CodexError, 'unsupported_native_method'):
            await CodexRpc(self.path).call('turn/start', {})


if __name__ == '__main__':
    unittest.main()
