"""Synthetic retained-input/Session composition; no native executable or provider."""

import asyncio
from contextlib import closing, contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from uuid import uuid4

from event_gateway.native import IDENTITY, NativeError, SessionNativeBridge
from event_gateway.native_terminal_evidence import NativeTerminalEvidenceAdapter
from event_gateway.native_terminal_inputs import collect_terminal_inputs
from test_native import ADMISSION, request
from test_native_bridge import witness
from test_native_session_proxy import session_fixture


# Independent fixture authority, not derived from the collected admission or binding.
ORIGINAL_NODE = '00000000-0000-4000-8000-000000000001'


class NativeTerminalCoupledInputsTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / 'historical.sqlite'
        self.item = {**request(), 'receiptVersion': 3}
        self.wire = {k: v for k, v in self.item.items() if k != 'receiptVersion'}
        self.row = witness()
        self.row.update({k: self.item[k] for k in (
            'clientId', 'threadId', 'generation', 'serverInstanceId', 'serverGeneration')})
        self.item_id, self.receipt_id = str(uuid4()), str(uuid4())
        self.anchor = {**{k: self.item[k] for k in (*IDENTITY, 'generation')},
                       'outcome': {'status': 'inputRecorded',
                                   'turnId': self.item['clientUserMessageId'],
                                   'itemId': self.item_id, 'replayed': True}}
        self.admission = deepcopy(ADMISSION)
        self.assertEqual(self.admission['nodeId'], ORIGINAL_NODE)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('CREATE TABLE attempts (delivery_id TEXT, attempt_id TEXT, '
                       'envelope TEXT, admission TEXT, native_request TEXT, '
                       'input_recorded_receipt TEXT)')
            db.execute('CREATE TABLE attachments (value TEXT)')
            db.execute('INSERT INTO attachments VALUES (?)', ('unrelated current attachment',))
            db.execute('INSERT INTO attempts VALUES (?,?,?,?,?,?)', (
                self.item['deliveryId'], self.item['attemptId'],
                json.dumps(self.admission['envelope']), json.dumps(self.admission),
                json.dumps(self.item), json.dumps(self.anchor)))
            db.commit()

    @contextmanager
    def original_session(self, *, item_id=None, missing_native_history=False):
        with session_fixture(self.row, persisted=None if missing_native_history else self.wire,
                             input_item_id=item_id or self.item_id,
                             terminal_receipt_id=self.receipt_id) as fixture:
            state, mapping, client, current, calls = fixture
            # Freeze the complete fixture-owned route before reading any journal data.
            route = (state, json.dumps(mapping, sort_keys=True), ORIGINAL_NODE)
            current.update(eligible=False, threadId=str(uuid4()),
                           generation=self.row['generation'] + 1)
            yield route, client, calls

    def query(self, route):
        state, frozen_mapping, original_node = route
        before = hashlib.sha256(self.path.read_bytes()).hexdigest()
        statements = []
        with closing(sqlite3.connect(f'{self.path.as_uri()}?mode=ro', uri=True)) as db:
            db.set_trace_callback(statements.append)
            try:
                saved = collect_terminal_inputs(db, self.item['deliveryId'], self.item['attemptId'])
                if saved is None or saved['admission']['nodeId'] != original_node:
                    raise NativeError('untrusted_original_node')
                # Deliberately never construct a route from saved['binding'] or attachments.
                mapping = json.loads(frozen_mapping)
                adapter = NativeTerminalEvidenceAdapter(mapping, SessionNativeBridge(state, mapping))
                return asyncio.run(adapter.terminal_evidence(
                    saved['request'], saved['input_recorded_receipt']))
            finally:
                self.assertEqual(db.total_changes, 0)
                self.assertEqual(len(statements), 1)
                self.assertTrue(statements[0].lstrip().upper().startswith('SELECT'))
                self.assertNotIn('attachments', statements[0].lower())
                self.assertEqual(hashlib.sha256(self.path.read_bytes()).hexdigest(), before)

    def test_retained_pair_uses_frozen_original_route_and_repeats_without_authority(self):
        with self.original_session() as (route, client, calls):
            with closing(sqlite3.connect(self.path)) as db:
                rotated = json.loads(route[1])
                rotated['sessionId'] = str(uuid4())
                db.execute('UPDATE attachments SET value=?', (json.dumps(rotated),))
                db.commit()
            first, second = self.query(route), self.query(route)
            self.assertEqual(first, second)
            self.assertEqual(first, {**self.anchor, 'outcome': {
                'status': 'terminal', 'turnId': self.item['clientUserMessageId'],
                'itemId': self.item_id, 'receiptId': self.receipt_id,
                'terminalStatus': 'completed', 'replayed': True}})
            self.assertEqual(calls, ['terminalEvidence', 'terminalEvidence'])
            self.assertIsNone(client.bridge.witness)
            self.assertEqual(client.bridge.valid_until, 0)
            self.assertEqual(client.bridge.terminal_attempts, set())

    def test_wrong_original_route_fails_without_wire_query(self):
        with self.original_session() as (route, _, calls):
            state, frozen_mapping, node = route
            for field in ('sessionId', 'nativeThreadId'):
                with self.subTest(field=field):
                    mapping = json.loads(frozen_mapping)
                    mapping[field] = str(uuid4())
                    with self.assertRaises((NativeError, ValueError)):
                        self.query((state, json.dumps(mapping), node))
            mapping = json.loads(frozen_mapping)
            mapping['nativeBinding']['generation'] += 1
            with self.assertRaises((NativeError, ValueError)):
                self.query((state, json.dumps(mapping), node))
            with self.assertRaises((NativeError, ValueError)):
                self.query((state / 'missing-original-state', frozen_mapping, node))
            self.assertEqual(calls, [])

    def test_collector_binding_cannot_substitute_for_original_route(self):
        with self.original_session() as (route, _, calls):
            mapping = {k: self.item[k] for k in (
                'clientId', 'generation', 'serverInstanceId', 'serverGeneration', 'threadId')}
            with self.assertRaises((NativeError, ValueError)):
                self.query((route[0], json.dumps(mapping), route[2]))
            self.assertEqual(calls, [])

    def test_wrong_original_node_fails_before_wire_query(self):
        with self.original_session() as (route, _, calls):
            with self.assertRaisesRegex(NativeError, 'untrusted_original_node'):
                self.query((route[0], route[1], str(uuid4())))
            self.assertEqual(calls, [])

    def test_missing_saved_anchor_fails_before_wire_query(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute('UPDATE attempts SET input_recorded_receipt=NULL')
            db.commit()
        with self.original_session() as (route, _, calls):
            with self.assertRaises(NativeError):
                self.query(route)
            self.assertEqual(calls, [])

    def test_native_terminal_item_must_match_retained_anchor(self):
        with self.original_session(item_id=str(uuid4())) as (route, _, calls):
            with self.assertRaises(NativeError):
                self.query(route)
            self.assertEqual(calls, ['terminalEvidence'])

    def test_missing_native_history_returns_only_unknown(self):
        with self.original_session(missing_native_history=True) as (route, _, calls):
            self.assertEqual(self.query(route), {**self.anchor, 'outcome': {'status': 'unknown'}})
            self.assertEqual(calls, ['terminalEvidence'])
