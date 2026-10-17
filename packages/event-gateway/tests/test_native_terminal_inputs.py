import copy
from contextlib import closing
import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from event_gateway.cloud import _timestamp, validate_admission
from event_gateway.native import IDENTITY, NativeError
from event_gateway.native_terminal_inputs import collect_terminal_inputs
from test_native import ADMISSION, request


_UPDATE_JSON = {
    'envelope': 'UPDATE attempts SET envelope=?',
    'admission': 'UPDATE attempts SET admission=?',
    'native_request': 'UPDATE attempts SET native_request=?',
    'input_recorded_receipt': 'UPDATE attempts SET input_recorded_receipt=?',
}


class NativeTerminalInputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'journal.sqlite'
        self.db = sqlite3.connect(self.path)
        self.addCleanup(self.db.close)
        # Deliberately omit PK to exercise ambiguous/corrupt journal rejection.
        self.db.execute('CREATE TABLE attempts (delivery_id TEXT, attempt_id TEXT, '
                        'envelope TEXT, admission TEXT, native_request TEXT, '
                        'input_recorded_receipt TEXT)')
        self.item = {**request(), 'receiptVersion': 3}
        self.anchor = {key: self.item[key] for key in (*IDENTITY, 'generation')}
        self.anchor['outcome'] = {'status': 'inputRecorded',
                                  'turnId': self.item['clientUserMessageId'],
                                  'itemId': str(uuid.uuid4()), 'replayed': True}
        self.save()

    def save(self, admission=None, item=None, anchor=None):
        self.db.execute('DELETE FROM attempts')
        self.db.execute('INSERT INTO attempts VALUES (?,?,?,?,?,?)', (
            self.item['deliveryId'], self.item['attemptId'],
            json.dumps(ADMISSION['envelope']),
            json.dumps(ADMISSION if admission is None else admission),
            json.dumps(self.item if item is None else item),
            json.dumps(self.anchor if anchor is None else anchor)))
        self.db.commit()

    def collect(self):
        with closing(sqlite3.connect(f'{self.path.as_uri()}?mode=ro', uri=True)) as connection:
            return collect_terminal_inputs(connection, self.item['deliveryId'], self.item['attemptId'])

    def reject(self):
        with self.assertRaisesRegex(NativeError, '^invalid_native_terminal_inputs$'):
            self.collect()

    def test_original_saved_pair_and_binding_read_only_single_select(self):
        connection = sqlite3.connect(f'{self.path.as_uri()}?mode=ro', uri=True)
        self.addCleanup(connection.close)
        statements = []
        connection.row_factory = sqlite3.Row
        connection.set_trace_callback(statements.append)
        result = collect_terminal_inputs(connection, self.item['deliveryId'], self.item['attemptId'])
        self.assertEqual(result['request'], self.item)
        self.assertEqual(result['admission'], ADMISSION)
        self.assertEqual(result['input_recorded_receipt'], self.anchor)
        self.assertEqual(result['binding'], {key: self.item[key] for key in (
            'clientId', 'generation', 'serverInstanceId', 'serverGeneration', 'threadId')})
        self.assertEqual(len(statements), 1)
        self.assertTrue(statements[0].lstrip().upper().startswith('SELECT'))
        self.assertEqual(connection.total_changes, 0)

    def test_absent_exact_attempt_is_unknown(self):
        self.db.execute('DELETE FROM attempts')
        self.db.commit()
        self.assertIsNone(self.collect())

    def test_other_attempt_is_not_reconstructed(self):
        self.db.execute('UPDATE attempts SET attempt_id=?', (str(uuid.uuid4()),))
        self.db.commit()
        self.assertIsNone(self.collect())

    def test_all_echoed_identities_must_match(self):
        for key in (*IDENTITY, 'generation'):
            with self.subTest(key=key):
                anchor = copy.deepcopy(self.anchor)
                anchor[key] = anchor[key] + 1 if isinstance(anchor[key], int) else 'changed'
                self.save(anchor=anchor)
                self.reject()

    def test_each_admission_event_field_must_match(self):
        for key in self.item['event']:
            with self.subTest(key=key):
                admission = copy.deepcopy(ADMISSION)
                admission['envelope'][key] = 'changed'
                self.save(admission=admission)
                self.reject()

    def test_admission_envelope_must_match_independent_saved_envelope(self):
        for key, value in (('principal', 'other@knitli.com'), ('agent', 'other-agent'),
                           ('policyRevision', 2)):
            with self.subTest(key=key):
                admission = copy.deepcopy(ADMISSION)
                admission['envelope'][key] = value
                # Each altered envelope is individually valid and does not change
                # the narrower native-request identity. Only the independent row
                # envelope can reject this mismatch.
                validate_admission(admission, admission['envelope'],
                                   now_ms=_timestamp(admission['permitIssuedAt']))
                self.save(admission=admission)
                self.reject()

    def test_independent_saved_envelope_tampering_is_rejected(self):
        envelope = {**ADMISSION['envelope'], 'principal': 'other@knitli.com'}
        self.db.execute(_UPDATE_JSON['envelope'], (json.dumps(envelope),))
        self.db.commit()
        self.reject()

    def test_request_admission_and_row_identities_must_match(self):
        for key in ('attemptId', 'deliveryId', 'permitId', 'permitIssuedAt', 'permitExpiresAt'):
            with self.subTest(key=key):
                item = copy.deepcopy(self.item)
                item[key] = item[key] + 1 if isinstance(item[key], int) else str(uuid.uuid4())
                self.save(item=item)
                self.reject()
        self.save()
        self.db.execute('UPDATE attempts SET delivery_id=?', ('dly_' + 'f' * 64,))
        self.db.commit()
        with self.assertRaises(NativeError):
            collect_terminal_inputs(self.db, 'dly_' + 'f' * 64, self.item['attemptId'])

    def test_explicit_v3_required(self):
        for version in (None, 2, True, 3.0, '3', 4):
            with self.subTest(version=version):
                item = {**self.item, 'receiptVersion': version}
                if version is None:
                    del item['receiptVersion']
                self.save(item=item)
                self.reject()

    def test_only_actual_input_recorded_anchor(self):
        for outcome in ({'status': 'unknown'}, {'status': 'started',
                        'turnId': self.item['clientUserMessageId'], 'replayed': True},
                        {**self.anchor['outcome'], 'replayed': False},
                        {**self.anchor['outcome'], 'itemId': self.item['clientUserMessageId']}):
            with self.subTest(outcome=outcome):
                self.save(anchor={**self.anchor, 'outcome': outcome})
                self.reject()

    def test_duplicate_rows_rejected(self):
        self.db.execute('INSERT INTO attempts SELECT * FROM attempts')
        self.db.commit()
        self.reject()

    def test_many_corrupt_duplicate_rows_rejected_without_counting_all(self):
        # A damaged table without its PK must not make ambiguity detection scan
        # every matching JSON row. Bound SQLite work, not just returned row count.
        for _ in range(10):
            self.db.execute('INSERT INTO attempts SELECT * FROM attempts')
        self.db.commit()
        with closing(sqlite3.connect(f'{self.path.as_uri()}?mode=ro', uri=True)) as connection:
            steps = 0

            def budget():
                nonlocal steps
                steps += 1
                return int(steps >= 1000)

            connection.set_progress_handler(budget, 1)
            with self.assertRaises(NativeError):
                collect_terminal_inputs(connection, self.item['deliveryId'], self.item['attemptId'])
            self.assertLess(steps, 1000, 'duplicate detection exhausted the SQLite work budget')

    def test_malformed_duplicate_deep_oversize_json_rejected(self):
        for column, document in (('envelope', ADMISSION['envelope']),
                                 ('admission', ADMISSION), ('native_request', self.item),
                                 ('input_recorded_receipt', self.anchor)):
            raw = json.dumps(document)
            first = next(iter(document))
            duplicate = '{' + json.dumps(first) + ':' + json.dumps(document[first]) + ',' + raw[1:]
            for value in (None, '{', '{}', '{"a":1,"a":2}', '[' * 34 + '0' + ']' * 34,
                          raw + ' ' * 4097, duplicate, '{"a":NaN}'):
                with self.subTest(column=column, value=value):
                    self.save()
                    self.db.execute(_UPDATE_JSON[column], (value,))
                    self.db.commit()
                    self.reject()

    def test_attachment_rotation_does_not_replace_saved_binding(self):
        self.db.execute('CREATE TABLE attachments (runtime TEXT, data TEXT)')
        self.db.execute('INSERT INTO attachments VALUES (?,?)', ('current', json.dumps({
            'nativeThreadId': str(uuid.uuid4()), 'nativeClientId': str(uuid.uuid4())})))
        self.db.commit()
        self.assertEqual(self.collect()['request'], self.item)

    def test_missing_schema_is_bounded_error(self):
        self.db.execute('DROP TABLE attempts')
        self.db.commit()
        self.reject()
