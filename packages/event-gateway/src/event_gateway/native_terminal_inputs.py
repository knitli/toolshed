"""Dormant exact-attempt evidence collection; no native or settlement authority."""

import re
import sqlite3

from .cloud import _timestamp, _uuid, validate_admission
from .native import NativeError, _copy, validate_receipt, validate_request
from .protocol import _decode

_BINDING = ('clientId', 'generation', 'serverInstanceId', 'serverGeneration', 'threadId')
# Projection bounds apply before SQLite hands stored JSON to Python. A single SELECT
# pairs all three original values in one read snapshot; no mutable attachment join.
_QUERY = """SELECT
 CASE WHEN typeof(admission)='text' AND length(CAST(admission AS BLOB))<=4096
      THEN admission END,
 CASE WHEN typeof(native_request)='text' AND length(CAST(native_request AS BLOB))<=4096
      THEN native_request END,
 CASE WHEN typeof(input_recorded_receipt)='text' AND length(CAST(input_recorded_receipt AS BLOB))<=4096
      THEN input_recorded_receipt END
 FROM attempts WHERE delivery_id=? AND attempt_id=? LIMIT 2"""


def collect_terminal_inputs(connection, delivery_id, attempt_id):
    """Read a trusted read-only journal connection; return saved inputs or None.

    None means only that this exact attempt is absent, never that no debt exists.
    Invalid/ambiguous/unsupported records raise one bounded NativeError. The caller
    owns connection provenance and must open it read-only. This function executes
    one SELECT, never opens a database, creates a Store, or changes transactions.
    Returned binding is historical native identity, not a complete session route.
    """
    try:
        if (not isinstance(delivery_id, str)
                or re.fullmatch(r'dly_[0-9a-f]{64}', delivery_id) is None
                or not _uuid(attempt_id)):
            raise ValueError()
        cursor = connection.execute(_QUERY, (delivery_id, attempt_id))
        try:
            rows = cursor.fetchmany(2)
        finally:
            cursor.close()
        if not rows:
            return None
        if len(rows) != 1:
            raise ValueError()
        admission_raw, request_raw, receipt_raw = rows[0]
        # Existing decoder rejects duplicate keys, non-finite numbers and depth>32;
        # native copy also enforces its 4 KiB serialized-value contract.
        admission, request, receipt = (
            _copy(_decode(value)) for value in (admission_raw, request_raw, receipt_raw)
        )
        if (not isinstance(request, dict)
                or type(request.get('receiptVersion')) is not int
                or request['receiptVersion'] != 3):
            raise ValueError()
        # Historical validation uses the original issue time, not current eligibility.
        validate_admission(admission, admission['envelope'],
                           now_ms=_timestamp(admission['permitIssuedAt']))
        validate_request(request, admission)
        if request['deliveryId'] != delivery_id or request['attemptId'] != attempt_id:
            raise ValueError()
        outcome = validate_receipt(request, receipt, allow_input_recorded=True)
        if outcome['status'] != 'inputRecorded':
            raise ValueError()
        return {'admission': admission, 'request': request,
                'input_recorded_receipt': receipt,
                'binding': {key: request[key] for key in _BINDING}}
    except (sqlite3.Error, ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        raise NativeError('invalid_native_terminal_inputs') from None
