"""Pinned Event Runtime v1 wire validation. Errors contain reason codes only."""
import hashlib
import json
import math
import re
import time
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

MAX_PROTOCOL_MESSAGE_BYTES = 4096
CLOCK_SKEW_MS = 30_000
FRESHNESS_LIFETIME_MS = 60_000


class ProtocolError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _schema():
    resource = files('event_gateway').joinpath('contracts/event-v1/protocol.schema.json')
    if resource.is_file():
        return json.loads(resource.read_text())
    return json.loads((Path(__file__).resolve().parents[2] / 'contracts/event-v1/protocol.schema.json').read_text())


_FORMATS = FormatChecker()


@_FORMATS.checks('date-time')
def _canonical_datetime(value):
    if not isinstance(value, str):
        return True
    try:
        _timestamp(value)
        return True
    except ProtocolError:
        return False



def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError('duplicate_json_key')
        result[key] = value
    return result


def _depth(value, depth=0):
    if depth > 32:
        raise ProtocolError('invalid_json')
    children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
    for child in children:
        _depth(child, depth + 1)


def _decode(body):
    if not isinstance(body, (bytes, str)):
        raise ProtocolError('invalid_json')
    if len(body) > MAX_PROTOCOL_MESSAGE_BYTES:
        raise ProtocolError('message_too_large')
    try:
        if isinstance(body, bytes):
            body = body.decode('utf-8')
        if len(body.encode('utf-8')) > MAX_PROTOCOL_MESSAGE_BYTES:
            raise ProtocolError('message_too_large')
        value = json.loads(body, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        _depth(value)
        return value
    except (UnicodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError('invalid_json') from None


def _timestamp(value):
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z', value):
        raise ProtocolError('stale_message')
    try:
        # Python datetime starts at year 1; ECMAScript also permits year 0000.
        shifted = value.startswith('0000-')
        parsed = ('0400' + value[4:]) if shifted else value
        delta = datetime.fromisoformat(parsed.replace('Z', '+00:00')) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        milliseconds = delta.days * 86400000 + delta.seconds * 1000 + delta.microseconds // 1000
        return milliseconds - (146097 * 86400000 if shifted else 0)
    except ValueError:
        raise ProtocolError('stale_message') from None


_SCHEMA = _schema()
_VALIDATORS = [Draft202012Validator(branch, format_checker=_FORMATS) for branch in _SCHEMA['anyOf']]


def _parse(body, acknowledgment, now_ms):
    value = _decode(body)
    if not _VALIDATORS[int(acknowledgment)].is_valid(value):
        raise ProtocolError('invalid_acknowledgment' if acknowledgment else 'invalid_envelope')
    now = time.time() * 1000 if now_ms is None else now_ms
    if not isinstance(now, (int, float)) or isinstance(now, bool) or not math.isfinite(now):
        raise ProtocolError('stale_message')
    if acknowledgment:
        fresh = _timestamp(value['acknowledgedAt']) <= now + CLOCK_SKEW_MS
    else:
        issued, expires, observed = map(_timestamp, (value['issuedAt'], value['expiresAt'], value['observedAt']))
        fresh = (0 < expires - issued <= FRESHNESS_LIFETIME_MS and issued <= now + CLOCK_SKEW_MS
                 and now <= expires + CLOCK_SKEW_MS and observed <= issued + CLOCK_SKEW_MS
                 and observed <= now + CLOCK_SKEW_MS)
    if not fresh:
        raise ProtocolError('stale_message')
    return value


def parse_envelope(body, now_ms=None):
    return _parse(body, False, now_ms)


def parse_acknowledgment(body, now_ms=None):
    return _parse(body, True, now_ms)


def derive_delivery_id(identity):
    props = _SCHEMA['anyOf'][0]['anyOf'][0]['properties']
    keys = ('eventId', 'runtimeId', 'nodeGeneration', 'runtimeGeneration', 'attachmentGeneration')
    selected = {}
    try:
        for key in (*keys, 'consumerGeneration'):
            if key == 'consumerGeneration' and key not in identity:
                continue
            value = identity[key]
            if not Draft202012Validator(props[key]).is_valid(value):
                raise ValueError()
            selected[key] = int(value) if key.endswith('Generation') else value
    except (KeyError, TypeError, ValueError):
        raise ProtocolError('invalid_delivery_identity') from None
    semantic = [1, *(selected[key] for key in keys), selected.get('consumerGeneration')]
    return 'dly_' + hashlib.sha256(json.dumps(semantic, separators=(',', ':')).encode()).hexdigest()


def matches_delivery_id(envelope):
    try:
        return envelope['deliveryId'] == derive_delivery_id(envelope)
    except (ProtocolError, KeyError, TypeError):
        return False


def acknowledgment_matches_delivery(envelope, acknowledgment):
    keys = ('eventId', 'deliveryId', 'attemptId', 'principal', 'agent', 'runtimeId',
            'nodeGeneration', 'runtimeGeneration', 'attachmentGeneration', 'consumerGeneration')
    return all(acknowledgment.get(key) == envelope.get(key) for key in keys) and acknowledgment.get('deliveredSourceStateVersion') == envelope.get('sourceStateVersion')


def acknowledgment_advances_current_watermark(envelope, acknowledgment, current_source_state_version):
    return (acknowledgment_matches_delivery(envelope, acknowledgment) and acknowledgment['status'] == 'observed'
            and acknowledgment['deliveredSourceStateVersion'] == current_source_state_version)
