"""Dormant Messaging v2 DTO and raw-wire conformance; no admission authority."""

# Separate from the active v1 contract: valid DTOs do not grant execution authority.

# Exact built-in types reject bool-as-int and subclasses outside decoded JSON DTOs.
# pylint: disable=unidiomatic-typecheck

import hashlib
import json
import math
import re
import time
from datetime import datetime, timezone

MESSAGING_PROTOCOL_VERSION = 2
MAX_SAFE_INTEGER = 2**53 - 1
MAX_PROTOCOL_MESSAGE_BYTES = 4096
CLOCK_SKEW_MS = 30_000
FRESHNESS_LIFETIME_MS = 60_000

_UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}')
_PRINCIPAL = re.compile(
    r"(?=[^@]{1,64}@)[a-z0-9!#$%&'*+/=?^_`{|}~-]+"
    r"(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+"
)
_GENERATIONS = ('nodeGeneration', 'runtimeGeneration', 'attachmentGeneration',
                'consumerGeneration', 'routingGeneration')
_IDENTITY_FIELDS = ('eventId', 'nodeId', 'runtimeId', *_GENERATIONS)
_ATTEMPT_FIELDS = ('schemaVersion', 'eventId', 'deliveryId', 'attemptId', 'principal',
                   'agent', 'nodeId', 'runtimeId', *_GENERATIONS)
_ENVELOPE_FIELDS = frozenset((*_ATTEMPT_FIELDS, 'source', 'eventKind', 'reasonCode',
    'canonicalSubject', 'sourceStateVersion', 'policyRevision', 'eventReference',
    'observedAt', 'issuedAt', 'expiresAt'))
_ACK_FIELDS = frozenset((*_ATTEMPT_FIELDS, 'deliveredSourceStateVersion',
                        'acknowledgedAt', 'status', 'nativeCorrelation'))


class MessagingProtocolError(ValueError):
    """A safe reason code, without caller-supplied metadata."""

    def __init__(self, code: str):
        """Store the safe protocol reason code."""
        self.code = code
        super().__init__(code)


def _matches(pattern: re.Pattern[str], value: object) -> bool:
    return type(value) is str and pattern.fullmatch(value) is not None


def _integer(value: object, minimum: int = 1) -> bool:
    # bool is an int subclass in Python; integral floats are JS integer numbers.
    if type(value) is int:
        return minimum <= value <= MAX_SAFE_INTEGER
    return (type(value) is float and math.isfinite(value) and value.is_integer()
            and minimum <= value <= MAX_SAFE_INTEGER)


def _exact(value: object, keys: frozenset[str] | tuple[str, ...]) -> bool:
    return type(value) is dict and value.keys() == set(keys)


def _timestamp(value: object) -> int | None:
    if type(value) is not str or re.fullmatch(
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z', value) is None:
        return None
    try:
        # A complete 400-year Gregorian cycle preserves year 0000 leap dates.
        shifted = value.startswith('0000-')
        parsed = '0400' + value[4:] if shifted else value
        delta = datetime.fromisoformat(parsed.replace('Z', '+00:00')) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        milliseconds = delta.days * 86_400_000 + delta.seconds * 1000 + delta.microseconds // 1000
        return milliseconds - (146097 * 86_400_000 if shifted else 0)
    except ValueError:
        return None


def _json_bytes(value: object) -> bytes:
    def numbers(item):
        if type(item) is dict:
            return {key: numbers(child) for key, child in item.items()}
        if type(item) is list:
            return [numbers(child) for child in item]
        return int(item) if type(item) is float and item.is_integer() else item

    def surrogate(match):
        text = match.group()
        if len(text) == 2:
            return chr(0x10000 + ((ord(text[0]) - 0xD800) << 10) + ord(text[1]) - 0xDC00)
        return f'\\u{ord(text):04x}'

    encoded = json.dumps(numbers(value), ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    # JSON.stringify preserves real Unicode but escapes unpaired UTF-16 surrogates.
    encoded = re.sub(r'[\ud800-\udbff][\udc00-\udfff]|[\ud800-\udfff]', surrogate, encoded)
    return encoded.encode('utf-8')


def _fits(value: object) -> bool:
    try:
        return len(_json_bytes(value)) <= MAX_PROTOCOL_MESSAGE_BYTES
    except (TypeError, ValueError, OverflowError, RecursionError, UnicodeError):
        return False


def _identity(value: object) -> bool:
    return (type(value) is dict
            and all(_matches(_UUID, value.get(key)) for key in ('eventId', 'nodeId', 'runtimeId'))
            and all(_integer(value.get(key)) for key in _GENERATIONS)
            and value['consumerGeneration'] == value['attachmentGeneration'])


def _attempt(value: dict) -> bool:
    return (_integer(value.get('schemaVersion')) and value['schemaVersion'] == MESSAGING_PROTOCOL_VERSION
            and _identity(value) and _matches(_UUID, value.get('attemptId'))
            and _matches(re.compile(r'dly_[0-9a-f]{64}'), value.get('deliveryId'))
            and _matches(_PRINCIPAL, value.get('principal')) and len(value['principal']) <= 254
            and _matches(re.compile(r'[a-z0-9-]{1,32}'), value.get('agent')))


def _code_points(value: str) -> int:
    # Locked Zod 4.6.5 uses codePointLength, including paired surrogate strings.
    return len(value) - len(re.findall(r'[\ud800-\udbff][\udc00-\udfff]', value))


def _envelope_shape(value: object) -> bool:
    if not _exact(value, _ENVELOPE_FIELDS) or not _attempt(value):
        return False
    subject = value['canonicalSubject']
    if not _exact(subject, ('kind', 'namespace', 'messageId', 'agentIncarnation')):
        return False
    namespace = subject['namespace']
    return (value['source'] == 'messaging' and value['eventKind'] == 'message'
            and value['reasonCode'] == 'inbox_message' and subject['kind'] == 'message'
            and type(namespace) is str
            and 1 <= _code_points(namespace) <= 256
            and re.search(r'[\x00-\x1f\x7f]', namespace) is None
            and _matches(_UUID, subject['messageId']) and _integer(subject['agentIncarnation'], 0)
            and _matches(re.compile(r'msg:[a-f0-9]{64}'), value['sourceStateVersion'])
            and _integer(value['policyRevision'])
            and type(value['eventReference']) is str and value['eventReference'].startswith('ref_')
            and _matches(_UUID, value['eventReference'][4:])
            and all(_timestamp(value[key]) is not None for key in ('observedAt', 'issuedAt', 'expiresAt')))


def _ack_shape(value: object) -> bool:
    if not _exact(value, _ACK_FIELDS) or not _attempt(value):
        return False
    if (not _matches(re.compile(r'msg:[a-f0-9]{64}'), value['deliveredSourceStateVersion'])
            or _timestamp(value['acknowledgedAt']) is None):
        return False
    correlation = value['nativeCorrelation']
    if value['status'] == 'submitted':
        return (_exact(correlation, ('kind', 'permitId', 'turnId'))
                and correlation['kind'] == 'native_turn_started'
                and all(_matches(_UUID, correlation[key]) for key in ('permitId', 'turnId')))
    if value['status'] == 'observed':
        return (_exact(correlation, ('kind', 'permitId', 'turnId', 'itemId'))
                and correlation['kind'] == 'native_input_recorded'
                and all(_matches(_UUID, correlation[key]) for key in ('permitId', 'turnId', 'itemId'))
                and correlation['itemId'] != correlation['turnId'])
    return False


def validate_envelope(value: object, now_ms: int | float | None = None) -> bool:
    """Validate an already-decoded plain DTO, without authenticating its source."""
    now = time.time() * 1000 if now_ms is None else now_ms
    if type(now) not in (int, float) or not _envelope_shape(value) or not _fits(value):
        return False
    try:
        if not math.isfinite(now):
            return False
    except OverflowError:
        return False
    issued, expires, observed = (_timestamp(value[key]) for key in ('issuedAt', 'expiresAt', 'observedAt'))
    return (0 < expires - issued <= FRESHNESS_LIFETIME_MS and issued <= now + CLOCK_SKEW_MS
            and now <= expires + CLOCK_SKEW_MS and observed <= issued + CLOCK_SKEW_MS
            and observed <= now + CLOCK_SKEW_MS)


def validate_acknowledgment(value: object, now_ms: int | float | None = None) -> bool:
    """Validate an already-decoded ACK; runtime authentication remains external."""
    now = time.time() * 1000 if now_ms is None else now_ms
    if type(now) not in (int, float) or not _ack_shape(value) or not _fits(value):
        return False
    try:
        return math.isfinite(now) and _timestamp(value['acknowledgedAt']) <= now + CLOCK_SKEW_MS
    except OverflowError:
        return False


def _parse_wire(body: str | bytes, acknowledgment: bool, now_ms: int | float | None) -> dict:
    if type(body) not in (str, bytes):
        raise MessagingProtocolError('invalid_json')
    # Keep schema loading confined to explicit wire calls; reuse the audited decoder.
    from .protocol import ProtocolError, _decode  # pylint: disable=import-outside-toplevel

    try:
        value = _decode(body)
    except ProtocolError as exc:
        raise MessagingProtocolError(exc.code) from None
    shape = _ack_shape if acknowledgment else _envelope_shape
    if not shape(value):
        raise MessagingProtocolError('invalid_acknowledgment' if acknowledgment else 'invalid_envelope')
    validate = validate_acknowledgment if acknowledgment else validate_envelope
    if not validate(value, now_ms):
        raise MessagingProtocolError('stale_message')
    return value


def parse_envelope(body: str | bytes, now_ms: int | float | None = None) -> dict:
    """Parse bounded raw UTF-8 JSON without granting delivery authority."""
    return _parse_wire(body, False, now_ms)


def parse_acknowledgment(body: str | bytes, now_ms: int | float | None = None) -> dict:
    """Parse a bounded raw ACK without authenticating or settling delivery."""
    return _parse_wire(body, True, now_ms)


def derive_delivery_id(identity: object) -> str:
    """Versioned immutable destination identity; retry/timestamp fields are ignored."""
    if not _identity(identity):
        raise MessagingProtocolError('invalid_delivery_identity')
    semantic = [MESSAGING_PROTOCOL_VERSION, *(int(identity[key]) if key in _GENERATIONS
                                             else identity[key] for key in _IDENTITY_FIELDS)]
    return 'dly_' + hashlib.sha256(_json_bytes(semantic)).hexdigest()


def matches_delivery_id(envelope: object) -> bool:
    try:
        return type(envelope) is dict and envelope.get('deliveryId') == derive_delivery_id(envelope)
    except MessagingProtocolError:
        return False


def acknowledgment_matches_delivery(envelope: object, acknowledgment: object) -> bool:
    """Exact validated-shape mapping, not freshness/current-authority/settlement."""
    # Shape checks prevent Python's True == 1 or absent None == None from matching.
    return (_envelope_shape(envelope) and _ack_shape(acknowledgment)
            and all(acknowledgment[key] == envelope[key] for key in _ATTEMPT_FIELDS)
            and acknowledgment['deliveredSourceStateVersion'] == envelope['sourceStateVersion'])
