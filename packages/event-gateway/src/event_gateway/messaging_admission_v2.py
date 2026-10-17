"""Dormant v2 metadata checks; no persistence, start permission, or ACK authority."""

# Exact built-in types reject bool-as-int and subclasses outside decoded JSON DTOs.
# pylint: disable=unidiomatic-typecheck

import math

from . import messaging_protocol_v2 as protocol
from .security import verify

ATTACHMENT_FIELDS = ('principal', 'agent', 'nodeId', 'runtimeId',
                     'nodeGeneration', 'runtimeGeneration', 'attachmentGeneration',
                     'consumerGeneration', 'routingGeneration')
_ADMISSION_FIELDS = frozenset(('status', 'permitId', 'nodeId', 'permitIssuedAt',
                               'permitExpiresAt', 'envelope'))


def _fail(code):
    raise protocol.MessagingProtocolError(code)


def _finite(value):
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def attachment_matches(attachment, envelope):
    """Compare a validated envelope's destination tuple without granting authority."""
    if type(attachment) is not dict:
        return False
    expected = {key: envelope[key] for key in ATTACHMENT_FIELDS}
    expected.update((key, envelope['canonicalSubject'][key])
                    for key in ('namespace', 'agentIncarnation'))
    # Canonical JSON keeps bool distinct from integers but accepts integral floats.
    try:
        return all(protocol._json_bytes(attachment.get(key)) == protocol._json_bytes(value)
                   for key, value in expected.items())
    except (ValueError, TypeError, RecursionError, OverflowError):
        return False


def validate_authenticated_envelope(body, *, signature, audience, public_key,
                                    expected_audience, node_id, attachment, now_ms):
    """Authenticate exact bytes, then validate freshness and current destination metadata."""
    # The caller selects public_key from trusted configuration, never from the message.
    # attachment holds ATTACHMENT_FIELDS, namespace, agentIncarnation, and
    # leaseExpiresAt (Unix seconds); metadata validation grants no start authority.
    if type(audience) is not str or audience != expected_audience:
        _fail('invalid_transport_authority')
    if type(body) is not bytes:
        _fail('invalid_body')
    if len(body) > protocol.MAX_PROTOCOL_MESSAGE_BYTES:
        _fail('message_too_large')
    verify(body, signature, public_key, audience)
    if not _finite(now_ms):
        _fail('invalid_clock')
    envelope = protocol.parse_envelope(body, now_ms=now_ms)
    if not protocol.matches_delivery_id(envelope):
        _fail('invalid_delivery_identity')
    if type(node_id) is not str or envelope['nodeId'] != node_id:
        _fail('node_mismatch')
    if (type(attachment) is not dict or not _finite(attachment.get('leaseExpiresAt'))
            or attachment['leaseExpiresAt'] <= now_ms / 1000):
        _fail('attachment_unavailable')
    if not attachment_matches(attachment, envelope):
        _fail('attachment_fenced')
    return envelope


def _historical_envelope(envelope, now_ms):
    if type(envelope) is not dict:
        _fail('invalid_envelope')
    issued = protocol._timestamp(envelope.get('issuedAt'))
    if issued is None:
        _fail('invalid_envelope')
    try:
        parsed = protocol.parse_envelope(protocol._json_bytes(envelope), min(now_ms, issued))
    except (ValueError, TypeError, RecursionError, OverflowError):
        _fail('invalid_envelope')
    if not protocol.matches_delivery_id(parsed):
        _fail('identity_mismatch')
    return parsed


def validate_admission(admission, expected_envelope, *, now_ms, node_id):
    """Validate immutable admission HISTORY, including expired permits; never allow start."""
    # Authentication of the cloud response and subsequent live start gates remain external.
    if not _finite(now_ms):
        _fail('invalid_clock')
    if (not protocol._exact(admission, _ADMISSION_FIELDS)
            or admission['status'] != 'admitted'
            or not protocol._matches(protocol._UUID, admission['permitId'])
            or not protocol._matches(protocol._UUID, node_id)
            or admission['nodeId'] != node_id):
        _fail('invalid_response')
    issued = protocol._timestamp(admission['permitIssuedAt'])
    expires = protocol._timestamp(admission['permitExpiresAt'])
    if issued is None or expires is None:
        _fail('invalid_response')
    if expires - issued != 5000 or issued > now_ms:
        _fail('permit_expired')
    expected = _historical_envelope(expected_envelope, now_ms)
    admitted = _historical_envelope(admission['envelope'], now_ms)
    if (admitted['nodeId'] != node_id or expected['nodeId'] != node_id
            or any(admitted[key] != expected[key] for key in expected
                   if key not in ('issuedAt', 'expiresAt'))
            or protocol._timestamp(admitted['issuedAt']) > issued
            or protocol._timestamp(admitted['expiresAt']) < expires):
        _fail('identity_mismatch')
    return {**admission, 'envelope': admitted}
