"""Dormant native Messaging V2 metadata; validation grants no admission authority."""

import json

from .messaging_protocol_v2 import _envelope_shape, _json_bytes

FIELDS = (
    "schemaVersion", "eventId", "source", "eventKind", "reasonCode", "principal",
    "agent", "nodeId", "runtimeId", "nodeGeneration", "runtimeGeneration",
    "attachmentGeneration", "consumerGeneration", "routingGeneration",
    "canonicalSubject", "sourceStateVersion", "policyRevision", "eventReference",
    "observedAt",
)
INTEGERS = ("schemaVersion", "nodeGeneration", "runtimeGeneration",
            "attachmentGeneration", "consumerGeneration", "routingGeneration", "policyRevision")
SUBJECT_FIELDS = ("kind", "namespace", "messageId", "agentIncarnation")


def canonical_metadata(event, attempt_id, delivery_id, *, strict_wire=False):
    """Validate shape and return stable native metadata, without checking freshness."""
    if type(event) is not dict or set(event) != set(FIELDS):
        raise ValueError("invalid_native_messaging_metadata")
    # Delivery-window fields are excluded from durable identity; only shape is reused.
    envelope = {**event, "attemptId": attempt_id, "deliveryId": delivery_id,
                "issuedAt": event["observedAt"], "expiresAt": event["observedAt"]}
    if (not _envelope_shape(envelope)
            or (strict_wire and (any(type(event[key]) is not int for key in INTEGERS)
                or type(event["canonicalSubject"]["agentIncarnation"]) is not int))):
        raise ValueError("invalid_native_messaging_metadata")
    canonical = {key: event[key] for key in FIELDS}
    canonical["canonicalSubject"] = {key: event["canonicalSubject"][key] for key in SUBJECT_FIELDS}
    canonical = json.loads(_json_bytes(canonical))
    # Native Rust strings require Unicode scalars; namespace is the only free Unicode field.
    if any(0xD800 <= ord(char) <= 0xDFFF for char in canonical["canonicalSubject"]["namespace"]):
        raise ValueError("invalid_native_messaging_metadata")
    return canonical
