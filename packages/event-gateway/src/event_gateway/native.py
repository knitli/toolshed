"""Injected private-bridge provider; never launches or discovers a native client."""

import asyncio
import json
import re
from uuid import UUID, uuid4

from .cloud import _timestamp, _uuid


IDENTITY = (
    "clientId", "serverInstanceId", "serverGeneration", "threadId", "attemptId",
    "deliveryId", "clientUserMessageId", "permitId", "permitIssuedAt", "permitExpiresAt",
)
EVENT_FIELDS = ("eventId", "source", "sourceStateVersion", "canonicalSubject", "eventReference")
NOT_STARTED_REASONS = frozenset((
    "busy serverDraining selectionExpired selectionChanged permitExpired "
    "permitInvalid duplicateConflict receiptCapacity connectionClosed threadUnavailable inputInvalid"
).split())
TERMINAL_REASONS = NOT_STARTED_REASONS - {"permitInvalid", "duplicateConflict", "receiptCapacity"}


class NativeError(ValueError):
    """Only a bounded code escapes native validation."""

    def __init__(self, code="invalid_native_receipt"):
        """Expose only a fixed validation code, never native response contents."""
        self.code = code
        super().__init__(code)


def _copy(value):
    try:
        encoded = json.dumps(value, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode()) > 4096:
            raise NativeError()
        return json.loads(encoded)
    except (ValueError, TypeError, RecursionError):
        raise NativeError() from None


def _native_uuid(value):
    try:
        return isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        return False


def _uint(value):
    # JSON integers must exclude booleans and caller-defined integer subclasses.
    return type(value) is int and 0 <= value <= 2**64 - 1  # pylint: disable=unidiomatic-typecheck


def _receipt_version(request):
    version = request.get("receiptVersion", 2)
    if type(version) is not int or version not in (2, 3):  # pylint: disable=unidiomatic-typecheck
        raise NativeError()
    return version


def validate_request(request, admission):
    """Bind the complete native start request to its exact cloud admission."""
    request = _copy(request)
    if not isinstance(request, dict):
        raise NativeError("invalid_native_request")
    expected = set(IDENTITY) | {"generation", "event"}
    if "receiptVersion" in request:
        expected.add("receiptVersion")
    if set(request) != expected:
        raise NativeError("invalid_native_request")
    try:
        _receipt_version(request)
    except NativeError:
        raise NativeError("invalid_native_request") from None
    # A started turn ID must satisfy the v4/v7 grammar of its submitted ACK.
    if (
        any(not _native_uuid(request[key]) for key in ("clientId", "serverInstanceId", "threadId"))
        or not _uuid(request["clientUserMessageId"])
        or any(not _uint(request[key]) for key in (
            "generation", "serverGeneration", "permitIssuedAt", "permitExpiresAt",
        ))
    ):
        raise NativeError("invalid_native_request")
    try:
        envelope = admission["envelope"]
        expected = {
            "attemptId": envelope["attemptId"], "deliveryId": envelope["deliveryId"],
            "permitId": admission["permitId"],
            "permitIssuedAt": _timestamp(admission["permitIssuedAt"]),
            "permitExpiresAt": _timestamp(admission["permitExpiresAt"]),
            "event": {key: envelope[key] for key in EVENT_FIELDS},
        }
        if any(request[key] != value for key, value in expected.items()):
            raise NativeError("invalid_native_request")
        if (not _uuid(request["attemptId"]) or not _uuid(request["permitId"])
                or not re.fullmatch(r"dly_[0-9a-f]{64}", request["deliveryId"])
                or request["permitExpiresAt"] - request["permitIssuedAt"] != 5000):
            raise NativeError("invalid_native_request")
    except (KeyError, TypeError, ValueError):
        raise NativeError("invalid_native_request") from None
    return request


def validate_receipt(request, receipt, *, allow_input_recorded=False):
    """Return an outcome only after its entire echoed native identity matches."""
    if not isinstance(request, dict) or not set(IDENTITY) <= set(request):
        raise NativeError()
    receipt = _copy(receipt)
    if not isinstance(receipt, dict):
        raise NativeError()
    identity = IDENTITY + (("generation",) if _receipt_version(request) == 3 else ())
    if (set(receipt) != set(identity) | {"outcome"}
            or ("generation" in receipt and not _uint(request.get("generation")))):
        raise NativeError()
    if any(type(receipt[key]) is not type(request[key]) or receipt[key] != request[key]
           for key in identity):
        raise NativeError()
    outcome = receipt["outcome"]
    if not isinstance(outcome, dict):
        raise NativeError()
    status = outcome.get("status")
    if status == "started":
        if (set(outcome) != {"status", "turnId", "replayed"}
                or not _native_uuid(outcome["turnId"])
                or outcome["turnId"] != request["clientUserMessageId"]
                or type(outcome["replayed"]) is not bool):  # pylint: disable=unidiomatic-typecheck
            raise NativeError()
    elif status == "inputRecorded":
        if (not allow_input_recorded
                or set(outcome) != {"status", "turnId", "itemId", "replayed"}
                or not _uuid(outcome["turnId"])
                or outcome["turnId"] != request["clientUserMessageId"]
                or not _uuid(outcome["itemId"])
                or outcome["itemId"] == request["clientUserMessageId"]
                or outcome["replayed"] is not True):
            raise NativeError()
    elif status == "terminalNotStarted":
        if (set(outcome) != {"status", "reason", "receiptId", "replayed"}
                or not isinstance(outcome["reason"], str)
                or outcome["reason"] not in TERMINAL_REASONS
                or not _uuid(outcome["receiptId"])
                or type(outcome["replayed"]) is not bool):  # pylint: disable=unidiomatic-typecheck
            raise NativeError()
    elif status == "notStarted":
        if (set(outcome) != {"status", "reason"}
                or not isinstance(outcome["reason"], str)
                or outcome["reason"] not in NOT_STARTED_REASONS):
            raise NativeError()
    elif outcome != {"status": "unknown"}:
        raise NativeError()
    return outcome


class NativeBridgeAdapter:
    """A caller supplies an already qualified private bridge; no default exists."""

    def __init__(self, mapping, bridge):
        """Use an existing bridge bound to an explicitly mapped native thread."""
        self.thread_id = mapping.get("nativeThreadId") if isinstance(mapping, dict) else None
        if not _native_uuid(self.thread_id):
            raise NativeError("invalid_native_mapping")
        self.bridge, self.witness = bridge, None
        self.receipt_version = _receipt_version({"receiptVersion": getattr(bridge, "receipt_version", 2)})

    async def check(self):
        self.witness = None
        try:
            witness = await asyncio.to_thread(self.bridge.challenge)
        except Exception:
            raise NativeError("native_unavailable") from None
        if (not isinstance(witness, dict) or witness.get("eligible") is not True
                or witness.get("threadId") != self.thread_id
                or any(not _native_uuid(witness.get(key)) for key in ("clientId", "serverInstanceId", "threadId"))
                or any(not _uint(witness.get(key)) for key in ("generation", "serverGeneration"))):
            return "unavailable"
        self.witness = dict(witness)
        return "available"

    async def prepare(self, admission):
        """Create request bytes without issuing a native event operation."""
        if self.witness is None:
            raise NativeError("native_unavailable")
        envelope = admission["envelope"]
        request = {
            **{key: self.witness[key] for key in (
                "clientId", "generation", "serverInstanceId", "serverGeneration", "threadId",
            )},
            "attemptId": envelope["attemptId"], "deliveryId": envelope["deliveryId"],
            "clientUserMessageId": str(uuid4()), "permitId": admission["permitId"],
            "permitIssuedAt": _timestamp(admission["permitIssuedAt"]),
            "permitExpiresAt": _timestamp(admission["permitExpiresAt"]),
            "event": {key: envelope[key] for key in EVENT_FIELDS},
        }
        if self.receipt_version == 3:
            request["receiptVersion"] = 3
        return validate_request(request, admission)

    def _wire_request(self, request):
        # The expected reader mode is durable before Start, but is not a wire field.
        current = getattr(self.bridge, "receipt_version", 2)
        if (type(current) is not int or current != self.receipt_version  # pylint: disable=unidiomatic-typecheck
                or _receipt_version(request) != self.receipt_version):
            raise NativeError("native_receipt_version_mismatch")
        return {key: value for key, value in request.items() if key != "receiptVersion"}

    async def submit(self, request):
        outcome = await asyncio.to_thread(self.bridge.start, self._wire_request(request))
        receipt = {**{key: request[key] for key in IDENTITY}, "outcome": outcome}
        if self.receipt_version == 3:
            receipt["generation"] = request["generation"]
        validate_receipt(request, receipt)
        return receipt

    async def reconcile(self, request):
        # Restoring this identity permits only an exact read-only lookup. It also
        # consumes the bridge's start-once ledger so recovery cannot start it.
        wire_request = self._wire_request(request)
        self.bridge.restore_attempt(wire_request)
        outcome = await asyncio.to_thread(self.bridge.receipt, wire_request)
        receipt = {**{key: request[key] for key in IDENTITY}, "outcome": outcome}
        if self.receipt_version == 3:
            receipt["generation"] = request["generation"]
        validate_receipt(request, receipt, allow_input_recorded=True)
        if outcome.get("status") in ("started", "terminalNotStarted") and not outcome["replayed"]:
            raise NativeError()
        return receipt
