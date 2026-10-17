"""Dormant historical terminal query; never grants Start or acknowledgment authority."""

import asyncio

from .cloud import _uuid
from .native import NativeBridgeAdapter, NativeError, _copy, validate_receipt


def validate_terminal_receipt(request, receipt):
    """Validate the paired v3 reply separately from actionable start/input receipts."""
    from .native_reader import validate_start

    request, receipt = _copy(request), _copy(receipt)
    if (
        not isinstance(request, dict)
        or type(request.get("receiptVersion")) is not int
        or request["receiptVersion"] != 3
    ):
        raise NativeError("invalid_native_request")
    try:
        validate_start(
            {key: value for key, value in request.items() if key != "receiptVersion"}
        )
    except (ValueError, TypeError, KeyError):
        raise NativeError("invalid_native_request") from None
    if not isinstance(receipt, dict) or "outcome" not in receipt:
        raise NativeError()
    validate_receipt(request, {**receipt, "outcome": {"status": "unknown"}})
    outcome = receipt["outcome"]
    if outcome == {"status": "unknown"}:
        return outcome
    if (
        not isinstance(outcome, dict)
        or set(outcome)
        != {"status", "turnId", "itemId", "receiptId", "terminalStatus", "replayed"}
        or outcome["status"] != "terminal"
        or not _uuid(outcome["turnId"])
        or outcome["turnId"] != request["clientUserMessageId"]
        or not _uuid(outcome["itemId"])
        or outcome["itemId"] == outcome["turnId"]
        or not _uuid(outcome["receiptId"])
        or outcome["terminalStatus"] not in ("completed", "failed", "canceled")
        or outcome["replayed"] is not True
    ):
        raise NativeError()
    return outcome


class NativeTerminalEvidenceAdapter(NativeBridgeAdapter):
    """Explicitly injected query for a trusted recovery caller; no active gateway caller."""

    async def terminal_evidence(self, request, input_recorded_receipt):
        """Cross-check native durable evidence against a trusted saved input receipt.

        The caller supplies its original persisted v3 request and previously validated
        InputRecorded receipt. This method neither loads nor changes settlement state.
        """
        request = _copy(request)
        anchor = validate_receipt(
            request, input_recorded_receipt, allow_input_recorded=True
        )
        receipt = {**_copy(input_recorded_receipt), "outcome": {"status": "unknown"}}
        validate_terminal_receipt(request, receipt)
        wire_request = self._wire_request(request)
        if anchor["status"] != "inputRecorded" or request["threadId"] != self.thread_id:
            raise NativeError()
        try:
            self.bridge.restore_attempt(wire_request)
            outcome = await asyncio.to_thread(
                self.bridge.terminal_evidence, wire_request
            )
        except (AttributeError, OSError, ValueError):
            raise NativeError("native_unavailable") from None
        receipt["outcome"] = outcome
        outcome = validate_terminal_receipt(request, receipt)
        if outcome["status"] == "terminal" and (
            outcome["turnId"] != anchor["turnId"]
            or outcome["itemId"] != anchor["itemId"]
        ):
            raise NativeError()
        return receipt
