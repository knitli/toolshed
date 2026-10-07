"""Durable cloud admission and native no-start settlement state machine."""

import asyncio
import time

from .cloud import _iso
from .codex import CodexError
from .native import NativeError, validate_request, validate_receipt
from .protocol import parse_envelope, matches_delivery_id
from .security import verify
from .store import StoreError


class Refused(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


FENCES = (
    "principal", "agent", "runtimeId", "nodeGeneration", "runtimeGeneration",
    "attachmentGeneration", "consumerGeneration", "sourceStateVersion", "policyRevision",
)


class UnavailableAuthority:
    async def claim(self, envelope):
        raise Refused("authority_unavailable")

    async def settle_no_start(self, admission, evidence):
        raise Refused("authority_unavailable")

    async def acknowledge(self, envelope, acknowledgment):
        raise Refused("authority_unavailable")


class Gateway:
    def __init__(self, store, authority, adapter_factory, *, audience, keys, clock=time.time):
        """Bind durable storage to explicitly injected authority and native providers."""
        self.store, self.authority = store, authority
        self.adapter_factory, self.clock = adapter_factory, clock
        self.audience, self.keys = audience, dict(keys)
        self._locks = {}

    def accept(self, body, *, signature, audience, key_id):
        # Authenticate exact bytes before parsing, deduplication, or persistence.
        if audience != self.audience or key_id not in self.keys:
            raise Refused("invalid_transport_authority")
        if len(body) > 4096:
            raise Refused("message_too_large")
        verify(body, signature, self.keys[key_id], audience)
        envelope = parse_envelope(body, now_ms=self.clock() * 1000)
        if not matches_delivery_id(envelope):
            raise Refused("invalid_delivery_identity")
        mapping = self.store.get_attachment(envelope["runtimeId"])
        if not mapping or mapping["leaseExpiresAt"] <= self.clock():
            raise Refused("attachment_unavailable")
        if any(mapping.get(key) != envelope.get(key) for key in FENCES[:7]):
            raise Refused("attachment_fenced")
        return self.store.accept(envelope)

    def _row(self, delivery_id, reason=None):
        row = self.store.delivery(delivery_id)
        return {**row, "reason": reason} if reason else row

    async def _adapter_available(self, adapter):
        try:
            return await asyncio.wait_for(adapter.check(), 8) == "available"
        except (Refused, CodexError, NativeError, OSError, TimeoutError):
            return False

    async def _available_adapter(self, mapping):
        try:
            adapter = self.adapter_factory(mapping)
        except (Refused, CodexError, NativeError, OSError):
            return None
        return adapter if await self._adapter_available(adapter) else None

    async def _claim(self, delivery_id):
        attempt = self.store.current_attempt(delivery_id)
        try:
            admission = await asyncio.wait_for(self.authority.claim(attempt["envelope"]), 8)
            if isinstance(admission, dict) and admission.get("status") == "over_budget":
                self.store.note_claim_budget(delivery_id, attempt["attempt_id"])
                return "over_budget"
            # No await or post-admission gate may precede this durable write.
            return self.store.record_admission(delivery_id, admission)
        except Exception:
            # Claim intent survives every uncertain response/storage failure.
            return None

    async def _settle(self, delivery_id):
        attempt = self.store.current_attempt(delivery_id)
        if not attempt or attempt["state"] != "settlement_pending":
            return self._row(delivery_id)
        try:
            result = await asyncio.wait_for(self.authority.settle_no_start(
                attempt["admission"], attempt["evidence"]), 8)
            self.store.complete_settlement(delivery_id, attempt["attempt_id"], result)
        except Exception:
            return self._row(delivery_id, "settlement_pending")
        return self._row(delivery_id)

    async def _retire_local(self, delivery_id, reason):
        attempt = self.store.current_attempt(delivery_id)
        try:
            self.store.begin_settlement(delivery_id, attempt["attempt_id"],
                                        {"type": "local_not_submitted"}, reason=reason)
        except StoreError:
            return self._row(delivery_id, "local_retirement_pending")
        return await self._settle(delivery_id)

    async def _receipt(self, delivery_id, attempt, receipt, *, allow_input_recorded=False):
        outcome = validate_receipt(attempt["native_request"], receipt, allow_input_recorded=allow_input_recorded)
        if outcome["status"] in ("started", "inputRecorded"):
            record = self.store.record_input_recorded if outcome["status"] == "inputRecorded" else self.store.record_started
            record(delivery_id, attempt["attempt_id"], receipt)
            return await self._ack_native(delivery_id, attempt["attempt_id"])
        if attempt.get("started_receipt") or attempt.get("input_recorded_receipt"):
            return self._row(delivery_id, "native_input_unconfirmed")
        if outcome["status"] == "terminalNotStarted":
            self.store.begin_settlement(delivery_id, attempt["attempt_id"],
                {"type": "native_terminal_no_start", "receiptId": outcome["receiptId"]},
                receipt=receipt, reason="native_terminal_no_start")
            return await self._settle(delivery_id)
        return self.store.finish(delivery_id, "ambiguous", reason="native_outcome_unknown",
                                 attempt_id=attempt["attempt_id"])

    def _native_acknowledgment(self, attempt, *, observed=False):
        envelope = attempt["admission"]["envelope"]
        receipt = (attempt["input_recorded_receipt"] if observed else
                   attempt.get("started_receipt") or attempt["input_recorded_receipt"])
        acknowledgment = {
            "schemaVersion": 1,
            **{key: envelope[key] for key in (
                "eventId", "deliveryId", "attemptId", "principal", "agent", "runtimeId",
                "nodeGeneration", "runtimeGeneration", "attachmentGeneration",
            )},
            "deliveredSourceStateVersion": envelope["sourceStateVersion"],
            "acknowledgedAt": _iso(self.clock()),
            "status": "observed" if observed else "submitted",
            "nativeCorrelation": {
                "kind": "native_input_recorded" if observed else "native_turn_started",
                "permitId": attempt["admission"]["permitId"],
                "turnId": receipt["outcome"]["turnId"],
            },
        }
        if observed:
            acknowledgment["nativeCorrelation"]["itemId"] = receipt["outcome"]["itemId"]
        if "consumerGeneration" in envelope:
            acknowledgment["consumerGeneration"] = envelope["consumerGeneration"]
        return acknowledgment

    async def _ack_native(self, delivery_id, attempt_id):
        # Each phase has its own immutable DTO; observation cannot precede confirmed registration.
        for observed in (False, True):
            attempt = self.store.current_attempt(delivery_id)
            if (not attempt or attempt["attempt_id"] != attempt_id
                    or not (attempt.get("started_receipt") or attempt.get("input_recorded_receipt"))):
                return self._row(delivery_id)
            if observed and not attempt.get("input_recorded_receipt"):
                break
            if attempt["ack_state"] == "observed" or (not observed and attempt["ack_state"] == "submitted"):
                continue
            column = "native_observed_ack" if observed else "native_ack"
            try:
                acknowledgment = self.store.persist_native_ack(
                    delivery_id, attempt_id,
                    attempt.get(column) or self._native_acknowledgment(attempt, observed=observed),
                    observed=observed,
                )
            except StoreError:
                return self._row(delivery_id, "native_ack_persistence_pending")
            try:
                result = await asyncio.wait_for(
                    self.authority.acknowledge(attempt["admission"]["envelope"], acknowledgment), 8
                )
                if not self.store.complete_native_ack(delivery_id, attempt_id, acknowledgment, result, observed=observed):
                    raise StoreError("acknowledgment_conflict")
            except Exception:
                return self._row(delivery_id, "native_observed_ack_pending" if observed else "native_started_ack_pending")
        return self._row(delivery_id)

    async def dispatch(self, delivery_id):
        envelope = self.store.delivery_envelope(delivery_id)
        if envelope is None:
            raise Refused("not_found")
        async with self._locks.setdefault(envelope["runtimeId"], asyncio.Lock()):
            # An earlier dispatch can settle and rotate the attempt while this
            # caller waits for the runtime lock.
            envelope = self.store.delivery_envelope(delivery_id)
            if envelope is None:
                raise Refused("not_found")
            row = self._row(delivery_id)
            if row["status"] != "queued":
                return row
            mapping = self.store.get_attachment(envelope["runtimeId"])
            if not mapping or mapping["leaseExpiresAt"] <= self.clock():
                return self._row(delivery_id, "client_unavailable")
            adapter = await self._available_adapter(mapping)
            if adapter is None:
                return self._row(delivery_id, "client_unavailable_or_busy")
            try:
                if not self.store.begin_claim(delivery_id):
                    return self._row(delivery_id)
            except StoreError:
                return self._row(delivery_id, "capacity")
            admission = await self._claim(delivery_id)
            if admission == "over_budget":
                return self._row(delivery_id, "over_budget")
            if admission is None:
                return self._row(delivery_id, "claim_outcome_unknown")
            try:
                current = self.store.get_attachment(envelope["runtimeId"])
                if (not current or
                        {key: value for key, value in current.items() if key != "leaseExpiresAt"}
                        != {key: value for key, value in mapping.items() if key != "leaseExpiresAt"}
                        or not await self._adapter_available(adapter)):
                    return await self._retire_local(delivery_id, "admission_fenced")
                request = validate_request(await adapter.prepare(admission), admission)
                if request["threadId"] != mapping.get("nativeThreadId"):
                    raise NativeError("invalid_native_mapping")
                if not self.store.begin_native(delivery_id, envelope["attemptId"], request):
                    return await self._retire_local(delivery_id, "admission_expired_or_fenced")
            except asyncio.CancelledError:
                # Still admitted: reconcile can prove that no event operation began.
                raise
            except Exception:
                return await self._retire_local(delivery_id, "native_preparation_failed")
            attempt = self.store.current_attempt(delivery_id)
            try:
                receipt = await asyncio.wait_for(adapter.submit(request), 10)
                return await self._receipt(delivery_id, attempt, receipt)
            except asyncio.CancelledError:
                # Settlement cancellation preserves pending proof; only an unresolved
                # native operation transitions to ambiguity.
                if self.store.current_attempt(delivery_id)["state"] == "submitting":
                    self.store.finish(delivery_id, "ambiguous", reason="native_outcome_unknown",
                                      attempt_id=attempt["attempt_id"])
                raise
            except Exception:
                if self.store.current_attempt(delivery_id)["state"] == "submitting":
                    return self.store.finish(delivery_id, "ambiguous", reason="native_outcome_unknown",
                                             attempt_id=attempt["attempt_id"])
                return self._row(delivery_id, "native_outcome_unknown")

    async def reconcile(self, delivery_id):
        envelope = self.store.delivery_envelope(delivery_id)
        if envelope is None:
            return None
        async with self._locks.setdefault(envelope["runtimeId"], asyncio.Lock()):
            attempt = self.store.current_attempt(delivery_id)
            if not attempt:
                return self._row(delivery_id)
            if attempt["state"] == "claiming":
                admission = await self._claim(delivery_id)
                if admission == "over_budget":
                    return self._row(delivery_id, "over_budget")
                if admission is None:
                    return self._row(delivery_id, "claim_outcome_unknown")
                return await self._retire_local(delivery_id, "recovered_claim_not_submitted")
            if attempt["state"] == "admitted":
                return await self._retire_local(delivery_id, "recovered_admission_not_submitted")
            if attempt["state"] == "settlement_pending":
                return await self._settle(delivery_id)
            if attempt.get("started_receipt") or attempt.get("input_recorded_receipt"):
                result = await self._ack_native(delivery_id, attempt["attempt_id"])
                attempt = self.store.current_attempt(delivery_id)
                if attempt.get("input_recorded_receipt") or attempt["ack_state"] != "submitted":
                    return result
            if attempt["state"] not in ("submitting", "submitted", "ambiguous"):
                return self._row(delivery_id)
            mapping = self.store.get_attachment(envelope["runtimeId"])
            if (not mapping or attempt["fenced"]
                    or any(mapping.get(key) != envelope.get(key) for key in FENCES[:7])
                    or mapping.get("nativeThreadId") != attempt["native_request"]["threadId"]):
                return self._row(delivery_id, "attachment_fenced")
            try:
                adapter = self.adapter_factory(mapping)
                receipt = await asyncio.wait_for(adapter.reconcile(attempt["native_request"]), 10)
                outcome = validate_receipt(attempt["native_request"], receipt, allow_input_recorded=True)
                if outcome["status"] in ("started", "terminalNotStarted") and not outcome["replayed"]:
                    raise NativeError()
                return await self._receipt(delivery_id, attempt, receipt, allow_input_recorded=True)
            except Exception:
                return self._row(delivery_id, "reconciliation_unknown")
