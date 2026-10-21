"""Durable cloud admission and native no-start settlement state machine."""

import asyncio
import contextlib
import time

from .cloud import CloudError, _iso, _timestamp
from .codex import CodexError
from .native import NativeError, validate_request, validate_receipt
from .protocol import parse_envelope, matches_delivery_id
from .security import verify
from .store import StoreError, RETRYABLE_CLAIM_REFUSALS


class Refused(ValueError):
    def __init__(self, code):
        """Create a refusal with a stable machine-readable code."""
        self.code = code
        super().__init__(code)


class _Retire(Exception):
    """Internal signal to retire the admitted attempt locally."""

    def __init__(self, reason):
        """Carry the local-retirement reason."""
        self.reason = reason
        super().__init__(reason)


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


class _RuntimeLock:
    """One asyncio.Lock plus its in-flight user count (holders + waiters)."""

    __slots__ = ("lock", "users")

    def __init__(self):
        self.lock = asyncio.Lock()
        self.users = 0


class Gateway:
    def __init__(self, store, authority, adapter_factory, *, audience, keys, clock=time.time,
                 stock_codex_binary=None):
        """Bind durable storage to explicitly injected authority and native providers."""
        self.store, self.authority = store, authority
        self.adapter_factory, self.clock = adapter_factory, clock
        self.audience, self.keys = audience, dict(keys)
        self.stock_codex_binary = stock_codex_binary
        self._locks = {}  # runtimeId -> _RuntimeLock, only while in flight

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

    def accept_messaging_v2(self, body, *, signature, audience, key_id, node_id, runtime_id):
        """Callable-only authenticated journal entry; the active listener remains v1."""
        from .messaging_admission_v2 import validate_authenticated_envelope

        if audience != self.audience or key_id not in self.keys:
            raise Refused("invalid_transport_authority")
        envelope = validate_authenticated_envelope(
            body, signature=signature, audience=audience, public_key=self.keys[key_id],
            expected_audience=self.audience, node_id=node_id,
            attachment=self.store.get_attachment(runtime_id), now_ms=self.clock() * 1000,
        )
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
            uncertain = self.store.note_claim_request(delivery_id, attempt["attempt_id"])
            try:
                admission = await asyncio.wait_for(self.authority.claim(attempt["envelope"]), 8)
            except CloudError as error:
                # Pre-send failures cannot rule out an earlier lost claim response.
                if error.ambiguous or not error.definitive_refusal:
                    return None
                if error.code in RETRYABLE_CLAIM_REFUSALS:
                    self.store.note_claim_refusal(delivery_id, attempt["attempt_id"], error.code, uncertain=uncertain)
                    return error.code
                if uncertain:
                    return None
                self.store.reject_claim(delivery_id, attempt["attempt_id"])
                return "refused"
            if isinstance(admission, dict) and admission.get("status") == "over_budget":
                self.store.note_claim_refusal(delivery_id, attempt["attempt_id"], "over_budget", uncertain=uncertain)
                return "over_budget"
            # No await or post-admission gate may precede this durable write.
            return self.store.record_admission(delivery_id, admission)
        except Exception:
            # Claim intent survives every uncertain response/storage failure.
            return None

    async def _claim_messaging_history(self, delivery_id):
        """Private one-shot path through the injected trusted cloud authority."""
        envelope = self._require_envelope(delivery_id)
        if envelope.get("schemaVersion") != 2:
            return self._row(delivery_id, "messaging_v2_disabled")
        async with self._runtime_guard(envelope["runtimeId"]):
            attempt = self.store.current_attempt(delivery_id)
            if attempt is not None:
                if attempt["admission"] is not None:
                    return attempt["admission"]
                if attempt["evidence"] is not None and not attempt["claim_uncertain"]:
                    return attempt["evidence"]
                return self._row(delivery_id, "claim_outcome_unknown")
            attempt = self.store._begin_messaging_claim_history(delivery_id)
            if attempt is None:
                return self._row(delivery_id, "claim_outcome_unknown")
            try:
                result = await asyncio.wait_for(
                    self.authority.claim_messaging_history(attempt["envelope"]), 8,
                )
                # Record immediately; a failed write leaves the pre-RPC intent unknown.
                if isinstance(result, dict) and result.get("status") == "over_budget":
                    return self.store._record_messaging_claim_refusal(delivery_id, result)
                return self.store._record_messaging_admission_history(
                    delivery_id, result, node_id=attempt["envelope"]["nodeId"],
                )
            except Exception:
                return self._row(delivery_id, "claim_outcome_unknown")

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

    def _require_envelope(self, delivery_id):
        """Return the delivery envelope or raise not_found."""
        envelope = self.store.delivery_envelope(delivery_id)
        if envelope is None:
            raise Refused("not_found")
        return envelope

    async def _dispatch_adapter(self, delivery_id, envelope):
        """Resolve (mapping, adapter) or an early client-unavailable row."""
        mapping = self.store.get_attachment(envelope["runtimeId"])
        if not mapping or mapping["leaseExpiresAt"] <= self.clock():
            return None, None, self._row(delivery_id, "client_unavailable")
        adapter = await self._available_adapter(mapping)
        if adapter is None:
            return None, None, self._row(delivery_id, "client_unavailable_or_busy")
        return mapping, adapter, None

    def _begin_claim_or_row(self, delivery_id):
        """Begin claiming; return an early row when dispatch cannot proceed."""
        try:
            if not self.store.begin_claim(delivery_id):
                return self._row(delivery_id)
        except StoreError:
            return self._row(delivery_id, "capacity")
        return None

    async def _admission_or_row(self, delivery_id):
        """Claim admission; return (admission, None) or (None, early row)."""
        admission = await self._claim(delivery_id)
        if admission in ("over_budget", *RETRYABLE_CLAIM_REFUSALS):
            return None, self._row(delivery_id, admission)
        if admission == "refused":
            return None, self._row(delivery_id)
        if admission is None:
            return None, self._row(delivery_id, "claim_outcome_unknown")
        return admission, None

    @staticmethod
    def _attachment_rotated(mapping, current):
        """Detect attachment rotation, ignoring lease expiry timestamps."""
        if not current:
            return True
        old = {key: value for key, value in mapping.items() if key != "leaseExpiresAt"}
        new = {key: value for key, value in current.items() if key != "leaseExpiresAt"}
        return old != new

    async def _admission_fenced(self, mapping, adapter, runtime_id):
        """Check whether the admission lost its attachment or client."""
        current = self.store.get_attachment(runtime_id)
        return (self._attachment_rotated(mapping, current)
                or not await self._adapter_available(adapter))

    async def _prepare_native_request(self, delivery_id, envelope, mapping, adapter, admission):
        """Prepare the native request or raise _Retire with the reason."""
        try:
            if await self._admission_fenced(mapping, adapter, envelope["runtimeId"]):
                raise _Retire("admission_fenced")
            request = validate_request(await adapter.prepare(admission), admission)
            if request["threadId"] != mapping.get("nativeThreadId"):
                raise NativeError("invalid_native_mapping")
            if not self.store.begin_native(delivery_id, envelope["attemptId"], request):
                raise _Retire("admission_expired_or_fenced")
            return request
        except asyncio.CancelledError:
            # Still admitted: reconcile can prove that no event operation began.
            raise
        except _Retire:
            raise
        except Exception:
            raise _Retire("native_preparation_failed")

    async def _submit_native(self, delivery_id, adapter, attempt, request):
        """Submit the native request and settle the receipt outcome."""
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

    async def _dispatch_locked(self, delivery_id):
        """Run the admitted-submission pipeline under the runtime lock."""
        envelope = self._require_envelope(delivery_id)
        if envelope.get("runtimeProfile") is not None:
            return await self._dispatch_stock_locked(delivery_id, envelope)
        if envelope.get("schemaVersion") != 1:
            return self._row(delivery_id, "messaging_v2_disabled")
        row = self._row(delivery_id)
        if row["status"] != "queued":
            return row
        mapping, adapter, early = await self._dispatch_adapter(delivery_id, envelope)
        if early is not None:
            return early
        early = self._begin_claim_or_row(delivery_id)
        if early is not None:
            return early
        admission, early = await self._admission_or_row(delivery_id)
        if early is not None:
            return early
        try:
            request = await self._prepare_native_request(
                delivery_id, envelope, mapping, adapter, admission)
        except _Retire as retire:
            return await self._retire_local(delivery_id, retire.reason)
        attempt = self.store.current_attempt(delivery_id)
        return await self._submit_native(delivery_id, adapter, attempt, request)

    def _stock_acknowledgment(self, envelope):
        acknowledgment = {
            "schemaVersion": 1,
            **{key: envelope[key] for key in (
                "eventId", "deliveryId", "attemptId", "principal", "agent", "runtimeId",
                "nodeGeneration", "runtimeGeneration", "attachmentGeneration",
            )},
            "deliveredSourceStateVersion": envelope["sourceStateVersion"],
            "acknowledgedAt": _iso(self.clock()),
            "status": "command_accepted",
            "runtimeProfile": envelope["runtimeProfile"],
        }
        if "consumerGeneration" in envelope:
            acknowledgment["consumerGeneration"] = envelope["consumerGeneration"]
        return acknowledgment

    async def _send_stock_acknowledgment(self, delivery_id, attempt):
        acknowledgment = attempt.get("native_ack")
        admission = attempt.get("admission")
        if not acknowledgment or not admission:
            return self._row(delivery_id, "command_outcome_unknown")
        envelope = admission["envelope"]
        try:
            result = await asyncio.wait_for(self.authority.acknowledge(envelope, acknowledgment), 8)
            if not isinstance(result, dict) or result.get("status") != "command_accepted":
                raise Refused("invalid_acknowledgment")
            if not self.store.complete_stock_acknowledgment(
                    delivery_id, attempt["attempt_id"], acknowledgment):
                raise StoreError("acknowledgment_conflict")
        except Exception:
            return self._row(delivery_id, "stock_ack_pending")
        return self._row(delivery_id)

    # Keep the durable fence, launch and ambiguous-outcome handling in one reviewed sequence.
    async def _dispatch_stock_locked(self, delivery_id, envelope):  # noqa: MC0001
        """Claim and queue one opaque reference through the assigned stock CLI."""
        from .stock_codex import StockCodexAdapter
        from .protocol import ProtocolError, validate_runtime_profile

        row = self._row(delivery_id)
        if row["status"] not in ("queued", "claiming", "admitted"):
            return row
        try:
            profile = validate_runtime_profile(envelope.get("runtimeProfile"))
            self.store._matches(envelope)
        except (ProtocolError, StoreError):
            return self._row(delivery_id, "stock_assignment_unavailable")
        if profile["client"] != "codex":
            return self._row(delivery_id, "unsupported_stock_client")
        if not self.stock_codex_binary:
            return self._row(delivery_id, "stock_client_disabled")
        attempt = self.store.current_attempt(delivery_id)
        if attempt is None:
            early = self._begin_claim_or_row(delivery_id)
            if early is not None:
                return early
            admission, early = await self._admission_or_row(delivery_id)
            if early is not None:
                return early
        elif attempt["state"] == "claiming":
            admission, early = await self._admission_or_row(delivery_id)
            if early is not None:
                return early
        elif attempt["state"] == "admitted" and attempt["admission"] is not None:
            admission = attempt["admission"]
        else:
            return self._row(delivery_id)

        if _timestamp(admission["permitExpiresAt"]) <= self.clock() * 1000:
            return await self._retire_local(delivery_id, "admission_expired")
        try:
            self.store._matches(admission["envelope"])
        except StoreError:
            return await self._retire_local(delivery_id, "admission_fenced")
        try:
            # This durable transition precedes every await that can launch the client.
            self.store.begin_stock_submit(delivery_id, envelope["attemptId"])
        except StoreError:
            return self._row(delivery_id, "stock_submission_not_started")
        adapter = StockCodexAdapter(profile["conversationId"], self.stock_codex_binary)
        try:
            await adapter.submit(envelope["eventReference"])
        except asyncio.CancelledError:
            try:
                self.store.finish(delivery_id, "ambiguous", reason="client_outcome_unknown",
                                  attempt_id=envelope["attemptId"])
            except StoreError:
                pass
            raise
        except Exception:
            try:
                return self.store.finish(delivery_id, "ambiguous", reason="client_outcome_unknown",
                                         attempt_id=envelope["attemptId"])
            except StoreError:
                return self._row(delivery_id, "client_outcome_unknown")
        try:
            acknowledgment = self.store.record_stock_command_accepted(
                delivery_id, envelope["attemptId"],
                self._stock_acknowledgment(admission["envelope"]),
            )
        except Exception:
            # CLI launch may have succeeded; an unwritten result must never be replayed.
            try:
                self.store.finish(delivery_id, "ambiguous", reason="client_outcome_unknown",
                                  attempt_id=envelope["attemptId"])
            except StoreError:
                pass
            return self._row(delivery_id, "client_outcome_unknown")
        attempt = self.store.current_attempt(delivery_id)
        attempt["native_ack"] = acknowledgment
        return await self._send_stock_acknowledgment(delivery_id, attempt)

    @contextlib.asynccontextmanager
    async def _runtime_guard(self, runtime_id):
        """Hold the runtime lock until its last holder or waiter leaves."""
        # The increment runs synchronously (no await) before acquisition, covering
        # waiters as well as the holder; the decrement+delete runs synchronously
        # (no await) after release. On a single event loop this makes deletion safe:
        # an entry with users == 0 has no holder and no waiter.
        entry = self._locks.get(runtime_id)
        if entry is None:
            entry = self._locks[runtime_id] = _RuntimeLock()
        try:
            entry.users += 1
            async with entry.lock:
                yield
        finally:
            entry.users -= 1
            if entry.users == 0 and self._locks.get(runtime_id) is entry:
                del self._locks[runtime_id]

    async def dispatch(self, delivery_id):
        """Dispatch one queued delivery through claim, submit, and settle."""
        envelope = self._require_envelope(delivery_id)
        async with self._runtime_guard(envelope["runtimeId"]):
            # An earlier dispatch can settle and rotate the attempt while this
            # caller waits for the runtime lock.
            return await self._dispatch_locked(delivery_id)

    async def reconcile(self, delivery_id):
        envelope = self.store.delivery_envelope(delivery_id)
        if envelope is None:
            return None
        if envelope.get("runtimeProfile") is not None:
            async with self._runtime_guard(envelope["runtimeId"]):
                attempt = self.store.current_attempt(delivery_id)
                if (attempt and attempt["state"] == "command_accepted"
                        and attempt.get("native_ack")):
                    return await self._send_stock_acknowledgment(delivery_id, attempt)
                if (not attempt or attempt["state"] in ("claiming", "admitted")
                        and self._row(delivery_id)["status"] in ("queued", "claiming", "admitted")):
                    return await self._dispatch_stock_locked(delivery_id, envelope)
                return self._row(delivery_id)
        if envelope.get("schemaVersion") != 1:
            return self._row(delivery_id, "messaging_v2_disabled")
        async with self._runtime_guard(envelope["runtimeId"]):
            attempt = self.store.current_attempt(delivery_id)
            if not attempt:
                return self._row(delivery_id)
            if attempt["state"] == "claiming":
                admission = await self._claim(delivery_id)
                if admission in ("over_budget", *RETRYABLE_CLAIM_REFUSALS):
                    return self._row(delivery_id, admission)
                if admission == "refused":
                    return self._row(delivery_id)
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
