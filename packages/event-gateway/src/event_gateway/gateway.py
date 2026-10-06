"""Delivery state machine with fail-closed authority and presence seams."""

# This is a local integration interface, not a cloud API frozen by PR1. No
# production authority or qualified Codex presence provider ships in this stage.

import asyncio
from dataclasses import dataclass
import time
import re

from .codex import CodexError
from .protocol import parse_envelope, matches_delivery_id
from .security import verify


class Refused(ValueError):
    def __init__(self, code):
        """Expose a bounded refusal code without payload details."""
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class Permit:
    """A freshly authenticated, single-use admission; never cached offline."""

    delivery_id: str
    attempt_id: str
    issued_at: float
    expires_at: float
    identity: tuple


FENCES = (
    "principal",
    "agent",
    "runtimeId",
    "nodeGeneration",
    "runtimeGeneration",
    "attachmentGeneration",
    "consumerGeneration",
    "sourceStateVersion",
    "policyRevision",
)


def identity(envelope):
    return tuple(envelope.get(key) for key in FENCES)


def valid_native_id(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None
    )


class UnavailableAuthority:
    async def admit(self, envelope):
        raise Refused("authority_unavailable")

    async def acknowledge(self, envelope, evidence):
        raise Refused("authority_unavailable")


class Gateway:
    def __init__(
        self, store, authority, adapter_factory, *, audience, keys, clock=time.time
    ):
        """Bind local storage to explicit trusted integration providers."""
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

    def _permit_valid(self, permit, envelope):
        now = self.clock()
        return (
            isinstance(permit, Permit)
            and permit.delivery_id == envelope["deliveryId"]
            and permit.attempt_id == envelope["attemptId"]
            and permit.identity == identity(envelope)
            and permit.issued_at <= now < permit.expires_at
            and 0 < permit.expires_at - permit.issued_at <= 5
        )

    async def dispatch(self, delivery_id):
        envelope = self.store.delivery_envelope(delivery_id)
        if envelope is None:
            raise Refused("not_found")
        runtime = envelope["runtimeId"]
        lock = self._locks.setdefault(runtime, asyncio.Lock())
        async with lock:
            row = self.store.delivery(delivery_id)
            if row["status"] != "queued":
                return row
            mapping = self.store.get_attachment(runtime)
            if not mapping or mapping["leaseExpiresAt"] <= self.clock():
                return {**row, "reason": "client_unavailable"}
            try:
                adapter = self.adapter_factory(mapping)
                available = await adapter.check() == "available"
            except (Refused, CodexError, OSError):
                available = False
            if not available:
                return {**row, "reason": "client_unavailable_or_busy"}
            try:
                permit = await asyncio.wait_for(self.authority.admit(envelope), 8)
            except (Refused, TimeoutError, OSError):
                return {**row, "reason": "authority_unavailable"}
            # Remote awaits may race detach, transfer, expiration, and client exit.
            current = self.store.get_attachment(runtime)
            if (
                current != mapping
                or not self._permit_valid(permit, envelope)
                or await adapter.check() != "available"
            ):
                return {**row, "reason": "admission_fenced"}
            if not self._permit_valid(permit, envelope):
                return {**row, "reason": "admission_expired"}
            if not self.store.begin_submit(delivery_id):
                return self.store.delivery(delivery_id)
            try:
                # Submission already durably started: EVERY error is uncertain.
                result = await asyncio.wait_for(adapter.submit(envelope), 10)
                submission_id = result["submission_id"]
                if not valid_native_id(submission_id):
                    raise Refused("invalid_native_receipt")
                # Detach/transfer can fence the in-flight native call. Retain
                # its authentic receipt without undoing the ambiguous state.
                state = self.store.delivery(delivery_id)["status"]
                row = self.store.finish(
                    delivery_id,
                    "ambiguous" if state == "ambiguous" else "submitted",
                    submission_id=submission_id,
                )
            except asyncio.CancelledError:
                self.store.finish(
                    delivery_id, "ambiguous", reason="native_outcome_unknown"
                )
                raise
            except Exception:
                return self.store.finish(
                    delivery_id, "ambiguous", reason="native_outcome_unknown"
                )
            if row["status"] == "submitted":
                await self._acknowledge(envelope, result)
            return row

    async def _acknowledge(self, envelope, evidence):
        expected_state = self.store.delivery(envelope["deliveryId"])["status"]
        try:
            await asyncio.wait_for(self.authority.acknowledge(envelope, evidence), 8)
        except (Refused, TimeoutError, OSError):
            # Durable row owns ACK recovery; never retry the native submission.
            return False
        self.store.mark_acknowledged(envelope["deliveryId"], expected_state)
        return True

    async def reconcile(self, delivery_id):
        envelope = self.store.delivery_envelope(delivery_id)
        if envelope is None:
            return None
        lock = self._locks.setdefault(envelope["runtimeId"], asyncio.Lock())
        async with lock:
            row = self.store.delivery(delivery_id)
            if not row or row["status"] not in ("submitted", "ambiguous", "observed"):
                return row
            receipt = self.store.native_receipt(delivery_id) or {}
            # Stored receipts can retry historical ACKs even after client exit.
            if receipt.get("ack_pending"):
                await self._acknowledge(envelope, {**receipt, "status": row["status"]})
            row = self.store.delivery(delivery_id)
            if row["status"] == "observed":
                return row
            mapping = self.store.get_attachment(envelope["runtimeId"])
            if (
                not mapping
                or mapping["leaseExpiresAt"] <= self.clock()
                or any(mapping.get(key) != envelope.get(key) for key in FENCES[:7])
            ):
                return {**row, "reason": "attachment_fenced"}
            try:
                adapter = self.adapter_factory(mapping)
                result = await asyncio.wait_for(
                    adapter.reconcile(
                        delivery_id, known_submission_id=receipt.get("submission_id")
                    ),
                    10,
                )
            except Exception:
                return {**row, "reason": "reconciliation_unknown"}
            # Native evidence belongs only to the unchanged, live destination.
            current = self.store.get_attachment(envelope["runtimeId"])
            if current != mapping or current["leaseExpiresAt"] <= self.clock():
                return {**self.store.delivery(delivery_id), "reason": "attachment_fenced"}
            if result.get("status") in ("submitted", "observed") and not valid_native_id(
                result.get("submission_id")
            ):
                return {**row, "reason": "invalid_native_receipt"}
            if (
                receipt.get("submission_id") is not None
                and result.get("status") in ("submitted", "observed")
                and result.get("submission_id") != receipt["submission_id"]
            ):
                return {**row, "reason": "native_receipt_conflict"}
            if result.get("status") == "observed" and not valid_native_id(
                result.get("turn_id")
            ):
                return {**row, "reason": "invalid_native_receipt"}
            if result.get("status") == "observed":
                row = self.store.finish(
                    delivery_id,
                    "observed",
                    submission_id=result.get("submission_id"),
                    turn_id=result["turn_id"],
                )
            elif result.get("status") == "submitted":
                # Queue evidence can recover a lost response's authentic receipt;
                # preserve ambiguity until a native turn is correlated.
                self.store.finish(
                    delivery_id, row["status"], submission_id=result["submission_id"]
                )
            # Known queued evidence settles submitted only; ambiguity stays fenced
            # until consumption is correlated. No absent-history retry.
            if result.get("status") in ("submitted", "observed"):
                await self._acknowledge(envelope, result)
            return row
