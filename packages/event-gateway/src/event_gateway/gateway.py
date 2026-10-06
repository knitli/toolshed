"""
Delivery state machine. Authority and client-presence seams are fail closed.

This is a local integration interface, not a cloud API frozen by PR1. No
production authority or qualified Codex presence provider ships in this stage.
"""

import asyncio
from dataclasses import dataclass
import time
import re

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
        if any(mapping.get(key) != envelope.get(key) for key in FENCES[:6]):
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
            adapter = self.adapter_factory(mapping)
            if await adapter.check() != "available":
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
                row = self.store.finish(
                    delivery_id, "submitted", submission_id=submission_id
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
        row = self.store.delivery(delivery_id)
        if not row or row["status"] not in ("submitted", "ambiguous", "observed"):
            return row
        envelope = self.store.delivery_envelope(delivery_id)
        receipt = self.store.native_receipt(delivery_id) or {}
        if row["status"] == "observed":
            if receipt.get("ack_pending"):
                await self._acknowledge(envelope, {**receipt, "status": "observed"})
            return self.store.delivery(delivery_id)
        mapping = self.store.get_attachment(envelope["runtimeId"])
        if not mapping:
            return {**row, "reason": "client_unavailable"}
        adapter = self.adapter_factory(mapping)
        try:
            result = await asyncio.wait_for(
                adapter.reconcile(
                    delivery_id, known_submission_id=receipt.get("submission_id")
                ),
                10,
            )
        except Exception:
            return {**row, "reason": "reconciliation_unknown"}
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
