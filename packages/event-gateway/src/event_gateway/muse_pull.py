"""Dormant local notification journal; trusted host metadata is not Muse authentication."""

from contextlib import contextmanager
import json
import math
import re
import sqlite3

from .messaging_protocol_v2 import _PRINCIPAL, _UUID, _matches
from .store import Store, StoreError, _json

_GENERATIONS = (
    "bindingGeneration",
    "nodeGeneration",
    "runtimeGeneration",
    "attachmentGeneration",
    "consumerGeneration",
)
_FIELDS = frozenset(
    (
        "slotId",
        "principal",
        "nodeId",
        "runtimeId",
        "sessionId",
        "leaseExpiresAt",
        *_GENERATIONS,
    )
)
_IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,256}")
_SLOT = re.compile(r"[A-Za-z0-9_.-]{1,64}")
MAX_NOTIFICATION_BYTES = 4096


def _binding(value, now):
    if (
        type(value) is not dict
        or value.keys() != _FIELDS
        or not _matches(_SLOT, value["slotId"])
        or not _matches(_PRINCIPAL, value["principal"])
        or len(value["principal"]) > 254
        or any(
            not _matches(_UUID, value[key])
            for key in ("nodeId", "runtimeId", "sessionId")
        )
        or any(
            type(value[key]) is not int or not 1 <= value[key] <= 2**53 - 1
            for key in _GENERATIONS
        )
        or type(value["leaseExpiresAt"]) not in (int, float)
    ):
        raise StoreError("invalid_muse_binding")
    try:
        live = (
            math.isfinite(now)
            and math.isfinite(value["leaseExpiresAt"])
            and value["leaseExpiresAt"] > now
        )
    except OverflowError:
        live = False
    if not live:
        raise StoreError("muse_binding_expired")
    return dict(value)


class MusePullJournal:
    """
    Use a separate bounded child ledger, without dispatch wiring.

    slotId is a stable host-owned consumer slot, never a caller-selected session key.
    A different slot is a different authority domain: this API promises no cross-slot
    fencing. Only an independently authenticated host may provision or use bindings.
    """

    def __init__(self, store, *, max_rows=1000, max_bytes=8 * 1024 * 1024):
        """Own a private child Store with independent capacity and writer lock."""
        self.store = Store(store.path / "muse-pull", clock=store.clock,
                           max_rows=max_rows, max_bytes=max_bytes)
        self.db = self.store.db
        try:
            self._initialize_schema()
        except BaseException:
            self.close()
            raise

    def close(self):
        """Release only this journal's connection and writer lock."""
        self.store.close()

    def __enter__(self):
        """Return this journal for a managed lifecycle."""
        return self

    def __exit__(self, *_):
        """Close the journal when leaving its managed lifecycle."""
        self.close()

    def _initialize_schema(self):
        with self._transaction():
            existing = {
                row[0]
                for row in self.db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                    "('muse_pull_bindings_v1','muse_pull_notifications_v1')"
                )
            }
            if existing and len(existing) != 2:
                raise StoreError("invalid_muse_schema")
            if not existing:
                self.store._capacity(65536)
                self.db.execute("""CREATE TABLE muse_pull_bindings_v1 (
                    slot TEXT PRIMARY KEY, metadata TEXT NOT NULL)""")
                self.db.execute("""CREATE TABLE muse_pull_notifications_v1 (
                    sequence INTEGER PRIMARY KEY, slot TEXT NOT NULL, generation INTEGER NOT NULL,
                    notification_id TEXT NOT NULL, reference TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','acked__')),
                    UNIQUE(slot,generation,notification_id))""")

    @contextmanager
    def _transaction(self):
        if self.db.in_transaction:
            raise StoreError("muse_nested_transaction")
        try:
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                yield
        except sqlite3.Error:
            raise StoreError("storage_unavailable") from None

    def _capacity(self, extra_rows, byte_reserve):
        # Count all generations and ACK tombstones; nothing is silently evicted.
        count = self.db.execute("""SELECT
            (SELECT COUNT(*) FROM muse_pull_bindings_v1) +
            (SELECT COUNT(*) FROM muse_pull_notifications_v1)""").fetchone()[0]
        if count + extra_rows > self.store.max_rows:
            raise StoreError("capacity")
        self.store._capacity(byte_reserve)

    def _current(self, value):
        binding = _binding(value, self.store.clock())
        row = self.db.execute(
            "SELECT metadata FROM muse_pull_bindings_v1 WHERE slot=?",
            (binding["slotId"],),
        ).fetchone()
        if row is None or json.loads(row[0]) != binding:
            raise StoreError("muse_binding_fenced")
        return binding

    def put_binding(self, trusted_binding):
        """Provision/rotate a trusted slot; same-generation live renewal keeps its queue."""
        binding = _binding(trusted_binding, self.store.clock())
        with self._transaction():
            row = self.db.execute(
                "SELECT metadata FROM muse_pull_bindings_v1 WHERE slot=?",
                (binding["slotId"],),
            ).fetchone()
            if row:
                old = json.loads(row[0])
                if binding == old:
                    return binding
                if binding["bindingGeneration"] < old["bindingGeneration"]:
                    raise StoreError("muse_binding_fenced")
                if binding["bindingGeneration"] == old["bindingGeneration"]:
                    if (
                        any(
                            binding[key] != old[key]
                            for key in _FIELDS - {"leaseExpiresAt"}
                        )
                        or old["leaseExpiresAt"] <= self.store.clock()
                        or binding["leaseExpiresAt"] < old["leaseExpiresAt"]
                    ):
                        raise StoreError("muse_binding_fenced")
            self._capacity(0 if row else 1, 32768)
            self.db.execute(
                """INSERT INTO muse_pull_bindings_v1 VALUES (?,?)
                ON CONFLICT(slot) DO UPDATE SET metadata=excluded.metadata""",
                (binding["slotId"], _json(binding)),
            )
        return binding

    def enqueue(self, trusted_binding, notification):
        """Persist a trusted opaque reference; duplicate identity never becomes new work."""
        if (
            type(notification) is not dict
            or notification.keys() != {"notificationId", "eventReference"}
            or any(not _matches(_IDENTIFIER, notification[key]) for key in notification)
            or len(_json(notification).encode("utf-8")) > MAX_NOTIFICATION_BYTES
        ):
            raise StoreError("invalid_muse_notification")
        with self._transaction():
            binding = self._current(trusted_binding)
            identity = (
                binding["slotId"],
                binding["bindingGeneration"],
                notification["notificationId"],
            )
            old = self.db.execute(
                """SELECT reference FROM muse_pull_notifications_v1
                WHERE slot=? AND generation=? AND notification_id=?""",
                identity,
            ).fetchone()
            if old:
                if old[0] != notification["eventReference"]:
                    raise StoreError("muse_notification_conflict")
                return dict(notification)
            self._capacity(1, 32768)
            self.db.execute(
                """INSERT INTO muse_pull_notifications_v1
                (slot,generation,notification_id,reference,state) VALUES (?,?,?,?,'pending')""",
                (*identity, notification["eventReference"]),
            )
        return dict(notification)

    def _pending(self, binding):
        return self.db.execute(
            """SELECT notification_id,reference FROM muse_pull_notifications_v1
            WHERE slot=? AND generation=? AND state='pending' ORDER BY sequence LIMIT 1""",
            (binding["slotId"], binding["bindingGeneration"]),
        ).fetchone()

    def read(self, trusted_binding):
        """Return at most one fixed-size notification; reads never advance the cursor."""
        with self._transaction():
            row = self._pending(self._current(trusted_binding))
            return {"notificationId": row[0], "eventReference": row[1]} if row else None

    def ack(self, trusted_binding, notification_id):
        """Consume the pending head idempotently; never a native or Cloud ACK."""
        if not _matches(_IDENTIFIER, notification_id):
            raise StoreError("invalid_muse_notification")
        with self._transaction():
            binding = self._current(trusted_binding)
            identity = (
                binding["slotId"],
                binding["bindingGeneration"],
                notification_id,
            )
            old = self.db.execute(
                """SELECT state FROM muse_pull_notifications_v1
                WHERE slot=? AND generation=? AND notification_id=?""",
                identity,
            ).fetchone()
            if old is None:
                raise StoreError("muse_ack_unknown")
            if old[0] != "acked__":
                pending = self._pending(binding)
                if pending is None or pending[0] != notification_id:
                    raise StoreError("muse_ack_out_of_order")
                # Equal-width state update allocates no new row or payload at capacity.
                self.db.execute(
                    """UPDATE muse_pull_notifications_v1 SET state='acked__'
                    WHERE slot=? AND generation=? AND notification_id=?""",
                    identity,
                )
        return {"notificationId": notification_id, "status": "acked"}
