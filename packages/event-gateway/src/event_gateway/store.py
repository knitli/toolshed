"""Private, single-writer durable delivery ledger."""

import fcntl
import hashlib
import json
import math
import os
import re
from pathlib import Path
import sqlite3
import stat
import time
import uuid
from datetime import datetime


class StoreError(ValueError):
    def __init__(self, code, message=None):
        """Create an error with a stable machine-readable code."""
        self.code = code
        super().__init__(message or code)


IDENTITY = (
    "runtimeId",
    "principal",
    "agent",
    "nodeGeneration",
    "runtimeGeneration",
    "attachmentGeneration",
)
RETENTION = 7 * 86400
CLAIM_RESERVE = 262144
RETRYABLE_CLAIM_REFUSALS = ("conflict", "capacity", "coordinator_capacity", "native_binding_unqualified")
MESSAGING_METADATA = ("routingGeneration", "namespace", "agentIncarnation")


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _assigned_stock_v2(envelope):
    profile = envelope.get("runtimeProfile") if isinstance(envelope, dict) else None
    return (envelope.get("schemaVersion") == 2 and isinstance(profile, dict)
            and profile.get("profile") == "assigned_stock_client")


def validate_native_route(mapping, *, allow_legacy=False):
    """Validate an exact launcher route; live adapter factories cannot omit it."""
    from .cloud import CloudError, _native_binding, _uuid

    if not isinstance(mapping, dict):
        raise StoreError("invalid_attachment")
    # Historical injected-adapter fixtures have no admitted binding or launcher route.
    if allow_legacy and "nativeBinding" not in mapping and "sessionId" not in mapping:
        return None
    if not _uuid(mapping.get("sessionId")):
        raise StoreError("invalid_attachment")
    try:
        binding = _native_binding(mapping.get("nativeBinding"))
    except CloudError:
        raise StoreError("invalid_attachment") from None
    if mapping.get("nativeThreadId") != binding["threadId"]:
        raise StoreError("invalid_attachment")
    return binding


class Store:
    def __init__(
        self, state_dir, clock=time.time, max_rows=1000, max_bytes=64 * 1024 * 1024
    ):
        """Open and exclusively lock a private durable delivery ledger."""
        self.clock, self.max_rows, self.max_bytes = clock, max_rows, max_bytes
        self.path = Path(state_dir).absolute()
        self.db = None
        self.lock = None
        self.blocked_reason = None
        if max_rows < 1 or max_bytes < 1:
            raise ValueError("positive store limits required")
        from .security import SecurityError, ensure_private_directory

        try:
            self.path = ensure_private_directory(self.path)
        except SecurityError as exc:
            raise StoreError("unsafe_state") from exc
        try:
            self._open_locked()
            self._initialize_schema()
            self._reclaim_overgrowth()
            self._capacity()
        except BaseException:
            self.close()
            raise

    def _page_budget(self):
        """Bound database + one full WAL + shared-memory/index overhead."""
        return max(1, (self.max_bytes - 65536) // (3 * 4096))

    def _open_locked(self):
        """Acquire the exclusive writer lock and open the ledger database."""
        self.lock = os.open(
            self.path / "writer.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        self._check(self.path / "writer.lock")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise StoreError("writer_locked") from exc
        for file in self.path.glob("ledger.sqlite*"):
            self._check(file)
        fd = os.open(
            self.path / "ledger.sqlite",
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
            0o600,
        )
        os.close(fd)
        self.db = sqlite3.connect(self.path / "ledger.sqlite")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA wal_autocheckpoint=1")
        self.db.execute("PRAGMA journal_size_limit=0")
        self.db.execute(f"PRAGMA max_page_count={self._page_budget()}")

    def _ensure_attempt_columns(self):
        """Add receipt/ack columns missing from older attempt tables."""
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(attempts)")}
        if "claim_uncertain" not in columns:
            # Legacy claims may already have been sent without a durable response.
            self.db.execute("ALTER TABLE attempts ADD COLUMN claim_uncertain INTEGER NOT NULL DEFAULT 1")
        if "started_receipt" not in columns:
            self.db.execute("ALTER TABLE attempts ADD COLUMN started_receipt TEXT")
        if "native_ack" not in columns:
            self.db.execute("ALTER TABLE attempts ADD COLUMN native_ack TEXT")
        for column in ("input_recorded_receipt", "native_observed_ack"):
            if column not in columns:
                self.db.execute(f"ALTER TABLE attempts ADD COLUMN {column} TEXT")
        if "operator_disposition" not in columns:
            self.db.execute("ALTER TABLE attempts ADD COLUMN operator_disposition TEXT")

    def _initialize_schema(self):
        """Create tables, migrate columns, and mark interrupted submits ambiguous."""
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in (0, 1, 2, 3, 4, 5):
            raise StoreError("unsupported_schema")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS attachments (runtime TEXT PRIMARY KEY, data TEXT NOT NULL)"
            )
            self.db.execute("""CREATE TABLE IF NOT EXISTS deliveries (
                id TEXT PRIMARY KEY, dedup TEXT UNIQUE NOT NULL, semantic TEXT NOT NULL,
                envelope TEXT NOT NULL, runtime TEXT NOT NULL, agent TEXT NOT NULL,
                state TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
                retain_until REAL NOT NULL, submission TEXT, turn TEXT, reason TEXT, ack_state TEXT)""")
            self.db.execute(
                "CREATE INDEX IF NOT EXISTS delivery_state ON deliveries(state)"
            )
            self.db.execute("""CREATE TABLE IF NOT EXISTS stock_watches (
                runtime TEXT NOT NULL, subject TEXT NOT NULL, incarnation INTEGER NOT NULL,
                data TEXT NOT NULL, updated REAL NOT NULL,
                PRIMARY KEY(runtime, subject, incarnation))""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS attempts (
                delivery_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
                state TEXT NOT NULL, envelope TEXT NOT NULL, admission TEXT,
                native_request TEXT, evidence TEXT, receipt TEXT, settlement TEXT, started_receipt TEXT,
                native_ack TEXT, input_recorded_receipt TEXT, native_observed_ack TEXT,
                reason TEXT, fenced INTEGER NOT NULL DEFAULT 0,
                reserved_bytes INTEGER NOT NULL, updated REAL NOT NULL,
                PRIMARY KEY(delivery_id,attempt_id))""")
            self._ensure_attempt_columns()
            if version < 3:
                self._migrate_native_turn_aliases()
            if version < 4:
                self.db.execute("PRAGMA user_version=4")
            self.db.execute(
                "UPDATE attempts SET state='ambiguous', reason='restart_during_submit', updated=? WHERE state='submitting'",
                (self.clock(),),
            )
            self.db.execute(
                "UPDATE deliveries SET state='ambiguous', reason='restart_during_submit', updated=? WHERE state='submitting'",
                (self.clock(),),
            )

    def _reclaim_overgrowth(self):
        """Vacuum the ledger when cleanup cannot bring it under budget."""
        reclaimed = self.cleanup()
        if reclaimed and self._size() > self.max_bytes:
            # DELETE frees SQLite pages but does not shrink the database file.
            self.db.execute("VACUUM")
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.execute(f"PRAGMA max_page_count={self._page_budget()}")

    def _check(self, path, directory=False):
        info = path.lstat()
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        if (
            not expected(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
        ):
            raise StoreError("unsafe_state")
        if not directory and info.st_nlink != 1:
            raise StoreError("unsafe_state")

    def _migrate_native_turn_aliases(self):
        """Clear only queue aliases proven to be retained native Started turns."""
        from .native import NativeError, validate_receipt

        rows = self.db.execute("""SELECT a.delivery_id,a.attempt_id,a.native_request,a.started_receipt,
                                        d.envelope,d.submission,d.turn
                                 FROM attempts a JOIN deliveries d ON d.id=a.delivery_id
                                 WHERE a.started_receipt IS NOT NULL AND a.state!='settled'
                                   AND d.submission IS NOT NULL""").fetchall()
        for row in rows:
            try:
                if json.loads(row["envelope"])["attemptId"] != row["attempt_id"]:
                    continue
                outcome = validate_receipt(json.loads(row["native_request"]), json.loads(row["started_receipt"]))
            except (NativeError, TypeError, ValueError, KeyError):
                continue
            turn = outcome.get("turnId") if outcome.get("status") == "started" else None
            if turn and row["submission"] == turn and row["turn"] == turn:
                self.db.execute("""UPDATE deliveries SET submission=NULL,
                                    reason=CASE WHEN reason='native_started_ack_unqualified'
                                                THEN 'native_started_ack_pending' ELSE reason END
                                    WHERE id=?""", (row["delivery_id"],))
                self.db.execute("UPDATE attempts SET reason='native_started_ack_pending' WHERE delivery_id=? AND attempt_id=?",
                                (row["delivery_id"], row["attempt_id"]))

    def _size(self):
        total = 0
        for file in self.path.glob("ledger.sqlite*"):
            self._check(file)
            total += file.stat().st_size
        return total

    def _capacity(self, reserve=0, *, credit=0):
        # All writers account for durable claim reservations, including after restart.
        reserved = self.db.execute("SELECT COALESCE(SUM(reserved_bytes),0) FROM attempts").fetchone()[0]
        reserve += max(0, reserved - credit)
        # Reserve pages for WAL + checkpoint copy before committing new data.
        pages = self.db.execute("PRAGMA page_count").fetchone()[0]
        free = self.db.execute("PRAGMA freelist_count").fetchone()[0]
        maximum = self.db.execute("PRAGMA max_page_count").fetchone()[0]
        if (
            self._size() + reserve > self.max_bytes
            or (maximum - pages + free) * 4096 < reserve
        ):
            self.blocked_reason = "storage_capacity"
            raise StoreError("capacity", self.blocked_reason)
        self.blocked_reason = None

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None

    def __enter__(self):
        """Return the open store."""
        return self

    def __exit__(self, *args):
        """Close the database and release the writer lock."""
        self.close()

    def get_attachment(self, runtime_id):
        row = self.db.execute(
            "SELECT data FROM attachments WHERE runtime=?", (runtime_id,)
        ).fetchone()
        value = json.loads(row[0]) if row else None
        return value if value and value["leaseExpiresAt"] != 0 else None

    def get_stock_reassignment_source(self, runtime_id):
        """Read an assigned-stock Messaging row for an explicit cloud reassignment CAS."""
        row = self.db.execute(
            "SELECT data FROM attachments WHERE runtime=?", (runtime_id,)
        ).fetchone()
        value = json.loads(row[0]) if row else None
        profile = value.get("runtimeProfile") if value else None
        return value if (value and value.get("leaseExpiresAt") == 0
                         and "routingGeneration" in value
                         and isinstance(profile, dict)
                         and profile.get("profile") == "assigned_stock_client"
                         and profile.get("client") == "codex") else None

    def list_attachments(self):
        return [
            value
            for row in self.db.execute("SELECT data FROM attachments ORDER BY runtime")
            if (value := json.loads(row[0]))["leaseExpiresAt"] > self.clock()
        ]

    def renew_stock_attachment(self, expected, lease_expires_at):
        """Extend only the exact assigned-stock mapping observed by the caller."""
        if (not isinstance(expected, dict)
                or not isinstance(expected.get("runtimeProfile"), dict)
                or expected["runtimeProfile"].get("profile") != "assigned_stock_client"
                or not isinstance(expected.get("leaseExpiresAt"), (int, float))
                or isinstance(expected.get("leaseExpiresAt"), bool)
                or not math.isfinite(expected["leaseExpiresAt"])
                or not isinstance(lease_expires_at, (int, float))
                or isinstance(lease_expires_at, bool)
                or not math.isfinite(lease_expires_at)
                or lease_expires_at <= max(self.clock(), expected["leaseExpiresAt"])):
            return False
        renewed = dict(expected, leaseExpiresAt=lease_expires_at)
        encoded = _json(renewed)
        try:
            self._capacity(32768 + len(encoded.encode()) * 3)
            with self.db:
                cursor = self.db.execute(
                    "UPDATE attachments SET data=? WHERE runtime=? AND data=?",
                    (encoded, expected["runtimeId"], _json(expected)),
                )
                return cursor.rowcount == 1
        except sqlite3.Error:
            raise StoreError("storage_unavailable") from None

    def stock_watch_rows(self, runtime_id):
        """Return the bounded durable watch associations for one stock runtime."""
        return [json.loads(row[0]) for row in self.db.execute(
            "SELECT data FROM stock_watches WHERE runtime=? ORDER BY subject,incarnation",
            (runtime_id,),
        )]

    def remember_stock_watch(self, mapping, watch):
        """Persist one exact owner-listed watch projection, retaining any pending CAS."""
        if (not isinstance(mapping, dict) or not isinstance(watch, dict)
                or watch.get("state") != "attached" or watch.get("attachment") is None):
            raise StoreError("invalid_stock_watch")
        runtime = mapping.get("runtimeId")
        subject = watch.get("subject")
        incarnation = watch.get("incarnation")
        # These JSON identities must exclude bools and other int subclasses.
        if (not isinstance(runtime, str) or not isinstance(subject, dict)
                or type(subject.get("repositoryId")) is not int  # pylint: disable=unidiomatic-typecheck
                or type(subject.get("prNumber")) is not int  # pylint: disable=unidiomatic-typecheck
                or type(incarnation) is not int or incarnation < 1):  # pylint: disable=unidiomatic-typecheck
            raise StoreError("invalid_stock_watch")
        for row in self.db.execute(
                "SELECT DISTINCT runtime FROM stock_watches").fetchall():
            tracked_runtime = row[0]
            attachment = self.get_attachment(tracked_runtime)
            if attachment is None or attachment["leaseExpiresAt"] <= self.clock():
                self.prune_stock_watches(tracked_runtime, set())
        key = _json(subject)
        old = self.db.execute(
            "SELECT data FROM stock_watches WHERE runtime=? AND subject=? AND incarnation=?",
            (runtime, key, incarnation),
        ).fetchone()
        value = json.loads(old[0]) if old else {"watch": watch, "pending": None, "failure": None}
        value.pop("observed", None)
        if value["pending"] is None:
            value["watch"] = watch
        if len(_json(value).encode()) > 16384:
            raise StoreError("invalid_stock_watch")
        try:
            self._capacity(32768 + len(_json(value).encode()) * 3)
            with self.db:
                if old is None:
                    count = self.db.execute("SELECT COUNT(*) FROM stock_watches").fetchone()[0]
                    if count >= 32:
                        raise StoreError("capacity", "stock_watch_capacity")
                    self.db.execute(
                        "INSERT INTO stock_watches VALUES(?,?,?,?,?)",
                        (runtime, key, incarnation, _json(value), self.clock()),
                    )
                else:
                    self.db.execute(
                        "UPDATE stock_watches SET data=?,updated=? WHERE runtime=? AND subject=? AND incarnation=?",
                        (_json(value), self.clock(), runtime, key, incarnation),
                    )
        except sqlite3.Error:
            raise StoreError("storage_unavailable") from None

    def save_stock_watch_request(self, runtime, subject, incarnation, request):
        """Durably bind one exact operation to its watch before network transmission."""
        key = _json(subject)
        row = self.db.execute(
            "SELECT data FROM stock_watches WHERE runtime=? AND subject=? AND incarnation=?",
            (runtime, key, incarnation),
        ).fetchone()
        if row is None:
            raise StoreError("stock_watch_missing")
        value = json.loads(row[0])
        if value["pending"] is not None:
            if value["pending"]["request"] != request:
                raise StoreError("stock_watch_pending")
            return value["pending"]
        pending = {"request": request, "startedAt": self.clock()}
        value.update(pending=pending, failure=None)
        try:
            self._capacity(32768 + len(_json(value).encode()) * 3)
            with self.db:
                self.db.execute(
                    "UPDATE stock_watches SET data=?,updated=? WHERE runtime=? AND subject=? AND incarnation=?",
                    (_json(value), self.clock(), runtime, key, incarnation),
                )
        except sqlite3.Error:
            raise StoreError("storage_unavailable") from None
        return pending

    def prune_stock_watches(self, runtime, current_keys):
        """Drop obsolete settled rows while retaining every pending recovery request."""
        remove = []
        for row in self.db.execute(
                "SELECT subject,incarnation,data FROM stock_watches WHERE runtime=?", (runtime,)):
            data = json.loads(row[2])
            key = (row[0], row[1])
            if key in current_keys:
                continue
            pending = data["pending"]
            if pending is None:
                remove.append((runtime, row[0], row[1]))
        if remove:
            try:
                with self.db:
                    self.db.executemany(
                        "DELETE FROM stock_watches WHERE runtime=? AND subject=? AND incarnation=?",
                        remove,
                    )
            except sqlite3.Error:
                raise StoreError("storage_unavailable") from None
        return len(remove)

    def finish_stock_watch_request(self, runtime, subject, incarnation, request, *, watch=None, failure=None):
        """Record an exact receipt or bounded failure and clear only its matching request."""
        key = _json(subject)
        row = self.db.execute(
            "SELECT data FROM stock_watches WHERE runtime=? AND subject=? AND incarnation=?",
            (runtime, key, incarnation),
        ).fetchone()
        if row is None:
            return False
        value = json.loads(row[0])
        if value["pending"] is None or value["pending"]["request"] != request:
            return False
        if watch is not None:
            value["watch"] = watch
        value.pop("observed", None)
        value.update(pending=None, failure=failure,
                     receipt={"operationId": request.get("operationId"),
                              "request": request, "watch": watch} if watch is not None else None)
        try:
            self._capacity(32768 + len(_json(value).encode()) * 3)
            with self.db:
                self.db.execute(
                    "UPDATE stock_watches SET data=?,updated=? WHERE runtime=? AND subject=? AND incarnation=?",
                    (_json(value), self.clock(), runtime, key, incarnation),
                )
            return True
        except sqlite3.Error:
            raise StoreError("storage_unavailable") from None

    def fail_stock_watch_request(self, runtime, subject, incarnation, request, reason):
        """Expose a bounded refusal while preserving the exact ambiguous request."""
        key = _json(subject)
        row = self.db.execute(
            "SELECT data FROM stock_watches WHERE runtime=? AND subject=? AND incarnation=?",
            (runtime, key, incarnation),
        ).fetchone()
        if row is None:
            return False
        value = json.loads(row[0])
        if value["pending"] is None or value["pending"]["request"] != request:
            return False
        value["failure"] = reason if reason in (
            "watch_conflict", "watch_expired", "watch_changed",
            "watch_unavailable", "watch_invalid_response", "runtime_changed",
        ) else "watch_unavailable"
        try:
            self._capacity(32768 + len(_json(value).encode()) * 3)
            with self.db:
                self.db.execute(
                    "UPDATE stock_watches SET data=?,updated=? WHERE runtime=? AND subject=? AND incarnation=?",
                    (_json(value), self.clock(), runtime, key, incarnation),
                )
            return True
        except sqlite3.Error:
            raise StoreError("storage_unavailable") from None

    def mark_stock_watch_listing_failure(self, runtime, reason):
        """Expose one owner-listing failure on known associations without changing pending requests."""
        if reason not in ("watch_list_invalid_response", "watch_list_unavailable",
                          "watch_list_over_quota"):
            reason = "watch_list_unavailable"
        rows = self.db.execute(
            "SELECT subject,incarnation,data FROM stock_watches WHERE runtime=?", (runtime,)
        ).fetchall()
        try:
            with self.db:
                for subject, incarnation, encoded in rows:
                    value = json.loads(encoded)
                    value["failure"] = reason
                    self.db.execute(
                        "UPDATE stock_watches SET data=?,updated=? WHERE runtime=? AND subject=? AND incarnation=?",
                        (_json(value), self.clock(), runtime, subject, incarnation),
                    )
        except sqlite3.Error:
            raise StoreError("storage_unavailable") from None

    def _validate_attachment(self, mapping, transfer):
        if not isinstance(mapping, dict) or any(
            k not in mapping for k in (*IDENTITY, "leaseExpiresAt")
        ):
            raise StoreError("invalid_attachment")
        validate_native_route(mapping, allow_legacy=True)
        if "runtimeProfile" in mapping:
            from .protocol import ProtocolError, validate_runtime_profile

            try:
                mapping["runtimeProfile"] = validate_runtime_profile(mapping["runtimeProfile"])
            except ProtocolError as exc:
                raise StoreError("invalid_attachment") from exc
        if transfer is not None and (
            not isinstance(transfer, dict)
            or set(transfer) != {
                "sourceRuntimeId", "expectedRuntimeGeneration", "expectedAttachmentGeneration",
                "runtimeGeneration", "attachmentGeneration",
            }
            or not isinstance(transfer["sourceRuntimeId"], str)
            or not transfer["sourceRuntimeId"]
            or transfer["sourceRuntimeId"] == mapping.get("runtimeId")
            or any(not isinstance(transfer[key], int) or isinstance(transfer[key], bool)
                   or not 1 <= transfer[key] < 2**53 - 1
                   for key in ("expectedRuntimeGeneration", "expectedAttachmentGeneration"))
            or any(not isinstance(transfer[key], int) or isinstance(transfer[key], bool)
                   or not 2 <= transfer[key] <= 2**53 - 1
                   for key in ("runtimeGeneration", "attachmentGeneration"))
            or transfer["runtimeGeneration"] != transfer["expectedRuntimeGeneration"] + 1
            or transfer["attachmentGeneration"] != transfer["expectedAttachmentGeneration"] + 1
        ):
            raise StoreError("invalid_attachment")
        if any(
            not isinstance(mapping[k], str) or not mapping[k]
            for k in ("runtimeId", "principal", "agent")
        ):
            raise StoreError("invalid_attachment")
        generations = (*IDENTITY[3:], "consumerGeneration")
        if any(
            not isinstance(mapping[k], int)
            or isinstance(mapping[k], bool)
            or not 1 <= mapping[k] <= 2**53 - 1
            for k in generations
            if k in mapping
        ):
            raise StoreError("invalid_attachment")
        lease = mapping["leaseExpiresAt"]
        if (
            not isinstance(lease, (int, float))
            or isinstance(lease, bool)
            or not math.isfinite(lease)
            or lease <= 0
        ):
            raise StoreError("invalid_attachment")

    def put_attachment(self, mapping, *, transfer=None):
        if isinstance(mapping, dict) and any(key in mapping for key in MESSAGING_METADATA):
            raise StoreError("invalid_attachment")
        try:
            return self._put_attachment(mapping, transfer=transfer)
        except sqlite3.Error:
            raise StoreError("storage_unavailable") from None

    def put_stock_reassignment(self, mapping, *, expected_mapping, expected_runtime_generation,
                                expected_attachment_generation):
        """Replace a Messaging stock mapping after cloud-confirmed reassignment only."""
        from .protocol import ProtocolError, validate_runtime_profile

        old_profile = expected_mapping.get("runtimeProfile") if isinstance(expected_mapping, dict) else None
        try:
            old_profile = validate_runtime_profile(old_profile)
        except ProtocolError:
            raise StoreError("invalid_attachment") from None
        # Exact built-in int checks reject bool-as-int in persisted JSON generations.
        # pylint: disable=unidiomatic-typecheck
        if (not isinstance(mapping, dict)
                or not isinstance(expected_mapping, dict)
                or not all(key in expected_mapping for key in MESSAGING_METADATA)
                or expected_mapping.get("leaseExpiresAt") != 0
                or any(key in expected_mapping for key in ("nativeBinding", "nativeThreadId", "sessionId"))
                or any(key in mapping for key in MESSAGING_METADATA)
                or any(key in mapping for key in ("nativeBinding", "nativeThreadId", "sessionId"))
                or type(expected_mapping.get("leaseExpiresAt")) is not int
                or any(type(expected_mapping.get(key)) is not int
                       or not 1 <= expected_mapping[key] < 2**53 - 1
                       for key in ("runtimeGeneration", "attachmentGeneration"))
                or expected_mapping.get("runtimeId") != mapping.get("runtimeId")
                or any(expected_mapping.get(key) != mapping.get(key) for key in ("principal", "agent"))
                or old_profile.get("profile") != "assigned_stock_client"
                or old_profile.get("client") != "codex"
                or not isinstance(mapping.get("runtimeProfile"), dict)
                or mapping["runtimeProfile"].get("profile") != "assigned_stock_client"
                or mapping["runtimeProfile"].get("client") != "codex"
                or any(type(value) is not int or not 1 <= value < 2**53 - 1
                       for value in (expected_runtime_generation, expected_attachment_generation))
                or mapping.get("runtimeGeneration") != expected_runtime_generation + 1
                or mapping.get("attachmentGeneration") != expected_attachment_generation + 1
                or mapping.get("consumerGeneration") != mapping.get("attachmentGeneration")
                or expected_mapping.get("runtimeGeneration", expected_runtime_generation)
                    > expected_runtime_generation
                or expected_mapping.get("attachmentGeneration", expected_attachment_generation)
                    > expected_attachment_generation
                or expected_mapping.get("consumerGeneration")
                    != expected_mapping.get("attachmentGeneration")):
            raise StoreError("invalid_attachment")
        try:
            return self._put_attachment(
                mapping, allow_stock_messaging_downgrade=True,
                expected_existing=expected_mapping,
            )
        except sqlite3.Error:
            raise StoreError("storage_unavailable") from None

    def put_messaging_attachment(self, mapping, *, expected_mapping=None):
        """Persist trusted v2 metadata only; no activation, transfer, or counter reset."""
        from .messaging_admission_v2 import ATTACHMENT_FIELDS, _finite
        from . import messaging_protocol_v2 as protocol

        mapping = self._normalize_messaging_attachment(mapping, ATTACHMENT_FIELDS, protocol, _finite)
        expected_mapping = self._validate_expected_messaging_attachment(
            expected_mapping, mapping, protocol,
        )
        try:
            return self._put_attachment(
                mapping, allow_stock_messaging_upgrade=True,
                expected_existing=expected_mapping,
            )
        except sqlite3.Error:
            raise StoreError("storage_unavailable") from None

    @staticmethod
    def _normalize_messaging_attachment(mapping, attachment_fields, protocol, finite):
        # Closed DTOs require exact built-in types, not user-defined subclasses.
        required = set(attachment_fields) | {"namespace", "agentIncarnation", "leaseExpiresAt"}
        # These exact-type checks reject bool-as-int and subclasses in decoded JSON DTOs.
        # pylint: disable=unidiomatic-typecheck
        if (type(mapping) is not dict  # pylint: disable=unidiomatic-typecheck
                or set(mapping) not in (required, required | {"runtimeProfile"})):
            raise StoreError("invalid_attachment")
        try:
            mapping = json.loads(protocol._json_bytes(mapping))
        except (TypeError, ValueError, RecursionError, OverflowError):
            raise StoreError("invalid_attachment") from None
        if Store._invalid_messaging_attachment_identity(mapping, protocol, finite):
            raise StoreError("invalid_attachment")
        if "runtimeProfile" in mapping and not protocol._runtime_profile(mapping["runtimeProfile"]):
            raise StoreError("invalid_attachment")
        return mapping

    @staticmethod
    def _invalid_messaging_attachment_identity(mapping, protocol, finite):
        namespace = mapping["namespace"]
        if (not all(protocol._matches(protocol._UUID, mapping[key]) for key in ("nodeId", "runtimeId"))
                or not protocol._matches(protocol._PRINCIPAL, mapping["principal"])
                or len(mapping["principal"]) > 254
                or not protocol._matches(re.compile(r"[a-z0-9-]{1,32}"), mapping["agent"])
                or not protocol._integer(mapping["routingGeneration"])
                or not protocol._integer(mapping["agentIncarnation"], 0)
                or not finite(mapping["leaseExpiresAt"])
                or mapping["consumerGeneration"] != mapping["attachmentGeneration"]):
            return True
        # Exact built-in type rejects subclasses outside the JSON DTO domain.
        # pylint: disable=unidiomatic-typecheck
        return (type(namespace) is not str or not 1 <= protocol._code_points(namespace) <= 256
                or re.search(r"[\x00-\x1f\x7f]", namespace))

    def _validate_expected_messaging_attachment(self, expected_mapping, mapping, protocol):
        if expected_mapping is None:
            return None
        expected_fields = set(IDENTITY) | {
            "nodeId", "consumerGeneration", "leaseExpiresAt", "runtimeProfile",
        }
        # Exact built-in type rejects subclasses outside the JSON DTO domain.
        # pylint: disable=unidiomatic-typecheck
        if (type(expected_mapping) is not dict
                or set(expected_mapping) not in (
                    expected_fields, expected_fields | set(MESSAGING_METADATA),
                )):
            raise StoreError("invalid_attachment")
        try:
            expected_mapping = json.loads(protocol._json_bytes(expected_mapping))
        except (TypeError, ValueError, RecursionError, OverflowError):
            raise StoreError("invalid_attachment") from None
        profile = expected_mapping["runtimeProfile"]
        try:
            self._validate_attachment(expected_mapping, None)
        except StoreError:
            raise StoreError("invalid_attachment") from None
        identity_fields = (
            "runtimeId", "principal", "agent", "nodeId", "nodeGeneration",
            "runtimeGeneration", "attachmentGeneration", "consumerGeneration",
            "runtimeProfile",
        )
        if set(expected_mapping) == expected_fields | set(MESSAGING_METADATA):
            identity_fields += MESSAGING_METADATA
        if (not protocol._runtime_profile(profile)
                or profile.get("profile") != "assigned_stock_client"
                or any(expected_mapping.get(key) != mapping.get(key) for key in identity_fields)):
            raise StoreError("invalid_attachment")
        return expected_mapping

    def _put_attachment(self, mapping, *, transfer=None, allow_stock_messaging_upgrade=False,
                        allow_stock_messaging_downgrade=False, expected_existing=None):
        self._validate_attachment(mapping, transfer)
        if mapping["leaseExpiresAt"] <= self.clock():
            raise StoreError("invalid_attachment")
        messaging = "routingGeneration" in mapping
        generations = (*IDENTITY[3:], "consumerGeneration", *(("routingGeneration", "agentIncarnation") if messaging else ()))
        old_data, old = self._existing_attachment(
            mapping, expected_existing, allow_stock_messaging_upgrade,
            allow_stock_messaging_downgrade, messaging,
        )
        target_error = None
        try:
            self._validate_attachment_target(mapping, old, transfer, generations)
        except StoreError as exc:
            if transfer is None:
                raise
            # Cloud-confirmed revocation must survive a superseded local target.
            target_error = exc
        return self._commit_attachment(
            mapping, old, old_data, messaging, transfer, expected_existing, target_error,
        )

    def _existing_attachment(self, mapping, expected_existing, allow_stock_messaging_upgrade,
                             allow_stock_messaging_downgrade, messaging):
        row = self.db.execute(
            "SELECT data FROM attachments WHERE runtime=?", (mapping["runtimeId"],)
        ).fetchone()
        old_data = row[0] if row else None
        old = json.loads(old_data) if row else None
        if expected_existing is not None and old != expected_existing:
            raise StoreError("stale")
        if old and ("routingGeneration" in old) != messaging:
            stock_messaging_upgrade = (
                self._stock_messaging_upgrade_allowed(
                    old, mapping, allow_stock_messaging_upgrade, messaging,
                )
            )
            stock_messaging_downgrade = (
                allow_stock_messaging_downgrade and not messaging
                and "routingGeneration" in old
                and isinstance(old.get("runtimeProfile"), dict)
                and old["runtimeProfile"].get("profile") == "assigned_stock_client"
                and old["runtimeProfile"].get("client") == "codex"
                and not any(key in old for key in ("nativeBinding", "nativeThreadId", "sessionId"))
                and old.get("runtimeId") == mapping.get("runtimeId")
                and all(old.get(key) == mapping.get(key) for key in ("principal", "agent"))
                and mapping.get("runtimeGeneration", 0) > old.get("runtimeGeneration", 0)
                and mapping.get("attachmentGeneration", 0) > old.get("attachmentGeneration", 0)
                and mapping.get("consumerGeneration") == mapping.get("attachmentGeneration")
            )
            if not (stock_messaging_upgrade or stock_messaging_downgrade):
                raise StoreError("invalid_attachment")
        return old_data, old

    @staticmethod
    def _stock_messaging_upgrade_allowed(old, mapping, allow_stock_messaging_upgrade, messaging):
        return (allow_stock_messaging_upgrade and messaging and "routingGeneration" not in old
                and not any(key in old for key in ("nativeBinding", "nativeThreadId", "sessionId"))
                and old.get("runtimeProfile") == mapping.get("runtimeProfile")
                and isinstance(old.get("runtimeProfile"), dict)
                and old["runtimeProfile"].get("profile") == "assigned_stock_client"
                and old["runtimeProfile"].get("client") == "codex"
                and all(old.get(key) == mapping.get(key) for key in (*IDENTITY, "consumerGeneration")))

    def _validate_attachment_target(self, mapping, old, transfer, generations):
        if self._attachment_capacity_reached(mapping, transfer):
            raise StoreError("capacity", "session_capacity")
        if old:
            self._validate_native_attachment_transition(mapping, old)
            self._validate_attachment_generations(mapping, old, generations)

    def _attachment_capacity_reached(self, mapping, transfer):
        return sum(
            live["agent"] == mapping["agent"]
            and live["runtimeId"] != mapping["runtimeId"]
            and (transfer is None or live["runtimeId"] != transfer["sourceRuntimeId"])
            for live in self.list_attachments()
        ) >= 3

    @staticmethod
    def _validate_native_attachment_transition(mapping, old):
        if "nativeBinding" in old and "nativeBinding" not in mapping:
            profile = mapping.get("runtimeProfile")
            if (not isinstance(profile, dict)
                    or profile.get("profile") != "assigned_stock_client"
                    or mapping["attachmentGeneration"] <= old["attachmentGeneration"]):
                raise StoreError("invalid_attachment")
        if (("nativeBinding" in old or "nativeBinding" in mapping)
                and mapping["attachmentGeneration"] == old["attachmentGeneration"]
                and any(mapping.get(key) != old.get(key)
                        for key in ("sessionId", "nativeThreadId", "nativeBinding"))):
            raise StoreError("conflict", "native route changed without attachment generation")

    def _validate_attachment_generations(self, mapping, old, generations):
        if old["leaseExpiresAt"] <= self.clock() and all(
            mapping.get(k, 0) == old.get(k, 0) for k in generations
        ):
            raise StoreError("stale")
        if any(mapping.get(k, 0) < old.get(k, 0) for k in generations):
            raise StoreError("stale")
        if all(mapping.get(k, 0) == old.get(k, 0) for k in generations) and {
            k: v for k, v in mapping.items() if k != "leaseExpiresAt"
        } != {k: v for k, v in old.items() if k != "leaseExpiresAt"}:
            raise StoreError("conflict", "attachment identity changed without generation")

    def _commit_attachment(self, mapping, old, old_data, messaging, transfer,
                           expected_existing, target_error):
        data = _json(mapping)
        target_reserve = 32768 + len(data.encode()) * 3
        self._capacity(target_reserve)
        with self.db:
            if messaging:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("PRAGMA user_version=5")
            if transfer is not None:
                self._revoke_transfer_source(mapping, transfer, target_reserve=target_reserve)
            if target_error is None:
                if old and any(
                    old.get(k) != mapping.get(k)
                    for k in (*IDENTITY, "consumerGeneration", "nodeId", *MESSAGING_METADATA,
                              "runtimeProfile")
                ):
                    self._fence(mapping["runtimeId"])
                if expected_existing is None:
                    self.db.execute(
                        "INSERT OR REPLACE INTO attachments VALUES (?,?)",
                        (mapping["runtimeId"], data),
                    )
                else:
                    cursor = self.db.execute(
                        "UPDATE attachments SET data=? WHERE runtime=? AND data=?",
                        (data, mapping["runtimeId"], old_data),
                    )
                    if cursor.rowcount != 1:
                        raise StoreError("stale")
        if target_error is not None:
            raise target_error
        return mapping.copy()

    def revoke_transfer_source(self, mapping, *, transfer):
        if transfer is None or (isinstance(mapping, dict) and any(key in mapping for key in MESSAGING_METADATA)):
            raise StoreError("invalid_attachment")
        self._validate_attachment(mapping, transfer)
        try:
            with self.db:
                self._revoke_transfer_source(mapping, transfer)
        except sqlite3.Error:
            raise StoreError("storage_unavailable") from None
        return {"revoked": True, "runtimeId": transfer["sourceRuntimeId"]}

    def _revoke_transfer_source(self, mapping, transfer, *, target_reserve=0):
        source_id = transfer["sourceRuntimeId"]
        source_row = self.db.execute(
            "SELECT data FROM attachments WHERE runtime=?", (source_id,)
        ).fetchone()
        source = json.loads(source_row[0]) if source_row else {
            "runtimeId": source_id,
            "principal": mapping["principal"],
            "agent": mapping["agent"],
            "nodeGeneration": mapping["nodeGeneration"],
            "runtimeGeneration": transfer["runtimeGeneration"],
            "attachmentGeneration": transfer["attachmentGeneration"],
            "leaseExpiresAt": 0,
        }
        if source.get("runtimeId") != source_id:
            raise StoreError("corrupt_state")
        if "routingGeneration" in source:
            raise StoreError("invalid_attachment")
        if source_row:
            if (source.get("principal") != mapping["principal"]
                    or source.get("agent") != mapping["agent"]):
                raise StoreError("transfer_identity_mismatch")
            if (source.get("runtimeGeneration") == transfer["runtimeGeneration"]
                    and source.get("attachmentGeneration") == transfer["attachmentGeneration"]
                    and source.get("leaseExpiresAt") == 0):
                # A durable receipt replay must not fence newer work.
                return
            if (source.get("runtimeGeneration") != transfer["expectedRuntimeGeneration"]
                    or source.get("attachmentGeneration") != transfer["expectedAttachmentGeneration"]):
                raise StoreError("stale_transfer")
        source.update(
            runtimeGeneration=transfer["runtimeGeneration"],
            attachmentGeneration=transfer["attachmentGeneration"],
            leaseExpiresAt=0,
        )
        source_data = _json(source)
        # Like detach, revoking an existing source is allowed at admission capacity.
        if target_reserve or not source_row:
            self._capacity(target_reserve + 32768 + len(source_data.encode()) * 3)
        self._fence(source_id)
        if source_row:
            self.db.execute(
                "UPDATE attachments SET data=? WHERE runtime=?", (source_data, source_id)
            )
        else:
            self.db.execute(
                "INSERT INTO attachments VALUES (?,?)", (source_id, source_data)
            )

    def _fence(self, runtime_id):
        # Terminal observation is historical evidence, never dispatchable authority.
        self.db.execute(
            """UPDATE attempts SET fenced=1,
               state=CASE WHEN state IN ('submitting','submitted') THEN 'ambiguous' ELSE state END,
               reason=CASE WHEN state='held' AND reason='over_budget' THEN reason
                           WHEN state='stale' AND reason='claim_refused' THEN reason
                           ELSE 'attachment_detached' END,
               updated=? WHERE delivery_id IN (SELECT id FROM deliveries WHERE runtime=?)
               AND state NOT IN ('settled','observed')""",
            (self.clock(), runtime_id),
        )
        self.db.execute(
            "UPDATE deliveries SET reason='attachment_detached', updated=? WHERE runtime=? AND state IN ('claiming','admitted','settlement_pending')",
            (self.clock(), runtime_id),
        )
        self.db.execute(
            """UPDATE deliveries
               SET state=CASE WHEN state IN ('queued','held') THEN 'stale' ELSE 'ambiguous' END,
                   reason='attachment_detached', updated=?
               WHERE runtime=? AND state IN ('queued','held','submitting','submitted')""",
            (self.clock(), runtime_id),
        )

    def detach(self, runtime_id):
        with self.db:
            self._fence(runtime_id)
            mapping = self.get_attachment(runtime_id)
            if mapping:
                mapping["leaseExpiresAt"] = 0
                self.db.execute(
                    "UPDATE attachments SET data=? WHERE runtime=?",
                    (_json(mapping), runtime_id),
                )

    @staticmethod
    def _expires(envelope):
        return datetime.fromisoformat(
            envelope["expiresAt"].replace("Z", "+00:00")
        ).timestamp()

    def _matches(self, envelope):
        mapping = self.get_attachment(envelope.get("runtimeId"))
        if envelope.get("schemaVersion") == 2:
            from .messaging_admission_v2 import attachment_matches

            if (not mapping or mapping["leaseExpiresAt"] <= self.clock()
                    or not attachment_matches(mapping, envelope)):
                raise StoreError("stale", "attachment_fenced")
            return mapping
        if (
            not mapping
            or "routingGeneration" in mapping
            or mapping["leaseExpiresAt"] <= self.clock()
            or any(
                envelope.get(k) != mapping.get(k)
                for k in (*IDENTITY, "consumerGeneration")
            )
        ):
            raise StoreError("stale", "attachment_fenced")
        profile = envelope.get("runtimeProfile")
        if profile is not None or "runtimeProfile" in mapping:
            from .protocol import ProtocolError, validate_runtime_profile

            try:
                if (profile is None or "runtimeProfile" not in mapping
                        or validate_runtime_profile(profile) != mapping["runtimeProfile"]):
                    raise StoreError("stale", "attachment_fenced")
            except ProtocolError:
                raise StoreError("stale", "attachment_fenced") from None
        return mapping

    def accept(self, envelope):
        if not isinstance(envelope, dict):
            raise StoreError("invalid_envelope")
        # Protocol validation is repeated at the store trust boundary when available.
        if envelope.get("schemaVersion") == 2:
            from .messaging_protocol_v2 import parse_envelope, matches_delivery_id, _json_bytes

            envelope = parse_envelope(_json_bytes(envelope), now_ms=self.clock() * 1000)
        else:
            from .protocol import parse_envelope, matches_delivery_id

            envelope = parse_envelope(_json(envelope), now_ms=self.clock() * 1000)
        if not matches_delivery_id(envelope):
            raise StoreError("invalid_delivery_identity")
        self._matches(envelope)
        semantic = _json(
            {
                k: v
                for k, v in envelope.items()
                if k not in ("attemptId", "issuedAt", "expiresAt")
            }
        )
        dedup = envelope["deliveryId"]
        old = self.db.execute(
            "SELECT * FROM deliveries WHERE dedup=?", (dedup,)
        ).fetchone()
        if old:
            if old["semantic"] != semantic:
                raise StoreError(
                    "conflict", "event identity reused with different content"
                )
            result = self._public(old)
            result["duplicate"] = True
            return result
        self.cleanup()
        count = self._pending_delivery_count()
        if count >= self.max_rows:
            self.blocked_reason = "pending_capacity"
            raise StoreError("capacity", self.blocked_reason)
        encoded = _json(envelope)
        self._capacity(65536 + 6 * len(encoded.encode()))
        delivery_id = envelope["deliveryId"]
        now = self.clock()
        horizon = max(now, self._expires(envelope)) + RETENTION
        with self.db:
            if envelope["schemaVersion"] == 2:
                self.db.execute("BEGIN IMMEDIATE")
                self._matches(envelope)
                self.db.execute("PRAGMA user_version=5")
            self.db.execute(
                "INSERT INTO deliveries VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    delivery_id,
                    dedup,
                    semantic,
                    encoded,
                    envelope["runtimeId"],
                    envelope["agent"],
                    "held" if envelope["schemaVersion"] == 2 else "queued",
                    now,
                    now,
                    horizon,
                    None,
                    None,
                    None,
                    None,
                ),
            )
        result = self.delivery(delivery_id)
        result["duplicate"] = False
        return result

    def _attempt(self, delivery_id, attempt_id=None):
        envelope = self.delivery_envelope(delivery_id)
        if not envelope or (attempt_id is not None and envelope["attemptId"] != attempt_id):
            return None
        return self.db.execute(
            "SELECT a.*, d.ack_state FROM attempts a JOIN deliveries d ON d.id=a.delivery_id "
            "WHERE a.delivery_id=? AND a.attempt_id=?",
            (delivery_id, envelope["attemptId"]),
        ).fetchone()

    def current_attempt(self, delivery_id):
        """Detached recovery metadata, including exact started_receipt; positive evidence forbids settlement."""
        row = self._attempt(delivery_id)
        if row is None:
            return None
        result = dict(row)
        for key in ("envelope", "admission", "native_request", "evidence", "receipt", "settlement", "started_receipt", "native_ack",
                    "input_recorded_receipt", "native_observed_ack"):
            result[key] = json.loads(result[key]) if result[key] is not None else None
        return result

    @staticmethod
    def _stock_recovery_identity(envelope, admission, now_ms=None):
        """Hash exact delivery, stock conversation, and all destination generations."""
        if isinstance(envelope, dict) and envelope.get("schemaVersion") == 2:
            return Store._stock_recovery_identity_v2(envelope, admission, now_ms=now_ms)
        from .cloud import _generation, _safe_uint, _uuid
        from .protocol import ProtocolError, validate_runtime_profile

        profile = envelope.get("runtimeProfile")
        admitted = admission.get("envelope") if isinstance(admission, dict) else None
        required = ("deliveryId", "attemptId", *IDENTITY, "consumerGeneration", "runtimeProfile")
        if (not _safe_uint(envelope.get("schemaVersion")) or envelope["schemaVersion"] != 1
                or any(key not in envelope for key in required)
                or not isinstance(admitted, dict)):
            return None
        try:
            profile = validate_runtime_profile(profile)
        except ProtocolError:
            return None
        messaging_keys = ("routingGeneration", "namespace", "agentIncarnation")
        messaging_present = tuple(key in envelope for key in messaging_keys)
        if (not isinstance(envelope.get("deliveryId"), str)
                or not re.fullmatch(r"dly_[a-f0-9]{64}", envelope["deliveryId"])
                or not _uuid(envelope.get("attemptId"))
                or not _uuid(envelope.get("runtimeId"))
                or any(not isinstance(envelope.get(key), str) or not 1 <= len(envelope[key]) <= 256
                       for key in ("principal", "agent"))
                or any(not _generation(envelope.get(key)) for key in (
                    "nodeGeneration", "runtimeGeneration", "attachmentGeneration", "consumerGeneration"))
                or (any(messaging_present) and not all(messaging_present))
                or (all(messaging_present)
                    and (not _generation(envelope["routingGeneration"])
                         or not _safe_uint(envelope.get("agentIncarnation"))
                         or not isinstance(envelope.get("namespace"), str)
                         or not 1 <= len(envelope["namespace"]) <= 256
                         or re.search(r"[\x00-\x1f\x7f]", envelope["namespace"])))):
            return None
        keys = ("deliveryId", "attemptId", *IDENTITY, "consumerGeneration",
                "routingGeneration", "namespace", "agentIncarnation", "runtimeProfile")
        identity = {key: envelope[key] for key in keys if key in envelope}
        if any(envelope.get(key) != admitted.get(key) for key in identity):
            return None
        if not _uuid(admission.get("nodeId")):
            return None
        identity["nodeId"] = admission["nodeId"]
        return identity, hashlib.sha256(_json(identity).encode()).hexdigest()

    @staticmethod
    def _stock_recovery_identity_v2(envelope, admission, *, now_ms=None):
        """Validate and hash an exact historical Messaging v2 stock admission."""
        from .messaging_admission_v2 import validate_admission
        from .messaging_protocol_v2 import MessagingProtocolError
        from . import messaging_protocol_v2 as protocol

        if not isinstance(admission, dict):
            return None
        try:
            admitted = validate_admission(
                admission, envelope, now_ms=time.time() * 1000 if now_ms is None else now_ms,
                node_id=admission.get("nodeId"),
            )
        except (MessagingProtocolError, KeyError, TypeError, ValueError, OverflowError, RecursionError):
            return None
        if not protocol._runtime_profile(admitted["envelope"].get("runtimeProfile")):
            return None
        # Hash all validated envelope and immutable admission metadata, with no
        # field projection that can drift away from the source contract.
        return admitted, hashlib.sha256(_json(admitted).encode()).hexdigest()

    def list_stock_recovery(self, limit=100, delivery_id=None):
        """Return a bounded, content-free view of unresolved stock input attempts."""
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise StoreError("invalid_limit")
        if delivery_id is not None and (
                not isinstance(delivery_id, str)
                or not re.fullmatch(r"dly_[a-f0-9]{64}", delivery_id)):
            raise StoreError("invalid_delivery_id")
        params = ["ambiguous", "ambiguous", "assigned_stock_client"]
        if delivery_id is None:
            query = (
                "SELECT a.* FROM deliveries d JOIN attempts a ON a.delivery_id=d.id "
                "WHERE d.state=? AND a.state=? "
                "AND json_extract(a.envelope,'$.runtimeProfile.profile')=? "
                "ORDER BY d.updated,d.id LIMIT ?"
            )
        else:
            query = (
                "SELECT a.* FROM deliveries d JOIN attempts a ON a.delivery_id=d.id "
                "WHERE d.state=? AND a.state=? "
                "AND json_extract(a.envelope,'$.runtimeProfile.profile')=? AND d.id=? "
                "ORDER BY d.updated,d.id LIMIT ?"
            )
            params.append(delivery_id)
        params.append(limit + 1)
        rows = self.db.execute(
            query, params,
        ).fetchall()
        summaries = []
        for row in rows[:limit]:
            envelope = json.loads(row["envelope"])
            identity = self._stock_recovery_identity(
                envelope, json.loads(row["admission"] or "null"), now_ms=self.clock() * 1000,
            )
            if identity is None:
                continue
            exact, digest = identity
            stock_envelope = exact["envelope"] if "envelope" in exact else exact
            summaries.append({
                "deliveryId": stock_envelope["deliveryId"], "attemptId": stock_envelope["attemptId"],
                "runtimeId": stock_envelope["runtimeId"],
                "conversationId": stock_envelope["runtimeProfile"]["conversationId"],
                "runtimeGeneration": stock_envelope["runtimeGeneration"],
                "attachmentGeneration": stock_envelope["attachmentGeneration"],
                "expectedIdentitySha256": digest, "machineState": "unknown",
                "operatorDisposition": (json.loads(row["operator_disposition"])
                                         if row["operator_disposition"] else None),
                "cloudObligation": "unresolved",
            })
        truncated = len(rows) > limit
        result = {"deliveries": summaries, "truncated": truncated}
        while summaries and len(json.dumps(result).encode()) > 7600:
            summaries.pop()
            result["truncated"] = truncated = True
        return result

    def abandon_stock_delivery(self, delivery_id, attempt_id, expected_identity_sha256):
        """Record local abandonment without settling or changing the uncertain attempt."""
        if (not isinstance(expected_identity_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_identity_sha256)):
            raise StoreError("invalid_recovery_identity")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            delivery = self.db.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
            attempt = self._attempt(delivery_id, attempt_id)
            if delivery is None or attempt is None:
                raise StoreError("not_found")
            envelope = json.loads(delivery["envelope"])
            identity = self._stock_recovery_identity(
                envelope, json.loads(attempt["admission"] or "null"), now_ms=self.clock() * 1000,
            )
            if identity is None:
                raise StoreError("not_stock_delivery")
            _, digest = identity
            if digest != expected_identity_sha256:
                raise StoreError("stale_recovery_identity")
            if delivery["state"] != "ambiguous" or attempt["state"] != "ambiguous":
                raise StoreError("not_ambiguous")
            record = {
                "action": "abandoned", "identitySha256": digest,
                "recordedAt": self.clock(), "machineState": "unknown",
                "cloudObligation": "unresolved",
            }
            encoded = _json(record)
            if len(encoded.encode()) > 512:
                raise StoreError("recovery_record_too_large")
            if attempt["operator_disposition"] is not None:
                previous = json.loads(attempt["operator_disposition"])
                if previous.get("identitySha256") != digest or previous.get("action") != "abandoned":
                    raise StoreError("operator_disposition_conflict")
                return previous
            self._capacity(1024)
            self.db.execute(
                "UPDATE attempts SET operator_disposition=? WHERE delivery_id=? AND attempt_id=?",
                (encoded, delivery_id, attempt_id),
            )
        return record

    def _spend(self, row, size=0):
        cost = 32768 + size * 6
        credit = min(cost, row["reserved_bytes"])
        self._capacity(cost, credit=credit)
        self.db.execute(
            "UPDATE attempts SET reserved_bytes=reserved_bytes-? WHERE delivery_id=? AND attempt_id=?",
            (credit, row["delivery_id"], row["attempt_id"]),
        )

    def begin_claim(self, delivery_id):
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self.db.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
            if row is None:
                return False
            envelope = json.loads(row["envelope"])
            stock_v2 = _assigned_stock_v2(envelope)
            if (row["state"] != ("held" if stock_v2 else "queued")
                    or (envelope.get("schemaVersion") != 1 and not stock_v2)):
                return False
            try:
                self._matches(envelope)
            except StoreError:
                self.db.execute("UPDATE deliveries SET state='stale', reason='attachment_or_event_expired', updated=? WHERE id=?",
                                (self.clock(), delivery_id))
                return False
            self._capacity(CLAIM_RESERVE + 32768 + len(row["envelope"].encode()) * 6)
            self.db.execute(
                "INSERT INTO attempts (delivery_id,attempt_id,state,envelope,reserved_bytes,updated,claim_uncertain) "
                "VALUES (?,?,'claiming',?,?,?,0)",
                (delivery_id, envelope["attemptId"], row["envelope"], CLAIM_RESERVE, self.clock()),
            )
            self.db.execute("UPDATE deliveries SET state='claiming', updated=? WHERE id=?", (self.clock(), delivery_id))
        return True

    def note_claim_budget(self, delivery_id, attempt_id):
        """Retain the exact claim intent while exposing a known budget refusal."""
        return self.note_claim_refusal(delivery_id, attempt_id, "over_budget", uncertain=True)

    def note_claim_request(self, delivery_id, attempt_id):
        """Persist possible admission before sending; return prior uncertainty."""
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id, attempt_id)
            if row is None or row["state"] != "claiming":
                raise StoreError("invalid_transition")
            self.db.execute("UPDATE attempts SET claim_uncertain=1, updated=? WHERE delivery_id=? AND attempt_id=?",
                            (self.clock(), delivery_id, attempt_id))
        return bool(row["claim_uncertain"])

    def note_claim_refusal(self, delivery_id, attempt_id, reason, *, uncertain):
        """A known retryable refusal preserves any earlier possible admission."""
        if reason not in ("over_budget", *RETRYABLE_CLAIM_REFUSALS):
            raise StoreError("invalid_reason")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id, attempt_id)
            if row is None or row["state"] != "claiming":
                raise StoreError("invalid_transition")
            self.db.execute("UPDATE attempts SET reason=?, claim_uncertain=?, updated=? WHERE delivery_id=? AND attempt_id=?",
                            (reason, int(uncertain), self.clock(), delivery_id, attempt_id))
            self.db.execute("UPDATE deliveries SET reason=?, updated=? WHERE id=?",
                            (reason, self.clock(), delivery_id))
        return True

    def reject_claim(self, delivery_id, attempt_id):
        """Retain a definitive refusal for deduplication without pending capacity."""
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id, attempt_id)
            delivery = self.db.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
            if (row is None or row["state"] != "claiming" or delivery["state"] != "claiming"
                    or delivery["submission"] is not None or delivery["turn"] is not None
                    or any(row[key] is not None for key in (
                        "admission", "native_request", "evidence", "started_receipt", "input_recorded_receipt"))):
                raise StoreError("invalid_transition")
            self._spend(row)
            self.db.execute(
                "UPDATE attempts SET state='stale', reason='claim_refused', reserved_bytes=0, updated=? "
                "WHERE delivery_id=? AND attempt_id=?", (self.clock(), delivery_id, attempt_id))
            self.db.execute(
                "UPDATE deliveries SET state='stale', reason='claim_refused', updated=? WHERE id=?",
                (self.clock(), delivery_id))
        return self.delivery(delivery_id)

    def _begin_messaging_claim_history(self, delivery_id):
        """Commit one exact v2 claim intent and its history storage before any RPC."""
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            delivery = self.db.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
            if delivery is None or delivery["state"] != "held":
                raise StoreError("invalid_transition")
            envelope = json.loads(delivery["envelope"])
            if envelope.get("schemaVersion") != 2:
                raise StoreError("invalid_transition")
            if self._attempt(delivery_id) is not None:
                return None
            self._matches(envelope)
            # Reserve only the bounded claim response, not native execution capacity.
            reserve = 65536 + 6 * (8192 + len(delivery["envelope"].encode()))
            self._capacity(reserve)
            self.db.execute(
                "INSERT INTO attempts (delivery_id,attempt_id,state,envelope,reserved_bytes,updated,claim_uncertain) "
                "VALUES (?,?,'held',?,?,?,1)",
                (delivery_id, envelope["attemptId"], delivery["envelope"], reserve, self.clock()),
            )
        return self.current_attempt(delivery_id)

    def _record_messaging_claim_refusal(self, delivery_id, refusal):
        """Keep a definitive over-budget response immutable without replacing its attempt."""
        from .cloud import CloudError, validate_over_budget

        try:
            encoded = _json(validate_over_budget(refusal))
        except CloudError as error:
            raise StoreError("invalid_refusal") from error
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id)
            if (row is None or row["state"] != "held"
                    or json.loads(row["envelope"]).get("schemaVersion") != 2
                    or row["envelope"] != _json(self.delivery_envelope(delivery_id))
                    or row["admission"] is not None):
                raise StoreError("invalid_transition")
            if row["evidence"] is not None:
                if row["evidence"] != encoded or row["claim_uncertain"]:
                    raise StoreError("admission_conflict")
                return json.loads(encoded)
            if not row["claim_uncertain"]:
                raise StoreError("invalid_transition")
            # Even after detach, a definitive response resolves this existing intent only.
            self._capacity(65536 + 6 * len(encoded.encode()), credit=row["reserved_bytes"])
            self.db.execute(
                "UPDATE attempts SET evidence=?,reason='over_budget',claim_uncertain=0,reserved_bytes=0,updated=? "
                "WHERE delivery_id=? AND attempt_id=?",
                (encoded, self.clock(), delivery_id, row["attempt_id"]),
            )
        return json.loads(encoded)

    def _record_messaging_admission_history(self, delivery_id, admission, *, node_id):
        """Record authenticated cloud history without granting native start authority."""
        from .messaging_admission_v2 import validate_admission
        from .messaging_protocol_v2 import MessagingProtocolError

        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            delivery = self.db.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
            if delivery is None or delivery["state"] != "held":
                raise StoreError("invalid_transition")
            envelope = json.loads(delivery["envelope"])
            if envelope.get("schemaVersion") != 2:
                raise StoreError("invalid_transition")
            try:
                admitted = validate_admission(admission, envelope, now_ms=self.clock() * 1000,
                                              node_id=node_id)
            except MessagingProtocolError as exc:
                raise StoreError("invalid_admission") from exc
            # This dormant writer binds the exact persisted envelope, including time bounds.
            if _json(admitted["envelope"]) != delivery["envelope"]:
                raise StoreError("invalid_admission")
            self._matches(envelope)
            encoded = _json(admitted)
            row = self._attempt(delivery_id, envelope["attemptId"])
            if row is None:
                raise StoreError("invalid_transition")
            if (row["state"] != "held" or row["fenced"] or row["evidence"] is not None
                    or row["envelope"] != delivery["envelope"]
                    or row["admission"] not in (None, encoded)):
                raise StoreError("admission_conflict")
            if row["admission"] is not None:
                return json.loads(row["admission"])
            if not row["claim_uncertain"]:
                raise StoreError("invalid_transition")
            self._capacity(65536 + 6 * (len(encoded.encode()) + len(delivery["envelope"].encode())),
                           credit=row["reserved_bytes"])
            self.db.execute(
                "UPDATE attempts SET admission=?,claim_uncertain=0,reserved_bytes=0,updated=? "
                "WHERE delivery_id=? AND attempt_id=?",
                (encoded, self.clock(), delivery_id, envelope["attemptId"]),
            )
        return json.loads(encoded)

    def begin_stock_submit(self, delivery_id, attempt_id):
        """Durably fence the assigned stock CLI invocation before process launch."""
        from .protocol import ProtocolError, _timestamp

        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            delivery = self.db.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
            attempt = self._attempt(delivery_id, attempt_id)
            if (delivery is None or attempt is None or delivery["state"] != "admitted"
                    or attempt["state"] != "admitted" or attempt["admission"] is None
                    or attempt["claim_uncertain"] or attempt["fenced"]):
                raise StoreError("invalid_transition")
            envelope = json.loads(delivery["envelope"])
            if (envelope.get("schemaVersion") not in (1, 2)
                    or not isinstance(envelope.get("runtimeProfile"), dict)
                    or envelope["runtimeProfile"].get("profile") != "assigned_stock_client"):
                raise StoreError("invalid_transition")
            admission = json.loads(attempt["admission"])
            try:
                permit_issued_at = _timestamp(admission["permitIssuedAt"])
                permit_expires_at = _timestamp(admission["permitExpiresAt"])
            except (KeyError, ProtocolError, TypeError, ValueError):
                raise StoreError("invalid_transition") from None
            now_ms = self.clock() * 1000
            if not permit_issued_at <= now_ms < permit_expires_at:
                raise StoreError("invalid_transition")
            self._matches(envelope)
            self.db.execute("UPDATE attempts SET state='submitting',updated=? WHERE delivery_id=? AND attempt_id=?",
                            (self.clock(), delivery_id, attempt_id))
            self.db.execute("UPDATE deliveries SET state='submitting',updated=? WHERE id=?",
                            (self.clock(), delivery_id))
        return True

    def record_stock_command_accepted(self, delivery_id, attempt_id, acknowledgment):
        """Persist CLI acceptance and its exact cloud ACK before sending the ACK."""
        from .protocol import ProtocolError, acknowledgment_matches_delivery, parse_acknowledgment

        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            delivery = self.db.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
            attempt = self._attempt(delivery_id, attempt_id)
            if delivery is None or attempt is None:
                raise StoreError("invalid_transition")
            envelope = json.loads(delivery["envelope"])
            try:
                if envelope.get("schemaVersion") == 2:
                    from . import messaging_protocol_v2 as messaging

                    normalized = messaging.parse_acknowledgment(_json(acknowledgment), now_ms=self.clock() * 1000)
                    valid = (messaging.acknowledgment_matches_delivery(envelope, normalized)
                             and normalized.get("status") == "command_accepted"
                             and attempt["admission"] is not None
                             and normalized.get("permitId") == json.loads(attempt["admission"])["permitId"])
                else:
                    normalized = parse_acknowledgment(_json(acknowledgment), now_ms=self.clock() * 1000)
                    valid = (acknowledgment_matches_delivery(envelope, normalized)
                             and normalized.get("status") == "command_accepted")
            except (ProtocolError, TypeError, ValueError, KeyError):
                valid = False
            if not valid:
                raise StoreError("invalid_acknowledgment")
            encoded = _json(normalized)
            if delivery["state"] == "command_accepted" and attempt["native_ack"] == encoded:
                return json.loads(encoded)
            if delivery["state"] != "submitting" or attempt["state"] != "submitting":
                raise StoreError("invalid_transition")
            self._spend(attempt, len(encoded.encode()))
            self.db.execute("UPDATE attempts SET state='command_accepted',native_ack=?,reason=NULL,updated=? "
                            "WHERE delivery_id=? AND attempt_id=?",
                            (encoded, self.clock(), delivery_id, attempt_id))
            self.db.execute("UPDATE deliveries SET state='command_accepted',ack_state=NULL,reason=NULL,updated=? "
                            "WHERE id=?", (self.clock(), delivery_id))
        return json.loads(encoded)

    def complete_stock_acknowledgment(self, delivery_id, attempt_id, acknowledgment):
        """Mark the persisted stock ACK complete without implying client receipt."""
        encoded = _json(acknowledgment)
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            attempt = self._attempt(delivery_id, attempt_id)
            delivery = self.db.execute("SELECT * FROM deliveries WHERE id=?", (delivery_id,)).fetchone()
            if (attempt is None or delivery is None or delivery["state"] != "command_accepted"
                    or attempt["state"] != "command_accepted" or attempt["native_ack"] != encoded):
                return False
            if delivery["ack_state"] == "command_accepted":
                return True
            self._spend(attempt)
            self.db.execute("UPDATE deliveries SET ack_state='command_accepted',updated=? WHERE id=?",
                            (self.clock(), delivery_id))
            self.db.execute("UPDATE attempts SET reserved_bytes=0,updated=? WHERE delivery_id=? AND attempt_id=?",
                            (self.clock(), delivery_id, attempt_id))
        return True

    def record_admission(self, delivery_id, admission):
        from .cloud import CloudError, validate_admission

        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id)
            if row is None:
                raise StoreError("invalid_transition")
            expected = json.loads(row["envelope"])
            if expected.get("schemaVersion") == 2:
                if not _assigned_stock_v2(expected):
                    raise StoreError("invalid_transition")
                from .messaging_admission_v2 import validate_admission as validate_v2_admission
                from .messaging_protocol_v2 import MessagingProtocolError

                try:
                    admitted = validate_v2_admission(admission, expected, now_ms=self.clock() * 1000,
                                                     node_id=expected["nodeId"])
                except MessagingProtocolError as exc:
                    raise StoreError("invalid_admission") from exc
                if _json(admitted["envelope"]) != row["envelope"]:
                    raise StoreError("invalid_admission")
            else:
                try:
                    admitted = validate_admission(admission, expected, now_ms=self.clock() * 1000)
                except CloudError as exc:
                    raise StoreError("invalid_admission") from exc
            encoded = _json(admitted)
            if row["admission"] is not None:
                if row["admission"] != encoded:
                    raise StoreError("admission_conflict")
                return admitted
            if row["state"] != "claiming":
                raise StoreError("invalid_transition")
            self._spend(row, len(encoded.encode()))
            self.db.execute(
                "UPDATE attempts SET state='admitted', admission=?, claim_uncertain=0, reason=NULL, updated=? WHERE delivery_id=? AND attempt_id=?",
                (encoded, self.clock(), delivery_id, row["attempt_id"]),
            )
            self.db.execute("UPDATE deliveries SET state='admitted', envelope=?, reason=NULL, updated=? WHERE id=?",
                            (_json(admitted["envelope"]), self.clock(), delivery_id))
        return admitted

    def begin_native(self, delivery_id, attempt_id, request):
        from .native import NativeError, validate_request
        from .protocol import _timestamp

        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id, attempt_id)
            if row is None or row["state"] != "admitted" or row["fenced"]:
                return False
            if json.loads(row["envelope"]).get("schemaVersion") != 1:
                return False
            admission = json.loads(row["admission"])
            if not _timestamp(admission["permitIssuedAt"]) <= self.clock() * 1000 < _timestamp(admission["permitExpiresAt"]):
                return False
            try:
                self._matches(admission["envelope"])
            except StoreError:
                return False
            try:
                encoded = _json(validate_request(request, admission))
            except NativeError as exc:
                raise StoreError("invalid_native_request") from exc
            self._spend(row, len(encoded.encode()))
            self.db.execute(
                "UPDATE attempts SET state='submitting', native_request=?, updated=? WHERE delivery_id=? AND attempt_id=?",
                (encoded, self.clock(), delivery_id, attempt_id),
            )
            self.db.execute("UPDATE deliveries SET state='submitting', updated=? WHERE id=?", (self.clock(), delivery_id))
        return True

    def record_started(self, delivery_id, attempt_id, receipt):
        return self._record_native_positive(delivery_id, attempt_id, receipt)

    def record_input_recorded(self, delivery_id, attempt_id, receipt):
        """Retain the actual full Core observation; never synthesize a Started receipt."""
        return self._record_native_positive(delivery_id, attempt_id, receipt, observed=True)

    def _record_native_positive(self, delivery_id, attempt_id, receipt, *, observed=False):
        from .native import NativeError, validate_receipt

        column = "input_recorded_receipt" if observed else "started_receipt"
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id, attempt_id)
            if row is None or row["native_request"] is None or row["state"] not in ("submitting", "submitted", "ambiguous", "settlement_pending", "observed"):
                raise StoreError("invalid_transition")
            try:
                outcome = validate_receipt(json.loads(row["native_request"]), receipt, allow_input_recorded=observed)
            except NativeError as exc:
                raise StoreError("invalid_receipt") from exc
            if outcome["status"] != ("inputRecorded" if observed else "started"):
                raise StoreError("invalid_receipt")
            turn = outcome["turnId"]
            positive = self.native_receipt(delivery_id)
            if positive["turn_id"] is not None and positive["turn_id"] != turn:
                raise StoreError("receipt_conflict")
            if row[column] is not None:
                previous = json.loads(row[column])
                current = json.loads(_json(receipt))
                previous["outcome"].pop("replayed", None)
                current["outcome"].pop("replayed", None)
                if previous != current:
                    raise StoreError("receipt_conflict")
                return self.delivery(delivery_id)
            encoded = _json(receipt)
            self._spend(row, len(encoded.encode()))
            state = ("observed" if row["state"] == "observed" else
                     "ambiguous" if row["state"] in ("ambiguous", "settlement_pending") else "submitted")
            reason = (None if state == "observed" else "native_observed_ack_pending" if observed
                      else "native_started_ack_pending")
            self.db.execute(
                # column is only input_recorded_receipt or started_receipt; all values are bound.
                f"UPDATE attempts SET state=?, {column}=?, reason=?, updated=? WHERE delivery_id=? AND attempt_id=?",  # nosec B608
                (state, encoded, reason, self.clock(), delivery_id, attempt_id),
            )
            self.db.execute(
                "UPDATE deliveries SET state=?, submission=?, turn=?, reason=?, updated=? WHERE id=?",
                (state, None if positive["submission_id"] == turn else positive["submission_id"], turn,
                 reason, self.clock(), delivery_id),
            )
        return self.delivery(delivery_id)

    def _validate_native_ack(self, attempt, acknowledgment, *, observed=False):
        from .native import NativeError, validate_receipt, validate_request
        from .protocol import _timestamp

        # Exact built-in dict required at this boundary; subclasses can override mapping methods.
        if type(acknowledgment) is not dict:  # pylint: disable=unidiomatic-typecheck
            raise StoreError("invalid_native_acknowledgment")
        stored_receipt = (attempt["input_recorded_receipt"] if observed else
                          attempt["started_receipt"] or attempt["input_recorded_receipt"])
        if attempt["admission"] is None or stored_receipt is None:
            raise StoreError("invalid_native_acknowledgment")
        if observed and (attempt["native_ack"] is None or attempt["ack_state"] not in ("submitted", "observed")):
            raise StoreError("native_registration_pending")
        admission = json.loads(attempt["admission"])
        envelope = admission["envelope"]
        request = json.loads(attempt["native_request"])
        receipt = json.loads(stored_receipt)
        try:
            request = validate_request(request, admission)
            outcome = validate_receipt(request, receipt, allow_input_recorded=True)
        except NativeError:
            raise StoreError("invalid_native_acknowledgment") from None
        if outcome["status"] not in (("inputRecorded",) if observed else ("started", "inputRecorded")):
            raise StoreError("invalid_native_acknowledgment")
        correlation = {"kind": "native_turn_started", "permitId": admission["permitId"],
                       "turnId": outcome["turnId"]}
        if observed:
            correlation.update(kind="native_input_recorded", itemId=outcome["itemId"])
            submitted = json.loads(attempt["native_ack"])
            if self._validate_native_ack(attempt, submitted) != attempt["native_ack"]:
                raise StoreError("invalid_native_acknowledgment")
        expected = {
            "schemaVersion": 1,
            "eventId": envelope["eventId"],
            "deliveryId": envelope["deliveryId"],
            "attemptId": envelope["attemptId"],
            "principal": envelope["principal"],
            "agent": envelope["agent"],
            "runtimeId": envelope["runtimeId"],
            "nodeGeneration": envelope["nodeGeneration"],
            "runtimeGeneration": envelope["runtimeGeneration"],
            "attachmentGeneration": envelope["attachmentGeneration"],
            "deliveredSourceStateVersion": envelope["sourceStateVersion"],
            "status": "observed" if observed else "submitted",
            "nativeCorrelation": correlation,
        }
        if "consumerGeneration" in envelope:
            expected["consumerGeneration"] = envelope["consumerGeneration"]
        try:
            encoded_identity = _json({key: value for key, value in acknowledgment.items() if key != "acknowledgedAt"})
            if (set(acknowledgment) != set(expected) | {"acknowledgedAt"}
                    or encoded_identity != _json(expected)
                    or _timestamp(acknowledgment["acknowledgedAt"]) > self.clock() * 1000 + 30_000):
                raise StoreError("invalid_native_acknowledgment")
            return _json(acknowledgment)
        except (TypeError, ValueError, KeyError, RecursionError):
            raise StoreError("invalid_native_acknowledgment") from None

    def persist_native_ack(self, delivery_id, attempt_id, acknowledgment, *, observed=False):
        """Persist one immutable ACK per phase after retaining the actual native receipt."""
        column = "native_observed_ack" if observed else "native_ack"
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id, attempt_id)
            if row is None or row["state"] not in ("submitted", "ambiguous", "observed"):
                raise StoreError("invalid_transition")
            encoded = self._validate_native_ack(row, acknowledgment, observed=observed)
            if row[column] is not None:
                if row[column] != encoded:
                    raise StoreError("acknowledgment_conflict")
                return json.loads(row[column])
            self._spend(row, len(encoded.encode()))
            # column is only native_observed_ack or native_ack; all values are bound.
            self.db.execute(f"UPDATE attempts SET {column}=?, updated=? WHERE delivery_id=? AND attempt_id=?",  # nosec B608
                            (encoded, self.clock(), delivery_id, attempt_id))
        return json.loads(encoded)

    def complete_native_ack(self, delivery_id, attempt_id, acknowledgment, result, *, observed=False):
        """CAS the exact accepted phase; older submitted replies never demote observation."""
        column = "native_observed_ack" if observed else "native_ack"
        status = "observed" if observed else "submitted"
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id, attempt_id)
            if row is None or row["state"] not in ("submitted", "ambiguous", "observed"):
                return False
            encoded = self._validate_native_ack(row, acknowledgment, observed=observed)
            if row[column] != encoded:
                raise StoreError("acknowledgment_conflict")
            # Exact built-in dict required at this boundary; subclasses can override mapping methods.
            if type(result) is not dict:  # pylint: disable=unidiomatic-typecheck
                raise StoreError("invalid_acknowledgment_result")
            if (set(result) != {"status", "current"}
                    or result["status"] != status or not isinstance(result["current"], bool)
                    or (not observed and result["current"] is not False)):
                raise StoreError("invalid_acknowledgment_result")
            if row["ack_state"] == "observed" or (not observed and row["ack_state"] == "submitted"):
                return True
            self.db.execute("UPDATE attempts SET state=?, reason=NULL, updated=? WHERE delivery_id=? AND attempt_id=?",
                            (status, self.clock(), delivery_id, attempt_id))
            self.db.execute("UPDATE deliveries SET state=?, ack_state=?, reason=NULL, updated=? WHERE id=?",
                            (status, status, self.clock(), delivery_id))
            if observed:
                self.db.execute("UPDATE attempts SET reserved_bytes=0 WHERE delivery_id=? AND attempt_id=?",
                                (delivery_id, attempt_id))
        return True

    # Keep the stock pre-exec proof and native receipt exclusions in the same transaction.
    def begin_settlement(self, delivery_id, attempt_id, evidence, *, receipt=None, reason=None):
        from .cloud import CloudError, _no_start_evidence
        from .native import NativeError, validate_receipt

        try:
            _no_start_evidence(evidence, code="invalid_evidence")
        except CloudError as exc:
            raise StoreError("invalid_evidence") from exc
        if reason is not None and (not isinstance(reason, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", reason)):
            raise StoreError("invalid_reason")
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id, attempt_id)
            if row is None or row["admission"] is None:
                raise StoreError("invalid_transition")
            positive = self.native_receipt(delivery_id)
            if positive["submission_id"] is not None or positive["turn_id"] is not None:
                raise StoreError("receipt_conflict")
            encoded_evidence = _json(evidence)
            encoded_receipt = None
            if evidence["type"] == "local_not_submitted":
                allowed_states = ("admitted", "settlement_pending")
                if row["native_request"] is not None or receipt is not None or row["state"] not in allowed_states:
                    raise StoreError("invalid_transition")
            else:
                if row["state"] not in ("submitting", "ambiguous", "settlement_pending") or row["native_request"] is None:
                    raise StoreError("invalid_transition")
                try:
                    outcome = validate_receipt(json.loads(row["native_request"]), receipt)
                except NativeError as exc:
                    raise StoreError("invalid_receipt") from exc
                if outcome["status"] != "terminalNotStarted" or outcome["receiptId"] != evidence["receiptId"]:
                    raise StoreError("invalid_receipt")
                encoded_receipt = _json(receipt)
            if row["state"] == "settlement_pending":
                if row["evidence"] != encoded_evidence or row["receipt"] != encoded_receipt:
                    raise StoreError("receipt_conflict")
                return True
            self._spend(row, len(encoded_evidence.encode()) + len((encoded_receipt or "").encode()))
            self.db.execute(
                "UPDATE attempts SET state='settlement_pending', evidence=?, receipt=?, reason=?, updated=? WHERE delivery_id=? AND attempt_id=?",
                (encoded_evidence, encoded_receipt, reason, self.clock(), delivery_id, attempt_id),
            )
            self.db.execute("UPDATE deliveries SET state='settlement_pending', reason=?, updated=? WHERE id=?",
                            (reason, self.clock(), delivery_id))
        return True

    def complete_settlement(self, delivery_id, attempt_id, result):
        from .cloud import _generation

        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id, attempt_id)
            if row is None or row["state"] != "settlement_pending":
                return False
            stock_v2 = _assigned_stock_v2(json.loads(row["envelope"]))
            if json.loads(row["envelope"]).get("schemaVersion") != 1 and not stock_v2:
                return False
            admission, evidence = json.loads(row["admission"]), json.loads(row["evidence"])
            expected = {key: admission["envelope"][key] for key in ("deliveryId", "attemptId", "nodeGeneration")}
            expected.update(status="not_started", permitId=admission["permitId"], nodeId=admission["nodeId"], evidence=evidence)
            if not isinstance(result, dict) or not _generation(result.get("nodeGeneration")) or result != expected:
                raise StoreError("invalid_settlement")
            positive = self.native_receipt(delivery_id)
            if positive["submission_id"] is not None or positive["turn_id"] is not None:
                raise StoreError("receipt_conflict")
            envelope = dict(admission["envelope"])
            stale = bool(row["fenced"])
            try:
                self._matches(envelope)
            except StoreError:
                stale = True
            if not stale:
                envelope["attemptId"] = str(uuid.uuid4())
            encoded = _json(result)
            self._spend(row, len(encoded.encode()) + len(_json(envelope).encode()))
            next_state = "held" if stock_v2 else "queued"
            self.db.execute(
                "UPDATE attempts SET state='settled', settlement=?, reserved_bytes=0, updated=? WHERE delivery_id=? AND attempt_id=?",
                (encoded, self.clock(), delivery_id, attempt_id),
            )
            self.db.execute(
                "UPDATE deliveries SET state=?, envelope=?, reason=?, submission=NULL, turn=NULL, ack_state=NULL, updated=?, retain_until=? WHERE id=?",
                ("stale" if stale else next_state, _json(envelope), "attachment_or_event_expired" if stale else None,
                 self.clock(), max(self.clock(), self._expires(envelope)) + RETENTION, delivery_id),
            )
        return True

    def begin_submit(self, delivery_id):
        row = self.db.execute(
            "SELECT * FROM deliveries WHERE id=?", (delivery_id,)
        ).fetchone()
        if not row or row["state"] != "queued":
            return False
        envelope = json.loads(row["envelope"])
        if envelope.get("schemaVersion") != 1:
            return False
        self._capacity(32768)
        try:
            self._matches(envelope)
        except StoreError:
            self.finish(delivery_id, "stale", reason="attachment_or_event_expired")
            return False
        with self.db:
            return (
                self.db.execute(
                    "UPDATE deliveries SET state='submitting', updated=? WHERE id=? AND state='queued'",
                    (self.clock(), delivery_id),
                ).rowcount
                == 1
            )

    def finish(
        self, delivery_id, status, submission_id=None, turn_id=None, reason=None, *, attempt_id=None
    ):
        if reason is not None and (
            not isinstance(reason, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,95}", reason)
        ):
            raise StoreError("invalid_reason")
        if any(
            v is not None
            and (
                not isinstance(v, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", v)
            )
            for v in (submission_id, turn_id)
        ):
            raise StoreError("invalid_native_id")
        transitions = {
            "held": {"stale"},
            "queued": {"stale"},
            "claiming": {"ambiguous"},
            "admitted": set(),
            "settlement_pending": set(),
            "submitting": {"submitted", "observed", "ambiguous"},
            "submitted": {"observed", "ambiguous"},
            "ambiguous": {"observed"},
            "observed": set(),
            "stale": set(),
        }
        row = self.db.execute(
            "SELECT * FROM deliveries WHERE id=?", (delivery_id,)
        ).fetchone()
        if not row:
            raise StoreError("not_found")
        envelope = json.loads(row["envelope"])
        stock_v2 = _assigned_stock_v2(envelope)
        if envelope.get("schemaVersion") == 2 and not stock_v2 and (
                status not in ("held", "stale") or submission_id is not None or turn_id is not None):
            raise StoreError("invalid_transition")
        if stock_v2 and (status in ("submitted", "observed") or submission_id is not None or turn_id is not None):
            raise StoreError("invalid_transition")
        if attempt_id is not None and json.loads(row["envelope"])["attemptId"] != attempt_id:
            raise StoreError("attempt_conflict")
        if row["state"] == "settlement_pending" and (submission_id is not None or turn_id is not None):
            raise StoreError("invalid_transition")
        if status != row["state"] and status not in transitions[row["state"]]:
            raise StoreError("invalid_transition")
        if any(
            old is not None and new is not None and old != new
            for old, new in ((row["submission"], submission_id), (row["turn"], turn_id))
        ):
            raise StoreError("receipt_conflict")
        submission = submission_id if submission_id is not None else row["submission"]
        turn = turn_id if turn_id is not None else row["turn"]
        if (status in ("submitted", "observed") and not submission) or (
            status == "observed" and not turn
        ):
            raise StoreError("missing_native_receipt")
        with self.db:
            attempt = self._attempt(delivery_id)
            if attempt:
                self._spend(attempt)
            else:
                self._capacity(32768)
            self.db.execute(
                "UPDATE deliveries SET state=?, updated=?, submission=COALESCE(?,submission), turn=COALESCE(?,turn), reason=? WHERE id=?",
                (status, self.clock(), submission_id, turn_id, reason, delivery_id),
            )
            self.db.execute(
                "UPDATE attempts SET state=?, reason=?, updated=? WHERE delivery_id=? AND attempt_id=?",
                (status, reason, self.clock(), delivery_id, json.loads(row["envelope"])["attemptId"]),
            )
        return self.delivery(delivery_id)

    def _public(self, row):
        return {
            "deliveryId": row["id"],
            "status": row["state"],
            "runtimeId": row["runtime"],
            "eventId": json.loads(row["envelope"]).get("eventId"),
            "createdAt": row["created"],
            "updatedAt": row["updated"],
            "reason": row["reason"],
        }

    def delivery(self, delivery_id):
        row = self.db.execute(
            "SELECT * FROM deliveries WHERE id=?", (delivery_id,)
        ).fetchone()
        return self._public(row) if row else None

    get = delivery

    def native_receipt(self, delivery_id):
        """Internal reconciliation evidence; never include in public status."""
        row = self.db.execute(
            """SELECT submission,turn,state,ack_state,
               EXISTS(SELECT 1 FROM attempts WHERE delivery_id=deliveries.id
                      AND (started_receipt IS NOT NULL OR input_recorded_receipt IS NOT NULL)
                      AND state!='settled') AS native_started,
               EXISTS(SELECT 1 FROM attempts WHERE delivery_id=deliveries.id
                      AND (started_receipt IS NOT NULL OR input_recorded_receipt IS NOT NULL)
                      AND native_ack IS NOT NULL AND state!='settled'
                      AND deliveries.ack_state IN ('submitted','observed')) AS native_acknowledged,
               EXISTS(SELECT 1 FROM attempts WHERE delivery_id=deliveries.id
                      AND input_recorded_receipt IS NOT NULL AND state!='settled'
                      AND deliveries.ack_state IS NOT 'observed') AS native_observation_pending
               FROM deliveries WHERE id=?""",
            (delivery_id,),
        ).fetchone()
        return (
            {
                "submission_id": row["submission"],
                "turn_id": row["turn"],
                "ack_pending": bool(row["native_observation_pending"]) or (
                    bool(row["native_started"]) and not row["native_acknowledged"]) or (
                    row["state"] in ("submitted", "observed")
                    and row["ack_state"] != row["state"]
                ) or (
                    row["state"] == "command_accepted" and row["ack_state"] != "command_accepted"
                ),
            }
            if row
            else None
        )

    def mark_acknowledged(self, delivery_id, expected_state, *, attempt_id=None):
        if attempt_id is not None:
            envelope = self.delivery_envelope(delivery_id)
            if not envelope or envelope["attemptId"] != attempt_id:
                return False
        if expected_state not in ("submitted", "observed"):
            return False
        with self.db:
            attempt = self._attempt(delivery_id)
            if attempt:
                self._spend(attempt)
            else:
                self._capacity(32768)
            changed = self.db.execute(
                "UPDATE deliveries SET ack_state=? WHERE id=? AND state=?",
                (expected_state, delivery_id, expected_state),
            ).rowcount == 1
            if changed and expected_state == "observed" and attempt:
                self.db.execute("UPDATE attempts SET reserved_bytes=0 WHERE delivery_id=? AND attempt_id=?",
                                (delivery_id, attempt["attempt_id"]))
            return changed

    def delivery_envelope(self, delivery_id):
        row = self.db.execute(
            "SELECT envelope FROM deliveries WHERE id=?", (delivery_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list_pending(self):
        return [
            self._public(row)
            for row in self.db.execute(
                "SELECT * FROM deliveries WHERE state IN ('queued','held') ORDER BY created,id"
            )
            if (envelope := json.loads(row["envelope"])).get("schemaVersion") == 1
            or _assigned_stock_v2(envelope)
        ]

    def list_reconcilable(self):
        return [
            self._public(row)
            for row in self.db.execute(
                "SELECT * FROM deliveries WHERE (state IN "
                "('claiming','admitted','settlement_pending','submitted','ambiguous') "
                "OR (state='observed' AND ack_state IS NOT state) "
                "OR (state='command_accepted' AND ack_state IS NOT state)) "
                "ORDER BY created,id"
            )
            if (envelope := json.loads(row["envelope"])).get("schemaVersion") == 1
            or _assigned_stock_v2(envelope)
        ]

    def _messaging_obligations(self):
        obligations = set()
        for row in self.db.execute(
            "SELECT d.id,d.envelope,d.state,d.ack_state,a.attempt_id,a.state AS attempt_state,"
            "a.reason AS attempt_reason,a.admission "
            "FROM deliveries d JOIN attempts a ON a.delivery_id=d.id"
        ):
            envelope = json.loads(row["envelope"])
            if envelope.get("schemaVersion") != 2:
                continue
            if _assigned_stock_v2(envelope):
                if row["attempt_state"] == "settled":
                    continue
                if (row["attempt_state"] == "stale" and row["attempt_reason"] == "claim_refused"
                        and row["admission"] is None):
                    continue
                if (row["state"] == row["ack_state"] == row["attempt_state"] == "command_accepted"
                        and row["attempt_id"] == envelope["attemptId"]):
                    continue
            obligations.add(row["id"])
        return obligations

    def _pending_delivery_count(self):
        pending = {row[0] for row in self.db.execute(
            "SELECT id FROM deliveries WHERE state IN "
            "('held','queued','claiming','admitted','settlement_pending','submitting','submitted','ambiguous') "
            "OR (state='observed' AND ack_state IS NOT state) "
            "OR (state='command_accepted' AND ack_state IS NOT state)"
        )}
        return len(pending | self._messaging_obligations())

    def cleanup(self):
        with self.db:
            protected = self._messaging_obligations()
            settled = self.db.execute(
                "SELECT delivery_id,attempt_id FROM attempts WHERE state='settled' AND updated<?",
                (self.clock() - RETENTION,),
            ).fetchall()
            self.db.executemany(
                "DELETE FROM attempts WHERE delivery_id=? AND attempt_id=?",
                ((row[0], row[1]) for row in settled if row[0] not in protected),
            )
            expired = self.db.execute(
                "SELECT id FROM deliveries WHERE (state='stale' OR (state='observed' AND ack_state=state) "
                "OR (state='command_accepted' AND ack_state=state)) "
                "AND retain_until<? AND updated<?", (self.clock(), self.clock() - RETENTION),
            ).fetchall()
            removable = [(row[0],) for row in expired if row[0] not in protected]
            self.db.executemany("DELETE FROM deliveries WHERE id=?", removable)
            self.db.execute("DELETE FROM attempts WHERE delivery_id NOT IN (SELECT id FROM deliveries)")
            return len(removable)

    def status(self):
        size = self._size()
        counts = {
            row[0]: row[1]
            for row in self.db.execute(
                "SELECT state,COUNT(*) FROM deliveries GROUP BY state"
            )
        }
        pending = self._pending_delivery_count()
        try:
            self._capacity(32768)
        except StoreError as exc:
            if exc.code != "capacity":
                raise
        reason = self.blocked_reason or (
            "pending_capacity" if pending >= self.max_rows else None
        )
        watch_rows = [json.loads(row[0]) for row in self.db.execute(
            "SELECT data FROM stock_watches")]
        watch_failures = {}
        for row in watch_rows:
            if row.get("failure"):
                watch_failures[row["failure"]] = watch_failures.get(row["failure"], 0) + 1
        return {
            "counts": counts,
            "pending": pending,
            "bytes": size,
            "blockedReason": reason,
            "attachments": len(self.list_attachments()),
            "stockWatchRenewal": {
                "associations": len(watch_rows),
                "pending": sum(row["pending"] is not None for row in watch_rows),
                "failures": watch_failures,
                "capacity": len(watch_rows) >= 32,
            },
        }
