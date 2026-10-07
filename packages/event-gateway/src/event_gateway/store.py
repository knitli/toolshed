"""Private, single-writer durable delivery ledger."""

import fcntl
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


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


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
            # Bound database + one full WAL + shared-memory/index overhead.
            pages = max(1, (max_bytes - 65536) // (3 * 4096))
            self.db.execute(f"PRAGMA max_page_count={pages}")
            version = self.db.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2):
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
                self.db.execute("""CREATE TABLE IF NOT EXISTS attempts (
                    delivery_id TEXT NOT NULL, attempt_id TEXT NOT NULL,
                    state TEXT NOT NULL, envelope TEXT NOT NULL, admission TEXT,
                    native_request TEXT, evidence TEXT, receipt TEXT, settlement TEXT, started_receipt TEXT,
                    reason TEXT, fenced INTEGER NOT NULL DEFAULT 0,
                    reserved_bytes INTEGER NOT NULL, updated REAL NOT NULL,
                    PRIMARY KEY(delivery_id,attempt_id))""")
                if "started_receipt" not in {row[1] for row in self.db.execute("PRAGMA table_info(attempts)")}:
                    self.db.execute("ALTER TABLE attempts ADD COLUMN started_receipt TEXT")
                self.db.execute("PRAGMA user_version=2")
                self.db.execute(
                    "UPDATE attempts SET state='ambiguous', reason='restart_during_submit', updated=? WHERE state='submitting'",
                    (self.clock(),),
                )
                self.db.execute(
                    "UPDATE deliveries SET state='ambiguous', reason='restart_during_submit', updated=? WHERE state='submitting'",
                    (self.clock(),),
                )
            reclaimed = self.cleanup()
            if reclaimed and self._size() > self.max_bytes:
                # DELETE frees SQLite pages but does not shrink the database file.
                self.db.execute("VACUUM")
                self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self.db.execute(f"PRAGMA max_page_count={pages}")
            self._capacity()
        except BaseException:
            self.close()
            raise

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

    def list_attachments(self):
        return [
            value
            for row in self.db.execute("SELECT data FROM attachments ORDER BY runtime")
            if (value := json.loads(row[0]))["leaseExpiresAt"] > self.clock()
        ]

    def put_attachment(self, mapping):
        if not isinstance(mapping, dict) or any(
            k not in mapping for k in (*IDENTITY, "leaseExpiresAt")
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
            or lease <= self.clock()
        ):
            raise StoreError("invalid_attachment")
        row = self.db.execute(
            "SELECT data FROM attachments WHERE runtime=?", (mapping["runtimeId"],)
        ).fetchone()
        old = json.loads(row[0]) if row else None
        if (
            sum(
                live["agent"] == mapping["agent"]
                and live["runtimeId"] != mapping["runtimeId"]
                for live in self.list_attachments()
            )
            >= 3
        ):
            raise StoreError("capacity", "session_capacity")
        if old:
            if old["leaseExpiresAt"] <= self.clock() and all(
                mapping.get(k, 0) == old.get(k, 0) for k in generations
            ):
                raise StoreError("stale")
            if any(mapping.get(k, 0) < old.get(k, 0) for k in generations):
                raise StoreError("stale")
            if all(mapping.get(k, 0) == old.get(k, 0) for k in generations) and {
                k: v for k, v in mapping.items() if k != "leaseExpiresAt"
            } != {k: v for k, v in old.items() if k != "leaseExpiresAt"}:
                raise StoreError(
                    "conflict", "attachment identity changed without generation"
                )
        data = _json(mapping)
        self._capacity(32768 + len(data.encode()) * 3)
        with self.db:
            if old and any(
                old.get(k) != mapping.get(k) for k in (*IDENTITY, "consumerGeneration")
            ):
                self._fence(mapping["runtimeId"])
            self.db.execute(
                "INSERT OR REPLACE INTO attachments VALUES (?,?)",
                (mapping["runtimeId"], data),
            )
        return mapping.copy()

    def _fence(self, runtime_id):
        self.db.execute(
            """UPDATE attempts SET fenced=1,
               state=CASE WHEN state IN ('submitting','submitted') THEN 'ambiguous' ELSE state END,
               reason='attachment_detached', updated=?
               WHERE delivery_id IN (SELECT id FROM deliveries WHERE runtime=?) AND state!='settled'""",
            (self.clock(), runtime_id),
        )
        self.db.execute(
            "UPDATE deliveries SET reason='attachment_detached', updated=? WHERE runtime=? AND state IN ('claiming','admitted','settlement_pending')",
            (self.clock(), runtime_id),
        )
        self.db.execute(
            """UPDATE deliveries
               SET state=CASE WHEN state='queued' THEN 'stale' ELSE 'ambiguous' END,
                   reason='attachment_detached', updated=?
               WHERE runtime=? AND state IN ('queued','submitting','submitted')""",
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
        if (
            not mapping
            or mapping["leaseExpiresAt"] <= self.clock()
            or any(
                envelope.get(k) != mapping.get(k)
                for k in (*IDENTITY, "consumerGeneration")
            )
        ):
            raise StoreError("stale", "attachment_fenced")
        return mapping

    def accept(self, envelope):
        if not isinstance(envelope, dict):
            raise StoreError("invalid_envelope")
        # Protocol validation is repeated at the store trust boundary when available.
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
        count = self.db.execute("""SELECT COUNT(*) FROM deliveries
                 WHERE state IN ('queued','claiming','admitted','settlement_pending','submitting','submitted','ambiguous')
                    OR (state='observed' AND ack_state IS NOT state)""").fetchone()[0]
        if count >= self.max_rows:
            self.blocked_reason = "pending_capacity"
            raise StoreError("capacity", self.blocked_reason)
        encoded = _json(envelope)
        self._capacity(65536 + 6 * len(encoded.encode()))
        delivery_id = envelope["deliveryId"]
        now = self.clock()
        horizon = max(now, self._expires(envelope)) + RETENTION
        with self.db:
            self.db.execute(
                "INSERT INTO deliveries VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    delivery_id,
                    dedup,
                    semantic,
                    encoded,
                    envelope["runtimeId"],
                    envelope["agent"],
                    "queued",
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
            "SELECT * FROM attempts WHERE delivery_id=? AND attempt_id=?",
            (delivery_id, envelope["attemptId"]),
        ).fetchone()

    def current_attempt(self, delivery_id):
        """Detached recovery metadata, including exact started_receipt; positive evidence forbids settlement."""
        row = self._attempt(delivery_id)
        if row is None:
            return None
        result = dict(row)
        for key in ("envelope", "admission", "native_request", "evidence", "receipt", "settlement", "started_receipt"):
            result[key] = json.loads(result[key]) if result[key] is not None else None
        return result

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
            if row is None or row["state"] != "queued":
                return False
            envelope = json.loads(row["envelope"])
            try:
                self._matches(envelope)
            except StoreError:
                self.db.execute("UPDATE deliveries SET state='stale', reason='attachment_or_event_expired', updated=? WHERE id=?",
                                (self.clock(), delivery_id))
                return False
            self._capacity(CLAIM_RESERVE + 32768 + len(row["envelope"].encode()) * 6)
            self.db.execute(
                "INSERT INTO attempts (delivery_id,attempt_id,state,envelope,reserved_bytes,updated) VALUES (?,?,'claiming',?,?,?)",
                (delivery_id, envelope["attemptId"], row["envelope"], CLAIM_RESERVE, self.clock()),
            )
            self.db.execute("UPDATE deliveries SET state='claiming', updated=? WHERE id=?", (self.clock(), delivery_id))
        return True

    def note_claim_budget(self, delivery_id, attempt_id):
        """Retain the exact claim intent while exposing a known budget refusal."""
        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id, attempt_id)
            if row is None or row["state"] != "claiming":
                return False
            self.db.execute("UPDATE attempts SET reason='over_budget', updated=? WHERE delivery_id=? AND attempt_id=?",
                            (self.clock(), delivery_id, attempt_id))
            self.db.execute("UPDATE deliveries SET reason='over_budget', updated=? WHERE id=?",
                            (self.clock(), delivery_id))
        return True

    def record_admission(self, delivery_id, admission):
        from .cloud import CloudError, validate_admission

        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id)
            if row is None:
                raise StoreError("invalid_transition")
            try:
                admitted = validate_admission(admission, json.loads(row["envelope"]), now_ms=self.clock() * 1000)
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
                "UPDATE attempts SET state='admitted', admission=?, reason=NULL, updated=? WHERE delivery_id=? AND attempt_id=?",
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
        from .native import NativeError, validate_receipt

        with self.db:
            self.db.execute("BEGIN IMMEDIATE")
            row = self._attempt(delivery_id, attempt_id)
            if row is None or row["native_request"] is None or row["state"] not in ("submitting", "submitted", "ambiguous", "settlement_pending"):
                raise StoreError("invalid_transition")
            try:
                outcome = validate_receipt(json.loads(row["native_request"]), receipt)
            except NativeError as exc:
                raise StoreError("invalid_receipt") from exc
            if outcome["status"] != "started":
                raise StoreError("invalid_receipt")
            turn = outcome["turnId"]
            positive = self.native_receipt(delivery_id)
            if any(value is not None and value != turn for value in (positive["submission_id"], positive["turn_id"])):
                raise StoreError("receipt_conflict")
            encoded = _json(receipt)
            self._spend(row, len(encoded.encode()))
            state = "ambiguous" if row["state"] in ("ambiguous", "settlement_pending") else "submitted"
            self.db.execute(
                "UPDATE attempts SET state=?, started_receipt=?, reason='native_started_ack_unqualified', updated=? WHERE delivery_id=? AND attempt_id=?",
                (state, encoded, self.clock(), delivery_id, attempt_id),
            )
            self.db.execute(
                "UPDATE deliveries SET state=?, submission=?, turn=?, reason='native_started_ack_unqualified', updated=? WHERE id=?",
                (state, turn, turn, self.clock(), delivery_id),
            )
        return self.delivery(delivery_id)

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
                if row["native_request"] is not None or receipt is not None or row["state"] not in ("admitted", "settlement_pending"):
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
            self.db.execute(
                "UPDATE attempts SET state='settled', settlement=?, reserved_bytes=0, updated=? WHERE delivery_id=? AND attempt_id=?",
                (encoded, self.clock(), delivery_id, attempt_id),
            )
            self.db.execute(
                "UPDATE deliveries SET state=?, envelope=?, reason=?, submission=NULL, turn=NULL, ack_state=NULL, updated=?, retain_until=? WHERE id=?",
                ("stale" if stale else "queued", _json(envelope), "attachment_or_event_expired" if stale else None,
                 self.clock(), max(self.clock(), self._expires(envelope)) + RETENTION, delivery_id),
            )
        return True

    def begin_submit(self, delivery_id):
        row = self.db.execute(
            "SELECT * FROM deliveries WHERE id=?", (delivery_id,)
        ).fetchone()
        if not row or row["state"] != "queued":
            return False
        self._capacity(32768)
        envelope = json.loads(row["envelope"])
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
                      AND started_receipt IS NOT NULL AND state!='settled') AS native_started
               FROM deliveries WHERE id=?""",
            (delivery_id,),
        ).fetchone()
        return (
            {
                "submission_id": row["submission"],
                "turn_id": row["turn"],
                "ack_pending": bool(row["native_started"]) or (
                    row["state"] in ("submitted", "observed")
                    and row["ack_state"] != row["state"]
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
                "SELECT * FROM deliveries WHERE state='queued' ORDER BY created,id"
            )
        ]

    def list_reconcilable(self):
        return [
            self._public(row)
            for row in self.db.execute(
                "SELECT * FROM deliveries WHERE state IN "
                "('claiming','admitted','settlement_pending','submitted','ambiguous') "
                "OR (state='observed' AND ack_state IS NOT state) ORDER BY created,id"
            )
        ]

    def cleanup(self):
        with self.db:
            self.db.execute(
                "DELETE FROM attempts WHERE state='settled' AND updated<?",
                (self.clock() - RETENTION,),
            )
            removed = self.db.execute(
                "DELETE FROM deliveries WHERE (state='stale' OR (state='observed' AND ack_state=state)) AND retain_until<? AND updated<?",
                (self.clock(), self.clock() - RETENTION),
            ).rowcount
            self.db.execute("DELETE FROM attempts WHERE delivery_id NOT IN (SELECT id FROM deliveries)")
            return removed

    def status(self):
        size = self._size()
        counts = {
            row[0]: row[1]
            for row in self.db.execute(
                "SELECT state,COUNT(*) FROM deliveries GROUP BY state"
            )
        }
        pending = self.db.execute("""SELECT COUNT(*) FROM deliveries
                 WHERE state IN ('queued','claiming','admitted','settlement_pending','submitting','submitted','ambiguous')
                    OR (state='observed' AND ack_state IS NOT state)""").fetchone()[0]
        try:
            self._capacity(32768)
        except StoreError as exc:
            if exc.code != "capacity":
                raise
        reason = self.blocked_reason or (
            "pending_capacity" if pending >= self.max_rows else None
        )
        return {
            "counts": counts,
            "pending": pending,
            "bytes": size,
            "blockedReason": reason,
            "attachments": len(self.list_attachments()),
        }
