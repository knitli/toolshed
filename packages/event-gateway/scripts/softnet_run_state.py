"""Root-only admission state for supervised Softnet recovery runs."""

from contextlib import AbstractContextManager
import fcntl
import hashlib
import os
from pathlib import Path
import plistlib
import re
import stat
import time
import uuid

import qualify_offline_macos_vm as canary
import softnet_recovery as recovery

STATE_KIND = "softnet-run-state"
STATE_VERSION = 1
IDENTITY_KEYS = {"vmName", "macAddress", "tartBinarySha256", "softnetBinarySha256",
                 "admissionSha256"}
HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MAC_ADDRESS = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")
RUN_ID = re.compile(r"[0-9a-f]{32}\Z")
ROOT_ENTRIES = {"controller.lock"}
RUN_ENTRIES = {"identity.plist", "complete.plist", "reserved", "snapshot.plist", "restored",
               "launch.plist", "stop.plist", "helper-logs", "vm-logs", "disposition.plist"}
LOG_FILES = {"tart-stdout.bin", "tart-stderr.bin"}
DISPOSITION_FILES = ("identity.plist", "reserved", "snapshot.plist", "restored",
                     "launch.plist", "stop.plist", "helper-logs/tart-stdout.bin",
                     "helper-logs/tart-stderr.bin", "vm-logs/tart-stdout.bin",
                     "vm-logs/tart-stderr.bin")
DISPOSITION_KIND = "softnet-failed-restored-disposition"
MAX_LOG_BYTES = canary.MAX_SHORT_OUTPUT


def _require(condition, message):
    if not condition:
        raise recovery.RecoveryError(message)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _identity_record(run_id, identity):
    _require(isinstance(identity, dict) and set(identity) == IDENTITY_KEYS, "invalid_identity")
    _require(isinstance(identity["vmName"], str) and 0 < len(identity["vmName"]) <= 128
             and "\x00" not in identity["vmName"], "invalid_identity")
    _require(isinstance(identity["macAddress"], str)
             and MAC_ADDRESS.fullmatch(identity["macAddress"]), "invalid_identity")
    _require(identity["tartBinarySha256"] == canary.TART_BINARY_SHA256, "invalid_identity")
    _require(all(isinstance(identity[key], str) and HEX_SHA256.fullmatch(identity[key])
                 for key in ("softnetBinarySha256", "admissionSha256")), "invalid_identity")
    return {"kind": STATE_KIND, "version": STATE_VERSION, "runId": run_id,
            "identity": identity}


def _plist(data, reason):
    try:
        return plistlib.loads(data)
    except (ValueError, TypeError, OverflowError) as error:
        raise recovery.RecoveryError(reason) from error


def _stop_evidence_shape(evidence):
    return (isinstance(evidence, dict)
            and set(evidence) == {"vmReaped", "helperReaped", "vmStopped"}
            and all(type(evidence[key]) is bool for key in evidence))


def _valid_stop_evidence(evidence):
    return _stop_evidence_shape(evidence) and all(evidence.values())


def _failed_restored_files(root, name, *, receipt_present=False):
    """Validate the narrow failed-restored state and return hashes of retained evidence."""
    path = Path(root) / name
    fd = recovery._directory(path)
    try:
        entries = set(os.listdir(fd))
        required = {"identity.plist", "reserved", "snapshot.plist", "restored", "launch.plist",
                    "stop.plist", "helper-logs", "vm-logs"}
        _require(not ("complete.plist" in entries and "disposition.plist" in entries),
                 "conflicting_disposition")
        _require("complete.plist" not in entries
                 and (receipt_present or "disposition.plist" not in entries)
                 and required <= entries, "ineligible_disposition")
        _require(_check_run_directory(root, name) is False, "ineligible_disposition")
        identity_bytes = recovery._read(fd, "identity.plist")
        identity = _plist(identity_bytes, "invalid_identity")["identity"]
        _check_launch(fd, identity)
        stop_bytes, stop = _check_stop(fd)
        _require(stop == {"helperReaped": True, "vmReaped": False, "vmStopped": True},
                 "ineligible_disposition")
        _require(recovery._read(fd, "reserved") == b""
                 and recovery._read(fd, "restored") == b"restored\n", "invalid_incomplete_run")
        snapshot = _plist(recovery._read(fd, "snapshot.plist"), "invalid_snapshot")
        _require(isinstance(snapshot, dict)
                 and set(snapshot) == {"version", "present", "before", "target"}
                 and type(snapshot["version"]) is int and snapshot["version"] == 1
                 and type(snapshot["present"]) is bool
                 and type(snapshot["before"]) is bytes and type(snapshot["target"]) is bytes
                 and (snapshot["present"] or snapshot["before"] == b""), "invalid_snapshot")
        for blob in (snapshot["before"] if snapshot["present"] else None, snapshot["target"]):
            if blob is not None:
                _require(len(blob) <= recovery.MAX_BLOB and blob.startswith(b"bplist00"),
                         "invalid_snapshot")
        hashes = {}
        for relative in DISPOSITION_FILES:
            parts = relative.split("/")
            if len(parts) == 1:
                data = recovery._read(fd, relative)
            else:
                log_fd = recovery._directory(path / parts[0])
                try:
                    with os.fdopen(recovery._file(log_fd, parts[1], os.O_RDONLY), "rb") as stream:
                        info = os.fstat(stream.fileno())
                        _require(info.st_size <= MAX_LOG_BYTES, "oversized_run_log")
                        data = stream.read(MAX_LOG_BYTES + 1)
                        _require(len(data) <= MAX_LOG_BYTES, "oversized_run_log")
                finally:
                    os.close(log_fd)
            hashes[relative] = _digest(data)
        for log_name in ("helper-logs", "vm-logs"):
            _check_log_directory(root, name, log_name, complete=True)
        return hashes
    finally:
        os.close(fd)


def _observation(value):
    _require(isinstance(value, dict) and set(value) == {
        "observedAtUnixNs", "vmStopped", "processesQuiet", "preferencesOriginal"},
        "invalid_disposition_observation")
    _require(type(value["observedAtUnixNs"]) is int and value["observedAtUnixNs"] > 0
             and value["vmStopped"] is True and value["processesQuiet"] is True
             and value["preferencesOriginal"] is True, "invalid_disposition_observation")


def _check_disposition(root, name):
    run = Path(root) / name
    fd = recovery._directory(run)
    try:
        record = _plist(recovery._read(fd, "disposition.plist"), "invalid_disposition")
        _require(isinstance(record, dict) and set(record) == {
            "kind", "version", "runId", "approvalReference", "observation", "fileSha256"}
            and record["kind"] == DISPOSITION_KIND and type(record["version"]) is int
            and record["version"] == 1 and record["runId"] == name
            and isinstance(record["approvalReference"], str)
            and 0 < len(record["approvalReference"].strip()) <= 256
            and "\x00" not in record["approvalReference"]
            and isinstance(record["fileSha256"], dict)
            and set(record["fileSha256"]) == set(DISPOSITION_FILES)
            and all(isinstance(digest, str) and HEX_SHA256.fullmatch(digest)
                    for digest in record["fileSha256"].values()), "invalid_disposition")
        _observation(record["observation"])
        _require(record["fileSha256"] == _failed_restored_files(root, name, receipt_present=True),
                 "invalid_disposition")
    finally:
        os.close(fd)


def _check_launch(fd, identity):
    launch = _plist(recovery._read(fd, "launch.plist"), "invalid_launch")
    _require(isinstance(launch, dict) and set(launch) == {"vmName", "macAddress"}
             and launch == {key: identity[key] for key in ("vmName", "macAddress")},
             "invalid_launch")


def _check_stop(fd):
    stop_bytes = recovery._read(fd, "stop.plist")
    stop = _plist(stop_bytes, "invalid_stop")
    _require(_stop_evidence_shape(stop), "invalid_stop")
    return stop_bytes, stop


def _check_log_directory(root, run_name, name, *, complete):
    fd = recovery._directory(Path(root) / run_name / name)
    try:
        files = set(os.listdir(fd))
        _require(files <= LOG_FILES and (not complete or files == LOG_FILES), "invalid_run_logs")
        for filename in files:
            handle = recovery._file(fd, filename, os.O_RDONLY)
            try:
                _require(os.fstat(handle).st_size <= MAX_LOG_BYTES, "oversized_run_log")
            finally:
                os.close(handle)
    finally:
        os.close(fd)


def _check_run_directory(root, name):
    path = Path(root) / name
    fd = recovery._directory(path)
    try:
        entries = set(os.listdir(fd))
        _require(entries <= RUN_ENTRIES and "identity.plist" in entries, "invalid_run_entries")
        identity_bytes = recovery._read(fd, "identity.plist")
        identity_record = _plist(identity_bytes, "invalid_identity")
        _require(isinstance(identity_record, dict)
                 and set(identity_record) == {"kind", "version", "runId", "identity"}
                 and identity_record["kind"] == STATE_KIND
                 and type(identity_record["version"]) is int
                 and identity_record["version"] == STATE_VERSION
                 and identity_record["runId"] == name, "invalid_identity")
        expected = _identity_record(name, identity_record["identity"])
        _require(identity_record == expected, "invalid_identity")
        if "launch.plist" in entries:
            _check_launch(fd, identity_record["identity"])
        stop_bytes = stop = None
        if "stop.plist" in entries:
            stop_bytes, stop = _check_stop(fd)
        complete_present = "complete.plist" in entries
        _require(not (complete_present and "disposition.plist" in entries),
                 "conflicting_disposition")
        for log_name in ("helper-logs", "vm-logs"):
            if log_name in entries:
                _check_log_directory(root, name, log_name, complete=complete_present)
        if not complete_present:
            _require(not ("restored" in entries and "snapshot.plist" not in entries),
                     "invalid_incomplete_run")
            return False
        _require({"snapshot.plist", "restored", "reserved", "launch.plist", "stop.plist",
                  "helper-logs", "vm-logs"} <= entries, "invalid_completion")
        _require(recovery._read(fd, "reserved") == b"", "invalid_completion")
        _require(_valid_stop_evidence(stop), "invalid_completion")
        snapshot = recovery._read(fd, "snapshot.plist")
        restored = recovery._read(fd, "restored")
        _require(restored == b"restored\n", "invalid_completion")
        complete = _plist(recovery._read(fd, "complete.plist"), "invalid_completion")
        _require(isinstance(complete, dict)
                 and set(complete) == {"version", "identitySha256", "snapshotSha256",
                                       "restoredSha256", "stopSha256", "stopEvidence"}
                 and type(complete["version"]) is int and complete["version"] == 1
                 and complete["identitySha256"] == _digest(identity_bytes)
                 and complete["snapshotSha256"] == _digest(snapshot)
                 and complete["restoredSha256"] == _digest(restored)
                 and complete["stopSha256"] == _digest(stop_bytes)
                 and complete["stopEvidence"] == stop
                 and _valid_stop_evidence(complete["stopEvidence"]), "invalid_completion")
        return True
    finally:
        os.close(fd)


class State(AbstractContextManager):
    """Hold one non-waiting root lock across admission and the supervised run."""

    def __init__(self, root):
        """Bind this controller state to its root-owned directory."""
        self.root = Path(root)
        self._root_fd = None
        self._lock_fd = None
        self._active = None

    def __enter__(self):
        """Lock the state and reject unresolved retained runs."""
        self._acquire_lock()
        try:
            self._scan()
            return self
        except BaseException:
            self._close()
            raise

    def _acquire_lock(self):
        _require(self._root_fd is None and self._lock_fd is None, "state_already_entered")
        _require(os.geteuid() == recovery.OWNER_UID, "root_required")
        self._root_fd = recovery._directory(self.root)
        try:
            try:
                self._lock_fd = recovery._file(
                    self._root_fd, "controller.lock", os.O_RDWR | os.O_CREAT | os.O_EXCL)
                os.fsync(self._lock_fd)
                os.fsync(self._root_fd)
            except FileExistsError:
                self._lock_fd = recovery._file(self._root_fd, "controller.lock", os.O_RDWR)
            _require(os.fstat(self._lock_fd).st_size == 0, "invalid_controller_lock")
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise recovery.RecoveryError("controller_busy") from error
        except BaseException:
            self._close()
            raise

    def __exit__(self, *_):
        """Release the controller lock and root directory descriptor."""
        self._close()
        return False

    def _close(self):
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None

    def _scan(self, *, allowed_unresolved=None):
        entries = set(os.listdir(self._root_fd))
        _require(entries <= ROOT_ENTRIES | {name for name in entries if RUN_ID.fullmatch(name)},
                 "invalid_state_entries")
        unresolved = []
        for name in sorted(entries - ROOT_ENTRIES):
            info = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
            _require(stat.S_ISDIR(info.st_mode) and info.st_uid == recovery.OWNER_UID
                     and stat.S_IMODE(info.st_mode) == 0o700, "invalid_run_directory")
            if "disposition.plist" in os.listdir(self.root / name):
                _check_disposition(self.root, name)
            elif not _check_run_directory(self.root, name):
                unresolved.append(name)
        _require(set(unresolved) <= ({allowed_unresolved} if allowed_unresolved else set()),
                 "unresolved_run")

    def begin(self, identity):
        _require(self._root_fd is not None and self._active is None, "state_not_ready")
        run_id = uuid.uuid4().hex
        _identity_record(run_id, identity)
        os.mkdir(run_id, 0o700, dir_fd=self._root_fd)
        os.fsync(self._root_fd)
        run_fd = recovery._directory(self.root / run_id)
        try:
            identity_bytes = plistlib.dumps(
                _identity_record(run_id, identity), fmt=plistlib.FMT_BINARY, sort_keys=True)
            recovery._publish(run_fd, "identity.plist", identity_bytes)
        finally:
            os.close(run_fd)
        self._active = (run_id, self.root / run_id, identity_bytes)
        return self._active[1], run_id

    def complete(self, run, stop_evidence):
        _require(self._root_fd is not None and self._active is not None, "state_not_ready")
        run_id, run_path, identity_bytes = self._active
        _require(Path(run) == run_path and run_path.name == run_id, "invalid_active_run")
        _require(_valid_stop_evidence(stop_evidence), "invalid_stop_evidence")
        run_fd = recovery._directory(run_path)
        try:
            entries = set(os.listdir(run_fd))
            required = {"identity.plist", "reserved", "snapshot.plist", "restored", "launch.plist",
                        "stop.plist", "helper-logs", "vm-logs"}
            _require(entries <= RUN_ENTRIES and required <= entries, "invalid_run_entries")
            _require("disposition.plist" not in entries, "conflicting_disposition")
            _require(recovery._read(run_fd, "identity.plist") == identity_bytes,
                     "invalid_identity")
            _check_launch(run_fd, plistlib.loads(identity_bytes)["identity"])
            stop_bytes, recorded_stop = _check_stop(run_fd)
            _require(recorded_stop == stop_evidence, "stop_evidence_mismatch")
            _require(recovery._read(run_fd, "reserved") == b"", "invalid_completion")
            snapshot = recovery._read(run_fd, "snapshot.plist")
            restored = recovery._read(run_fd, "restored")
            _require(restored == b"restored\n", "invalid_completion")
            _check_log_directory(run_path.parent, run_id, "helper-logs", complete=True)
            _check_log_directory(run_path.parent, run_id, "vm-logs", complete=True)
            record = {"version": 1, "identitySha256": _digest(identity_bytes),
                      "snapshotSha256": _digest(snapshot), "restoredSha256": _digest(restored),
                      "stopSha256": _digest(stop_bytes),
                      "stopEvidence": stop_evidence}
            recovery._publish(run_fd, "complete.plist",
                              plistlib.dumps(record, fmt=plistlib.FMT_BINARY, sort_keys=True))
        finally:
            os.close(run_fd)
        self._active = None


def dispose_failed_restored(root, run_id, approval_reference, *, observe):
    """Record a root operator's disposition using trusted root-installed observation code."""
    _require(isinstance(run_id, str) and RUN_ID.fullmatch(run_id), "invalid_run_id")
    _require(isinstance(approval_reference, str)
             and 0 < len(approval_reference.strip()) <= 256
             and "\x00" not in approval_reference, "invalid_approval_reference")
    _require(callable(observe), "invalid_disposition_observer")
    state = State(root)
    state._acquire_lock()
    try:
        state._scan(allowed_unresolved=run_id)
        run_path = state.root / run_id
        before = _failed_restored_files(state.root, run_id)
        run_fd = recovery._directory(run_path)
        try:
            identity = _plist(recovery._read(run_fd, "identity.plist"), "invalid_identity")["identity"]
        finally:
            os.close(run_fd)
        observation = observe(run_path, identity)
        _observation(observation)
        state._scan(allowed_unresolved=run_id)
        after = _failed_restored_files(state.root, run_id)
        _require(before == after, "disposition_source_changed")
        _require(0 <= time.time_ns() - observation["observedAtUnixNs"] <= 30_000_000_000,
                 "stale_disposition_observation")
        record = {"kind": DISPOSITION_KIND, "version": 1, "runId": run_id,
                  "approvalReference": approval_reference, "observation": observation,
                  "fileSha256": after}
        run_fd = recovery._directory(run_path)
        try:
            recovery._publish(run_fd, "disposition.plist",
                              plistlib.dumps(record, fmt=plistlib.FMT_BINARY, sort_keys=True))
        finally:
            os.close(run_fd)
        state._scan()
    finally:
        state._close()

