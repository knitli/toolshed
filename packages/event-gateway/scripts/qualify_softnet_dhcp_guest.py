"""Fixed DHCP behavior probe for a disposable, NIC-isolated macOS guest."""

import base64
import hashlib
import os
from pathlib import Path
import platform
import pwd
import grp
import signal
import socket
import stat
import subprocess
import tempfile
import threading
import time
import softnet_preferences as preferences

import dhcp_probe_frames as dhcp
import qualify_offline_macos_vm as canary
from softnet_preferences import Preferences, PreferencesError


SOFTNET_SHA256 = "1584af036b6d6d11319b2a3766d1be212534c525e3805bc566180aec7a1b2a0e"
MAC = bytes.fromhex("02 00 00 00 88 01")
MAC_TEXT = "02:00:00:00:88:01"
CLIENT_IDS = (b"\x00knitli-softnet-a", b"\x00knitli-softnet-b")
ENV = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "LANG": "C"}
MAX_BINARY_BYTES = 64 * 1024**2
MAX_FRAME_BYTES = 2048
MAX_FRAMES = 128
TRANSACTION_SECONDS = 15
RETRY_WINDOW_SECONDS = 1
READY_SECONDS = 8
PREFS_BUSY = "preferences_lock_failed:3002:"


def _report(binary_digest="", source_hashes=None):
    return {
        "kind": "softnet-guest-dhcp-qualification-v1", "status": "failed",
        "dhcpQualified": False, "fullNativeQualified": False, "failureCode": "not_started",
        "cleanupFailure": None,
        "checks": {"environment": False, "binary": False, "helperTargetReadback": False,
                   "exchanges": False, "lease": False, "clientIdBehavior": False,
                   "helperReaped": False, "logsComplete": False},
        "sourceSha256": source_hashes or {}, "binarySha256": binary_digest,
        "exchanges": [], "logs": {},
    }


def _source_hashes():
    paths = (Path(__file__), Path(dhcp.__file__), Path(preferences.__file__), Path(canary.__file__))
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def _environment():
    if os.geteuid() != 0 or sys_platform() != "darwin" or platform.mac_ver()[0].split(".", 1)[0] != "15" or platform.machine() != "arm64":
        raise ValueError("environment_gate")
    return True


def sys_platform():
    import sys
    return sys.platform


def _binary(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("binary_path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o555
                or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > MAX_BINARY_BYTES):
            raise ValueError("binary_profile")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BINARY_BYTES:
                raise ValueError("binary_size")
            digest.update(chunk)
        if size != info.st_size or digest.hexdigest() != SOFTNET_SHA256:
            raise ValueError("binary_digest")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _target_readback():
    deadline = time.monotonic() + READY_SECONDS
    while True:
        busy = False
        try:
            with Preferences() as prefs:
                actual = prefs.read()
                expected = prefs.encode_target()
                if prefs.equal(actual, expected):
                    return True
        except PreferencesError as error:
            if not str(error).startswith(PREFS_BUSY):
                raise ValueError("helper_target_readback") from None
            busy = True
        if time.monotonic() >= deadline:
            raise ValueError("helper_target_readback" if busy else "helper_target_mismatch")
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))


def _receive(peer, mac, xid, message_type, server_id, deadline, counters, records):
    while time.monotonic() < deadline:
        peer.settimeout(min(0.2, max(0.001, deadline - time.monotonic())))
        try:
            frame = peer.recv(MAX_FRAME_BYTES + 1)
        except socket.timeout:
            continue
        counters["received"] += 1
        if counters["received"] + counters["sent"] > MAX_FRAMES or len(frame) > MAX_FRAME_BYTES:
            raise ValueError("frame_limit")
        reply = dhcp.parse_reply(frame, mac, xid, message_type, server_id)
        if reply is not None:
            if len(records) >= 8:
                raise ValueError("retained_frame_limit")
            records.append(_frame_record(frame))
            return frame, reply
    raise ValueError("dhcp_deadline")


def _exchange(peer, client_id, counters, records, deadline):
    first_record = len(records)
    xid = int.from_bytes(os.urandom(4), "big")
    discover = dhcp.build_discover(MAC, xid, client_id)
    _send(peer, discover, counters, records)
    offer_frame, offer = _receive_retry(peer, MAC, xid, 2, None, deadline, counters, discover, records)
    request = dhcp.build_request(MAC, xid, client_id, offer["yiaddr"], offer["server_id"])
    _send(peer, request, counters, records)
    ack_frame, ack = _receive_retry(peer, MAC, xid, 5, offer["server_id"], deadline, counters, request, records)
    if ack["yiaddr"] != offer["yiaddr"]:
        raise ValueError("dhcp_behavior")
    return {"clientIdBase64": base64.b64encode(client_id).decode("ascii"), "xid": xid,
            "yiaddr": ack["yiaddr"], "serverId": ack["server_id"], "offerLeaseSeconds": offer["lease_seconds"],
            "leaseSeconds": ack["lease_seconds"], "frames": records[first_record:]}


def _send(peer, frame, counters, records, *, retain=True):
    if (len(frame) > MAX_FRAME_BYTES or counters["sent"] + counters["received"] >= MAX_FRAMES
            or (retain and len(records) >= 8)):
        raise ValueError("frame_limit")
    peer.send(frame)
    counters["sent"] += 1
    if retain:
        records.append(_frame_record(frame))


def _receive_retry(peer, mac, xid, kind, server_id, deadline, counters, retransmit, records):
    for attempt in range(3):
        try:
            return _receive(peer, mac, xid, kind, server_id,
                            min(deadline, time.monotonic() + RETRY_WINDOW_SECONDS), counters, records)
        except ValueError as error:
            if str(error) != "dhcp_deadline" or attempt == 2 or time.monotonic() >= deadline:
                raise
            _send(peer, retransmit, counters, records, retain=False)
    raise ValueError("dhcp_deadline")


def _frame_record(frame):
    return {"bytes": len(frame), "base64": base64.b64encode(frame).decode("ascii"),
            "sha256": hashlib.sha256(frame).hexdigest()}


def _drain(process, errors, destination):
    try:
        canary._drain_tart_logs(process, errors, destination, Path(destination["_dir"]))
    except BaseException:
        errors.append("log_drainer_failed")


def _stop(process):
    sent = []
    try:
        os.killpg(process.pid, signal.SIGTERM)
        sent.append(signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        result = process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            sent.append(signal.SIGKILL)
        except ProcessLookupError:
            pass
        result = process.wait(timeout=3)
    return result, tuple(sent)


def _launch(binary_path):
    account = pwd.getpwnam("admin")
    if account.pw_uid <= 0 or account.pw_gid != 20:
        raise ValueError("helper_account")
    if grp.getgrnam("staff").gr_gid != 20:
        raise ValueError("helper_group")
    peer, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        process = subprocess.Popen([str(binary_path), "--vm-fd", "0", "--vm-mac-address", MAC_TEXT,
                                    "--block=0.0.0.0/0", "--user", "admin", "--group", "staff"],
                                   stdin=child, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=ENV, close_fds=True, pass_fds=(), start_new_session=True)
    except BaseException:
        peer.close()
        child.close()
        raise
    child.close()
    return process, peer


def _collect_logs(temp, log_result, report):
    entries = log_result.get("tartRunLogs", {})
    for name, summary in entries.items():
        path = Path(temp.name) / summary["file"]
        raw = path.read_bytes()
        report["logs"][name] = {"bytes": summary["bytesRetained"], "sha256": summary["sha256"],
                                "base64": base64.b64encode(raw).decode("ascii")}
        if (len(raw) != summary["bytesObserved"] or len(raw) != summary["bytesRetained"]
                or len(raw) > canary.MAX_SHORT_OUTPUT or hashlib.sha256(raw).hexdigest() != summary["sha256"]):
            raise ValueError("logs_incomplete")
    if set(entries) != {"stdout", "stderr"} or len(report["logs"]) != 2:
        raise ValueError("logs_incomplete")


def _cleanup(process, log_thread, temp, log_result, log_errors, report):
    if process is not None:
        try:
            result, signals_sent = _stop(process)
            report["checks"]["helperReaped"] = process.returncode is not None
            if result not in (0, *(-sig for sig in signals_sent)):
                report["cleanupFailure"] = "helper_nonzero_exit"
        except BaseException:
            report["cleanupFailure"] = "helper_shutdown"
        if log_thread is not None:
            log_thread.join(timeout=2)
            if log_thread.is_alive():
                log_errors.append("log_drainer_unjoined")
        if temp is not None:
            try:
                _collect_logs(temp, log_result, report)
            except BaseException:
                log_errors.append("log_unavailable")
            try:
                temp.cleanup()
            except BaseException:
                report["cleanupFailure"] = "temp_cleanup_failed"
        else:
            log_errors.append("log_unavailable")
        if log_errors:
            report["cleanupFailure"] = "logs_incomplete"
        else:
            report["checks"]["logsComplete"] = True


def _failure_code(error, stage):
    known = {"environment_gate", "binary_profile", "binary_path", "binary_digest", "binary_size",
             "helper_account", "helper_group", "helper_launch", "helper_target_readback",
             "helper_target_mismatch", "dhcp_deadline", "frame_limit", "dhcp_behavior"}
    return str(error) if str(error) in known else stage


def _qualified(report, operation_failed):
    return not operation_failed and all(report["checks"].values()) and report["cleanupFailure"] is None


def qualify_guest_dhcp(binary_path):
    """Configure fixed DHCP policy via Softnet and qualify two peer exchanges."""
    report = _report(source_hashes=_source_hashes())
    process = None
    peer = None
    log_thread = None
    log_errors = []
    log_result = {"_dir": ""}
    temp = None
    failure = "environment_gate"
    operation_failed = False
    try:
        _environment()
        report["checks"]["environment"] = True
        failure = "binary_profile"
        report["binarySha256"] = _binary(binary_path)
        report["checks"]["binary"] = True
        failure = "helper_launch"
        process, peer = _launch(binary_path)
        temp = tempfile.TemporaryDirectory(prefix="softnet-dhcp-logs-")
        log_result["_dir"] = temp.name
        log_thread = threading.Thread(target=_drain, args=(process, log_errors, log_result), daemon=True)
        log_thread.start()
        failure = "helper_target_readback"
        _target_readback()
        report["checks"]["helperTargetReadback"] = True
        failure = "dhcp_exchange"
        counters = {"sent": 0, "received": 0}
        frames = []
        deadline = time.monotonic() + TRANSACTION_SECONDS
        for client_id in CLIENT_IDS:
            report["exchanges"].append(_exchange(peer, client_id, counters, frames, deadline))
        report["checks"]["exchanges"] = True
        report["checks"]["lease"] = all(item["leaseSeconds"] == 600 and item["offerLeaseSeconds"] == 600
                                          for item in report["exchanges"])
        report["checks"]["clientIdBehavior"] = (report["exchanges"][0]["yiaddr"] == report["exchanges"][1]["yiaddr"]
                                                 and [item["clientIdBase64"] for item in report["exchanges"]]
                                                 == [base64.b64encode(item).decode("ascii") for item in CLIENT_IDS])
        if not report["checks"]["lease"] or not report["checks"]["clientIdBehavior"]:
            raise ValueError("dhcp_behavior")
        failure = "helper_shutdown"
    except BaseException as error:
        operation_failed = True
        failure = _failure_code(error, failure)
    finally:
        if peer is not None:
            peer.close()
        _cleanup(process, log_thread, temp, log_result, log_errors, report)
    report["failureCode"] = failure
    if _qualified(report, operation_failed):
        report["status"] = "passed"
        report["dhcpQualified"] = True
        report["failureCode"] = None
    return report
