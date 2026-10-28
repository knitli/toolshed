"""Fixed DHCP behavior probe for a disposable, NIC-isolated macOS guest."""

import base64
import errno
import hashlib
import os
import plistlib
from pathlib import Path
import platform
import pwd
import grp
import signal
import shlex
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
DIAGNOSTIC_MAX_BYTES = 64 * 1024
DIAGNOSTIC_CONFIGS = (("etc", "/private/etc/bootpd.plist"),
                      ("systemConfiguration", "/Library/Preferences/SystemConfiguration/bootpd.plist"))
DIAGNOSTIC_LEASES = "/private/var/db/dhcpd_leases"


def _report(binary_digest="", source_hashes=None):
    return {
        "kind": "softnet-guest-dhcp-qualification-v1", "status": "failed",
        "dhcpQualified": False, "fullNativeQualified": False, "failureCode": "not_started",
        "cleanupFailure": None,
        "checks": {"environment": False, "binary": False, "helperTargetReadback": False,
                   "exchanges": False, "lease": False, "clientIdBehavior": False,
                   "helperReaped": False, "logsComplete": False},
        "sourceSha256": source_hashes or {}, "binarySha256": binary_digest,
        "exchanges": [], "logs": {}, "diagnostics": [],
    }


def _diagnostic_file(path):
    """Read one fixed guest file without following links or retaining its contents."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        return {"status": "missing" if error.errno in (errno.ENOENT, errno.ENOTDIR) else "unreadable"}
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            return {"status": "not_regular"}
        if before.st_size > DIAGNOSTIC_MAX_BYTES:
            return {"status": "oversize"}
        raw = bytearray()
        while len(raw) <= DIAGNOSTIC_MAX_BYTES:
            chunk = os.read(fd, min(4096, DIAGNOSTIC_MAX_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        if (len(raw) > DIAGNOSTIC_MAX_BYTES or len(raw) != before.st_size
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            return {"status": "changed" if len(raw) <= DIAGNOSTIC_MAX_BYTES else "oversize"}
        return {"status": "ok", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "raw": bytes(raw)}
    except OSError:
        return {"status": "unreadable"}
    finally:
        os.close(fd)


def _diagnostic_selected(value, key):
    if key not in value:
        return {"status": "absent"}
    item = value[key]
    if type(item) is bool:
        return {"status": "bool", "value": item}
    if type(item) is int and -(1 << 63) <= item <= (1 << 64) - 1:
        return {"status": "int", "value": item}
    return {"status": "unsupported"}


def _diagnostic_config(path):
    result = _diagnostic_file(path)
    raw = result.pop("raw", None)
    if result["status"] != "ok":
        return result
    try:
        value = plistlib.loads(raw)
        if type(value) is not dict:
            raise ValueError("plist root")
    except Exception:
        result["status"] = "malformed"
        return result
    result["selected"] = {key: _diagnostic_selected(value, key)
                          for key in ("dhcp_ignore_client_identifier", "DHCPLeaseTimeSecs")}
    return result


def _diagnostic_bootpd():
    try:
        stdout, _stderr = canary._run_bounded(["/bin/ps", "-A", "-o", "pid=,comm="], timeout=0.75,
                                               env=ENV, output_limit=32 * 1024)
    except Exception as error:
        code = str(error)
        status = {"tart_command_timeout": "command_timeout", "tart_command_output_limit": "output_limit",
                  "tart_command_failed": "command_error"}.get(code, "command_error")
        return {"status": status, "pids": []}
    try:
        lines = stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return {"status": "invalid_output", "pids": []}
    pids = []
    seen = set()
    for line in lines:
        fields = line.split(None, 1)
        if (len(fields) != 2 or not fields[0].isdigit()
                or not 0 < int(fields[0]) <= (1 << 31) - 1 or not fields[1].strip()):
            return {"status": "invalid_output", "pids": []}
        pid = int(fields[0])
        if os.path.basename(fields[1].strip()) == "bootpd":
            if pid in seen or len(pids) >= 4:
                return {"status": "invalid_output", "pids": []}
            seen.add(pid)
            pids.append(pid)
    return {"status": "running" if pids else "none",
            "pids": [{"pid": pid, **_diagnostic_process(pid)} for pid in pids]}


def _diagnostic_config_argument(argv):
    overrides = []
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument == "-f":
            if index + 1 >= len(argv):
                return "unclassified"
            overrides.append(argv[index + 1])
            index += 2
        elif argument.startswith("-f/"):
            overrides.append(argument[2:])
            index += 1
        else:
            index += 1
    if not overrides:
        return "none_observed"
    if len(overrides) != 1:
        return "unclassified"
    return {"/etc/bootpd.plist": "etc", "/private/etc/bootpd.plist": "etc",
            "/Library/Preferences/SystemConfiguration/bootpd.plist": "systemConfiguration"}.get(
                overrides[0], "other")


def _diagnostic_process(pid):
    try:
        stdout, _stderr = canary._run_bounded(["/bin/ps", "-ww", "-p", str(pid), "-o", "args="],
                                               timeout=0.75, env=ENV, output_limit=2048)
        argv = shlex.split(stdout.decode("utf-8"))
        if not argv or os.path.basename(argv[0]) != "bootpd":
            return {"configArgument": "unclassified", "configStatus": "process_changed"}
        return {"configArgument": _diagnostic_config_argument(argv)}
    except Exception as error:
        code = str(error)
        status = {"tart_command_timeout": "command_timeout", "tart_command_output_limit": "output_limit",
                  "tart_command_failed": "command_failed"}.get(code, "command_error")
        return {"configArgument": "unclassified", "configStatus": status}


def _diagnostic_snapshot(phase):
    """Return a bounded, allowlisted observation of candidate DHCP state."""
    configs = {name: _diagnostic_config(path) for name, path in DIAGNOSTIC_CONFIGS}
    leases = _diagnostic_file(DIAGNOSTIC_LEASES)
    leases.pop("raw", None)
    return {"phase": phase, "configs": configs, "leases": leases, "bootpd": _diagnostic_bootpd()}


def _capture_diagnostics(report, phase):
    if len(report["diagnostics"]) >= 3:
        return
    try:
        snapshot = _diagnostic_snapshot(phase)
    except Exception:
        snapshot = {"phase": phase, "status": "collector_failed",
                    "configs": {name: {"status": "collector_failed"} for name, _path in DIAGNOSTIC_CONFIGS},
                    "leases": {"status": "collector_failed"},
                    "bootpd": {"status": "collector_failed", "pids": []}}
    report["diagnostics"].append(snapshot)


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
        try:
            reply = dhcp.parse_reply(frame, mac, xid, message_type, server_id)
        except ValueError as error:
            if message_type != 5 or str(error) != "unexpected DHCP message type":
                raise
            if dhcp.parse_reply(frame, mac, xid, 2, server_id) is not None:
                continue
            raise
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
    entries = log_result.get("tartRunLogs")
    if (type(entries) is not dict or set(entries) != {"stdout", "stderr", "maxBytesPerStream"}
            or type(entries["maxBytesPerStream"]) is not int
            or entries["maxBytesPerStream"] != canary.MAX_SHORT_OUTPUT):
        raise ValueError("logs_incomplete")
    for name in ("stdout", "stderr"):
        summary = entries[name]
        if (type(summary) is not dict or set(summary) != {"bytesObserved", "bytesRetained", "sha256", "file"}
                or any(type(summary[key]) is not int or summary[key] < 0
                       for key in ("bytesObserved", "bytesRetained"))
                or summary["bytesObserved"] != summary["bytesRetained"]
                or summary["bytesRetained"] > canary.MAX_SHORT_OUTPUT
                or summary["file"] != "tart-" + name + ".bin"
                or not isinstance(summary["sha256"], str) or len(summary["sha256"]) != 64
                or any(char not in "0123456789abcdef" for char in summary["sha256"])):
            raise ValueError("logs_incomplete")
        raw = (Path(temp.name) / summary["file"]).read_bytes()
        if len(raw) != summary["bytesRetained"] or hashlib.sha256(raw).hexdigest() != summary["sha256"]:
            raise ValueError("logs_incomplete")
        report["logs"][name] = {"bytes": summary["bytesRetained"], "sha256": summary["sha256"],
                                "base64": base64.b64encode(raw).decode("ascii")}


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
        _capture_diagnostics(report, "before_helper")
        failure = "helper_launch"
        process, peer = _launch(binary_path)
        temp = tempfile.TemporaryDirectory(prefix="softnet-dhcp-logs-")
        log_result["_dir"] = temp.name
        log_thread = threading.Thread(target=_drain, args=(process, log_errors, log_result), daemon=True)
        log_thread.start()
        failure = "helper_target_readback"
        _target_readback()
        report["checks"]["helperTargetReadback"] = True
        _capture_diagnostics(report, "helper_ready")
        failure = "dhcp_exchange"
        counters = {"sent": 0, "received": 0}
        frames = []
        deadline = time.monotonic() + TRANSACTION_SECONDS
        try:
            for client_id in CLIENT_IDS:
                report["exchanges"].append(_exchange(peer, client_id, counters, frames, deadline))
        finally:
            _capture_diagnostics(report, "after_exchange")
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
