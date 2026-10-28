"""Package and validate the fixed host-to-guest Softnet DHCP behavior probe."""

import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

import dhcp_probe_frames as dhcp
import qualify_offline_macos_vm as canary
import scpreferences_guest_probe as shared

REPORT_KIND = "softnet-guest-dhcp-qualification-v1"
BINARY_SHA256 = "1584af036b6d6d11319b2a3766d1be212534c525e3805bc566180aec7a1b2a0e"
MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_SOURCE_BYTES = 256 * 1024
MAX_BUNDLE_ARG = 128 * 1024
MAX_OUTPUT_BYTES = 256 * 1024
MAX_LOG_BYTES = 64 * 1024
MAX_FRAME_BYTES = 2048
MAX_FRAMES = 8
TIMEOUT = 60
CHECKS = {"environment", "binary", "helperTargetReadback", "exchanges", "lease",
          "clientIdBehavior", "helperReaped", "logsComplete"}
SOURCE_FILES = {
    "qualify_softnet_dhcp_guest.py": "qualify_softnet_dhcp_guest.py",
    "dhcp_probe_frames.py": "dhcp_probe_frames.py",
    "softnet_preferences.py": "softnet_preferences.py",
    "qualify_offline_macos_vm.py": "qualify_offline_macos_vm.py",
}
SOURCE_DIR = Path(__file__).resolve().parent
SOURCE_PATHS = {name: SOURCE_DIR / filename for name, filename in SOURCE_FILES.items()}

_BINARY_SETUP = '''import hashlib, os, stat, sys
expected_binary_digest = EXPECTED_BINARY_SHA256
helper_path = os.path.join(root, "softnet-dhcp-helper")
fd = os.open(helper_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
digest = hashlib.sha256()
count = 0
try:
    with os.fdopen(fd, "wb") as stream:
        while True:
            block = sys.stdin.buffer.read(min(65536, 67108865 - count))
            if not block:
                break
            count += len(block)
            if count > 67108864:
                raise ValueError("helper_too_large")
            digest.update(block)
            stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())
    if count == 0 or digest.hexdigest() != expected_binary_digest:
        raise ValueError("helper_digest_mismatch")
    os.chmod(helper_path, 0o555, follow_symlinks=False)
    info = os.stat(helper_path, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o555):
        raise ValueError("unsafe_guest_helper")
except BaseException:
    try: os.close(fd)
    except OSError: pass
    raise SystemExit("invalid_guest_helper") from None'''
LOADER = shared._source_loader(
    set(SOURCE_FILES.values()), "qualify_softnet_dhcp_guest", "qualify_guest_dhcp",
    "softnet-dhcp-modules-", guest_setup=_BINARY_SETUP.replace(
        "EXPECTED_BINARY_SHA256", repr(BINARY_SHA256)), call_args="helper_path")


def _read_binary(path):
    path = Path(path).absolute()
    try:
        for parent in reversed(path.parents):
            info = parent.lstat()
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                    or (info.st_uid != 0 and info.st_uid != os.getuid())
                    or (stat.S_IMODE(info.st_mode) & 0o022 and not info.st_mode & stat.S_ISVTX)):
                raise canary.CanaryError("softnet_dhcp_binary_unsafe")
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_size <= 0 or info.st_size > MAX_BINARY_BYTES):
            raise canary.CanaryError("softnet_dhcp_binary_unsafe")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.getuid()
                    or stat.S_IMODE(opened.st_mode) & 0o077 or opened.st_size != info.st_size
                    or opened.st_size > MAX_BINARY_BYTES):
                raise canary.CanaryError("softnet_dhcp_binary_unsafe")
            canary._check_tart_acl(path, fd=fd)
            digest = hashlib.sha256()
            count = 0
            while True:
                block = os.read(fd, min(65536, MAX_BINARY_BYTES + 1 - count))
                if not block:
                    break
                digest.update(block)
                count += len(block)
                if count > MAX_BINARY_BYTES:
                    raise canary.CanaryError("softnet_dhcp_binary_oversized")
            after = os.fstat(fd)
            if (count != opened.st_size or after.st_size != opened.st_size
                    or after.st_ino != opened.st_ino or after.st_dev != opened.st_dev
                    or after.st_mtime_ns != opened.st_mtime_ns or after.st_ctime_ns != opened.st_ctime_ns):
                raise canary.CanaryError("softnet_dhcp_binary_changed_during_read")
            if digest.hexdigest() != BINARY_SHA256:
                raise canary.CanaryError("softnet_dhcp_binary_digest_mismatch")
            os.lseek(fd, 0, os.SEEK_SET)
            return fd, {"sha256": digest.hexdigest(), "bytes": count}
        except BaseException:
            os.close(fd)
            raise
    except canary.CanaryError:
        raise
    except OSError:
        raise canary.CanaryError("softnet_dhcp_binary_unavailable") from None


def _rewind_verified_binary(binary_fd):
    try:
        before = os.fstat(binary_fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) & 0o077 or before.st_size <= 0
                or before.st_size > MAX_BINARY_BYTES):
            raise canary.CanaryError("softnet_dhcp_binary_unsafe")
        os.lseek(binary_fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        count = 0
        while True:
            block = os.read(binary_fd, min(65536, MAX_BINARY_BYTES + 1 - count))
            if not block:
                break
            digest.update(block)
            count += len(block)
            if count > MAX_BINARY_BYTES:
                raise canary.CanaryError("softnet_dhcp_binary_oversized")
        after = os.fstat(binary_fd)
        if (count != before.st_size or after.st_size != before.st_size
                or after.st_ino != before.st_ino or after.st_dev != before.st_dev
                or after.st_mtime_ns != before.st_mtime_ns or after.st_ctime_ns != before.st_ctime_ns):
            raise canary.CanaryError("softnet_dhcp_binary_changed_before_transfer")
        if digest.hexdigest() != BINARY_SHA256:
            raise canary.CanaryError("softnet_dhcp_binary_digest_mismatch")
        os.lseek(binary_fd, 0, os.SEEK_SET)
    except canary.CanaryError:
        raise
    except OSError:
        raise canary.CanaryError("softnet_dhcp_binary_unavailable") from None


def build_bundle():
    return shared._build_source_bundle(
        SOURCE_FILES, SOURCE_PATHS, error_prefix="softnet_dhcp",
        max_source_bytes=MAX_SOURCE_BYTES, max_bundle_arg=MAX_BUNDLE_ARG)


def prepare(binary_path):
    if not isinstance(binary_path, (str, os.PathLike)) or not os.fspath(binary_path):
        raise canary.CanaryError("invalid_softnet_dhcp_binary_path")
    fd, binary = _read_binary(binary_path)
    try:
        bundle = build_bundle()
    except BaseException:
        os.close(fd)
        raise
    return bundle, fd, binary


def _decode_blob(value, expected_bytes, maximum, *, allow_empty=False):
    if (not isinstance(value, dict) or set(value) != {"bytes", "base64", "sha256"}
            or type(value["bytes"]) is not int or not (0 if allow_empty else 1) <= value["bytes"] <= maximum
            or not isinstance(value["base64"], str)
            or not isinstance(value["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])):
        return None
    try:
        raw = base64.b64decode(value["base64"], validate=True)
    except (ValueError, TypeError):
        return None
    if len(raw) != value["bytes"] or (expected_bytes is not None and len(raw) != expected_bytes):
        return None
    if hashlib.sha256(raw).hexdigest() != value["sha256"]:
        return None
    return raw


def _valid_unicast_ipv4(value):
    address = ipaddress.IPv4Address(value)
    return not (address.is_unspecified or address.is_multicast or address.is_loopback
                or address == ipaddress.IPv4Address("255.255.255.255"))


def _validate_exchange(exchange, expected_client_id):
    if (not isinstance(exchange, dict)
            or set(exchange) != {"clientIdBase64", "xid", "yiaddr", "serverId", "offerLeaseSeconds",
                                 "leaseSeconds", "frames"}
            or type(exchange["xid"]) is not int or not 0 <= exchange["xid"] <= 0xFFFFFFFF
            or type(exchange["offerLeaseSeconds"]) is not int or exchange["offerLeaseSeconds"] != 600
            or type(exchange["leaseSeconds"]) is not int or exchange["leaseSeconds"] != 600
            or not isinstance(exchange["clientIdBase64"], str)
            or not isinstance(exchange["yiaddr"], str) or not isinstance(exchange["serverId"], str)
            or not isinstance(exchange["frames"], list) or len(exchange["frames"]) != 4):
        raise canary.CanaryError("softnet_dhcp_report_unqualified")
    try:
        client_id = base64.b64decode(exchange["clientIdBase64"], validate=True)
        yiaddr = str(ipaddress.IPv4Address(exchange["yiaddr"]))
        server_id = str(ipaddress.IPv4Address(exchange["serverId"]))
    except (ValueError, TypeError):
        raise canary.CanaryError("softnet_dhcp_report_unqualified") from None
    if (client_id != expected_client_id or base64.b64encode(client_id).decode("ascii") != exchange["clientIdBase64"]
            or not _valid_unicast_ipv4(yiaddr) or not _valid_unicast_ipv4(server_id)):
        raise canary.CanaryError("softnet_dhcp_report_unqualified")
    frames = [_decode_blob(frame, None, MAX_FRAME_BYTES) for frame in exchange["frames"]]
    if any(frame is None for frame in frames):
        raise canary.CanaryError("softnet_dhcp_report_unqualified")
    mac = bytes.fromhex("02 00 00 00 88 01")
    xid = exchange["xid"]
    try:
        offer = dhcp.parse_reply(frames[1], mac, xid, 2)
        if offer is None:
            raise ValueError("missing_offer")
        expected_discover = dhcp.build_discover(mac, xid, client_id)
        expected_request = dhcp.build_request(mac, xid, client_id, offer["yiaddr"], offer["server_id"])
        ack = dhcp.parse_reply(frames[3], mac, xid, 5, offer["server_id"])
    except ValueError:
        raise canary.CanaryError("softnet_dhcp_report_unqualified") from None
    if (frames[0] != expected_discover or frames[2] != expected_request or ack is None
            or exchange["offerLeaseSeconds"] != offer["lease_seconds"]
            or exchange["leaseSeconds"] != ack["lease_seconds"]
            or offer["lease_seconds"] != 600 or ack["lease_seconds"] != 600
            or offer["yiaddr"] != yiaddr or ack["yiaddr"] != yiaddr
            or offer["server_id"] != server_id or ack["server_id"] != server_id):
        raise canary.CanaryError("softnet_dhcp_report_unqualified")
    return yiaddr


def _validated_report(stdout, stderr, expected_hashes):
    if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES or stderr:
        raise canary.CanaryError("softnet_dhcp_output_invalid")
    try:
        report = json.loads(stdout)
    except (ValueError, UnicodeError, RecursionError):
        raise canary.CanaryError("softnet_dhcp_report_invalid") from None
    keys = {"kind", "status", "dhcpQualified", "fullNativeQualified", "failureCode", "checks",
            "sourceSha256", "binarySha256", "exchanges", "logs", "cleanupFailure"}
    if (not isinstance(report, dict) or set(report) != keys or report["kind"] != REPORT_KIND
            or report["status"] != "passed" or report["dhcpQualified"] is not True
            or report["fullNativeQualified"] is not False or report["failureCode"] is not None
            or report["cleanupFailure"] is not None or report["sourceSha256"] != expected_hashes
            or report["binarySha256"] != BINARY_SHA256
            or not isinstance(report["checks"], dict) or set(report["checks"]) != CHECKS
            or any(value is not True for value in report["checks"].values())):
        raise canary.CanaryError("softnet_dhcp_report_unqualified")
    logs = report["logs"]
    if not isinstance(logs, dict) or set(logs) != {"stdout", "stderr"}:
        raise canary.CanaryError("softnet_dhcp_report_unqualified")
    for item in logs.values():
        if _decode_blob(item, None, MAX_LOG_BYTES, allow_empty=True) is None:
            raise canary.CanaryError("softnet_dhcp_report_unqualified")
    exchanges = report["exchanges"]
    client_ids = (b"\x00knitli-softnet-a", b"\x00knitli-softnet-b")
    if not isinstance(exchanges, list) or len(exchanges) != len(client_ids):
        raise canary.CanaryError("softnet_dhcp_report_unqualified")
    yiaddrs = [_validate_exchange(exchange, client_id)
               for exchange, client_id in zip(exchanges, client_ids)]
    if exchanges[0]["xid"] == exchanges[1]["xid"] or yiaddrs[0] != yiaddrs[1]:
        raise canary.CanaryError("softnet_dhcp_report_unqualified")
    return report


def metadata(bundle, binary):
    return {"sourceSha256": bundle["sourceSha256"], "bundleSha256": bundle["bundleSha256"],
            "binarySha256": binary["sha256"], "binaryBytes": binary["bytes"],
            "rawLogs": {"stdout": "softnet-dhcp-stdout.bin", "stderr": "softnet-dhcp-stderr.bin",
                        "maxBytesPerStream": MAX_OUTPUT_BYTES}}


def command_template(tart_path, vm_name):
    return [str(tart_path), "exec", "-i", vm_name, "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I",
            "-c", LOADER, "<fixed-source-bundle-b64>"]


def qualify(tart_path, vm_name, env, evidence, bundle, binary_fd, *, run_bounded):
    _rewind_verified_binary(binary_fd)
    argv = [str(tart_path), "exec", "-i", vm_name, "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I",
            "-c", LOADER, bundle["argument"]]
    stdout_path = Path(evidence) / "softnet-dhcp-stdout.bin"
    stderr_path = Path(evidence) / "softnet-dhcp-stderr.bin"
    stdout, stderr = run_bounded(argv, timeout=TIMEOUT, env=env, output_limit=MAX_OUTPUT_BYTES,
                                 input_fd=binary_fd, capture_paths=(stdout_path, stderr_path))
    return {"report": _validated_report(stdout, stderr, bundle["sourceSha256"])}


def close(binary_fd):
    os.close(binary_fd)
