#!/usr/bin/env python3
"""Run the fixed offline NIC-drop canary in one prepared local Tart VM.

This is a boundary canary only. It never installs Tart, pulls an image, starts
the Rust workspace, or accepts a caller-supplied guest command.
"""

import argparse
import ctypes
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid


TART_VERSION = "2.41.1"
TART_PACKAGE_SHA256 = "e680a734febccfce7d4e910c1f7f13fc3b00f19a181c945e2d746de3214c32c2"
TART_BINARY_SHA256 = "6d3a455456979c138387d0660af8e956a054018f7516bd0e8bcd175382973823"
TART_SOURCE_COMMIT = "543453404cd1b15c1338b6b70e162d000c8ba5e2"
OCI_BASE_DIGEST = "ghcr.io/cirruslabs/macos-sequoia-base@sha256:eee659985b01e4df2a6c0754bd8d25e54969933c43fdcd4edef8bea337b3d354"
MAX_RECEIPT_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 1024 * 1024
MAX_DISK_BYTES = 1024**4
MAX_SHORT_OUTPUT = 64 * 1024
MAX_GUEST_OUTPUT = 16 * 1024
MAX_FRAME = 2048
MAX_FRAMES = 256
CANARY_TIMEOUT = 90
VM_READY_TIMEOUT = 60
VM_READY_PROBE_TIMEOUT = 3
VM_READY_RETRY_INTERVAL = 0.25
CLONE_LOG_HEADROOM = 512 * 1024**2
BASE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z")
_TART_ACL_API = None
_ACL_TYPE_EXTENDED = 0x100
_ACL_FIRST_ENTRY = 0
_ACL_NEXT_ENTRY = -1
_ACL_EXTENDED_ALLOW = 1
_ACL_EXTENDED_DENY = 2
# Darwin sys/acl.h: write, append, delete, and metadata/ACL/owner changes.
_ACL_MUTATING_PERMISSIONS = 4 | 16 | 32 | 64 | 256 | 1024 | 4096 | 8192


class CanaryError(ValueError):
    """Stable, non-sensitive failure code."""


def _install_termination_handlers():
    if threading.current_thread() is not threading.main_thread():
        return None
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}

    def interrupted(signum, _frame):
        name = "sigterm" if signum == signal.SIGTERM else "sigint"
        raise CanaryError("interrupted_by_" + name)

    for sig in previous:
        signal.signal(sig, interrupted)
    return previous


def _ignore_termination_handlers(previous):
    if previous is not None:
        for sig in previous:
            signal.signal(sig, signal.SIG_IGN)


def _restore_termination_handlers(previous):
    if previous is not None:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _safe_dir(path, *, empty=False):
    try:
        path = _qualified_tart_path(path)
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise CanaryError("unsafe_evidence_directory")
        _check_tart_acl(path)
        if empty and any(path.iterdir()):
            raise CanaryError("evidence_directory_not_empty")
    except CanaryError as exc:
        if exc.args and exc.args[0] == "evidence_directory_not_empty":
            raise
        raise CanaryError("unsafe_evidence_directory") from None
    except (OSError, RuntimeError):
        raise CanaryError("unsafe_evidence_directory") from None
    return path


def _read_receipt(path):
    try:
        path = Path(path).resolve(strict=True)
        if path.stat().st_size > MAX_RECEIPT_BYTES:
            raise CanaryError("receipt_too_large")
        value = json.loads(path.read_text())
    except CanaryError:
        raise
    except (OSError, RuntimeError):
        raise CanaryError("receipt_unavailable") from None
    except (ValueError, UnicodeError):
        raise CanaryError("invalid_receipt") from None
    required = {
        "kind", "baseVmName", "tartVersion", "tartPackageSha256", "tartBinarySha256",
        "ociBaseDigest", "preparedSnapshot", "storageMeasurement",
    }
    if not isinstance(value, dict) or set(value) != required or value.get("kind") != "offline-macos-vm-base-receipt-v1":
        raise CanaryError("invalid_receipt_shape")
    if value["tartVersion"] != TART_VERSION:
        raise CanaryError("tart_version_not_pinned")
    if value["tartPackageSha256"] != TART_PACKAGE_SHA256:
        raise CanaryError("tart_package_digest_not_pinned")
    if value["ociBaseDigest"] != OCI_BASE_DIGEST:
        raise CanaryError("oci_base_not_digest_pinned")
    for field in ("tartBinarySha256",):
        if not isinstance(value[field], str) or not re.fullmatch(r"[0-9a-f]{64}", value[field]):
            raise CanaryError("invalid_receipt_digest")
    if value["tartBinarySha256"] != TART_BINARY_SHA256:
        raise CanaryError("tart_release_digest_not_pinned")
    if not isinstance(value["baseVmName"], str) or not BASE_NAME.fullmatch(value["baseVmName"]):
        raise CanaryError("invalid_base_vm_name")
    snapshot = value["preparedSnapshot"]
    if (not isinstance(snapshot, dict) or set(snapshot) != {"sha256", "bytes"}
            or not isinstance(snapshot["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", snapshot["sha256"])
            or type(snapshot["bytes"]) is not int or snapshot["bytes"] <= 0):
        raise CanaryError("invalid_snapshot_measurement")
    measurement = value["storageMeasurement"]
    if (not isinstance(measurement, dict)
            or set(measurement) != {"configSha256", "configBytes", "nvramSha256", "nvramBytes"}
            or any(not isinstance(measurement[key], str) or not re.fullmatch(r"[0-9a-f]{64}", measurement[key])
                   for key in ("configSha256", "nvramSha256"))
            or type(measurement["configBytes"]) is not int or measurement["configBytes"] <= 0
            or type(measurement["nvramBytes"]) is not int or measurement["nvramBytes"] <= 0):
        raise CanaryError("invalid_storage_measurement")
    return value


def _run_bounded(argv, *, timeout, env, output_limit=MAX_SHORT_OUTPUT, pass_fds=(),
                 capture_paths=None, cancel_check=None):
    """Run fixed local Tart commands with bounded stdout/stderr and process cleanup."""
    captures = []
    if capture_paths is not None:
        try:
            for path in capture_paths:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                captures.append(os.fdopen(fd, "wb"))
        except BaseException:
            for stream in captures:
                stream.close()
            raise CanaryError("raw_evidence_file_create_failed") from None
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env, close_fds=True,
                                   pass_fds=tuple(pass_fds), start_new_session=True)
    except BaseException:
        for capture in captures:
            capture.flush()
            os.fsync(capture.fileno())
            capture.close()
        raise
    selector = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map() or process.poll() is None:
            if cancel_check is not None and cancel_check():
                raise CanaryError("tart_command_cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CanaryError("tart_command_timeout")
            for key, _ in selector.select(min(0.1, remaining)):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                output = streams[key.fileobj]
                capture = captures[0 if key.fileobj is process.stdout else 1] if captures else None
                if capture is not None:
                    remaining_capture = max(0, output_limit - len(output))
                    if remaining_capture:
                        capture.write(chunk[:remaining_capture])
                if len(output) + len(chunk) > output_limit:
                    raise CanaryError("tart_command_output_limit")
                output.extend(chunk)
        try:
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise CanaryError("tart_command_timeout") from None
        if code:
            raise CanaryError("tart_command_failed")
        return bytes(streams[process.stdout]), bytes(streams[process.stderr])
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        raise
    finally:
        selector.close()
        for stream in streams:
            if not stream.closed:
                stream.close()
        for capture in captures:
            if not capture.closed:
                capture.flush()
                os.fsync(capture.fileno())
                capture.close()


def _raw_evidence(path, maximum):
    path = Path(path)
    try:
        digest, count = _hash_file(path, maximum=maximum)
    except (FileNotFoundError, CanaryError):
        return None
    return {"bytes": count, "sha256": digest, "maxBytes": maximum}


def _hash_file(path, *, maximum, collect=False, require_executable=False, require_protected=False):
    path = Path(path)
    if path.is_symlink():
        raise CanaryError("unsafe_base_vm_file")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise CanaryError("unsafe_base_vm_file") from None
    digest = hashlib.sha256()
    count = 0
    collected = bytearray() if collect else None
    try:
        try:
            info = os.fstat(fd)
        except OSError:
            raise CanaryError("unsafe_base_vm_file") from None
        if require_executable and (
                not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
                or stat.S_IMODE(info.st_mode) & 0o022 or not info.st_mode & 0o111):
            raise CanaryError("unsafe_tart_executable")
        if require_protected and (
                not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid())
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise CanaryError("unsafe_base_vm_file")
        if require_executable or require_protected:
            _check_tart_acl(path, fd=fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise CanaryError("unsafe_base_vm_file")
        try:
            while True:
                block = os.read(fd, 8 * 1024 * 1024)
                if not block:
                    break
                count += len(block)
                if count > maximum:
                    raise CanaryError("base_vm_file_too_large")
                digest.update(block)
                if collected is not None:
                    collected.extend(block)
            after = os.fstat(fd)
        except OSError:
            raise CanaryError("unsafe_base_vm_file") from None
    finally:
        os.close(fd)
    if (count != info.st_size or after.st_size != info.st_size or after.st_ino != info.st_ino
            or after.st_dev != info.st_dev or after.st_mtime_ns != info.st_mtime_ns
            or after.st_ctime_ns != info.st_ctime_ns):
        raise CanaryError("base_vm_file_changed_during_measurement")
    if collected is not None:
        return digest.hexdigest(), count, bytes(collected)
    return digest.hexdigest(), count


def _base_vm_measurement(tart_home, name, receipt):
    vms = Path(tart_home) / "vms"
    if vms.is_symlink() or not vms.is_dir():
        raise CanaryError("unsafe_tart_vms_directory")
    vms_info = vms.stat()
    if vms_info.st_uid != os.getuid() or stat.S_IMODE(vms_info.st_mode) & 0o022:
        raise CanaryError("unsafe_tart_vms_directory")
    _check_tart_acl(vms)
    root = Path(tart_home) / "vms" / name
    if root.is_symlink() or not root.is_dir():
        raise CanaryError("base_vm_storage_missing")
    root_info = root.stat()
    if root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) & 0o022:
        raise CanaryError("unsafe_base_vm_directory")
    _check_tart_acl(root)
    config_path = root / "config.json"
    disk_path = root / "disk.img"
    nvram_path = root / "nvram.bin"
    if (root / "state").exists() or (root / "state").is_symlink():
        raise CanaryError("base_vm_has_saved_memory_state")
    config_hash, config_bytes, config_raw = _hash_file(config_path, maximum=MAX_CONFIG_BYTES, collect=True, require_protected=True)
    if config_bytes == 0:
        raise CanaryError("base_vm_config_empty")
    try:
        config = json.loads(config_raw)
    except (ValueError, UnicodeError):
        raise CanaryError("invalid_base_vm_config") from None
    if (not isinstance(config, dict) or config.get("os") != "darwin" or config.get("arch") != "arm64"
            or not isinstance(config.get("macAddress"), str)):
        raise CanaryError("base_vm_config_not_macos_arm64")
    disk_hash, disk_bytes = _hash_file(disk_path, maximum=MAX_DISK_BYTES, require_protected=True)
    nvram_hash, nvram_bytes = _hash_file(nvram_path, maximum=MAX_CONFIG_BYTES * 1024, require_protected=True)
    measurement = {"configSha256": config_hash, "configBytes": config_bytes,
                   "nvramSha256": nvram_hash, "nvramBytes": nvram_bytes}
    if receipt["storageMeasurement"] != measurement:
        raise CanaryError("base_vm_storage_measurement_mismatch")
    snapshot = {"sha256": disk_hash, "bytes": disk_bytes}
    if receipt["preparedSnapshot"] != snapshot:
        raise CanaryError("prepared_snapshot_measurement_mismatch")
    return config, disk_bytes


def _tart_identity(tart, receipt, env, *, run_bounded=None):
    tart_path = _qualified_tart_path(tart)
    try:
        digest, _ = _hash_file(tart_path, maximum=128 * 1024**2, require_executable=True)
    except CanaryError as exc:
        if exc.args and exc.args[0] == "base_vm_file_changed_during_measurement":
            raise CanaryError("tart_binary_changed_during_measurement") from None
        if exc.args and exc.args[0] in ("unsafe_tart_executable", "unsafe_tart_acl"):
            raise
        raise CanaryError("tart_binary_unreadable") from None
    if not os.access(tart_path, os.X_OK):
        raise CanaryError("tart_not_executable")
    if digest != receipt["tartBinarySha256"] or digest != TART_BINARY_SHA256:
        raise CanaryError("tart_binary_digest_mismatch")
    runner = _run_bounded if run_bounded is None else run_bounded
    stdout, _ = runner([str(tart_path), "--version"], timeout=5, env=env)
    if stdout.decode("ascii", "replace").strip() != TART_VERSION:
        raise CanaryError("tart_version_mismatch")
    return tart_path


def _qualified_tart_path(tart):
    try:
        requested = Path(tart)
        if ".." in requested.parts:
            raise CanaryError("unsafe_tart_path")
        path = requested if requested.is_absolute() else Path.cwd() / requested
        components = [Path(path.anchor)]
        for part in path.parts[1:]:
            components.append(components[-1] / part)
        for index, current in enumerate(components):
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode):
                raise CanaryError("unsafe_tart_path")
            if index < len(components) - 1:
                sticky_root = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                        or (info.st_mode & 0o022 and not sticky_root)):
                    raise CanaryError("unsafe_tart_path")
                _check_tart_acl(current)
        canonical = path.resolve(strict=True)
        if canonical != path:
            raise CanaryError("unsafe_tart_path")
        return canonical
    except CanaryError:
        raise
    except (OSError, RuntimeError):
        raise CanaryError("tart_not_executable") from None


def _load_tart_acl_api():
    global _TART_ACL_API
    if _TART_ACL_API is None:
        try:
            library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            library.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
            library.acl_get_link_np.restype = ctypes.c_void_p
            library.acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
            library.acl_get_fd_np.restype = ctypes.c_void_p
            library.acl_get_entry.argtypes = [
                ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p),
            ]
            library.acl_get_entry.restype = ctypes.c_int
            library.acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            library.acl_get_tag_type.restype = ctypes.c_int
            library.acl_get_permset_mask_np.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint64),
            ]
            library.acl_get_permset_mask_np.restype = ctypes.c_int
            library.acl_free.argtypes = [ctypes.c_void_p]
            library.acl_free.restype = ctypes.c_int
            _TART_ACL_API = library
        except (OSError, AttributeError, TypeError):
            raise CanaryError("unsafe_tart_acl") from None
    return _TART_ACL_API


def _check_tart_acl(path, *, fd=None):
    # POSIX ACL write masks appear in st_mode; Darwin extended ACLs do not.
    if sys.platform != "darwin":
        return
    try:
        library = _load_tart_acl_api()
        ctypes.set_errno(0)
        acl = (library.acl_get_fd_np(fd, _ACL_TYPE_EXTENDED) if fd is not None
               else library.acl_get_link_np(os.fsencode(path), _ACL_TYPE_EXTENDED))
        if not acl:
            if ctypes.get_errno() == errno.ENOENT:
                return
            raise CanaryError("unsafe_tart_acl")
        try:
            entry_kind = _ACL_FIRST_ENTRY
            for index in range(129):
                entry = ctypes.c_void_p()
                ctypes.set_errno(0)
                status = library.acl_get_entry(acl, entry_kind, ctypes.byref(entry))
                if status == -1:
                    if ctypes.get_errno() == errno.EINVAL:
                        return
                    raise CanaryError("unsafe_tart_acl")
                if status != 0:
                    raise CanaryError("unsafe_tart_acl")
                if index == 128:
                    raise CanaryError("unsafe_tart_acl")
                entry_kind = _ACL_NEXT_ENTRY
                tag = ctypes.c_int()
                permissions = ctypes.c_uint64()
                if (library.acl_get_tag_type(entry, ctypes.byref(tag)) != 0
                        or library.acl_get_permset_mask_np(entry, ctypes.byref(permissions)) != 0):
                    raise CanaryError("unsafe_tart_acl")
                if tag.value == _ACL_EXTENDED_DENY:
                    continue
                if tag.value != _ACL_EXTENDED_ALLOW:
                    raise CanaryError("unsafe_tart_acl")
                if permissions.value & _ACL_MUTATING_PERMISSIONS:
                    raise CanaryError("unsafe_tart_acl")
            raise CanaryError("unsafe_tart_acl")
        finally:
            library.acl_free(acl)
    except CanaryError:
        raise
    except (OSError, ValueError, TypeError, AttributeError):
        raise CanaryError("unsafe_tart_acl") from None


def _safe_tart_home(tart_home):
    configured = tart_home or os.environ.get("TART_HOME") or (Path.home() / ".tart")
    try:
        # Protected ancestors keep every later Tart pathname lookup on the measured home.
        path = _qualified_tart_path(configured)
        info = path.stat()
    except CanaryError as exc:
        if exc.args and exc.args[0] == "unsafe_tart_acl":
            raise
        raise CanaryError("unsafe_tart_home") from None
    except OSError:
        raise CanaryError("unsafe_tart_home") from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise CanaryError("unsafe_tart_home")
    _check_tart_acl(path)
    return path


def _vm_stopped(raw):
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        return False
    return isinstance(value, dict) and value.get("Running") is False and value.get("State") == "stopped"


def _decode_frame(frame):
    """Return only fixed-probe classification; never retain arbitrary packet bytes."""
    if len(frame) < 14:
        return None
    ethertype = int.from_bytes(frame[12:14], "big")
    offset = 14
    if ethertype == 0x0800:
        if len(frame) < offset + 20:
            return None
        ihl = (frame[offset] & 0x0f) * 4
        if ihl < 20 or len(frame) < offset + ihl + 8 or frame[offset + 9] != 17:
            return None
        src = ipaddress.IPv4Address(frame[offset + 12:offset + 16])
        dst = ipaddress.IPv4Address(frame[offset + 16:offset + 20])
        udp = offset + ihl
        family = "ipv4"
    elif ethertype == 0x86DD:
        if len(frame) < offset + 48 or frame[offset + 6] != 17:
            return None
        src = ipaddress.IPv6Address(frame[offset + 8:offset + 24])
        dst = ipaddress.IPv6Address(frame[offset + 24:offset + 40])
        udp = offset + 40
        family = "ipv6"
    else:
        return None
    source_port = int.from_bytes(frame[udp:udp + 2], "big")
    dest_port = int.from_bytes(frame[udp + 2:udp + 4], "big")
    length = int.from_bytes(frame[udp + 4:udp + 6], "big")
    payload = frame[udp + 8:udp + length]
    if length < 8 or len(payload) != length - 8:
        return None
    return {"family": family, "source": str(src), "destination": str(dst),
            "sourcePort": source_port, "destinationPort": dest_port, "payload": payload}


def _ethernet_udp(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload):
    """Build the expected minimal untagged Ethernet/UDP frame for test fixtures."""
    src_mac = bytes.fromhex(src_mac.replace(":", ""))
    dst_mac = bytes.fromhex(dst_mac.replace(":", ""))
    source = ipaddress.ip_address(src_ip)
    dest = ipaddress.ip_address(dst_ip)
    udp = src_port.to_bytes(2, "big") + dst_port.to_bytes(2, "big") + (8 + len(payload)).to_bytes(2, "big") + b"\0\0" + payload
    if source.version == 4 and dest.version == 4:
        total = 20 + len(udp)
        ip = bytes([0x45, 0]) + total.to_bytes(2, "big") + b"\0\0\0\0" + bytes([64, 17]) + b"\0\0" + source.packed + dest.packed
        ethertype = b"\x08\x00"
    elif source.version == 6 and dest.version == 6:
        ip = bytes.fromhex("60000000") + len(udp).to_bytes(2, "big") + bytes([17, 64]) + source.packed + dest.packed
        ethertype = b"\x86\xdd"
    else:
        raise ValueError("address family mismatch")
    return dst_mac + src_mac + ethertype + ip + udp


GUEST_CANARY = r'''import json, os, platform, re, socket, subprocess, tempfile, time
nonce = __import__("sys").argv[1]
results = {}
product_version = subprocess.check_output(["/usr/bin/sw_vers", "-productVersion"], text=True).strip()
build_version = subprocess.check_output(["/usr/bin/sw_vers", "-buildVersion"], text=True).strip()
architecture = platform.machine()
if not re.fullmatch(r"15\.[0-9]+(?:\.[0-9]+)?", product_version) or architecture != "arm64" or not build_version:
    raise SystemExit("guest_platform_not_macos15_arm64")
def require(ok, code):
    if not ok: raise SystemExit(code)
for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
    server = socket.socket(family, socket.SOCK_STREAM)
    server.bind((host, 0)); server.listen(1); server.settimeout(2)
    client = socket.socket(family, socket.SOCK_STREAM); client.settimeout(2)
    client.connect(server.getsockname()); conn, _ = server.accept(); conn.close(); client.close(); server.close()
    receiver = socket.socket(family, socket.SOCK_DGRAM); receiver.bind((host, 0)); receiver.settimeout(2)
    sender = socket.socket(family, socket.SOCK_DGRAM); sender.sendto(b"loopback", (host, receiver.getsockname()[1]))
    require(receiver.recvfrom(32)[0] == b"loopback", "loopback_udp_failed"); sender.close(); receiver.close()
    results["loopback-" + ("ipv4" if family == socket.AF_INET else "ipv6")] = True
def check_unix_socket():
    with tempfile.TemporaryDirectory(prefix="offline-canary-", dir="/tmp") as directory:
        path = os.path.join(directory, "probe.sock")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); server.bind(path); server.listen(1)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); client.connect(path)
        conn, _ = server.accept(); conn.close(); client.close(); server.close()
check_unix_socket()
results["unix-socket"] = True
subprocess.run(["/usr/bin/sandbox-exec", "-p", "(version 1) (allow default)", "/usr/bin/true"], check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
results["nested-seatbelt"] = True
def root(*args): subprocess.run(["/usr/bin/sudo", "-n", *args], check=True, timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
iface = "en0"
root("/sbin/ifconfig", iface, "inet", "198.18.88.2", "netmask", "255.255.255.0", "up")
root("/sbin/ifconfig", iface, "inet6", "fd00:8888::2", "prefixlen", "64")
root("/sbin/route", "-n", "add", "-host", "203.0.113.7", "-interface", iface)
root("/usr/sbin/arp", "-s", "203.0.113.7", "02:00:00:00:00:02")
root("/sbin/route", "-n", "add", "-inet6", "-host", "2001:db8::7", "-interface", iface)
root("/usr/sbin/ndp", "-s", "2001:db8::7", "02:00:00:00:00:02")
v6_ready_deadline = time.monotonic() + 10
while True:
    probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        probe.bind(("fd00:8888::2", 0, 0, 0)); probe.close(); break
    except OSError:
        probe.close()
        if time.monotonic() >= v6_ready_deadline: raise SystemExit("ipv6_source_not_ready")
        time.sleep(0.1)
for family, source, host, port in ((socket.AF_INET, "198.18.88.2", "203.0.113.7", 49371), (socket.AF_INET6, "fd00:8888::2", "2001:db8::7", 49372)):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind((source, 0) if family == socket.AF_INET else (source, 0, 0, 0))
    sock.sendto(("OFFLINE_CANARY:" + nonce + ("4" if family == socket.AF_INET else "6")).encode(), (host, port)); sock.close()
    results["sent-" + ("ipv4" if family == socket.AF_INET else "ipv6")] = True
print(json.dumps({"kind": "offline-macos-vm-guest-canary-v1", "nonce": nonce, "checks": results,
    "runtime": {"productVersion": product_version, "buildVersion": build_version, "architecture": architecture}}, separators=(",", ":")))
'''


def _guest_result(data, nonce):
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError):
        raise CanaryError("invalid_guest_canary_result") from None
    expected = {"loopback-ipv4", "loopback-ipv6", "unix-socket", "nested-seatbelt", "sent-ipv4", "sent-ipv6"}
    if (not isinstance(value, dict) or set(value) != {"kind", "nonce", "checks", "runtime"}
            or value["kind"] != "offline-macos-vm-guest-canary-v1" or value["nonce"] != nonce
            or value["checks"] != {name: True for name in expected}):
        raise CanaryError("guest_canary_checks_failed")
    runtime = value["runtime"]
    if (not isinstance(runtime, dict) or set(runtime) != {"productVersion", "buildVersion", "architecture"}
            or not isinstance(runtime["productVersion"], str)
            or not re.fullmatch(r"15\.[0-9]+(?:\.[0-9]+)?", runtime["productVersion"])
            or not isinstance(runtime["buildVersion"], str) or not runtime["buildVersion"]
            or runtime["architecture"] != "arm64"):
        raise CanaryError("guest_platform_not_macos15_arm64")
    return {"checks": sorted(expected), "runtime": runtime}


def _drain(peer, stop, nonce, vm_mac, records, failures, counters, evidence):
    marker4 = ("OFFLINE_CANARY:" + nonce + "4").encode()
    marker6 = ("OFFLINE_CANARY:" + nonce + "6").encode()
    wanted = {"ipv4": ("203.0.113.7", 49371, marker4), "ipv6": ("2001:db8::7", 49372, marker6)}
    count = 0
    try:
        peer.settimeout(0.1)
        while not stop.is_set():
            try:
                frame = peer.recv(MAX_FRAME + 1)
            except socket.timeout:
                continue
            count += 1
            counters["received"] = count
            counters["receivedBytes"] = counters.get("receivedBytes", 0) + len(frame)
            if count > MAX_FRAMES or len(frame) > MAX_FRAME:
                failures.append("frame_limit_exceeded")
                stop.set()
                break
            packet = _decode_frame(frame)
            if packet is None or frame[6:12].hex(":").lower() != vm_mac.lower():
                continue
            family = packet["family"]
            target = wanted.get(family)
            if (target and frame[:6] == bytes.fromhex("020000000002")
                    and packet["source"] == ("198.18.88.2" if family == "ipv4" else "fd00:8888::2")
                    and (packet["destination"], packet["destinationPort"], packet["payload"]) == target):
                if family not in records:
                    frame_path = evidence / f"frame-{family}.bin"
                    fd = os.open(frame_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "wb") as output:
                        output.write(frame)
                        output.flush()
                        os.fsync(output.fileno())
                    records[family] = {"count": 1, "frameSha256": _sha256(frame),
                                       "file": frame_path.name}
                else:
                    records[family]["count"] += 1
    except OSError:
        if not stop.is_set():
            failures.append("network_drainer_failed")
            stop.set()


def _drain_tart_logs(process, failures, result, evidence):
    """Continuously hash capped Tart output so diagnostics cannot fill disk or pipes."""
    selector = selectors.DefaultSelector()
    hashes = {process.stdout: hashlib.sha256(), process.stderr: hashlib.sha256()}
    counts = {process.stdout: 0, process.stderr: 0}
    observed = {process.stdout: 0, process.stderr: 0}
    files = {}
    try:
        for stream, name in ((process.stdout, "tart-stdout.bin"), (process.stderr, "tart-stderr.bin")):
            fd = os.open(evidence / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            files[stream] = os.fdopen(fd, "wb")
        for stream in hashes:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            for key, _ in selector.select(0.1):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                observed[key.fileobj] += len(chunk)
                retained = chunk[:max(0, MAX_SHORT_OUTPUT - counts[key.fileobj])]
                if retained:
                    files[key.fileobj].write(retained)
                    hashes[key.fileobj].update(retained)
                    counts[key.fileobj] += len(retained)
                if observed[key.fileobj] > MAX_SHORT_OUTPUT:
                    failures.append("tart_run_output_limit")
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
    except OSError:
        failures.append("tart_run_log_read_failed")
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    finally:
        selector.close()
        for stream in hashes:
            if not stream.closed:
                stream.close()
        for stream in files.values():
            if not stream.closed:
                stream.flush()
                os.fsync(stream.fileno())
                stream.close()
    result["tartRunLogs"] = {
        "stdout": {"bytesObserved": observed[process.stdout], "bytesRetained": counts[process.stdout],
                   "sha256": hashes[process.stdout].hexdigest(), "file": "tart-stdout.bin"},
        "stderr": {"bytesObserved": observed[process.stderr], "bytesRetained": counts[process.stderr],
                   "sha256": hashes[process.stderr].hexdigest(), "file": "tart-stderr.bin"},
        "maxBytesPerStream": MAX_SHORT_OUTPUT,
    }


def _write_result_manifest(evidence, result):
    raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(raw) > MAX_SHORT_OUTPUT:
        prior_errors = result.get("cleanupErrors", [])
        result = {
            "kind": "offline-macos-vm-boundary-canary-v1",
            "status": "tainted",
            "baseVmName": result.get("baseVmName"),
            "cloneVmName": result.get("cloneVmName"),
            "error": result.get("error") or "result_too_large",
            "cleanupErrors": [*prior_errors, "result_too_large"],
            "vmStop": result.get("vmStop", {"commandSucceeded": None, "stateConfirmedStopped": False}),
        }
        raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    path = evidence / "offline-macos-vm-canary.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    evidence_fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(evidence_fd)
    finally:
        os.close(evidence_fd)
    return {"kind": result["kind"], "status": result["status"], "resultSha256": _sha256(raw)}


def qualify(base_vm, receipt_path, evidence_dir, *, tart="/opt/homebrew/bin/tart", clock=time.monotonic,
            popen=subprocess.Popen, run_bounded=_run_bounded, tart_home=None):
    """Run one owned clone and return its published summary after cleanup."""
    if not BASE_NAME.fullmatch(base_vm) or "://" in base_vm:
        raise CanaryError("base_vm_must_be_local_name")
    receipt = _read_receipt(receipt_path)
    if receipt["baseVmName"] != base_vm:
        raise CanaryError("base_vm_receipt_mismatch")
    evidence = _safe_dir(evidence_dir, empty=True)
    tart_home = _safe_tart_home(tart_home)
    env = {"PATH": os.defpath, "HOME": str(Path.home()), "TART_HOME": str(tart_home),
           "LC_ALL": "C", "LANG": "C", "TART_NO_AUTO_PRUNE": "1"}
    tart_path = _tart_identity(tart, receipt, env, run_bounded=run_bounded)
    _, base_disk_bytes = _base_vm_measurement(tart_home, base_vm, receipt)
    free = shutil.disk_usage(tart_home).free
    if free < base_disk_bytes + CLONE_LOG_HEADROOM:
        raise CanaryError("insufficient_vm_storage_capacity")
    clone = "offline-canary-" + uuid.uuid4().hex
    clone_created = False
    clone_attempted = False
    clone_config = {}
    vm_proc = None
    vm_reaped = True
    parent = child = None
    stop_drain = threading.Event()
    records = {}
    counters = {"received": 0, "receivedBytes": 0}
    commands = []
    failures = []
    drain_thread = None
    log_thread = None
    result = {"kind": "offline-macos-vm-boundary-canary-v1", "baseVmName": base_vm,
              "storageMeasurement": receipt["storageMeasurement"], "ociBaseDigest": receipt["ociBaseDigest"],
              "preparedSnapshot": receipt["preparedSnapshot"],
              "tartVersion": TART_VERSION, "tartBinarySha256": receipt["tartBinarySha256"],
              "tartPackageSha256": receipt["tartPackageSha256"],
              "ociProvenance": "operator-declared; controller does not independently bind the OCI import",
              "guestScriptSha256": _sha256(GUEST_CANARY.encode()),
              "startedUnix": int(time.time()), "cloneVmName": clone,
              "status": "failed", "checks": [], "frames": {"hostReceived": 0, "hostTransmitted": 0}}
    result["readinessProbe"] = {"command": ["/usr/bin/true"], "attempts": 0, "ready": False}
    guest_stdout_path = evidence / "guest-stdout.bin"
    guest_stderr_path = evidence / "guest-stderr.bin"
    cleanup_errors = []
    stop_outcome = {"commandSucceeded": None, "stateConfirmedStopped": False}
    saved_signal_handlers = _install_termination_handlers()
    try:
        clone_attempted = True
        run_bounded([str(tart_path), "clone", base_vm, clone], timeout=60, env=env)
        clone_created = True
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        parent.setblocking(False)
        network_fd = child.fileno()
        vm_proc = popen([str(tart_path), "run", clone, f"--net-fd={network_fd}", "--no-clipboard",
                         "--no-audio", "--no-usb-accessories", "--no-graphics"], stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, close_fds=True,
                        pass_fds=(child.fileno(),), start_new_session=True)
        vm_reaped = False
        log_thread = threading.Thread(target=_drain_tart_logs, args=(vm_proc, failures, result, evidence), daemon=True)
        log_thread.start()
        child.close()
        child = None
        stdout, _ = run_bounded([str(tart_path), "get", clone, "--format", "json"], timeout=10, env=env)
        clone_config = json.loads(stdout)
        vm_mac = clone_config.get("MACAddress")
        if not isinstance(vm_mac, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", vm_mac):
            raise CanaryError("clone_mac_missing")
        nonce = uuid.uuid4().hex
        drain_thread = threading.Thread(target=_drain, args=(parent, stop_drain, nonce, vm_mac, records, failures, counters, evidence), daemon=True)
        drain_thread.start()
        ready_deadline = clock() + VM_READY_TIMEOUT

        def supervision_failed():
            if failures:
                return True
            if drain_thread.ident is not None and not drain_thread.is_alive():
                failures.append("network_drainer_stopped")
                return True
            if (log_thread.ident is not None and not log_thread.is_alive()
                    and vm_proc.poll() is None):
                failures.append("tart_log_drainer_stopped")
                return True
            return vm_proc.poll() is not None

        readiness_argv = [str(tart_path), "exec", clone, "/usr/bin/true"]
        result["readinessProbe"]["argv"] = readiness_argv
        commands.extend([[str(tart_path), "clone", base_vm, clone],
                         [str(tart_path), "run", clone, f"--net-fd={network_fd}", "--no-clipboard",
                          "--no-audio", "--no-usb-accessories", "--no-graphics"],
                         readiness_argv])
        while clock() < ready_deadline:
            if supervision_failed():
                if failures:
                    raise CanaryError(failures[0])
                raise CanaryError("tart_vm_exited_before_guest_ready")
            if vm_proc.poll() is not None:
                raise CanaryError("tart_vm_exited_before_guest_ready")
            result["readinessProbe"]["attempts"] += 1
            try:
                run_bounded(readiness_argv, timeout=min(VM_READY_PROBE_TIMEOUT, max(0.1, ready_deadline - clock())),
                            env=env, output_limit=MAX_GUEST_OUTPUT,
                            cancel_check=supervision_failed)
                result["readinessProbe"]["ready"] = True
                break
            except CanaryError as exc:
                if failures:
                    raise CanaryError(failures[0]) from None
                if vm_proc.poll() is not None:
                    raise CanaryError("tart_vm_exited_before_guest_ready") from None
                if exc.args and exc.args[0] in {"tart_command_failed", "tart_command_timeout"}:
                    time.sleep(min(VM_READY_RETRY_INTERVAL, max(0, ready_deadline - clock())))
                    continue
                raise
        if not result["readinessProbe"]["ready"]:
            raise CanaryError("guest_agent_readiness_timeout")
        deadline = clock() + CANARY_TIMEOUT
        guest_argv = [str(tart_path), "exec", clone, "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-c", GUEST_CANARY, nonce]
        commands.append(guest_argv)
        try:
            guest_stdout, guest_stderr = run_bounded(
                guest_argv, timeout=max(1, deadline - clock()), env=env,
                output_limit=MAX_GUEST_OUTPUT, capture_paths=(guest_stdout_path, guest_stderr_path),
                cancel_check=supervision_failed)
        except CanaryError:
            if failures:
                raise CanaryError(failures[0]) from None
            if vm_proc.poll() is not None:
                raise CanaryError("tart_vm_exited_during_guest_canary") from None
            raise
        result["guestOutput"] = {"bytes": len(guest_stdout), "sha256": _sha256(guest_stdout),
                                 "stderrBytes": len(guest_stderr), "stderrSha256": _sha256(guest_stderr),
                                 "scriptSha256": _sha256(GUEST_CANARY.encode())}
        guest_validation = _guest_result(guest_stdout, nonce)
        result["checks"] = guest_validation["checks"]
        result["guestRuntime"] = guest_validation["runtime"]
        while clock() < deadline and ("ipv4" not in records or "ipv6" not in records):
            if supervision_failed():
                if failures:
                    raise CanaryError(failures[0])
                raise CanaryError("tart_vm_exited_during_canary")
            if vm_proc.poll() is not None:
                raise CanaryError("tart_vm_exited_during_canary")
            time.sleep(0.05)
        if "ipv4" not in records or "ipv6" not in records:
            raise CanaryError("guest_external_frames_not_observed")
        if failures:
            raise CanaryError(failures[0])
        result["status"] = "passed"
    except BaseException as exc:
        result["error"] = exc.args[0] if isinstance(exc, CanaryError) and exc.args else "canary_failed"
        raise
    finally:
        _ignore_termination_handlers(saved_signal_handlers)
        try:
            stop_drain.set()
            if parent is not None:
                parent.close()
            if child is not None:
                child.close()
            if vm_proc is not None:
                # No reconnect is attempted. Closing the inherited network FD leaves the VM NIC
                # disconnected. Request exact-VM stop, then terminate its owned Tart process group.
                try:
                    run_bounded([str(tart_path), "stop", clone], timeout=15, env=env)
                except BaseException:
                    stop_outcome["commandSucceeded"] = False
                else:
                    stop_outcome["commandSucceeded"] = True
                try:
                    os.killpg(vm_proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                except OSError:
                    vm_proc.terminate()
                try:
                    vm_proc.wait(timeout=10)
                    vm_reaped = True
                except BaseException:
                    try:
                        os.killpg(vm_proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except OSError:
                        vm_proc.kill()
                    try:
                        vm_proc.wait(timeout=5)
                        vm_reaped = True
                    except BaseException:
                        cleanup_errors.append("tart_process_reap_failed")
            if clone_created:
                try:
                    state_output, _ = run_bounded(
                        [str(tart_path), "get", clone, "--format", "json"], timeout=10, env=env)
                    stop_outcome["stateConfirmedStopped"] = _vm_stopped(state_output)
                except BaseException:
                    stop_outcome["stateConfirmedStopped"] = False
                if not stop_outcome["stateConfirmedStopped"]:
                    cleanup_errors.append("owned_clone_vm_state_not_confirmed_stopped")
            if drain_thread is not None:
                drain_thread.join(timeout=2)
                if drain_thread.is_alive():
                    cleanup_errors.append("network_drainer_not_joined")
            if log_thread is not None:
                log_thread.join(timeout=2)
                if log_thread.is_alive():
                    cleanup_errors.append("tart_log_drainer_not_joined")
            if failures and result["status"] == "passed":
                result["status"] = "failed"
                result["error"] = failures[0]
            result["frames"] = {"hostReceived": counters["received"], "hostReceivedBytes": counters["receivedBytes"],
                                "hostTransmitted": 0, "matched": records,
                                "dropMechanism": "host-drained-and-discarded-every-datagram; no send operation exists"}
            result["rawEvidence"] = {
                name: _raw_evidence(evidence / name, limit)
                for name, limit in (("guest-stdout.bin", MAX_GUEST_OUTPUT),
                                    ("guest-stderr.bin", MAX_GUEST_OUTPUT),
                                    ("tart-stdout.bin", MAX_SHORT_OUTPUT),
                                    ("tart-stderr.bin", MAX_SHORT_OUTPUT),
                                    ("frame-ipv4.bin", MAX_FRAME), ("frame-ipv6.bin", MAX_FRAME))
            }
            # Delete only our random clone. The prepared base is never modified or removed.
            if clone_created and vm_reaped and stop_outcome["stateConfirmedStopped"]:
                try:
                    run_bounded([str(tart_path), "delete", clone], timeout=20, env=env)
                except BaseException:
                    cleanup_errors.append("owned_clone_delete_failed")
            elif clone_created and not vm_reaped:
                cleanup_errors.append("owned_clone_retained_vm_process_unreaped")
            elif clone_created and not stop_outcome["stateConfirmedStopped"]:
                cleanup_errors.append("owned_clone_retained_vm_not_confirmed_stopped")
            elif clone_attempted:
                cleanup_errors.append("clone_creation_ownership_unverified")
            if cleanup_errors:
                result["status"] = "tainted"
                result["cleanupErrors"] = cleanup_errors
            result["hostCommandTemplates"] = commands
            if vm_proc is not None:
                result["hostCommandTemplates"].append([str(tart_path), "stop", clone])
            if clone_created:
                result["hostCommandTemplates"].append([str(tart_path), "get", clone, "--format", "json"])
            if clone_created and vm_reaped and stop_outcome["stateConfirmedStopped"]:
                result["hostCommandTemplates"].append([str(tart_path), "delete", clone])
            result["vmStop"] = stop_outcome
            result["frameCounters"] = {**counters, "hostTransmitted": 0}
            summary = _write_result_manifest(evidence, result)
        finally:
            _restore_termination_handlers(saved_signal_handlers)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-vm", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--tart", type=Path, default=Path("/opt/homebrew/bin/tart"))
    parser.add_argument("--tart-home", type=Path, default=None,
                        help="private Tart home (defaults to TART_HOME, then ~/.tart)")
    args = parser.parse_args(argv)
    try:
        summary = qualify(args.base_vm, args.receipt, args.evidence_dir, tart=str(args.tart), tart_home=args.tart_home)
    except CanaryError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except OSError:
        print("filesystem_operation_failed", file=sys.stderr)
        return 1
    print(json.dumps(summary, separators=(",", ":")))
    return 0 if summary["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
