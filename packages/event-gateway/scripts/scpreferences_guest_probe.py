"""Build and validate the fixed guest SCPreferences API probe bundle."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import zlib

import qualify_offline_macos_vm as canary

REPORT_KIND = "scpreferences-guest-api-qualification-v1"
CHECKS = {"environmentSupported", "captureCompleted", "targetWriteAppliedSynchronized",
          "freshTargetReadback", "lockContentionRejected", "restoreCompleted",
          "freshOriginalReadback", "restoredMarkerVerified"}
SOURCE_FILES = {
    "offlineCanary": "qualify_offline_macos_vm.py",
    "softnetPreferences": "softnet_preferences.py",
    "softnetRecovery": "softnet_recovery.py",
    "guestApi": "qualify_scpreferences_guest.py",
}
SOURCE_DIR = Path(__file__).resolve().parent
SOURCE_PATHS = {key: SOURCE_DIR / filename for key, filename in SOURCE_FILES.items()}
MAX_SOURCE_BYTES = 256 * 1024
MAX_BUNDLE_ARG = 128 * 1024
MAX_REPORT_BYTES = 16 * 1024
TIMEOUT = 30

LOADER = r'''import base64, hashlib, json, os, re, shutil, stat, sys, tempfile, zlib
if len(sys.argv) != 2 or len(sys.argv[1]) > 131072:
    raise SystemExit("invalid_bundle_argument")
try:
    packed = base64.b64decode(sys.argv[1], validate=True)
    decoder = zlib.decompressobj()
    raw = decoder.decompress(packed, 262145)
    if len(raw) > 262144 or decoder.unconsumed_tail or not decoder.eof or decoder.unused_data:
        raise ValueError("invalid_bundle_size")
    bundle = json.loads(raw)
    expected = {"qualify_offline_macos_vm.py", "softnet_preferences.py",
                "softnet_recovery.py", "qualify_scpreferences_guest.py"}
    if type(bundle) is not dict or set(bundle) != expected:
        raise ValueError("invalid_bundle_files")
    files = {}
    for name in expected:
        item = bundle[name]
        if type(item) is not dict or set(item) != {"sha256", "content"}:
            raise ValueError("invalid_bundle_record")
        if not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            raise ValueError("invalid_bundle_digest")
        content = base64.b64decode(item["content"], validate=True)
        if len(content) > 262144 or hashlib.sha256(content).hexdigest() != item["sha256"]:
            raise ValueError("bundle_digest_mismatch")
        files[name] = content
except (ValueError, TypeError, UnicodeError, zlib.error):
    raise SystemExit("invalid_source_bundle") from None
root = tempfile.mkdtemp(prefix="softnet-scpreferences-modules-", dir="/private/tmp")
try:
    os.chmod(root, 0o700)
    for name, content in files.items():
        path = os.path.join(root, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            try: os.close(fd)
            except OSError: pass
            raise
    directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    sys.dont_write_bytecode = True
    sys.path.insert(0, root)
    import qualify_scpreferences_guest
    report = qualify_scpreferences_guest.qualify_guest_apis()
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    raise SystemExit(0 if report.get("status") == "passed" else 1)
finally:
    shutil.rmtree(root, ignore_errors=True)
'''


def _read_source(path):
    path = Path(path)
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
            raise canary.CanaryError("scpreferences_api_source_unsafe")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
                raise canary.CanaryError("scpreferences_api_source_unsafe")
            data = bytearray()
            while True:
                block = os.read(fd, min(65536, MAX_SOURCE_BYTES + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
                if len(data) > MAX_SOURCE_BYTES:
                    raise canary.CanaryError("scpreferences_api_source_oversized")
            return bytes(data)
        finally:
            os.close(fd)
    except OSError as error:
        raise canary.CanaryError("scpreferences_api_source_unavailable") from error


def build_bundle():
    files = {}
    source_hashes = {}
    for key, filename in SOURCE_FILES.items():
        data = _read_source(SOURCE_PATHS[key])
        digest = hashlib.sha256(data).hexdigest()
        files[filename] = {"sha256": digest, "content": base64.b64encode(data).decode("ascii")}
        source_hashes[key] = digest
    raw = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("utf-8")
    encoded = base64.b64encode(zlib.compress(raw, 9))
    if len(raw) > MAX_SOURCE_BYTES or len(encoded) > MAX_BUNDLE_ARG:
        raise canary.CanaryError("scpreferences_api_bundle_oversized")
    return {"argument": encoded.decode("ascii"), "sourceSha256": source_hashes,
            "bundleSha256": hashlib.sha256(encoded).hexdigest()}


def _validated_report(stdout, stderr, expected_hashes):
    if len(stdout) > MAX_REPORT_BYTES or len(stderr) > MAX_REPORT_BYTES or stderr:
        raise canary.CanaryError("scpreferences_api_output_invalid")
    try:
        report = json.loads(stdout)
    except (ValueError, UnicodeError, RecursionError):
        raise canary.CanaryError("scpreferences_api_report_invalid") from None
    expected_keys = {"kind", "status", "apiQualified", "effectiveDaemonQualified", "failureCode",
                     "checks", "savedValuePresent", "sourceSha256", "journalDirectory"}
    journal = report.get("journalDirectory") if isinstance(report, dict) else None
    if (not isinstance(report, dict) or set(report) != expected_keys
            or report["kind"] != REPORT_KIND or report["status"] != "passed"
            or report["apiQualified"] is not True or report["effectiveDaemonQualified"] is not False
            or report["failureCode"] is not None
            or not isinstance(report["checks"], dict) or set(report["checks"]) != CHECKS
            or any(value is not True for value in report["checks"].values())
            or type(report["savedValuePresent"]) is not bool
            or report["sourceSha256"] != expected_hashes
            or not isinstance(journal, str)
            or not re.fullmatch(r"/private/tmp/softnet-scpreferences-api-[A-Za-z0-9_-]+", journal)):
        raise canary.CanaryError("scpreferences_api_report_unqualified")
    return report


def metadata(bundle):
    return {"sourceSha256": bundle["sourceSha256"], "bundleSha256": bundle["bundleSha256"],
            "rawLogs": {"stdout": "scpreferences-api-stdout.bin",
                        "stderr": "scpreferences-api-stderr.bin",
                        "maxBytesPerStream": MAX_REPORT_BYTES}}


def command_template(tart_path, vm_name):
    return [str(tart_path), "exec", vm_name, "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I",
            "-c", LOADER, "<fixed-source-bundle-b64>"]


def qualify(tart_path, vm_name, env, evidence, bundle, *, run_bounded):
    argv = [str(tart_path), "exec", vm_name, "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I",
            "-c", LOADER, bundle["argument"]]
    stdout_path = Path(evidence) / "scpreferences-api-stdout.bin"
    stderr_path = Path(evidence) / "scpreferences-api-stderr.bin"
    stdout, stderr = run_bounded(argv, timeout=TIMEOUT, env=env,
                                 output_limit=MAX_REPORT_BYTES,
                                 capture_paths=(stdout_path, stderr_path))
    report = _validated_report(stdout, stderr, bundle["sourceSha256"])
    return {"report": report}
