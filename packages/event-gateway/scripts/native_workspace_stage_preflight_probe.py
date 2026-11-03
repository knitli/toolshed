#!/usr/bin/env python3
"""Offline host preflight for the fixed native workspace staging input bundle.

This receives source files and smoke-imports the stager only. It never calls
stage(), Cargo, a downloader, an installer, or a caller-provided guest program.
"""

import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat

import native_workspace_stage_inputs as staging
import qualify_offline_macos_vm as canary


KIND = "native-workspace-stage-preflight-v1"
MAX_OUTPUT_BYTES = 32 * 1024
MAX_REPORT_BYTES = MAX_OUTPUT_BYTES
MAX_ARCHIVE_BYTES = staging.MAX_ARCHIVE_BYTES
COMMAND_TIMEOUT = 45
LOG_NAMES = ("stage-inputs-receiver.stdout.bin", "stage-inputs-receiver.stderr.bin",
             "stage-inputs-import.stdout.bin", "stage-inputs-import.stderr.bin")
GUEST_ROOT = re.compile(r"/private/tmp/native-workspace-inputs-[A-Za-z0-9_-]+\Z")
IMPORT_KIND = "native-workspace-stage-import-v1"
IMPORT_CODE = "\n".join((
    "import json, os, sys",
    "if sys.version_info < (3, 13): raise SystemExit(3)",
    "sys.path.insert(0, sys.argv[1] + '/packages/event-gateway/scripts')",
    "import stage_native_workspace",
    "print(json.dumps({'kind':'native-workspace-stage-import-v1',",
    "'status':'passed','qualified':False,",
    "'pythonVersion':'.'.join(map(str, sys.version_info[:3])),",
    "'pythonExecutable':os.path.realpath(sys.executable)},",
    "sort_keys=True,separators=(',',':')))"
))
IMPORT_ENV = {
    "HOME": "/Users/admin", "USER": "admin", "LOGNAME": "admin",
    "PATH": "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin",
    "TMPDIR": "/private/tmp/", "LC_ALL": "C", "LANG": "C",
    "PYTHONDONTWRITEBYTECODE": "1",
}


class PreflightError(canary.CanaryError):
    """Stable validation failure for the offline staging-input preflight."""


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def build_bundle(root=staging.ROOT):
    """Build the fixed archive and receipt receiver from the exact source closure."""
    return staging.build_bundle(root)


def _safe_evidence_path(evidence, name):
    directory = Path(evidence)
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise PreflightError("unsafe_evidence_directory")
    return directory / name


def _write_archive(path, bundle):
    data = bundle.get("archive")
    manifest = bundle.get("manifest")
    if not isinstance(data, bytes) or type(manifest) is not dict:
        raise PreflightError("invalid_bundle")
    if (len(data) > MAX_ARCHIVE_BYTES or manifest.get("qualified") is not False
            or manifest.get("archiveBytes") != len(data)
            or manifest.get("archiveSha256") != _digest(data)):
        raise PreflightError("bundle_archive_digest_mismatch")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        written = 0
        while written < len(data):
            count = os.write(fd, data[written:])
            if count <= 0:
                raise PreflightError("archive_write_failed")
            written += count
        os.fsync(fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != len(data)):
            raise PreflightError("bundle_archive_digest_mismatch")
    except BaseException:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    os.close(fd)
    try:
        read_fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(read_fd)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size != len(data)
                or _digest(os.read(read_fd, len(data) + 1)) != manifest["archiveSha256"]):
            raise PreflightError("bundle_archive_digest_mismatch")
        os.lseek(read_fd, 0, os.SEEK_SET)
        return read_fd
    except BaseException:
        if "read_fd" in locals():
            os.close(read_fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def _source_hashes(manifest):
    records = manifest.get("members")
    if (type(records) is not list or len(records) != len(staging.MEMBERS)
            or [item.get("path") for item in records if type(item) is dict] != list(staging.MEMBERS)):
        raise PreflightError("invalid_bundle_manifest")
    hashes = {}
    for item in records:
        if (set(item) != {"path", "bytes", "sha256"}
                or type(item["bytes"]) is not int or item["bytes"] < 0
                or not isinstance(item["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise PreflightError("invalid_bundle_manifest")
        hashes[item["path"]] = item["sha256"]
    return hashes


def _validate_receipt(stdout, bundle):
    try:
        receipt = json.loads(stdout.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        raise PreflightError("invalid_receiver_receipt") from None
    manifest = bundle["manifest"]
    hashes = _source_hashes(manifest)
    expected = {
        "status": "inputs-received", "qualified": False,
        "archiveSha256": manifest["archiveSha256"],
        "manifestSha256": manifest["manifestSha256"],
        "memberCount": manifest["memberCount"], "totalBytes": manifest["totalBytes"],
        "members": manifest["members"],
    }
    if type(receipt) is not dict or set(receipt) != set(expected) | {"root"}:
        raise PreflightError("invalid_receiver_receipt_shape")
    root = receipt.get("root")
    if not isinstance(root, str) or not GUEST_ROOT.fullmatch(root):
        raise PreflightError("invalid_guest_root")
    if any(receipt.get(key) != value for key, value in expected.items()):
        raise PreflightError("receiver_receipt_mismatch")
    if receipt.get("qualified") is not False:
        raise PreflightError("receiver_qualified_state_invalid")
    return root, hashes


def _validate_import_receipt(stdout, stderr):
    if stderr:
        raise PreflightError("import_smoke_stderr_unexpected")
    try:
        receipt = json.loads(stdout.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError):
        raise PreflightError("invalid_import_receipt") from None
    expected = {"kind", "status", "qualified", "pythonVersion", "pythonExecutable"}
    if type(receipt) is not dict or set(receipt) != expected:
        raise PreflightError("invalid_import_receipt_shape")
    if (receipt["kind"] != IMPORT_KIND or receipt["status"] != "passed"
            or receipt["qualified"] is not False):
        raise PreflightError("invalid_import_receipt_state")
    version = receipt["pythonVersion"]
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version) if isinstance(version, str) else None
    if match is None or tuple(map(int, match.groups())) < (3, 13, 0):
        raise PreflightError("import_python_version_unqualified")
    executable = receipt["pythonExecutable"]
    if (not isinstance(executable, str) or not executable.startswith("/opt/homebrew/")
            or posixpath.normpath(executable) != executable
            or not re.fullmatch(r"/opt/homebrew/.+/bin/python3(?:\.\d+)?", executable)):
        raise PreflightError("import_python_executable_unqualified")
    return receipt


def _fixed_import_command(tart, vm, root):
    fixed_env = [key + "=" + value for key, value in IMPORT_ENV.items()]
    return [str(tart), "exec", vm, "/usr/bin/sudo", "-n", "-u", "admin", "-g", "staff",
            "--", "/usr/bin/env", "-i", *fixed_env,
            "/opt/homebrew/bin/python3", "-I", "-B", "-c", IMPORT_CODE, root]


def collect(tart, vm, env, evidence, bundle=None, run_bounded=None, cancel_check=None):
    """Collect a receipt-only preflight using the fixed Tart commands and bounded runner."""
    bundle = build_bundle() if bundle is None else bundle
    runner = canary._run_bounded if run_bounded is None else run_bounded
    manifest = bundle.get("manifest") if type(bundle) is dict else None
    if type(manifest) is not dict or manifest.get("qualified") is not False:
        raise PreflightError("invalid_bundle_manifest")
    _source_hashes(manifest)
    evidence_dir = Path(evidence)
    archive_path = _safe_evidence_path(evidence_dir, "native-workspace-stage-inputs.tar.gz")
    receiver_stdout, receiver_stderr, import_stdout, import_stderr = (
        _safe_evidence_path(evidence_dir, name) for name in LOG_NAMES
    )
    archive_fd = _write_archive(archive_path, bundle)
    try:
        receiver_argv = staging.command_template(tart, vm, manifest)
        stdout, stderr = runner(receiver_argv, timeout=COMMAND_TIMEOUT, env=env,
                                output_limit=MAX_OUTPUT_BYTES, input_fd=archive_fd,
                                capture_paths=(receiver_stdout, receiver_stderr),
                                cancel_check=cancel_check)
        root, received_hashes = _validate_receipt(stdout, bundle)
        import_argv = _fixed_import_command(tart, vm, root)
        import_out, import_err = runner(import_argv, timeout=COMMAND_TIMEOUT,
                                        env=env, output_limit=MAX_OUTPUT_BYTES,
                                        capture_paths=(import_stdout, import_stderr),
                                        cancel_check=cancel_check)
        import_receipt = _validate_import_receipt(import_out, import_err)
        return {
            "kind": KIND, "status": "passed", "qualified": False,
            "archiveSha256": manifest["archiveSha256"],
            "manifestSha256": manifest["manifestSha256"],
            "sourceSha256": received_hashes,
            "guestRoot": root,
            "importSmoke": {**import_receipt, "stdoutEvidence": str(import_stdout),
                            "stderrEvidence": str(import_stderr),
                            "stdoutSha256": _digest(import_out),
                            "stderrSha256": _digest(import_err)},
            "hostCommandTemplates": [receiver_argv, import_argv],
        }
    finally:
        os.close(archive_fd)

