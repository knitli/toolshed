"""Fixed, guest-only SCPreferences API qualification; no host or VM control."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import tempfile

import qualify_offline_macos_vm as canary
import softnet_preferences
import softnet_recovery as recovery
from softnet_preferences import Preferences

REPORT_KIND = "scpreferences-guest-api-qualification-v1"
CHECKS = ("environmentSupported", "captureCompleted", "targetWriteAppliedSynchronized",
          "freshTargetReadback", "lockContentionRejected", "restoreCompleted",
          "freshOriginalReadback", "restoredMarkerVerified")
LOCK_PROBE = """import sys
sys.path.insert(0, sys.argv[1])
from softnet_preferences import Preferences, PreferencesError
try:
    with Preferences():
        pass
except PreferencesError as error:
    raise SystemExit(0 if str(error).startswith('preferences_lock_failed:3002:') else 2)
raise SystemExit(1)
"""


def _supported_environment():
    return (os.geteuid() == 0 and sys.platform == "darwin"
            and platform.mac_ver()[0].split(".", 1)[0] == "15"
            and platform.machine() == "arm64")


def _source_hashes():
    return {
        "guestApi": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "offlineCanary": hashlib.sha256(Path(canary.__file__).read_bytes()).hexdigest(),
        "softnetPreferences": hashlib.sha256(Path(softnet_preferences.__file__).read_bytes()).hexdigest(),
        "softnetRecovery": hashlib.sha256(Path(recovery.__file__).read_bytes()).hexdigest(),
    }


def _probe_nonwaiting_lock():
    """Use a separate bounded process to prove the SC lock is globally held."""
    try:
        stdout, stderr = canary._run_bounded(
            [sys.executable, "-I", "-c", LOCK_PROBE,
             str(Path(softnet_preferences.__file__).resolve().parent)],
            timeout=10, env={"PATH": os.defpath, "LC_ALL": "C", "LANG": "C"},
            output_limit=1024)
    except (OSError, canary.CanaryError):
        return False
    return not stdout and not stderr


def _verify_restoration(report, directory, before):
    recovery.restore(directory, preferences_factory=Preferences)
    report["checks"]["restoreCompleted"] = True
    with Preferences() as preferences:
        report["checks"]["freshOriginalReadback"] = preferences.equal(
            preferences.read(), before)
    fd = recovery._directory(directory)
    try:
        report["checks"]["restoredMarkerVerified"] = (
            recovery._read(fd, "restored") == b"restored\n")
    finally:
        os.close(fd)


def qualify_guest_apis():
    """Exercise only fixed Softnet preference capture, typed write, and restore APIs."""
    report = {
        "kind": REPORT_KIND,
        "status": "failed",
        "apiQualified": False,
        "effectiveDaemonQualified": False,
        "failureCode": None,
        "checks": {name: False for name in CHECKS},
        "savedValuePresent": None,
        "sourceSha256": _source_hashes(),
        "journalDirectory": None,
    }
    if not _supported_environment():
        report["failureCode"] = "unsupported_environment"
        return report
    report["checks"]["environmentSupported"] = True

    directory = None
    capture_completed = False
    before = None
    operation_failed = False
    stage = "journal_create"
    try:
        directory = Path(tempfile.mkdtemp(prefix="softnet-scpreferences-api-", dir="/private/tmp"))
        report["journalDirectory"] = str(directory)
        os.chmod(directory, 0o700)
        stage = "capture"
        recovery.capture(directory, preferences_factory=Preferences)
        capture_completed = True
        report["checks"]["captureCompleted"] = True

        fd = recovery._directory(directory)
        try:
            stage = "target_write"
            with Preferences() as preferences:
                before, snapshot_target = recovery._snapshot(fd, preferences)
                target = preferences.encode_target()
                if not preferences.equal(snapshot_target, target):
                    raise softnet_preferences.PreferencesError("target_mismatch")
                report["savedValuePresent"] = before is not None
                preferences.write(target)
                preferences.commit_apply()
                preferences.synchronize()
                report["checks"]["targetWriteAppliedSynchronized"] = True
        finally:
            os.close(fd)

        stage = "target_readback"
        with Preferences() as preferences:
            report["checks"]["freshTargetReadback"] = preferences.equal(
                preferences.read(), preferences.encode_target())
        if not report["checks"]["freshTargetReadback"]:
            raise softnet_preferences.PreferencesError("target_readback_mismatch")

        stage = "lock_contention"
        with Preferences():
            report["checks"]["lockContentionRejected"] = _probe_nonwaiting_lock()
        if not report["checks"]["lockContentionRejected"]:
            raise softnet_preferences.PreferencesError("lock_contention_not_rejected")

        stage = "restore_and_readback"
        _verify_restoration(report, directory, before)
    except BaseException:
        operation_failed = True
        report["failureCode"] = stage
        report["apiQualified"] = False
        if capture_completed:
            try:
                _verify_restoration(report, directory, before)
            except BaseException:
                pass

    report["apiQualified"] = (
        not operation_failed and all(report["checks"][name] for name in CHECKS))
    if report["apiQualified"]:
        report["status"] = "passed"
    elif report["failureCode"] is None:
        report["failureCode"] = "check_failed"
    return report


def main(argv=None):
    """Emit one fixed JSON report after validating command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    report = qualify_guest_apis()
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
