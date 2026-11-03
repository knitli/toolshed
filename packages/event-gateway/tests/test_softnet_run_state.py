"""Offline tests for fail-closed Softnet run admission state."""

import hashlib
import ipaddress
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import sys
import tempfile
import time
from contextlib import redirect_stdout
from types import SimpleNamespace
from urllib.parse import urlsplit
import unittest
from unittest.mock import Mock, patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import qualify_offline_macos_vm as canary  # noqa: E402 -- Script modules load from their local directory.
import qualify_softnet_macos_vm as controller  # noqa: E402 -- Script modules load from their local directory.
import softnet_public_probe_guest as probe_guest  # noqa: E402 -- Script modules load from their local directory.
import softnet_recovery as recovery  # noqa: E402 -- Script modules load from their local directory.
import softnet_run_state as run_state  # noqa: E402 -- Script modules load from their local directory.
import native_workspace_provisioning_downloads as provisioning_downloads  # noqa: E402
import native_workspace_provisioning_guest as provisioning_guest  # noqa: E402


class SoftnetRunStateTests(unittest.TestCase):
    """Check state admission and record validation using private local fixtures."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(
            prefix="softnet-state-test-", dir=str(Path(tempfile.gettempdir()).resolve()))
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / "state"
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)
        self.owner_uid_patch = patch.object(recovery, "OWNER_UID", os.getuid())
        self.euid_patch = patch.object(recovery.os, "geteuid", return_value=os.getuid())
        self.owner_uid_patch.start()
        self.euid_patch.start()
        self.addCleanup(self.euid_patch.stop)
        self.addCleanup(self.owner_uid_patch.stop)
        self.identity = {
            "vmName": "softnet-test-vm",
            "macAddress": "02:00:00:00:00:01",
            "tartBinarySha256": canary.TART_BINARY_SHA256,
            "softnetBinarySha256": "a" * 64,
            "admissionSha256": "b" * 64,
        }

    def _run_with_recovery_records(self, state):
        run, run_id = state.begin(self.identity)
        fd = recovery._directory(run)
        try:
            reserved = recovery._file(fd, "reserved", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            os.close(reserved)
            recovery._publish(fd, "snapshot.plist", plistlib.dumps(
                {"version": 1, "present": False, "before": b"", "target": b"bplist00"},
                fmt=plistlib.FMT_BINARY))
            recovery._publish(fd, "restored", b"restored\n")
            recovery._publish(fd, "launch.plist", plistlib.dumps(
                {"vmName": self.identity["vmName"], "macAddress": self.identity["macAddress"]},
                fmt=plistlib.FMT_BINARY))
            recovery._publish(fd, "stop.plist", plistlib.dumps(
                self._stop_evidence(), fmt=plistlib.FMT_BINARY))
        finally:
            os.close(fd)
        for name in ("helper-logs", "vm-logs"):
            log_dir = run / name
            log_dir.mkdir(mode=0o700)
            log_fd = recovery._directory(log_dir)
            try:
                for filename in run_state.LOG_FILES:
                    handle = recovery._file(log_fd, filename,
                                            os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                    os.close(handle)
            finally:
                os.close(log_fd)
        return run, run_id

    @staticmethod
    def _stop_evidence():
        return {"vmReaped": True, "helperReaped": True, "vmStopped": True}

    @staticmethod
    def _probe_report(destination="104.20.0.1"):
        now = time.time_ns()
        return {
            "kind": "native-guest-public-probe-v1", "method": "GET",
            "host": run_state.PUBLIC_PROBE_HOST, "path": run_state.PUBLIC_PROBE_PATH,
            "destinationIPv4": destination, "port": 443,
            "startedAtUnixNs": now, "finishedAtUnixNs": now,
            "tlsVerified": True, "gatewayContextVerified": True,
            "expectedHostPosturePassed": True, "status": 200, "bodyBytes": 16,
            "bodySha256": run_state.PUBLIC_PROBE_BODY_SHA256,
            "verified": True, "error": "",
        }

    @staticmethod
    def _route_report(identity="104.20.0.1", positive="104.20.0.2", roots="f" * 64):
        now = time.time_ns()
        return {
            "kind": "native-guest-route-contract-v1",
            "identityHost": run_state.PUBLIC_PROBE_HOST, "identityPath": run_state.PUBLIC_PROBE_PATH,
            "identityDestinationIPv4": identity, "identityStatus": 404,
            "identityTlsVerified": True, "identityBodyBytes": 0,
            "identityBodySha256": hashlib.sha256(b"").hexdigest(),
            "identityNoStore": True, "identityNoGatewayMarkers": True, "identityError": "",
            "positiveHost": run_state.ROUTE_POSITIVE_HOST,
            "positivePath": run_state.ROUTE_POSITIVE_PATH,
            "positiveDestinationIPv4": positive, "positiveStatus": 200,
            "positiveTlsVerified": True, "positiveContentType": run_state.ROUTE_POSITIVE_CONTENT_TYPE,
            "positiveBodyBytes": run_state.ROUTE_POSITIVE_BODY_BYTES,
            "positiveBodySha256": run_state.ROUTE_POSITIVE_BODY_SHA256, "positiveError": "",
            "publicTrustRootsSha256": roots, "gatewayCaAbsent": True,
            "startedAtUnixNs": now, "finishedAtUnixNs": now, "verified": True, "error": "",
        }

    @staticmethod
    def _provisioning_identity():
        manifest_raw = (provisioning_downloads.ROOT / provisioning_downloads.MANIFEST).read_bytes()
        manifest = provisioning_downloads._json_no_duplicates(manifest_raw)
        hosts = {urlsplit(asset["url"]).hostname for asset in manifest["assets"]}
        hosts.update(rule["host"] for asset in manifest["assets"]
                     for rule in asset["redirects"])
        addresses = iter(("1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222",
                          "185.199.108.154"))
        return {
            "vmName": "softnet-provisioning-test-vm",
            "macAddress": "02:00:00:00:00:02",
            "tartBinarySha256": canary.TART_BINARY_SHA256,
            "softnetBinarySha256": "a" * 64,
            "admissionSha256": "b" * 64,
            "provisioningBundleSha256": "c" * 64,
            "provisioningCaSha256": "d" * 64,
            "provisioningDnsMap": {host: [next(addresses)] for host in sorted(hosts)},
            "provisioningManifest": manifest_raw,
        }

    @staticmethod
    def _retained_provisioning_identity():
        identity = SoftnetRunStateTests._provisioning_identity()
        manifest = provisioning_downloads._json_no_duplicates(identity["provisioningManifest"])
        for asset in manifest["assets"]:
            asset["redirects"] = [rule for rule in asset["redirects"]
                                  if rule["host"] != provisioning_downloads.GHCR_REDIRECT_HOST]
        raw = provisioning_downloads._canonical_manifest_bytes(manifest)
        if hashlib.sha256(raw).hexdigest() != provisioning_guest.RETAINED_MANIFEST_SHA256:
            raise AssertionError("legacy manifest fixture no longer has its reviewed digest")
        hosts = {urlsplit(asset["url"]).hostname for asset in manifest["assets"]}
        hosts.update(rule["host"] for asset in manifest["assets"] for rule in asset["redirects"])
        identity["provisioningDnsMap"] = {
            host: addresses for host, addresses in identity["provisioningDnsMap"].items()
            if host in hosts
        }
        identity["provisioningManifest"] = raw
        return identity

    @staticmethod
    def _provisioning_result(identity, *, allow_retained_manifest=False):
        manifest, dns = provisioning_guest.validate_binding(
            manifest_bytes=identity["provisioningManifest"],
            dns_map=identity["provisioningDnsMap"],
            ca_sha256=identity["provisioningCaSha256"],
            bundle_sha256=identity["provisioningBundleSha256"],
            allow_retained_manifest=allow_retained_manifest)
        assets = []
        for asset in manifest["assets"]:
            parsed = provisioning_downloads._validate_url(asset["url"])
            assets.append({
                "name": asset["name"], "initialUrl": asset["url"],
                "finalHost": parsed.hostname, "finalPath": parsed.path or "/",
                "selectedIPv4": dns[parsed.hostname][0], "status": 200,
                "redirectCount": 0, "outcome": "downloaded", "bytes": 1,
                "sha256": asset["sha256"],
            })
        return {
            "kind": provisioning_guest.RESULT_KIND, "qualified": False, "prepared": False,
            "guestRoot": "/Users/admin/.knitli-native-provisioning-a1b2c3d4",
            "bundleSha256": identity["provisioningBundleSha256"],
            "downloadReceipt": {
                "kind": provisioning_downloads.KIND, "status": "downloaded-only",
                "qualified": False, "prepared": False,
                "manifestSha256": provisioning_downloads.MANIFEST_SHA256,
                "caBundleSha256": identity["provisioningCaSha256"],
                "dnsMap": dns, "totalBytes": len(assets), "assets": assets,
            },
        }

    @staticmethod
    def _command_failure_record(**overrides):
        record = {
            "kind": "softnet-command-failure-v1", "phase": "provisioning-command",
            "errorType": "ProvisioningError", "errorCode": "command_failed",
            "stdoutTail": b"out", "stderrTail": b"err",
            "stdoutObservedBytes": 3, "stderrObservedBytes": 3, "exitCode": 1,
        }
        return {**record, **overrides}

    def test_command_failure_record_is_valid_only_on_incomplete_provisioning_run(self):
        identity = self._provisioning_identity()
        run, run_id = self._failed_restored_run(identity)
        raw = plistlib.dumps(self._command_failure_record(), fmt=plistlib.FMT_BINARY)
        self._rewrite(run / "command-failure.plist", raw)
        self.assertFalse(run_state._check_run_directory(self.root, run_id))
        self.assertEqual(run_state._failed_restored_files(self.root, run_id)[
            "command-failure.plist"], hashlib.sha256(raw).hexdigest())

        for bad in (
            self._command_failure_record(kind="other"),
            self._command_failure_record(phase="unknown"),
            self._command_failure_record(phase=[]),
            self._command_failure_record(errorType="bad type"),
            self._command_failure_record(errorCode="UPPER"),
            self._command_failure_record(stdoutTail=b"x" * 4097,
                                         stdoutObservedBytes=4097),
            self._command_failure_record(stdoutObservedBytes=2),
            self._command_failure_record(stdoutObservedBytes=True),
            self._command_failure_record(stderrObservedBytes=16 * 1024 * 1024 + 4097),
            self._command_failure_record(exitCode=0),
            self._command_failure_record(exitCode=True),
            {**self._command_failure_record(), "argv": ["secret"]},
        ):
            self._rewrite(run / "command-failure.plist",
                          plistlib.dumps(bad, fmt=plistlib.FMT_BINARY))
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_command_failure"):
                with run_state.State(self.root):
                    self.fail("invalid command failure record accepted")

        self._rewrite(run / "command-failure.plist", b"x" * (run_state.MAX_COMMAND_FAILURE_BYTES + 1))
        with self.assertRaisesRegex(recovery.RecoveryError, "oversized_command_failure"):
            run_state._check_run_directory(self.root, run_id)

        with tempfile.TemporaryDirectory(prefix="softnet-mode-test-",
                                         dir=str(Path(tempfile.gettempdir()).resolve())) as directory:
            mode_root = Path(directory) / "state"
            mode_root.mkdir(mode=0o700)
            mode_root.chmod(0o700)
            with run_state.State(mode_root) as state:
                ordinary_run, ordinary_id = self._run_with_recovery_records(state)
                self._rewrite(ordinary_run / "command-failure.plist", raw)
                with self.assertRaisesRegex(recovery.RecoveryError,
                                            "invalid_command_failure_mode"):
                    run_state._check_run_directory(mode_root, ordinary_id)

    def test_command_failure_tail_validation_tracks_canary_cap(self):
        identity = self._provisioning_identity()
        run, _ = self._failed_restored_run(identity)
        fd = recovery._directory(run)
        try:
            with patch.object(canary, "COMMAND_FAILURE_TAIL_BYTES", 2):
                valid = self._command_failure_record(
                    stdoutTail=b"ok", stdoutObservedBytes=2, stderrTail=b"x", stderrObservedBytes=1)
                self._rewrite(run / "command-failure.plist",
                              plistlib.dumps(valid, fmt=plistlib.FMT_BINARY))
                self.assertEqual(run_state._check_command_failure(fd)[1]["stdoutTail"], b"ok")

                over_limit = self._command_failure_record(stdoutTail=b"bad", stdoutObservedBytes=3)
                self._rewrite(run / "command-failure.plist",
                              plistlib.dumps(over_limit, fmt=plistlib.FMT_BINARY))
                with self.assertRaisesRegex(recovery.RecoveryError, "invalid_command_failure"):
                    run_state._check_command_failure(fd)
        finally:
            os.close(fd)

    def test_command_failure_record_is_hashed_by_disposition_and_cannot_complete(self):
        identity = self._provisioning_identity()
        run, run_id = self._failed_restored_run(identity)
        raw = plistlib.dumps(self._command_failure_record(), fmt=plistlib.FMT_BINARY)
        self._rewrite(run / "command-failure.plist", raw)
        with tempfile.TemporaryDirectory(prefix="softnet-complete-test-",
                                         dir=str(Path(tempfile.gettempdir()).resolve())) as directory:
            complete_root = Path(directory) / "state"
            complete_root.mkdir(mode=0o700)
            complete_root.chmod(0o700)
            with run_state.State(complete_root) as state:
                complete_run, _ = state.begin(identity)
                self._rewrite(complete_run / "command-failure.plist", raw)
                with self.assertRaisesRegex(recovery.RecoveryError,
                                            "invalid_command_failure_completion"):
                    state.complete(complete_run, self._stop_evidence())
        run_state.dispose_failed_restored(
            self.root, run_id, "failure ticket", expected_vm_reaped=False,
            observe=lambda *_: self._observation())
        disposition = plistlib.loads((run / "disposition.plist").read_bytes())
        self.assertEqual(disposition["fileSha256"]["command-failure.plist"],
                         hashlib.sha256(raw).hexdigest())
        changed = dict(self._command_failure_record(), stderrTail=b"changed",
                       stderrObservedBytes=7)
        self._rewrite(run / "command-failure.plist",
                      plistlib.dumps(changed, fmt=plistlib.FMT_BINARY))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_disposition"):
            with run_state.State(self.root):
                self.fail("changed command failure record accepted")


    @staticmethod
    def _route_timeout_report(duration_ns):
        """Return a valid positive-leg timeout receipt with controlled elapsed time."""
        report = SoftnetRunStateTests._route_report()
        empty_hash = hashlib.sha256(b"").hexdigest()
        report.update({
            "positiveStatus": 0, "positiveTlsVerified": False, "positiveContentType": "",
            "positiveBodyBytes": 0, "positiveBodySha256": empty_hash,
            "positiveError": "timeout", "finishedAtUnixNs": (
                report["startedAtUnixNs"] + duration_ns),
            "verified": False, "error": "timeout",
        })
        return report

    @staticmethod
    def _cli_report_too_large(identity, positive, roots):
        """Run the actual guest CLI through route overflow and validate its receipt."""
        empty_hash = hashlib.sha256(b"").hexdigest()
        positive_leg = {
            "status": 200, "tlsVerified": True,
            "bodyBytes": run_state.ROUTE_POSITIVE_BODY_BYTES,
            "bodySha256": run_state.ROUTE_POSITIVE_BODY_SHA256,
            "contentType": run_state.ROUTE_POSITIVE_CONTENT_TYPE,
            "noStore": False, "noGatewayMarkers": False, "error": "",
        }
        identity_leg = {
            "status": 404, "tlsVerified": True, "bodyBytes": 0,
            "bodySha256": empty_hash, "contentType": "", "noStore": True,
            "noGatewayMarkers": True, "error": "",
        }
        output = io.StringIO()
        with patch.object(probe_guest, "_public_context",
                          return_value=(object(), roots, True)), \
             patch.object(probe_guest, "_route_request",
                          side_effect=[(positive_leg, b"x" * run_state.ROUTE_POSITIVE_BODY_BYTES),
                                       (identity_leg, b"")]), \
             patch.object(probe_guest, "ROUTE_MAX_REPORT", 1), \
             redirect_stdout(output):
            probe_guest.main(["--guest-route-contract", identity, positive, roots])
        receipt = output.getvalue().encode("utf-8")
        report = controller._validate_guest_route_report(receipt, identity, positive, roots)
        return receipt, report

    @classmethod
    def _route_preflight_report(cls, error="trust_roots_mismatch"):
        empty_hash = hashlib.sha256(b"").hexdigest()
        report = cls._route_report()
        report.update({
            "identityStatus": 0, "identityTlsVerified": False, "identityBodyBytes": 0,
            "identityBodySha256": empty_hash, "identityNoStore": False,
            "identityNoGatewayMarkers": False, "identityError": error,
            "positiveStatus": 0, "positiveTlsVerified": False,
            "positiveContentType": "", "positiveBodyBytes": 0,
            "positiveBodySha256": empty_hash, "positiveError": error,
            "publicTrustRootsSha256": "", "gatewayCaAbsent": False,
            "verified": False, "error": error,
        })
        return report

    def _completed_run(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            state.complete(run, self._stop_evidence())
        return run

    def _failed_restored_run(self, identity=None):
        with run_state.State(self.root) as state:
            original = self.identity
            if identity is not None:
                self.identity = identity
            try:
                run, run_id = self._run_with_recovery_records(state)
            finally:
                self.identity = original
        self._rewrite(run / "stop.plist", plistlib.dumps(
            {"vmReaped": False, "helperReaped": True, "vmStopped": True},
            fmt=plistlib.FMT_BINARY))
        return run, run_id

    @staticmethod
    def _observation():
        return {"observedAtUnixNs": time.time_ns(), "vmStopped": True,
                "processesQuiet": True, "preferencesOriginal": True}

    @staticmethod
    def _rewrite(path, data):
        path.write_bytes(data)
        path.chmod(0o600)

    def test_begin_publishes_identity_in_a_retained_uuid_run_and_keeps_lock_file(self):
        with run_state.State(self.root) as state:
            run, run_id = state.begin(self.identity)
            self.assertRegex(run_id, r"\A[0-9a-f]{32}\Z")
            record = plistlib.loads((run / "identity.plist").read_bytes())
            self.assertEqual(record, {
                "kind": run_state.STATE_KIND,
                "version": 1,
                "runId": run_id,
                "identity": self.identity,
            })
            self.assertEqual((run.stat().st_mode & 0o777), 0o700)
        self.assertEqual((self.root / "controller.lock").stat().st_mode & 0o777, 0o600)
        self.assertTrue((self.root / "controller.lock").exists())

    def test_unfinished_run_blocks_next_admission(self):
        with run_state.State(self.root) as state:
            run, _ = state.begin(self.identity)
            self.assertTrue(run.exists())
        with self.assertRaisesRegex(recovery.RecoveryError, "unresolved_run"):
            with run_state.State(self.root):
                self.fail("unfinished run admitted")

    def test_probe_identity_requires_ipv4_text_not_integer_address(self):
        self.identity["probeIPv4"] = int(ipaddress.IPv4Address("104.20.0.1"))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_identity"):
            run_state._identity_record("a" * 32, self.identity)

    def test_complete_requires_all_stop_proofs(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_stop_evidence"):
                state.complete(run, {"vmReaped": True, "helperReaped": True, "vmStopped": False})

    def test_complete_requires_snapshot_record(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            (run / "snapshot.plist").unlink()
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_run_entries"):
                state.complete(run, self._stop_evidence())

    def test_complete_requires_stop_record(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            (run / "stop.plist").unlink()
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_run_entries"):
                state.complete(run, self._stop_evidence())

    def test_completion_is_bound_to_active_run_and_published_immutably(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_active_run"):
                state.complete(run.parent / "other", {
                    "vmReaped": True, "helperReaped": True, "vmStopped": True})
            evidence = self._stop_evidence()
            state.complete(run, evidence)
            complete = plistlib.loads((run / "complete.plist").read_bytes())
            self.assertEqual(complete["stopEvidence"], evidence)
            with self.assertRaisesRegex(recovery.RecoveryError, "state_not_ready"):
                state.complete(run, evidence)
        with run_state.State(self.root):
            pass

    def test_probe_completion_requires_and_binds_fixed_report(self):
        self.identity["probeIPv4"] = "104.20.0.1"
        # A valid "0" posture is an observed distinct host identity, not a failed network probe.
        report_bytes = plistlib.dumps({**self._probe_report(),
                                       "expectedHostPosturePassed": False},
                                      fmt=plistlib.FMT_BINARY)
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            try:
                recovery._publish(fd, "probe.plist", report_bytes)
            finally:
                os.close(fd)
            state.complete(run, self._stop_evidence())
        complete = plistlib.loads((run / "complete.plist").read_bytes())
        self.assertEqual(complete["probeSha256"], hashlib.sha256(report_bytes).hexdigest())
        with run_state.State(self.root):
            pass
        self._rewrite(run / "probe.plist", plistlib.dumps(
            {**self._probe_report(), "destinationIPv4": "104.20.0.2"},
            fmt=plistlib.FMT_BINARY))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_probe"):
            with run_state.State(self.root):
                self.fail("changed probe receipt accepted")

    def test_probe_completion_without_receipt_fails_closed(self):
        self.identity["probeIPv4"] = "104.20.0.1"
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_run_entries"):
                state.complete(run, self._stop_evidence())

    def test_provisioning_identity_uses_pinned_manifest_and_exact_dns_binding(self):
        identity = self._provisioning_identity()
        run_state._identity_record("a" * 32, identity)
        changed = dict(identity, provisioningManifest=identity["provisioningManifest"] + b" ")
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_identity"):
            run_state._identity_record("a" * 32, changed)
        changed = dict(identity, provisioningBundleSha256="E" * 64)
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_identity"):
            run_state._identity_record("a" * 32, changed)
        changed = dict(identity, provisioningCaSha256="not-a-digest")
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_identity"):
            run_state._identity_record("a" * 32, changed)
        bad_dns = dict(identity["provisioningDnsMap"])
        bad_dns.pop(next(iter(bad_dns)))
        changed = dict(identity, provisioningDnsMap=bad_dns)
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_identity"):
            run_state._identity_record("a" * 32, changed)
        result = self._provisioning_result(identity)
        changed = dict(identity, provisioningDnsMap=dict(identity["provisioningDnsMap"]))
        first_host = next(iter(changed["provisioningDnsMap"]))
        changed["provisioningDnsMap"][first_host] = ["1.0.0.1"]
        with self.assertRaises(ValueError):
            provisioning_guest.validate_result(
                result, manifest_bytes=changed["provisioningManifest"],
                dns_map=changed["provisioningDnsMap"],
                ca_sha256=changed["provisioningCaSha256"],
                bundle_sha256=changed["provisioningBundleSha256"])
        bad_dns = dict(identity["provisioningDnsMap"])
        first_host = next(iter(bad_dns))
        bad_dns[first_host] = ["192.0.2.1"]
        changed = dict(identity, provisioningDnsMap=bad_dns)
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_identity"):
            run_state._identity_record("a" * 32, changed)

    def test_retained_manifest_is_read_only_compatibility_for_known_history(self):
        identity = self._retained_provisioning_identity()
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_identity"):
            run_state._identity_record("a" * 32, identity)
        with run_state.State(self.root) as state:
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_identity"):
                state.begin(identity)
        run_state._identity_record("a" * 32, identity, allow_retained_manifest=True)
        result = self._provisioning_result(identity, allow_retained_manifest=True)
        result["guestRoot"] = "/private/tmp/knitli-native-provisioning-a1b2c3d4"
        result["downloadReceipt"]["manifestSha256"] = provisioning_guest.RETAINED_MANIFEST_SHA256
        self.assertEqual(provisioning_guest.validate_result(
            result, manifest_bytes=identity["provisioningManifest"],
            dns_map=identity["provisioningDnsMap"], ca_sha256=identity["provisioningCaSha256"],
            bundle_sha256=identity["provisioningBundleSha256"],
            allow_retained_manifest=True), result)
        with self.assertRaisesRegex(ValueError, "manifest_binding_mismatch"):
            provisioning_guest.validate_result(
                result, manifest_bytes=identity["provisioningManifest"],
                dns_map=identity["provisioningDnsMap"], ca_sha256=identity["provisioningCaSha256"],
                bundle_sha256=identity["provisioningBundleSha256"])
        changed = dict(identity, provisioningManifest=identity["provisioningManifest"] + b" ")
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_identity"):
            run_state._identity_record("a" * 32, changed, allow_retained_manifest=True)
        bad_dns = dict(identity["provisioningDnsMap"])
        bad_dns[next(iter(bad_dns))] = ["192.0.2.1"]
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_identity"):
            run_state._identity_record("a" * 32,
                dict(identity, provisioningDnsMap=bad_dns), allow_retained_manifest=True)
        with run_state.State(self.root) as state:
            run, run_id = state.begin(self._provisioning_identity())
        self._rewrite(run / "identity.plist", plistlib.dumps(
            run_state._identity_record(run_id, identity, allow_retained_manifest=True),
            fmt=plistlib.FMT_BINARY, sort_keys=True))
        with self.assertRaisesRegex(recovery.RecoveryError, "unresolved_run"):
            with run_state.State(self.root):
                self.fail("unresolved retained historical run was admitted")

    def test_provisioning_download_completion_validates_receipt_and_binds_hash(self):
        self.identity = self._provisioning_identity()
        result = self._provisioning_result(self.identity)
        receipt = json.dumps(result, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            try:
                recovery._publish(fd, "provisioning-download.json", receipt)
            finally:
                os.close(fd)
            state.complete(run, self._stop_evidence())
        complete = plistlib.loads((run / "complete.plist").read_bytes())
        self.assertEqual(complete["provisioningDownloadSha256"], hashlib.sha256(receipt).hexdigest())
        with run_state.State(self.root):
            pass
        altered = dict(result, prepared=True)
        self._rewrite(run / "provisioning-download.json",
                      json.dumps(altered, sort_keys=True, separators=(",", ":")).encode())
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_provisioning_download"):
            with run_state.State(self.root):
                self.fail("prepared provisioning result accepted")

    def test_completed_retained_manifest_receipt_survives_root_scan(self):
        self.identity = self._provisioning_identity()
        result = self._provisioning_result(self.identity)
        receipt_bytes = json.dumps(result, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        with run_state.State(self.root) as state:
            run, run_id = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            try:
                recovery._publish(fd, "provisioning-download.json", receipt_bytes)
            finally:
                os.close(fd)
            state.complete(run, self._stop_evidence())

        identity = self._retained_provisioning_identity()
        identity_record = run_state._identity_record(
            run_id, identity, allow_retained_manifest=True)
        self._rewrite(run / "identity.plist", plistlib.dumps(
            identity_record, fmt=plistlib.FMT_BINARY, sort_keys=True))
        result = self._provisioning_result(identity, allow_retained_manifest=True)
        result["guestRoot"] = "/private/tmp/knitli-native-provisioning-a1b2c3d4"
        result["downloadReceipt"]["manifestSha256"] = provisioning_guest.RETAINED_MANIFEST_SHA256
        receipt_bytes = json.dumps(result, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self._rewrite(run / "provisioning-download.json", receipt_bytes)
        complete = plistlib.loads((run / "complete.plist").read_bytes())
        complete["identitySha256"] = hashlib.sha256((run / "identity.plist").read_bytes()).hexdigest()
        complete["provisioningDownloadSha256"] = hashlib.sha256(receipt_bytes).hexdigest()
        self._rewrite(run / "complete.plist", plistlib.dumps(
            complete, fmt=plistlib.FMT_BINARY, sort_keys=True))
        with run_state.State(self.root):
            pass
        result["qualified"] = True
        corrupted = json.dumps(result, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self._rewrite(run / "provisioning-download.json", corrupted)
        complete["provisioningDownloadSha256"] = hashlib.sha256(corrupted).hexdigest()
        self._rewrite(run / "complete.plist", plistlib.dumps(
            complete, fmt=plistlib.FMT_BINARY, sort_keys=True))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_provisioning_download"):
            with run_state.State(self.root):
                self.fail("corrupt historical provisioning result accepted")

    def test_disposed_retained_manifest_receipt_and_file_hashes_survive_root_scan(self):
        run, run_id = self._failed_restored_run(self._provisioning_identity())
        identity = self._retained_provisioning_identity()
        self._rewrite(run / "identity.plist", plistlib.dumps(
            run_state._identity_record(run_id, identity, allow_retained_manifest=True),
            fmt=plistlib.FMT_BINARY, sort_keys=True))
        result = self._provisioning_result(identity, allow_retained_manifest=True)
        result["downloadReceipt"]["manifestSha256"] = provisioning_guest.RETAINED_MANIFEST_SHA256
        receipt = json.dumps(result, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        self._rewrite(run / "provisioning-download.json", receipt)
        hashes = run_state._failed_restored_files(self.root, run_id, receipt_present=True)
        disposition = {
            "kind": run_state.DISPOSITION_KIND, "version": 1, "runId": run_id,
            "approvalReference": "reviewed historical disposition",
            "observation": self._observation(), "fileSha256": hashes,
        }
        self._rewrite(run / "disposition.plist", plistlib.dumps(
            disposition, fmt=plistlib.FMT_BINARY, sort_keys=True))
        with run_state.State(self.root):
            pass
        hashes["provisioning-download.json"] = "0" * 64
        disposition["fileSha256"] = hashes
        self._rewrite(run / "disposition.plist", plistlib.dumps(
            disposition, fmt=plistlib.FMT_BINARY, sort_keys=True))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_disposition"):
            with run_state.State(self.root):
                self.fail("tampered retained file hash accepted")

    def test_provisioning_download_requires_a_valid_report_to_complete(self):
        self.identity = self._provisioning_identity()
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_run_entries"):
                state.complete(run, self._stop_evidence())

    def test_provisioning_download_rejects_malformed_and_tampered_results(self):
        self.identity = self._provisioning_identity()
        valid = self._provisioning_result(self.identity)
        candidates = [b"not json", json.dumps(dict(valid, qualified=True)).encode()]
        wrong_bundle = dict(valid, bundleSha256="e" * 64)
        candidates.append(json.dumps(wrong_bundle).encode())
        legacy_root = dict(valid, guestRoot="/private/tmp/knitli-native-provisioning-a1b2c3d4")
        candidates.append(json.dumps(legacy_root).encode())
        tampered = json.loads(json.dumps(valid))
        tampered["downloadReceipt"]["assets"][0]["sha256"] = "0" * 64
        candidates.append(json.dumps(tampered).encode())
        for receipt in candidates:
            with self.subTest(receipt=receipt[:30]), run_state.State(self.root) as state:
                run, _ = self._run_with_recovery_records(state)
                fd = recovery._directory(run)
                try:
                    recovery._publish(fd, "provisioning-download.json", receipt)
                finally:
                    os.close(fd)
                with self.assertRaisesRegex(recovery.RecoveryError,
                                           "invalid_provisioning_download"):
                    state.complete(run, self._stop_evidence())
            shutil.rmtree(run)

    def test_startup_failure_without_provisioning_receipt_remains_disposition_eligible(self):
        identity = self._provisioning_identity()
        run, run_id = self._failed_restored_run(identity)
        run_state.dispose_failed_restored(
            self.root, run_id, "startup failed before report", expected_vm_reaped=False,
            observe=lambda *_: self._observation())
        disposition = plistlib.loads((run / "disposition.plist").read_bytes())
        self.assertNotIn("provisioning-download.json", disposition["fileSha256"])
        with run_state.State(self.root):
            pass

    def test_standalone_restored_marker_does_not_complete_a_run(self):
        with run_state.State(self.root) as state:
            self._run_with_recovery_records(state)
        with self.assertRaisesRegex(recovery.RecoveryError, "unresolved_run"):
            with run_state.State(self.root):
                self.fail("standalone restored marker admitted")

    def test_completion_detects_changed_snapshot_and_unknown_root_entries(self):
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            state.complete(run, self._stop_evidence())
        (run / "snapshot.plist").write_bytes(b"changed")
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_completion"):
            with run_state.State(self.root):
                self.fail("changed snapshot accepted")

        (run / "snapshot.plist").write_bytes(b"changed")
        (self.root / "surprise").write_text("x")
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_state_entries"):
            with run_state.State(self.root):
                self.fail("unknown state entry accepted")

    def test_corrupt_identity_blocks_admission(self):
        run = self._completed_run()
        identity_path = run / "identity.plist"
        identity = plistlib.loads(identity_path.read_bytes())
        identity["identity"]["tartBinarySha256"] = "c" * 64
        identity_bytes = plistlib.dumps(identity, fmt=plistlib.FMT_BINARY, sort_keys=True)
        self._rewrite(identity_path, identity_bytes)
        complete_path = run / "complete.plist"
        complete = plistlib.loads(complete_path.read_bytes())
        complete["identitySha256"] = hashlib.sha256(identity_bytes).hexdigest()
        self._rewrite(complete_path, plistlib.dumps(complete, fmt=plistlib.FMT_BINARY, sort_keys=True))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_identity"):
            with run_state.State(self.root):
                self.fail("corrupt identity accepted")

    def test_corrupt_complete_record_blocks_admission(self):
        run = self._completed_run()
        complete = plistlib.loads((run / "complete.plist").read_bytes())
        complete["version"] = 2
        self._rewrite(run / "complete.plist", plistlib.dumps(complete, fmt=plistlib.FMT_BINARY))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_completion"):
            with run_state.State(self.root):
                self.fail("corrupt completion accepted")

    def test_malformed_stop_record_blocks_admission(self):
        run = self._completed_run()
        stop_bytes = b"not a plist"
        self._rewrite(run / "stop.plist", stop_bytes)
        complete = plistlib.loads((run / "complete.plist").read_bytes())
        complete["stopSha256"] = hashlib.sha256(stop_bytes).hexdigest()
        self._rewrite(run / "complete.plist", plistlib.dumps(complete, fmt=plistlib.FMT_BINARY))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_stop"):
            with run_state.State(self.root):
                self.fail("malformed stop evidence accepted")

    def test_stop_record_must_match_completion(self):
        run = self._completed_run()
        self._rewrite(run / "stop.plist", plistlib.dumps(
            self._stop_evidence(), fmt=plistlib.FMT_XML))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_completion"):
            with run_state.State(self.root):
                self.fail("changed stop evidence accepted")

    def test_run_logs_reject_symlinks(self):
        run = self._completed_run()
        log = run / "helper-logs" / "tart-stdout.bin"
        log.unlink()
        target = self.root.parent / "log-target"
        target.write_bytes(b"safe")
        log.symlink_to(target)
        with self.assertRaises(OSError):
            with run_state.State(self.root):
                self.fail("symlinked log accepted")

    def test_run_logs_reject_oversized_files(self):
        run = self._completed_run()
        log = run / "vm-logs" / "tart-stderr.bin"
        log.write_bytes(b"x" * (run_state.MAX_LOG_BYTES + 1))
        log.chmod(0o600)
        with self.assertRaisesRegex(recovery.RecoveryError, "oversized_run_log"):
            with run_state.State(self.root):
                self.fail("oversized log accepted")

    def test_reservation_only_run_without_identity_fails_closed(self):
        with run_state.State(self.root) as state:
            run, _ = state.begin(self.identity)
            (run / "identity.plist").unlink()
            fd = recovery._directory(run)
            reserved = recovery._file(fd, "reserved", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            os.close(reserved)
            os.close(fd)
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_run_entries"):
            with run_state.State(self.root):
                self.fail("reservation without identity accepted")

    def test_reentering_state_rejects_before_opening_more_descriptors(self):
        state = run_state.State(self.root)
        state.__enter__()
        root_fd, lock_fd = state._root_fd, state._lock_fd
        try:
            with patch.object(recovery, "_directory", wraps=recovery._directory) as directory:
                with self.assertRaisesRegex(recovery.RecoveryError, "state_already_entered"):
                    state.__enter__()
                directory.assert_not_called()
            self.assertEqual((state._root_fd, state._lock_fd), (root_fd, lock_fd))
            os.fstat(root_fd)
            os.fstat(lock_fd)
        finally:
            state.__exit__(None, None, None)

    def test_controller_lock_is_nonblocking_and_never_unlinked(self):
        state = run_state.State(self.root)
        state.__enter__()
        try:
            with self.assertRaisesRegex(recovery.RecoveryError, "controller_busy"):
                with run_state.State(self.root):
                    self.fail("concurrent state lock acquired")
        finally:
            state.__exit__(None, None, None)
        self.assertTrue((self.root / "controller.lock").is_file())
        self.assertEqual(os.stat(self.root / "controller.lock").st_nlink, 1)

    def test_failed_restored_disposition_is_immutable_and_admits_future_runs(self):
        run, run_id = self._failed_restored_run()
        before = {name: (run / name).read_bytes() for name in (
            "identity.plist", "reserved", "snapshot.plist", "restored", "launch.plist",
            "stop.plist")}
        observed = self._observation()

        def observe(path, identity):
            self.assertEqual(path, run)
            self.assertEqual(identity, self.identity)
            with self.assertRaisesRegex(recovery.RecoveryError, "controller_busy"):
                with run_state.State(self.root):
                    pass
            return observed

        run_state.dispose_failed_restored(self.root, run_id, "operator ticket 42", expected_vm_reaped=False, observe=observe)
        disposition = plistlib.loads((run / "disposition.plist").read_bytes())
        self.assertEqual(disposition["kind"], run_state.DISPOSITION_KIND)
        self.assertEqual(disposition["runId"], run_id)
        self.assertEqual(disposition["approvalReference"], "operator ticket 42")
        self.assertEqual(disposition["observation"], observed)
        self.assertEqual(set(disposition["fileSha256"]), set(run_state.DISPOSITION_FILES))
        self.assertEqual({name: (run / name).read_bytes() for name in before}, before)
        self.assertFalse((run / "complete.plist").exists())
        self.assertFalse(run_state._check_run_directory(self.root, run_id))
        self.assertFalse(plistlib.loads((run / "stop.plist").read_bytes())["vmReaped"])
        with run_state.State(self.root):
            pass

    def test_timeout_probe_disposition_hashes_receipt_and_reopens(self):
        self.identity["probeIPv4"] = "104.20.0.1"
        with run_state.State(self.root) as state:
            run, run_id = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            probe_report = self._probe_report()
            failed_report = {**probe_report, "finishedAtUnixNs": (
                probe_report["startedAtUnixNs"] + 15_000_763_492),
                "gatewayContextVerified": False, "expectedHostPosturePassed": False,
                "status": 0, "bodyBytes": 0, "bodySha256": hashlib.sha256(b"").hexdigest(),
                "verified": False, "error": "total_timeout"}
            try:
                recovery._publish(fd, "probe.plist", plistlib.dumps(
                    failed_report, fmt=plistlib.FMT_BINARY))
            finally:
                os.close(fd)
        self._rewrite(run / "stop.plist", plistlib.dumps(
            {"vmReaped": False, "helperReaped": True, "vmStopped": True},
            fmt=plistlib.FMT_BINARY))

        run_state.dispose_failed_restored(self.root, run_id, "ticket",
                                          expected_vm_reaped=False, observe=lambda *_: self._observation())
        disposition = plistlib.loads((run / "disposition.plist").read_bytes())
        self.assertEqual(set(disposition["fileSha256"]),
                         set(run_state.DISPOSITION_FILES) | {"probe.plist"})
        self.assertEqual(disposition["fileSha256"]["probe.plist"],
                         hashlib.sha256((run / "probe.plist").read_bytes()).hexdigest())
        with run_state.State(self.root):
            pass

        changed_report = {**failed_report, "status": 502}
        self._rewrite(run / "probe.plist", plistlib.dumps(
            changed_report, fmt=plistlib.FMT_BINARY))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_disposition"):
            with run_state.State(self.root):
                self.fail("changed probe receipt accepted after disposition")

    def test_failed_route_disposition_hashes_receipt_and_binds_both_admitted_ips(self):
        identity = {**self.identity, "identityProbeIPv4": "104.20.0.1",
                    "positiveOriginIPv4": "104.20.0.2", "publicTrustRootsSha256": "f" * 64}
        run, run_id = self._failed_restored_run(identity)
        report = self._route_report()
        report.update({"positiveStatus": 503, "positiveTlsVerified": True,
                       "positiveBodyBytes": 0, "positiveBodySha256": hashlib.sha256(b"").hexdigest(),
                       "verified": False, "error": "predicate_failed"})
        self._rewrite(run / "route-probe.plist", plistlib.dumps(report, fmt=plistlib.FMT_BINARY))
        run_state.dispose_failed_restored(self.root, run_id, "ticket",
                                          expected_vm_reaped=False, observe=lambda *_: self._observation())
        record = plistlib.loads((run / "disposition.plist").read_bytes())
        self.assertIn("route-probe.plist", record["fileSha256"])
        self.assertEqual(record["fileSha256"]["route-probe.plist"],
                         hashlib.sha256((run / "route-probe.plist").read_bytes()).hexdigest())
        with run_state.State(self.root):
            pass
        changed_receipt = dict(report, positiveStatus=502)
        self._rewrite(run / "route-probe.plist", plistlib.dumps(changed_receipt,
                                                                  fmt=plistlib.FMT_BINARY))
        with self.assertRaises(recovery.RecoveryError):
            with run_state.State(self.root):
                self.fail("changed route receipt accepted after disposition")
        self._rewrite(run / "route-probe.plist", plistlib.dumps(report, fmt=plistlib.FMT_BINARY))
        altered = dict(identity, positiveOriginIPv4="104.20.0.3")
        identity_record = plistlib.loads((run / "identity.plist").read_bytes())
        identity_record["identity"] = altered
        self._rewrite(run / "identity.plist", plistlib.dumps(identity_record, fmt=plistlib.FMT_BINARY,
                                                                sort_keys=True))
        with self.assertRaises(recovery.RecoveryError):
            with run_state.State(self.root):
                self.fail("changed route admission IP accepted after disposition")

    def test_fully_reaped_failed_route_disposition_requires_restoration_and_binds_evidence(self):
        identity = {**self.identity, "identityProbeIPv4": "104.20.0.1",
                    "positiveOriginIPv4": "104.20.0.2", "publicTrustRootsSha256": "f" * 64}
        run, run_id = self._failed_restored_run(identity)
        report = self._route_report()
        report.update({"positiveStatus": 503, "positiveTlsVerified": True,
                       "positiveBodyBytes": 0, "positiveBodySha256": hashlib.sha256(b"").hexdigest(),
                       "verified": False, "error": "predicate_failed"})
        self._rewrite(run / "route-probe.plist", plistlib.dumps(report, fmt=plistlib.FMT_BINARY))
        stop = {"vmReaped": True, "helperReaped": True, "vmStopped": True}
        self._rewrite(run / "stop.plist", plistlib.dumps(stop, fmt=plistlib.FMT_BINARY))
        retained_before = {path.relative_to(run): path.read_bytes()
                           for path in run.rglob("*") if path.is_file()}

        run_state.dispose_failed_restored(
            self.root, run_id, "fully reaped ticket", expected_vm_reaped=True,
            observe=lambda *_: self._observation())

        receipt = plistlib.loads((run / "disposition.plist").read_bytes())
        self.assertEqual(receipt["fileSha256"]["stop.plist"],
                         hashlib.sha256((run / "stop.plist").read_bytes()).hexdigest())
        self.assertEqual(receipt["fileSha256"]["route-probe.plist"],
                         hashlib.sha256((run / "route-probe.plist").read_bytes()).hexdigest())
        self.assertEqual({path.relative_to(run): path.read_bytes()
                          for path in run.rglob("*") if path.is_file()
                          and path.name != "disposition.plist"}, retained_before)
        self.assertFalse((run / "complete.plist").exists())
        self.assertFalse(run_state._check_run_directory(self.root, run_id))
        with run_state.State(self.root):
            pass

    def test_fully_reaped_route_identity_without_probe_receipt_disposes_exact_failed_run(self):
        identity = {**self.identity, "identityProbeIPv4": "104.20.0.1",
                    "positiveOriginIPv4": "104.20.0.2", "publicTrustRootsSha256": "f" * 64}
        run, run_id = self._failed_restored_run(identity)
        stop = {"vmReaped": True, "helperReaped": True, "vmStopped": True}
        self._rewrite(run / "stop.plist", plistlib.dumps(stop, fmt=plistlib.FMT_BINARY))
        self.assertTrue((run / "restored").is_file())
        self.assertFalse((run / "route-probe.plist").exists())
        retained_before = {path.relative_to(run): path.read_bytes()
                           for path in run.rglob("*") if path.is_file()}

        run_state.dispose_failed_restored(
            self.root, run_id, "fully reaped route ticket", expected_vm_reaped=True,
            observe=lambda *_: self._observation())

        receipt = plistlib.loads((run / "disposition.plist").read_bytes())
        self.assertEqual(set(receipt["fileSha256"]), set(run_state.DISPOSITION_FILES))
        self.assertEqual(receipt["fileSha256"]["stop.plist"],
                         hashlib.sha256((run / "stop.plist").read_bytes()).hexdigest())
        self.assertEqual({path.relative_to(run): path.read_bytes()
                          for path in run.rglob("*") if path.is_file()
                          and path.name != "disposition.plist"}, retained_before)
        self.assertFalse((run / "route-probe.plist").exists())
        self.assertFalse((run / "complete.plist").exists())
        self.assertFalse(run_state._check_run_directory(self.root, run_id))
        with run_state.State(self.root):
            pass

    def test_disposition_stop_mode_mismatch_and_non_boolean_ack_refuse_before_observation(self):
        run, run_id = self._failed_restored_run()
        observer = Mock(return_value=self._observation())
        with self.assertRaisesRegex(recovery.RecoveryError, "disposition_stop_mode_mismatch"):
            run_state.dispose_failed_restored(
                self.root, run_id, "ticket", expected_vm_reaped=True, observe=observer)
        observer.assert_not_called()
        self.assertFalse((run / "disposition.plist").exists())

        self._rewrite(run / "stop.plist", plistlib.dumps(self._stop_evidence(),
                                                          fmt=plistlib.FMT_BINARY))
        observer.reset_mock()
        with self.assertRaisesRegex(recovery.RecoveryError, "disposition_stop_mode_mismatch"):
            run_state.dispose_failed_restored(
                self.root, run_id, "ticket", expected_vm_reaped=False, observe=observer)
        observer.assert_not_called()
        self.assertFalse((run / "disposition.plist").exists())

        for invalid in (None, 1):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                    recovery.RecoveryError, "invalid_expected_vm_reaped"):
                run_state.dispose_failed_restored(
                    self.root, run_id, "ticket", expected_vm_reaped=invalid, observe=observer)
            observer.assert_not_called()
            self.assertFalse((run / "disposition.plist").exists())

    def test_fully_reaped_disposition_still_requires_restored_marker(self):
        run, run_id = self._failed_restored_run()
        self._rewrite(run / "stop.plist", plistlib.dumps(self._stop_evidence(),
                                                          fmt=plistlib.FMT_BINARY))
        (run / "restored").unlink()
        observer = Mock(return_value=self._observation())
        with self.assertRaisesRegex(recovery.RecoveryError, "ineligible_disposition"):
            run_state.dispose_failed_restored(
                self.root, run_id, "ticket", expected_vm_reaped=True, observe=observer)
        observer.assert_not_called()
        self.assertFalse((run / "disposition.plist").exists())

    def test_fully_reaped_disposition_rejects_unreaped_helper_or_unstopped_vm(self):
        invalid_stops = (
            {"vmReaped": True, "helperReaped": False, "vmStopped": True},
            {"vmReaped": True, "helperReaped": True, "vmStopped": False},
        )
        for stop in invalid_stops:
            with self.subTest(stop=stop):
                shutil.rmtree(self.root)
                self.root.mkdir(mode=0o700)
                self.root.chmod(0o700)
                run, run_id = self._failed_restored_run()
                self._rewrite(run / "stop.plist", plistlib.dumps(stop, fmt=plistlib.FMT_BINARY))
                records_before = {path.relative_to(run): path.read_bytes()
                                  for path in run.rglob("*") if path.is_file()}
                observer = Mock(return_value=self._observation())

                with self.assertRaisesRegex(recovery.RecoveryError, "ineligible_disposition"):
                    run_state.dispose_failed_restored(
                        self.root, run_id, "ticket", expected_vm_reaped=True, observe=observer)

                observer.assert_not_called()
                self.assertFalse((run / "disposition.plist").exists())
                self.assertEqual({path.relative_to(run): path.read_bytes()
                                  for path in run.rglob("*") if path.is_file()}, records_before)

    def test_cli_controller_retains_too_large_route_failure_and_blocks_completion(self):
        identity_ip, positive_ip, roots = "104.20.0.1", "104.20.0.2", "f" * 64
        identity = {**self.identity, "identityProbeIPv4": identity_ip,
                    "positiveOriginIPv4": positive_ip, "publicTrustRootsSha256": roots}
        receipt, report = self._cli_report_too_large(identity_ip, positive_ip, roots)
        self.assertTrue(receipt.endswith(b"\n"))
        self.assertEqual(report["error"], "report_too_large")
        self.assertEqual(report["publicTrustRootsSha256"], roots)
        self.assertTrue(report["gatewayCaAbsent"])
        self.identity = identity
        with run_state.State(self.root) as state:
            run, run_id = self._run_with_recovery_records(state)
            report_bytes = plistlib.dumps(report, fmt=plistlib.FMT_BINARY)
            self._rewrite(run / "route-probe.plist", report_bytes)
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_route_probe"):
                state.complete(run, self._stop_evidence())

        self._rewrite(run / "stop.plist", plistlib.dumps(
            {"vmReaped": False, "helperReaped": True, "vmStopped": True},
            fmt=plistlib.FMT_BINARY))
        run_state.dispose_failed_restored(self.root, run_id, "route overflow ticket",
                                          expected_vm_reaped=False, observe=lambda *_: self._observation())
        disposition_bytes = (run / "disposition.plist").read_bytes()
        disposition = plistlib.loads(disposition_bytes)
        self.assertEqual(disposition["fileSha256"]["route-probe.plist"],
                         hashlib.sha256(report_bytes).hexdigest())
        self.assertFalse((run / "complete.plist").exists())
        with run_state.State(self.root):
            pass

        for change in ({"identityError": "timeout"},
                       {"publicTrustRootsSha256": "0" * 64}):
            with self.subTest(change=change):
                changed_report = {**report, **change}
                changed_bytes = plistlib.dumps(changed_report, fmt=plistlib.FMT_BINARY)
                self._rewrite(run / "route-probe.plist", changed_bytes)
                changed_disposition = dict(disposition)
                changed_hashes = dict(disposition["fileSha256"])
                changed_hashes["route-probe.plist"] = hashlib.sha256(changed_bytes).hexdigest()
                changed_disposition["fileSha256"] = changed_hashes
                self._rewrite(run / "disposition.plist", plistlib.dumps(
                    changed_disposition, fmt=plistlib.FMT_BINARY))
                with self.assertRaisesRegex(recovery.RecoveryError, "invalid_route_probe"):
                    with run_state.State(self.root):
                        self.fail("tampered failed route receipt accepted")
                self._rewrite(run / "route-probe.plist", report_bytes)
                self._rewrite(run / "disposition.plist", disposition_bytes)

    def test_route_failure_elapsed_backstop_does_not_relax_success_limit(self):
        self.identity.update({"identityProbeIPv4": "104.20.0.1",
                              "positiveOriginIPv4": "104.20.0.2",
                              "publicTrustRootsSha256": "f" * 64})
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            try:
                success = self._route_report()
                success["finishedAtUnixNs"] = success["startedAtUnixNs"] + 13_000_000_000
                self._rewrite(run / "route-probe.plist", plistlib.dumps(
                    success, fmt=plistlib.FMT_BINARY))
                with self.assertRaisesRegex(recovery.RecoveryError, "invalid_route_probe"):
                    run_state._check_route_probe(fd, self.identity)

                for duration_ns in (13_000_000_000, 25_000_000_000):
                    report = self._route_timeout_report(duration_ns)
                    self._rewrite(run / "route-probe.plist", plistlib.dumps(
                        report, fmt=plistlib.FMT_BINARY))
                    _, validated = run_state._check_route_probe(fd, self.identity)
                    self.assertFalse(validated["verified"])

                too_slow = self._route_timeout_report(25_000_000_001)
                self._rewrite(run / "route-probe.plist", plistlib.dumps(
                    too_slow, fmt=plistlib.FMT_BINARY))
                with self.assertRaisesRegex(recovery.RecoveryError, "invalid_route_probe"):
                    run_state._check_route_probe(fd, self.identity)
            finally:
                os.close(fd)

    def test_failed_trust_preflight_route_disposition_retains_and_hashes_receipt(self):
        identity = {**self.identity, "identityProbeIPv4": "104.20.0.1",
                    "positiveOriginIPv4": "104.20.0.2", "publicTrustRootsSha256": "f" * 64}
        run, run_id = self._failed_restored_run(identity)
        receipt = plistlib.dumps(self._route_preflight_report("trust_override"),
                                 fmt=plistlib.FMT_BINARY)
        self._rewrite(run / "route-probe.plist", receipt)
        run_state.dispose_failed_restored(self.root, run_id, "ticket",
                                          expected_vm_reaped=False, observe=lambda *_: self._observation())
        record = plistlib.loads((run / "disposition.plist").read_bytes())
        self.assertEqual(record["fileSha256"]["route-probe.plist"], hashlib.sha256(receipt).hexdigest())
        self.assertFalse((run / "complete.plist").exists())
        with run_state.State(self.root):
            pass

    def test_guest_trust_override_receipt_is_retained_as_a_failed_state_disposition(self):
        identity_ip, positive_ip, roots = "104.20.0.1", "104.20.0.2", "f" * 64
        output = io.StringIO()
        with patch.dict(probe_guest.os.environ, {"SSL_CERT_FILE": "/untrusted/ca.pem"}), \
                redirect_stdout(output):
            self.assertEqual(probe_guest.main([
                "--guest-route-contract", identity_ip, positive_ip, roots]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["error"], "trust_override")
        self.assertFalse(report["verified"])

        identity = {**self.identity, "identityProbeIPv4": identity_ip,
                    "positiveOriginIPv4": positive_ip, "publicTrustRootsSha256": roots}
        run, run_id = self._failed_restored_run(identity)
        receipt = plistlib.dumps(report, fmt=plistlib.FMT_BINARY)
        self._rewrite(run / "route-probe.plist", receipt)
        self.assertFalse(run_state._check_run_directory(self.root, run_id))
        run_state.dispose_failed_restored(
            self.root, run_id, "ticket", expected_vm_reaped=False, observe=lambda *_: self._observation()
        )
        disposition = plistlib.loads((run / "disposition.plist").read_bytes())
        self.assertEqual(disposition["fileSha256"]["route-probe.plist"],
                         hashlib.sha256(receipt).hexdigest())
        with run_state.State(self.root):
            pass

    def test_probe_completion_rejects_unverified_receipt(self):
        self.identity["probeIPv4"] = "104.20.0.1"
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            failed_report = {**self._probe_report(), "status": 503, "bodyBytes": 11,
                             "bodySha256": hashlib.sha256(b"unavailable").hexdigest(),
                             "verified": False}
            try:
                recovery._publish(fd, "probe.plist", plistlib.dumps(
                    failed_report, fmt=plistlib.FMT_BINARY))
            finally:
                os.close(fd)
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_probe"):
                state.complete(run, self._stop_evidence())

    def test_probe_receipt_rejects_missing_gateway_context_without_error(self):
        self.identity["probeIPv4"] = "104.20.0.1"
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            try:
                recovery._publish(fd, "probe.plist", plistlib.dumps(
                    {**self._probe_report(), "gatewayContextVerified": False,
                     "verified": False}, fmt=plistlib.FMT_BINARY))
                with self.assertRaisesRegex(recovery.RecoveryError, "invalid_probe"):
                    run_state._check_probe(fd, self.identity)
            finally:
                os.close(fd)

    def test_probe_receipt_duration_allows_only_bounded_timeout_overhead(self):
        self.identity["probeIPv4"] = "104.20.0.1"
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            try:
                report = self._probe_report()
                self._rewrite(run / "probe.plist", plistlib.dumps(
                    {**report, "finishedAtUnixNs": report["startedAtUnixNs"] + 15_000_000_001},
                    fmt=plistlib.FMT_BINARY))
                with self.assertRaisesRegex(recovery.RecoveryError, "invalid_probe"):
                    run_state._check_probe(fd, self.identity)

                timeout = {**report, "finishedAtUnixNs": report["startedAtUnixNs"] + 25_000_000_000,
                           "gatewayContextVerified": False,
                           "expectedHostPosturePassed": False, "status": 0, "bodyBytes": 0,
                           "bodySha256": hashlib.sha256(b"").hexdigest(), "verified": False,
                           "error": "total_timeout"}
                self._rewrite(run / "probe.plist", plistlib.dumps(timeout, fmt=plistlib.FMT_BINARY))
                self.assertEqual(run_state._check_probe(fd, self.identity)[1], timeout)

                timeout["finishedAtUnixNs"] += 1
                self._rewrite(run / "probe.plist", plistlib.dumps(timeout, fmt=plistlib.FMT_BINARY))
                with self.assertRaisesRegex(recovery.RecoveryError, "invalid_probe"):
                    run_state._check_probe(fd, self.identity)
            finally:
                os.close(fd)

    def test_route_receipt_is_exact_binds_two_ips_and_completes_with_digest(self):
        self.identity.update({"identityProbeIPv4": "104.20.0.1", "positiveOriginIPv4": "104.20.0.2",
                              "publicTrustRootsSha256": "f" * 64})
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            report_bytes = plistlib.dumps(self._route_report(), fmt=plistlib.FMT_BINARY)
            try:
                recovery._publish(fd, "route-probe.plist", report_bytes)
            finally:
                os.close(fd)
            state.complete(run, self._stop_evidence())
        complete = plistlib.loads((run / "complete.plist").read_bytes())
        self.assertEqual(complete["routeProbeSha256"], hashlib.sha256(report_bytes).hexdigest())
        with run_state.State(self.root):
            pass
        fd = recovery._directory(run)
        try:
            for change in ({"identityDestinationIPv4": "104.20.0.3"},
                           {"positiveDestinationIPv4": "104.20.0.3"},
                           {"publicTrustRootsSha256": "0" * 64}, {"identityStatus": 200},
                           {"positiveStatus": 503}, {"identityBodyBytes": 1},
                           {"identityNoStore": False}, {"identityNoGatewayMarkers": False},
                           {"positiveContentType": "text/html"}, {"positiveBodyBytes": 455},
                           {"positiveBodySha256": "0" * 64}, {"gatewayCaAbsent": False},
                           {"verified": False}, {"error": "predicate_failed"}, {"error": {}},
                           {"positiveContentType": []}, {"positiveError": []}):
                report = self._route_report()
                report.update(change)
                self._rewrite(run / "route-probe.plist", plistlib.dumps(report, fmt=plistlib.FMT_BINARY))
                with self.assertRaises(recovery.RecoveryError):
                    run_state._check_route_probe(fd, self.identity)
            self._rewrite(run / "route-probe.plist", report_bytes)
        finally:
            os.close(fd)

    def test_route_completion_requires_receipt_and_rejects_cross_mode_entries(self):
        self.identity.update({"identityProbeIPv4": "104.20.0.1", "positiveOriginIPv4": "104.20.0.2",
                              "publicTrustRootsSha256": "f" * 64})
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_run_entries"):
                state.complete(run, self._stop_evidence())
            fd = recovery._directory(run)
            try:
                recovery._publish(fd, "probe.plist", plistlib.dumps(self._probe_report(), fmt=plistlib.FMT_BINARY))
            finally:
                os.close(fd)
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_probe_mode"):
                run_state._check_run_directory(self.root, run.name)

    def test_route_preflight_failure_is_valid_retained_but_never_complete(self):
        self.identity.update({"identityProbeIPv4": "104.20.0.1", "positiveOriginIPv4": "104.20.0.2",
                              "publicTrustRootsSha256": "f" * 64})
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            report_bytes = plistlib.dumps(self._route_preflight_report(), fmt=plistlib.FMT_BINARY)
            try:
                recovery._publish(fd, "route-probe.plist", report_bytes)
                self.assertFalse(run_state._check_route_probe(fd, self.identity)[1]["verified"])
            finally:
                os.close(fd)
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_route_probe"):
                state.complete(run, self._stop_evidence())
            self.assertFalse((run / "complete.plist").exists())

    def test_complete_scanner_rejects_failed_route_with_matching_receipt_digest(self):
        self.identity.update({"identityProbeIPv4": "104.20.0.1", "positiveOriginIPv4": "104.20.0.2",
                              "publicTrustRootsSha256": "f" * 64})
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            route_bytes = plistlib.dumps(self._route_report(), fmt=plistlib.FMT_BINARY)
            try:
                recovery._publish(fd, "route-probe.plist", route_bytes)
            finally:
                os.close(fd)
            state.complete(run, self._stop_evidence())
        failed = self._route_report()
        failed.update({"positiveStatus": 503, "positiveContentType": "",
                       "positiveBodyBytes": 0, "positiveBodySha256": hashlib.sha256(b"").hexdigest(),
                       "verified": False, "error": "predicate_failed"})
        failed_bytes = plistlib.dumps(failed, fmt=plistlib.FMT_BINARY)
        self._rewrite(run / "route-probe.plist", failed_bytes)
        complete = plistlib.loads((run / "complete.plist").read_bytes())
        complete["routeProbeSha256"] = hashlib.sha256(failed_bytes).hexdigest()
        self._rewrite(run / "complete.plist", plistlib.dumps(complete, fmt=plistlib.FMT_BINARY))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_route_probe"):
            with run_state.State(self.root):
                self.fail("failed route result accepted as a complete run")

    def test_complete_scanner_rejects_failed_v1_probe_with_matching_receipt_digest(self):
        self.identity["probeIPv4"] = "104.20.0.1"
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            report_bytes = plistlib.dumps(self._probe_report(), fmt=plistlib.FMT_BINARY)
            try:
                recovery._publish(fd, "probe.plist", report_bytes)
            finally:
                os.close(fd)
            state.complete(run, self._stop_evidence())
        failed = {**self._probe_report(), "status": 503, "bodyBytes": 0,
                  "bodySha256": hashlib.sha256(b"").hexdigest(), "verified": False}
        failed_bytes = plistlib.dumps(failed, fmt=plistlib.FMT_BINARY)
        self._rewrite(run / "probe.plist", failed_bytes)
        complete = plistlib.loads((run / "complete.plist").read_bytes())
        complete["probeSha256"] = hashlib.sha256(failed_bytes).hexdigest()
        self._rewrite(run / "complete.plist", plistlib.dumps(complete, fmt=plistlib.FMT_BINARY))
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_probe"):
            with run_state.State(self.root):
                self.fail("failed v1 probe accepted as a complete run")

    def test_complete_rejects_cross_mode_probe_before_publishing_marker(self):
        self.identity.update({"identityProbeIPv4": "104.20.0.1", "positiveOriginIPv4": "104.20.0.2",
                              "publicTrustRootsSha256": "f" * 64})
        with run_state.State(self.root) as state:
            run, _ = self._run_with_recovery_records(state)
            fd = recovery._directory(run)
            try:
                recovery._publish(fd, "probe.plist", plistlib.dumps(
                    self._probe_report(destination=None), fmt=plistlib.FMT_BINARY))
                recovery._publish(fd, "route-probe.plist", plistlib.dumps(
                    self._route_report(), fmt=plistlib.FMT_BINARY))
            finally:
                os.close(fd)
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_probe_mode"):
                state.complete(run, self._stop_evidence())
            self.assertFalse((run / "complete.plist").exists())

    def test_disposition_fails_closed_on_bad_observation_and_wrong_stop_shape(self):
        run, run_id = self._failed_restored_run()
        with self.assertRaisesRegex(recovery.RecoveryError, "invalid_approval_reference"):
            run_state.dispose_failed_restored(self.root, run_id, "   ",
                                              expected_vm_reaped=False, observe=lambda *_: self._observation())
        for observation in (
            {**self._observation(), "extra": True},
            {**self._observation(), "vmStopped": 1},
            {**self._observation(), "preferencesOriginal": False},
        ):
            with self.subTest(observation=observation):
                with self.assertRaisesRegex(recovery.RecoveryError, "invalid_disposition_observation"):
                    run_state.dispose_failed_restored(self.root, run_id, "ticket",
                                                      expected_vm_reaped=False, observe=lambda *_: observation)
                self.assertFalse((run / "disposition.plist").exists())
        self._rewrite(run / "stop.plist", plistlib.dumps(self._stop_evidence()))
        with self.assertRaisesRegex(recovery.RecoveryError, "disposition_stop_mode_mismatch"):
            run_state.dispose_failed_restored(self.root, run_id, "ticket",
                                              expected_vm_reaped=False, observe=lambda *_: self._observation())

    def test_disposition_rejects_unrelated_unresolved_run_stale_observation_and_changes(self):
        with run_state.State(self.root) as state:
            run, run_id = self._run_with_recovery_records(state)
            state.complete(run, self._stop_evidence())
            other, _ = state.begin(self.identity)
        (run / "complete.plist").unlink()
        self._rewrite(run / "stop.plist", plistlib.dumps(
            {"vmReaped": False, "helperReaped": True, "vmStopped": True},
            fmt=plistlib.FMT_BINARY))
        with self.assertRaisesRegex(recovery.RecoveryError, "unresolved_run"):
            run_state.dispose_failed_restored(self.root, run_id, "ticket",
                                              expected_vm_reaped=False, observe=lambda *_: self._observation())
        shutil.rmtree(other)
        self._rewrite(run / "stop.plist", plistlib.dumps(
            {"vmReaped": False, "helperReaped": True, "vmStopped": True}))
        stale = self._observation()
        stale["observedAtUnixNs"] -= 31_000_000_000
        with self.assertRaisesRegex(recovery.RecoveryError, "stale_disposition_observation"):
            run_state.dispose_failed_restored(self.root, run_id, "ticket", expected_vm_reaped=False, observe=lambda *_: stale)

        def changed(path, _identity):
            self._rewrite(path / "helper-logs" / "tart-stdout.bin", b"changed\n")
            return self._observation()
        with self.assertRaisesRegex(recovery.RecoveryError, "disposition_source_changed"):
            run_state.dispose_failed_restored(self.root, run_id, "ticket", expected_vm_reaped=False, observe=changed)

    def test_new_unresolved_run_during_observation_prevents_receipt_publication(self):
        run, run_id = self._failed_restored_run()
        other_id = "e" * 32
        other = self.root / other_id

        def observe(*_):
            other.mkdir(mode=0o700)
            fd = recovery._directory(other)
            try:
                recovery._publish(fd, "identity.plist", plistlib.dumps(
                    run_state._identity_record(other_id, self.identity), fmt=plistlib.FMT_BINARY,
                    sort_keys=True))
            finally:
                os.close(fd)
            return self._observation()
        with self.assertRaisesRegex(recovery.RecoveryError, "unresolved_run"):
            run_state.dispose_failed_restored(self.root, run_id, "ticket", expected_vm_reaped=False, observe=observe)
        self.assertFalse((run / "disposition.plist").exists())
        shutil.rmtree(other)

    def test_disposition_receipt_schema_and_digests_are_checked_on_every_scan(self):
        run, run_id = self._failed_restored_run()
        run_state.dispose_failed_restored(self.root, run_id, "ticket",
                                          expected_vm_reaped=False, observe=lambda *_: self._observation())
        receipt = run / "disposition.plist"
        original = receipt.read_bytes()
        mutations = (
            lambda record: record.update(runId="0" * 32),
            lambda record: record.update(extra=True),
            lambda record: record.update(version=2),
            lambda record: record.update(approvalReference="   "),
            lambda record: record["observation"].update(extra=True),
            lambda record: record["fileSha256"].update(restored="0" * 64),
        )
        for mutate in mutations:
            record = plistlib.loads(original)
            mutate(record)
            self._rewrite(receipt, plistlib.dumps(record, fmt=plistlib.FMT_BINARY))
            with self.subTest(record=record):
                with self.assertRaisesRegex(recovery.RecoveryError, "invalid_disposition"):
                    with run_state.State(self.root):
                        self.fail("malformed disposition accepted")
            self._rewrite(receipt, original)

    def test_disposition_rejects_changed_sources_missing_marker_and_complete_conflict(self):
        run, run_id = self._failed_restored_run()
        restored = (run / "restored").read_bytes()
        (run / "restored").unlink()
        with self.assertRaisesRegex(recovery.RecoveryError, "ineligible_disposition"):
            run_state.dispose_failed_restored(self.root, run_id, "ticket",
                                              expected_vm_reaped=False, observe=lambda *_: self._observation())
        self._rewrite(run / "restored", restored)
        run_state.dispose_failed_restored(self.root, run_id, "ticket",
                                          expected_vm_reaped=False, observe=lambda *_: self._observation())
        for relative, changed in (("restored", b"changed\n"),
                                  ("helper-logs/tart-stdout.bin", b"changed\n")):
            source = run / relative
            original = source.read_bytes()
            self._rewrite(source, changed)
            with self.subTest(source=relative):
                with self.assertRaises(recovery.RecoveryError):
                    with run_state.State(self.root):
                        self.fail("changed retained source accepted")
            self._rewrite(source, original)
        (run / "complete.plist").write_bytes(b"conflict")
        (run / "complete.plist").chmod(0o600)
        with self.assertRaisesRegex(recovery.RecoveryError, "conflicting_disposition"):
            with run_state.State(self.root):
                self.fail("complete and disposition markers accepted together")

    def test_disposition_is_not_overwritten_and_requires_root(self):
        run, run_id = self._failed_restored_run()
        real_stat = os.stat

        def unowned_run(path, *args, **kwargs):
            info = real_stat(path, *args, **kwargs)
            if path == run_id and kwargs.get("dir_fd") is not None:
                return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid + 1)
            return info
        with patch.object(run_state.os, "stat", side_effect=unowned_run):
            with self.assertRaisesRegex(recovery.RecoveryError, "invalid_run_directory"):
                run_state.dispose_failed_restored(self.root, run_id, "ticket",
                                                  expected_vm_reaped=False, observe=lambda *_: self._observation())
        original_publish = recovery._publish

        def race_publish(fd, name, data):
            if name == "disposition.plist":
                existing = recovery._file(fd, name, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
                os.close(existing)
            return original_publish(fd, name, data)
        with self.assertRaises(OSError):
            with patch.object(recovery, "_publish", side_effect=race_publish):
                run_state.dispose_failed_restored(self.root, run_id, "ticket",
                                                  expected_vm_reaped=False, observe=lambda *_: self._observation())
        (run / "disposition.plist").unlink()
        with patch.object(recovery.os, "geteuid", return_value=os.getuid() + 1):
            with self.assertRaisesRegex(recovery.RecoveryError, "root_required"):
                run_state.dispose_failed_restored(self.root, run_id, "ticket",
                                                  expected_vm_reaped=False, observe=lambda *_: self._observation())

    def test_source_change_after_prepublication_scan_blocks_receipt(self):
        run, run_id = self._failed_restored_run()
        original_scan = run_state.State._scan
        scan_count = 0

        def scan_then_change(state, **kwargs):
            nonlocal scan_count
            original_scan(state, **kwargs)
            scan_count += 1
            if scan_count == 2:
                self._rewrite(run / "helper-logs" / "tart-stdout.bin", b"changed\n")

        with patch.object(run_state.State, "_scan", scan_then_change):
            with self.assertRaisesRegex(recovery.RecoveryError, "disposition_source_changed"):
                run_state.dispose_failed_restored(
                    self.root, run_id, "ticket", expected_vm_reaped=False, observe=lambda *_: self._observation())
        self.assertEqual(scan_count, 2)
        self.assertFalse((run / "disposition.plist").exists())


if __name__ == "__main__":
    unittest.main()
