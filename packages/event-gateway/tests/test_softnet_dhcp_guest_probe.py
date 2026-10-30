"""Offline checks for fixed Softnet DHCP packaging and host-to-guest transfer."""

import base64
from contextlib import redirect_stdout
from io import StringIO
import hashlib
import json
import os
from types import SimpleNamespace
from pathlib import Path
import subprocess  # nosec B404 -- fixed test Python child with generated fixtures only.
import sys
import tempfile
import unittest
import zlib
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "scripts"))
import qualify_offline_macos_vm as canary  # noqa: E402
import dhcp_probe_frames as dhcp  # noqa: E402
import softnet_dhcp_guest_probe as probe  # noqa: E402
from test_dhcp_probe_frames import offer_frame  # noqa: E402


def blob(data):
    return {"bytes": len(data), "base64": base64.b64encode(data).decode(),
            "sha256": hashlib.sha256(data).hexdigest()}


CLIENT_IDS = (b"\x00knitli-softnet-a", b"\x00knitli-softnet-b")
MAC = bytes.fromhex("02 00 00 00 88 01")


def exchange_for(client_id, xid, lease=600):
    yiaddr = "192.0.2.44"
    server_id = "192.0.2.1"
    frames = [dhcp.build_discover(MAC, xid, client_id),
              offer_frame(xid=xid, chaddr=MAC, server=server_id, lease=lease),
              dhcp.build_request(MAC, xid, client_id, yiaddr, server_id),
              offer_frame(msg_type=5, xid=xid, chaddr=MAC, server=server_id, lease=lease)]
    return {"clientIdBase64": base64.b64encode(client_id).decode(), "xid": xid,
            "yiaddr": yiaddr, "serverId": server_id, "offerLeaseSeconds": lease,
            "leaseSeconds": lease, "frames": [blob(frame) for frame in frames]}


def report_for(hashes, binary_hash=None):
    return {"kind": probe.REPORT_KIND, "status": "passed", "dhcpQualified": True,
            "fullNativeQualified": False, "failureCode": None,
            "checks": {name: True for name in probe.CHECKS}, "sourceSha256": hashes,
            "binarySha256": probe.BINARY_SHA256 if binary_hash is None else binary_hash,
            "exchanges": [exchange_for(client_id, xid)
                          for client_id, xid in zip(CLIENT_IDS, (3, 4))],
            "logs": {"stdout": blob(b"helper stdout"), "stderr": blob(b"")},
            "cleanupFailure": None,
            "diagnostics": [{"phase": phase, "status": "collector_failed"}
                            for phase in ("before_helper", "helper_ready", "after_exchange")]}


class SoftnetDhcpGuestProbeTests(unittest.TestCase):
    def test_bundle_contains_only_four_fixed_hashed_sources(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-source-copy-") as temp:
            root = Path(temp)
            paths = {}
            for name in probe.SOURCE_FILES:
                path = root / name
                path.write_bytes((name + "\n").encode())
                paths[name] = path
            with patch.object(probe, "SOURCE_PATHS", paths):
                bundle = probe.build_bundle()
        raw = zlib.decompress(base64.b64decode(bundle["argument"], validate=True))
        files = json.loads(raw)
        self.assertEqual(set(files), set(probe.SOURCE_FILES.values()))
        self.assertLessEqual(len(raw), probe.MAX_SOURCE_BYTES)
        self.assertLessEqual(len(bundle["argument"]), probe.MAX_BUNDLE_ARG)
        hashes = {}
        for name, item in files.items():
            content = base64.b64decode(item["content"], validate=True)
            hashes[name] = hashlib.sha256(content).hexdigest()
            self.assertEqual(item["sha256"], hashes[name])
        self.assertEqual(bundle["sourceSha256"], hashes)

    def test_bundle_rejects_symlinked_sources_and_oversized_encoding(self):
        with tempfile.TemporaryDirectory(prefix="dhcp-source-links-") as temp:
            root = Path(temp)
            paths = {}
            for name in probe.SOURCE_FILES:
                path = root / name
                path.write_text("source\n")
                paths[name] = path
            target = paths["qualify_softnet_dhcp_guest.py"]
            target.unlink()
            target.symlink_to(paths["softnet_preferences.py"])
            with patch.object(probe, "SOURCE_PATHS", paths), self.assertRaisesRegex(
                    canary.CanaryError, "softnet_dhcp_source_unsafe"):
                probe.build_bundle()
            target.unlink()
            target.write_text("source\n")
            with patch.object(probe, "SOURCE_PATHS", paths), patch.object(
                    probe, "MAX_BUNDLE_ARG", 1), self.assertRaisesRegex(
                        canary.CanaryError, "softnet_dhcp_bundle_oversized"):
                probe.build_bundle()

    def test_binary_preflight_accepts_only_owner_private_pinned_regular_file(self):
        payload = b"offline pinned helper fixture"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as temp:
            helper = Path(temp).resolve() / "helper"
            helper.write_bytes(payload)
            os.chmod(helper, 0o600)
            with patch.object(probe, "BINARY_SHA256", digest):
                fd, metadata = probe._read_binary(helper)
                try:
                    self.assertEqual(metadata, {"sha256": digest, "bytes": len(payload)})
                    self.assertEqual(os.read(fd, len(payload)), payload)
                    for mode in (0o400, 0o500, 0o700):
                        os.chmod(helper, mode)
                        with self.subTest(transfer_mode=oct(mode)), self.assertRaisesRegex(
                                canary.CanaryError, "softnet_dhcp_binary_unsafe"):
                            probe._rewind_verified_binary(fd)
                        os.chmod(helper, 0o600)
                finally:
                    os.close(fd)
                real_open = os.open

                def widen_after_open(path, flags):
                    opened_fd = real_open(path, flags)
                    os.fchmod(opened_fd, 0o700)
                    return opened_fd

                with patch.object(probe.os, "open", side_effect=widen_after_open), self.assertRaisesRegex(
                        canary.CanaryError, "softnet_dhcp_binary_unsafe"):
                    probe._read_binary(helper)
                os.chmod(helper, 0o600)
                for mode in (0o400, 0o500, 0o644, 0o700):
                    os.chmod(helper, mode)
                    with patch.object(probe.os, "open", wraps=os.open) as opened_file:
                        with self.subTest(preflight_mode=oct(mode)), self.assertRaisesRegex(
                                canary.CanaryError, "softnet_dhcp_binary_unsafe"):
                            probe._read_binary(helper)
                        opened_file.assert_not_called()
            with patch.object(probe, "BINARY_SHA256", "0" * 64), self.assertRaisesRegex(
                    canary.CanaryError, "softnet_dhcp_binary_digest_mismatch"):
                os.chmod(helper, 0o600)
                probe._read_binary(helper)


    def test_fixed_loader_verifies_received_stdin_before_guest_call(self):
        payload = b"verified helper bytes\x00\xff"
        digest = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory(prefix="dhcp-loader-sources-") as temp:
            root = Path(temp)
            paths = {}
            for name in probe.SOURCE_FILES:
                paths[name] = root / name
                paths[name].write_text("# fixed fixture source\n")
            guest_source = '''import hashlib, json, os, stat
def qualify_guest_dhcp(helper_path):
    data = open(helper_path, "rb").read()
    info = os.stat(helper_path)
    return {"status": "passed", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "mode": stat.S_IMODE(info.st_mode)}
'''
            paths["qualify_softnet_dhcp_guest.py"].write_text(guest_source)
            with patch.object(probe, "SOURCE_PATHS", paths):
                bundle = probe.build_bundle()
            loader = probe.LOADER.replace(probe.BINARY_SHA256, digest).replace(
                'info.st_uid != 0', 'info.st_uid != os.getuid()').replace(
                    'dir="/private/tmp"', f"dir={tempfile.gettempdir()!r}")
            result = subprocess.run(  # nosec B603 -- fixed loader with generated source and helper fixtures, no shell.
                [sys.executable, "-I", "-c", loader, bundle["argument"]], input=payload,
                capture_output=True, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report, {"status": "passed", "bytes": len(payload), "sha256": digest,
                                      "mode": 0o555})
            invalid = subprocess.run(  # nosec B603 -- same fixed loader, intentionally mismatched helper fixture.
                [sys.executable, "-I", "-c", loader, bundle["argument"]], input=b"wrong",
                capture_output=True, check=False, timeout=10)
            self.assertNotEqual(invalid.returncode, 0)
            self.assertEqual(invalid.stdout, b"")

    def test_report_validates_exact_binding_checks_and_embedded_log_frame_digests(self):
        hashes = {name: "a" * 64 for name in probe.SOURCE_FILES}
        report = report_for(hashes)
        self.assertEqual(probe._validated_report(json.dumps(report).encode(), b"", hashes), report)
        bad_frames = [blob(b"fake frame")] * 4
        bad_request = exchange_for(CLIENT_IDS[0], 3)
        bad_request["frames"][2] = blob(dhcp.build_request(MAC, 3, CLIENT_IDS[0], "192.0.2.45", "192.0.2.1"))
        bad_discover = exchange_for(CLIENT_IDS[0], 3)
        bad_discover["frames"][0] = blob(dhcp.build_discover(MAC, 99, CLIENT_IDS[0]))
        duplicate_xid = report_for(hashes)
        duplicate_xid["exchanges"][1] = exchange_for(CLIENT_IDS[1], 3)
        cases = [
            dict(report, fullNativeQualified=True),
            dict(report, dhcpQualified=False),
            dict(report, binarySha256="b" * 64),
            dict(report, sourceSha256=dict(hashes, extra="c" * 64)),
            dict(report, cleanupFailure="helper_shutdown"),
            dict(report, checks=dict(report["checks"], lease=False)),
            dict(report, logs={**report["logs"], "stdout": {**report["logs"]["stdout"], "sha256": "0" * 64}}),
            dict(report, exchanges=[exchange_for(CLIENT_IDS[0], 3, lease=3600),
                                    report["exchanges"][1]]),
            dict(report, exchanges=[{**report["exchanges"][0], "frames": bad_frames},
                                    report["exchanges"][1]]),
            dict(report, exchanges=[bad_request, report["exchanges"][1]]),
            dict(report, exchanges=[bad_discover, report["exchanges"][1]]),
            duplicate_xid,
            dict(report, exchanges=[report["exchanges"][0],
                                    exchange_for(CLIENT_IDS[0], 4)]),
        ]
        for invalid in cases:
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                    canary.CanaryError, "softnet_dhcp_report_unqualified"):
                probe._validated_report(json.dumps(invalid).encode(), b"", hashes)
        with self.assertRaisesRegex(canary.CanaryError, "softnet_dhcp_output_invalid"):
            probe._validated_report(json.dumps(report).encode(), b"unexpected diagnostic", hashes)

    def test_diagnostics_are_bound_in_summary_without_copying_observations(self):
        hashes = {name: "a" * 64 for name in probe.SOURCE_FILES}
        report = report_for(hashes)
        report["diagnostics"][1] = {"phase": "helper_ready", "configs": {
            "etc": {"status": "ok", "selected": {"dhcp_ignore_client_identifier": {
                "status": "absent"}}}}}
        accepted = probe._validated_report(json.dumps(report).encode(), b"", hashes)
        summary = probe._report_summary(accepted)
        raw = json.dumps(report["diagnostics"], sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
        self.assertEqual(summary["diagnostics"], {
            "snapshots": 3, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertNotIn("dhcp_ignore_client_identifier", json.dumps(summary))
        self.assertEqual(accepted["diagnostics"], report["diagnostics"])

    def test_diagnostics_reject_wrong_phases_and_oversized_observations(self):
        hashes = {name: "a" * 64 for name in probe.SOURCE_FILES}
        invalid_cases = [None, {}, [], [{"phase": "helper_ready"}],
                         [{"phase": phase} for phase in (
                             "helper_ready", "before_helper", "after_exchange")],
                         [{"phase": "before_helper"}, {"phase": "helper_ready"},
                          {"phase": "after_exchange", "observation": "x" * (12 * 1024)}]]
        for observations in invalid_cases:
            report = report_for(hashes)
            report["diagnostics"] = observations
            with self.subTest(observations=observations), self.assertRaisesRegex(
                    canary.CanaryError, "softnet_dhcp_report_unqualified"):
                probe._validated_report(json.dumps(report).encode(), b"", hashes)

    def test_qualify_uses_fixed_nonpty_stdin_command_and_bounded_capture(self):
        hashes = {name: "d" * 64 for name in probe.SOURCE_FILES}
        bundle = {"argument": "QkFORExF", "sourceSha256": hashes, "bundleSha256": "e" * 64}
        output = json.dumps(report_for(hashes)).encode()
        payload = b"pinned-helper-fixture"
        with tempfile.NamedTemporaryFile() as source, tempfile.TemporaryDirectory(prefix="dhcp-evidence-") as temp:
            source.write(payload)
            source.flush()
            source.seek(0)
            captured = {}
            digest = hashlib.sha256(payload).hexdigest()
            output = json.dumps(report_for(hashes, digest)).encode()

            def run(argv, **kwargs):
                captured["argv"] = argv
                captured["kwargs"] = kwargs
                for path, data in zip(kwargs["capture_paths"], (output, b"")):
                    Path(path).write_bytes(data)
                return output, b""

            with patch.object(probe, "BINARY_SHA256", digest):
                result = probe.qualify("/fixed/tart", "offline-canary-123", {"PATH": "/usr/bin"},
                                       temp, bundle, source.fileno(), run_bounded=run)
                expected = probe._report_summary(probe._validated_report(output, b"", hashes))
            self.assertEqual(result, {"reportSummary": expected})
            self.assertEqual(Path(temp, "softnet-dhcp-stdout.bin").read_bytes(), output)
            self.assertEqual(Path(temp, "softnet-dhcp-stderr.bin").read_bytes(), b"")
            self.assertEqual(captured["argv"], ["/fixed/tart", "exec", "-i", "offline-canary-123",
                "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-c", probe.LOADER, "QkFORExF"])
            self.assertEqual(captured["kwargs"], {
                "timeout": probe.TIMEOUT, "env": {"PATH": "/usr/bin"},
                "output_limit": probe.MAX_OUTPUT_BYTES, "input_fd": source.fileno(),
                "capture_paths": (Path(temp, "softnet-dhcp-stdout.bin"),
                                  Path(temp, "softnet-dhcp-stderr.bin"))})
            self.assertEqual(probe.command_template("/fixed/tart", "offline-canary-123")[2], "-i")

    def test_bounded_runner_streams_input_fd_and_preserves_default_eof(self):
        child = ("import hashlib, json, sys; data=sys.stdin.buffer.read(); "
                 "print(json.dumps({'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}))")
        payload = b"fd fixture\x00\xff"
        with tempfile.NamedTemporaryFile() as source:
            source.write(payload)
            source.flush()
            source.seek(0)
            fd = source.fileno()
            stdout, stderr = canary._run_bounded([sys.executable, "-c", child], timeout=5,
                                                 env=os.environ.copy(), input_fd=fd)
            self.assertEqual(stderr, b"")
            self.assertEqual(json.loads(stdout), {"bytes": len(payload),
                                                  "sha256": hashlib.sha256(payload).hexdigest()})
            self.assertEqual(os.fstat(fd).st_size, len(payload))
        stdout, stderr = canary._run_bounded([sys.executable, "-c", child], timeout=5,
                                             env=os.environ.copy())
        self.assertEqual(stderr, b"")
        self.assertEqual(json.loads(stdout), {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()})


    def test_default_fake_canary_pipeline_does_not_activate_dhcp(self):
        from test_offline_macos_vm import OfflineMacosVmCanaryTest, canary as fixture_canary

        harness = OfflineMacosVmCanaryTest()
        harness.setUp()
        try:
            harness._write_fake_tart(frames="both")
            harness._write_receipt()
            with patch.object(fixture_canary, "_prepare_softnet_dhcp",
                              wraps=fixture_canary._prepare_softnet_dhcp) as prepare, \
                    patch.object(fixture_canary, "_run_softnet_dhcp",
                                 wraps=fixture_canary._run_softnet_dhcp) as run_probe:
                harness._run()
            prepare.assert_called_once_with(None)
            run_probe.assert_called_once()
            self.assertIsNone(run_probe.call_args.args[0])
            saved = json.loads((harness.evidence / "offline-macos-vm-canary.json").read_text())
            self.assertNotIn("softnetDhcp", saved)
            self.assertFalse(any(command[1:3] == ["exec", "-i"]
                                 for command in saved["hostCommandTemplates"] if len(command) > 2))
        finally:
            harness.tearDown()

    def test_opt_in_pipeline_closes_binary_fd_when_clone_launch_fails(self):
        from test_offline_macos_vm import OfflineMacosVmCanaryTest, canary as fixture_canary

        harness = OfflineMacosVmCanaryTest()
        harness.setUp()
        source = tempfile.TemporaryFile()
        fd = os.dup(source.fileno())
        fake_probe = SimpleNamespace(canary=fixture_canary, MAX_OUTPUT_BYTES=probe.MAX_OUTPUT_BYTES,
                                     metadata=lambda *_: {"binarySha256": probe.BINARY_SHA256}, close=os.close)
        clone_commands = []

        def fail_clone(argv, **_kwargs):
            clone_commands.append(argv)
            raise fixture_canary.CanaryError("tart_command_failed")

        try:
            with patch.object(fixture_canary, "TART_BINARY_SHA256", harness.receipt["tartBinarySha256"]), \
                    patch.object(fixture_canary, "_tart_identity", return_value=harness.tart), \
                    patch.object(fixture_canary, "_base_vm_measurement", return_value=(None, 1)), \
                    patch.object(fixture_canary.shutil, "disk_usage", return_value=SimpleNamespace(free=10**12)), \
                    patch.object(fixture_canary, "_prepare_softnet_dhcp",
                                 return_value=(fake_probe, {}, fd, {"sha256": probe.BINARY_SHA256, "bytes": 1})), \
                    patch.object(fixture_canary, "_run_bounded", side_effect=fail_clone):
                with self.assertRaisesRegex(fixture_canary.CanaryError, "tart_command_failed"):
                    fixture_canary.qualify("prepared-macos15", harness.receipt_path, harness.evidence,
                                   tart=str(harness.tart), tart_home=harness.tart_home,
                                   softnet_dhcp_binary="fixture", run_bounded=fail_clone)
            self.assertEqual(len(clone_commands), 1)
            self.assertEqual(clone_commands[0][1], "clone")
            with self.assertRaises(OSError):
                os.fstat(fd)
        finally:
            source.close()
            harness.tearDown()


    def test_opt_in_fake_pipeline_runs_after_boundary_and_publishes_bounded_logs(self):
        from test_offline_macos_vm import OfflineMacosVmCanaryTest, canary as fixture_canary

        harness = OfflineMacosVmCanaryTest()
        harness.setUp()
        source = tempfile.TemporaryFile()
        fd = os.dup(source.fileno())
        hashes = {name: "a" * 64 for name in probe.SOURCE_FILES}
        bundle = {"sourceSha256": hashes, "bundleSha256": "b" * 64}
        binary = {"sha256": probe.BINARY_SHA256, "bytes": 7}
        payload = json.dumps(report_for(hashes), sort_keys=True, separators=(",", ":")).encode()
        calls = []

        def fake_qualify(tart_path, vm_name, env, evidence, _bundle, binary_fd, *, run_bounded):
            calls.append((tart_path, vm_name, env, binary_fd, run_bounded))
            self.assertTrue(Path(evidence, "frame-ipv4.bin").is_file())
            self.assertTrue(Path(evidence, "frame-ipv6.bin").is_file())
            Path(evidence, "softnet-dhcp-stdout.bin").write_bytes(payload)
            Path(evidence, "softnet-dhcp-stderr.bin").write_bytes(b"")
            return {"reportSummary": probe._report_summary(
                probe._validated_report(payload, b"", hashes))}

        try:
            harness._write_fake_tart(frames="both")
            harness._write_receipt()

            class FixedUuid:
                hex = "c" * 32

            with patch.multiple(fixture_canary, TART_BINARY_SHA256=harness.receipt["tartBinarySha256"],
                                CANARY_TIMEOUT=2, VM_READY_TIMEOUT=4, VM_READY_PROBE_TIMEOUT=0.2), \
                    patch.object(fixture_canary.uuid, "uuid4", return_value=FixedUuid()), \
                    patch.object(fixture_canary.shutil, "disk_usage",
                                 return_value=SimpleNamespace(free=200 * 1024**3)), \
                    patch.object(fixture_canary, "_prepare_softnet_dhcp",
                                 return_value=(probe, bundle, fd, binary)), \
                    patch.object(probe, "qualify", side_effect=fake_qualify):
                fixture_canary.qualify("prepared-macos15", harness.receipt_path, harness.evidence,
                                        tart=str(harness.tart), tart_home=harness.tart_home,
                                        softnet_dhcp_binary="fixture")
            self.assertEqual(len(calls), 1)
            self.assertEqual(calls[0][3], fd)
            with self.assertRaises(OSError):
                os.fstat(fd)
            saved = json.loads((harness.evidence / "offline-macos-vm-canary.json").read_text())
            self.assertEqual(saved["status"], "passed")
            self.assertEqual(saved["softnetDhcp"]["binarySha256"], probe.BINARY_SHA256)
            self.assertEqual(saved["softnetDhcp"]["reportSummary"]["kind"], probe.REPORT_KIND)
            self.assertEqual(saved["rawEvidence"]["softnet-dhcp-stdout.bin"]["bytes"], len(payload))
            self.assertEqual((harness.evidence / "softnet-dhcp-stderr.bin").read_bytes(), b"")
            self.assertTrue(any(command[1:3] == ["exec", "-i"]
                                for command in saved["hostCommandTemplates"] if len(command) > 2))
        finally:
            source.close()
            harness.tearDown()

    def test_near_limit_guest_logs_keep_full_raw_report_and_bounded_manifest(self):
        from test_offline_macos_vm import OfflineMacosVmCanaryTest, canary as fixture_canary

        harness = OfflineMacosVmCanaryTest()
        harness.setUp()
        helper_path = harness.root / "softnet-helper"
        helper = b"pinned fixture helper"
        helper_path.write_bytes(helper)
        os.chmod(helper_path, 0o600)
        digest = hashlib.sha256(helper).hexdigest()
        bundle = probe.build_bundle()
        report = report_for(bundle["sourceSha256"], digest)
        report["logs"] = {name: blob(bytes((index + 1,)) * probe.MAX_LOG_BYTES)
                           for index, name in enumerate(("stdout", "stderr"))}
        report["diagnostics"][-1]["observation"] = "x" * (11 * 1024)
        self.assertGreater(probe._diagnostics_metadata(report["diagnostics"])["bytes"], 11 * 1024)
        payload = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
        self.assertLessEqual(len(payload), probe.MAX_OUTPUT_BYTES)
        calls = []
        real_runner = fixture_canary._run_bounded

        def run_bounded(argv, **kwargs):
            if probe.LOADER in argv:
                calls.append(argv)
                for path, data in zip(kwargs["capture_paths"], (payload, b"")):
                    Path(path).write_bytes(data)
                return payload, b""
            return real_runner(argv, **kwargs)

        try:
            harness._write_fake_tart(frames="both")
            harness._write_receipt()

            class FixedUuid:
                hex = "c" * 32

            with patch.multiple(fixture_canary, TART_BINARY_SHA256=harness.receipt["tartBinarySha256"],
                                CANARY_TIMEOUT=2, VM_READY_TIMEOUT=4, VM_READY_PROBE_TIMEOUT=0.2), \
                    patch.object(fixture_canary.uuid, "uuid4", return_value=FixedUuid()), \
                    patch.object(fixture_canary.shutil, "disk_usage",
                                 return_value=SimpleNamespace(free=200 * 1024**3)), \
                    patch.object(probe, "BINARY_SHA256", digest):
                summary = fixture_canary.qualify("prepared-macos15", harness.receipt_path,
                                                 harness.evidence, tart=str(harness.tart),
                                                 tart_home=harness.tart_home,
                                                 softnet_dhcp_binary=helper_path,
                                                 run_bounded=run_bounded)

            saved = harness._assert_published_summary(summary)
            manifest_path = harness.evidence / "offline-macos-vm-canary.json"
            self.assertEqual(saved["status"], "passed", saved)
            self.assertLess(manifest_path.stat().st_size, fixture_canary.MAX_SHORT_OUTPUT)
            self.assertEqual(len(calls), 1)
            softnet = saved["softnetDhcp"]
            self.assertEqual(softnet["rawReport"], {
                "file": "softnet-dhcp-stdout.bin", "maxBytes": probe.MAX_OUTPUT_BYTES})
            compact = softnet["reportSummary"]
            self.assertNotIn("base64", json.dumps(compact))
            self.assertEqual(compact["diagnostics"], probe._diagnostics_metadata(report["diagnostics"]))
            self.assertNotIn("observation", json.dumps(compact))
            self.assertEqual(compact["logs"], {
                name: {"bytes": probe.MAX_LOG_BYTES, "sha256": hashlib.sha256(
                    bytes((index + 1,)) * probe.MAX_LOG_BYTES).hexdigest()}
                for index, name in enumerate(("stdout", "stderr"))})
            for exchange_summary, exchange in zip(compact["exchanges"], report["exchanges"]):
                self.assertEqual(exchange_summary["clientIdBase64"], exchange["clientIdBase64"])
                self.assertEqual(exchange_summary["xid"], exchange["xid"])
                self.assertEqual(exchange_summary["yiaddr"], exchange["yiaddr"])
                self.assertEqual(exchange_summary["serverId"], exchange["serverId"])
                self.assertEqual(exchange_summary["offerLeaseSeconds"], exchange["offerLeaseSeconds"])
                self.assertEqual(exchange_summary["leaseSeconds"], exchange["leaseSeconds"])
                self.assertEqual(exchange_summary["frames"], [
                    {"bytes": frame["bytes"], "sha256": frame["sha256"]}
                    for frame in exchange["frames"]])
            raw_report = (harness.evidence / "softnet-dhcp-stdout.bin").read_bytes()
            raw_record = saved["rawEvidence"]["softnet-dhcp-stdout.bin"]
            self.assertEqual(raw_report, payload)
            self.assertEqual(raw_record["bytes"], len(payload))
            self.assertEqual(raw_record["sha256"], hashlib.sha256(payload).hexdigest())
        finally:
            harness.tearDown()

    def test_invalid_opt_in_binary_fails_before_clone(self):
        from test_offline_macos_vm import OfflineMacosVmCanaryTest, canary as fixture_canary

        harness = OfflineMacosVmCanaryTest()
        harness.setUp()
        try:
            run = unittest.mock.Mock()
            with patch.object(fixture_canary, "TART_BINARY_SHA256", harness.receipt["tartBinarySha256"]), \
                    patch.object(fixture_canary, "_tart_identity", return_value=harness.tart), \
                    patch.object(fixture_canary, "_base_vm_measurement", return_value=(None, 1)), \
                    patch.object(fixture_canary.shutil, "disk_usage", return_value=SimpleNamespace(free=10**12)), \
                    patch.object(fixture_canary, "_prepare_softnet_dhcp",
                                 side_effect=fixture_canary.CanaryError("softnet_dhcp_binary_digest_mismatch")):
                popen = unittest.mock.Mock(side_effect=AssertionError("clone launch reached"))
                with self.assertRaisesRegex(fixture_canary.CanaryError, "softnet_dhcp_binary_digest_mismatch"):
                    fixture_canary.qualify("prepared-macos15", harness.receipt_path, harness.evidence,
                                   tart=str(harness.tart), tart_home=harness.tart_home, popen=popen,
                                   softnet_dhcp_binary="fixture", run_bounded=run)
            run.assert_not_called()
            popen.assert_not_called()
        finally:
            harness.tearDown()

    def test_cli_flag_is_opt_in_and_forwards_only_a_local_path(self):
        args = ["--base-vm", "prepared", "--receipt", "receipt.json", "--evidence-dir", "evidence"]
        summary = {"kind": "offline-macos-vm-boundary-canary-v1", "status": "passed"}
        with patch.object(canary, "qualify", return_value=summary) as qualify:
            self.assertEqual(canary.main(args), 0)
        self.assertNotIn("softnet_dhcp_binary", qualify.call_args.kwargs)
        with patch.object(canary, "qualify", return_value=summary) as qualify, redirect_stdout(StringIO()):
            self.assertEqual(canary.main([*args, "--softnet-dhcp-binary", "/private/tmp/helper"]), 0)
        self.assertEqual(qualify.call_args.kwargs["softnet_dhcp_binary"], Path("/private/tmp/helper"))
        with self.assertRaisesRegex(canary.CanaryError, "invalid_softnet_dhcp_binary_path"):
            canary._validate_softnet_dhcp_flag(1)


if __name__ == "__main__":
    unittest.main()
