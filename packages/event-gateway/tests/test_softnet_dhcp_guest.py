import base64
import hashlib
import ipaddress
import os
import plistlib
import signal
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import qualify_softnet_dhcp_guest as guest


MAC = guest.MAC
SERVER = "192.0.2.1"
ASSIGNED = "192.0.2.44"


def _checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _reply(xid, kind, client_mac=MAC, yiaddr=ASSIGNED, server=SERVER, lease=600):
    options = (b"\x35\x01" + bytes((kind,)) + b"\x33\x04" + struct.pack("!I", lease)
               + b"\x36\x04" + ipaddress.IPv4Address(server).packed + b"\xff")
    bootp = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, xid, 0, 0,
                        b"\0" * 4, ipaddress.IPv4Address(yiaddr).packed, b"\0" * 4, b"\0" * 4,
                        client_mac + b"\0" * 10, b"\0" * 64, b"\0" * 128)
    bootp += b"\x63\x82\x53\x63" + options
    udp = struct.pack("!HHHH", 67, 68, 8 + len(bootp), 0) + bootp
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     ipaddress.IPv4Address(server).packed, b"\xff" * 4)
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x01\x08\x00" + ip + udp


class Peer:
    def __init__(self):
        """Queue deterministic DHCP replies for the fixed MAC and 600-second lease."""
        self.incoming = []
        self.drop_next = False
        self.offer_lease = 600
        self.offer_yiaddr = ASSIGNED
        self.ack_yiaddr = ASSIGNED

    def send(self, frame):
        if self.drop_next:
            self.drop_next = False
            return
        xid = struct.unpack_from("!I", frame, 42 + 4)[0]
        options = frame[14 + 20 + 8 + 240:]
        kind = options[2]
        self.incoming.append(_reply(xid, 2 if kind == 1 else 5,
                                    yiaddr=self.offer_yiaddr if kind == 1 else self.ack_yiaddr,
                                    lease=self.offer_lease if kind == 1 else 600))

    def recv(self, _size):
        if not self.incoming:
            raise socket.timeout()
        return self.incoming.pop(0)

    def settimeout(self, _timeout):
        pass

    def close(self):
        pass


class DuplicateOfferPeer(Peer):
    def __init__(self, *, server=SERVER, malformed=False):
        """Queue a duplicate OFFER before its ACK, optionally malformed."""
        super().__init__()
        self.stale_server = server
        self.malformed = malformed

    def send(self, frame):
        options = frame[14 + 20 + 8 + 240:]
        kind = options[2]
        super().send(frame)
        if kind == 3:
            ack = self.incoming.pop()
            xid = struct.unpack_from("!I", frame, 42 + 4)[0]
            stale_offer = bytearray(_reply(xid, 2, server=self.stale_server))
            if self.malformed:
                stale_offer[24] ^= 1
            self.incoming.extend((bytes(stale_offer), ack))


class Process:
    def __init__(self):
        """Track the fake helper exit and its output pipe descriptors."""
        self.pid = 999999
        self.returncode = None
        self.wait_result = 0
        self.signals = []
        self.stdout, out = os.pipe()
        self.stderr, err = os.pipe()
        os.close(out)
        os.close(err)

    def send_signal(self, value):
        self.signals.append(value)

    def wait(self, timeout=None):
        self.returncode = self.wait_result
        return self.wait_result


class Endpoint:
    def close(self):
        pass


def _logs(process, errors, result):
    directory = Path(result["_dir"])
    entries = {}
    for label in ("stdout", "stderr"):
        raw = b"fake " + label.encode()
        name = "tart-" + label + ".bin"
        (directory / name).write_bytes(raw)
        entries[label] = {"bytesObserved": len(raw), "bytesRetained": len(raw),
                          "sha256": hashlib.sha256(raw).hexdigest(), "file": name}
    entries["maxBytesPerStream"] = guest.canary.MAX_SHORT_OUTPUT
    result["tartRunLogs"] = entries
    os.close(process.stdout)
    os.close(process.stderr)


class GuestQualificationTests(unittest.TestCase):
    def _patch_run(self, **extra):
        process = Process()
        peer = Peer()
        patches = [patch.object(guest, "_environment", return_value=True),
                   patch.object(guest, "_binary", return_value="a" * 64),
                   patch.object(guest, "_target_readback", return_value=True),
                   patch.object(guest.socket, "socketpair", return_value=(peer, Endpoint())),
                   patch.object(guest.subprocess, "Popen", return_value=process),
                   patch.object(guest, "_drain", side_effect=_logs),
                   patch.object(guest.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=501, pw_gid=20)),
                   patch.object(guest.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=20)),
                   patch.object(guest.os, "killpg")]
        diagnostic = patch.object(guest, "_diagnostic_snapshot",
                                  side_effect=lambda phase: {"phase": phase, "marker": "fake"})
        diagnostic.start()
        self.addCleanup(diagnostic.stop)
        patches.extend(extra.values())
        return process, peer, patches

    def test_two_fixed_exchanges_and_logs_pass_with_fake_helper(self):
        process, _peer, patches = self._patch_run()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8] as killpg:
            report = guest.qualify_guest_dhcp("/fresh/root/private/softnet")
        self.assertEqual(report["kind"], "softnet-guest-dhcp-qualification-v1")
        self.assertEqual(set(report["sourceSha256"]), {"qualify_softnet_dhcp_guest.py", "dhcp_probe_frames.py",
                                                        "softnet_preferences.py", "qualify_offline_macos_vm.py"})
        self.assertEqual(report["status"], "passed")
        self.assertTrue(report["dhcpQualified"])
        self.assertFalse(report["fullNativeQualified"])
        self.assertTrue(report["checks"]["helperReaped"])
        self.assertIsNone(report["cleanupFailure"])
        self.assertEqual([item["leaseSeconds"] for item in report["exchanges"]], [600, 600])
        self.assertEqual([item["offerLeaseSeconds"] for item in report["exchanges"]], [600, 600])
        self.assertEqual(report["exchanges"][0]["yiaddr"], report["exchanges"][1]["yiaddr"])
        self.assertEqual([item["clientIdBase64"] for item in report["exchanges"]],
                         ["AGtuaXRsaS1zb2Z0bmV0LWE=", "AGtuaXRsaS1zb2Z0bmV0LWI="])
        frames = [frame for exchange in report["exchanges"] for frame in exchange["frames"]]
        self.assertEqual(len(frames), 8)
        self.assertTrue(all(0 < frame["bytes"] <= 2048 and len(frame["base64"]) <= 2732
                            and len(frame["sha256"]) == 64 for frame in frames))
        self.assertEqual(killpg.call_args_list, [call(process.pid, signal.SIGTERM)])
        self.assertEqual(set(report["logs"]), {"stdout", "stderr"})
        self.assertEqual([item["phase"] for item in report["diagnostics"]],
                         ["before_helper", "helper_ready", "after_exchange"])
        self.assertTrue(all(item["bytes"] == len(__import__("base64").b64decode(item["base64"]))
                            and len(item["sha256"]) == 64 for item in report["logs"].values()))
        self.assertIsNone(report["cleanupFailure"])

    def test_client_id_address_mismatch_stays_failed_with_last_diagnostic(self):
        _process, _peer, patches = self._patch_run()
        first = {"clientIdBase64": base64.b64encode(b"\x00knitli-softnet-a").decode("ascii"),
                 "yiaddr": "192.0.2.2",
                 "leaseSeconds": 600, "offerLeaseSeconds": 600}
        second = {"clientIdBase64": base64.b64encode(b"\x00knitli-softnet-b").decode("ascii"),
                  "yiaddr": "192.0.2.3",
                  "leaseSeconds": 600, "offerLeaseSeconds": 600}
        patches.append(patch.object(guest, "_exchange", side_effect=[first, second]))
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], \
             patches[8], patches[9]:
            report = guest.qualify_guest_dhcp("/fresh/root/private/softnet")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["failureCode"], "dhcp_behavior")
        self.assertTrue(report["checks"]["exchanges"])
        self.assertTrue(report["checks"]["lease"])
        self.assertFalse(report["checks"]["clientIdBehavior"])
        self.assertEqual([item["yiaddr"] for item in report["exchanges"]], ["192.0.2.2", "192.0.2.3"])
        self.assertEqual([item["phase"] for item in report["diagnostics"]],
                         ["before_helper", "helper_ready", "after_exchange"])

    def test_diagnostic_files_distinguish_missing_oversize_malformed_and_selected_types(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.plist"
            self.assertEqual(guest._diagnostic_config(str(missing)), {"status": "missing"})
            oversized = Path(directory) / "oversized.plist"
            oversized.write_bytes(b"x" * (guest.DIAGNOSTIC_MAX_BYTES + 1))
            self.assertEqual(guest._diagnostic_config(str(oversized)), {"status": "oversize"})
            malformed = Path(directory) / "malformed.plist"
            malformed.write_bytes(b"not a plist")
            malformed_result = guest._diagnostic_config(str(malformed))
            self.assertEqual(malformed_result["status"], "malformed")
            self.assertEqual(malformed_result["bytes"], len(b"not a plist"))
            self.assertEqual(malformed_result["sha256"], hashlib.sha256(b"not a plist").hexdigest())
            typed = Path(directory) / "typed.plist"
            typed.write_bytes(plistlib.dumps({"dhcp_ignore_client_identifier": 1,
                                              "DHCPLeaseTimeSecs": True, "unknown": "private"}))
            selected = guest._diagnostic_config(str(typed))["selected"]
            self.assertEqual(selected["dhcp_ignore_client_identifier"], {"status": "int", "value": 1})
            self.assertEqual(selected["DHCPLeaseTimeSecs"], {"status": "bool", "value": True})
            self.assertEqual(guest._diagnostic_selected({}, "DHCPLeaseTimeSecs"), {"status": "absent"})
            unsupported = guest._diagnostic_selected({"dhcp_ignore_client_identifier": "private"},
                                                     "dhcp_ignore_client_identifier")
            self.assertEqual(unsupported, {"status": "unsupported"})

    def test_diagnostic_collector_error_does_not_replace_exchange_failure(self):
        _process, _peer, patches = self._patch_run()
        patches.append(patch.object(guest, "_exchange", side_effect=ValueError("dhcp_deadline")))
        with patch.object(guest, "_diagnostic_snapshot", side_effect=OSError("private diagnostic failure")), \
             patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], \
             patches[8], patches[9]:
            report = guest.qualify_guest_dhcp("/fresh/root/private/softnet")
        self.assertEqual(report["failureCode"], "dhcp_deadline")
        self.assertEqual([item["status"] for item in report["diagnostics"]],
                         ["collector_failed", "collector_failed", "collector_failed"])

    def test_bootpd_diagnostic_uses_fixed_bounded_command_and_validates_pids(self):
        with patch.object(guest.canary, "_run_bounded",
                          side_effect=[(b" 123 /usr/libexec/bootpd\n 124 bootpd-helper\n", b""),
                                       (b"/usr/libexec/bootpd -f /etc/bootpd.plist", b"")]) as run_bounded:
            self.assertEqual(guest._diagnostic_bootpd(),
                             {"status": "running", "pids": [{"pid": 123, "configArgument": "etc"}]})
        self.assertEqual(run_bounded.call_args_list, [
            call(["/bin/ps", "-A", "-o", "pid=,comm="], timeout=0.75,
                 env=guest.ENV, output_limit=32 * 1024),
            call(["/bin/ps", "-ww", "-p", "123", "-o", "args="], timeout=0.75,
                 env=guest.ENV, output_limit=2048),
        ])

    def test_bootpd_diagnostic_without_matching_process_reports_none(self):
        with patch.object(guest.canary, "_run_bounded", return_value=(b" 123 launchd\n 124 helper\n", b"")) as run_bounded:
            self.assertEqual(guest._diagnostic_bootpd(), {"status": "none", "pids": []})
        run_bounded.assert_called_once_with(["/bin/ps", "-A", "-o", "pid=,comm="], timeout=0.75,
                                            env=guest.ENV, output_limit=32 * 1024)

    def test_bootpd_config_argument_reports_only_allowlisted_labels(self):
        for argv, label in (
                (["bootpd", "-f", "/etc/bootpd.plist"], "etc"),
                (["bootpd", "-f/Library/Preferences/SystemConfiguration/bootpd.plist"], "systemConfiguration"),
                (["bootpd", "-f", "/opt/knitli-fixtures/other-bootpd.plist"], "other"),
                (["bootpd", "-frelative.plist"], "other"),
                (["bootpd", "-df/etc/bootpd.plist"], "unclassified"),
                (["bootpd"], "none_observed"),
                (["bootpd", "-f"], "unclassified")):
            with self.subTest(argv=argv):
                self.assertEqual(guest._diagnostic_config_argument(argv), label)
        with patch.object(guest.canary, "_run_bounded", side_effect=[
                (b"123 bootpd", b""), (b"bootpd -f 'unterminated", b"")]):
            process = guest._diagnostic_bootpd()
        self.assertEqual(process["pids"][0]["configArgument"], "unclassified")
        self.assertEqual(process["pids"][0]["configStatus"], "command_error")
        with patch.object(guest.canary, "_run_bounded", side_effect=[
                (b"123 bootpd", b""), (b"/usr/libexec/other -f /etc/bootpd.plist", b"")]):
            changed = guest._diagnostic_bootpd()
        self.assertEqual(changed["pids"][0],
                         {"pid": 123, "configArgument": "unclassified", "configStatus": "process_changed"})

    def test_environment_failure_precedes_binary_preferences_and_launch(self):
        calls = []
        with patch.object(guest, "_environment", side_effect=lambda: (_ for _ in ()).throw(ValueError("environment_gate"))), \
             patch.object(guest, "_binary", side_effect=lambda _path: calls.append("binary")), \
             patch.object(guest, "_target_readback", side_effect=lambda: calls.append("prefs")), \
             patch.object(guest.subprocess, "Popen", side_effect=lambda *a, **k: calls.append("launch")):
            report = guest.qualify_guest_dhcp("/nope")
        self.assertEqual(report["failureCode"], "environment_gate")
        self.assertEqual(calls, [])
        self.assertFalse(report["checks"]["environment"])

    def test_failed_readback_stays_failed_after_reap_and_complete_logs(self):
        process, _peer, patches = self._patch_run()
        patches[2] = patch.object(guest, "_target_readback", side_effect=ValueError("helper_target_readback"))
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8] as killpg:
            report = guest.qualify_guest_dhcp("/fresh/root/private/softnet")
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["dhcpQualified"])
        self.assertEqual(report["failureCode"], "helper_target_readback")
        self.assertTrue(report["checks"]["helperReaped"])
        self.assertTrue(report["checks"]["logsComplete"])
        self.assertEqual(killpg.call_args_list, [call(process.pid, signal.SIGTERM)])

    def test_shutdown_escalates_only_after_timeout(self):
        process = Process()
        wait_attempts = []

        def wait(timeout=None):
            wait_attempts.append(timeout)
            if len(wait_attempts) == 1:
                raise guest.subprocess.TimeoutExpired("helper", timeout)
            process.returncode = 0
            return 0

        process.wait = wait
        calls = []
        original_wait = process.wait

        def ordered_wait(timeout=None):
            calls.append(("wait", timeout))
            return original_wait(timeout)

        process.wait = ordered_wait
        with patch.object(guest.os, "killpg", side_effect=lambda pid, sig: calls.append(("signal", sig))):
            self.assertEqual(guest._stop(process), (0, (signal.SIGTERM, signal.SIGKILL)))
        self.assertEqual(calls, [("signal", signal.SIGTERM), ("wait", 2),
                                 ("signal", signal.SIGKILL), ("wait", 3)])

    def test_expected_controlled_signal_exit_is_not_cleanup_failure(self):
        process = Process()
        process.wait_result = -signal.SIGTERM
        report = guest._report()
        temp = SimpleNamespace(name="unused", cleanup=lambda: None)
        with patch.object(guest.os, "killpg"), patch.object(guest, "_collect_logs"):
            guest._cleanup(process, None, temp, {}, [], report)
        self.assertTrue(report["checks"]["helperReaped"])
        self.assertTrue(report["checks"]["logsComplete"])
        self.assertIsNone(report["cleanupFailure"])

    def test_unexpected_helper_crash_is_preserved(self):
        process = Process()
        process.wait_result = -signal.SIGSEGV
        report = guest._report()
        temp = SimpleNamespace(name="unused", cleanup=lambda: None)
        with patch.object(guest.os, "killpg"), patch.object(guest, "_collect_logs"):
            guest._cleanup(process, None, temp, {}, [], report)
        self.assertTrue(report["checks"]["helperReaped"])
        self.assertEqual(report["cleanupFailure"], "helper_nonzero_exit")

    def test_temp_cleanup_error_returns_fixed_cleanup_failure(self):
        process = Process()

        def fail_cleanup():
            raise OSError("private temp detail")

        report = guest._report()
        temp = SimpleNamespace(name="unused", cleanup=fail_cleanup)
        with patch.object(guest.os, "killpg"), patch.object(guest, "_collect_logs"):
            guest._cleanup(process, None, temp, {}, [], report)
        self.assertEqual(report["cleanupFailure"], "temp_cleanup_failed")
        self.assertTrue(report["checks"]["helperReaped"])

    def test_typed_readback_retries_only_busy_lock_in_fresh_sessions(self):
        opened = []

        class Prefs:
            def __init__(self):
                opened.append(self)

            def __enter__(self):
                if len(opened) == 1:
                    raise guest.PreferencesError("preferences_lock_failed:3002:busy")
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b"typed"

            def encode_target(self):
                return b"typed"

            def equal(self, left, right):
                return left == right

        with patch.object(guest, "Preferences", Prefs), patch.object(guest.time, "sleep") as sleep, \
             patch.object(guest.time, "monotonic", side_effect=(0, 0, 0, 8)):
            self.assertTrue(guest._target_readback())
        self.assertEqual(len(opened), 2)
        sleep.assert_called_once()

    def test_target_mismatch_retries_fresh_reads_until_target_appears(self):
        opened = []

        class Prefs:
            def __init__(self):
                opened.append(self)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b"current"

            def encode_target(self):
                return b"target"

            def equal(self, actual, expected):
                return len(opened) > 1

        with patch.object(guest, "Preferences", Prefs), patch.object(guest.time, "sleep") as sleep, \
             patch.object(guest.time, "monotonic", side_effect=(0, 0, 0, 8)):
            self.assertTrue(guest._target_readback())
        self.assertEqual(len(opened), 2)
        sleep.assert_called_once()

    def test_busy_lock_timeout_has_stable_readback_failure(self):
        class Prefs:
            def __enter__(self):
                raise guest.PreferencesError("preferences_lock_failed:3002:busy")

            def __exit__(self, *_args):
                return False

        ticks = iter((0, 0, 0, 8))
        with patch.object(guest, "Preferences", Prefs), \
             patch.object(guest.time, "monotonic", side_effect=lambda: next(ticks)), \
             patch.object(guest.time, "sleep"):
            with self.assertRaisesRegex(ValueError, "helper_target_readback"):
                guest._target_readback()

    def test_target_mismatch_times_out_with_fixed_mismatch_code(self):
        class Prefs:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b"old"

            def encode_target(self):
                return b"new"

            def equal(self, _actual, _expected):
                return False

        ticks = iter((0, 0, 0, 8))
        with patch.object(guest, "Preferences", Prefs), \
             patch.object(guest.time, "monotonic", side_effect=lambda: next(ticks)), \
             patch.object(guest.time, "sleep"):
            with self.assertRaisesRegex(ValueError, "helper_target_mismatch"):
                guest._target_readback()

    def test_readback_does_not_retry_nonbusy_preference_errors(self):
        calls = []

        class Prefs:
            def __init__(self):
                calls.append(1)

            def __enter__(self):
                raise guest.PreferencesError("preferences_lock_failed:5:denied")

            def __exit__(self, *_args):
                return False

        with patch.object(guest, "Preferences", Prefs):
            with self.assertRaisesRegex(ValueError, "helper_target_readback"):
                guest._target_readback()
        self.assertEqual(calls, [1])

    def test_receive_rejects_offer_from_wrong_selected_server(self):
        peer = Peer()
        peer.incoming = [_reply(7, 2, server="192.0.2.9")]
        with self.assertRaisesRegex(ValueError, "unexpected server"):
            guest._receive(peer, MAC, 7, 2, SERVER, guest.time.monotonic() + 1,
                           {"sent": 0, "received": 0}, [])

    def test_frame_record_carries_independently_checkable_measurements(self):
        frame = b"sent frame"
        record = guest._frame_record(frame)
        self.assertEqual(record["bytes"], len(frame))
        self.assertEqual(record["sha256"], hashlib.sha256(frame).hexdigest())
        self.assertEqual(__import__("base64").b64decode(record["base64"]), frame)

    def test_environment_gate_rejects_nonroot_before_platform_checks(self):
        with patch.object(guest.os, "geteuid", return_value=501):
            with self.assertRaisesRegex(ValueError, "environment_gate"):
                guest._environment()

    def test_binary_gate_rejects_symlink(self):
        self.assertEqual(guest.MAX_BINARY_BYTES, 64 * 1024**2)
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.write_bytes(b"not helper")
            link = Path(directory) / "helper"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "binary_path"):
                guest._binary(link)

    def test_receive_retry_retransmits_once_then_accepts(self):
        peer = Peer()
        peer.drop_next = True
        records = []
        counters = {"sent": 0, "received": 0}
        result = guest._exchange(peer, guest.CLIENT_IDS[0], counters, records,
                                 guest.time.monotonic() + 2)
        self.assertEqual(result["leaseSeconds"], 600)
        self.assertEqual(counters["sent"], 3)
        self.assertEqual(len(records), 4)

    def test_two_exchanges_keep_canonical_frames_when_one_retries(self):
        peer = Peer()
        peer.drop_next = True
        frames = []
        counters = {"sent": 0, "received": 0}
        deadline = guest.time.monotonic() + 15
        first = guest._exchange(peer, guest.CLIENT_IDS[0], counters, frames, deadline)
        peer.drop_next = True
        second = guest._exchange(peer, guest.CLIENT_IDS[1], counters, frames, deadline)
        self.assertEqual(len(first["frames"]), 4)
        self.assertEqual(len(second["frames"]), 4)
        self.assertEqual(len(frames), 8)
        self.assertEqual(counters["sent"], 6)

    def test_duplicate_offer_before_ack_is_ignored_and_counted(self):
        peer = DuplicateOfferPeer()
        counters = {"sent": 0, "received": 0}
        records = []
        result = guest._exchange(peer, guest.CLIENT_IDS[0], counters, records,
                                 guest.time.monotonic() + 2)
        self.assertEqual(result["leaseSeconds"], 600)
        self.assertEqual(counters, {"sent": 2, "received": 3})
        self.assertEqual(len(result["frames"]), 4)

    def test_real_drainer_metadata_flows_through_log_collector(self):
        out_read, out_write = os.pipe()
        err_read, err_write = os.pipe()
        os.write(out_write, b"drained stdout")
        os.write(err_write, b"drained stderr")
        os.close(out_write)
        os.close(err_write)
        process = SimpleNamespace(pid=999999, stdout=os.fdopen(out_read, "rb"),
                                  stderr=os.fdopen(err_read, "rb"))
        errors = []
        with tempfile.TemporaryDirectory() as directory:
            drained = {"_dir": directory}
            guest._drain(process, errors, drained)
            report = {"logs": {}}
            guest._collect_logs(SimpleNamespace(name=directory), drained, report)
            self.assertEqual(errors, [])
            self.assertEqual(set(drained["tartRunLogs"]),
                             {"stdout", "stderr", "maxBytesPerStream"})
            self.assertEqual(report["logs"]["stdout"]["bytes"], len(b"drained stdout"))
            self.assertEqual(report["logs"]["stderr"]["bytes"], len(b"drained stderr"))

    def test_wrong_server_and_malformed_stale_offers_fail(self):
        for peer, message in ((DuplicateOfferPeer(server="192.0.2.9"), "unexpected server"),
                              (DuplicateOfferPeer(malformed=True), "checksum")):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                guest._exchange(peer, guest.CLIENT_IDS[0], {"sent": 0, "received": 0}, [],
                                guest.time.monotonic() + 2)

    def test_exchange_rejects_ack_address_that_changes_offer(self):
        peer = Peer()
        peer.ack_yiaddr = "192.0.2.55"
        with self.assertRaisesRegex(ValueError, "dhcp_behavior"):
            guest._exchange(peer, guest.CLIENT_IDS[0], {"sent": 0, "received": 0}, [],
                            guest.time.monotonic() + 2)

    def test_offer_lease_is_retained_for_final_lease_qualification(self):
        peer = Peer()
        peer.offer_lease = 599
        result = guest._exchange(peer, guest.CLIENT_IDS[0], {"sent": 0, "received": 0}, [],
                                 guest.time.monotonic() + 2)
        self.assertEqual(result["offerLeaseSeconds"], 599)

    def test_qualification_rejects_short_offer_lease(self):
        _process, peer, patches = self._patch_run()
        peer.offer_lease = 599
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], patches[8]:
            report = guest.qualify_guest_dhcp("/fresh/root/private/softnet")
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["checks"]["lease"])
        self.assertEqual(report["failureCode"], "dhcp_behavior")

    def test_partial_completed_exchange_survives_second_exchange_failure(self):
        _process, _peer, patches = self._patch_run()
        first = {"clientIdBase64": "first", "yiaddr": ASSIGNED, "leaseSeconds": 600}
        patches.append(patch.object(guest, "_exchange", side_effect=[first, ValueError("dhcp_deadline")]))
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7], \
             patches[8], patches[9]:
            report = guest.qualify_guest_dhcp("/fresh/root/private/softnet")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["failureCode"], "dhcp_deadline")
        self.assertEqual(report["exchanges"], [first])

    def test_pass_gate_keeps_operation_failure_sticky_with_all_checks_true(self):
        report = guest._report()
        report["checks"] = {name: True for name in report["checks"]}
        self.assertFalse(guest._qualified(report, operation_failed=True))
        self.assertTrue(guest._qualified(report, operation_failed=False))

    def test_failure_code_is_fixed_and_does_not_echo_exception(self):
        self.assertEqual(guest._failure_code(ValueError("helper_group"), "helper_launch"), "helper_group")
        self.assertEqual(guest._failure_code(ValueError("private detail"), "dhcp_exchange"), "dhcp_exchange")

    def test_sys_platform_reports_runtime_platform(self):
        self.assertEqual(guest.sys_platform(), sys.platform)

    def test_launch_uses_only_fixed_helper_profile(self):
        process = Process()
        peer = Peer()
        with patch.object(guest.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=501, pw_gid=20)), \
             patch.object(guest.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=20)), \
             patch.object(guest.socket, "socketpair", return_value=(peer, Endpoint())), \
             patch.object(guest.subprocess, "Popen", return_value=process) as popen:
            actual, actual_peer = guest._launch("/root/private/softnet")
        self.assertIs(actual, process)
        self.assertIs(actual_peer, peer)
        self.assertEqual(popen.call_args.args[0], ["/root/private/softnet", "--vm-fd", "0",
                                                   "--vm-mac-address", guest.MAC_TEXT,
                                                   "--block=0.0.0.0/0", "--user", "admin", "--group", "staff"])
        self.assertEqual(popen.call_args.kwargs["env"], guest.ENV)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])

    def test_launch_rejects_unexpected_admin_identity(self):
        with patch.object(guest.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=0, pw_gid=20)), \
             patch.object(guest.socket, "socketpair") as socketpair:
            with self.assertRaisesRegex(ValueError, "helper_account"):
                guest._launch("/root/private/softnet")
        socketpair.assert_not_called()

    def test_log_collector_rejects_incomplete_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tart-stdout.bin"
            path.write_bytes(b"short")
            summary = {"bytesRetained": 5, "bytesObserved": 6, "sha256": "0" * 64,
                       "file": "tart-stdout.bin"}
            with self.assertRaisesRegex(ValueError, "logs_incomplete"):
                guest._collect_logs(SimpleNamespace(name=directory),
                                    {"tartRunLogs": {"stdout": summary, "stderr": summary, "maxBytesPerStream": guest.canary.MAX_SHORT_OUTPUT}}, {"logs": {}})

    def test_log_collector_rejects_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            data = b"same length"
            (Path(directory) / "tart-stdout.bin").write_bytes(data)
            (Path(directory) / "tart-stderr.bin").write_bytes(data)
            stdout = {"bytesRetained": len(data), "bytesObserved": len(data), "sha256": "0" * 64,
                      "file": "tart-stdout.bin"}
            stderr = {"bytesRetained": len(data), "bytesObserved": len(data),
                      "sha256": hashlib.sha256(data).hexdigest(), "file": "tart-stderr.bin"}
            with self.assertRaisesRegex(ValueError, "logs_incomplete"):
                guest._collect_logs(SimpleNamespace(name=directory),
                                    {"tartRunLogs": {"stdout": stdout, "stderr": stderr,
                                                     "maxBytesPerStream": guest.canary.MAX_SHORT_OUTPUT}}, {"logs": {}})

    def test_log_drainer_retains_and_hashes_both_bounded_streams(self):
        read_out, write_out = os.pipe()
        read_err, write_err = os.pipe()
        os.write(write_out, b"guest out")
        os.write(write_err, b"guest err")
        os.close(write_out)
        os.close(write_err)
        process = SimpleNamespace(pid=999999, stdout=os.fdopen(read_out, "rb"),
                                  stderr=os.fdopen(read_err, "rb"))
        errors = []
        with tempfile.TemporaryDirectory() as directory:
            result = {"_dir": directory}
            guest._drain(process, errors, result)
            self.assertEqual(errors, [])
            self.assertEqual(result["tartRunLogs"]["stdout"]["bytesObserved"], 9)
            self.assertEqual(result["tartRunLogs"]["stderr"]["bytesObserved"], 9)
            self.assertTrue((Path(directory) / "tart-stdout.bin").exists())

    def test_log_drainer_failure_is_sticky(self):
        errors = []
        with patch.object(guest.canary, "_drain_tart_logs", side_effect=OSError("private detail")):
            guest._drain(None, errors, {"_dir": "/unused"})
        self.assertEqual(errors, ["log_drainer_failed"])


if __name__ == "__main__":
    unittest.main()
