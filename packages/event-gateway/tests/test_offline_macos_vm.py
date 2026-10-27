"""Unit and causal tests for the fixed offline Tart canary."""

import ast
from contextlib import redirect_stderr
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import socket
import stat
import subprocess  # nosec B404 -- subprocess calls target the fake Tart fixture, never a VM.
import sys
import tempfile
import signal
import time
import threading
import types
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "qualify_offline_macos_vm.py"
spec = importlib.util.spec_from_file_location("offline_macos_vm", SCRIPT)
canary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)


class GuestUnixSocketProbeTest(unittest.TestCase):
    def test_guest_unix_socket_probe_uses_private_directory_and_cleans_up(self):
        guest_tree = ast.parse(canary.GUEST_CANARY)
        function = next(node for node in guest_tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == "check_unix_socket")
        route_paths = [node.value for node in ast.walk(guest_tree)
                       if isinstance(node, ast.Constant) and node.value in {"/sbin/route", "/usr/sbin/route"}]
        self.assertEqual(route_paths.count("/sbin/route"), 2)
        self.assertNotIn("/usr/sbin/route", route_paths)
        namespace = {"os": os, "socket": socket, "tempfile": tempfile}
        module_code = compile(ast.Module(body=[function], type_ignores=[]), "<guest-unix-probe>", "exec")
        function_code = next(
            constant for constant in module_code.co_consts
            if isinstance(constant, types.CodeType) and constant.co_name == function.name
        )
        unix_probe = types.FunctionType(function_code, namespace)
        bound_paths = []
        opened_sockets = []
        real_socket = socket.socket
        test_case = self

        class SocketProbe(real_socket):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                opened_sockets.append(self)

            def bind(self, address):
                parent = Path(address).parent
                test_case.assertTrue(parent.is_dir())
                test_case.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
                bound_paths.append(Path(address))
                super().bind(address)

            def accept(self):
                conn, address = super().accept()
                opened_sockets.append(conn)
                return conn, address

        namespace["socket"] = type("SocketModule", (), {
            "AF_UNIX": socket.AF_UNIX, "SOCK_STREAM": socket.SOCK_STREAM, "socket": SocketProbe,
        })
        try:
            unix_probe()
            self.assertEqual(len(bound_paths), 1)
            self.assertFalse(bound_paths[0].parent.exists())
            self.assertTrue(opened_sockets)
            self.assertTrue(all(sock.fileno() == -1 for sock in opened_sockets))
        finally:
            for sock in opened_sockets:
                sock.close()


TART_CONFIG = {"OS": "darwin", "CPU": 4, "Memory": 8192, "Disk": 50,
               "DiskFormat": "raw", "Size": "30.603", "Display": "1024x768",
               "MACAddress": "02:aa:bb:cc:dd:ee", "Running": False, "State": "stopped"}
TART_STOPPED_JSON = b'''{
  "Size" : "30.603",
  "Running" : false,
  "State" : "stopped",
  "DiskFormat" : "raw",
  "Disk" : 50,
  "MACAddress" : "02:aa:bb:cc:dd:ee",
  "Display" : "1024x768",
  "OS" : "darwin",
  "Memory" : 8192,
  "CPU" : 4
}'''
BASE_CONFIG = {"os": "darwin", "arch": "arm64", "macAddress": "02:aa:bb:cc:dd:ee",
               "cpuCount": 4, "memorySize": 8192 * 1024 * 1024, "diskFormat": "asif"}


class OfflineMacosVmCanaryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="offline-vm-test-")
        self.root = Path(self.temp.name)
        self.tart_home = self.root / "tart-home"
        self.tart_home.mkdir(mode=0o700)
        self.base_vm_dir = self.tart_home / "vms" / "prepared-macos15"
        self.base_vm_dir.mkdir(parents=True, mode=0o700)
        (self.base_vm_dir / "config.json").write_text(json.dumps(BASE_CONFIG, sort_keys=True))
        (self.base_vm_dir / "disk.img").write_bytes(b"prepared-disk-fixture" * 1024)
        (self.base_vm_dir / "nvram.bin").write_bytes(b"prepared-nvram-fixture")
        self.evidence = self.root / "evidence"
        self.evidence.mkdir(mode=0o700)
        os.chmod(self.evidence, 0o700)
        self.tart = self.root / "tart-fake"
        self._write_fake_tart()
        self.receipt_path = self.root / "base-receipt.json"
        self._write_receipt()

    def tearDown(self):
        self.temp.cleanup()

    def _write_receipt(self):
        config_bytes = (self.base_vm_dir / "config.json").read_bytes()
        disk_bytes = (self.base_vm_dir / "disk.img").read_bytes()
        nvram_bytes = (self.base_vm_dir / "nvram.bin").read_bytes()
        config_digest = canary._sha256(config_bytes)
        disk_digest = canary._sha256(disk_bytes)
        nvram_digest = canary._sha256(nvram_bytes)
        measurements = {"configSha256": config_digest, "configBytes": len(config_bytes),
                        "nvramSha256": nvram_digest, "nvramBytes": len(nvram_bytes)}
        self.receipt = {
            "kind": "offline-macos-vm-base-receipt-v1",
            "baseVmName": "prepared-macos15",
            "tartVersion": canary.TART_VERSION,
            "tartPackageSha256": canary.TART_PACKAGE_SHA256,
            "tartBinarySha256": canary._sha256(self.tart.read_bytes()),
            "ociBaseDigest": canary.OCI_BASE_DIGEST,
            "preparedSnapshot": {"sha256": disk_digest, "bytes": len(disk_bytes)},
            "storageMeasurement": measurements,
        }
        self.receipt_path.write_text(json.dumps(self.receipt))
        os.chmod(self.receipt_path, 0o600)

    def test_stopped_state_matches_captured_tart_json_exactly(self):
        self.assertTrue(canary._vm_stopped(TART_STOPPED_JSON))
        rejected = (
            {"Running": True, "State": "stopped"},
            {"Running": False, "State": "Stopped"},
            {"Running": True, "State": "running"},
            {"State": "stopped"},
            {"Running": False},
            [],
        )
        for value in rejected:
            with self.subTest(value=value):
                self.assertFalse(canary._vm_stopped(json.dumps(value)))

    def _write_fake_tart(self, *, frames="none", fail_delete=False, running_after_stop=False,
                         readiness=None, sleep_guest=0, runtime=None, partial_clone_failure=False):
        readiness = readiness or {}
        runtime = runtime or {}
        readiness_failures = readiness.get("failures", 0)
        readiness_delay_first = readiness.get("delay_first", 0)
        guest_version = runtime.get("product_version", "15.0.1")
        guest_arch = runtime.get("architecture", "arm64")
        sender = ""
        source_mac = "02:aa:bb:cc:dd:ef" if frames == "badmac" else "02:aa:bb:cc:dd:ee"
        marker4 = "x" * 32 if frames == "wrongnonce" else "c" * 32
        if frames in ("both", "ipv4", "badmac", "wrongnonce"):
            sender += (
                f'''peer.send(m._ethernet_udp("{source_mac}", "02:00:00:00:00:02", '''
                f'''"198.18.88.2", "203.0.113.7", 40000, 49371, ("OFFLINE_CANARY:" + "{marker4}" + "4").encode()))\n'''
            )
        if frames in ("both", "ipv6"):
            sender += (
                '''peer.send(m._ethernet_udp("02:aa:bb:cc:dd:ee", "02:00:00:00:00:02", '''
                '''"fd00:8888::2", "2001:db8::7", 40001, 49372, ("OFFLINE_CANARY:" + "c" * 32 + "6").encode()))\n'''
            )
        fake_config = {**TART_CONFIG, "Running": running_after_stop,
                       "State": "running" if running_after_stop else "stopped"}
        script = f'''#!{sys.executable}
import json, os, shutil, signal, socket, sys, time
root = {str(SCRIPT.parent)!r}
if sys.argv[1:] == ["--version"]:
    print("{canary.TART_VERSION}"); raise SystemExit
cmd = sys.argv[1]
if cmd == "get":
    print(json.dumps({fake_config!r}, separators=(",", ":"))); raise SystemExit
if cmd == "clone":
    shutil.copytree(os.path.join(os.environ["TART_HOME"], "vms", sys.argv[2]), os.path.join(os.environ["TART_HOME"], "vms", sys.argv[3]))
    if {partial_clone_failure!r}: raise SystemExit(1)
    raise SystemExit(0)
if cmd == "run":
    sys.path.insert(0, root)
    import qualify_offline_macos_vm as m
    fd = int(next(x.split("=", 1)[1] for x in sys.argv if x.startswith("--net-fd=")))
    peer = socket.socket(fileno=fd)
{''.join('    ' + line + '\n' for line in sender.rstrip().splitlines())}
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    while True: time.sleep(0.1)
if cmd == "stop":
    with open(os.path.join(os.environ["TART_HOME"], "stop-started"), "w") as stream: stream.write("stopping")
    raise SystemExit(0)
if cmd == "delete":
    if {fail_delete!r}: raise SystemExit(1)
    shutil.rmtree(os.path.join(os.environ["TART_HOME"], "vms", sys.argv[2]))
    raise SystemExit(0)
if cmd == "exec":
    if sys.argv[-1] == "/usr/bin/true":
        count_path = os.path.join(os.environ["TART_HOME"], "readiness-count")
        try: count = int(open(count_path).read())
        except FileNotFoundError: count = 0
        with open(count_path, "w") as stream: stream.write(str(count + 1))
        if count == 0: time.sleep({readiness_delay_first})
        if count < {readiness_failures}: raise SystemExit(1)
        raise SystemExit(0)
    nonce = sys.argv[-1]
    with open(os.path.join(os.environ["TART_HOME"], "guest-started"), "w") as stream: stream.write("started")
    time.sleep({sleep_guest})
    print(json.dumps({{"kind":"offline-macos-vm-guest-canary-v1", "nonce":nonce,
      "checks":{{k:True for k in ("loopback-ipv4","loopback-ipv6","unix-socket","nested-seatbelt","sent-ipv4","sent-ipv6")}},
      "runtime":{{"productVersion":{guest_version!r},"buildVersion":"24A5289h","architecture":{guest_arch!r}}}}}, separators=(",", ":")))
    raise SystemExit(0)
raise SystemExit(2)
'''
        self.tart.write_text(script)
        self.tart.chmod(0o700)

    def _run(self, *, free_space=200 * 1024**3, popen=None, probe_timeout=0.2):
        nonce_file = self.root / "nonce"

        class FixedUuid:
            hex = "c" * 32
        with patch.object(canary.uuid, "uuid4", return_value=FixedUuid()):
            nonce_file.write_text("c" * 32)
            with patch.dict(os.environ, {"CANARY_NONCE_FILE": str(nonce_file)}):
                with patch.multiple(canary, CANARY_TIMEOUT=2, VM_READY_TIMEOUT=4,
                                    VM_READY_PROBE_TIMEOUT=probe_timeout,
                                    TART_BINARY_SHA256=canary._sha256(self.tart.read_bytes())), patch.object(
                    canary.shutil, "disk_usage", return_value=type("Usage", (), {"free": free_space})()
                ):
                    return canary.qualify("prepared-macos15", self.receipt_path, self.evidence,
                                          tart=str(self.tart), tart_home=self.tart_home,
                                          **({"popen": popen} if popen is not None else {}))

    def qualify(self, base_vm="prepared-macos15"):
        with patch.object(canary, "TART_BINARY_SHA256", canary._sha256(self.tart.read_bytes())):
            return canary.qualify(base_vm, self.receipt_path, self.evidence,
                                  tart=str(self.tart), tart_home=self.tart_home)

    def test_missing_paths_return_stable_codes_without_disclosing_paths(self):
        missing_receipt = self.root / "private-receipt-not-found.json"
        with self.assertRaisesRegex(canary.CanaryError, "receipt_unavailable") as receipt_error:
            canary._read_receipt(missing_receipt)
        self.assertNotIn(str(missing_receipt), str(receipt_error.exception))
        with self.assertRaisesRegex(canary.CanaryError, "unsafe_evidence_directory"):
            canary._safe_dir(self.root / "evidence-not-found")
        with self.assertRaisesRegex(canary.CanaryError, "tart_not_executable"):
            canary._tart_identity(self.root / "tart-not-found", self.receipt, {})
        with self.assertRaisesRegex(canary.CanaryError, "unsafe_base_vm_file"):
            canary._hash_file(self.root / "base-file-not-found", maximum=1024)

        stderr = StringIO()
        with redirect_stderr(stderr):
            code = canary.main([
                "--base-vm", "prepared-macos15", "--receipt", str(missing_receipt),
                "--evidence-dir", str(self.evidence), "--tart", str(self.tart),
            ])
        self.assertEqual(code, 1)
        self.assertEqual(stderr.getvalue().strip(), "receipt_unavailable")
        self.assertNotIn(str(missing_receipt), stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_wait_timeout_is_normalized_and_process_is_reaped(self):
        class WaitTimeoutProcess:
            pid = 987654321

            def __init__(self):
                out_read, out_write = os.pipe()
                err_read, err_write = os.pipe()
                os.close(out_write)
                os.close(err_write)
                self.stdout = os.fdopen(out_read, "rb")
                self.stderr = os.fdopen(err_read, "rb")
                self.reaped = False

            def poll(self):
                return 0

            def wait(self, timeout=None):
                if timeout is not None:
                    raise subprocess.TimeoutExpired("fake-tart", timeout)
                self.reaped = True
                return -signal.SIGKILL

        process = WaitTimeoutProcess()
        with patch.object(canary.subprocess, "Popen", return_value=process), \
                patch.object(canary.os, "killpg", side_effect=ProcessLookupError):
            with self.assertRaisesRegex(canary.CanaryError, "tart_command_timeout"):
                canary._run_bounded(["fake-tart"], timeout=1, env={})
        self.assertTrue(process.reaped)

    def test_inherited_real_datagram_fd_and_fixed_drop_canary(self):
        self._write_fake_tart(frames="both", readiness={"failures": 2})
        self._write_receipt()
        result = self._run()
        self.assertEqual(result, None)
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "passed")
        self.assertEqual(saved["frames"]["hostReceived"], 2)
        self.assertEqual(saved["frames"]["hostTransmitted"], 0)
        self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
        self.assertEqual(saved["readinessProbe"]["command"], ["/usr/bin/true"])
        self.assertTrue(saved["readinessProbe"]["ready"])
        self.assertEqual(saved["readinessProbe"]["attempts"], 3)
        self.assertEqual(saved["hostCommandTemplates"].count(saved["readinessProbe"]["argv"]), 1)
        run_argv = next(argv for argv in saved["hostCommandTemplates"] if len(argv) > 1 and argv[1] == "run")
        self.assertTrue(any(argument.startswith("--net-fd=") for argument in run_argv))
        self.assertFalse(any(argument in {"--net-softnet", "--net-host", "--net-bridged"}
                             for argument in run_argv))
        self.assertEqual(saved["guestRuntime"], {"productVersion": "15.0.1", "buildVersion": "24A5289h", "architecture": "arm64"})
        self.assertIn("not independently bind", saved["ociProvenance"])
        self.assertEqual(set(saved["frames"]["matched"]), {"ipv4", "ipv6"})
        self.assertEqual(saved["guestOutput"]["scriptSha256"], canary._sha256(canary.GUEST_CANARY.encode()))
        self.assertEqual(saved["rawEvidence"]["guest-stdout.bin"]["sha256"],
                         canary._sha256((self.evidence / "guest-stdout.bin").read_bytes()))
        self.assertEqual((self.evidence / "tart-stdout.bin").stat().st_mode & 0o777, 0o600)
        for family in ("ipv4", "ipv6"):
            frame_path = self.evidence / f"frame-{family}.bin"
            self.assertEqual(canary._sha256(frame_path.read_bytes()), saved["frames"]["matched"][family]["frameSha256"])
            self.assertEqual(stat.S_IMODE(frame_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE((self.evidence / "offline-macos-vm-canary.json").stat().st_mode), 0o600)
        self.assertTrue(self.base_vm_dir.exists())
        self.assertEqual(sorted(path.name for path in (self.tart_home / "vms").iterdir()), ["prepared-macos15"])

    def test_readiness_probe_timeout_retries_within_budget(self):
        self._write_fake_tart(frames="both", readiness={"delay_first": 1.0})
        self._write_receipt()
        self.assertIsNone(self._run(probe_timeout=0.5))
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "passed")
        self.assertEqual(saved["readinessProbe"]["attempts"], 2)
        self.assertEqual(saved["hostCommandTemplates"].count(saved["readinessProbe"]["argv"]), 1)

    def test_oversized_result_writes_bounded_tainted_manifest_and_keeps_identity(self):
        self._write_fake_tart(frames="both")
        self._write_receipt()
        with patch.object(canary, "GUEST_CANARY", canary.GUEST_CANARY + "\n# " + "x" * 70_000):
            self._run()
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "tainted")
        self.assertEqual(saved["error"], "result_too_large")
        self.assertIn("result_too_large", saved["cleanupErrors"])
        self.assertRegex(saved["cloneVmName"], r"^offline-canary-[0-9a-f]{32}$")
        self.assertEqual(saved["baseVmName"], "prepared-macos15")
        self.assertLess((self.evidence / "offline-macos-vm-canary.json").stat().st_size, canary.MAX_SHORT_OUTPUT)
        self.assertTrue(self.base_vm_dir.exists())

    def test_oversized_failure_manifest_preserves_primary_error(self):
        self._write_fake_tart(frames="none")
        self._write_receipt()
        with patch.object(canary, "GUEST_CANARY", canary.GUEST_CANARY + "\n# " + "x" * 70_000):
            with self.assertRaisesRegex(canary.CanaryError, "guest_external_frames_not_observed"):
                self._run()
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "tainted")
        self.assertEqual(saved["error"], "guest_external_frames_not_observed")
        self.assertIn("result_too_large", saved["cleanupErrors"])
        self.assertRegex(saved["cloneVmName"], r"^offline-canary-[0-9a-f]{32}$")
        self.assertLess((self.evidence / "offline-macos-vm-canary.json").stat().st_size, canary.MAX_SHORT_OUTPUT)

    def test_partial_clone_creation_failure_is_retained_and_recorded(self):
        self._write_fake_tart(partial_clone_failure=True)
        self._write_receipt()
        with self.assertRaisesRegex(canary.CanaryError, "tart_command_failed"):
            self._run()
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        clone_name = saved["cloneVmName"]
        self.assertEqual(saved["status"], "tainted")
        self.assertEqual(saved["error"], "tart_command_failed")
        self.assertIn("clone_creation_ownership_unverified", saved["cleanupErrors"])
        self.assertTrue((self.tart_home / "vms" / clone_name).exists())
        self.assertTrue(self.base_vm_dir.exists())

    def test_no_frame_is_causally_rejected_not_mistaken_for_denial(self):
        with self.assertRaisesRegex(canary.CanaryError, "guest_external_frames_not_observed"):
            self._run()
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "failed")
        self.assertEqual(saved["rawEvidence"]["guest-stdout.bin"]["sha256"],
                         canary._sha256((self.evidence / "guest-stdout.bin").read_bytes()))

    def test_drainer_failure_cancels_active_guest_exec(self):
        self._write_fake_tart(frames="none", sleep_guest=10)
        self._write_receipt()

        def fail_after_guest_starts(peer, stop, nonce, vm_mac, records, failures, counters, evidence):
            marker = self.tart_home / "guest-started"
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            failures.append("network_drainer_failed")

        started = time.monotonic()
        with patch.object(canary, "_drain", side_effect=fail_after_guest_starts):
            with self.assertRaisesRegex(canary.CanaryError, "network_drainer_failed"):
                self._run()
        self.assertLess(time.monotonic() - started, 4)

    def test_late_drainer_failure_during_cleanup_prevents_pass(self):
        self._write_fake_tart(frames="both")
        self._write_receipt()

        def fail_after_stop(process, failures, result, evidence):
            marker = self.tart_home / "stop-started"
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            process.stdout.close()
            process.stderr.close()
            failures.append("tart_run_output_limit")

        with patch.object(canary, "_drain_tart_logs", side_effect=fail_after_stop):
            self._run()
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "failed")
        self.assertEqual(saved["error"], "tart_run_output_limit")
        self.assertNotEqual(saved["status"], "passed")

    def test_sigterm_cleans_owned_vm_ignores_repeats_and_restores_handlers(self):
        self._write_fake_tart(frames="both", sleep_guest=10)
        self._write_receipt()
        before_term = signal.getsignal(signal.SIGTERM)
        before_int = signal.getsignal(signal.SIGINT)

        def send_termination():
            guest_started = self.tart_home / "guest-started"
            deadline = time.monotonic() + 10
            while not guest_started.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            os.kill(os.getpid(), signal.SIGTERM)
            stop_started = self.tart_home / "stop-started"
            deadline = time.monotonic() + 10
            while not stop_started.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            os.kill(os.getpid(), signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGINT)

        sender = threading.Thread(target=send_termination)
        sender.start()
        with self.assertRaisesRegex(canary.CanaryError, "interrupted_by_sigterm"):
            self._run()
        sender.join(timeout=10)
        self.assertFalse(sender.is_alive())
        self.assertEqual(signal.getsignal(signal.SIGTERM), before_term)
        self.assertEqual(signal.getsignal(signal.SIGINT), before_int)
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "failed")
        self.assertEqual(sorted(path.name for path in (self.tart_home / "vms").iterdir()), ["prepared-macos15"])

    def test_cleanup_signals_owned_process_group(self):
        self._write_fake_tart(frames="both")
        self._write_receipt()
        real_killpg = os.killpg
        signals = []

        def record_killpg(pid, sig):
            signals.append((pid, sig))
            return real_killpg(pid, sig)

        with patch.object(canary.os, "killpg", side_effect=record_killpg):
            self._run()
        self.assertTrue(any(sig == signal.SIGTERM for _, sig in signals))

    def test_guest_output_cap_is_retained_and_hashed(self):
        stdout_path = self.root / "bounded-stdout.bin"
        stderr_path = self.root / "bounded-stderr.bin"
        with self.assertRaisesRegex(canary.CanaryError, "tart_command_output_limit"):
            canary._run_bounded([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 20)"],
                                timeout=5, env=os.environ, output_limit=8,
                                capture_paths=(stdout_path, stderr_path))
        retained = stdout_path.read_bytes()
        self.assertEqual(retained, b"x" * 8)
        self.assertEqual(canary._raw_evidence(stdout_path, 8)["sha256"], canary._sha256(retained))
        self.assertEqual(stat.S_IMODE(stdout_path.stat().st_mode), 0o600)

    def test_one_family_only_is_rejected(self):
        self._write_fake_tart(frames="ipv4")
        self._write_receipt()
        with self.assertRaisesRegex(canary.CanaryError, "guest_external_frames_not_observed"):
            self._run()

    def test_foreign_mac_and_wrong_nonce_are_not_accepted(self):
        for kind in ("badmac", "wrongnonce"):
            self._write_fake_tart(frames=kind)
            self._write_receipt()
            with self.assertRaisesRegex(canary.CanaryError, "guest_external_frames_not_observed"):
                self._run()
            self.evidence = self.root / ("evidence-" + kind)
            self.evidence.mkdir(mode=0o700)

    def test_saved_guest_memory_state_is_refused_before_clone(self):
        (self.base_vm_dir / "state").write_bytes(b"saved-state")
        with self.assertRaisesRegex(canary.CanaryError, "base_vm_has_saved_memory_state"):
            self.qualify()

    def test_remote_base_name_and_receipt_mismatch_fail_before_clone(self):
        with self.assertRaisesRegex(canary.CanaryError, "base_vm_must_be_local_name"):
            self.qualify("https://example.invalid/vm")
        with self.assertRaisesRegex(canary.CanaryError, "base_vm_receipt_mismatch"):
            self.qualify("other-base")

    def test_receipt_requires_immutable_oci_reference_and_bound_storage_measurement(self):
        self.receipt["ociBaseDigest"] = "ghcr.io/cirruslabs/macos-sequoia-base:latest"
        self.receipt_path.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(canary.CanaryError, "oci_base_not_digest_pinned"):
            canary._read_receipt(self.receipt_path)

    def test_tart_binary_identity_mismatch_fails_before_clone(self):
        self.receipt["tartBinarySha256"] = "0" * 64
        self.receipt_path.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(canary.CanaryError, "tart_release_digest_not_pinned"):
            self.qualify()

    def test_tart_package_digest_mismatch_fails_before_clone(self):
        self.receipt["tartPackageSha256"] = "0" * 64
        self.receipt_path.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(canary.CanaryError, "tart_package_digest_not_pinned"):
            canary._read_receipt(self.receipt_path)

    def test_wrong_guest_os_and_architecture_fail_closed(self):
        for version, arch in (("14.7.2", "arm64"), ("15.0.1", "x86_64")):
            with self.subTest(version=version, arch=arch):
                with self.assertRaisesRegex(canary.CanaryError, "guest_platform_not_macos15_arm64"):
                    canary._guest_result(json.dumps({
                        "kind": "offline-macos-vm-guest-canary-v1", "nonce": "n" * 32,
                        "checks": {key: True for key in ("loopback-ipv4", "loopback-ipv6", "unix-socket",
                                                         "nested-seatbelt", "sent-ipv4", "sent-ipv6")},
                        "runtime": {"productVersion": version, "buildVersion": "24A5289h", "architecture": arch},
                    }).encode(), "n" * 32)

    def test_tart_home_environment_is_honored_and_requires_private_directory(self):
        self._write_fake_tart(frames="both")
        self._write_receipt()
        evidence = self.root / "cli-evidence"
        evidence.mkdir(mode=0o700)

        class FixedUuid:
            hex = "c" * 32
        with patch.dict(os.environ, {"TART_HOME": str(self.tart_home)}), \
                patch.object(canary, "TART_BINARY_SHA256", canary._sha256(self.tart.read_bytes())), \
                patch.multiple(canary, CANARY_TIMEOUT=2, VM_READY_TIMEOUT=2), \
                patch.object(canary.uuid, "uuid4", return_value=FixedUuid()):
            self.assertEqual(canary.main([
                "--base-vm", "prepared-macos15", "--receipt", str(self.receipt_path),
                "--evidence-dir", str(evidence), "--tart", str(self.tart),
            ]), 0)
        saved = json.loads((evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "passed")

        os.chmod(self.tart_home, 0o755)  # nosec B103 -- intentionally unsafe fixture must be rejected.
        with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_home"):
            canary._safe_tart_home(self.tart_home)
        os.chmod(self.tart_home, 0o700)

    def test_symlink_or_foreign_writable_base_storage_is_rejected(self):
        preserved = self.tart_home / "vms" / "prepared-macos15-preserved"
        self.base_vm_dir.rename(preserved)
        self.base_vm_dir.symlink_to(preserved, target_is_directory=True)
        with self.assertRaisesRegex(canary.CanaryError, "base_vm_storage_missing"):
            self.qualify()
        self.base_vm_dir.unlink()
        preserved.rename(self.base_vm_dir)

        os.chmod(self.base_vm_dir, 0o777)  # nosec B103 -- intentionally unsafe fixture must be rejected.
        with self.assertRaisesRegex(canary.CanaryError, "unsafe_base_vm_directory"):
            self.qualify()
        os.chmod(self.base_vm_dir, 0o700)

    def test_symlinked_tart_vms_directory_is_rejected(self):
        vms = self.tart_home / "vms"
        preserved = self.tart_home / "vms-preserved"
        vms.rename(preserved)
        vms.symlink_to(preserved, target_is_directory=True)
        with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_vms_directory"):
            self.qualify()

    def test_foreign_writable_tart_vms_directory_is_rejected(self):
        vms = self.tart_home / "vms"
        original_mode = stat.S_IMODE(vms.stat().st_mode)
        os.chmod(vms, 0o777)  # nosec B103 -- intentionally unsafe fixture must be rejected.
        with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_vms_directory"):
            self.qualify()
        os.chmod(vms, original_mode)

    def test_config_and_disk_measurement_mismatch_fails_before_clone(self):
        self.receipt["storageMeasurement"]["configSha256"] = "0" * 64
        self.receipt_path.write_text(json.dumps(self.receipt))
        with self.assertRaisesRegex(canary.CanaryError, "base_vm_storage_measurement_mismatch"):
            self.qualify()

    def test_insufficient_free_capacity_fails_before_clone(self):
        required = self.receipt["preparedSnapshot"]["bytes"] + canary.CLONE_LOG_HEADROOM
        with patch.object(canary.shutil, "disk_usage", return_value=type("Usage", (), {"free": required - 1})()):
            with self.assertRaisesRegex(canary.CanaryError, "insufficient_vm_storage_capacity"):
                self.qualify()

    def test_disk_capacity_uses_actual_logical_disk_bytes_and_headroom(self):
        self._write_fake_tart(frames="both")
        self._write_receipt()
        required = self.receipt["preparedSnapshot"]["bytes"] + canary.CLONE_LOG_HEADROOM
        self._run(free_space=required)
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["preparedSnapshot"]["bytes"], (self.base_vm_dir / "disk.img").stat().st_size)
        self.assertEqual(saved["status"], "passed")

    def test_clone_is_retained_and_tainted_until_tart_reports_stopped(self):
        self._write_fake_tart(frames="both", running_after_stop=True)
        self._write_receipt()
        self._run()
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "tainted")
        self.assertFalse(saved["vmStop"]["stateConfirmedStopped"])
        self.assertTrue((self.tart_home / "vms" / saved["cloneVmName"]).exists())
        self.assertTrue(self.base_vm_dir.exists())

    def test_clone_is_not_deleted_until_tart_process_is_reaped(self):
        self._write_fake_tart(frames="none")
        self._write_receipt()

        class UnreapedProcess:
            pid = 999999999

            def __init__(self, pass_fd):
                out_read, out_write = os.pipe()
                err_read, err_write = os.pipe()
                self.write_fds = [out_write, err_write]
                self.stdout = os.fdopen(out_read, "rb")
                self.stderr = os.fdopen(err_read, "rb")
                self.peer = socket.socket(fileno=os.dup(pass_fd))

            def poll(self):
                return None

            def terminate(self):
                return None

            def wait(self, timeout=None):
                raise subprocess.TimeoutExpired("fake-tart-run", timeout)

            def close(self):
                self.peer.close()
                for fd in self.write_fds:
                    os.close(fd)

        real_popen = subprocess.Popen
        fake_processes = []

        def fake_popen(argv, **kwargs):
            if argv[1] != "run":
                return real_popen(argv, **kwargs)
            process = UnreapedProcess(kwargs["pass_fds"][0])
            fake_processes.append(process)
            return process

        try:
            with self.assertRaisesRegex(canary.CanaryError, "guest_external_frames_not_observed"):
                self._run(popen=fake_popen)
        finally:
            for process in fake_processes:
                process.close()
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "tainted")
        self.assertIn("owned_clone_retained_vm_process_unreaped", saved["cleanupErrors"])
        self.assertTrue((self.tart_home / "vms" / saved["cloneVmName"]).exists())

    def test_preexisting_or_symlink_evidence_is_refused(self):
        (self.evidence / "existing").write_text("preserve")
        with self.assertRaisesRegex(canary.CanaryError, "evidence_directory_not_empty"):
            self.qualify()


if __name__ == "__main__":
    unittest.main()
