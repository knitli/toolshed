"""Unit and causal tests for the fixed offline Tart canary."""

import ast
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
from io import StringIO
import json
import os
from pathlib import Path
import socket
import stat
import subprocess  # nosec B404 -- fake Tart and fixed sys.executable process fixtures; no shell.
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


def _set_macos_acl(path, *arguments):
    subprocess.run(
        ["/bin/chmod", *arguments, str(path)], check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )  # nosec B603 -- fixed local chmod ACL fixture arguments, no shell.


def _stat_with_uid(info, uid):
    fields = ("st_mode", "st_uid", "st_size", "st_dev", "st_ino", "st_mtime_ns", "st_ctime_ns")
    values = {name: getattr(info, name) for name in fields}
    values["st_uid"] = uid
    return types.SimpleNamespace(**values)


class _ObservedPopen:
    def __init__(self, real_popen):
        self.real_popen = real_popen
        self.process = None
        self.terminate_calls = 0
        self.kill_calls = 0

    def __call__(self, argv, **kwargs):
        process = self.real_popen(argv, **kwargs)
        if len(argv) > 1 and argv[1] == "run":
            self.process = process
            return self
        return process

    def __getattr__(self, name):
        return getattr(self.process, name)

    def terminate(self):
        self.terminate_calls += 1
        return self.process.terminate()

    def kill(self):
        self.kill_calls += 1
        return self.process.kill()


class _PythonChildProcesses:
    def __init__(self, real_popen):
        self.real_popen = real_popen
        self.processes = []

    def __call__(self, argv, **kwargs):
        process = self.real_popen(argv, **kwargs)
        if argv and argv[0] == sys.executable:
            self.processes.append(process)
        return process


def _wait_for_unreaped_exit(pid, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None:
            return True
        time.sleep(0.01)
    return False


def _reap_test_children(processes):
    for process in processes:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except ChildProcessError:
                process.returncode = -signal.SIGKILL


class _UnverifiedGroupKillFailure:
    def __init__(self, observed_popen):
        self.process = observed_popen
        self.signals = []

    def __call__(self, pid, sig):
        self.signals.append(sig)
        if sig == signal.SIGTERM:
            os.kill(pid, signal.SIGTERM)
            canary._wait_owned_vm_exit(self.process, 5)
        elif sig == signal.SIGKILL and self.process.returncode is not None:
            raise AssertionError("Popen reaped the leader before final group KILL")
        elif sig != signal.SIGKILL:
            raise AssertionError(f"unexpected group signal {sig}")
        raise PermissionError("injected unverified group signal failure")


class OfflineMacosVmCanaryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="offline-vm-test-", dir="/tmp")  # nosec B108 -- atomic private fixture under root-sticky tmp.
        self.root = Path(self.temp.name).resolve(strict=True)
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
        self.assertFalse(canary._vm_stopped((b"{" + b'"x":' * 5000 + b"0" + b"}")))
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
                         readiness=None, sleep_guest=0, partial_clone_failure=False,
                         spawn_term_ignoring_child=False):
        readiness = readiness or {}
        readiness_failures = readiness.get("failures", 0)
        readiness_delay_first = readiness.get("delay_first", 0)
        guest_version = "15.0.1"
        guest_arch = "arm64"
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
import json, os, shutil, signal, socket, subprocess, sys, time
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
    if {spawn_term_ignoring_child!r}:
        child_marker = os.path.join(os.environ["TART_HOME"], "descendant-pid")
        child_code = "import os,signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); open(sys.argv[1], 'w').write(str(os.getpid())); time.sleep(60)"
        subprocess.Popen([sys.executable, "-c", child_code, child_marker])
        child_deadline = time.monotonic() + 5
        while not os.path.exists(child_marker) and time.monotonic() < child_deadline:
            time.sleep(0.01)
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

    def _run(self, *, free_space=200 * 1024**3, popen=None, probe_timeout=0.2,
             scpreferences_api=False, native_workspace_guest_inventory=False, run_bounded=None):
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
                    options = {"tart": str(self.tart), "tart_home": self.tart_home}
                    if popen is not None:
                        options["popen"] = popen
                    if run_bounded is not None:
                        options["run_bounded"] = run_bounded
                    if scpreferences_api:
                        options["scpreferences_api"] = True
                    if native_workspace_guest_inventory:
                        options["native_workspace_guest_inventory"] = True
                    return canary.qualify("prepared-macos15", self.receipt_path, self.evidence, **options)

    def qualify(self, base_vm="prepared-macos15"):
        with patch.object(canary, "TART_BINARY_SHA256", canary._sha256(self.tart.read_bytes())):
            return canary.qualify(base_vm, self.receipt_path, self.evidence,
                                  tart=str(self.tart), tart_home=self.tart_home)

    def _assert_published_summary(self, summary, evidence=None):
        manifest = (evidence or self.evidence) / "offline-macos-vm-canary.json"
        raw = manifest.read_bytes()
        saved = json.loads(raw)
        expected = {"kind": saved["kind"], "status": saved["status"],
                    "resultSha256": canary._sha256(raw)}
        self.assertEqual(summary, expected)
        return saved

    def _import_guest_probe(self):
        with patch.object(sys, "path", [str(SCRIPT.parent), *sys.path]):
            return importlib.import_module("scpreferences_guest_probe")

    def test_scpreferences_api_opt_in_runs_and_publishes_report_and_raw_logs(self):
        self._write_fake_tart(frames="both")
        self._write_receipt()
        probe = self._import_guest_probe()
        source_hashes = {"offlineCanary": "a" * 64, "softnetPreferences": "b" * 64,
                         "softnetRecovery": "c" * 64, "guestApi": "d" * 64}
        bundle = {"argument": "fixed-test-bundle", "sourceSha256": source_hashes,
                  "bundleSha256": "e" * 64}
        report = {"kind": "scpreferences-guest-api-qualification-v1", "status": "passed",
                  "apiQualified": True, "effectiveDaemonQualified": False, "failureCode": None,
                  "checks": {name: True for name in probe.CHECKS}, "savedValuePresent": False,
                  "sourceSha256": source_hashes,
                  "journalDirectory": "/private/tmp/softnet-scpreferences-api-fixedtest"}
        stdout = json.dumps(report, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        stderr = b""
        calls = []

        def qualify_guest(tart_path, vm_name, env, evidence, actual_bundle, *, run_bounded):
            calls.append((tart_path, vm_name, env, Path(evidence), actual_bundle, run_bounded))
            (Path(evidence) / "scpreferences-api-stdout.bin").write_bytes(stdout)
            (Path(evidence) / "scpreferences-api-stderr.bin").write_bytes(stderr)
            return {"report": report}

        with patch.object(sys, "path", [str(SCRIPT.parent), *sys.path]), \
                patch.dict(sys.modules, {"scpreferences_guest_probe": probe}), \
                patch.object(probe, "build_bundle", return_value=bundle) as build_bundle, \
                patch.object(probe, "qualify", side_effect=qualify_guest) as qualify_guest_mock:
            summary = self._run(scpreferences_api=True)

        saved = self._assert_published_summary(summary)
        self.assertEqual(saved["scpreferencesApi"]["report"], report)
        self.assertEqual(saved["scpreferencesApi"]["sourceSha256"], source_hashes)
        self.assertEqual(saved["status"], "passed", saved)
        for name, raw in (("scpreferences-api-stdout.bin", stdout),
                          ("scpreferences-api-stderr.bin", stderr)):
            record = saved["rawEvidence"][name]
            self.assertEqual(record["bytes"], len(raw))
            self.assertEqual(record["sha256"], canary._sha256(raw))
            self.assertEqual((self.evidence / name).read_bytes(), raw)
        build_bundle.assert_called_once_with()
        qualify_guest_mock.assert_called_once()
        tart_path, clone, env, evidence, called_bundle, runner = calls[0]
        self.assertEqual(tart_path, self.tart)
        self.assertEqual(clone, saved["cloneVmName"])
        self.assertEqual(env["TART_HOME"], str(self.tart_home))
        self.assertEqual(evidence, self.evidence)
        self.assertIs(called_bundle, bundle)
        self.assertIs(runner, canary._run_bounded)
        command = [str(self.tart), "exec", clone, "/usr/bin/sudo", "-n", "/usr/bin/python3", "-I",
                   "-c", probe.LOADER, "<fixed-source-bundle-b64>"]
        self.assertIn(command, saved["hostCommandTemplates"])
        self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
        self.assertFalse((self.tart_home / "vms" / clone).exists())

    def test_scpreferences_api_report_validation_failure_still_cleans_exact_clone(self):
        self._write_fake_tart(frames="both")
        self._write_receipt()
        probe = self._import_guest_probe()
        captured = []
        real_run_bounded = canary._run_bounded

        def invalid_api_report(argv, **kwargs):
            if len(argv) > 3 and argv[1] == "exec" and "/usr/bin/sudo" in argv:
                if argv[-1] != "c" * 32:
                    stdout, stderr = b"{}\n", b""
                    for path, raw in zip(kwargs["capture_paths"], (stdout, stderr)):
                        Path(path).write_bytes(raw)
                    captured.append(tuple(argv))
                    return stdout, stderr
            return real_run_bounded(argv, **kwargs)

        with patch.object(sys, "path", [str(SCRIPT.parent), *sys.path]), \
                patch.dict(sys.modules, {"scpreferences_guest_probe": probe}), \
                self.assertRaisesRegex(canary.CanaryError, "scpreferences_api_report_unqualified"):
            self._run(scpreferences_api=True, run_bounded=invalid_api_report)

        self.assertEqual(len(captured), 1)
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_bytes())
        self.assertEqual(saved["status"], "failed")
        self.assertEqual(saved["error"], "scpreferences_api_report_unqualified")
        self.assertEqual(saved["rawEvidence"]["scpreferences-api-stdout.bin"]["bytes"], 3)
        self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
        clone = saved["cloneVmName"]
        self.assertEqual([path.name for path in (self.tart_home / "vms").iterdir()],
                         ["prepared-macos15"])
        self.assertFalse((self.tart_home / "vms" / clone).exists())
        self.assertTrue((self.tart_home / "stop-started").is_file())

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

    def test_running_process_timeout_is_normalized_and_process_is_reaped(self):
        class RunningProcess:
            pid = 987654321

            def __init__(self):
                out_read, out_write = os.pipe()
                err_read, err_write = os.pipe()
                os.close(out_write)
                os.close(err_write)
                self.stdout = os.fdopen(out_read, "rb")
                self.stderr = os.fdopen(err_read, "rb")
                self.reaped = False
                self.wait_calls = []

            def poll(self):
                return -signal.SIGKILL if self.reaped else None

            def wait(self, timeout=None):
                self.wait_calls.append(timeout)
                self.reaped = True
                return -signal.SIGKILL

        process = RunningProcess()
        with patch.object(canary.os, "waitid", return_value=None), \
                patch.object(canary.subprocess, "Popen", return_value=process), \
                patch.object(canary.os, "killpg", side_effect=ProcessLookupError) as killpg:
            with self.assertRaisesRegex(canary.CanaryError, "tart_command_timeout"):
                canary._run_bounded(["fake-tart"], timeout=0.05, env={})
        self.assertTrue(process.reaped)
        self.assertEqual(process.wait_calls, [5])
        killpg.assert_called_once_with(process.pid, signal.SIGKILL)

    def test_nonzero_child_is_group_swept_before_its_leader_is_reaped(self):
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        child_processes = _PythonChildProcesses(real_popen)
        signals = []

        def record_popen(argv, **kwargs):
            return child_processes(argv, **kwargs)

        def observe_group_signal(pid, sig):
            signals.append((pid, sig))
            self.assertEqual(pid, child_processes.processes[0].pid)
            self.assertEqual(sig, signal.SIGKILL)
            self.assertIsNotNone(os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT))
            return real_killpg(pid, sig)

        with patch.object(canary.os, "killpg", side_effect=observe_group_signal), \
                patch.object(canary.subprocess, "Popen", side_effect=record_popen):
            with self.assertRaisesRegex(canary.CanaryError, "tart_command_failed"):
                canary._run_bounded([sys.executable, "-c", "raise SystemExit(7)"], timeout=5, env=os.environ)

        child = child_processes.processes[0]
        self.assertEqual(signals, [(child.pid, signal.SIGKILL)])
        self.assertEqual(child.returncode, 7)

    def test_reap_timeout_is_reported_without_replacing_command_timeout(self):
        class UnreapableProcess:
            pid = 987654322
            returncode = None

            def __init__(self):
                out_read, out_write = os.pipe()
                err_read, err_write = os.pipe()
                os.close(out_write)
                os.close(err_write)
                self.stdout = os.fdopen(out_read, "rb")
                self.stderr = os.fdopen(err_read, "rb")
                self.wait_timeouts = []

            def poll(self):
                return None

            def wait(self, timeout=None):
                self.wait_timeouts.append(timeout)
                raise subprocess.TimeoutExpired("fake", timeout)

            def kill(self):
                pass

        process = UnreapableProcess()
        with patch.object(canary.os, "waitid", return_value=None), \
                patch.object(canary.subprocess, "Popen", return_value=process), \
                patch.object(canary.os, "killpg", side_effect=ProcessLookupError):
            with self.assertRaisesRegex(canary.CanaryError, "tart_command_timeout") as raised:
                canary._run_bounded(["fake-tart"], timeout=0.02, env={})

        self.assertEqual(process.wait_timeouts, [5])
        self.assertIn("process_reap_failed", raised.exception.cleanup_errors)
        self.assertIs(raised.exception.unreaped_process, process)

    def test_externally_reaped_child_with_unset_popen_returncode_receives_no_signals(self):
        real_popen = subprocess.Popen
        real_read = os.read
        child = None
        externally_reaped = False
        reaped_status = None
        signals = []

        def record_popen(argv, **kwargs):
            nonlocal child
            child = real_popen(argv, **kwargs)
            return child

        def reap_during_output_read(fd, size):
            nonlocal externally_reaped, reaped_status
            chunk = real_read(fd, size)
            if chunk and not externally_reaped:
                waited_pid, reaped_status = os.waitpid(child.pid, 0)
                self.assertEqual(waited_pid, child.pid)
                externally_reaped = True
            return chunk

        with patch.object(canary.os, "read", side_effect=reap_during_output_read), \
                patch.object(canary.os, "killpg", side_effect=lambda pid, sig: signals.append((pid, sig))), \
                patch.object(canary.subprocess, "Popen", side_effect=record_popen):
            with self.assertRaisesRegex(canary.CanaryError, "tart_command_process_identity_lost"):
                canary._run_bounded(
                    [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'done')"],
                    timeout=5, env=os.environ,
                )

        self.assertTrue(externally_reaped)
        self.assertIsNone(child.returncode)
        self.assertEqual(signals, [])
        child.returncode = os.waitstatus_to_exitcode(reaped_status)
        self.assertEqual(child.returncode, 0)

    def test_bounded_runner_preserves_primary_error_when_darwin_eprem_proves_zombie_group(self):
        real_killpg = os.killpg
        process_recorder = _PythonChildProcesses(subprocess.Popen)

        def darwin_zombie_eperm(pid, sig):
            if pid == process_recorder.processes[-1].pid and sig == signal.SIGKILL:
                os.kill(pid, signal.SIGKILL)
                self.assertTrue(_wait_for_unreaped_exit(pid))
                raise PermissionError(1, "operation not permitted")
            return real_killpg(pid, sig)

        with patch.object(canary, "_owned_group_is_zombie_only", return_value=True) as zombie_proof, \
                patch.object(canary.os, "killpg", side_effect=darwin_zombie_eperm), \
                patch.object(canary.subprocess, "Popen", side_effect=process_recorder):
            with self.assertRaisesRegex(canary.CanaryError, "tart_command_output_limit") as raised:
                canary._run_bounded(
                    [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * (69 * 1024))"],
                    timeout=5, env=os.environ,
                )

        self.assertTrue(process_recorder.processes[0].returncode is not None)
        self.assertEqual(raised.exception.cleanup_errors, ())
        zombie_proof.assert_called_once()
        self.assertEqual(zombie_proof.call_args.args[0], process_recorder.processes[0].pid)

    def test_bounded_runner_reports_cleanup_failure_without_replacing_primary_error(self):
        process_recorder = _PythonChildProcesses(subprocess.Popen)

        def failed_group_signal(pid, sig):
            if pid == process_recorder.processes[0].pid and sig == signal.SIGKILL:
                os.kill(pid, signal.SIGKILL)
                if not _wait_for_unreaped_exit(pid):
                    self.fail("bounded child did not exit before the injected group-signal failure")
            raise PermissionError(1, "injected proof-runner signal failure")

        def fail_proof(_pid, runner, env):
            # Fail the bounded ps child too. The internal nonrecursive path must
            # report this cleanup failure instead of attempting another proof.
            with self.assertRaises(canary.CanaryError) as proof_error:
                runner([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'z' * 20)"],
                       timeout=5, env=env, output_limit=8)
            self.assertEqual(proof_error.exception.args, ("tart_command_output_limit",))
            return False

        with patch.object(canary, "_owned_group_is_zombie_only", side_effect=fail_proof), \
                patch.object(canary.os, "killpg", side_effect=failed_group_signal), \
                patch.object(canary.subprocess, "Popen", side_effect=process_recorder):
            with self.assertRaisesRegex(canary.CanaryError, "tart_command_output_limit") as raised:
                canary._run_bounded(
                    [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 20)"],
                    timeout=5, env=os.environ, output_limit=8,
                )

        processes = process_recorder.processes
        self.assertEqual(len(processes), 2)
        self.assertIn("process_group_kill_failed", raised.exception.cleanup_errors)
        self.assertIn("process_not_reaped_group_unverified", raised.exception.cleanup_errors)
        self.assertIs(raised.exception.unreaped_process, processes[0])
        _reap_test_children(processes)

    def test_killpg_interruption_finishes_owned_leader_cleanup_and_preserves_primary(self):
        process_recorder = _PythonChildProcesses(subprocess.Popen)
        signals = []

        def interrupt_group_signal(pid, sig):
            signals.append((pid, sig))
            raise canary.CanaryError("interrupted_by_sigint")

        try:
            with patch.object(canary.os, "killpg", side_effect=interrupt_group_signal), \
                    patch.object(canary.subprocess, "Popen", side_effect=process_recorder):
                with self.assertRaisesRegex(canary.CanaryError, "interrupted_by_sigint") as raised:
                    canary._run_bounded(
                        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 20)"],
                        timeout=5, env=os.environ, output_limit=8,
                    )

            child = process_recorder.processes[0]
            self.assertEqual(raised.exception.__cause__.args, ("tart_command_output_limit",))
            self.assertEqual(signals, [(child.pid, signal.SIGKILL)])
            self.assertIn("process_group_kill_failed", raised.exception.cleanup_errors)
            self.assertIn("process_not_reaped_group_unverified", raised.exception.cleanup_errors)
            self.assertIs(raised.exception.unreaped_process, child)
        finally:
            _reap_test_children(process_recorder.processes)

    def test_reap_interruption_propagates_and_retains_bounded_process(self):
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        processes = []
        signals = []

        class WaitInterruptProcess:
            def __init__(self, process):
                self.process = process

            def __getattr__(self, name):
                return getattr(self.process, name)

            def wait(self, timeout=None):
                if timeout == 5:
                    raise canary.CanaryError("interrupted_by_sigterm")
                return self.process.wait(timeout=timeout)

        def record_popen(argv, **kwargs):
            process = WaitInterruptProcess(real_popen(argv, **kwargs))
            if argv[0] == sys.executable:
                processes.append(process)
            return process

        def group_kill_succeeds(pid, sig):
            signals.append((pid, sig))
            return real_killpg(pid, sig)

        try:
            with patch.object(canary.os, "killpg", side_effect=group_kill_succeeds), \
                    patch.object(canary.subprocess, "Popen", side_effect=record_popen):
                with self.assertRaisesRegex(canary.CanaryError, "interrupted_by_sigterm") as raised:
                    canary._run_bounded(
                        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 20)"],
                        timeout=5, env=os.environ, output_limit=8,
                    )

            process = processes[0]
            self.assertEqual(raised.exception.__cause__.args, ("tart_command_output_limit",))
            self.assertEqual(signals, [(process.pid, signal.SIGKILL)])
            self.assertIn("process_reap_failed", raised.exception.cleanup_errors)
            self.assertIs(raised.exception.unreaped_process, process)
        finally:
            for process in processes:
                process.process.kill()
                process.process.wait(timeout=5)

    def test_interruption_during_zombie_proof_cleans_parent_and_retains_both_children(self):
        real_runner = canary._run_bounded
        process_recorder = _PythonChildProcesses(subprocess.Popen)
        proof_process = subprocess.Popen(  # nosec B603 -- fixed sys.executable sleep fixture, no shell.
            [sys.executable, "-c", "import time; time.sleep(60)"], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )

        def interrupted_proof(*args, **kwargs):
            error = canary.CanaryError("interrupted_by_sigint")
            error.cleanup_errors = ("proof_process_group_unverified",)
            error.unreaped_process = proof_process
            raise error

        try:
            with patch.object(canary, "_run_bounded", side_effect=interrupted_proof), \
                    patch.object(canary.os, "killpg", side_effect=PermissionError(1, "injected EPERM")), \
                    patch.object(canary.subprocess, "Popen", side_effect=process_recorder):
                with self.assertRaisesRegex(canary.CanaryError, "interrupted_by_sigint") as raised:
                    real_runner(
                        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 20)"],
                        timeout=5, env=os.environ, output_limit=8,
                    )

            parent_process = process_recorder.processes[0]
            self.assertEqual(raised.exception.__cause__.args, ("tart_command_output_limit",))
            self.assertIn("proof_process_group_unverified", raised.exception.cleanup_errors)
            self.assertIn("process_group_kill_failed", raised.exception.cleanup_errors)
            self.assertIn("process_not_reaped_group_unverified", raised.exception.cleanup_errors)
            self.assertEqual(raised.exception.unreaped_processes, (proof_process, parent_process))
        finally:
            _reap_test_children([proof_process, *process_recorder.processes])

    def test_proof_cleanup_failure_preserves_both_unreaped_process_handles(self):
        real_runner = canary._run_bounded
        process_recorder = _PythonChildProcesses(subprocess.Popen)
        proof_process = subprocess.Popen(  # nosec B603 -- fixed sys.executable sleep fixture, no shell.
            [sys.executable, "-c", "import time; time.sleep(60)"], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )

        def failed_proof(*args, **kwargs):
            error = canary.CanaryError("tart_command_output_limit")
            error.cleanup_errors = ("proof_process_group_kill_failed", "proof_process_not_reaped")
            error.unreaped_process = proof_process
            raise error

        try:
            with patch.object(canary, "_run_bounded", side_effect=failed_proof), \
                    patch.object(canary.os, "killpg", side_effect=PermissionError(1, "injected EPERM")), \
                    patch.object(canary.subprocess, "Popen", side_effect=process_recorder):
                with self.assertRaisesRegex(canary.CanaryError, "tart_command_output_limit") as raised:
                    real_runner(
                        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 20)"],
                        timeout=5, env=os.environ, output_limit=8,
                    )

            parent_process = process_recorder.processes[0]
            self.assertIn("proof_process_group_kill_failed", raised.exception.cleanup_errors)
            self.assertIn("process_group_kill_failed", raised.exception.cleanup_errors)
            self.assertEqual(raised.exception.unreaped_processes, (proof_process, parent_process))
        finally:
            _reap_test_children([proof_process, *process_recorder.processes])

    def test_base_vm_file_changed_through_same_inode_during_read_is_rejected(self):
        target = self.base_vm_dir / "disk.img"
        original = target.read_bytes()
        target_stat = os.stat(target, follow_symlinks=False)
        real_read = os.read
        real_fstat = os.fstat
        mutated = False

        def mutate_after_read(fd, size):
            nonlocal mutated
            data = real_read(fd, size)
            info = real_fstat(fd)
            if not mutated and (info.st_dev, info.st_ino) == (target_stat.st_dev, target_stat.st_ino):
                with target.open("r+b") as stream:
                    stream.write(b"X" + original[1:])
                    stream.flush()
                    os.fsync(stream.fileno())
                mutated = True
            return data

        try:
            with patch.object(canary.os, "read", side_effect=mutate_after_read):
                with self.assertRaisesRegex(canary.CanaryError, "base_vm_file_changed_during_measurement"):
                    canary._hash_file(target, maximum=canary.MAX_DISK_BYTES, require_protected=True)
            self.assertTrue(mutated)
        finally:
            with target.open("r+b") as stream:
                stream.write(original)
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())

    def test_tart_binary_changed_through_same_inode_during_hash_is_rejected(self):
        original = self.tart.read_bytes()
        tart_stat = os.stat(self.tart, follow_symlinks=False)
        real_read = os.read
        real_fstat = os.fstat
        mutated = False

        def mutate_after_read(fd, size):
            nonlocal mutated
            data = real_read(fd, size)
            info = real_fstat(fd)
            if not mutated and (info.st_dev, info.st_ino) == (tart_stat.st_dev, tart_stat.st_ino):
                with self.tart.open("r+b") as stream:
                    stream.write(b"X" + original[1:])
                    stream.flush()
                    os.fsync(stream.fileno())
                mutated = True
            return data

        digest = canary._sha256(original)
        try:
            with patch.object(canary, "TART_BINARY_SHA256", digest), \
                    patch.object(canary, "_run_bounded") as run, \
                    patch.object(canary.os, "read", side_effect=mutate_after_read):
                with self.assertRaisesRegex(canary.CanaryError, "tart_binary_changed_during_measurement"):
                    canary._tart_identity(self.tart, {**self.receipt, "tartBinarySha256": digest}, {})
                run.assert_not_called()
            self.assertTrue(mutated)
        finally:
            with self.tart.open("r+b") as stream:
                stream.write(original)
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())

    def test_tart_identity_accepts_private_path_beneath_root_sticky_tmp(self):
        sticky_tmp = os.lstat(Path("/tmp").resolve(strict=True))  # nosec B108 -- inspect the real sticky test ancestor.
        self.assertEqual(sticky_tmp.st_uid, 0)
        self.assertTrue(sticky_tmp.st_mode & stat.S_ISVTX)
        digest = canary._sha256(self.tart.read_bytes())
        injected_runner = unittest.mock.Mock(
            return_value=(f"{canary.TART_VERSION}\n".encode(), b""),
        )
        with patch.object(canary, "TART_BINARY_SHA256", digest), \
                patch.object(canary, "_run_bounded") as default_runner:
            self.assertEqual(canary._tart_identity(
                self.tart, self.receipt, {}, run_bounded=injected_runner,
            ), self.tart.resolve())
        injected_runner.assert_called_once_with(
            [str(self.tart.resolve()), "--version"], timeout=5, env={},
        )
        default_runner.assert_not_called()

    def test_tart_identity_rejects_symlink_and_writable_ancestors(self):
        secure = self.root / "tart-secure"
        secure.mkdir(mode=0o700)
        binary = secure / "tart"
        binary.write_bytes(self.tart.read_bytes())
        binary.chmod(0o700)
        link = self.root / "tart-link"
        link.symlink_to(secure, target_is_directory=True)
        executable_link = self.root / "tart-executable-link"
        executable_link.symlink_to(binary)
        writable = self.root / "tart-writable"
        writable.mkdir(mode=0o700)
        writable_binary = writable / "tart"
        writable_binary.write_bytes(binary.read_bytes())
        writable_binary.chmod(0o700)
        nonroot_sticky = self.root / "tart-sticky"
        nonroot_sticky.mkdir(mode=0o700)
        sticky_binary = nonroot_sticky / "tart"
        sticky_binary.write_bytes(binary.read_bytes())
        sticky_binary.chmod(0o700)
        os.chmod(writable, 0o777)  # nosec B103 -- intentionally unsafe ancestor must be rejected.
        os.chmod(nonroot_sticky, 0o1777)  # nosec B103 -- sticky mode is insufficient for non-root owner.
        digest = canary._sha256(binary.read_bytes())
        operator_uid = os.getuid() if os.getuid() != 0 else 1
        real_lstat = os.lstat

        def lstat_with_nonroot_sticky_owner(path):
            info = real_lstat(path)
            if Path(path) == nonroot_sticky:
                return types.SimpleNamespace(st_mode=info.st_mode, st_uid=operator_uid)
            return info

        with patch.object(canary, "TART_BINARY_SHA256", digest), \
                patch.object(canary, "_run_bounded", return_value=(f"{canary.TART_VERSION}\n".encode(), b"")) as run, \
                patch.object(canary.os, "getuid", return_value=operator_uid), \
                patch.object(canary.os, "lstat", side_effect=lstat_with_nonroot_sticky_owner):
            for path in (link / "tart", executable_link, writable_binary, sticky_binary):
                with self.subTest(path=path), self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_path"):
                    canary._tart_identity(path, {**self.receipt, "tartBinarySha256": digest}, {})
            run.assert_not_called()

    def test_tart_identity_rejects_untrusted_ancestor_owner(self):
        parent = self.root / "foreign-owner"
        parent.mkdir(mode=0o700)
        binary = parent / "tart"
        binary.write_bytes(self.tart.read_bytes())
        binary.chmod(0o700)
        real_lstat = os.lstat

        def foreign_owner(path):
            info = real_lstat(path)
            if Path(path) == parent:
                return types.SimpleNamespace(st_mode=info.st_mode, st_uid=os.getuid() + 1)
            return info

        with patch.object(canary.os, "lstat", side_effect=foreign_owner), \
                patch.object(canary, "_run_bounded") as run:
            with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_path"):
                canary._qualified_tart_path(binary)
            run.assert_not_called()

    def test_tart_executable_metadata_is_checked_on_hashed_descriptor(self):
        digest = canary._sha256(self.tart.read_bytes())
        with patch.object(canary, "TART_BINARY_SHA256", digest), \
                patch.object(canary, "_run_bounded") as run:
            for mode in (0o777, 0o600):
                os.chmod(self.tart, mode)  # nosec B103 -- invalid executable modes must be rejected.
                with self.subTest(mode=oct(mode)), self.assertRaisesRegex(
                        canary.CanaryError, "unsafe_tart_executable"):
                    canary._tart_identity(self.tart, self.receipt, {})
            os.chmod(self.tart, 0o700)

            real_fstat = os.fstat
            tart_stat = os.stat(self.tart, follow_symlinks=False)

            def foreign_file_owner(fd):
                info = real_fstat(fd)
                if info.st_dev == tart_stat.st_dev and info.st_ino == tart_stat.st_ino:
                    return types.SimpleNamespace(
                        st_mode=info.st_mode, st_uid=os.getuid() + 1, st_size=info.st_size,
                    )
                return info

            with patch.object(canary.os, "fstat", side_effect=foreign_file_owner):
                with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_executable"):
                    canary._tart_identity(self.tart, self.receipt, {})
            run.assert_not_called()

    def test_writable_path_cannot_reach_tart_version_probe(self):
        digest = canary._sha256(self.tart.read_bytes())
        original_bytes = self.tart.read_bytes()
        original_mode = stat.S_IMODE(self.root.stat().st_mode)
        os.chmod(self.root, 0o777)  # nosec B103 -- writable ancestor is the replacement-race fixture.
        real_hash_file = canary._hash_file

        def replace_after_hash(path, **kwargs):
            measurement = real_hash_file(path, **kwargs)
            Path(path).write_text("#!/bin/sh\nexit 99\n")
            Path(path).chmod(0o700)
            return measurement

        try:
            with patch.object(canary, "TART_BINARY_SHA256", digest), \
                    patch.object(canary, "_hash_file", side_effect=replace_after_hash) as hash_file, \
                    patch.object(canary, "_run_bounded", return_value=(f"{canary.TART_VERSION}\n".encode(), b"")) as run:
                with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_path"):
                    canary._tart_identity(self.tart, self.receipt, {})
                hash_file.assert_not_called()
                run.assert_not_called()
                self.assertEqual(self.tart.read_bytes(), original_bytes)
        finally:
            os.chmod(self.root, original_mode)

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_acl_write_grants_on_executable_or_ancestor_are_rejected(self):
        parent = self.root / "acl-write-directory"
        parent.mkdir(mode=0o700)
        binary = parent / "tart"
        binary.write_bytes(self.tart.read_bytes())
        binary.chmod(0o700)
        digest = canary._sha256(binary.read_bytes())
        with patch.object(canary, "TART_BINARY_SHA256", digest), \
                patch.object(canary, "_run_bounded", return_value=(f"{canary.TART_VERSION}\n".encode(), b"")) as run:
            for target, executable in ((binary, binary), (parent, binary)):
                with self.subTest(target=target):
                    try:
                        _set_macos_acl(target, "+a", "everyone allow write")
                        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o700)
                        with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_acl"):
                            canary._tart_identity(executable, self.receipt, {})
                    finally:
                        _set_macos_acl(target, "-N")
            run.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_read_allow_and_deny_write_acl_are_accepted(self):
        parent = self.root / "acl-read-deny-directory"
        parent.mkdir(mode=0o700)
        binary = parent / "tart"
        binary.write_bytes(self.tart.read_bytes())
        binary.chmod(0o700)
        digest = canary._sha256(binary.read_bytes())
        with patch.object(canary, "TART_BINARY_SHA256", digest), \
                patch.object(canary, "_run_bounded", return_value=(f"{canary.TART_VERSION}\n".encode(), b"")):
            try:
                _set_macos_acl(binary, "+a", "everyone allow read")
                _set_macos_acl(parent, "+a", "everyone deny write")
                self.assertEqual(canary._tart_identity(binary, self.receipt, {}), binary.resolve())
            finally:
                _set_macos_acl(binary, "-N")
                _set_macos_acl(parent, "-N")

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_multi_entry_read_allow_and_deny_acl_are_accepted(self):
        parent = self.root / "acl-multi-entry-directory"
        parent.mkdir(mode=0o700)
        binary = parent / "tart"
        binary.write_bytes(self.tart.read_bytes())
        binary.chmod(0o700)
        digest = canary._sha256(binary.read_bytes())
        with patch.object(canary, "TART_BINARY_SHA256", digest), \
                patch.object(canary, "_run_bounded", return_value=(f"{canary.TART_VERSION}\n".encode(), b"")):
            try:
                _set_macos_acl(binary, "+a", "everyone deny write")
                _set_macos_acl(binary, "+a", "everyone allow read")
                _set_macos_acl(binary, "+a", "everyone deny delete")
                self.assertEqual(canary._tart_identity(binary, self.receipt, {}), binary.resolve())
            finally:
                _set_macos_acl(binary, "-N")

    def test_tart_acl_api_failure_fails_closed(self):
        with patch.object(canary.sys, "platform", "darwin"), \
                patch.object(canary, "_load_tart_acl_api", side_effect=OSError("injected")):
            with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_acl"):
                canary._check_tart_acl(self.tart)

    def test_null_tart_acl_with_zero_errno_fails_closed(self):
        class EmptyAclApi:
            @staticmethod
            def acl_get_fd_np(_fd, _acl_type):
                return None

        canary.ctypes.set_errno(canary.errno.ENOENT)
        try:
            with patch.object(canary.sys, "platform", "darwin"), \
                    patch.object(canary, "_load_tart_acl_api", return_value=EmptyAclApi()):
                with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_acl"):
                    canary._check_tart_acl(self.tart, fd=123)
        finally:
            canary.ctypes.set_errno(0)

    def test_inherited_real_datagram_fd_and_fixed_drop_canary(self):
        self._write_fake_tart(frames="both", readiness={"failures": 2})
        self._write_receipt()
        result = self._run()
        saved = self._assert_published_summary(result)
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

    def test_main_reports_malformed_clone_config_and_cleans_clone(self):
        malformed_outputs = (b"\xff", b"{invalid", b"[]", b"1", b"[" * 10_000 + b"0" + b"]" * 10_000)
        real_qualify = canary.qualify
        real_runner = canary._run_bounded

        class FixedUuid:
            hex = "c" * 32

        for index, malformed in enumerate(malformed_outputs):
            with self.subTest(malformed=malformed):
                self._write_fake_tart(frames="both")
                self._write_receipt()
                evidence = self.root / f"malformed-config-evidence-{index}"
                evidence.mkdir(mode=0o700)
                initial_gets = 0

                def runner(argv, **kwargs):
                    nonlocal initial_gets
                    if (len(argv) >= 5 and argv[1] == "get"
                            and argv[2].startswith("offline-canary-")):
                        initial_gets += 1
                        if initial_gets == 1:
                            return malformed, b""
                    return real_runner(argv, **kwargs)

                def qualify_with_malformed_get(*args, **kwargs):
                    kwargs["run_bounded"] = runner
                    return real_qualify(*args, **kwargs)

                stdout, stderr = StringIO(), StringIO()
                with patch.object(canary, "TART_BINARY_SHA256", canary._sha256(self.tart.read_bytes())), \
                        patch.object(canary, "qualify", side_effect=qualify_with_malformed_get), \
                        patch.object(canary.uuid, "uuid4", return_value=FixedUuid()), \
                        redirect_stdout(stdout), redirect_stderr(stderr):
                    exit_code = canary.main([
                        "--base-vm", "prepared-macos15", "--receipt", str(self.receipt_path),
                        "--evidence-dir", str(evidence), "--tart", str(self.tart),
                        "--tart-home", str(self.tart_home),
                    ])

                self.assertEqual(exit_code, 1)
                self.assertEqual(stderr.getvalue(), "clone_config_invalid\n")
                self.assertNotIn("Traceback", stderr.getvalue())
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(initial_gets, 2)
                saved = json.loads((evidence / "offline-macos-vm-canary.json").read_text())
                self.assertEqual(saved["status"], "failed")
                self.assertEqual(saved["error"], "clone_config_invalid")
                self.assertEqual(sorted(path.name for path in (self.tart_home / "vms").iterdir()),
                                 ["prepared-macos15"])

    def test_readiness_probe_timeout_retries_within_budget(self):
        self._write_fake_tart(frames="both", readiness={"delay_first": 1.0})
        self._write_receipt()
        summary = self._run(probe_timeout=0.5)
        saved = self._assert_published_summary(summary)
        self.assertEqual(saved["status"], "passed")
        self.assertEqual(saved["readinessProbe"]["attempts"], 2)
        self.assertEqual(saved["hostCommandTemplates"].count(saved["readinessProbe"]["argv"]), 1)

    def test_oversized_result_writes_bounded_tainted_manifest_and_keeps_identity(self):
        self._write_fake_tart(frames="both")
        self._write_receipt()
        with patch.object(canary, "GUEST_CANARY", canary.GUEST_CANARY + "\n# " + "x" * 70_000):
            summary = self._run()
        saved = self._assert_published_summary(summary)
        self.assertEqual(summary["status"], "tainted")
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

    def test_cleanup_kills_owned_process_group_before_leader_is_reaped(self):
        self._write_fake_tart(frames="both", spawn_term_ignoring_child=True)
        self._write_receipt()
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        signals = []
        state = {"leaderReaped": False, "killBeforeLeaderReaped": False, "leaderExitedObserved": False}

        class ObservedProcess:
            def __init__(self, process, argv):
                self.process = process
                self.argv = argv

            def __getattr__(self, name):
                return getattr(self.process, name)

            def wait(self, *args, **kwargs):
                result = self.process.wait(*args, **kwargs)
                if self.argv[1] == "run" and self.process.poll() is not None:
                    state["leaderReaped"] = True
                return result

        def observed_popen(argv, **kwargs):
            process = real_popen(argv, **kwargs)
            if len(argv) > 1 and argv[1] == "run":
                state["groupId"] = process.pid
                return ObservedProcess(process, argv)
            return process

        def record_killpg(pid, sig):
            signals.append((pid, sig))
            if sig == signal.SIGKILL:
                state["killBeforeLeaderReaped"] = not state["leaderReaped"]
                try:
                    os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    state["leaderExitedObserved"] = True
                except ChildProcessError:
                    pass
            return real_killpg(pid, sig)

        marker = self.tart_home / "descendant-pid"
        try:
            with patch.object(canary.os, "killpg", side_effect=record_killpg):
                self._run(popen=observed_popen)
        finally:
            if marker.exists() and not state["killBeforeLeaderReaped"]:
                try:
                    real_killpg(state.get("groupId", int(marker.read_text())), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        self.assertTrue(marker.exists())
        self.assertTrue(any(sig == signal.SIGTERM for _, sig in signals))
        self.assertTrue(any(sig == signal.SIGKILL for _, sig in signals))
        self.assertTrue(state["killBeforeLeaderReaped"])
        self.assertTrue(state["leaderExitedObserved"])

    def test_term_eperm_keeps_exited_leader_unreaped_until_zombie_group_proof(self):
        self._write_fake_tart(frames="both")
        self._write_receipt()
        real_popen = subprocess.Popen
        real_waitid = os.waitid
        state = {"pollCalls": 0, "pollCallsAtTerm": None, "terminateCalls": 0, "termExitObserved": False,
                 "killExitObserved": False, "returncodeAtKill": "unset"}
        signals = []

        class ObservedProcess:
            def __init__(self, process):
                self.process = process
                self.pid = process.pid

            def __getattr__(self, name):
                return getattr(self.process, name)

            def poll(self):
                state["pollCalls"] += 1
                return self.process.poll()

            def terminate(self):
                state["terminateCalls"] += 1
                return self.process.terminate()

        processes = []

        def observed_popen(argv, **kwargs):
            process = real_popen(argv, **kwargs)
            if len(argv) > 1 and argv[1] == "run":
                process = ObservedProcess(process)
                processes.append(process)
            return process

        def observe_exit_without_reaping(pid):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                info = real_waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if info is not None:
                    return True
                time.sleep(0.01)
            return False

        def inject_darwin_eperm(pid, sig):
            signals.append((pid, sig))
            if sig == signal.SIGTERM:
                state["pollCallsAtTerm"] = state["pollCalls"]
                os.kill(pid, signal.SIGTERM)
                state["termExitObserved"] = observe_exit_without_reaping(pid)
                raise PermissionError(1, "operation not permitted")
            if sig == signal.SIGKILL:
                state["returncodeAtKill"] = processes[0].returncode
                state["killExitObserved"] = observe_exit_without_reaping(pid)
                raise PermissionError(1, "zombie-only group")
            self.fail(f"unexpected signal {sig}")

        real_zombie_proof = canary._owned_group_is_zombie_only
        with patch.object(canary, "_owned_group_is_zombie_only", wraps=real_zombie_proof) as zombie_proof, \
                patch.object(canary.os, "killpg", side_effect=inject_darwin_eperm):
            summary = self._run(popen=observed_popen)

        self.assertEqual(summary["status"], "passed")
        self.assertEqual([sig for _, sig in signals], [signal.SIGTERM, signal.SIGKILL])
        self.assertTrue(state["termExitObserved"])
        self.assertTrue(state["killExitObserved"])
        self.assertIsNone(state["returncodeAtKill"])
        self.assertEqual(state["terminateCalls"], 0)
        self.assertEqual(state["pollCalls"], state["pollCallsAtTerm"])
        zombie_proof.assert_called_once()
        self.assertEqual(zombie_proof.call_args.args[0], processes[0].pid)
        self.assertEqual(sorted(path.name for path in (self.tart_home / "vms").iterdir()),
                         ["prepared-macos15"])

    def test_already_reaped_owned_child_receives_no_group_signals_and_retains_clone(self):
        self._write_fake_tart(frames="none")
        self._write_receipt()
        real_wait = canary._wait_owned_vm_exit
        signals = []

        def reap_before_identity_check(process, timeout):
            os.kill(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
            return real_wait(process, timeout)

        with patch.object(canary, "_wait_owned_vm_exit", side_effect=reap_before_identity_check), \
                patch.object(canary.os, "killpg", side_effect=lambda pid, sig: signals.append((pid, sig))):
            with self.assertRaisesRegex(canary.CanaryError, "guest_external_frames_not_observed"):
                self._run()
        self.assertEqual(signals, [])
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "tainted")
        self.assertIn("owned_clone_process_group_identity_lost", saved["cleanupErrors"])
        self.assertIn("owned_clone_retained_vm_process_unreaped", saved["cleanupErrors"])
        self.assertTrue((self.tart_home / "vms" / saved["cloneVmName"]).exists())

    def test_zombie_only_process_group_proof_is_strict_and_bounded(self):
        pid = 41001
        valid_rows = b"41001 41001 Z\n41002 41001 Z+\n"
        cases = (
            (valid_rows, True),
            (b"41001 41001 Z\n41002 41001 S\n", False),
            (b"41002 41001 Z\n", False),
            (b"", False),
            (b"not a ps row\n", False),
        )
        for output, expected in cases:
            with self.subTest(output=output):
                calls = []

                def runner(argv, *, timeout, env):
                    calls.append((argv, timeout, env))
                    return output, b""

                self.assertEqual(canary._owned_group_is_zombie_only(pid, runner, {"SAFE": "1"}), expected)
                self.assertEqual(calls, [
                    (["/bin/ps", "-A", "-o", "pid=", "-o", "pgid=", "-o", "stat="],
                     5, {"SAFE": "1"}),
                ])

        for failure in (OSError("ps unavailable"), canary.CanaryError("ps_failed")):
            with self.subTest(failure=type(failure).__name__):
                self.assertFalse(canary._owned_group_is_zombie_only(
                    pid, lambda *args, **kwargs: (_ for _ in ()).throw(failure), {}))

    def test_failed_final_group_kill_taints_and_retains_clone_before_leader_reaped(self):
        self._write_fake_tart(frames="none")
        self._write_receipt()
        popen = _ObservedPopen(subprocess.Popen)
        failed_group_kill = _UnverifiedGroupKillFailure(popen)
        with patch.object(canary, "_owned_group_is_zombie_only", return_value=False) as zombie_proof, \
                patch.object(canary.os, "killpg", side_effect=failed_group_kill):
            with self.assertRaisesRegex(canary.CanaryError, "guest_external_frames_not_observed"):
                self._run(popen=popen)
        self.assertEqual(failed_group_kill.signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(popen.terminate_calls, 0)
        self.assertEqual(popen.kill_calls, 1)
        zombie_proof.assert_called_once_with(popen.pid, canary._run_bounded, unittest.mock.ANY)
        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "tainted")
        self.assertIn("owned_clone_process_group_kill_failed", saved["cleanupErrors"])
        self.assertIn("owned_clone_retained_vm_process_unreaped", saved["cleanupErrors"])
        self.assertTrue((self.tart_home / "vms" / saved["cloneVmName"]).exists())

    def test_vm_zombie_proof_cleanup_failure_keeps_handles_and_publishes_tainted_manifest(self):
        self._write_fake_tart(frames="none")
        self._write_receipt()
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        proof_process = subprocess.Popen(  # nosec B603 -- fixed sys.executable sleep fixture, no shell.
            [sys.executable, "-c", "import time; time.sleep(60)"], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True,
        )
        vm_process = None

        def observe_vm_popen(argv, **kwargs):
            nonlocal vm_process
            process = real_popen(argv, **kwargs)
            if len(argv) > 1 and argv[1] == "run":
                vm_process = process
            return process

        def inject_vm_group_kill_failure(pid, sig):
            if vm_process is not None and pid == vm_process.pid:
                if sig == signal.SIGTERM:
                    os.kill(pid, sig)
                    return
                if sig == signal.SIGKILL:
                    raise PermissionError(1, "injected EPERM")
            return real_killpg(pid, sig)

        def fail_zombie_proof(*_args, **_kwargs):
            error = canary.CanaryError("tart_command_output_limit")
            error.cleanup_errors = ("proof_process_group_unverified",)
            error.unreaped_process = proof_process
            raise error

        try:
            with patch.object(canary, "_owned_group_is_zombie_only", side_effect=fail_zombie_proof), \
                    patch.object(canary.os, "killpg", side_effect=inject_vm_group_kill_failure):
                with self.assertRaisesRegex(canary.CanaryError, "guest_external_frames_not_observed"):
                    self._run(popen=observe_vm_popen)

            saved = self._assert_published_summary(
                {"kind": "offline-macos-vm-boundary-canary-v1", "status": "tainted",
                 "resultSha256": canary._sha256(
                     (self.evidence / "offline-macos-vm-canary.json").read_bytes())})
            self.assertEqual(saved["error"], "guest_external_frames_not_observed")
            self.assertEqual(saved["status"], "tainted")
            self.assertIn("proof_process_group_unverified", saved["cleanupErrors"])
            self.assertIn("owned_clone_process_group_kill_failed", saved["cleanupErrors"])
            self.assertIn("owned_clone_retained_vm_process_unreaped", saved["cleanupErrors"])
            self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
            self.assertIsNone(proof_process.returncode)
            self.assertIsNotNone(vm_process)
            self.assertIsNone(vm_process.returncode)
            self.assertTrue((self.tart_home / "vms" / saved["cloneVmName"]).exists())
            self.assertNotIn("Popen", (self.evidence / "offline-macos-vm-canary.json").read_text())
        finally:
            _reap_test_children([proof_process, *([vm_process] if vm_process is not None else [])])

    def test_unknown_vm_exit_status_fails_closed_and_still_publishes_manifest(self):
        self._write_fake_tart(frames="none")
        self._write_receipt()
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        vm_process = None
        vm_group_signals = []

        def observe_vm_popen(argv, **kwargs):
            nonlocal vm_process
            process = real_popen(argv, **kwargs)
            if len(argv) > 1 and argv[1] == "run":
                vm_process = process
            return process

        def unknown_vm_status(process, timeout):
            if vm_process is not None and process.pid == vm_process.pid:
                raise canary.CanaryError("tart_command_process_status_unavailable")
            return real_wait_owned_vm_exit(process, timeout)

        real_wait_owned_vm_exit = canary._wait_owned_vm_exit

        def record_killpg(pid, sig):
            if vm_process is not None and pid == vm_process.pid:
                vm_group_signals.append(sig)
                return
            return real_killpg(pid, sig)

        try:
            with patch.object(canary, "_wait_owned_vm_exit", side_effect=unknown_vm_status), \
                    patch.object(canary.os, "killpg", side_effect=record_killpg):
                with self.assertRaisesRegex(canary.CanaryError, "guest_external_frames_not_observed"):
                    self._run(popen=observe_vm_popen)

            saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
            self.assertEqual(saved["error"], "guest_external_frames_not_observed")
            self.assertEqual(saved["status"], "tainted")
            self.assertIn("owned_clone_process_group_identity_lost", saved["cleanupErrors"])
            self.assertIn("owned_clone_retained_vm_process_unreaped", saved["cleanupErrors"])
            self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
            self.assertEqual(vm_group_signals, [])
            self.assertIsNotNone(vm_process)
            self.assertIsNone(vm_process.returncode)
            self.assertTrue((self.tart_home / "vms" / saved["cloneVmName"]).exists())
        finally:
            _reap_test_children([vm_process] if vm_process is not None else [])

    def test_unverified_bounded_child_cleanup_taints_artifact_and_preserves_primary_error(self):
        self._write_fake_tart(frames="both")
        self._write_receipt()
        real_runner = canary._run_bounded
        real_popen = subprocess.Popen
        real_killpg = os.killpg
        injected_recorder = _PythonChildProcesses(real_popen)
        injected_processes = injected_recorder.processes
        vm_process = None

        def record_vm_popen(argv, **kwargs):
            nonlocal vm_process
            process = real_popen(argv, **kwargs)
            if len(argv) > 1 and argv[1] == "run":
                vm_process = process
            return process

        def controlled_killpg(pid, sig):
            if any(process.pid == pid for process in injected_processes):
                raise PermissionError(1, "injected EPERM")
            if vm_process is not None and vm_process.pid == pid:
                os.kill(pid, sig)
                return
            return real_killpg(pid, sig)

        def runner(argv, **kwargs):
            if len(argv) > 1 and argv[1] == "exec" and argv[-1] == "/usr/bin/true":
                with patch.object(canary, "_owned_group_is_zombie_only", return_value=False), \
                        patch.object(canary.subprocess, "Popen", side_effect=injected_recorder):
                    return real_runner(
                        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 20)"],
                        timeout=kwargs["timeout"], env=kwargs["env"], output_limit=8,
                    )
            if len(argv) > 1 and argv[1] == "stop":
                error = canary.CanaryError("tart_command_failed")
                error.cleanup_errors = ("stop_command_process_group_unverified",)
                raise error
            return real_runner(argv, **kwargs)

        error = None
        try:
            with patch.object(canary.os, "killpg", side_effect=controlled_killpg):
                with self.assertRaisesRegex(canary.CanaryError, "tart_command_output_limit") as raised:
                    self._run(popen=record_vm_popen, run_bounded=runner)
                error = raised.exception
        finally:
            for process in injected_processes:
                if process.returncode is None:
                    process.wait(timeout=5)

        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["error"], "tart_command_output_limit")
        self.assertEqual(saved["status"], "tainted")
        self.assertIn("process_group_kill_failed", saved["cleanupErrors"])
        self.assertIn("process_not_reaped_group_unverified", saved["cleanupErrors"])
        self.assertIn("stop_command_process_group_unverified", saved["cleanupErrors"])
        self.assertFalse(saved["vmStop"]["commandSucceeded"])
        self.assertTrue(saved["vmStop"]["stateConfirmedStopped"])
        self.assertEqual(sorted(path.name for path in (self.tart_home / "vms").iterdir()),
                         ["prepared-macos15"])
        self.assertIsNotNone(error)

    def test_inventory_collection_cleanup_metadata_taints_artifact(self):
        import native_workspace_guest_inventory_probe as inventory_probe

        self._write_fake_tart(frames="both")
        self._write_receipt()
        real_runner = canary._run_bounded
        child = object()

        def runner(argv, **kwargs):
            if len(argv) > 5 and argv[1] == "exec" and "-u" in argv and "admin" in argv:
                error = inventory_probe.canary.CanaryError("tart_command_output_limit")
                error.cleanup_errors = ("process_group_kill_failed", "process_not_reaped_group_unverified")
                error.unreaped_process = child
                raise error
            return real_runner(argv, **kwargs)

        with self.assertRaisesRegex(canary.CanaryError, "native_guest_inventory_collection_failed"):
            self._run(native_workspace_guest_inventory=True, run_bounded=runner)

        saved = json.loads((self.evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(saved["status"], "tainted")
        self.assertEqual(saved["error"], "native_guest_inventory_collection_failed")
        self.assertEqual(saved["nativeWorkspaceGuestInventory"]["failureCode"], "tart_command_output_limit")
        self.assertIn("process_group_kill_failed", saved["cleanupErrors"])
        self.assertIn("process_not_reaped_group_unverified", saved["cleanupErrors"])

    def test_guest_output_cap_is_retained_and_hashed(self):
        stdout_path = self.root / "bounded-stdout.bin"
        stderr_path = self.root / "bounded-stderr.bin"
        with self.assertRaisesRegex(canary.CanaryError, "tart_command_output_limit"):
            canary._run_bounded([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * 20)"],
                                timeout=5, env=os.environ, output_limit=8,
                                capture_paths=(stdout_path, stderr_path))
        retained = stdout_path.read_bytes()
        self.assertEqual(retained, b"x" * 8)
        cleanup_errors = []
        self.assertEqual(canary._raw_evidence(stdout_path, 8, cleanup_errors)["sha256"], canary._sha256(retained))
        self.assertEqual(cleanup_errors, [])
        self.assertIsNone(canary._raw_evidence(self.root / "missing-raw-evidence", 8, cleanup_errors))
        self.assertEqual(cleanup_errors, [])
        self.assertEqual(stat.S_IMODE(stdout_path.stat().st_mode), 0o600)

    def test_raw_evidence_change_taints_result_but_clone_cleanup_continues(self):
        self._write_fake_tart(frames="both")
        self._write_receipt()
        target = self.evidence / "guest-stdout.bin"
        real_read = os.read
        real_fstat = os.fstat
        mutation = {}

        def mutate_evidence_during_read(fd, size):
            data = real_read(fd, size)
            if target.exists() and not mutation.get("done"):
                file_stat = os.stat(target, follow_symlinks=False)
                descriptor_stat = real_fstat(fd)
                if (file_stat.st_dev, file_stat.st_ino) == (descriptor_stat.st_dev, descriptor_stat.st_ino):
                    original = target.read_bytes()
                    mutation["original"] = original
                    with target.open("r+b") as stream:
                        stream.write(b"X" + original[1:])
                        stream.flush()
                        os.fsync(stream.fileno())
                    mutation["done"] = True
            return data

        try:
            with patch.object(canary.os, "read", side_effect=mutate_evidence_during_read):
                summary = self._run()
        finally:
            if mutation.get("original") is not None:
                with target.open("r+b") as stream:
                    stream.write(mutation["original"])
                    stream.truncate()
                    stream.flush()
                    os.fsync(stream.fileno())

        saved = self._assert_published_summary(summary)
        self.assertTrue(mutation.get("done"))
        self.assertEqual(saved["status"], "tainted")
        self.assertIn("raw_evidence_file_changed_during_measurement", saved["cleanupErrors"])
        self.assertIsNone(saved["rawEvidence"]["guest-stdout.bin"])
        self.assertTrue(self.base_vm_dir.exists())
        self.assertEqual(sorted(path.name for path in (self.tart_home / "vms").iterdir()),
                         ["prepared-macos15"])

    def test_missing_raw_capture_on_success_taints_but_clone_cleanup_continues(self):
        self._write_fake_tart(frames="both")
        self._write_receipt()
        real_raw_evidence = canary._raw_evidence

        def omit_capture(path, maximum, cleanup_errors):
            if Path(path).name == "tart-stderr.bin":
                return None
            return real_raw_evidence(path, maximum, cleanup_errors)

        with patch.object(canary, "_raw_evidence", side_effect=omit_capture):
            summary = self._run()
        saved = self._assert_published_summary(summary)
        self.assertEqual(saved["status"], "tainted")
        self.assertIn("raw_evidence_incomplete", saved["cleanupErrors"])
        self.assertIsNone(saved["rawEvidence"]["tart-stderr.bin"])
        self.assertEqual(sorted(path.name for path in (self.tart_home / "vms").iterdir()),
                         ["prepared-macos15"])

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

    def test_json_recursion_errors_are_normalized_at_boundaries(self):
        with patch.object(canary.json, "loads", side_effect=RecursionError("injected")) as loads:
            with self.assertRaisesRegex(canary.CanaryError, "invalid_receipt"):
                canary._read_receipt(self.receipt_path)
            loads.assert_called_once()

        with patch.object(canary.json, "loads", side_effect=RecursionError("injected")) as loads:
            with self.assertRaisesRegex(canary.CanaryError, "invalid_base_vm_config"):
                canary._base_vm_measurement(self.tart_home, "prepared-macos15", self.receipt)
            loads.assert_called_once()

        with patch.object(canary.json, "loads", side_effect=RecursionError("injected")) as loads:
            with self.assertRaisesRegex(canary.CanaryError, "invalid_guest_canary_result"):
                canary._guest_result(b"{}", "n" * 32)
            loads.assert_called_once()

    def test_json_boundaries_reject_parsed_nonobject_shapes(self):
        self.receipt_path.write_text("[]")
        with self.assertRaisesRegex(canary.CanaryError, "invalid_receipt_shape"):
            canary._read_receipt(self.receipt_path)

        (self.base_vm_dir / "config.json").write_text("[]")
        with self.assertRaisesRegex(canary.CanaryError, "base_vm_config_not_macos_arm64"):
            canary._base_vm_measurement(self.tart_home, "prepared-macos15", self.receipt)

        with self.assertRaisesRegex(canary.CanaryError, "guest_canary_checks_failed"):
            canary._guest_result(b"[]", "n" * 32)

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

    def test_tart_home_rejects_writable_ancestor_before_tart_or_base_vm_work(self):
        parent = self.root / "tart-home-writable-parent"
        parent.mkdir(mode=0o700)
        home = parent / "tart-home"
        home.mkdir(mode=0o700)
        os.chmod(parent, 0o777)  # nosec B103 -- unsafe ancestor must be rejected.
        foreign_uid = 1 if os.getuid() != 1 else 2
        real_lstat = os.lstat
        real_stat = os.stat

        def fake_owner(path, stat_call):
            info = stat_call(path)
            if Path(path) == parent:
                return _stat_with_uid(info, foreign_uid)
            return info

        with patch.object(canary.os, "lstat", side_effect=lambda path: fake_owner(path, real_lstat)), \
                patch.object(canary.os, "stat", side_effect=lambda path, **kwargs: fake_owner(
                    path, lambda candidate: real_stat(candidate, **kwargs))), \
                patch.object(canary, "TART_BINARY_SHA256", self.receipt["tartBinarySha256"]), \
                patch.object(canary, "_tart_identity", return_value=self.tart) as tart_identity, \
                patch.object(canary, "_base_vm_measurement",
                             side_effect=canary.CanaryError("base_measurement_reached")) as measurement:
            run = unittest.mock.Mock(side_effect=canary.CanaryError("clone_reached"))
            with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_home"):
                canary.qualify("prepared-macos15", self.receipt_path, self.evidence,
                               tart=str(self.tart), tart_home=home, run_bounded=run)
            tart_identity.assert_not_called()
            measurement.assert_not_called()
            run.assert_not_called()

    def test_tart_home_rejects_symlink_ancestor_before_tart_or_base_vm_work(self):
        real_parent = self.root / "real-tart-home-parent"
        real_parent.mkdir(mode=0o700)
        home = real_parent / "tart-home"
        home.mkdir(mode=0o700)
        symlink_parent = self.root / "symlink-tart-home-parent"
        symlink_parent.symlink_to(real_parent, target_is_directory=True)
        requested_home = symlink_parent / "tart-home"
        with patch.object(canary, "TART_BINARY_SHA256", self.receipt["tartBinarySha256"]), \
                patch.object(canary, "_tart_identity", return_value=self.tart) as tart_identity, \
                patch.object(canary, "_base_vm_measurement",
                             side_effect=canary.CanaryError("base_measurement_reached")) as measurement:
            run = unittest.mock.Mock(side_effect=canary.CanaryError("clone_reached"))
            with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_home"):
                canary.qualify("prepared-macos15", self.receipt_path, self.evidence,
                               tart=str(self.tart), tart_home=requested_home, run_bounded=run)
            tart_identity.assert_not_called()
            measurement.assert_not_called()
            run.assert_not_called()

    def test_tart_home_root_sticky_parent_is_allowed_but_nonroot_sticky_is_rejected(self):
        root_sticky = self.root / "root-sticky-parent"
        nonroot_sticky = self.root / "nonroot-sticky-parent"
        root_sticky.mkdir(mode=0o700)
        nonroot_sticky.mkdir(mode=0o700)
        os.chmod(root_sticky, 0o1777)  # nosec B103 -- model a root-owned sticky ancestor.
        os.chmod(nonroot_sticky, 0o1777)  # nosec B103 -- model a nonroot sticky ancestor.
        root_home = root_sticky / "tart-home"
        nonroot_home = nonroot_sticky / "tart-home"
        root_home.mkdir(mode=0o700)
        nonroot_home.mkdir(mode=0o700)
        root_uid = 0
        operator_uid = os.getuid() if os.getuid() != 0 else 1
        real_lstat = os.lstat
        real_stat = os.stat

        def model_sticky_owners(path, stat_call):
            info = stat_call(path)
            if Path(path) == root_sticky:
                return _stat_with_uid(info, root_uid)
            if Path(path) == nonroot_sticky:
                return _stat_with_uid(info, operator_uid)
            if Path(path) in (root_home, nonroot_home):
                return _stat_with_uid(info, operator_uid)
            return info

        with patch.object(canary.os, "getuid", return_value=operator_uid), \
                patch.object(canary.os, "lstat", side_effect=lambda path: model_sticky_owners(path, real_lstat)), \
                patch.object(canary.os, "stat", side_effect=lambda path, **kwargs: model_sticky_owners(
                    path, lambda candidate: real_stat(candidate, **kwargs))):
            self.assertEqual(canary._safe_tart_home(root_home), root_home.resolve())
            with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_home"):
                canary._safe_tart_home(nonroot_home)

    def test_tart_home_rejects_writable_base_files_before_clone(self):
        files = (self.base_vm_dir / "config.json", self.base_vm_dir / "disk.img",
                 self.base_vm_dir / "nvram.bin")
        for target in files:
            with self.subTest(target=target.name):
                original_mode = stat.S_IMODE(target.stat().st_mode)
                os.chmod(target, 0o777)  # nosec B103 -- world-writable base file must be rejected.
                try:
                    with patch.object(canary, "TART_BINARY_SHA256", self.receipt["tartBinarySha256"]), \
                            patch.object(canary, "_tart_identity", return_value=self.tart):
                        run = unittest.mock.Mock(side_effect=canary.CanaryError("clone_reached"))
                        evidence = self.root / f"evidence-mode-{target.name}"
                        evidence.mkdir(mode=0o700)
                        with self.assertRaisesRegex(canary.CanaryError, "unsafe_base_vm_file"):
                            canary.qualify("prepared-macos15", self.receipt_path, evidence,
                                           tart=str(self.tart), tart_home=self.tart_home, run_bounded=run)
                        run.assert_not_called()
                finally:
                    os.chmod(target, original_mode)

    def test_tart_home_rejects_foreign_owned_base_file_before_clone(self):
        target = self.base_vm_dir / "config.json"
        target_stat = os.stat(target, follow_symlinks=False)
        foreign_uid = 1 if os.getuid() != 1 else 2
        real_fstat = os.fstat

        def foreign_file_owner(fd):
            info = real_fstat(fd)
            if (info.st_dev, info.st_ino) == (target_stat.st_dev, target_stat.st_ino):
                return _stat_with_uid(info, foreign_uid)
            return info

        with patch.object(canary, "TART_BINARY_SHA256", self.receipt["tartBinarySha256"]), \
                patch.object(canary, "_tart_identity", return_value=self.tart), \
                patch.object(canary.os, "fstat", side_effect=foreign_file_owner):
            run = unittest.mock.Mock(side_effect=canary.CanaryError("clone_reached"))
            with self.assertRaisesRegex(canary.CanaryError, "unsafe_base_vm_file"):
                canary.qualify("prepared-macos15", self.receipt_path, self.evidence,
                               tart=str(self.tart), tart_home=self.tart_home, run_bounded=run)
            run.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_tart_home_and_base_path_write_acls_reject_before_clone(self):
        vms = self.tart_home / "vms"
        targets = (self.root, self.tart_home, vms, self.base_vm_dir,
                   self.base_vm_dir / "config.json", self.base_vm_dir / "disk.img",
                   self.base_vm_dir / "nvram.bin")
        for target in targets:
            with self.subTest(target=target.relative_to(self.root)):
                try:
                    _set_macos_acl(target, "+a", "everyone allow write")
                    if target == self.root:
                        with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_acl"):
                            canary._safe_tart_home(self.tart_home)
                        continue
                    with patch.object(canary, "TART_BINARY_SHA256", self.receipt["tartBinarySha256"]), \
                            patch.object(canary, "_tart_identity", return_value=self.tart) as tart_identity:
                        run = unittest.mock.Mock(side_effect=canary.CanaryError("clone_reached"))
                        evidence = self.root / f"evidence-acl-{target.name or 'root'}"
                        evidence.mkdir(mode=0o700)
                        with self.assertRaisesRegex(canary.CanaryError, "unsafe_tart_acl"):
                            canary.qualify("prepared-macos15", self.receipt_path, evidence,
                                           tart=str(self.tart), tart_home=self.tart_home,
                                           run_bounded=run)
                        if target in (self.root, self.tart_home):
                            tart_identity.assert_not_called()
                        else:
                            tart_identity.assert_called_once()
                        run.assert_not_called()
                finally:
                    _set_macos_acl(target, "-N")

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_tart_home_and_base_read_or_deny_acls_are_accepted(self):
        vms = self.tart_home / "vms"
        config = self.base_vm_dir / "config.json"
        try:
            _set_macos_acl(self.tart_home, "+a", "everyone allow read")
            _set_macos_acl(vms, "+a", "everyone deny write")
            _set_macos_acl(config, "+a", "everyone deny write")
            self.assertEqual(canary._safe_tart_home(self.tart_home), self.tart_home.resolve())
            measured_config, disk_bytes = canary._base_vm_measurement(
                self.tart_home, "prepared-macos15", self.receipt,
            )
            self.assertEqual(measured_config["os"], "darwin")
            self.assertEqual(disk_bytes, self.receipt["preparedSnapshot"]["bytes"])
        finally:
            _set_macos_acl(self.tart_home, "-N")
            _set_macos_acl(vms, "-N")
            _set_macos_acl(config, "-N")

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
            with patch.object(canary, "_wait_owned_vm_exit", return_value=None):
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

    def test_evidence_directory_rejects_writable_ancestor_before_tart(self):
        parent = self.root / "evidence-writable-parent"
        parent.mkdir(mode=0o700)
        evidence = parent / "private-evidence"
        evidence.mkdir(mode=0o700)
        os.chmod(parent, 0o777)  # nosec B103 -- lower-UID writable parent must be rejected.
        foreign_uid = 1 if os.getuid() != 1 else 2
        real_lstat = os.lstat

        def fake_parent_owner(path):
            info = real_lstat(path)
            if Path(path) == parent:
                return _stat_with_uid(info, foreign_uid)
            return info

        with patch.object(canary.os, "lstat", side_effect=fake_parent_owner), \
                patch.object(canary, "TART_BINARY_SHA256", self.receipt["tartBinarySha256"]), \
                patch.object(canary, "_tart_identity") as tart_identity, \
                patch.object(canary, "_base_vm_measurement",
                             side_effect=canary.CanaryError("base_measurement_reached")) as measurement:
            run = unittest.mock.Mock()
            with self.assertRaisesRegex(canary.CanaryError, "unsafe_evidence_directory"):
                canary.qualify("prepared-macos15", self.receipt_path, evidence,
                               tart=str(self.tart), tart_home=self.tart_home, run_bounded=run)
            tart_identity.assert_not_called()
            measurement.assert_not_called()
            run.assert_not_called()

    def test_evidence_directory_rejects_symlink_ancestor_before_tart(self):
        real_parent = self.root / "real-evidence-parent"
        real_parent.mkdir(mode=0o700)
        evidence = real_parent / "private-evidence"
        evidence.mkdir(mode=0o700)
        alias = self.root / "evidence-parent-alias"
        alias.symlink_to(real_parent, target_is_directory=True)
        requested = alias / "private-evidence"
        with patch.object(canary, "TART_BINARY_SHA256", self.receipt["tartBinarySha256"]), \
                patch.object(canary, "_tart_identity") as tart_identity, \
                patch.object(canary, "_base_vm_measurement",
                             side_effect=canary.CanaryError("base_measurement_reached")) as measurement:
            run = unittest.mock.Mock()
            with self.assertRaisesRegex(canary.CanaryError, "unsafe_evidence_directory"):
                canary.qualify("prepared-macos15", self.receipt_path, requested,
                               tart=str(self.tart), tart_home=self.tart_home, run_bounded=run)
            tart_identity.assert_not_called()
            measurement.assert_not_called()
            run.assert_not_called()

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_evidence_path_write_acls_reject_before_tart(self):
        for target in (self.root, self.evidence):
            with self.subTest(target=target.name):
                try:
                    _set_macos_acl(target, "+a", "everyone allow write")
                    with patch.object(canary, "TART_BINARY_SHA256", self.receipt["tartBinarySha256"]), \
                            patch.object(canary, "_tart_identity") as tart_identity, \
                            patch.object(canary, "_base_vm_measurement",
                                         side_effect=canary.CanaryError("base_measurement_reached")) as measurement:
                        run = unittest.mock.Mock()
                        with self.assertRaisesRegex(canary.CanaryError, "unsafe_evidence_directory"):
                            canary.qualify("prepared-macos15", self.receipt_path, self.evidence,
                                           tart=str(self.tart), tart_home=self.tart_home,
                                           run_bounded=run)
                        tart_identity.assert_not_called()
                        measurement.assert_not_called()
                        run.assert_not_called()
                finally:
                    _set_macos_acl(target, "-N")

    @unittest.skipUnless(sys.platform == "darwin", "requires macOS extended ACLs")
    def test_macos_evidence_read_allow_and_deny_write_acls_are_accepted(self):
        try:
            _set_macos_acl(self.root, "+a", "everyone deny write")
            _set_macos_acl(self.evidence, "+a", "everyone allow read")
            self.assertEqual(canary._safe_dir(self.evidence, empty=True), self.evidence.resolve())
        finally:
            _set_macos_acl(self.root, "-N")
            _set_macos_acl(self.evidence, "-N")

    def test_main_uses_qualify_summary_after_manifest_is_replaced(self):
        self._write_fake_tart(frames="both", fail_delete=True)
        self._write_receipt()
        evidence = self.root / "main-evidence"
        evidence.mkdir(mode=0o700)
        real_qualify = canary.qualify
        returned = {}

        def qualify_then_replace_manifest(*args, **kwargs):
            summary = real_qualify(*args, **kwargs)
            manifest = Path(args[2]) / "offline-macos-vm-canary.json"
            published_raw = manifest.read_bytes()
            returned["summary"] = summary
            returned["publishedRaw"] = published_raw
            forged = {"kind": "offline-macos-vm-boundary-canary-v1", "status": "passed"}
            manifest.write_bytes(json.dumps(forged, sort_keys=True, separators=(",", ":")).encode() + b"\n")
            return summary

        class FixedUuid:
            hex = "c" * 32

        output = StringIO()
        with patch.object(canary, "TART_BINARY_SHA256", canary._sha256(self.tart.read_bytes())), \
                patch.object(canary, "qualify", side_effect=qualify_then_replace_manifest), \
                patch.object(canary.uuid, "uuid4", return_value=FixedUuid()), \
                redirect_stdout(output):
            exit_code = canary.main([
                "--base-vm", "prepared-macos15", "--receipt", str(self.receipt_path),
                "--evidence-dir", str(evidence), "--tart", str(self.tart),
                "--tart-home", str(self.tart_home),
            ])

        raw = returned["publishedRaw"]
        expected = {"kind": "offline-macos-vm-boundary-canary-v1", "status": "tainted",
                    "resultSha256": canary._sha256(raw)}
        self.assertEqual(returned["summary"], expected)
        self.assertEqual(json.loads(raw)["status"], "tainted")
        self.assertEqual(exit_code, 1)
        self.assertEqual(output.getvalue(), json.dumps(expected, separators=(",", ":")) + "\n")
        forged = json.loads((evidence / "offline-macos-vm-canary.json").read_text())
        self.assertEqual(forged["status"], "passed")


if __name__ == "__main__":
    unittest.main()
