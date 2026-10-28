"""Offline supervisor tests: no host preferences, Tart binary, or Softnet helper."""

import hashlib
import json
import os
from pathlib import Path
import plistlib
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import selectors
import unittest
from types import SimpleNamespace
from unittest.mock import call, patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import qualify_offline_macos_vm as canary  # noqa: E402
import qualify_softnet_macos_vm as supervisor  # noqa: E402
import softnet_recovery as recovery  # noqa: E402
import softnet_run_state as run_state  # noqa: E402


class FakeProcess:
    """Minimal process record for supervisor tests that never launch binaries."""

    _pid = 71000

    def __init__(self, name):
        """Create an unreaped fake child with stable diagnostic streams."""
        type(self)._pid += 1
        self.pid = type(self)._pid
        self.name = name
        self.returncode = None
        self.stdout = object()
        self.stderr = object()
        self.wait_calls = []

    def wait(self, timeout=None):
        """Record reaping and return a successful exit status."""
        self.wait_calls.append(timeout)
        self.returncode = 0
        return 0


class FakeThread:
    """Joinable fake log drainer for fail-closed cleanup cases."""

    def __init__(self, alive=False, events=None, label="thread"):
        """Capture join calls and configure the reported liveness."""
        self.alive = alive
        self.events = events if events is not None else []
        self.label = label

    def join(self, timeout=None):
        """Record the supervisor's bounded join attempt."""
        self.events.append(("join", self.label, timeout))

    def is_alive(self):
        """Return the fixture's fixed thread state."""
        return self.alive


class SoftnetSupervisorTests(unittest.TestCase):
    """Exercise supervisor decisions without touching host preferences or tools."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="softnet-supervisor-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.admission = {
            "kind": "softnet-startup-admission-v1", "ownerUid": 501,
            "tartHome": str(self.root / "tart-home"),
            "vmName": "softnet-canary-" + "a" * 32,
            "macAddress": "02:00:00:00:00:01",
            "measurement": {"configSha256": "a" * 64, "configBytes": 2,
                             "diskSha256": "b" * 64, "diskBytes": 3,
                             "nvramSha256": "c" * 64, "nvramBytes": 4},
        }

    def test_root_darwin_gate_rejects_before_opening_state(self):
        for uid, platform in ((501, "darwin"), (0, "linux"), (501, "linux")):
            with self.subTest(uid=uid, platform=platform), \
                    patch.object(supervisor.os, "geteuid", return_value=uid), \
                    patch.object(supervisor.sys, "platform", platform), \
                    patch.object(supervisor, "_admission", return_value=(
                        self.admission, SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_name="owner"),
                        "staff", "a" * 64)), \
                    patch.object(supervisor, "_exercise", return_value={
                        "vmReaped": True, "helperReaped": True, "vmStopped": True}), \
                    patch.object(supervisor, "State") as state:
                with self.assertRaisesRegex(recovery.RecoveryError, "root_macos_required"):
                    supervisor.qualify(self.root)
                state.assert_not_called()

    def test_qualify_keeps_one_fixed_global_state_root_for_every_admission_directory(self):
        state_roots = []
        admission_dirs = []

        class State:
            """Record the state root selected by qualification."""

            def __init__(self, root):
                """Save the requested run-state directory."""
                state_roots.append(Path(root))

            def __enter__(self):
                """Enter the fake state lock."""
                return self

            def __exit__(self, *args):
                """Leave the fake state lock without suppressing exceptions."""
                return False

            def begin(self, identity):
                """Return a stable fake run path for the qualification call."""
                return self_outer.root / "run", "d" * 32

            def complete(self, run, evidence):
                """Assert that qualification completed only with all stop proofs."""
                self_outer.assertEqual(evidence, {"vmReaped": True, "helperReaped": True, "vmStopped": True})

        self_outer = self
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_name="owner")

        def admit(directory):
            admission_dirs.append(Path(directory))
            return self.admission, account, "staff", "e" * 64

        for name in ("admission-one", "admission-two"):
            with patch.object(supervisor.os, "geteuid", return_value=0), \
                    patch.object(supervisor.sys, "platform", "darwin"), \
                    patch.object(supervisor, "State", State), \
                    patch.object(supervisor, "_admission", side_effect=admit), \
                    patch.object(supervisor, "_exercise", return_value={
                        "vmReaped": True, "helperReaped": True, "vmStopped": True}):
                supervisor.qualify(self.root / name)

        self.assertEqual(admission_dirs, [self.root / "admission-one", self.root / "admission-two"])
        self.assertEqual(state_roots, [supervisor.STATE_ROOT, supervisor.STATE_ROOT])

    def test_real_state_capture_exercise_restore_complete_and_reopen_integration(self):
        state_root = self.root / "state"
        state_root.mkdir(mode=0o700)
        initial = plistlib.dumps({"value": "before"}, fmt=plistlib.FMT_BINARY)
        target = plistlib.dumps({"value": "softnet"}, fmt=plistlib.FMT_BINARY)
        preferences_state = {"current": initial}

        class Preferences:
            """Mutable fake preference source used by real recovery code."""

            def __enter__(self):
                """Open a fake preference session."""
                return self

            def __exit__(self, *args):
                """Close a fake preference session without suppressing failures."""
                return False

            def read(self):
                """Return the current binary plist."""
                return preferences_state["current"]

            def encode_target(self):
                """Return the expected Softnet target plist."""
                return target

            def validate(self, value):
                """Require a syntactically valid plist value."""
                plistlib.loads(value)

            def equal(self, left, right):
                """Compare complete encoded preference values."""
                return left == right

            def write(self, value):
                """Apply a restored encoded value to fixture state."""
                preferences_state["current"] = value

            def commit_apply(self):
                """Model a successful preference commit."""

            def synchronize(self):
                """Model a successful preference synchronization."""

        class FinishedThread:
            """Finished drainer fixture accepted by the state completion checks."""

            def join(self, timeout=None):
                """Accept the supervisor's bounded join call."""

            def is_alive(self):
                """Report that the fake drainer has exited."""
                return False

        def bounded(argv, **kwargs):
            if argv[1:2] == ["get"]:
                return b'{"Running":false,"State":"stopped"}', 0
            return b"", 0

        def popen(argv, **kwargs):
            process = FakeProcess("helper" if str(argv[0]) == str(supervisor.SOFTNET) else "vm")
            if process.name == "helper":
                preferences_state["current"] = target
            return process

        def start_logs(process, directory, failures):
            directory.mkdir(mode=0o700)
            for filename in ("tart-stdout.bin", "tart-stderr.bin"):
                fd = os.open(directory / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                os.write(fd, b"")
                os.close(fd)
            return FinishedThread()

        def stop_owned(process, log_thread=None):
            process.returncode = 0

        owner_uid = os.getuid()
        account = SimpleNamespace(pw_uid=owner_uid, pw_gid=os.getgid(), pw_name="owner")
        identity = {"vmName": self.admission["vmName"], "macAddress": self.admission["macAddress"],
                    "tartBinarySha256": canary.TART_BINARY_SHA256,
                    "softnetBinarySha256": supervisor.SOFTNET_SHA256,
                    "admissionSha256": "f" * 64}
        with patch.object(recovery, "OWNER_UID", owner_uid), \
                patch.object(recovery.os, "geteuid", return_value=owner_uid), \
                patch.object(canary, "_run_bounded", side_effect=bounded), \
                patch.object(supervisor.subprocess, "Popen", side_effect=popen), \
                patch.object(supervisor, "_start_logs", side_effect=start_logs), \
                patch.object(supervisor, "_stop_owned", side_effect=stop_owned), \
                patch.object(supervisor, "_child_exited", return_value=False):
            with run_state.State(state_root) as state:
                run, _ = state.begin(identity)
                supervisor._exercise(run, {**self.admission, "tartHome": str(self.root / "tart-home")},
                                     account, "staff", Preferences)
                state.complete(run, {"vmReaped": True, "helperReaped": True, "vmStopped": True})
            self.assertEqual(preferences_state["current"], initial)
            with run_state.State(state_root):
                pass
        for run in state_root.iterdir():
            if run.is_dir():
                for log_dir in (run / "helper-logs", run / "vm-logs"):
                    self.assertEqual({path.name for path in log_dir.iterdir()},
                                     {"tart-stdout.bin", "tart-stderr.bin"})
                    self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600
                                        for path in log_dir.iterdir()))

    def test_admission_accepts_exact_measured_assets_and_rejects_schema_measurement_and_digest(self):
        admission_root = self.root / "admission-root"
        admission_root.mkdir()
        home = self.root / "home"
        vm = home / "vms" / self.admission["vmName"]
        vm.mkdir(parents=True)
        home.chmod(0o700)
        (vm / "config.json").write_text(json.dumps({"os": "darwin", "arch": "arm64",
                                                       "macAddress": self.admission["macAddress"]}))
        (vm / "disk.img").write_bytes(b"dsk")
        (vm / "nvram.bin").write_bytes(b"nvram")
        self.admission["tartHome"] = str(home)
        measured = {"config": (hashlib.sha256((vm / "config.json").read_bytes()).hexdigest(),
                                (vm / "config.json").stat().st_size),
                    "disk": (hashlib.sha256(b"dsk").hexdigest(), 3),
                    "nvram": (hashlib.sha256(b"nvram").hexdigest(), 5)}
        self.admission["measurement"] = {
            key + suffix: value
            for key, (digest, size) in measured.items()
            for suffix, value in (("Sha256", digest), ("Bytes", size))
        }
        admission_path = admission_root / "admission.plist"
        admission_path.write_bytes(plistlib.dumps(self.admission))
        account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid(), pw_name="owner")
        with patch.object(supervisor.recovery, "_directory", side_effect=lambda _: os.open(admission_path, os.O_RDONLY)), \
                patch.object(supervisor.recovery, "_read", return_value=plistlib.dumps(self.admission)), \
                patch.object(supervisor.pwd, "getpwuid", return_value=account), \
                patch.object(supervisor.grp, "getgrgid", return_value=SimpleNamespace(gr_name="staff")), \
                patch.object(supervisor, "_protected", side_effect=lambda path, *a, **k: Path(path)), \
                patch.object(supervisor.canary, "_hash_file", side_effect=lambda path, **k: measured[Path(path).name.split(".")[0]]), \
                patch.object(supervisor, "_binary") as binary:
            parsed, actual_account, group, digest = supervisor._admission(admission_root)
        self.assertEqual(parsed, self.admission)
        self.assertIs(actual_account, account)
        self.assertEqual(group, "staff")
        self.assertEqual(digest, hashlib.sha256(plistlib.dumps(self.admission)).hexdigest())
        self.assertEqual(binary.call_args_list,
                         [call(supervisor.TART, canary.TART_BINARY_SHA256),
                          call(supervisor.SOFTNET, supervisor.SOFTNET_SHA256)])

        mutations = (
            ("invalid_admission", lambda v: v.update(extra=True)),
            ("invalid_admission", lambda v: v.update(ownerUid=True)),
            ("invalid_admission", lambda v: v["measurement"].update(diskBytes=2**63)),
            ("invalid_admission", lambda v: v["measurement"].update(diskSha256="not-a-digest")),
            ("vm_measurement_mismatch", lambda v: v["measurement"].update(
                configBytes=v["measurement"]["configBytes"] + 1)),
        )
        for reason, mutate in mutations:
            invalid = json.loads(json.dumps(self.admission))
            mutate(invalid)
            with self.subTest(invalid=invalid), \
                    patch.object(supervisor.recovery, "_directory", side_effect=lambda _: os.open(admission_path, os.O_RDONLY)), \
                    patch.object(supervisor.recovery, "_read", return_value=plistlib.dumps(invalid)), \
                    patch.object(supervisor.pwd, "getpwuid", return_value=account), \
                    patch.object(supervisor.grp, "getgrgid", return_value=SimpleNamespace(gr_name="staff")), \
                    patch.object(supervisor, "_protected", side_effect=lambda path, *a, **k: Path(path)), \
                    patch.object(supervisor.canary, "_hash_file", side_effect=lambda path, **k: measured[Path(path).name.split(".")[0]]), \
                    patch.object(supervisor, "_binary"):
                with self.assertRaisesRegex(recovery.RecoveryError, reason):
                    supervisor._admission(admission_root)

    def test_protected_paths_and_pinned_binary_require_safe_files_and_digest(self):
        safe = self.root / "protected"
        safe.mkdir(mode=0o700)
        file_path = safe / "input"
        file_path.write_bytes(b"fixture")
        link_path = safe / "link"
        link_path.symlink_to(file_path)
        with patch.object(supervisor.canary, "_check_tart_acl"):
            self.assertEqual(supervisor._protected(file_path, os.getuid()), file_path)
            with self.assertRaisesRegex(recovery.RecoveryError, "unsafe_input_path"):
                supervisor._protected(link_path, os.getuid())
            writable = self.root / "writable"
            writable.mkdir(mode=0o700)
            (writable / "input").touch()
            writable.chmod(0o777)
            with self.assertRaisesRegex(recovery.RecoveryError, "unsafe_input_path"):
                supervisor._protected(writable / "input", os.getuid())

        class BinaryPath:
            """Fake filesystem metadata for root-pinned binary validation."""

            def __init__(self, uid=0, mode=0o555):
                """Set the ownership and permission bits exposed by stat."""
                self.uid, self.mode = uid, mode

            def stat(self):
                """Return synthetic regular-file metadata."""
                return SimpleNamespace(st_uid=self.uid, st_mode=stat.S_IFREG | self.mode)

        expected = "a" * 64
        with patch.object(supervisor, "_protected", side_effect=lambda path, *_a, **_k: path), \
                patch.object(supervisor.canary, "_hash_file", return_value=(expected, 7)):
            supervisor._binary(BinaryPath(), expected)
            for path, reason, digest in ((BinaryPath(mode=0o755), "unsafe_binary", expected),
                                         (BinaryPath(uid=os.getuid() or 42), "unsafe_binary", expected),
                                         (BinaryPath(), "binary_digest_mismatch", "b" * 64)):
                with self.subTest(reason=reason), self.assertRaisesRegex(recovery.RecoveryError, reason):
                    supervisor._binary(path, digest)

    def test_bounded_runner_uses_injected_factory_for_a_real_fixed_child(self):
        calls = []

        def factory(argv, **kwargs):
            calls.append((argv, kwargs.copy()))
            return subprocess.Popen(argv, **kwargs)

        argv = [sys.executable, "-c", "print('bounded-child')"]
        stdout, stderr = canary._run_bounded(
            argv, timeout=5, env={"PATH": os.environ["PATH"]}, popen=factory)
        self.assertEqual(stdout, b"bounded-child\n")
        self.assertEqual(stderr, b"")
        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0][0], argv)
        self.assertIs(calls[0][1]["stdin"], subprocess.DEVNULL)
        self.assertTrue(calls[0][1]["start_new_session"])

    def _exercise_patches(self, *, capture_error=None, restore_error=None, stop_error=None,
                          stopped=True, log_alive=False, command_error=None):
        events = []
        processes = []
        get_count = 0

        def bounded(argv, **kwargs):
            nonlocal get_count
            events.append(("command", tuple(argv), kwargs.copy()))
            if argv[1:2] == ["get"]:
                get_count += 1
                return (b'{"Running":false,"State":"stopped"}' if get_count == 1 or stopped else
                        b'{"Running":true,"State":"running"}'), 0
            if argv[1:2] == ["exec"] and command_error:
                raise command_error
            if argv[1:2] == ["exec"]:
                return b"", 0
            return b"", 0

        def popen(argv, **kwargs):
            process = FakeProcess("helper" if str(argv[0]) == str(supervisor.SOFTNET) else "vm")
            events.append(("popen", tuple(argv), kwargs.copy()))
            processes.append(process)
            return process

        threads = []

        def start_logs(process, directory, failures):
            thread = FakeThread(alive=log_alive, events=events, label=process.name)
            threads.append(thread)
            events.append(("logs", process.name))
            return thread

        def stop_owned(process, log_thread=None):
            events.append(("stop_owned", process.name, log_thread))
            if stop_error == process.name:
                raise RuntimeError("unproven child")

        def capture(*args, **kwargs):
            events.append(("capture",))
            if capture_error:
                raise capture_error

        def restore(*args, **kwargs):
            events.append(("restore",))
            if restore_error:
                raise restore_error

        class Preferences:
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return b"target"
            def encode_target(self):
                return b"target"
            def equal(self, left, right):
                return left == right

        stack = [patch.object(supervisor.canary, "_run_bounded", side_effect=bounded),
                 patch.object(supervisor.subprocess, "Popen", side_effect=popen),
                 patch.object(supervisor, "_start_logs", side_effect=start_logs),
                 patch.object(supervisor, "_record"),
                 patch.object(supervisor, "_stop_owned", side_effect=stop_owned),
                 patch.object(supervisor, "_child_exited", return_value=False),
                 patch.object(supervisor.canary, "_install_termination_handlers", return_value=None),
                 patch.object(supervisor.canary, "_ignore_termination_handlers"),
                 patch.object(supervisor.canary, "_restore_termination_handlers"),
                 patch.object(supervisor.recovery, "capture", side_effect=capture),
                 patch.object(supervisor.recovery, "restore", side_effect=restore),
                 patch.object(supervisor.time, "sleep"),
                 patch.object(supervisor.time, "monotonic", side_effect=[0, 0, 0, 0, 1000]),]
        return stack, events, processes, threads, Preferences

    def test_capture_precedes_launch_and_tart_is_owner_scoped_fixed_argv(self):
        stack, events, processes, threads, preferences = self._exercise_patches()
        with stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7], stack[8], stack[9], stack[10], stack[11], stack[12]:
            result = supervisor._exercise(self.root, self.admission,
                                           SimpleNamespace(pw_uid=501, pw_gid=20, pw_name="owner"),
                                           "staff", preferences)
        self.assertTrue(all(result.values()))
        self.assertLess(events.index(("capture",)), next(i for i, e in enumerate(events) if e[0] == "popen"))
        helper, vm = [e for e in events if e[0] == "popen"]
        self.assertEqual(helper[1], (str(supervisor.SOFTNET), "--vm-fd", "0", "--vm-mac-address",
                                     self.admission["macAddress"], "--block=0.0.0.0/0", "--user", "owner",
                                     "--group", "staff"))
        self.assertEqual((helper[2]["start_new_session"], helper[2]["close_fds"]), (True, True))
        self.assertEqual(helper[2]["stdin"].family, socket.AF_UNIX)
        self.assertFalse(os.isatty(helper[2]["stdin"].fileno()))
        self.assertFalse({"user", "group", "extra_groups"} & helper[2].keys())
        self.assertEqual(vm[1][1:], ("run", self.admission["vmName"], "--net-fd=" + str(vm[2]["pass_fds"][0]),
                                     "--no-clipboard", "--no-audio", "--no-usb-accessories", "--no-graphics"))
        self.assertEqual((vm[2].get("user"), vm[2].get("group"), vm[2].get("extra_groups")), (501, 20, []))
        self.assertIs(vm[2]["stdin"], subprocess.DEVNULL)
        self.assertNotIn("--user", vm[1])
        commands = [event for event in events if event[0] == "command"]
        self.assertGreaterEqual(len(commands), 4)
        for _, _, kwargs in commands:
            self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C",
                                               "LANG": "C", "HOME": self.admission["tartHome"],
                                               "TART_HOME": self.admission["tartHome"],
                                               "TART_NO_AUTO_PRUNE": "1"})
            self.assertEqual(getattr(kwargs.get("popen"), "keywords", None),
                             {"user": 501, "group": 20, "extra_groups": []})

    def test_capture_failure_never_launches_and_failed_restore_never_completes(self):
        stack, events, processes, _, preferences = self._exercise_patches(capture_error=RuntimeError("capture"))
        with stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7], stack[8], stack[9], stack[10], stack[11], stack[12]:
            with self.assertRaisesRegex(RuntimeError, "capture"):
                supervisor._exercise(self.root, self.admission, SimpleNamespace(pw_uid=501, pw_gid=20, pw_name="owner"), "staff", preferences)
        self.assertFalse(processes)
        self.assertFalse(any(e[0] == "restore" for e in events))

        class State:
            """Fake state object that fails if failed recovery gets completed."""

            def __init__(self, _):
                """Accept the fixed root selected by qualification."""

            def __enter__(self):
                """Enter the fake state lock."""
                return self

            def __exit__(self, *args):
                """Leave the fake state lock without suppressing failures."""
                return False

            def begin(self, identity):
                """Return the fake run directory."""
                return self.root, "a" * 32

            def complete(self, *_):
                """Reject completion when restore has failed."""
                self.fail("completed after failed restore")

        stack, events, _, _, preferences = self._exercise_patches(restore_error=RuntimeError("restore"))
        state = State(self.root)
        state.root = self.root
        state.fail = self.fail
        with patch.object(supervisor.os, "geteuid", return_value=0), \
                patch.object(supervisor.sys, "platform", "darwin"), \
                patch.object(supervisor, "State", return_value=state), \
                patch.object(supervisor, "_admission", return_value=(self.admission,
                              SimpleNamespace(pw_uid=501, pw_gid=20, pw_name="owner"), "staff", "c" * 64)), \
                stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7], stack[8], stack[9], stack[10], stack[11], stack[12]:
            with self.assertRaisesRegex(RuntimeError, "restore"):
                supervisor.qualify(self.root, preferences_factory=preferences)

    def test_unreaped_children_vm_stop_and_log_join_fail_closed_before_restore(self):
        cases = (("helper", True, False), ("vm", True, False), (None, False, False), (None, True, True))
        for child, stopped, log_alive in cases:
            with self.subTest(child=child, stopped=stopped, log_alive=log_alive):
                stack, events, _, _, preferences = self._exercise_patches(
                    stop_error=child, stopped=stopped, log_alive=log_alive)
                with stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7], stack[8], stack[9], stack[10], stack[11], stack[12]:
                    with self.assertRaisesRegex(recovery.RecoveryError, "cleanup_unproven"):
                        supervisor._exercise(self.root, self.admission,
                                             SimpleNamespace(pw_uid=501, pw_gid=20, pw_name="owner"), "staff", preferences)
                self.assertFalse(any(e[0] == "restore" for e in events))

    def test_readiness_timeout_is_bounded_and_does_not_restore_until_owned_children_proven(self):
        timeout = canary.CanaryError("tart_command_timeout")
        stack, events, _, _, preferences = self._exercise_patches(command_error=timeout)
        # First clock value sets deadline; the later value expires it after a failed probe.
        stack[-1] = patch.object(supervisor.time, "monotonic", side_effect=[0, 0, 0, 1000, 1000])
        with stack[0], stack[1], stack[2], stack[3], stack[4], stack[5], stack[6], stack[7], stack[8], stack[9], stack[10], stack[11], stack[12]:
            with self.assertRaisesRegex(recovery.RecoveryError, "vm_readiness_timeout"):
                supervisor._exercise(self.root, self.admission,
                                     SimpleNamespace(pw_uid=501, pw_gid=20, pw_name="owner"), "staff", preferences)
        self.assertEqual(sum(e[0] == "command" and e[1][1:2] == ("exec",) for e in events), 3)
        # The timeout is recoverable once the finally block proves stop and reap.
        self.assertTrue(any(e[0] == "restore" for e in events))
        self.assertLess(next(i for i, e in enumerate(events) if e[0] == "stop_owned"),
                        next(i for i, e in enumerate(events) if e[0] == "restore"))

    def test_owned_python_process_group_is_quiet_before_wnowait_then_reaped(self):
        child_code = "import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); time.sleep(30)"
        leader_code = ("import subprocess,sys,time; "
                       f"p=subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
                       "print(p.pid, flush=True); time.sleep(30)")
        process = subprocess.Popen([sys.executable, "-c", leader_code], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, text=True)
        quiet_seen = []
        log_join_seen = []
        original_waitid = os.waitid
        original_wait = process.wait

        def cleanup_group():
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    original_wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    original_wait(timeout=3)
            for stream in (process.stdout, process.stderr):
                if not stream.closed:
                    stream.close()

        self.addCleanup(cleanup_group)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            self.assertTrue(selector.select(timeout=3), "child group did not start in time")
            line = process.stdout.readline()
        finally:
            selector.close()
        self.assertTrue(line.strip().isdigit(), "child group did not start")

        def waitid(*args, **kwargs):
            self.assertIsNone(process.returncode, "Popen was reaped before waitid observation")
            self.assertTrue(args[2] & os.WNOWAIT, "exit observation did not use WNOWAIT")
            return original_waitid(*args, **kwargs)

        def wait(*args, **kwargs):
            self.assertTrue(quiet_seen, "Popen.wait preceded independent group-quiet proof")
            self.assertTrue(log_join_seen, "Popen.wait preceded log-drainer join")
            return original_wait(*args, **kwargs)

        class LogDrain:
            """Record a log join while the child PID remains unreaped."""

            def join(inner_self, timeout=None):
                """Assert the drainer joins after quiet proof and before reap."""
                self.assertIsNone(process.returncode, "log drainer joined after leader reap")
                self.assertTrue(quiet_seen, "log drainer joined before group-quiet proof")
                log_join_seen.append(timeout)

            def is_alive(inner_self):
                """Report the drainer stopped after its join."""
                return False

        process.wait = wait
        def quiet(pid):
            self.assertIsNone(process.returncode, "leader was reaped before group quiet proof")
            quiet_seen.append(pid)
            return original_quiet(pid)

        original_quiet = supervisor._group_quiet
        with patch.object(supervisor, "_group_quiet", side_effect=quiet), \
                patch.object(supervisor.os, "waitid", side_effect=waitid):
            supervisor._stop_owned(process, log_thread=LogDrain())
        process.stdout.close()
        process.stderr.close()
        self.assertTrue(quiet_seen)
        self.assertEqual(log_join_seen, [2])
        self.assertIsNotNone(process.returncode)
        with self.assertRaises(ChildProcessError):
            original_waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def test_sigint_permission_error_after_exit_still_requires_quiet_proof_before_reap(self):
        process = FakeProcess("already-exited")
        order = []

        def observe(child):
            self.assertIs(child, process)
            self.assertIsNone(child.returncode, "fake WNOWAIT observation must preserve the PID")
            order.append("wnowait")
            return True

        def killpg(pid, sig):
            self.assertEqual(pid, process.pid)
            order.append(("signal", sig))
            raise PermissionError("zombie-only group")

        def quiet(pid):
            self.assertIsNone(process.returncode, "leader reaped before quiet proof")
            order.append("quiet")
            return True

        def wait(timeout=None):
            self.assertEqual(order[-2:], ["quiet", "wnowait"])
            order.append("wait")
            process.returncode = 0
            return 0

        process.wait = wait
        with patch.object(supervisor.os, "getpgid", return_value=process.pid), \
                patch.object(supervisor.os, "getsid", return_value=process.pid), \
                patch.object(supervisor.os, "killpg", side_effect=killpg), \
                patch.object(supervisor, "_child_exited", side_effect=observe), \
                patch.object(canary, "_wait_owned_vm_exit"), \
                patch.object(supervisor, "_group_quiet", side_effect=quiet):
            supervisor._stop_owned(process)
        self.assertEqual(order, ["wnowait", ("signal", signal.SIGINT),
                                 ("signal", signal.SIGKILL), "quiet", "wnowait", "wait"])

    def test_signals_without_group_quiet_proof_do_not_reap_child(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True)
        try:
            with patch.object(canary, "_wait_owned_vm_exit"), \
                    patch.object(supervisor, "_group_quiet", return_value=False), \
                    patch.object(supervisor.time, "monotonic", side_effect=[10, 100]), \
                    patch.object(supervisor.time, "sleep"):
                with self.assertRaisesRegex(recovery.RecoveryError, "owned_group_still_live"):
                    supervisor._stop_owned(process)
            self.assertIsNone(process.returncode, "signals alone must not release the process-group PID")
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            process.wait(timeout=3)
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    unittest.main()
