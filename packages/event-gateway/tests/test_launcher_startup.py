"""Startup signals must run cleanup before a client can escape ownership."""

import os
from pathlib import Path
import signal
import subprocess  # nosec B404 - fixed interpreter runs a disposable startup probe
import sys
import tempfile
import unittest

from event_gateway import launcher


PROBE = r'''
import os, signal, subprocess, sys
from pathlib import Path
from unittest.mock import patch
from event_gateway import launcher
root, signum = Path(sys.argv[1]), int(sys.argv[2])
original_handler = signal.getsignal(signum)
def interrupt_hash(*_):
    os.kill(os.getpid(), signum)
    return root / "unused"
with patch.object(launcher.os, "isatty", return_value=True), \
     patch.object(launcher, "qualified_binary", side_effect=interrupt_hash), \
     patch.object(launcher.subprocess, "Popen", side_effect=AssertionError("spawned after stop")):
    try:
        launcher.launch(root / "state", root / "unused", launcher.QUALIFIED_SHA256, root)
    except KeyboardInterrupt:
        assert signum == signal.SIGINT
    except launcher.LaunchError as error:
        assert signum != signal.SIGINT
        assert str(error) == "native_launch_interrupted", str(error)
    else:
        raise AssertionError("startup signal ignored")
assert not list((root / "state").glob("c-*.sock"))
assert signal.getsignal(signum) == original_handler
'''

LIFECYCLE_PROBE = r'''
from contextlib import redirect_stderr, redirect_stdout
import io, json, os, signal, sys
from pathlib import Path
from unittest.mock import Mock, patch
from event_gateway import cli, launcher
root, phase = Path(sys.argv[1]), sys.argv[2]
original_handler = signal.getsignal(signal.SIGINT)
events = []
process = Mock(pid=12345, returncode=0)
def interrupt():
    os.kill(os.getpid(), signal.SIGINT)
    events.append("signal-handled")
def terminal(*_, **__):
    if phase == "before-terminal":
        interrupt()
def wait(**_):
    events.append("wait-entered")
    if phase == "cleanup":
        interrupt()
        interrupt()
    events.append("wait-finished")
process.wait.side_effect = wait
output, errors = io.StringIO(), io.StringIO()
with patch.object(launcher.os, "isatty", return_value=True), \
     patch.object(launcher, "qualified_binary", return_value=root / "unused"), \
     patch.object(launcher.subprocess, "Popen", return_value=process), \
     patch.object(launcher.os, "killpg", side_effect=lambda *_: events.append("kill")), \
     patch.object(launcher.threading, "Thread"), \
     patch.object(launcher, "run_terminal", side_effect=terminal), \
     redirect_stdout(output), redirect_stderr(errors):
    code = cli.main(["--state-dir", str(root / "state"), "launch",
                     "--codex-binary", str(root / "unused"),
                     "--binary-sha256", launcher.QUALIFIED_SHA256, "--cwd", str(root)])
assert code == 130, (code, errors.getvalue())
assert json.loads(errors.getvalue()) == {"reason": "interrupted"}, errors.getvalue()
assert events.count("kill") == 1, events
assert events[-1] == "wait-finished", events
assert events.count("signal-handled") == (2 if phase == "cleanup" else 1), events
assert not list((root / "state").glob("c-*.sock"))
assert signal.getsignal(signal.SIGINT) == original_handler
'''


class LauncherStartupTests(unittest.TestCase):
    def test_actual_sigint_before_terminal_and_repeated_during_cleanup(self):
        temporary_root = "/private/tmp" if Path("/private/tmp").is_dir() else "/tmp"  # nosec B108 - secure temporary directory and bounded socket path
        for phase in ("before-terminal", "cleanup"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory(dir=temporary_root) as directory:
                env = dict(os.environ)
                env["PYTHONPATH"] = str(Path(launcher.__file__).resolve().parents[1])
                result = subprocess.run(  # nosec B603 - fixed interpreter and test-owned signal probe
                    [sys.executable, "-c", LIFECYCLE_PROBE, directory, phase],
                    env=env, capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_signal_while_hashing_cleans_socket_without_spawning(self):
        for signum in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            with self.subTest(signal=signum), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                # Keep the session socket within the Unix-domain path limit.
                state_root = root
                if len(str(root)) > 40:
                    temporary = tempfile.TemporaryDirectory(dir="/private/tmp")  # nosec B108 - secure directory, short macOS socket path
                    self.addCleanup(temporary.cleanup)
                    state_root = Path(temporary.name)
                env = dict(os.environ)
                env["PYTHONPATH"] = str(Path(launcher.__file__).resolve().parents[1])
                result = subprocess.run(  # nosec B603 - fixed interpreter and disposable test probe
                    [sys.executable, "-c", PROBE, str(state_root), str(signum)],
                    env=env, capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(list((state_root / "state").glob("c-*.sock")), [])


if __name__ == "__main__":
    unittest.main()
