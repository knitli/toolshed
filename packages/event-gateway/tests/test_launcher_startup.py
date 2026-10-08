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
def interrupt_hash(*_):
    os.kill(os.getpid(), signum)
    return root / "unused"
with patch.object(launcher.os, "isatty", return_value=True), \
     patch.object(launcher, "qualified_binary", side_effect=interrupt_hash), \
     patch.object(launcher.subprocess, "Popen", side_effect=AssertionError("spawned after stop")):
    try:
        launcher.launch(root / "state", root / "unused", launcher.QUALIFIED_SHA256, root)
    except launcher.LaunchError as error:
        assert str(error) == "native_launch_interrupted", str(error)
    else:
        raise AssertionError("startup signal ignored")
assert not list((root / "state").glob("c-*.sock"))
assert signal.getsignal(signum) == signal.SIG_DFL
'''


class LauncherStartupTests(unittest.TestCase):
    def test_signal_while_hashing_cleans_socket_without_spawning(self):
        for signum in (signal.SIGTERM, signal.SIGHUP):
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
