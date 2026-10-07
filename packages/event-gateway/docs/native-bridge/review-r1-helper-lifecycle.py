"""Prove both inherited bridge modes close before a live, blocked fs helper."""

import json
import os
import socket
import subprocess
import sys
import tempfile

results = []
for binary in sys.argv[1:]:
    markers = (
        (os.environ["BRIDGE_LIFECYCLE_MARKER"],)
        if "BRIDGE_LIFECYCLE_MARKER" in os.environ
        else ("CODEX_NATIVE_BRIDGE_FD", "CODEX_SELECTION_WITNESS_FD")
    )
    for marker in markers:
        with tempfile.TemporaryDirectory(prefix="codex-helper-lifecycle-") as home:
            parent, child = socket.socketpair()
            parent.settimeout(5)
            env = {
                **os.environ,
                "HOME": home,
                "CODEX_HOME": home,
                marker: str(child.fileno()),
            }
            proc = subprocess.Popen(
                [binary, "--codex-run-as-fs-helper"],
                env=env,
                pass_fds=(child.fileno(),),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            child.close()
            try:
                try:
                    data = parent.recv(1)
                except TimeoutError:
                    raise AssertionError(
                        f"{marker}: endpoint retained by blocked fs helper"
                    ) from None
                if data != b"":
                    raise AssertionError(f"{marker}: endpoint did not close")
                if proc.poll() is not None:
                    raise AssertionError(
                        f"{marker}: helper exited instead of staying live"
                    )
                # The helper responds to an invalid JSON request while stdin stays open.
                proc.stdin.write(b"not-json\n")
                proc.stdin.flush()
                proc.stdin.close()
                proc.stdin = None
                _, stderr = proc.communicate(timeout=5)
                if b"fs sandbox helper failed" not in stderr:
                    raise AssertionError(stderr)
                results.append(
                    {"binary": binary, "mode": marker, "closedWhileHelperAlive": True}
                )
            finally:
                parent.close()
                if proc.poll() is None:
                    proc.kill()
                    proc.communicate()
print(json.dumps(results, indent=2))
