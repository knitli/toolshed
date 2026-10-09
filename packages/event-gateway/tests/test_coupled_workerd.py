"""Focused checks load harness definitions without launching its disposable services."""
import argparse
import ast
import asyncio
from contextlib import redirect_stderr
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HARNESS = Path(__file__).resolve().parents[1] / "docs/native-bridge/coupled-workerd.py"


def definitions(*names, **namespace):
    tree = ast.parse(HARNESS.read_text())
    selected = [node for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
    # Fixed repository harness definitions; never accepts external source.
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(HARNESS), "exec"), namespace)  # nosec B102
    return namespace


class CoupledWorkerdTests(unittest.TestCase):
    def test_conflicting_modes_rejected_before_artifact_resolution(self):
        tree = ast.parse(HARNESS.read_text())
        start = next(i for i, node in enumerate(tree.body)
                     if isinstance(node, ast.Assign) and ast.unparse(node.targets[0]) == "parser")
        end = next(i for i, node in enumerate(tree.body)
                   if isinstance(node, ast.Assign) and "PACKAGE" in ast.unparse(node.targets[0]))
        code = compile(ast.Module(body=tree.body[start:end], type_ignores=[]), str(HARNESS), "exec")
        required = [arg for name in ("package", "qualifier", "binary", "binary-sha", "node",
                                    "cloud-source", "esbuild", "miniflare", "output")
                    for arg in ("--" + name, "unresolved")]
        for flags in (("--restart-native", "--terminal-no-start"), ("--forget-terminal",)):
            with self.subTest(flags=flags), patch("sys.argv", ["harness", *required, *flags]), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    # Fixed repository parser prefix, excluding artifact access and runtime launch.
                    exec(code, {"argparse": argparse, "__doc__": "test"})  # nosec B102
                self.assertEqual(error.exception.code, 2)

    def test_native_delay_is_bounded_and_requires_live_process(self):
        request = {"permitExpiresAt": 1000}

        async def cutoff(_):
            raise AssertionError("unbounded poll reached safety cutoff")

        for now, stopped in ((11, None), (1, 0)):
            with self.subTest(now=now, stopped=stopped):
                ticks = iter((0, now))
                namespace = definitions("require", "DelayedNativeAdapter",
                    NativeBridgeAdapter=object, terminal_receipts=[], ident="delivery",
                    store=SimpleNamespace(current_attempt=lambda _: {"state": "submitting", "native_request": request}),
                    time=SimpleNamespace(monotonic=lambda: next(ticks), time_ns=lambda: 0),
                    native_process=SimpleNamespace(poll=lambda: stopped), asyncio=SimpleNamespace(sleep=cutoff))
                with self.assertRaisesRegex(AssertionError, "native delay fixture exceeded deadline or native process stopped"):
                    asyncio.run(namespace["DelayedNativeAdapter"]().submit(request))

    def test_restart_requires_death_and_every_identity_rotation(self):
        check = definitions("require", "verify_native_restart")["verify_native_restart"]
        witness = {key: i for i, key in enumerate(("clientId", "serverInstanceId", "backendPid", "threadId"))}
        new_witness = {key: value + 10 for key, value in witness.items()}
        old = SimpleNamespace(pid=1, poll=lambda: 0)
        new = SimpleNamespace(pid=2)
        launcher = SimpleNamespace(alive=lambda _: False)
        self.assertTrue(all(check(old, new, witness, new_witness, launcher).values()))
        for field in ("oldTui", "oldBackend", "pid", *witness):
            with self.subTest(field=field):
                changed = dict(new_witness)
                if field in witness:
                    changed[field] = witness[field]
                with self.assertRaisesRegex(AssertionError, "old native processes stopped and all restart identities rotated"):
                    check(SimpleNamespace(pid=1, poll=lambda: None if field == "oldTui" else 0),
                          SimpleNamespace(pid=1 if field == "pid" else 2), witness, changed,
                          SimpleNamespace(alive=lambda _: field == "oldBackend"))
