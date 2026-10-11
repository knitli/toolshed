"""Failure boundaries for the offline native host qualifier."""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import unittest
import tempfile
from unittest.mock import patch

PATH = Path(__file__).parents[1] / "docs/native-bridge/native-host-launcher-qualification.py"
SPEC = importlib.util.spec_from_file_location("native_host_qualification", PATH)
QUALIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFIER)


class NativeHostQualificationTests(unittest.TestCase):
    def test_only_correlated_tool_output_counts(self):
        nonce = "unique-source-nonce"
        output = {"type": "custom_tool_call_output", "call_id": QUALIFIER.CALL_ID,
                  "output": [{"type": "text", "text": json.dumps({"exit_code": 0, "output": nonce + "\n"})}]}
        requests = [{"input": []}, {"input": [output]}]
        self.assertEqual(QUALIFIER.verify_output(requests, nonce), output)
        for changed in (
            [{"input": [nonce]}, requests[1]],
            [requests[0], {"input": [{**output, "call_id": "other"}]}],
            [requests[0], {"input": [output, output]}],
            [requests[0], {"input": [{**output, "output": [{"text": "missing"}]}]}],
            [requests[0], {"input": [{**output, "output": [{"text": json.dumps({
                "exit_code": 1, "output": nonce + "\n"})}]}]}],
            requests + [{"input": []}],
        ):
            with self.subTest(changed=changed), self.assertRaises(AssertionError):
                QUALIFIER.verify_output(changed, nonce)

    def test_concurrent_title_request_is_distinct_from_tool_turn(self):
        title = {"tools": [], "text": {"format": {"schema": {
            "required": ["title"], "properties": {"title": {"type": "string"}}}}},
            "input": [{"text": "Generate a concise, single-line task title"}]}
        self.assertEqual(QUALIFIER.request_kind(title), "title")
        self.assertEqual(QUALIFIER.request_kind({"tools": [{"name": "exec"}]}), "main")
        for request in ({"tools": []}, {**title, "input": []},
                        {**title, "tools": [{"name": "other"}]}):
            with self.subTest(request=request), self.assertRaises(AssertionError):
                QUALIFIER.request_kind(request)

    def test_program_reads_path_without_embedding_file_contents(self):
        program = QUALIFIER.source_program(Path("/private/tmp/a ' quoted.txt"))
        self.assertTrue(program.startswith("text(await tools.exec_command("))
        arguments = json.loads(program[len("text(await tools.exec_command("):-3])
        self.assertEqual(arguments["cmd"], "/bin/cat '/private/tmp/a '\"'\"' quoted.txt'")
        self.assertFalse(arguments["login"])

    def test_frozen_helper_is_verified_before_execution(self):
        helper = QUALIFIER.verified_helper("qualification-installed.py")
        try:
            self.assertTrue(callable(helper.verify_installed))
            snapshot = Path(helper.__file__)
            self.assertNotEqual(snapshot.parent, PATH.parent)
            self.assertEqual(hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                             QUALIFIER.HELPERS["qualification-installed.py"])
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
        finally:
            helper._private_helper.cleanup()
        with patch.object(Path, "read_bytes", return_value=b"raise RuntimeError('executed')"):
            with self.assertRaisesRegex(AssertionError, "digest mismatch"):
                QUALIFIER.verified_helper("qualification-installed.py")

    def test_start_has_five_second_permit_and_exact_binding(self):
        from event_gateway.native_reader import validate_start
        from uuid import uuid4
        binding = {"clientId": str(uuid4()), "serverInstanceId": str(uuid4()),
                   "serverGeneration": 3, "threadId": str(uuid4()), "generation": 4}
        request = QUALIFIER.start_request(binding)
        validate_start(request)
        self.assertEqual({key: request[key] for key in binding}, binding)
        self.assertEqual(request["permitExpiresAt"] - request["permitIssuedAt"], 5000)

    def test_config_snapshots_preserve_native_changes_even_on_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            initial, final = b'model="initial"\n', b'model="updated"\n'
            path.write_bytes(initial)
            trace = QUALIFIER.config_snapshot(path, "initial")
            with self.assertRaisesRegex(RuntimeError, "later failure"):
                with QUALIFIER.preserve_final_config(trace, path):
                    path.write_bytes(final)
                    raise RuntimeError("later failure")
            for phase, data in (("initial", initial), ("final", final)):
                self.assertEqual(trace[phase + "Config"].encode(), data)
                self.assertEqual(trace[phase + "ConfigSha256"], hashlib.sha256(data).hexdigest())

    def test_launch_always_wraps_inner_unsandboxed_config(self):
        argv = QUALIFIER.launch_argv("/tmp/profile.sb", "/tmp/cache", "/tmp/state", "/tmp/codex", "/tmp/root")
        self.assertEqual(argv[:3], ["/usr/bin/sandbox-exec", "-f", "/tmp/profile.sb"])
        self.assertIn("-I", argv)
        self.assertEqual(argv[argv.index("--binary-sha256") + 1], QUALIFIER.CLI_SHA)

    def test_profile_denies_external_network_and_protects_real_home(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory).resolve() / "test-user"
            codex_home = Path(directory).resolve() / 'custom "codex"'
            with patch.object(Path, "home", return_value=home), \
                    patch.dict(os.environ, {"CODEX_HOME": str(codex_home)}):
                profile = QUALIFIER.sandbox_profile(43210)
            self.assertIn('(deny network*)', profile)
            self.assertIn('(remote ip "localhost:43210")', profile)
            self.assertIn("(subpath " + json.dumps(str(home / ".codex")) + ")", profile)
            self.assertIn("(subpath " + json.dumps(str(codex_home)) + ")", profile)
            self.assertNotIn('(allow network-outbound)', profile)



if __name__ == "__main__":
    unittest.main()
