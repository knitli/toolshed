import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
with patch.object(sys, "path", [str(SCRIPTS), *sys.path]):
    spec = importlib.util.spec_from_file_location("native_ci_producer", SCRIPTS / "produce_native_ci_artifact.py")
    PRODUCER = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(PRODUCER)


class NativeCIProducerTests(unittest.TestCase):
    def env(self):
        return {"GITHUB_REPOSITORY_ID": "1200860702", "GITHUB_REPOSITORY": "knitli/toolshed",
                "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
                "RUNNER_ARCH": "ARM64", "GITHUB_SHA": "a" * 40,
                "GITHUB_WORKFLOW_REF": "knitli/toolshed/.github/workflows/event-native-build.yml@refs/heads/main",
                "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}

    def test_identity_rejects_each_untrusted_dispatch_dimension(self):
        good = self.env()
        self.assertEqual(PRODUCER.identity(good)["runAttempt"], 2)
        for key, value in {"GITHUB_REPOSITORY_ID": "1", "GITHUB_REPOSITORY": "fork/toolshed",
                           "GITHUB_REF": "refs/heads/pr", "GITHUB_EVENT_NAME": "pull_request",
                           "RUNNER_ARCH": "X64", "GITHUB_SHA": "main",
                           "GITHUB_WORKFLOW_REF": "knitli/toolshed/.github/workflows/evil.yml@refs/heads/main",
                           "GITHUB_RUN_ID": "0", "GITHUB_RUN_ATTEMPT": "-1"}.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                PRODUCER.identity({**good, key: value})

    def test_platform_gate_rejects_non_arm_macos_before_commands(self):
        for system, machine in (("Linux", "arm64"), ("Darwin", "x86_64")):
            with patch.object(PRODUCER.platform, "system", return_value=system), \
                    patch.object(PRODUCER.platform, "machine", return_value=machine), \
                    patch.object(PRODUCER, "command") as command:
                with self.assertRaises(ValueError):
                    PRODUCER.environment(self.env())
                command.assert_not_called()

    def test_receipt_binds_actual_outputs_and_rejects_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def package(_source, binary, evidence, _host, **kwargs):
                self.assertEqual(kwargs, {"prime_dependencies": True})
                binary.write_bytes(b"cli")
                (binary.parent / "codex-code-mode-host").write_bytes(b"host")
                evidence.write_text("{}")
                return {"binarySha256": PRODUCER.builder.sha256(b"cli"),
                        "codeModeHost": {"executableSha256": PRODUCER.builder.sha256(b"host")}}
            with patch.dict(os.environ, self.env(), clear=True), \
                    patch.object(PRODUCER, "command", return_value="a" * 40), \
                    patch.object(PRODUCER, "environment", return_value={"sdkVersion": "27.0"}), \
                    patch.object(PRODUCER.builder, "package", side_effect=package):
                receipt = PRODUCER.produce(root, root / "host.tar.gz", root / "output")
                self.assertEqual(receipt["artifactName"], "native-client-123-2")
                self.assertEqual(set(p.name for p in (root / "output").iterdir()),
                                 {"codex", "codex-code-mode-host", "build-receipt.json"})
                self.assertEqual(receipt["inputs"]["producerSha256"],
                                 PRODUCER.builder.sha256_file(Path(PRODUCER.__file__)))

                def substituted(*args, **kwargs):
                    evidence = package(*args, **kwargs)
                    args[1].write_bytes(b"substituted")
                    return evidence
                with patch.object(PRODUCER.builder, "package", side_effect=substituted), \
                        self.assertRaisesRegex(ValueError, "native_producer_output_changed"):
                    PRODUCER.produce(root, root / "host.tar.gz", root / "bad-output")
                self.assertFalse((root / "bad-output/build-receipt.json").exists())
