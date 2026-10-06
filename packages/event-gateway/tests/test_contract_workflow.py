"""Test the trusted workflow's inline verifier without credentials or network."""
import copy
import hashlib
import io
import json
from pathlib import Path
import runpy
import tempfile
import textwrap
import unittest
from unittest.mock import patch


PACKAGE = Path(__file__).resolve().parents[1]
WORKFLOW = PACKAGE.parents[1] / ".github/workflows/event-gateway-contract.yml"
SOURCE = textwrap.dedent(WORKFLOW.read_text().split("<<'PYTHON'\n", 1)[1].rsplit("          PYTHON", 1)[0])
with tempfile.TemporaryDirectory() as policy_directory:
    policy_path = Path(policy_directory) / "verifier.py"
    policy_path.write_text(SOURCE)
    POLICY = runpy.run_path(str(policy_path), run_name="workflow_test")["verify_contract"].__globals__
HEAD = "a" * 40


class ContractWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.blobs = {POLICY["SNAPSHOT"] + path.name: path.read_bytes()
                      for path in (PACKAGE / "contracts/event-v1").iterdir()}
        self.reads = []

    def read_blob(self, path, ref, token):
        self.assertEqual(ref, HEAD)
        self.assertEqual(token, "test-token")
        self.reads.append(path)
        return self.blobs[path]

    def verify(self):
        with patch.dict(POLICY, {"read_blob": self.read_blob}):
            POLICY["verify_contract"](HEAD, "test-token")

    def test_fixed_paths_and_exact_head(self):
        self.verify()
        self.assertEqual(len(self.reads), 5)
        self.assertEqual(set(self.reads), set(self.blobs))
        with patch.dict(POLICY, {"read_blob": self.read_blob}):
            with self.assertRaises(ValueError):
                POLICY["verify_contract"]("main", "test-token")
        self.assertEqual(len(self.reads), 5)

    def test_candidate_cannot_redefine_hashes_or_pin(self):
        manifest_path = POLICY["SNAPSHOT"] + "manifest.json"
        original = json.loads(self.blobs[manifest_path])
        for field, value in (("commit", "b" * 40), ("repository", "https://attacker.invalid/repo"), ("protocolVersion", True)):
            with self.subTest(field=field):
                manifest = copy.deepcopy(original)
                manifest[field] = value
                self.blobs[manifest_path] = json.dumps(manifest).encode()
                with self.assertRaises(ValueError):
                    self.verify()
        manifest = copy.deepcopy(original)
        entry = manifest["files"][0]
        self.blobs[POLICY["SNAPSHOT"] + entry["file"]] = b"changed candidate bytes"
        entry["sha256"] = hashlib.sha256(b"changed candidate bytes").hexdigest()
        self.blobs[manifest_path] = json.dumps(manifest).encode()
        with self.assertRaises(ValueError):
            self.verify()

    def test_redirects_are_refused(self):
        with self.assertRaises(ValueError):
            POLICY["NoRedirect"]().redirect_request(None, None, 302, "", {}, "https://attacker.invalid")

    def test_blob_response_is_bounded_and_file_only(self):
        import base64
        for value in (
            b" " * (POLICY["LIMIT"] + 1),
            json.dumps({"type": "symlink", "encoding": "base64", "content": "", "size": 0}).encode(),
            json.dumps({"type": "file", "encoding": "base64", "content": base64.b64encode(b"data").decode(), "size": 5}).encode(),
        ):
            with self.subTest(length=len(value)):
                with patch.object(POLICY["urllib"].request, "build_opener") as opener:
                    opener.return_value.open.return_value = io.BytesIO(value)
                    with self.assertRaises(ValueError):
                        POLICY["read_blob"]("fixed-path", HEAD, "test-token")
                    requested = opener.return_value.open.call_args.args[0]
                    self.assertEqual(requested.full_url,
                                     "https://api.github.com/repos/knitli/toolshed/contents/fixed-path?ref=" + HEAD)
