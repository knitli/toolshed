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

    def test_control_pins_reject_drift_and_allow_staged_rotation(self):
        control_directory = PACKAGE / "contracts/event-control-v1"
        old_pins = {
            "fixtures.json": "1f803540d102cecce15a134ff29cc4fa62a83483e07112a3f33036b111b4473c",
            "manifest.json": "88e5cdb37621417ccc0656932b47f6993f7aaa0d0ac4243391a799461f6ae4d7",
        }
        self.assertEqual(POLICY["CONTROL_PINS"], old_pins)
        original = {name: (control_directory / name).read_bytes() for name in old_pins}
        control_paths = [
            "packages/event-gateway/contracts/event-control-v1/fixtures.json",
            "packages/event-gateway/contracts/event-control-v1/manifest.json",
        ]
        self.blobs.update({POLICY["CONTROL_SNAPSHOT"] + name: value
                           for name, value in original.items()})

        def verify_control():
            with patch.dict(POLICY, {"read_blob": self.read_blob}):
                POLICY["verify_control_contract"](HEAD, "test-token")

        # The first policy-only PR is evaluated by trusted old pins against the
        # unchanged candidate snapshot. read_blob also rejects any base ref.
        with patch.dict(POLICY, {"CONTROL_PINS": old_pins}):
            verify_control()
        self.assertEqual(self.reads, control_paths)

        fixture_path = POLICY["CONTROL_SNAPSHOT"] + "fixtures.json"
        manifest_path = POLICY["CONTROL_SNAPSHOT"] + "manifest.json"
        self.reads.clear()
        self.blobs[fixture_path] = original["fixtures.json"] + b"\n"
        with patch.dict(POLICY, {"CONTROL_PINS": old_pins}):
            with self.assertRaises(ValueError):
                verify_control()

        self.reads.clear()
        self.blobs[fixture_path] = original["fixtures.json"]
        del self.blobs[manifest_path]
        with patch.dict(POLICY, {"CONTROL_PINS": old_pins}):
            with self.assertRaises(KeyError):
                verify_control()

        rotated_fixtures = original["fixtures.json"] + b"\n"
        rotated_manifest_value = json.loads(original["manifest.json"])
        rotated_manifest_value["fixturesSha256"] = hashlib.sha256(rotated_fixtures).hexdigest()
        rotated_manifest = (json.dumps(rotated_manifest_value, indent=2) + "\n").encode()
        rotated_snapshot = {"fixtures.json": rotated_fixtures,
                            "manifest.json": rotated_manifest}
        rotated_pins = {name: hashlib.sha256(value).hexdigest()
                        for name, value in rotated_snapshot.items()}

        # The new constants and new snapshot are separate reviewed changes:
        # old policy rejects the new bytes; new policy rejects the old bytes.
        self.blobs.update({POLICY["CONTROL_SNAPSHOT"] + name: value
                           for name, value in rotated_snapshot.items()})
        self.reads.clear()
        with patch.dict(POLICY, {"CONTROL_PINS": old_pins}):
            with self.assertRaises(ValueError):
                verify_control()

        self.blobs.update({POLICY["CONTROL_SNAPSHOT"] + name: value
                           for name, value in original.items()})
        with patch.dict(POLICY, {"CONTROL_PINS": rotated_pins}):
            with self.assertRaises(ValueError):
                verify_control()

        self.blobs.update({POLICY["CONTROL_SNAPSHOT"] + name: value
                           for name, value in rotated_snapshot.items()})
        self.reads.clear()
        with patch.dict(POLICY, {"CONTROL_PINS": rotated_pins}):
            verify_control()
        self.assertEqual(self.reads, control_paths)

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
