"""Verify the packaged public query proof without invoking native tools."""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch


BRIDGE = Path(__file__).resolve().parents[1] / "docs/native-bridge"
BUNDLE = BRIDGE / "terminal-public-query-spike"
PATCH_ORDER = [
    "01-public-query.patch",
    "02-tui-terminal-query.patch",
    "03-generated-protocol.patch",
]
spec = importlib.util.spec_from_file_location(
    "public_query_verify", BUNDLE / "verify.py"
)
verifier = importlib.util.module_from_spec(spec)
with patch.object(sys, "dont_write_bytecode", True):
    spec.loader.exec_module(verifier)


def read_json(path):
    return json.loads(path.read_bytes())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TerminalPublicQueryArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bundle = self.root / BUNDLE.name
        shutil.copytree(BUNDLE, self.bundle)
        sibling = self.root / "terminal-history-spike"
        sibling.mkdir()
        shutil.copy2(BRIDGE / sibling.name / "manifest.json", sibling / "manifest.json")
        self.manifest = read_json(self.bundle / "manifest.json")

    def save(self):
        (self.bundle / "manifest.json").write_text(json.dumps(self.manifest))

    def repin(self, name, contents):
        target = self.bundle / name
        target.write_text(contents)
        self.manifest["bundledArtifactSha256"][name] = digest(target)
        self.save()

    def rejected(self):
        with self.assertRaises(ValueError):
            verifier.verify(self.bundle)

    def test_valid_bundle_and_exact_inventory(self):
        self.assertIsNotNone(verifier.verify(self.bundle))
        self.assertEqual(self.manifest["patchOrder"], PATCH_ORDER)
        for field, count in (
            ("fileSha256", 18),
            ("testedSha256", 18),
            ("selectedSourceClosureSha256", 71),
        ):
            self.assertEqual(len(self.manifest[field]), count)
        payloads = {
            p.relative_to(self.bundle).as_posix()
            for p in self.bundle.rglob("*")
            if p.is_file()
        }
        self.assertEqual(
            payloads - {"README.md", "manifest.json", "verify.py"},
            set(self.manifest["bundledArtifactSha256"]),
        )
        paths = []
        for name, count in zip(PATCH_ORDER, (8, 4, 6)):
            text = (self.bundle / name).read_text()
            current = re.findall(r"^diff --git a/(\S+) b/\1$", text, re.MULTILINE)
            self.assertEqual(len(current), count)
            self.assertEqual(text.count("GIT binary patch"), 2 if count == 6 else 0)
            paths.extend(current)
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(set(paths), set(self.manifest["fileSha256"]))

    def test_each_payload_hash_is_checked_before_parsing(self):
        for name in self.manifest["bundledArtifactSha256"]:
            with self.subTest(name=name):
                target = self.bundle / name
                original = target.read_bytes()
                try:
                    target.write_bytes(b"malformed payload")
                    with self.assertRaisesRegex(ValueError, "hash mismatch"):
                        verifier.verify(self.bundle)
                finally:
                    target.write_bytes(original)

    def test_patch_order_is_exact(self):
        for order in (
            PATCH_ORDER[::-1],
            PATCH_ORDER[:-1],
            PATCH_ORDER + PATCH_ORDER[:1],
        ):
            with self.subTest(order=order):
                self.manifest["patchOrder"] = order
                self.save()
                self.rejected()

    def test_source_maps_require_exact_keys_and_values(self):
        for field in ("fileSha256", "testedSha256", "selectedSourceClosureSha256"):
            original = self.manifest[field].copy()
            name = next(iter(original))
            for mutation in (
                {k: v for k, v in original.items() if k != name},
                {**original, name: "0" * 64},
            ):
                with self.subTest(field=field):
                    self.manifest[field] = mutation
                    self.save()
                    self.rejected()
            self.manifest[field] = original
            self.save()

    def test_repinned_tested_and_base_proofs_must_match_source_chain(self):
        for name in (
            "proof/tested-source-hashes.json",
            "proof/base-history-closure.json",
        ):
            with self.subTest(name=name):
                original = (self.bundle / name).read_text()
                values = json.loads(original)
                values[next(iter(values))] = "0" * 64
                try:
                    self.repin(name, json.dumps(values))
                    self.rejected()
                finally:
                    self.repin(name, original)

    def test_sibling_history_closure_must_match(self):
        target = self.root / "terminal-history-spike/manifest.json"
        prior = read_json(target)
        values = prior["selectedSourceClosureSha256"]
        values[next(iter(values))] = "0" * 64
        target.write_text(json.dumps(prior))
        self.rejected()

    def test_unexpected_hidden_files_and_empty_directories(self):
        for name in (".env", "proof/stale.json", "__pycache__/stale.pyc", "unused/"):
            with self.subTest(name=name):
                target = self.bundle / name
                target.parent.mkdir(parents=True, exist_ok=True)
                if name.endswith("/"):
                    target.mkdir()
                else:
                    target.write_text("unexpected")
                try:
                    self.rejected()
                finally:
                    if target.is_dir():
                        target.rmdir()
                    else:
                        target.unlink()
                    if target.parent.name == "__pycache__":
                        target.parent.rmdir()

    def test_symlinks_are_rejected(self):
        for name in ("README.md", "proof"):
            with self.subTest(name=name):
                target = self.bundle / name
                backup = self.root / (name + "-backup")
                target.rename(backup)
                target.symlink_to(backup, target_is_directory=backup.is_dir())
                try:
                    self.rejected()
                finally:
                    target.unlink()
                    backup.rename(target)

    def test_manifest_paths_cannot_escape_bundle(self):
        for name in ("../outside", "/absolute", "a/../../outside"):
            with self.subTest(name=name):
                self.manifest["bundledArtifactSha256"][name] = "0" * 64
                self.save()
                self.rejected()
                del self.manifest["bundledArtifactSha256"][name]

    def test_repinned_diffs_reject_malformed_hunks_and_paths(self):
        for name in ("tested-to-final.diff", "clippy-source-delta.diff"):
            original = (self.bundle / name).read_text()
            mutations = [
                "",
                original.replace("+++ b/", "+++ b/../", 1),
                re.sub(r"@@ -\d+(?:,\d+)? \+", "@@ -999999,0 +", original, count=1),
            ]
            for contents in mutations:
                with self.subTest(name=name, length=len(contents)):
                    self.assertNotEqual(contents, original)
                    self.repin(name, contents)
                    self.rejected()
            self.repin(name, original)

    def test_repinned_patch_scope_rejects_traversal(self):
        name = PATCH_ORDER[0]
        original = (self.bundle / name).read_text()
        self.repin(name, original.replace("a/codex-rs/", "a/../codex-rs/", 1))
        self.rejected()

    def test_repinned_replay_metadata_must_match_actual_inventory(self):
        name = "proof/replay.json"
        original = (self.bundle / name).read_text()
        for field, value in (
            ("patchOrder", PATCH_ORDER[::-1]),
            ("finalChangedFiles", 17),
            ("selectedSourceFiles", 70),
            ("baseSelectedSourceFiles", 65),
            ("nativeExecution", True),
        ):
            with self.subTest(field=field):
                replay = json.loads(original)
                replay[field] = value
                self.repin(name, json.dumps(replay))
                self.rejected()
        replay = json.loads(original)
        replay["stages"][0]["fileSha256"] = {}
        self.repin(name, json.dumps(replay))
        self.rejected()

    def test_nonpayload_file_size_is_bounded(self):
        with patch.object(verifier, "JSON_LIMIT", 1024 * 1024):
            (self.bundle / "README.md").write_bytes(b"x" * (1024 * 1024 + 1))
            self.rejected()

    def test_sdk_followup_is_separate_and_bound_to_generation(self):
        self.assertEqual(
            self.manifest["followupPatchOrder"], ["04-generated-sdk.patch"]
        )
        self.assertEqual(len(self.manifest["finalSelectedSourceClosureSha256"]), 71)
        proof = read_json(self.bundle / "proof/sdk-generation.json")
        path = next(iter(self.manifest["followupFileSha256"]))
        self.assertEqual(
            proof["generatedFiles"][path]["after"],
            self.manifest["followupFileSha256"][path],
        )
        self.assertEqual(
            proof["generatedFiles"][path]["before"],
            self.manifest["selectedSourceClosureSha256"][path],
        )
        proof["generatedFiles"][path]["after"] = "0" * 64
        self.repin("proof/sdk-generation.json", json.dumps(proof))
        self.rejected()

    def test_followup_order_and_final_closure_are_bound(self):
        self.manifest["followupPatchOrder"] = []
        self.save()
        self.rejected()
        self.manifest["followupPatchOrder"] = ["04-generated-sdk.patch"]
        name = next(iter(self.manifest["finalSelectedSourceClosureSha256"]))
        self.manifest["finalSelectedSourceClosureSha256"][name] = "0" * 64
        self.save()
        self.rejected()

    def test_sdk_stage_and_supplement_cannot_be_rewritten_together(self):
        name = "proof/replay.json"
        original = (self.bundle / name).read_text()
        replay = json.loads(original)
        replay["stages"][3]["fileSha256"] = {}
        self.repin(name, json.dumps(replay))
        self.rejected()
        replay = json.loads(original)
        source = next(iter(self.manifest["baseReplaySupplementSha256"]))
        self.manifest["baseReplaySupplementSha256"][source] = "0" * 64
        replay["baseReplaySupplementSha256"][source] = "0" * 64
        replay["baseSupplementProvenance"]["sha256"] = "0" * 64
        self.repin(name, json.dumps(replay))
        self.rejected()

    def test_diff_parser_rejects_bad_hunks_without_relying_on_pins(self):
        path = "codex-rs/example.rs"
        for hunk in (
            "@@ -1,2 +1 @@\n-before\n+after\n",
            "@@ -1 +2 @@\n-before\n+after\n",
        ):
            with self.subTest(hunk=hunk):
                data = f"--- a/{path}\n+++ b/{path}\n{hunk}".encode()
                with self.assertRaises(ValueError):
                    verifier.parse_diff(data)
        original = (self.bundle / PATCH_ORDER[0]).read_bytes()
        with self.assertRaises(ValueError):
            verifier.patch_paths(original.replace(b"a/codex-rs/", b"a/../codex-rs/", 1))

    def test_optional_source_missing(self):
        source = self.root / "source"
        source.mkdir()
        with self.assertRaises(ValueError):
            verifier.verify(self.bundle, source_root=source)

    def test_optional_frozen_base_manifest_mismatch(self):
        frozen = self.root / "frozen.json"
        frozen.write_text("{}")
        with self.assertRaises(ValueError):
            verifier.verify(self.bundle, frozen_base_manifest=frozen)


if __name__ == "__main__":
    unittest.main()
