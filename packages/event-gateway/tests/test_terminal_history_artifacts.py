"""Check packaged history evidence without invoking native tools."""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
from uuid import UUID
from unittest.mock import patch


BRIDGE = Path(__file__).resolve().parents[1] / "docs/native-bridge"
BUNDLE = BRIDGE / "terminal-history-spike"
spec = importlib.util.spec_from_file_location("history_verify", BUNDLE / "verify.py")
verifier = importlib.util.module_from_spec(spec)
with patch.object(sys, "dont_write_bytecode", True):
    spec.loader.exec_module(verifier)


def read_json(path):
    return json.loads(path.read_bytes())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TerminalHistoryArtifactTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.bundle = self.root / BUNDLE.name
        shutil.copytree(BUNDLE, self.bundle)
        for name in verifier.PROVENANCE:
            destination = self.bundle.parent / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(BRIDGE / name, destination)
        self.manifest = read_json(self.bundle / "manifest.json")

    def save(self):
        (self.bundle / "manifest.json").write_text(json.dumps(self.manifest))

    def test_package_payload_inventory_and_valid_bundle(self):
        payloads = {
            path.relative_to(BUNDLE).as_posix()
            for path in BUNDLE.rglob("*")
            if path.is_file() and "__pycache__" not in path.parts
        } - {"manifest.json", "README.md", "verify.py"}
        self.assertEqual(set(self.manifest["bundledArtifactSha256"]), payloads)
        result = verifier.verify(self.bundle)
        self.assertEqual(result["selectedSourceFiles"], 66)
        self.assertEqual(result["sourceHashes"], "not checked")
        self.assertEqual(
            result["provenanceHashes"]["frozenManifest"], "not checked (not bundled)"
        )

    def test_recorded_process_phases(self):
        rows = read_json(self.bundle / "proof/results.json")
        expected = {
            "regression": 0,
            "produce": 100,
            "recover1": 0,
            "recover2": 0,
            "core-tasks": 0,
        }
        self.assertEqual(len(rows), 5)
        self.assertEqual({row["phase"]: row["exitCode"] for row in rows}, expected)
        for row in rows:
            self.assertEqual(row["expectedExitCode"], expected[row["phase"]])
            self.assertEqual(row["log"], Path(row["log"]).name)
            self.assertRegex(row["logSha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(row["command"][0], "just")
            self.assertNotRegex(json.dumps(row), r"/private/tmp|/Users/|/opt/coder")
            if row["phase"] == "produce":
                self.assertEqual(row["expectedChildExitCode"], 71)
            if row["phase"] == "regression":
                self.assertIn("35 tests run: 35 passed", row["summary"])
            if row["phase"] == "core-tasks":
                self.assertIn("11 tests run: 11 passed", row["summary"])

    def test_canonical_fixture_matrix_and_recovery_receipts(self):
        fixtures = read_json(self.bundle / "proof/core-fixtures.json")["fixtures"]
        receipts = read_json(self.bundle / "proof/terminal-receipts.json")
        outcomes = {"completed", "failed", "canceled"}
        self.assertEqual(len(fixtures), 9)
        self.assertEqual(
            {(row["fault"], row["outcome"]) for row in fixtures},
            {
                (fault, outcome)
                for fault in ("none", "before_input", "before_terminal")
                for outcome in outcomes
            },
        )
        self.assertEqual(len(receipts), 3)
        self.assertEqual({row["outcome"] for row in receipts}, outcomes)
        self.assertEqual(len({row["receipt"] for row in receipts}), 3)
        for fixture in fixtures:
            with self.subTest(fault=fixture["fault"], outcome=fixture["outcome"]):
                for field in ("threadId", "turnId", "deliveredUserItemId"):
                    UUID(fixture[field])
                self.assertEqual(fixture["sessionMeta"]["id"], fixture["threadId"])
                self.assertRegex(fixture["canonicalRolloutSha256"], r"^[0-9a-f]{64}$")
                users = fixture["canonicalUserItemEvents"]
                terminals = fixture["canonicalTerminalEvents"]
                recovery = fixture["processVerifiedRecovery"]
                self.assertEqual(
                    len(users), 0 if fixture["fault"] == "before_input" else 1
                )
                for event in users:
                    payload = event["payload"]
                    self.assertEqual(payload["type"], "item_completed")
                    self.assertEqual(payload["thread_id"], fixture["threadId"])
                    self.assertEqual(payload["turn_id"], fixture["turnId"])
                    self.assertEqual(payload["item"]["type"], "UserMessage")
                    self.assertEqual(
                        payload["item"]["id"], fixture["deliveredUserItemId"]
                    )
                    self.assertEqual(payload["item"]["client_id"], fixture["turnId"])
                if fixture["fault"] != "none":
                    self.assertEqual(terminals, [])
                    self.assertEqual(
                        recovery, {"stage": "pending", "terminalProof": None}
                    )
                    continue
                self.assertEqual(len(terminals), 1)
                self.assertLess(users[0]["ordinal"], terminals[0]["ordinal"])
                payload = terminals[0]["payload"]
                self.assertEqual(payload["turn_id"], fixture["turnId"])
                canceled = fixture["outcome"] == "canceled"
                self.assertEqual(
                    payload["type"], "turn_aborted" if canceled else "task_complete"
                )
                if canceled:
                    self.assertEqual(payload["reason"], "interrupted")
                else:
                    self.assertEqual(
                        payload.get("error") is not None, fixture["outcome"] == "failed"
                    )
                self.assertEqual(recovery["stage"], "input_recorded")
                proof = recovery["terminalProof"]
                UUID(proof["receipt"])
                self.assertEqual(proof["turn"], fixture["turnId"])
                self.assertEqual(proof["outcome"], fixture["outcome"])
                self.assertIn(proof, receipts)

    def test_recorded_causal_reds_are_restored_assertion_failures(self):
        rows = read_json(self.bundle / "proof/causal-red.json")
        self.assertEqual(len(rows), 18)
        self.assertEqual(len({row["name"] for row in rows}), 18)
        for row in rows:
            self.assertEqual(row["result"], "expected assertion failure")
            self.assertIs(row["productionSourceRestored"], True)
            self.assertTrue(row["mutation"])
            self.assertTrue(row["assertionExcerpt"])
            self.assertEqual(row["rawLog"], Path(row["rawLog"]).name)
            self.assertRegex(row["rawLogSha256"], r"^[0-9a-f]{64}$")

    def test_patch_scope_matches_selected_final_files(self):
        for kind in ("incremental", "cumulative"):
            entry = self.manifest["patches"][kind]
            patch = (self.bundle / entry["path"]).read_text()
            paths = re.findall(r"^diff --git a/(\S+) b/\1$", patch, re.MULTILINE)
            self.assertTrue(paths)
            self.assertEqual(len(paths), len(set(paths)))
            self.assertLessEqual(set(paths), self.manifest["fileSha256"].keys())
            if kind == "cumulative":
                self.assertEqual(set(paths), self.manifest["fileSha256"].keys())

    def test_each_provenance_pin_precedes_json_parsing(self):
        for name in verifier.PROVENANCE:
            with self.subTest(name=name):
                path = self.bundle.parent / name
                original = path.read_bytes()
                try:
                    path.write_bytes(b"malformed JSON or changed patch")
                    with self.assertRaisesRegex(ValueError, "provenance hash mismatch"):
                        verifier.verify(self.bundle)
                finally:
                    path.write_bytes(original)
        self.manifest["provenanceSha256"].pop(next(iter(verifier.PROVENANCE)))
        self.save()
        with self.assertRaises(ValueError):
            verifier.verify(self.bundle)

    def test_incomplete_and_inconsistent_source_unions(self):
        for field in ("fileSha256", "testedSha256", "selectedSourceClosureSha256"):
            original = self.manifest[field].copy()
            with self.subTest(field=field):
                self.manifest[field].pop(next(iter(original)))
                self.save()
                with self.assertRaises(ValueError):
                    verifier.verify(self.bundle)
                self.manifest[field] = original
        name = next(iter(self.manifest["selectedSourceClosureSha256"]))
        self.manifest["selectedSourceClosureSha256"][name] = "0" * 64
        self.save()
        with self.assertRaisesRegex(ValueError, "66-file union"):
            verifier.verify(self.bundle)

    def test_tested_hash_values_match_authenticated_source_proof(self):
        name = next(iter(self.manifest["testedSha256"]))
        self.manifest["testedSha256"][name] = "0" * 64
        self.save()
        with self.assertRaisesRegex(ValueError, "tested source hash mismatch"):
            verifier.verify(self.bundle)

    def test_repinned_source_proof_must_match_tested_hash_values(self):
        path = self.bundle / "proof/source-hashes.json"
        proof = read_json(path)
        proof[next(iter(proof))] = "0" * 64
        path.write_text(json.dumps(proof))
        self.manifest["bundledArtifactSha256"]["proof/source-hashes.json"] = digest(
            path
        )
        self.save()
        with self.assertRaisesRegex(ValueError, "tested source hash mismatch"):
            verifier.verify(self.bundle)

    def test_formatting_evidence_requires_exact_true_source_map(self):
        original = self.manifest["equalsExactRustfmtOfTestedSource"].copy()
        name = next(iter(original))
        for mutation in (
            {**original, name: False},
            {**original, name: 1},
            {key: value for key, value in original.items() if key != name},
        ):
            with self.subTest(mutation=mutation):
                self.manifest["equalsExactRustfmtOfTestedSource"] = mutation
                self.save()
                with self.assertRaisesRegex(ValueError, "formatting evidence"):
                    verifier.verify(self.bundle)

    def test_repinned_formatting_diff_must_cover_changed_source_hashes(self):
        path = self.bundle / "tested-to-formatted.diff"
        path.write_text("")
        self.manifest["bundledArtifactSha256"]["tested-to-formatted.diff"] = digest(
            path
        )
        self.save()
        with self.assertRaisesRegex(ValueError, "formatting evidence"):
            verifier.verify(self.bundle)

    def test_repinned_formatting_diff_rejects_wrong_paths_and_hunk_counts(self):
        path = self.bundle / "tested-to-formatted.diff"
        original = path.read_text()
        mutations = (
            original.replace(
                "+++ formatted/codex-rs/", "+++ formatted/../codex-rs/", 1
            ),
            original.replace("@@ -966,7 +966,11 @@", "@@ -966,6 +966,11 @@", 1),
            original.replace("@@ -966,7 +966,11 @@", "@@ -966,7 +967,11 @@", 1),
        )
        for contents in mutations:
            with self.subTest(mutation=contents[:80]):
                self.assertNotEqual(contents, original)
                path.write_text(contents)
                self.manifest["bundledArtifactSha256"]["tested-to-formatted.diff"] = (
                    digest(path)
                )
                self.save()
                with self.assertRaisesRegex(ValueError, "formatting evidence"):
                    verifier.verify(self.bundle)

    def test_repinned_formatting_diff_rejects_incomplete_lines_and_counts(self):
        name = next(name for name in self.manifest["fileSha256"]
                    if self.manifest["fileSha256"][name] != self.manifest["testedSha256"][name])
        header = f"--- tested/{name}\n+++ formatted/{name}\n"
        path = self.bundle / "tested-to-formatted.diff"
        for hunk, error in (
            ("@@ -1 +1 @@\n-old\n+new", "requires complete lines"),
            ("@@ -1 +1 @@\n-old\n", "incomplete hunk"),
            ("@@ -0,0 +1 @@\n-old\n+new\n", "incorrect hunk counts"),
        ):
            with self.subTest(error=error):
                path.write_text(header + hunk)
                self.manifest["bundledArtifactSha256"]["tested-to-formatted.diff"] = digest(path)
                self.save()
                with self.assertRaisesRegex(ValueError, error):
                    verifier.verify(self.bundle)

    def test_nonpayload_inventory_file_size_is_bounded(self):
        with patch.object(verifier, "JSON_LIMIT", 1024 * 1024):
            (self.bundle / "README.md").write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, "inventory.*size limit"):
                verifier.verify(self.bundle)

    def test_standalone_inventory_rejects_unlisted_files_and_directories(self):
        for name in (
            "extra.txt",
            ".hidden",
            "proof/stale.json",
            "credentials.json",
            ".env",
            "__pycache__/stale.pyc",
            "unused-directory/",
        ):
            with self.subTest(name=name):
                path = self.bundle / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if name.endswith("/"):
                    path.mkdir()
                else:
                    path.write_text("unexpected fixture")
                try:
                    with self.assertRaisesRegex(ValueError, "inventory|unexpected"):
                        verifier.verify(self.bundle)
                finally:
                    if path.is_dir():
                        path.rmdir()
                    else:
                        path.unlink()
                    if path.parent.name == "__pycache__":
                        path.parent.rmdir()

    def test_standalone_inventory_rejects_symlinks_without_following_them(self):
        for name in ("README.md", "proof"):
            with self.subTest(name=name):
                path = self.bundle / name
                backup = self.root / (name + "-original")
                path.rename(backup)
                path.symlink_to(backup, target_is_directory=backup.is_dir())
                try:
                    with self.assertRaisesRegex(ValueError, "symlink"):
                        verifier.verify(self.bundle)
                finally:
                    path.unlink()
                    backup.rename(path)
        path = self.bundle / "loop"
        path.symlink_to(self.bundle, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            verifier.verify(self.bundle)

    def test_standalone_inventory_rejects_deep_paths_before_expansion(self):
        deep = "/".join(["nested"] * 129)
        self.manifest["bundledArtifactSha256"][deep] = "0" * 64
        self.save()
        with self.assertRaisesRegex(ValueError, "inventory.*depth limit"):
            verifier.verify(self.bundle)

    def test_standalone_inventory_is_bounded(self):
        for index in range(256):
            (self.bundle / f"unexpected-{index}").touch()
        with patch.object(verifier, "INVENTORY_LIMIT", 20, create=True):
            with self.assertRaisesRegex(ValueError, "inventory|unexpected"):
                verifier.verify(self.bundle)

    def test_prior_union_is_checked_after_repinning(self):
        name = "terminal-ordering-spike/manifest.json"
        path = self.bundle.parent / name
        prior = read_json(path)
        prior["selectedSourceClosureSha256"][
            next(iter(prior["selectedSourceClosureSha256"]))
        ] = "0" * 64
        path.write_text(json.dumps(prior))
        self.manifest["provenanceSha256"][name] = digest(path)
        self.save()
        with self.assertRaisesRegex(ValueError, "61-file union"):
            verifier.verify(self.bundle)

    def test_payload_hashes_precede_proof_parsing_and_patch_pins_match(self):
        for name in self.manifest["bundledArtifactSha256"]:
            with self.subTest(name=name):
                path = self.bundle / name
                original = path.read_bytes()
                try:
                    path.write_bytes(b"malformed payload")
                    with self.assertRaisesRegex(ValueError, "bundle hash mismatch"):
                        verifier.verify(self.bundle)
                finally:
                    path.write_bytes(original)
        for kind in ("incremental", "cumulative"):
            original = self.manifest["patches"][kind].copy()
            self.manifest["patches"][kind]["sha256"] = "0" * 64
            self.save()
            with self.assertRaisesRegex(ValueError, "patch must match bundled pin"):
                verifier.verify(self.bundle)
            self.manifest["patches"][kind] = original

    def test_optional_frozen_manifest(self):
        frozen = self.root / "original.json"
        frozen.write_bytes(b'{"original":true}')
        self.manifest["frozenManifestSha256"] = digest(frozen)
        self.save()
        self.assertEqual(
            verifier.verify(self.bundle, frozen_manifest=frozen)["provenanceHashes"][
                "frozenManifest"
            ],
            "PASS",
        )
        frozen.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "frozenManifestSha256"):
            verifier.verify(self.bundle, frozen_manifest=frozen)

    def test_optional_source_missing_wrong_and_valid(self):
        source_root = self.root / "source"
        source_root.mkdir()
        with self.assertRaisesRegex(ValueError, "missing or escaped"):
            verifier.verify(self.bundle, source_root)
        qualified = {}
        for name in self.manifest["selectedSourceClosureSha256"]:
            path = source_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"fixture {name}\n")
            qualified[name] = digest(path)
        with self.assertRaisesRegex(ValueError, "selected source hash mismatch"):
            verifier.verify(self.bundle, source_root)
        for name in (
            "native-core-idle-v1-source-manifest.json",
            "terminal-ordering-spike/manifest.json",
        ):
            path = self.bundle.parent / name
            previous = read_json(path)
            for field in ("fileSha256", "selectedSourceClosureSha256"):
                if field in previous:
                    previous[field] = {key: qualified[key] for key in previous[field]}
            path.write_text(json.dumps(previous))
            self.manifest["provenanceSha256"][name] = digest(path)
        for field in ("fileSha256", "testedSha256", "selectedSourceClosureSha256"):
            self.manifest[field] = {key: qualified[key] for key in self.manifest[field]}
        proof = self.bundle / "proof/source-hashes.json"
        proof.write_text(json.dumps(self.manifest["testedSha256"]))
        formatting = self.bundle / "tested-to-formatted.diff"
        formatting.write_text("")
        for path in (proof, formatting):
            self.manifest["bundledArtifactSha256"][
                path.relative_to(self.bundle).as_posix()
            ] = digest(path)
        self.save()
        self.assertEqual(
            verifier.verify(self.bundle, source_root)["sourceHashes"], "PASS"
        )
        # Both recorded tested maps agree, but the reverse diff reconstructs other bytes.
        changed = next(iter(self.manifest["testedSha256"]))
        tested_before = self.manifest["testedSha256"][changed]
        pins_before = self.manifest["bundledArtifactSha256"].copy()
        proof_before = proof.read_bytes()
        self.manifest["testedSha256"][changed] = "0" * 64
        proof.write_text(json.dumps(self.manifest["testedSha256"]))
        formatting.write_text(
            f"--- tested/{changed}\n+++ formatted/{changed}\n"
            f"@@ -1 +1 @@\n-before formatting\n+fixture {changed}\n"
        )
        for path in (proof, formatting):
            self.manifest["bundledArtifactSha256"][
                path.relative_to(self.bundle).as_posix()
            ] = digest(path)
        self.save()
        with self.subTest(reverse_diff="tested byte mismatch"):
            with self.assertRaisesRegex(ValueError, "tested source hash mismatch"):
                verifier.verify(self.bundle, source_root)
        final_bytes = (source_root / changed).read_bytes()
        self.manifest["testedSha256"][changed] = hashlib.sha256(
            final_bytes + b"deleted\n"
        ).hexdigest()
        proof.write_text(json.dumps(self.manifest["testedSha256"]))
        formatting.write_text(
            f"--- tested/{changed}\n+++ formatted/{changed}\n"
            "@@ -1000 +999,0 @@\n-deleted\n"
        )
        for path in (proof, formatting):
            self.manifest["bundledArtifactSha256"][
                path.relative_to(self.bundle).as_posix()
            ] = digest(path)
        self.save()
        with self.subTest(reverse_diff="deletion beyond EOF"):
            with self.assertRaisesRegex(ValueError, "formatting evidence"):
                verifier.verify(self.bundle, source_root)
        self.manifest["testedSha256"][changed] = tested_before
        self.manifest["bundledArtifactSha256"] = pins_before
        proof.write_bytes(proof_before)
        formatting.write_text("")
        self.save()
        target = source_root / next(iter(qualified))
        target.unlink()
        target.symlink_to(self.root / "original-outside")
        (self.root / "original-outside").write_text("outside")
        with self.assertRaisesRegex(ValueError, "missing or escaped"):
            verifier.verify(self.bundle, source_root)

    def test_paths_and_size_limits(self):
        for name in ("../escape", "/absolute", "a/../../escape"):
            with self.subTest(name=name):
                self.manifest["bundledArtifactSha256"] = {name: "0" * 64}
                self.save()
                with self.assertRaisesRegex(ValueError, "relative"):
                    verifier.verify(self.bundle)
        oversized = self.root / "oversized"
        oversized.write_bytes(b"x" * 11)
        with self.assertRaisesRegex(ValueError, "size limit"):
            verifier.read_bounded(oversized, 10)
