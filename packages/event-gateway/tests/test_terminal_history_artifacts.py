"""Check packaged history evidence without invoking native tools."""

import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from uuid import UUID


BRIDGE = Path(__file__).resolve().parents[1] / "docs/native-bridge"
BUNDLE = BRIDGE / "terminal-history-spike"
spec = importlib.util.spec_from_file_location("history_verify", BUNDLE / "verify.py")
verifier = importlib.util.module_from_spec(spec)
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
            path.write_text(f"fixture {name}")
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
        self.save()
        self.assertEqual(
            verifier.verify(self.bundle, source_root)["sourceHashes"], "PASS"
        )
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
