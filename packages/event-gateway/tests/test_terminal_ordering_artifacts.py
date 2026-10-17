"""Check the frozen terminal-ordering proof bundle without running native tools."""

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
BUNDLE = BRIDGE / "terminal-ordering-spike"
STATUSES = ["completed", "failed", "canceled"]


def read_json(path):
    return json.loads(path.read_text())


class TerminalOrderingArtifactTests(unittest.TestCase):
    def test_source_closure_and_patch_scope(self):
        manifest = read_json(BUNDLE / "manifest.json")
        historical = read_json(BRIDGE / "native-core-idle-v1-source-manifest.json")
        sources = manifest["fileSha256"]
        self.assertEqual(len(sources), 13)
        closure = historical["fileSha256"] | sources
        self.assertEqual(len(closure), 61)
        self.assertEqual(manifest["selectedSourceClosureSha256"], closure)
        for digest in sources.values():
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
        patch_paths = {}
        for name, count in [
            ("ordering-incremental.patch", 6),
            ("terminal-ordering-cumulative.patch", 13),
        ]:
            patch_file = BUNDLE / name
            entry = manifest["patches"]["incremental" if count == 6 else "cumulative"]
            self.assertEqual(entry["path"], name)
            self.assertEqual(
                entry["sha256"], hashlib.sha256(patch_file.read_bytes()).hexdigest()
            )
            patch = patch_file.read_text()
            paths = re.findall(r"^diff --git a/(\S+) b/\1$", patch, re.MULTILINE)
            self.assertEqual(len(paths), count)
            self.assertEqual(len(set(paths)), count)
            self.assertLessEqual(set(paths), sources.keys())
            patch_paths[name] = set(paths)
        self.assertEqual(
            patch_paths["terminal-ordering-cumulative.patch"], sources.keys()
        )

    def test_matrix_has_successes_and_only_expected_crash_phases(self):
        results = read_json(BUNDLE / "proof/results.json")
        self.assertEqual(len(results), 20)
        self.assertEqual(len({row["name"] for row in results}), 20)
        self.assertEqual(sum(row["exitCode"] == 0 for row in results), 14)
        expected_crashes = {
            f"{label}-{phase}"
            for label in ("normal", "rollout-failure")
            for phase in ("before", "candidate", "after")
        }
        failures = {row["name"] for row in results if row["exitCode"] != 0}
        self.assertEqual(failures, expected_crashes)
        for row in results:
            with self.subTest(name=row["name"]):
                self.assertEqual(
                    row["exitCode"], 100 if row["name"] in expected_crashes else 0
                )
                self.assertRegex(row["logSha256"], r"^[0-9a-f]{64}$")
                self.assertEqual(row["command"][0], "just")
                self.assertEqual(row["log"], Path(row["log"]).name)
                self.assertNotRegex(json.dumps(row), r"/private/tmp|/Users/|/opt/coder")
                fixture_hash = row["env"].get("EVENT_TERMINAL_CORE_FIXTURE_SHA256")
                if fixture_hash is not None:
                    fixture_name = Path(row["env"]["EVENT_TERMINAL_CORE_FIXTURE"]).name
                    fixture_bytes = (BUNDLE / "proof" / fixture_name).read_bytes()
                    self.assertEqual(
                        fixture_hash, hashlib.sha256(fixture_bytes).hexdigest()
                    )

    def test_core_fixtures_match_terminal_status_and_turn_identity(self):
        for label in ("normal", "rollout-failure"):
            fixtures = read_json(BUNDLE / f"proof/core-{label}.json")
            self.assertEqual([fixture["status"] for fixture in fixtures], STATUSES)
            self.assertEqual(len({fixture["turnId"] for fixture in fixtures}), 3)
            for fixture in fixtures:
                with self.subTest(label=label, status=fixture["status"]):
                    UUID(fixture["threadId"])
                    UUID(fixture["turnId"])
                    event = fixture["event"]
                    self.assertEqual(event["turn_id"], fixture["turnId"])
                    canceled = fixture["status"] == "canceled"
                    self.assertEqual(
                        event["type"], "turn_aborted" if canceled else "task_complete"
                    )
                    if canceled:
                        self.assertEqual(event["reason"], "interrupted")
                    else:
                        self.assertEqual(
                            event.get("error") is not None,
                            fixture["status"] == "failed",
                        )

    def test_recovery_keeps_candidates_unknown_until_original_start_anchor(self):
        for label in ("normal", "rollout-failure"):
            fixtures = read_json(BUNDLE / f"proof/core-{label}.json")
            failed_writes = read_json(BUNDLE / f"proof/{label}-write_failure-rows.json")
            self.assertEqual(len(failed_writes), 3)
            for row in failed_writes:
                self.assertEqual(row[1:], [None, None, None, "pending", None])
            for phase in ("before", "candidate", "after"):
                snapshot = read_json(
                    BUNDLE / f"proof/{label}-recover_{phase}-rows.json"
                )
                self.assertEqual(set(snapshot), {"before", "after"})
                self.assertEqual(len(snapshot["before"]), 3)
                self.assertEqual(len(snapshot["after"]), 3)
                if phase != "candidate":
                    self.assertEqual(snapshot["before"], snapshot["after"])
                for index, (before, after) in enumerate(
                    zip(snapshot["before"], snapshot["after"], strict=True)
                ):
                    with self.subTest(label=label, phase=phase, status=STATUSES[index]):
                        attempt = f"terminal-attempt-{index}"
                        status = STATUSES[index]
                        if phase in ("before", "candidate"):
                            candidate = status if phase == "candidate" else None
                            self.assertEqual(
                                before,
                                [attempt, None, None, None, "pending", candidate],
                            )
                        if phase in ("candidate", "after"):
                            self.assertEqual(len(after), 6)
                            UUID(after[3])
                            self.assertEqual(
                                after,
                                [
                                    attempt,
                                    fixtures[index]["turnId"],
                                    status,
                                    after[3],
                                    "started",
                                    status,
                                ],
                            )

    def test_six_causal_mutations_failed_assertions_and_restored_sources(self):
        results = read_json(BUNDLE / "proof/causal-red.json")
        self.assertEqual(len(results), 6)
        self.assertEqual(len({row["name"] for row in results}), 6)
        for row in results:
            with self.subTest(name=row["name"]):
                self.assertEqual(row["exitCode"], 100)
                self.assertIs(row["restored"], True)
                self.assertTrue(row["test"])
                self.assertTrue(row["mutation"])
                self.assertTrue(row["assertionExcerpt"])
                self.assertRegex(row["logSha256"], r"^[0-9a-f]{64}$")
                self.assertEqual(row["command"][0], "just")
                self.assertNotRegex(json.dumps(row), r"/private/tmp|/Users/|/opt/coder")

    def test_verifier_rejects_mutations_in_both_source_layers(self):
        spec = importlib.util.spec_from_file_location(
            "terminal_ordering_verify", BUNDLE / "verify.py"
        )
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "artifacts" / BUNDLE.name
            shutil.copytree(BUNDLE, bundle)
            historical_path = bundle.parent / "native-core-idle-v1-source-manifest.json"
            prior_patch = (
                bundle.parent / "terminal-completion-spike/terminal-completion.patch"
            )
            prior_patch.parent.mkdir()
            shutil.copy2(
                BRIDGE / "terminal-completion-spike/terminal-completion.patch",
                prior_patch,
            )
            historical = read_json(BRIDGE / historical_path.name)
            manifest = read_json(bundle / "manifest.json")
            source_root = root / "checkout"
            qualified = {}
            for relative in historical["fileSha256"] | manifest["fileSha256"]:
                source = source_root / relative
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text(f"qualified fixture: {relative}\n")
                qualified[relative] = hashlib.sha256(source.read_bytes()).hexdigest()
            historical["fileSha256"] = {
                path: (
                    hashlib.sha256(
                        f"older historical bytes: {path}".encode()
                    ).hexdigest()
                    if path in manifest["fileSha256"]
                    else qualified[path]
                )
                for path in historical["fileSha256"]
            }
            manifest["fileSha256"] = {
                path: qualified[path] for path in manifest["fileSha256"]
            }
            manifest["selectedSourceClosureSha256"] = qualified
            historical_path.write_text(json.dumps(historical))
            manifest["historicalManifestSha256"] = hashlib.sha256(
                historical_path.read_bytes()
            ).hexdigest()
            (bundle / "manifest.json").write_text(json.dumps(manifest))
            verifier.verify(bundle, source_root)
            historical_only = next(
                path
                for path in historical["fileSha256"]
                if path not in manifest["fileSha256"]
            )
            for relative in (historical_only, next(iter(manifest["fileSha256"]))):
                with self.subTest(relative=relative):
                    source = source_root / relative
                    original = source.read_bytes()
                    source.write_bytes(b"unqualified mutation")
                    with self.assertRaises(ValueError):
                        verifier.verify(bundle, source_root)
                    source.write_bytes(original)
                    verifier.verify(bundle, source_root)

    def test_provenance_bytes_are_pinned_even_when_source_closure_is_unchanged(self):
        spec = importlib.util.spec_from_file_location(
            "ordering_verify", BUNDLE / "verify.py"
        )
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / BUNDLE.name
            shutil.copytree(BUNDLE, bundle)
            paths = [
                "native-core-idle-v1-source-manifest.json",
                "terminal-completion-spike/terminal-completion.patch",
            ]
            for relative in paths:
                destination = bundle.parent / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(BRIDGE / relative, destination)
            verifier.verify(bundle)
            selected = read_json(bundle / "manifest.json")[
                "selectedSourceClosureSha256"
            ]
            for relative in paths:
                with self.subTest(relative=relative):
                    target = bundle.parent / relative
                    original = target.read_bytes()
                    try:
                        if target.suffix == ".json":
                            historical = json.loads(original)
                            original_sources = historical["fileSha256"].copy()
                            historical["baseCommit"] = (
                                "changed provenance, unchanged sources"
                            )
                            target.write_text(json.dumps(historical))
                            self.assertEqual(
                                read_json(target)["fileSha256"], original_sources
                            )
                        else:
                            target.write_bytes(original + b"\n")
                        self.assertEqual(
                            read_json(bundle / "manifest.json")[
                                "selectedSourceClosureSha256"
                            ],
                            selected,
                        )
                        with self.assertRaisesRegex(
                            ValueError, "provenance hash mismatch"
                        ):
                            verifier.verify(bundle)
                    finally:
                        target.write_bytes(original)
                    verifier.verify(bundle)

            frozen = Path(directory) / "original-manifest.json"
            frozen.write_bytes(b'{"original": "unbundled provenance"}\n')
            manifest_path = bundle / "manifest.json"
            manifest = read_json(manifest_path)
            manifest["frozenManifestSha256"] = hashlib.sha256(
                frozen.read_bytes()
            ).hexdigest()
            manifest_path.write_text(json.dumps(manifest))
            self.assertEqual(
                verifier.verify(bundle)["provenanceHashes"]["frozenManifest"],
                "not checked (not bundled)",
            )
            self.assertEqual(
                verifier.verify(bundle, frozen_manifest=frozen)["provenanceHashes"][
                    "frozenManifest"
                ],
                "PASS",
            )
            original = frozen.read_bytes()
            frozen.write_bytes(original + b" ")
            with self.assertRaisesRegex(
                ValueError, "provenance hash mismatch: frozenManifestSha256"
            ):
                verifier.verify(bundle, frozen_manifest=frozen)
            frozen.write_bytes(original)
            verifier.verify(bundle, frozen_manifest=frozen)
