"""Registry and verifier-only adoption checks; no build or native execution."""

import ast
from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import MappingProxyType
import unittest
from unittest.mock import patch


PACKAGE = Path(__file__).resolve().parents[1]
SCRIPT = PACKAGE / "scripts/native_recipe_registry.py"
SPEC = importlib.util.spec_from_file_location("native_recipe_registry", SCRIPT)
R = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = R
SPEC.loader.exec_module(R)
TERMINAL = "terminal-query-v1"


class NativeRecipeRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for selected in R.RECIPES.values():
            for asset in (selected.manifest, *selected.parents, *selected.ordered_patches):
                destination = self.root / asset.path
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(R.DOCS / asset.path, destination)
        self.docs_patch = patch.object(R, "DOCS", self.root)
        self.docs_patch.start()
        self.addCleanup(self.docs_patch.stop)

    def replace_recipe(self, selected):
        values = dict(R.RECIPES)
        values[selected.family, selected.revision] = selected
        patched = patch.object(R, "RECIPES", MappingProxyType(values))
        patched.start()
        self.addCleanup(patched.stop)

    def manifest(self, family=TERMINAL):
        return json.loads((self.root / R.recipe(family).manifest.path).read_bytes())

    def authenticate_manifest(self, manifest, family=TERMINAL, raw=None):
        """Test-only pin replacement reaches semantic checks after byte authentication."""
        selected = R.recipe(family)
        data = json.dumps(manifest).encode() if raw is None else raw
        (self.root / selected.manifest.path).write_bytes(data)
        asset = replace(selected.manifest, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.replace_recipe(replace(selected, manifest=asset))

    def test_default_and_explicit_family_preserve_exact_source_maps(self):
        self.assertEqual(R.recipe().family, "core-idle-v1")
        self.assertEqual(R.recipe().file_count, 57)
        self.assertEqual(len(R.recipe().ordered_patches), 1)
        self.assertEqual(R.recipe(TERMINAL).file_count, 71)
        self.assertEqual(len(R.recipe(TERMINAL).ordered_patches), 7)
        for family, count in ((R.DEFAULT_FAMILY, 57), (TERMINAL, 71)):
            with self.subTest(family=family):
                result = R.validate_recipe(family)
                self.assertEqual(dict(result.file_sha256), self.manifest(family)["fileSha256"])
                self.assertEqual(len(result.file_sha256), count)
                self.assertEqual((result.authorization, result.coverage, result.source_files_checked),
                                 ("none", "selected_source_only", 0))

    def test_records_registries_and_returned_inventory_are_immutable(self):
        selected = R.recipe()
        with self.assertRaises(FrozenInstanceError):
            selected.file_count = 71
        with self.assertRaises(FrozenInstanceError):
            selected.manifest.path = "replacement"
        with self.assertRaises(TypeError):
            R.RECIPES["replacement", 1] = selected
        with self.assertRaises(TypeError):
            R.HISTORICAL_INPUTS[TERMINAL, 1] = ()
        result = R.validate_recipe()
        with self.assertRaises(TypeError):
            result.file_sha256["replacement"] = "0" * 64
        with self.assertRaises(FrozenInstanceError):
            result.authorization = "accepted"

    def test_unknown_or_noncanonical_recipe_identity_rejected(self):
        for family, revision in (("unknown", 1), (R.DEFAULT_FAMILY, 2), (R.DEFAULT_FAMILY, True),
                                 (R.DEFAULT_FAMILY, False), (R.DEFAULT_FAMILY, 0),
                                 (R.DEFAULT_FAMILY, "1"), ([], 1), (None, 1)):
            with self.subTest(family=family, revision=revision), self.assertRaises(ValueError):
                R.recipe(family, revision)

    def test_every_registered_historical_tuple_matches_only_its_family(self):
        for (family, revision), records in R.HISTORICAL_INPUTS.items():
            for record in records:
                with self.subTest(family=family, revision=revision):
                    self.assertTrue(R.matches_historical_inputs(family, revision, asdict(record)))
                    self.assertFalse(R.matches_historical_inputs(TERMINAL, 1, asdict(record)))
        self.assertEqual(R.HISTORICAL_INPUTS[TERMINAL, 1], ())
        inputs = asdict(R.HISTORICAL_INPUTS[R.DEFAULT_FAMILY, 1][0])
        with self.assertRaises(ValueError):
            R.matches_historical_inputs(R.DEFAULT_FAMILY, 2, inputs)

    def test_each_historical_field_is_required_and_compared(self):
        good = asdict(R.HISTORICAL_INPUTS[R.DEFAULT_FAMILY, 1][0])
        self.assertEqual(set(good), {"builderSha256", "producerSha256", "workflowSha256",
                                     "sourceManifestSha256", "patchSha256"})
        for name in good:
            with self.subTest(field=name):
                missing = dict(good)
                del missing[name]
                with self.assertRaisesRegex(ValueError, "input fields"):
                    R.matches_historical_inputs(R.DEFAULT_FAMILY, 1, missing)
                changed = {**good, name: "0" * 64}
                self.assertFalse(R.matches_historical_inputs(R.DEFAULT_FAMILY, 1, changed))

    def test_historical_input_schema_rejects_extras_and_malformed_hashes(self):
        good = asdict(R.HISTORICAL_INPUTS[R.DEFAULT_FAMILY, 1][0])
        for invalid in (None, list(good.values()), {**good, "family": R.DEFAULT_FAMILY}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                R.matches_historical_inputs(R.DEFAULT_FAMILY, 1, invalid)
        for value in (None, True, 1, "a" * 63, "A" * 64, "g" * 64, "a" * 64 + "\n"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "input digest"):
                R.matches_historical_inputs(R.DEFAULT_FAMILY, 1, {**good, "builderSha256": value})

    def test_individually_registered_hashes_cannot_be_mixed(self):
        # Synthetic records exercise the rule without registering invented build history.
        fields = tuple(R.HistoricalInputs.__dataclass_fields__)
        first = R.HistoricalInputs(*[str(index) * 64 for index in range(1, 6)])
        second = R.HistoricalInputs(*[str(index) * 64 for index in range(5, 10)])
        registry = MappingProxyType({(R.DEFAULT_FAMILY, 1): (first, second), (TERMINAL, 1): ()})
        with patch.object(R, "HISTORICAL_INPUTS", registry):
            self.assertTrue(R.matches_historical_inputs(R.DEFAULT_FAMILY, 1, asdict(first)))
            self.assertTrue(R.matches_historical_inputs(R.DEFAULT_FAMILY, 1, asdict(second)))
            for name in fields:
                with self.subTest(field=name):
                    mixed = {**asdict(first), name: getattr(second, name)}
                    self.assertFalse(R.matches_historical_inputs(R.DEFAULT_FAMILY, 1, mixed))

    def test_legacy_tuple_matches_reviewed_checked_in_inputs(self):
        paths = {
            "builderSha256": PACKAGE / "scripts/package_native_client.py",
            "producerSha256": PACKAGE / "scripts/produce_native_ci_artifact.py",
            "workflowSha256": PACKAGE.parents[1] / ".github/workflows/event-native-build.yml",
            "sourceManifestSha256": self.root / R.recipe().manifest.path,
            "patchSha256": self.root / R.recipe().ordered_patches[0].path,
        }
        inputs = {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}
        self.assertTrue(R.matches_historical_inputs(R.DEFAULT_FAMILY, 1, inputs))

    def test_missing_size_changed_and_same_size_corrupted_assets_reject(self):
        for family in (R.DEFAULT_FAMILY, TERMINAL):
            selected = R.recipe(family)
            for asset in (selected.manifest, *selected.parents, *selected.ordered_patches):
                with self.subTest(family=family, asset=asset.path):
                    target = self.root / asset.path
                    original = target.read_bytes()
                    for data in (None, original + b"x", bytes([original[0] ^ 1]) + original[1:]):
                        if data is None:
                            target.unlink()
                        else:
                            target.write_bytes(data)
                        with self.assertRaises(ValueError):
                            R.validate_recipe(family)
                        target.write_bytes(original)

    def test_symlink_file_directory_and_root_reject(self):
        asset = R.recipe(TERMINAL).ordered_patches[-1]
        target = self.root / asset.path
        saved = self.root / "saved.patch"
        target.rename(saved)
        target.symlink_to(saved)
        with self.assertRaisesRegex(ValueError, "symlink"):
            R.validate_recipe(TERMINAL)
        target.unlink()
        saved.rename(target)
        parent = target.parent
        moved = self.root / "moved"
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            R.validate_recipe(TERMINAL)
        alias = self.root / "root-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with patch.object(R, "DOCS", alias), self.assertRaisesRegex(ValueError, "asset root"):
            R.validate_recipe()

    def test_asset_bounds_and_unsafe_paths_reject_before_read(self):
        asset = R.recipe().manifest
        for name in ("../escape", "/absolute", "a/../b", "a\\b", "a//b", ".", "", "a/./b"):
            with self.subTest(path=name), self.assertRaisesRegex(ValueError, "unsafe asset path"):
                R._read_asset(replace(asset, path=name))
        for size in (True, False, 0, -1, R.ASSET_LIMIT + 1):
            with self.subTest(size=size), self.assertRaisesRegex(ValueError, "invalid asset identity"):
                R._read_asset(replace(asset, bytes=size))
        with patch.object(R, "TOTAL_ASSET_LIMIT", 1), self.assertRaisesRegex(ValueError, "asset total"):
            R.validate_recipe()

    def test_authenticated_missing_reordered_duplicate_patch_records_reject(self):
        original = self.manifest()
        records = original["patches"]
        for changed in (records[:-1], [records[1], records[0], *records[2:]],
                        [*records[:-1], records[-2]]):
            with self.subTest(records=changed):
                manifest = {**original, "patches": changed}
                self.authenticate_manifest(manifest)
                with self.assertRaisesRegex(ValueError, "patch identity or order"):
                    R.validate_recipe(TERMINAL)

    def test_authenticated_parent_order_and_base_prerequisite_reject(self):
        original = self.manifest()
        for changed, message in (
            ({**original, "parents": list(reversed(original["parents"]))}, "parent identity or order"),
            ({**original, "upstreamSupplement": {**original["upstreamSupplement"], "sha256": "0" * 64}},
             "base prerequisite"),
        ):
            with self.subTest(message=message):
                self.authenticate_manifest(changed)
                with self.assertRaisesRegex(ValueError, message):
                    R.validate_recipe(TERMINAL)

    def test_authenticated_pre_sdk_pre_repair_and_changed_final_maps_reject(self):
        selected = R.recipe(TERMINAL)
        query = json.loads((self.root / selected.parents[-1].path).read_bytes())
        original = self.manifest()
        changed = dict(original["fileSha256"])
        changed[next(iter(changed))] = "0" * 64
        for inventory in (query["selectedSourceClosureSha256"],
                          query["finalSelectedSourceClosureSha256"], changed):
            with self.subTest(inventory=inventory):
                self.authenticate_manifest({**original, "fileSha256": inventory})
                with self.assertRaisesRegex(ValueError, "source closure"):
                    R.validate_recipe(TERMINAL)

    def test_authenticated_inactive_identity_cannot_claim_authority_or_change_base(self):
        original = self.manifest()
        for field, value in (("authorization", "build"), ("coverage", "whole_tree"),
                             ("upstreamCommit", "0" * 40), ("schemaVersion", True), ("fileCount", 57)):
            with self.subTest(field=field):
                self.authenticate_manifest({**original, field: value})
                with self.assertRaisesRegex(ValueError, "inactive recipe identity"):
                    R.validate_recipe(TERMINAL)

    def test_duplicate_json_fields_and_extra_manifest_fields_reject(self):
        original = self.manifest()
        self.authenticate_manifest(original, raw=b'{"schemaVersion":1,"schemaVersion":1}')
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            R.validate_recipe(TERMINAL)
        self.authenticate_manifest({**original, "extra": "field"})
        with self.assertRaisesRegex(ValueError, "manifest fields"):
            R.validate_recipe(TERMINAL)

    def test_source_path_hash_count_and_legacy_file_records_reject(self):
        original = self.manifest(R.DEFAULT_FAMILY)
        for scenario in ("path", "hash", "count", "record", "duplicate"):
            with self.subTest(scenario=scenario):
                manifest = json.loads(json.dumps(original))
                key = next(iter(manifest["fileSha256"]))
                if scenario == "path":
                    manifest["fileSha256"]["../escape"] = manifest["fileSha256"].pop(key)
                elif scenario == "hash":
                    manifest["fileSha256"][key] = "not a hash"
                elif scenario == "count":
                    del manifest["fileSha256"][key]
                elif scenario == "record":
                    manifest["files"][0]["sha256"] = "0" * 64
                else:
                    manifest["files"][-1] = manifest["files"][0]
                self.authenticate_manifest(manifest, R.DEFAULT_FAMILY)
                with self.assertRaises(ValueError):
                    R.validate_recipe()

    def test_only_trusted_verifier_adopts_registry_without_runtime_actions(self):
        consumers = set()
        for directory in (PACKAGE / "src", PACKAGE / "scripts"):
            for path in directory.rglob("*.py"):
                if path == SCRIPT:
                    continue
                if "native_recipe_registry" in path.read_text():
                    consumers.add(path.relative_to(PACKAGE).as_posix())
        self.assertEqual(consumers, {"scripts/verify_native_ci_provenance.py"})
        tree = ast.parse(SCRIPT.read_text())
        imports = {item.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                   for item in node.names}
        imports.update(node.module.split(".")[0] for node in ast.walk(tree)
                       if isinstance(node, ast.ImportFrom) and node.module)
        self.assertFalse(imports & {"subprocess", "socket", "urllib", "event_gateway", "package_native_client"})
        launcher = ast.parse((PACKAGE / "src/event_gateway/launcher.py").read_text())
        pins = {node.targets[0].id: ast.literal_eval(node.value) for node in launcher.body
                if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id in {
                    "QUALIFIED_SHA256", "QUALIFIED_CODE_MODE_HOST_SHA256"}}
        self.assertEqual(pins, {
            "QUALIFIED_SHA256": "763e5e2b574f60b766d0d1b73b74ecc32d09d46479afe24e164299ca3633717b",
            "QUALIFIED_CODE_MODE_HOST_SHA256": "679eedaea70529aa1cffc9bc0a0788c186412663544fa76c09d63b57f383a65a",
        })


if __name__ == "__main__":
    unittest.main()
