"""V2 policy fixtures emitted by the actual producer with package execution mocked."""
import base64
import copy
import gzip
import json
from pathlib import Path
import unittest

import test_native_ci_provenance as legacy

V = legacy.V
DOCS = "packages/event-gateway/docs/native-bridge/"
with gzip.open(Path(__file__).parent / "fixtures/native-v2-producer-receipts.json.gz", "rt") as stream:
    FROZEN = json.load(stream)


class V2API(legacy.FakeAPI):
    def __init__(self, family="terminal-query-v1"):
        """Load frozen blobs and receipts for the selected registered recipe family."""
        super().__init__()
        self.receipt = copy.deepcopy(FROZEN["receipts"][family])
        self.selected.update(schemaVersion=2, recipe=self.receipt["recipe"])
        selected = V.R.recipe(family, 1)
        self.recipe = selected
        for path, encoded in FROZEN["blobs"].items():
            for revision in (legacy.HEAD, legacy.MAIN, legacy.BUILD):
                self.blobs[path, revision] = base64.b64decode(encoded)
        self.paths = {name: path for name, path in V.INPUTS.items() if name != "patchSha256"}
        self.paths.update(registrySha256=legacy.REGISTRY, sourceManifestSha256=DOCS + selected.manifest.path)
        for asset in (selected.manifest, *selected.parents, *selected.ordered_patches):
            for revision in (legacy.HEAD, legacy.MAIN, legacy.BUILD):
                self.blobs[DOCS + asset.path, revision] = (V.R.DOCS / asset.path).read_bytes()
        self.replace_receipt(self.receipt)


class NativeV2ProvenanceTests(unittest.TestCase):
    def test_real_producer_v2_receipts_accept_both_registered_source_families(self):
        for family, count in (("core-idle-v1", 57), ("terminal-query-v1", 71)):
            with self.subTest(family=family):
                api = V2API(family)
                self.assertEqual(api.receipt["build"]["patchedFileCount"], count)
                self.assertEqual(api.receipt["inputs"], {name: V.digest(api.blobs[path, legacy.BUILD])
                                                       for name, path in api.paths.items()})
                self.assertIn("verified main CI", V.verify_candidate(api, legacy.HEAD, legacy.MAIN))
                self.assertIn(("download", 456), api.calls)

    def assert_rejected_receipt(self, change, family="terminal-query-v1"):
        api = V2API(family)
        receipt = copy.deepcopy(api.receipt)
        change(receipt)
        api.replace_receipt(receipt)
        with self.assertRaises(ValueError):
            V.verify_candidate(api, legacy.HEAD, legacy.MAIN)
        self.assertIn(("download", 456), api.calls)

    def test_v2_selection_requires_exact_integer_schema_and_recipe_identity(self):
        good = V2API().selected
        self.assertEqual(V.selection(good), good)
        for schema in (True, 2.0, "2", 1, 3):
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                V.selection({**good, "schemaVersion": schema})
        for field, value in (("family", "unknown"), ("revision", True), ("revision", 2),
                             ("manifestSha256", "0" * 64), ("extra", "value")):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                V.selection({**good, "recipe": {**good["recipe"], field: value}})
        for field in good["recipe"]:
            changed = dict(good["recipe"])
            del changed[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                V.selection({**good, "recipe": changed})
        with self.assertRaises(ValueError):
            V.selection({key: value for key, value in good.items() if key != "recipe"})

    def test_v2_receipt_and_build_recipe_must_match_selection_exactly(self):
        for target in ("receipt", "build"):
            for field, value in (("family", "core-idle-v1"), ("revision", True), ("revision", 2),
                                 ("manifestSha256", "0" * 64), ("extra", "value")):
                def change(receipt):
                    location = receipt if target == "receipt" else receipt["build"]
                    location["recipe"][field] = value
                with self.subTest(target=target, field=field, value=value):
                    self.assert_rejected_receipt(change)

            def remove(receipt):
                del (receipt if target == "receipt" else receipt["build"])["recipe"]
            with self.subTest(target=target, missing=True):
                self.assert_rejected_receipt(remove)
        for schema in (1, True, 2.0, "2"):
            with self.subTest(receipt_schema=schema):
                self.assert_rejected_receipt(lambda receipt: receipt.update(schemaVersion=schema))

    def test_v2_inputs_are_exactly_five_authenticated_current_inputs(self):
        for revision in (legacy.HEAD, legacy.BUILD):
            for name in V2API().paths:
                api = V2API()
                api.blobs[api.paths[name], revision] += b"\nchanged"
                with self.subTest(revision=revision, field=name), self.assertRaises(ValueError):
                    V.verify_candidate(api, legacy.HEAD, legacy.MAIN)
                self.assertNotIn(("download", 456), api.calls)
        for field in V2API().paths:
            with self.subTest(receipt_field=field):
                self.assert_rejected_receipt(lambda receipt: receipt["inputs"].update({field: "0" * 64}))
            with self.subTest(missing=field):
                self.assert_rejected_receipt(lambda receipt: receipt["inputs"].pop(field))
        self.assert_rejected_receipt(lambda receipt: receipt["inputs"].update(patchSha256="0" * 64))

    def test_v2_selected_assets_are_pinned_even_when_all_three_refs_agree(self):
        selected = V.R.recipe("terminal-query-v1", 1)
        for asset in (selected.manifest, *selected.parents, *selected.ordered_patches):
            api = V2API()
            path = DOCS + asset.path
            original = api.blobs[path, legacy.MAIN]
            changed = bytes([original[0] ^ 1]) + original[1:]
            for revision in (legacy.HEAD, legacy.BUILD, legacy.MAIN):
                api.blobs[path, revision] = changed
            with self.subTest(asset=asset.path), self.assertRaises(ValueError):
                V.verify_candidate(api, legacy.HEAD, legacy.MAIN)
            self.assertNotIn(("download", 456), api.calls)

    def test_v2_archive_requires_complete_trusted_map_count_upstream_and_scope(self):
        original = V2API().receipt["build"]
        changed_map = dict(original["patchedFileSha256"])
        changed_map[next(iter(changed_map))] = "0" * 64
        for key, value in (("patchedFileCount", 57), ("patchedFileCount", True),
                           ("patchedFileSha256", changed_map), ("patchedFileSha256", {}),
                           ("upstreamCommit", "0" * 40), ("sourceManifestSha256", "0" * 64),
                           ("archiveScope", {"selection": "partial archive", "extractionFilter": "tarfile.data_filter"}),
                           ("archiveScope", {**original["archiveScope"], "extra": True})):
            with self.subTest(field=key, value=value):
                self.assert_rejected_receipt(lambda receipt: receipt["build"].update({key: value}))

    def test_v2_before_and_after_inventories_each_match_canonical_trusted_map(self):
        before = "patchedSourceInventoryBeforeBuildSha256"
        after = "patchedSourceInventoryAfterBuildSha256"
        for change in ({before: "0" * 64}, {after: "0" * 64}, {before: "0" * 64, after: "0" * 64}):
            with self.subTest(change=change):
                self.assert_rejected_receipt(lambda receipt: receipt["build"].update(change))
        for key in (before, after):
            with self.subTest(missing=key):
                self.assert_rejected_receipt(lambda receipt: receipt["build"].pop(key))

    def test_v2_applied_patches_require_exact_records_and_order(self):
        patches = V2API().receipt["build"]["appliedPatches"]
        mutations = [patches[:-1], [patches[1], patches[0], *patches[2:]],
                     [*patches[:-1], patches[-2]],
                     [{**patches[0], "sha256": "0" * 64}, *patches[1:]],
                     [{**patches[0], "bytes": patches[0]["bytes"] + 1}, *patches[1:]],
                     [{**patches[0], "extra": True}, *patches[1:]]]
        for index, changed in enumerate(mutations):
            with self.subTest(mutation=index):
                self.assert_rejected_receipt(lambda receipt: receipt["build"].update(appliedPatches=changed))

    def test_every_registered_recipe_asset_participates_in_policy_freshness(self):
        for changed_path in legacy.RECIPE_ASSETS:
            api = unittest.mock.Mock()
            api.blob.side_effect = lambda path, revision: (
                b"changed" if path == changed_path and revision == legacy.MAIN else b"same")
            with self.subTest(path=changed_path):
                self.assertFalse(V.current_policy(api, legacy.BUILD, legacy.MAIN))

    def test_v2_every_selected_asset_is_authenticated_at_candidate_and_build(self):
        selected = V.R.recipe("terminal-query-v1", 1)
        for revision in (legacy.HEAD, legacy.BUILD):
            for asset in (selected.manifest, *selected.parents, *selected.ordered_patches):
                api = V2API()
                path = DOCS + asset.path
                original = api.blobs[path, revision]
                api.blobs[path, revision] = bytes([original[0] ^ 1]) + original[1:]
                with self.subTest(revision=revision, asset=asset.path), self.assertRaises(ValueError):
                    V.verify_candidate(api, legacy.HEAD, legacy.MAIN)
                self.assertNotIn(("download", 456), api.calls)
