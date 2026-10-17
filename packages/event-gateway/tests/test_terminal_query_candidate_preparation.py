"""Offline evidence checks only: no patch application or native execution."""

import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
BUNDLE = Path(__file__).resolve().parents[1] / "docs/native-bridge/terminal-query-candidate-preparation"
SPEC = importlib.util.spec_from_file_location("terminal_query_preparation", BUNDLE / "verify.py")
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)


class TerminalQueryCandidatePreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle = self.root / BUNDLE.name
        shutil.copytree(BUNDLE, self.bundle)
        self.manifest = json.loads((self.bundle / "manifest.json").read_bytes())
        for record in self.manifest["parents"] + self.manifest["patches"]:
            destination = self.root / record["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(BUNDLE.parent / record["path"], destination)

    def authenticate_fixture_manifest(self):
        data = json.dumps(self.manifest).encode()
        (self.bundle / "manifest.json").write_bytes(data)
        patched = patch.object(V, "MANIFEST_SHA256", V.digest(data))
        patched.start()
        self.addCleanup(patched.stop)

    def rewrite_query(self, query):
        record = self.manifest["parents"][2]
        data = json.dumps(query).encode()
        (self.root / record["path"]).write_bytes(data)
        record.update(bytes=len(data), sha256=V.digest(data))
        self.authenticate_fixture_manifest()

    def query(self):
        return json.loads((self.root / V.PARENTS[2]).read_bytes())

    def test_reviewed_metadata_verifies_without_source_or_authorization(self):
        self.assertEqual(V.verify(self.bundle), {
            "status": "verified", "authorization": "none", "coverage": "selected_source_only",
            "orderedPatchCount": 7, "selectedFileCount": 71, "sourceFilesChecked": 0,
        })
        self.assertEqual({entry.name for entry in self.bundle.iterdir()},
                         {"manifest.json", "README.md", "verify.py"})

    def test_manifest_integer_fields_reject_booleans(self):
        original = copy.deepcopy(self.manifest)
        for field, error in (("schemaVersion", "invalid inactive recipe identity"),
                             ("fileCount", "source count mismatch")):
            for value in (True, False):
                with self.subTest(field=field, value=value):
                    self.manifest = copy.deepcopy(original)
                    self.manifest[field] = value
                    self.authenticate_fixture_manifest()
                    with self.assertRaisesRegex(ValueError, error):
                        V.verify(self.bundle)

    def test_one_byte_asset_size_rejects_boolean_true(self):
        content = b"x"
        (self.root / "one-byte.patch").write_bytes(content)
        record = {"path": "one-byte.patch", "bytes": 1, "sha256": V.digest(content)}
        self.assertEqual(V.assets(self.root, [record], [record["path"]], 1), [content])
        for value in (True, False):
            with self.subTest(value=value):
                record["bytes"] = value
                with self.assertRaisesRegex(ValueError, "invalid asset size"):
                    V.assets(self.root, [record], [record["path"]], 1)

    def test_manifest_byte_change_is_rejected(self):
        with (self.bundle / "manifest.json").open("ab") as stream:
            stream.write(b"\n")
        with self.assertRaisesRegex(ValueError, "manifest hash mismatch"):
            V.verify(self.bundle)

    def test_missing_and_changed_patch_bytes_are_rejected(self):
        target = self.root / V.PATCHES[-1]
        original = target.read_bytes()
        target.unlink()
        with self.assertRaisesRegex(ValueError, "missing regular file"):
            V.verify(self.bundle)
        target.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, "asset hash mismatch"):
            V.verify(self.bundle)

    def test_missing_reordered_and_duplicate_patch_records_are_rejected(self):
        original = copy.deepcopy(self.manifest["patches"])
        for records, error in ((original[:-1], "asset count mismatch"),
                               ([original[1], original[0], *original[2:]], "asset order mismatch"),
                               ([*original[:-1], original[-2]], "asset order mismatch")):
            with self.subTest(error=error, paths=[item["path"] for item in records]):
                self.manifest["patches"] = records
                self.authenticate_fixture_manifest()
                with self.assertRaisesRegex(ValueError, error):
                    V.verify(self.bundle)

    def test_pre_sdk_and_pre_repair_maps_cannot_replace_final_closure(self):
        query = self.query()
        for field in ("selectedSourceClosureSha256", "finalSelectedSourceClosureSha256"):
            with self.subTest(field=field):
                self.manifest["fileSha256"] = query[field]
                self.authenticate_fixture_manifest()
                with self.assertRaisesRegex(ValueError, "repaired closure mismatch"):
                    V.verify(self.bundle)

    def test_sdk_stage_map_drift_is_rejected_after_authenticating_parent(self):
        query = self.query()
        query["finalSelectedSourceClosureSha256"] = query["selectedSourceClosureSha256"]
        self.rewrite_query(query)
        with self.assertRaisesRegex(ValueError, "SDK closure mismatch"):
            V.verify(self.bundle)

    def test_repair_stage_map_drift_is_rejected_after_authenticating_parent(self):
        query = self.query()
        query["repairedSelectedSourceClosureSha256"] = query["finalSelectedSourceClosureSha256"]
        self.rewrite_query(query)
        with self.assertRaisesRegex(ValueError, "repaired closure mismatch"):
            V.verify(self.bundle)

    def test_unsafe_selected_source_path_is_rejected(self):
        key = next(iter(self.manifest["fileSha256"]))
        self.manifest["fileSha256"]["../escape"] = self.manifest["fileSha256"].pop(key)
        self.authenticate_fixture_manifest()
        with self.assertRaisesRegex(ValueError, "unsafe path"):
            V.verify(self.bundle)
        for name in ("/absolute", "../escape", "a/../escape", "a\\b", "a//b", "."):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "unsafe path"):
                V.safe_path(name)

    def test_unlisted_bundle_file_and_directory_are_rejected(self):
        extra = self.bundle / "extra"
        extra.write_bytes(b"unlisted")
        with self.assertRaisesRegex(ValueError, "unlisted"):
            V.verify(self.bundle)
        extra.unlink()
        extra.mkdir()
        with self.assertRaisesRegex(ValueError, "unexpected bundle entry"):
            V.verify(self.bundle)

    def test_selected_source_missing_and_hash_drift_are_rejected(self):
        source = self.root / "source"
        source.mkdir()
        with self.assertRaisesRegex(ValueError, "missing regular file"):
            V.verify(self.bundle, source)
        first = source / sorted(self.manifest["fileSha256"])[0]
        first.parent.mkdir(parents=True)
        first.write_bytes(b"changed source bytes")
        with self.assertRaisesRegex(ValueError, "source hash mismatch"):
            V.verify(self.bundle, source)

    def test_symlink_patch_and_source_paths_are_rejected(self):
        target = self.root / V.PATCHES[-1]
        saved = self.root / "saved-patch"
        target.rename(saved)
        target.symlink_to(saved)
        with self.assertRaisesRegex(ValueError, "symlink"):
            V.verify(self.bundle)
        source = self.root / "source"
        source.mkdir()
        (source / "linked").symlink_to(saved)
        with self.assertRaisesRegex(ValueError, "symlink"):
            V.read_file(source, "linked", V.SOURCE_LIMIT)
        (source / "directory").symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            V.read_file(source, "directory/saved-patch", V.SOURCE_LIMIT)
        alias = self.root / "source-alias"
        alias.symlink_to(source, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink root"):
            V.read_file(alias, "linked", V.SOURCE_LIMIT)

    def test_oversized_patch_and_source_are_rejected_before_hashing(self):
        with patch.object(V, "PATCH_LIMIT", 1):
            with self.assertRaisesRegex(ValueError, "invalid asset size"):
                V.verify(self.bundle)
        target = self.root / V.PATCHES[-1]
        with target.open("wb") as stream:
            stream.truncate(V.PATCH_LIMIT + 1)
        with self.assertRaisesRegex(ValueError, "file exceeds size limit"):
            V.verify(self.bundle)
        source = self.root / "source"
        source.mkdir()
        (source / "file").write_bytes(b"12345")
        self.assertEqual(V.read_file(source, "file", 5), b"12345")
        with self.assertRaisesRegex(ValueError, "file exceeds size limit"):
            V.read_file(source, "file", 4)

    def test_duplicate_json_fields_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
            V.read_json(b'{"authorization":"none","authorization":"build"}')


if __name__ == "__main__":
    unittest.main()
