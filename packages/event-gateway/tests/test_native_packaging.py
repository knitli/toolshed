import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

from event_gateway import launcher


PACKAGER = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts/package_native_client.py")
)


class NativePackagingTests(unittest.TestCase):
    def test_patched_source_manifest_verifies_exact_bytes_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = b"pinned source"
            (root / "native.rs").write_bytes(content)
            digest = hashlib.sha256(content).hexdigest()
            manifest = {
                "fileSha256": {"native.rs": digest},
                "files": [{"path": "native.rs", "sha256": digest, "bytes": len(content)}],
            }
            count, digest = PACKAGER["verify_patched_source"](root, manifest)
            self.assertEqual(count, 1)
            self.assertEqual(len(digest), 64)
            (root / "native.rs").write_bytes(b"tampered source")
            with self.assertRaisesRegex(ValueError, "native_source_hash_mismatch"):
                PACKAGER["verify_patched_source"](root, manifest)
            (root / "native.rs").write_bytes(content)
            (root / "native.rs").unlink()
            (root / "alias").symlink_to(root / "missing")
            manifest["fileSha256"] = {"alias": "0" * 64}
            manifest["files"] = [{"path": "alias", "sha256": "0" * 64, "bytes": 0}]
            with self.assertRaisesRegex(ValueError, "native_source_manifest_mismatch"):
                PACKAGER["verify_patched_source"](root, manifest)

    def test_manifest_rejects_a_missing_patched_file(self):
        manifest_bytes = PACKAGER["SOURCE_MANIFEST"].read_bytes()
        patch_bytes = PACKAGER["PATCH"].read_bytes()
        manifest = PACKAGER["verify_manifest"](manifest_bytes, patch_bytes)
        self.assertEqual(manifest["fileCount"], 48)
        manifest["fileCount"] -= 1
        removed = manifest["files"].pop()
        del manifest["fileSha256"][removed["path"]]
        with self.assertRaisesRegex(ValueError, "native_source_manifest_mismatch"):
            PACKAGER["verify_manifest"](json.dumps(manifest).encode(), patch_bytes)

    def test_lock_normalization_rejects_any_dependency_or_external_change(self):
        before = {
            "version": 4,
            "package": [
                {"name": f"workspace-{index}", "version": "0.0.0", "dependencies": []}
                for index in range(PACKAGER["LOCK_VERSION_CHANGES"])
            ] + [{"name": "serde", "version": "1.0.0", "source": "registry+x", "dependencies": []}],
        }
        after = copy.deepcopy(before)
        for package in after["package"][:-1]:
            package["version"] = "0.160.0"
        self.assertEqual(PACKAGER["lock_version_changes"](before, after), 159)
        changed = copy.deepcopy(after)
        changed["package"][0]["dependencies"] = ["unexpected"]
        with self.assertRaisesRegex(ValueError, "unexpected_cargo_lock_change"):
            PACKAGER["lock_version_changes"](before, changed)

    def test_builder_pin_matches_the_only_launcher_digest(self):
        self.assertEqual(PACKAGER["QUALIFIED_SHA256"], launcher.QUALIFIED_SHA256)

    def test_exclusive_create_race_preserves_the_other_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"candidate")
            original_open = Path.open

            for name, create in (
                ("manifest.json", lambda path: PACKAGER["_write_new"](path, b"candidate")),
                ("codex", lambda path: PACKAGER["_copy_new"](source, path)),
            ):
                with self.subTest(name=name):
                    destination = root / name

                    def race_open(path, mode="r", *args, **kwargs):
                        if path == destination and mode == "xb":
                            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                            with os.fdopen(fd, "wb") as raced_file:
                                raced_file.write(b"created by another process")
                        return original_open(path, mode, *args, **kwargs)

                    with patch.object(Path, "open", new=race_open):
                        with self.assertRaises(FileExistsError):
                            create(destination)
                    self.assertEqual(destination.read_bytes(), b"created by another process")


if __name__ == "__main__":
    unittest.main()
