import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess  # nosec B404 -- fixed local interpreter and receiver/import fixtures; no shell.
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import native_workspace_stage_inputs as staging  # noqa: E402


def digest(data):
    return hashlib.sha256(data).hexdigest()


class FakeRegistry:
    """Explicit fixture registry: fixture bytes are pinned only for these tests."""

    def __init__(self, files):
        """Pin the test-owned recipe assets without granting production authority."""
        self.files = files
        self.assets = {}
        for name in staging.MEMBERS[-2:]:
            relative = name.split("native-bridge/", 1)[1]
            self.assets[relative] = SimpleNamespace(path=relative, bytes=len(files[name]),
                                                    sha256=digest(files[name]))
        self.recipe = SimpleNamespace(family="core-idle-v1", revision=1,
                                      manifest=self.assets[staging.MEMBERS[-2].split("native-bridge/", 1)[1]],
                                      ordered_patches=(self.assets[staging.MEMBERS[-1].split("native-bridge/", 1)[1]],))

    def validate_recipe(self, family, revision):
        assert (family, revision) == ("core-idle-v1", 1)
        return SimpleNamespace(recipe=self.recipe)

    def _read_asset(self, asset):
        return self.files[next(name for name in staging.MEMBERS[-2:]
                               if name.endswith(asset.path))]


class StageInputBundleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private_tmp = self.root / "private-tmp"
        self.private_tmp.mkdir(mode=0o700)
        self.private_tmp.chmod(0o700)
        self.files = {}
        for index, name in enumerate(staging.MEMBERS):
            path = self.root.joinpath(*PurePosixPath(name).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            self.files[name] = (f"fixture-{index}\n".encode() if index < 5
                                else f"registered-fixture-asset-{index}\n".encode())
            path.write_bytes(self.files[name])
        self.registry = FakeRegistry(self.files)
        self.registry_patch = patch.object(staging.builder, "registry", self.registry)
        self.registry_patch.start()
        self.addCleanup(self.registry_patch.stop)

    def run_receiver(self, bundle, data=None):
        environment = dict(os.environ)
        environment["TMPDIR"] = str(self.private_tmp)
        return subprocess.run([sys.executable, "-I", "-c", bundle["receiver"]],  # nosec B603 -- fixed receiver source; hostile inputs remain archive/JSON data.
                              input=bundle["archive"] if data is None else data,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                              env=environment)

    def test_fixture_build_is_exact_deterministic_and_byte_pinned(self):
        first = staging.build_bundle(self.root)
        second = staging.build_bundle(self.root)
        self.assertEqual(first["archive"], second["archive"])
        self.assertEqual(first["manifest"], second["manifest"])
        self.assertEqual([item["path"] for item in first["manifest"]["members"]],
                         list(staging.MEMBERS))
        self.assertEqual(first["manifest"]["memberCount"], 8)
        self.assertEqual(first["manifest"]["totalBytes"], sum(map(len, self.files.values())))
        self.assertFalse(first["manifest"]["qualified"])
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(first["archive"]))) as archive:
            for member in archive.getmembers():
                self.assertTrue(member.isreg())
                self.assertEqual((member.uid, member.gid, member.mtime, member.mode),
                                 (0, 0, 0, 0o600))
                self.assertEqual(archive.extractfile(member).read(), self.files[member.name])

    def test_build_validates_registered_recipe_once(self):
        with patch.object(self.registry, "validate_recipe", wraps=self.registry.validate_recipe) as validate:
            staging.build_bundle(self.root)
        validate.assert_called_once_with("core-idle-v1", 1)

    def test_current_checkout_closure_and_real_recipe_pins(self):
        from importlib import import_module
        registry = import_module("native_recipe_registry")
        with patch.object(staging.builder, "registry", registry):
            bundle = staging.build_bundle()
        self.assertEqual([item["path"] for item in bundle["manifest"]["members"]],
                         list(staging.MEMBERS))
        self.assertEqual(bundle["manifest"]["memberCount"], 8)
        self.assertLess(bundle["manifest"]["totalBytes"], staging.MAX_TOTAL_BYTES)
        self.assertEqual(registry.validate_recipe().recipe.family, "core-idle-v1")

    def test_actual_receiver_writes_exact_private_tree_and_receipt_without_execution(self):
        bundle = staging.build_bundle(self.root)
        result = self.run_receiver(bundle)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        output = json.loads(result.stdout)
        self.assertEqual(output["status"], "inputs-received")
        self.assertIs(output["qualified"], False)
        root = Path(output["root"])
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
        for name in staging.MEMBERS:
            path = root.joinpath(*PurePosixPath(name).parts)
            self.assertEqual(path.read_bytes(), self.files[name])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        receipt = json.loads((root / staging.RECEIPT_NAME).read_bytes())
        self.assertEqual(receipt["status"], "inputs-received")
        self.assertIs(receipt["qualified"], False)
        self.assertEqual({p.name for p in (root / "packages/event-gateway/scripts").iterdir()},
                         {PurePosixPath(name).name for name in staging.MEMBERS[:5]})

    def test_current_bundle_imports_stager_and_omitting_launcher_fails_at_import(self):
        from importlib import import_module
        registry = import_module("native_recipe_registry")
        with patch.object(staging.builder, "registry", registry):
            bundle = staging.build_bundle()
        result = self.run_receiver(bundle)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        root = Path(output["root"])
        self.addCleanup(lambda: __import__("shutil").rmtree(root, ignore_errors=True))
        import_code = ("import sys; sys.path.insert(0, "
                       + repr(str(root / "packages/event-gateway/scripts"))
                       + "); import stage_native_workspace")
        imported = subprocess.run([sys.executable, "-I", "-B", "-c", import_code],  # nosec B603 -- fixed import of repository-owned staging source.
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertEqual((imported.stdout, imported.stderr), (b"", b""))
        launcher = root / "packages/event-gateway/src/event_gateway/launcher.py"
        launcher.unlink()
        missing = subprocess.run([sys.executable, "-I", "-B", "-c", import_code],  # nosec B603 -- same fixed import after removing its test-owned dependency.
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn(b"FileNotFoundError", missing.stderr)
        self.assertIn(b"launcher.py", missing.stderr)

    def test_future_command_template_is_fixed_to_stdin_receiver(self):
        bundle = staging.build_bundle(self.root)
        argv = staging.command_template("/usr/local/bin/tart", "guest-1", bundle["manifest"])
        self.assertEqual(argv[:4], ["/usr/local/bin/tart", "exec", "-i", "guest-1"])
        self.assertIn("/usr/bin/env", argv)
        self.assertEqual(argv[-5:], ["/usr/bin/python3", "-I", "-B", "-c", bundle["receiver"]])
        self.assertNotIn("--", argv[argv.index("-c") + 1:])
        with self.assertRaisesRegex(ValueError, "invalid_bundle_manifest"):
            staging.command_template("/usr/local/bin/tart", "guest-1", "print('arbitrary')")

    def test_receiver_manifest_strings_are_json_data_not_python_source(self):
        bundle = staging.build_bundle(self.root)
        marker = self.private_tmp / "receiver-code-executed"
        payload = ("bad-kind'); __import__('pathlib').Path(" + repr(str(marker))
                   + ").touch(); # __EXPECTED_JSON__ __FIXED_MEMBER_PATHS__ __MEMBER_COUNT__")
        manifest = dict(bundle["manifest"], kind=payload)
        manifest.pop("manifestSha256")
        manifest["manifestSha256"] = digest(json.dumps(
            manifest, sort_keys=True, separators=(",", ":")).encode())
        receiver = staging._receiver(manifest)
        self.assertIn("EXPECTED = json.loads(", receiver)
        for token in ("__EXPECTED_JSON__", "__FIXED_MEMBER_PATHS__", "__MEMBER_COUNT__"):
            self.assertIn(token, receiver)
        result = self.run_receiver({"archive": bundle["archive"], "receiver": receiver})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))
        self.assertFalse(marker.exists())

    def test_builder_rejects_symlinked_input_and_recipe_pin_drift(self):
        target = self.root / "target"
        target.write_bytes(self.files[staging.MEMBERS[0]])
        path = self.root.joinpath(*PurePosixPath(staging.MEMBERS[0]).parts)
        path.unlink()
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "source_member_not_regular"):
            staging.build_bundle(self.root)
        path.unlink()
        path.write_bytes(self.files[staging.MEMBERS[0]])
        pin_path = self.root.joinpath(*PurePosixPath(staging.MEMBERS[-2]).parts)
        pin_path.write_bytes(b"changed manifest")
        with self.assertRaisesRegex(ValueError, "registered_recipe_asset_mismatch"):
            staging.build_bundle(self.root)

    def test_builder_rejects_symlinked_parent_then_restores_green(self):
        scripts = self.root / "packages/event-gateway/scripts"
        saved = self.root / "saved-scripts"
        external = self.root.parent / (self.root.name + "-outside-scripts")
        self.addCleanup(lambda: shutil.rmtree(external, ignore_errors=True))
        scripts.rename(saved)
        shutil.copytree(saved, external)
        scripts.symlink_to(external, target_is_directory=True)
        try:
            self.assertEqual((scripts / "stage_native_workspace.py").read_bytes(),
                             self.files[staging.MEMBERS[0]])
            with self.assertRaisesRegex(ValueError, "source_member_parent_not_directory"):
                staging.build_bundle(self.root)
        finally:
            scripts.unlink()
            saved.rename(scripts)
        self.assertEqual(staging.build_bundle(self.root)["manifest"]["memberCount"],
                         len(staging.MEMBERS))

    def test_receiver_accepts_tar_padding_near_the_uncompressed_limit(self):
        payload = bytes(range(256)) * 1024
        for name in staging.MEMBERS:
            path = self.root.joinpath(*PurePosixPath(name).parts)
            path.write_bytes(payload)
            self.files[name] = payload
        self.registry = FakeRegistry(self.files)
        with patch.object(staging.builder, "registry", self.registry):
            bundle = staging.build_bundle(self.root)
        self.assertEqual(bundle["manifest"]["totalBytes"], staging.MAX_TOTAL_BYTES)
        result = self.run_receiver(bundle)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertIs(output["qualified"], False)
        shutil.rmtree(output["root"])

    def test_receiver_silently_rejects_archive_hash_and_truncation(self):
        bundle = staging.build_bundle(self.root)
        for data in (bundle["archive"][:-1], b"not-a-tar"):
            result = self.run_receiver(bundle, data)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((result.stdout, result.stderr), (b"", b""))
        invalid = dict(bundle["manifest"], qualified=True)
        invalid.pop("manifestSha256")
        invalid["manifestSha256"] = digest(json.dumps(
            invalid, sort_keys=True, separators=(",", ":")).encode())
        forged = {"archive": bundle["archive"], "receiver": staging._receiver(invalid)}
        result = self.run_receiver(forged)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))

    def _hostile_receiver(self, entries):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data, kind in entries:
                info = tarfile.TarInfo(name)
                info.mode = 0o600
                if kind == "symlink":
                    info.type = tarfile.SYMTYPE
                    info.linkname = "elsewhere"
                    archive.addfile(info)
                    continue
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        packed = gzip.compress(raw.getvalue(), mtime=0)
        records = [{"path": name, "bytes": len(self.files[name]),
                    "sha256": digest(self.files[name])} for name in staging.MEMBERS]
        total = sum(item["bytes"] for item in records)
        manifest = {"kind": "native-workspace-stage-inputs-v1", "qualified": False,
                    "memberCount": len(staging.MEMBERS), "totalBytes": total, "members": records,
                    "archiveBytes": len(packed), "archiveSha256": digest(packed),
                    "manifestSha256": ""}
        manifest["manifestSha256"] = digest(json.dumps(
            {key: value for key, value in manifest.items() if key != "manifestSha256"},
            sort_keys=True, separators=(",", ":")).encode())
        return {"archive": packed, "manifest": manifest,
                "receiver": staging._receiver(manifest)}

    def test_receiver_rejects_traversal_symlink_duplicate_oversize_and_digest_before_writing(self):
        base = [(name, self.files[name], "file") for name in staging.MEMBERS]
        cases = [
            [("../escape", base[0][1], "file"), *base[1:]],
            [(base[0][0], b"x", "symlink"), *base[1:]],
            [base[0], base[0], *base[2:]],
            [(base[0][0], b"x" * (staging.MAX_MEMBER_BYTES + 1), "file"), *base[1:]],
        ]
        for entries in cases:
            result = self.run_receiver(self._hostile_receiver(entries))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual((result.stdout, result.stderr), (b"", b""))
        tampered = list(base)
        name, content, kind = tampered[0]
        tampered[0] = (name, bytes([content[0] ^ 1]) + content[1:], kind)
        bad_digest = self._hostile_receiver(tampered)
        self.assertEqual(bad_digest["manifest"]["archiveSha256"], digest(bad_digest["archive"]))
        self.assertNotEqual(bad_digest["manifest"]["members"][0]["sha256"],
                            digest(tampered[0][1]))
        result = self.run_receiver(bad_digest)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))


if __name__ == "__main__":
    unittest.main()
