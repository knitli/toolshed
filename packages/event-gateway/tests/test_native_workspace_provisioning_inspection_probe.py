import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import native_workspace_provisioning_inspection_probe as probe  # noqa: E402


def _archive(member="opt/homebrew/Cellar/foo/1/INSTALL_RECEIPT.json", payload=b'{"name":"foo","version":"1"}', pax_headers=None):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tar:
        info = tarfile.TarInfo(member)
        info.size = len(payload)
        if pax_headers:
            info.pax_headers = pax_headers
        tar.addfile(info, io.BytesIO(payload))
    return raw.getvalue()


def _xz_archive():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        payload = b'{"name":"foo","version":"1","runtime_dependencies":[]}'
        info = tarfile.TarInfo("opt/homebrew/Cellar/foo/1/INSTALL_RECEIPT.json")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return lzma.compress(raw.getvalue())


def _rust_xz_archive():
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        for name, payload in (("rustc-1.95.0/components", b"rustc\nrust-std-aarch64-apple-darwin\n"),
                              ("rustc-1.95.0/rust-installer-version", b"3\n"),
                              ("rustc-1.95.0/rustc/manifest.in", b"[pkg.rustc]\nversion = 1.95.0\n"),
                              ("rustc-1.95.0/rustc/version", b"1.95.0\n"),
                              ("rustc-1.95.0/rustc/git-commit-hash", b"deadbeef\n")):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
    return lzma.compress(raw.getvalue())


class ProvisioningInspectionTests(unittest.TestCase):
    def _fixture(self, directory, corrupt_last=False, channel_bytes=None):
        root = Path(directory) / "downloads"
        root.mkdir(mode=0o700)
        archive = _archive()
        rust = b"channel = 'stable'\n" if channel_bytes is None else channel_bytes
        (root / "bottle-a.tar.gz").write_bytes(archive)
        channel_name = "channel-rust-1.95.0.toml"
        (root / channel_name).write_bytes(b"bad" if corrupt_last else rust)
        for child in root.iterdir():
            child.chmod(0o600)
        assets = [
            {"name": "bottle-a.tar.gz", "sha256": hashlib.sha256(archive).hexdigest(), "maxBytes": 1024 * 1024},
            {"name": channel_name, "sha256": hashlib.sha256(rust).hexdigest(),
             "maxBytes": max(1024, len(rust))},
        ]
        manifest = {"kind": "native-workspace-provisioning-assets-v1", "qualified": False,
                    "prepared": False, "assets": assets}
        manifest_raw = json.dumps(manifest, sort_keys=True, indent=2).encode() + b"\n"
        input_doc = {"guestRoot": "/private/tmp/knitli-native-provisioning-fixture",
                     "manifestSha256": hashlib.sha256(manifest_raw).hexdigest(),
                     "ownerReceiptSha256": "a" * 64, "postDownloadMeasurement": {}}
        return manifest, manifest_raw, input_doc

    def _guest_collect(self, directory, manifest, manifest_raw, input_doc, local=None):
        module_dir = Path(directory) / "module"
        module_dir.mkdir(mode=0o700)
        (module_dir / "manifest.json").write_bytes(manifest_raw)
        (module_dir / "inspection-input.json").write_text(json.dumps(input_doc))
        old_file = probe.__file__
        probe.__file__ = str(module_dir / "native_workspace_provisioning_inspection_probe.py")
        downloads_fd = os.open(Path(directory) / "downloads", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        root_fd = os.dup(downloads_fd)
        try:
            with mock.patch.object(probe, "_open_guest_downloads", return_value=(root_fd, downloads_fd)), \
                    mock.patch.object(probe, "_local_homebrew", return_value=local or self._local_ok()):
                return probe.collect_guest()
        finally:
            probe.__file__ = old_file

    @staticmethod
    def _local_ok():
        return {"state": "present", "version": {"state": "present", "value": "Homebrew 5.0"},
                "formulae": {"state": "present", "items": []},
                "cellar": {"state": "present", "items": []},
                "optLinks": {"state": "present", "items": []},
                "coreGit": {"head": {"state": "present", "value": "a" * 40},
                            "origin": {"state": "present", "value": "https://github.com/Homebrew/homebrew-core"},
                            "dirty": {"state": "present", "value": ""}}}

    def test_end_to_end_rust_checksum_metadata_does_not_shadow_input_bindings(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, raw, input_doc = self._fixture(directory)
            result = self._guest_collect(directory, manifest, raw, input_doc)
        self.assertEqual(result["manifestSha256"], input_doc["manifestSha256"])
        self.assertEqual(result["ownerReceiptSha256"], "a" * 64)
        self.assertEqual(result["status"], "passed")
        self.assertIn("channel", result["assets"][1]["textMetadata"])

    def test_large_pinned_channel_toml_flows_through_guest_and_host(self):
        channel = b"channel = 'stable'\n" + b"#" + b"x" * (70 * 1024)
        with tempfile.TemporaryDirectory() as directory:
            manifest, raw, input_doc = self._fixture(directory, channel_bytes=channel)
            guest_report = self._guest_collect(directory, manifest, raw, input_doc)
        channel_asset = next(asset for asset in manifest["assets"] if asset["name"].startswith("channel-rust-"))
        self.assertGreater(channel_asset["maxBytes"], probe.MAX_METADATA_BYTES)
        self.assertLessEqual(channel_asset["maxBytes"], probe.MAX_CHANNEL_TEXT_BYTES)
        self.assertEqual(len(guest_report["assets"][1]["textMetadata"].encode()), len(channel))
        owner_manifest = json.loads(probe.MANIFEST_PATH.read_text())
        real_channel = next(asset for asset in owner_manifest["assets"] if asset["name"] == channel_asset["name"])
        self.assertEqual(real_channel["maxBytes"], 848342)
        self.assertGreaterEqual(probe.MAX_CHANNEL_TEXT_BYTES, real_channel["maxBytes"])

        expected_assets = {asset["name"]: {"sha256": asset["sha256"], "maxBytes": asset["maxBytes"]}
                           for asset in manifest["assets"]}
        bundle = {"baseVmName": "softnet-canary-" + "a" * 32,
                  "guestRoot": input_doc["guestRoot"], "loader": "fixed-loader", "argument": "fixed-b64",
                  "ownerReceiptSha256": input_doc["ownerReceiptSha256"],
                  "postDownloadMeasurement": input_doc["postDownloadMeasurement"],
                  "manifestSha256": input_doc["manifestSha256"], "sourceSha256": {},
                  "bundleSha256": "e" * 64, "expectedAssets": expected_assets}
        with tempfile.TemporaryDirectory() as evidence:
            host_result = probe.collect("tart", "offline-canary-" + "f" * 32, {}, evidence, bundle,
                                        run_bounded=lambda *args, **kwargs: (
                                            json.dumps(guest_report).encode(), b""))
        self.assertEqual(host_result["status"], "passed")

    def test_corrupt_last_asset_prevents_archive_and_local_metadata_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, raw, input_doc = self._fixture(directory, corrupt_last=True)
            module_dir = Path(directory) / "module"
            module_dir.mkdir(mode=0o700)
            (module_dir / "manifest.json").write_bytes(raw)
            (module_dir / "inspection-input.json").write_text(json.dumps(input_doc))
            old_file = probe.__file__
            probe.__file__ = str(module_dir / "native_workspace_provisioning_inspection_probe.py")
            downloads_fd = os.open(Path(directory) / "downloads", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            root_fd = os.dup(downloads_fd)
            try:
                with mock.patch.object(probe, "_open_guest_downloads", return_value=(root_fd, downloads_fd)), \
                        mock.patch.object(probe, "_archive_fd") as archive, \
                        mock.patch.object(probe, "_local_homebrew") as local:
                    with self.assertRaisesRegex(ValueError, "asset_digest_mismatch"):
                        probe.collect_guest()
                archive.assert_not_called()
                local.assert_not_called()
            finally:
                probe.__file__ = old_file

    def test_incomplete_local_metadata_cannot_be_reported_passed_or_complete(self):
        local = self._local_ok()
        local["state"] = "incomplete"
        local["coreGit"]["dirty"]["state"] = "incomplete"
        with tempfile.TemporaryDirectory() as directory:
            manifest, raw, input_doc = self._fixture(directory)
            result = self._guest_collect(directory, manifest, raw, input_doc, local)
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["complete"])

    def test_archive_path_traversal_and_large_pax_header_are_incomplete(self):
        for content, expected in ((_archive("../../tmp/pwned"), "archive_path_unsafe"),
                (_archive(pax_headers={"comment": "x" * (probe.MAX_HEADER_BYTES + 1)}),
                                   "archive_metadata_header_cap")):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "asset"
                path.write_bytes(content)
                path.chmod(0o600)
                fd = os.open(path, os.O_RDONLY)
                try:
                    result = probe._archive_fd(fd)
                finally:
                    os.close(fd)
            self.assertFalse(result["complete"])
            self.assertEqual(result["failureCode"], expected)

    def test_gzip_and_xz_inventory_receipt_metadata(self):
        for content, compression in ((_archive(), "gz"), (_xz_archive(), "xz")):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "asset"
                path.write_bytes(content)
                path.chmod(0o600)
                fd = os.open(path, os.O_RDONLY)
                try:
                    result = probe._archive_fd(fd, compression)
                finally:
                    os.close(fd)
            self.assertTrue(result["complete"])
            self.assertEqual(result["memberCount"], 1)
            self.assertEqual(result["members"][0]["receipt"]["name"], "foo")

    def test_rust_xz_keeps_only_allowlisted_installer_metadata_as_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "asset"
            path.write_bytes(_rust_xz_archive())
            path.chmod(0o600)
            fd = os.open(path, os.O_RDONLY)
            try:
                report = probe._archive_fd(fd, "xz")
            finally:
                os.close(fd)
        self.assertTrue(report["complete"])
        metadata = {row.get("metadataKind"): row["rustInstallerMetadata"]
                    for row in report["members"] if "rustInstallerMetadata" in row}
        self.assertEqual(metadata["components"], "rustc\nrust-std-aarch64-apple-darwin\n")
        self.assertIn("version = 1.95.0", metadata["manifest.in"])

    def test_invalid_embedded_receipt_metadata_marks_archive_incomplete(self):
        for malformed in (b"not-json", b"[]", b"null"):
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "asset"
                path.write_bytes(_archive(payload=malformed))
                path.chmod(0o600)
                fd = os.open(path, os.O_RDONLY)
                try:
                    result = probe._archive_fd(fd)
                finally:
                    os.close(fd)
            self.assertFalse(result["complete"])
            self.assertEqual(result["members"][0]["metadataState"], "invalid_json")

    def test_collect_runs_fresh_clone_and_preserves_source_base_binding(self):
        bundle = {"baseVmName": "softnet-canary-" + "a" * 32,
                  "guestRoot": "/private/tmp/knitli-native-provisioning-fixture",
                  "loader": "fixed-loader", "argument": "fixed-b64",
                  "ownerReceiptSha256": "b" * 64, "postDownloadMeasurement": {"diskSha256": "c" * 64},
                  "manifestSha256": "d" * 64, "sourceSha256": {}, "bundleSha256": "e" * 64,
                  "expectedAssets": {"fixture.txt": {"sha256": "f" * 64, "maxBytes": 10}}}
        report = {"kind": probe.KIND, "status": "passed", "qualified": False, "prepared": False,
                  "complete": True, "assets": [{"name": "fixture.txt", "sha256": "f" * 64, "bytes": 3}],
                  "manifestSha256": bundle["manifestSha256"],
                  "ownerReceiptSha256": bundle["ownerReceiptSha256"],
                  "postDownloadMeasurement": bundle["postDownloadMeasurement"], "homebrew": self._local_ok()}
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv)
            return json.dumps(report).encode(), b""
        with tempfile.TemporaryDirectory() as evidence:
            result = probe.collect("tart", "offline-canary-" + "f" * 32, {}, evidence,
                                   bundle, run_bounded=runner)
        self.assertEqual(calls[0][2], "offline-canary-" + "f" * 32)
        self.assertEqual(result["baseVmName"], bundle["baseVmName"])

    def test_host_rejects_passed_but_incomplete_guest_report(self):
        bundle = {"baseVmName": "softnet-canary-" + "a" * 32,
                  "guestRoot": "/private/tmp/knitli-native-provisioning-fixture",
                  "loader": "fixed-loader", "argument": "fixed-b64",
                  "ownerReceiptSha256": "b" * 64, "postDownloadMeasurement": {},
                  "manifestSha256": "d" * 64, "sourceSha256": {}, "bundleSha256": "e" * 64,
                  "expectedAssets": {"fixture.txt": {"sha256": "f" * 64, "maxBytes": 10}}}
        report = {"kind": probe.KIND, "status": "passed", "qualified": False, "prepared": False,
                  "complete": False,
                  "assets": [{"name": "fixture.txt", "sha256": "f" * 64, "bytes": 3}],
                  "manifestSha256": bundle["manifestSha256"],
                  "ownerReceiptSha256": bundle["ownerReceiptSha256"],
                  "postDownloadMeasurement": bundle["postDownloadMeasurement"], "homebrew": self._local_ok()}
        with tempfile.TemporaryDirectory() as evidence:
            with self.assertRaisesRegex(probe.canary.CanaryError, "inspection_report_unqualified"):
                probe.collect("tart", "offline-canary-" + "f" * 32, {}, evidence,
                              bundle, run_bounded=lambda *args, **kwargs: (json.dumps(report).encode(), b""))

    def test_host_rejects_complete_report_missing_pinned_assets(self):
        bundle = {"baseVmName": "softnet-canary-" + "a" * 32,
                  "guestRoot": "/private/tmp/knitli-native-provisioning-fixture",
                  "loader": "fixed-loader", "argument": "fixed-b64",
                  "ownerReceiptSha256": "b" * 64, "postDownloadMeasurement": {},
                  "manifestSha256": "d" * 64, "sourceSha256": {}, "bundleSha256": "e" * 64,
                  "expectedAssets": {"fixture.txt": {"sha256": "f" * 64, "maxBytes": 10}}}
        report = {"kind": probe.KIND, "status": "passed", "qualified": False, "prepared": False,
                  "complete": True, "assets": [], "manifestSha256": bundle["manifestSha256"],
                  "ownerReceiptSha256": bundle["ownerReceiptSha256"],
                  "postDownloadMeasurement": bundle["postDownloadMeasurement"], "homebrew": self._local_ok()}
        with tempfile.TemporaryDirectory() as evidence:
            with self.assertRaisesRegex(probe.canary.CanaryError, "inspection_report_assets_invalid"):
                probe.collect("tart", "offline-canary-" + "f" * 32, {}, evidence,
                              bundle, run_bounded=lambda *args, **kwargs: (json.dumps(report).encode(), b""))

    def test_decompressed_stream_is_bounded(self):
        reader = probe._LimitedReader(io.BytesIO(b"123456"))
        with mock.patch.object(probe, "MAX_EXPANDED_BYTES", 5):
            with self.assertRaisesRegex(ValueError, "archive_expansion_cap"):
                reader.read(6)

    def test_archive_scan_enforces_decompressed_cap(self):
        payload = _archive(payload=b"x" * 2048)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "asset"
            path.write_bytes(payload)
            path.chmod(0o600)
            fd = os.open(path, os.O_RDONLY)
            try:
                with mock.patch.object(probe, "MAX_EXPANDED_BYTES", 1024):
                    result = probe._archive_fd(fd)
            finally:
                os.close(fd)
        self.assertFalse(result["complete"])
        self.assertEqual(result["failureCode"], "archive_expansion_cap")

    def test_directory_inventory_records_symlink_target_literally(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cellar").mkdir()
            (root / "opt-link").symlink_to("../Cellar/foo")
            fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                report = probe._directory_rows(fd)
            finally:
                os.close(fd)
        link = next(item for item in report["items"] if item["name"] == "opt-link")
        self.assertEqual(link["target"], "../Cellar/foo")

    def test_local_inventory_rejects_dirty_core_and_includes_untracked_status(self):
        def command(argv, limit):
            if argv[1] == "--version":
                return {"state": "present", "value": "Homebrew 5.0"}
            if argv[-1] == "HEAD":
                return {"state": "present", "value": "a" * 40}
            if argv[-1] == "origin":
                return {"state": "present", "value": "https://github.com/Homebrew/homebrew-core"}
            return {"state": "present", "value": "?? untracked.rb"}
        with mock.patch.object(probe, "_fixed_command", side_effect=command) as commands, \
                mock.patch.object(probe, "_cellar_inventory", return_value={"state": "present", "items": []}), \
                mock.patch.object(probe, "_directories", return_value={"state": "present", "items": [
                    {"name": "foo", "kind": "symlink", "target": "../Cellar/foo/1"}]}):
            report = probe._local_homebrew()
        self.assertEqual(report["state"], "incomplete")
        self.assertIn("--porcelain", commands.call_args_list[-1].args[0])
        self.assertNotIn("--untracked-files=no", commands.call_args_list[-1].args[0])

    def test_asset_inventory_rejects_symlink_at_exact_pinned_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            downloads = Path(directory) / "downloads"
            downloads.mkdir(mode=0o700)
            target = Path(directory) / "asset-target"
            target.write_bytes(b"pinned")
            target.chmod(0o600)
            (downloads / "asset.tar.gz").symlink_to(target)
            manifest = {"assets": [{"name": "asset.tar.gz", "sha256": hashlib.sha256(b"pinned").hexdigest(),
                                    "maxBytes": 64}]}
            data = {"assets": [{"name": "asset.tar.gz", "sha256": hashlib.sha256(b"pinned").hexdigest()}]}
            fd = os.open(downloads, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                with self.assertRaises(OSError):
                    probe._inspect_assets(data, manifest, fd)
            finally:
                os.close(fd)

    def test_download_directory_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as outside:
            root = Path(tempfile.mkdtemp(prefix="knitli-native-provisioning-", dir=outside))
            try:
                (root / "downloads").symlink_to(outside, target_is_directory=True)
                with mock.patch.object(probe, "GUEST_TMP", outside):
                    with self.assertRaises(OSError):
                        probe._open_guest_downloads(str(root))
            finally:
                (root / "downloads").unlink()
                root.rmdir()

    def test_bundle_binds_current_owner_receipt_and_fits_source_limit(self):
        owner = Path("/private/tmp/event-provisioning-ready-7f7db80a167d40afb4892dd2b9328fe5/owner-result.json")
        if not owner.exists():
            self.skipTest("owner receipt unavailable")
        bundle = probe.build_bundle(owner)
        self.assertEqual(bundle["baseVmName"], "softnet-canary-e2343dabc5cf4a48983fecea7700d970")
        self.assertEqual(bundle["guestRoot"], "/private/tmp/knitli-native-provisioning-lz7hvnc7")
        self.assertTrue(probe.MANIFEST_PATH.exists())
        self.assertLessEqual(len(bundle["argument"]), 128 * 1024)


if __name__ == "__main__":
    unittest.main()
