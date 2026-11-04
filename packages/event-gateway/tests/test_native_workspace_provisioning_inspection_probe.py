import base64
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
import zlib

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


def _xz_archive_with_dictionary(dictionary_bytes):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tar:
        payload = b'{"name":"foo","version":"1"}'
        info = tarfile.TarInfo("opt/homebrew/Cellar/foo/1/INSTALL_RECEIPT.json")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    return lzma.compress(raw.getvalue(), format=lzma.FORMAT_XZ,
                         filters=[{"id": lzma.FILTER_LZMA2, "dict_size": dictionary_bytes}])


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
    @staticmethod
    def _owner_receipt(guest_root):
        measurement = {"configBytes": 1, "configSha256": "a" * 64,
                       "diskBytes": 2, "diskSha256": "b" * 64,
                       "nvramBytes": 3, "nvramSha256": "c" * 64}
        return {
            "kind": "native-provisioning-downloaded-only-owner-receipt-v1",
            "status": "downloaded-only", "qualified": False, "prepared": False,
            "vmName": "softnet-canary-" + "d" * 32, "guestRoot": guest_root,
            "baseMeasurementBefore": measurement, "baseMeasurementAfter": measurement,
            "preDownloadMeasurement": measurement, "postDownloadMeasurement": measurement,
            "baseUnchanged": True, "vmStopped": True, "vmDeleted": False,
            "bundleSha256": "e" * 64, "downloadReceiptSha256": "f" * 64,
            "inventorySha256": "1" * 64, "admissionSha256": "2" * 64,
            "runId": "3" * 32, "macAddress": "02:00:00:00:00:01",
        }

    def _fixture(self, directory, corrupt_last=False, channel_bytes=None, wrapper_version=1):
        root = Path(directory) / "downloads"
        root.mkdir(mode=0o700)
        archive = _archive()
        rust = b"channel = 'stable'\n" if channel_bytes is None else channel_bytes
        (root / "bottle-a.tar.gz").write_bytes(archive)
        channel_name = "channel-rust-1.95.0.toml"
        (root / channel_name).write_bytes(b"bad" if corrupt_last else rust)
        assets = [
            {"name": "bottle-a.tar.gz", "sha256": hashlib.sha256(archive).hexdigest(), "maxBytes": 1024 * 1024},
            {"name": channel_name, "sha256": hashlib.sha256(rust).hexdigest(),
             "maxBytes": max(1024, len(rust))},
        ]
        manifest = {"kind": "native-workspace-provisioning-assets-v1", "qualified": False,
                    "prepared": False, "assets": assets}
        manifest_raw = json.dumps(manifest, sort_keys=True, indent=2).encode() + b"\n"
        manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()

        def download_record(name, digest, size):
            return {"name": name, "initialUrl": f"https://example.com/{name}",
                    "finalHost": "example.com", "finalPath": f"/{name}",
                    "selectedIPv4": "1.1.1.1", "status": 200, "redirectCount": 0,
                    "outcome": "downloaded", "bytes": size, "sha256": digest}
        producer_receipt = json.dumps({"kind": "native-workspace-provisioning-assets-v1",
                                       "status": "downloaded-only", "qualified": False,
                                       "prepared": False, "manifestSha256": manifest_sha256,
                                       "caBundleSha256": "c" * 64, "dnsMap": {"example.com": ["1.1.1.1"]},
                                       "totalBytes": len(archive) + len(rust), "assets": [
                                           download_record("bottle-a.tar.gz", hashlib.sha256(archive).hexdigest(), len(archive)),
                                           download_record(channel_name, hashlib.sha256(rust).hexdigest(), len(rust))]},
                                      sort_keys=True, separators=(",", ":")).encode() + b"\n"
        (root / "receipt.json").write_bytes(producer_receipt)
        for child in root.iterdir():
            child.chmod(0o600)
        guest_root = "/Users/admin/.knitli-native-provisioning-fixture0"
        bundle_sha256 = "b" * 64
        receipt = json.loads(producer_receipt)
        wrapper = {"kind": f"native-workspace-provisioning-guest-download-v{wrapper_version}",
                   "qualified": False, "prepared": False, "guestRoot": guest_root,
                   "bundleSha256": bundle_sha256, "downloadReceipt": receipt}
        if wrapper_version == 2:
            wrapper["preStopInventory"] = {
                "assets": [{"name": row["name"], "bytes": row["bytes"], "sha256": row["sha256"]}
                           for row in receipt["assets"]],
                "receiptSha256": hashlib.sha256(producer_receipt).hexdigest(),
            }
        wrapper_raw = (json.dumps(wrapper, sort_keys=True, separators=(",", ":")) + "\n").encode()
        input_doc = {"guestRoot": guest_root, "manifestSha256": manifest_sha256,
                     "downloadReceiptSha256": hashlib.sha256(wrapper_raw).hexdigest(),
                     "bundleSha256": bundle_sha256,
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

    def test_v2_download_receipt_reports_pre_stop_inventory_match(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, raw, input_doc = self._fixture(directory, wrapper_version=2)
            result = self._guest_collect(directory, manifest, raw, input_doc)
        self.assertEqual(result["preStopComparison"], "matched")

    def test_v1_download_receipt_reports_comparison_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, raw, input_doc = self._fixture(directory, wrapper_version=1)
            result = self._guest_collect(directory, manifest, raw, input_doc)
        self.assertEqual(result["preStopComparison"], "unavailable_legacy_v1")

    def test_v2_actual_asset_size_must_match_receipt_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, _, input_doc = self._fixture(directory, wrapper_version=2)
            downloads = Path(directory) / "downloads"
            receipt_path = downloads / "receipt.json"
            receipt = json.loads(receipt_path.read_text())
            receipt["assets"][0]["bytes"] += 1
            receipt_raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
            receipt_path.write_bytes(receipt_raw)
            wrapper = {"kind": "native-workspace-provisioning-guest-download-v2",
                       "qualified": False, "prepared": False, "guestRoot": input_doc["guestRoot"],
                       "bundleSha256": input_doc["bundleSha256"], "downloadReceipt": receipt,
                       "preStopInventory": {
                           "assets": [{"name": row["name"], "bytes": row["bytes"], "sha256": row["sha256"]}
                                      for row in receipt["assets"]],
                           "receiptSha256": hashlib.sha256(receipt_raw).hexdigest(),
                       }}
            wrapper_raw = (json.dumps(wrapper, sort_keys=True, separators=(",", ":")) + "\n").encode()
            input_doc["downloadReceiptSha256"] = hashlib.sha256(wrapper_raw).hexdigest()
            root_fd = os.open(downloads, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                with self.assertRaisesRegex(ValueError, "asset_digest_mismatch"):
                    probe._inspect_assets(input_doc, manifest, root_fd)
            finally:
                os.close(root_fd)

    def test_receipt_asset_bytes_must_be_positive_and_within_manifest_cap(self):
        for invalid_size in (0, 1024 * 1024 + 1):
            with self.subTest(invalid_size=invalid_size), tempfile.TemporaryDirectory() as directory:
                manifest, _, input_doc = self._fixture(directory, wrapper_version=2)
                downloads = Path(directory) / "downloads"
                receipt_path = downloads / "receipt.json"
                receipt = json.loads(receipt_path.read_text())
                receipt["assets"][0]["bytes"] = invalid_size
                receipt_raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
                receipt_path.write_bytes(receipt_raw)
                wrapper = {"kind": "native-workspace-provisioning-guest-download-v2",
                           "qualified": False, "prepared": False, "guestRoot": input_doc["guestRoot"],
                           "bundleSha256": input_doc["bundleSha256"], "downloadReceipt": receipt,
                           "preStopInventory": {
                               "assets": [{"name": row["name"], "bytes": row["bytes"], "sha256": row["sha256"]}
                                          for row in receipt["assets"]],
                               "receiptSha256": hashlib.sha256(receipt_raw).hexdigest(),
                           }}
                wrapper_raw = (json.dumps(wrapper, sort_keys=True, separators=(",", ":")) + "\n").encode()
                input_doc["downloadReceiptSha256"] = hashlib.sha256(wrapper_raw).hexdigest()
                root_fd = os.open(downloads, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    with self.assertRaisesRegex(ValueError, "download_receipt_binding_mismatch"):
                        probe._inspect_assets(input_doc, manifest, root_fd)
                finally:
                    os.close(root_fd)

    def test_two_matching_wrapper_hashes_are_rejected_as_ambiguous(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, _, input_doc = self._fixture(directory)
            input_doc["downloadReceiptSha256"] = "a" * 64
            root_fd = os.open(Path(directory) / "downloads", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            real_sha256 = hashlib.sha256

            class AmbiguousHash:
                def __init__(self, delegate):
                    self.delegate = delegate

                def update(self, data):
                    self.delegate.update(data)

                def hexdigest(self):
                    return "a" * 64

            def ambiguous_sha256(data=b""):
                return AmbiguousHash(real_sha256(data))

            try:
                with mock.patch.object(probe.hashlib, "sha256", side_effect=ambiguous_sha256):
                    with self.assertRaisesRegex(ValueError, "download_receipt_digest_mismatch"):
                        probe._inspect_assets(input_doc, manifest, root_fd)
            finally:
                os.close(root_fd)

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
            _, raw, input_doc = self._fixture(directory, corrupt_last=True)
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

    def test_xz_decoder_accepts_128_mib_dictionary_and_rejects_256_mib(self):
        for dictionary_bytes, should_complete in ((128 * 1024 * 1024, True),
                                                  (256 * 1024 * 1024, False)):
            with self.subTest(dictionary_bytes=dictionary_bytes), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "asset"
                path.write_bytes(_xz_archive_with_dictionary(dictionary_bytes))
                path.chmod(0o600)
                fd = os.open(path, os.O_RDONLY)
                try:
                    report = probe._archive_fd(fd, "xz")
                finally:
                    os.close(fd)
            self.assertEqual(report["complete"], should_complete)
            if not should_complete:
                self.assertIn("memory", report["failureCode"].lower())

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
                  "guestRoot": "/Users/admin/.knitli-native-provisioning-fixture0",
                  "loader": "fixed-loader", "argument": "fixed-b64",
                  "ownerReceiptSha256": "b" * 64, "postDownloadMeasurement": {"diskSha256": "c" * 64},
                  "manifestSha256": "d" * 64, "sourceSha256": {}, "bundleSha256": "e" * 64,
                  "expectedAssets": {"fixture.txt": {"sha256": "f" * 64, "maxBytes": 10}}}
        report = {"kind": probe.KIND, "status": "passed", "qualified": False, "prepared": False,
                  "complete": True, "assets": [{"name": "fixture.txt", "sha256": "f" * 64, "bytes": 3}],
                  "preStopComparison": "unavailable_legacy_v1",
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
        self.assertEqual(result["preStopComparison"], "unavailable_legacy_v1")

    def test_host_rejects_passed_but_incomplete_guest_report(self):
        bundle = {"baseVmName": "softnet-canary-" + "a" * 32,
                  "guestRoot": "/Users/admin/.knitli-native-provisioning-fixture0",
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
                  "guestRoot": "/Users/admin/.knitli-native-provisioning-fixture0",
                  "loader": "fixed-loader", "argument": "fixed-b64",
                  "ownerReceiptSha256": "b" * 64, "postDownloadMeasurement": {},
                  "manifestSha256": "d" * 64, "sourceSha256": {}, "bundleSha256": "e" * 64,
                  "expectedAssets": {"fixture.txt": {"sha256": "f" * 64, "maxBytes": 10}}}
        report = {"kind": probe.KIND, "status": "passed", "qualified": False, "prepared": False,
                  "complete": True, "assets": [], "preStopComparison": "unavailable_legacy_v1",
                  "manifestSha256": bundle["manifestSha256"],
                  "ownerReceiptSha256": bundle["ownerReceiptSha256"],
                  "postDownloadMeasurement": bundle["postDownloadMeasurement"], "homebrew": self._local_ok()}
        with tempfile.TemporaryDirectory() as evidence:
            with self.assertRaisesRegex(probe.canary.CanaryError, "inspection_report_assets_invalid"):
                probe.collect("tart", "offline-canary-" + "f" * 32, {}, evidence,
                              bundle, run_bounded=lambda *args, **kwargs: (json.dumps(report).encode(), b""))

    def test_host_rejects_missing_or_unknown_pre_stop_comparison(self):
        bundle = {"baseVmName": "softnet-canary-" + "a" * 32,
                  "guestRoot": "/Users/admin/.knitli-native-provisioning-fixture0",
                  "loader": "fixed-loader", "argument": "fixed-b64",
                  "ownerReceiptSha256": "b" * 64, "postDownloadMeasurement": {},
                  "manifestSha256": "d" * 64, "sourceSha256": {}, "bundleSha256": "e" * 64,
                  "expectedAssets": {"fixture.txt": {"sha256": "f" * 64, "maxBytes": 10}}}
        base_report = {"kind": probe.KIND, "status": "passed", "qualified": False, "prepared": False,
                       "complete": True,
                       "assets": [{"name": "fixture.txt", "sha256": "f" * 64, "bytes": 3}],
                       "manifestSha256": bundle["manifestSha256"],
                       "ownerReceiptSha256": bundle["ownerReceiptSha256"],
                       "postDownloadMeasurement": bundle["postDownloadMeasurement"],
                       "homebrew": self._local_ok()}
        for comparison in (None, "unrecognized"):
            with self.subTest(comparison=comparison), tempfile.TemporaryDirectory() as evidence:
                report = dict(base_report)
                if comparison is not None:
                    report["preStopComparison"] = comparison
                with self.assertRaisesRegex(probe.canary.CanaryError, "inspection_report_unqualified"):
                    probe.collect("tart", "offline-canary-" + "f" * 32, {}, evidence,
                                  bundle, run_bounded=lambda *args, **kwargs: (
                                      json.dumps(report).encode(), b""))

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
        with tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir())) as directory:
            core = Path(directory) / "homebrew-core"
            core.mkdir()
            with mock.patch.object(probe, "CORE", str(core)), \
                    mock.patch.object(probe, "_fixed_command", side_effect=command) as commands, \
                    mock.patch.object(probe, "_cellar_inventory", return_value={"state": "present", "items": []}), \
                    mock.patch.object(probe, "_directories", return_value={"state": "present", "items": [
                        {"name": "foo", "kind": "symlink", "target": "../Cellar/foo/1"}]}):
                report = probe._local_homebrew()
        self.assertEqual(report["state"], "incomplete")
        self.assertIn("--porcelain", commands.call_args_list[-1].args[0])
        self.assertNotIn("--untracked-files=no", commands.call_args_list[-1].args[0])

    def test_only_downloaded_stage_accepts_a_proven_missing_core_tap(self):
        with tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir())) as directory:
            core = Path(directory) / "homebrew-core"

            def command(argv, _limit):
                if argv[1] == "--version":
                    return {"state": "present", "value": "Homebrew 5.0"}
                if argv[1:4] == ["list", "--versions", "--formula"]:
                    return {"state": "present", "value": ""}
                self.fail("git must not run for a securely absent core tap")

            def directories(path):
                if path == str(core):
                    return real_directories(path)
                return {"state": "present", "items": []}

            real_directories = probe._directories
            with mock.patch.object(probe, "CORE", str(core)), \
                    mock.patch.object(probe, "_fixed_command", side_effect=command), \
                    mock.patch.object(probe, "_cellar_inventory", return_value={"state": "present", "items": []}), \
                    mock.patch.object(probe, "_directories", side_effect=directories):
                downloaded = probe._local_homebrew(downloaded_only=True)
                other_stage = probe._local_homebrew()

        self.assertEqual(downloaded["state"], "present")
        self.assertEqual(downloaded["coreGit"], {"state": "not_initialized"})
        self.assertEqual(other_stage["state"], "incomplete")
        self.assertEqual(other_stage["coreGit"], {"state": "incomplete"})

    def test_downloaded_stage_does_not_tolerate_existing_broken_core(self):
        with tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir())) as directory:
            core = Path(directory) / "homebrew-core"
            core.mkdir()

            def command(argv, _limit):
                if argv[1] == "--version":
                    return {"state": "present", "value": "Homebrew 5.0"}
                if argv[1:4] == ["list", "--versions", "--formula"]:
                    return {"state": "present", "value": ""}
                return {"state": "incomplete", "errorCode": "exit_2"}

            with mock.patch.object(probe, "CORE", str(core)), \
                    mock.patch.object(probe, "_fixed_command", side_effect=command), \
                    mock.patch.object(probe, "_cellar_inventory", return_value={"state": "present", "items": []}), \
                    mock.patch.object(probe, "_directories", return_value={"state": "present", "items": []}):
                report = probe._local_homebrew(downloaded_only=True)

        self.assertEqual(report["state"], "incomplete")
        self.assertEqual(report["coreGit"]["head"]["state"], "incomplete")

    def test_downloaded_stage_does_not_tolerate_symlinked_core_path(self):
        with tempfile.TemporaryDirectory(dir=os.path.realpath(tempfile.gettempdir())) as directory:
            root = Path(directory)
            target = root / "real-core"
            target.mkdir()
            core = root / "homebrew-core"
            core.symlink_to(target, target_is_directory=True)

            def command(argv, _limit):
                if argv[1] == "--version":
                    return {"state": "present", "value": "Homebrew 5.0"}
                if argv[1:4] == ["list", "--versions", "--formula"]:
                    return {"state": "present", "value": ""}
                self.fail("git must not run for a symlinked core tap")

            def directories(path):
                if path == str(core):
                    return real_directories(path)
                return {"state": "present", "items": []}

            real_directories = probe._directories
            with mock.patch.object(probe, "CORE", str(core)), \
                    mock.patch.object(probe, "_fixed_command", side_effect=command), \
                    mock.patch.object(probe, "_cellar_inventory", return_value={"state": "present", "items": []}), \
                    mock.patch.object(probe, "_directories", side_effect=directories):
                report = probe._local_homebrew(downloaded_only=True)

        self.assertEqual(report["state"], "incomplete")
        self.assertEqual(report["coreGit"], {"state": "incomplete"})

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
            asset = {"name": "asset.tar.gz", "sha256": hashlib.sha256(b"pinned").hexdigest(),
                     "initialUrl": "https://example.com/asset.tar.gz", "finalHost": "example.com",
                     "finalPath": "/asset.tar.gz", "selectedIPv4": "1.1.1.1", "status": 200,
                     "redirectCount": 0, "outcome": "downloaded", "bytes": 6}
            manifest_sha = "d" * 64
            guest_root, bundle_sha = "/Users/admin/.knitli-native-provisioning-fixture0", "b" * 64
            receipt = {"kind": "native-workspace-provisioning-assets-v1", "status": "downloaded-only",
                       "qualified": False, "prepared": False, "manifestSha256": manifest_sha,
                       "caBundleSha256": "c" * 64, "dnsMap": {}, "totalBytes": 6,
                       "assets": [asset]}
            receipt_raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
            (downloads / "receipt.json").write_bytes(receipt_raw)
            (downloads / "receipt.json").chmod(0o600)
            wrapper = {"kind": "native-workspace-provisioning-guest-download-v1", "qualified": False,
                       "prepared": False, "guestRoot": guest_root, "bundleSha256": bundle_sha,
                       "downloadReceipt": receipt}
            wrapper_raw = (json.dumps(wrapper, sort_keys=True, separators=(",", ":")) + "\n").encode()
            data = {"assets": [asset], "manifestSha256": manifest_sha, "guestRoot": guest_root,
                    "bundleSha256": bundle_sha,
                    "downloadReceiptSha256": hashlib.sha256(wrapper_raw).hexdigest()}
            fd = os.open(downloads, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                with self.assertRaises(OSError):
                    probe._inspect_assets(data, manifest, fd)
            finally:
                os.close(fd)

    def test_inspection_accepts_producer_receipt_and_rejects_unexpected_or_unsafe_extras(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, _, input_doc = self._fixture(directory)
            downloads = Path(directory) / "downloads"
            root_fd = os.open(downloads, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                inspected, _, comparison = probe._inspect_assets(input_doc, manifest, root_fd)
                self.assertEqual(len(inspected), len(manifest["assets"]))
                self.assertEqual(comparison["state"], "unavailable_legacy_v1")
                channel = downloads / "channel-rust-1.95.0.toml"
                channel_bytes = channel.read_bytes()
                channel.unlink()
                with self.assertRaisesRegex(ValueError, "asset_set_mismatch"):
                    probe._inspect_assets(input_doc, manifest, root_fd)
                channel.write_bytes(channel_bytes)
                channel.chmod(0o600)
                (downloads / "unexpected").write_bytes(b"extra")
                with self.assertRaisesRegex(ValueError, "asset_set_mismatch"):
                    probe._inspect_assets(input_doc, manifest, root_fd)
                (downloads / "unexpected").unlink()
                receipt = downloads / "receipt.json"
                tampered_receipt = json.loads(receipt.read_text())
                tampered_receipt["caBundleSha256"] = "d" * 64
                receipt.write_text(json.dumps(tampered_receipt, sort_keys=True, separators=(",", ":")) + "\n")
                with self.assertRaisesRegex(ValueError, "download_receipt_digest_mismatch"):
                    probe._inspect_assets(input_doc, manifest, root_fd)
                receipt.unlink()
                with self.assertRaisesRegex(ValueError, "asset_set_mismatch"):
                    probe._inspect_assets(input_doc, manifest, root_fd)
                (downloads / "receipt.json").symlink_to(downloads / "bottle-a.tar.gz")
                with self.assertRaises(OSError):
                    probe._inspect_assets(input_doc, manifest, root_fd)
            finally:
                os.close(root_fd)

    def test_receipt_rejects_malformed_duplicate_noncanonical_constant_and_unbound_json(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, _, input_doc = self._fixture(directory)
            downloads = Path(directory) / "downloads"
            receipt_path = downloads / "receipt.json"
            valid_raw = receipt_path.read_bytes()
            root_fd = os.open(downloads, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))

            def assert_receipt_rejected(raw, error, *, recompute_wrapper=False):
                receipt_path.write_bytes(raw)
                if recompute_wrapper:
                    receipt = json.loads(raw)
                    wrapper = {"kind": "native-workspace-provisioning-guest-download-v1",
                               "qualified": False, "prepared": False,
                               "guestRoot": input_doc["guestRoot"], "bundleSha256": input_doc["bundleSha256"],
                               "downloadReceipt": receipt}
                    wrapper_raw = (json.dumps(wrapper, sort_keys=True, separators=(",", ":")) + "\n").encode()
                    input_doc["downloadReceiptSha256"] = hashlib.sha256(wrapper_raw).hexdigest()
                with self.assertRaisesRegex(ValueError, error):
                    probe._inspect_assets(input_doc, manifest, root_fd)

            try:
                assert_receipt_rejected(b"{broken\n", "download_receipt_invalid")
                assert_receipt_rejected(valid_raw.replace(b'{"assets":', b'{"assets":[],"assets":'),
                                        "download_receipt_duplicate_key")
                nonstandard = json.loads(valid_raw)
                nonstandard["totalBytes"] = float("nan")
                nonstandard_raw = (json.dumps(nonstandard, sort_keys=True, separators=(",", ":")) + "\n").encode()
                assert_receipt_rejected(nonstandard_raw, "download_receipt_invalid",
                                        recompute_wrapper=True)
                assert_receipt_rejected(json.dumps(json.loads(valid_raw), indent=2).encode() + b"\n",
                                        "download_receipt_invalid")
                unbound = json.loads(valid_raw)
                unbound["manifestSha256"] = "0" * 64
                unbound_raw = (json.dumps(unbound, sort_keys=True, separators=(",", ":")) + "\n").encode()
                assert_receipt_rejected(unbound_raw, "download_receipt_binding_mismatch",
                                        recompute_wrapper=True)
                bad_asset = json.loads(valid_raw)
                bad_asset["assets"][0]["sha256"] = "0" * 64
                bad_asset_raw = (json.dumps(bad_asset, sort_keys=True, separators=(",", ":")) + "\n").encode()
                assert_receipt_rejected(bad_asset_raw, "download_receipt_binding_mismatch",
                                        recompute_wrapper=True)
            finally:
                receipt_path.write_bytes(valid_raw)
                os.close(root_fd)

    def test_receipt_change_during_single_bounded_read_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, _, input_doc = self._fixture(directory)
            downloads = Path(directory) / "downloads"
            receipt_path = downloads / "receipt.json"
            receipt_inode = receipt_path.stat().st_ino
            root_fd = os.open(downloads, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            real_read = os.read
            changed = False

            def read_and_change(fd, size):
                nonlocal changed
                chunk = real_read(fd, size)
                if not changed and chunk and os.fstat(fd).st_ino == receipt_inode:
                    with receipt_path.open("ab") as stream:
                        stream.write(b" ")
                    changed = True
                return chunk

            try:
                with mock.patch.object(probe.os, "read", side_effect=read_and_change):
                    with self.assertRaisesRegex(ValueError, "download_receipt_changed_during_read"):
                        probe._inspect_assets(input_doc, manifest, root_fd)
                self.assertTrue(changed)
            finally:
                os.close(root_fd)

    def test_download_directory_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as outside:
            root = Path(tempfile.mkdtemp(prefix=".knitli-native-provisioning-", dir=outside))
            try:
                (root / "downloads").symlink_to(outside, target_is_directory=True)
                with mock.patch.object(probe, "GUEST_PARENT", outside):
                    with self.assertRaises(OSError):
                        probe._open_guest_downloads(f"/Users/admin/{root.name}")
            finally:
                (root / "downloads").unlink()
                root.rmdir()

    def test_persistent_download_root_reopens_after_legacy_temp_root_is_removed(self):
        safe_parent = Path.cwd().resolve()
        with tempfile.TemporaryDirectory(dir=safe_parent) as parent, tempfile.TemporaryDirectory(dir=safe_parent) as old_tmp:
            old_root = Path(old_tmp) / "knitli-native-provisioning-abcdefgh"
            old_root.mkdir(mode=0o700)
            (old_root / "downloads").mkdir(mode=0o700)
            (old_root / "downloads/asset").write_bytes(b"legacy")
            import shutil
            shutil.rmtree(old_root)

            root_name = ".knitli-native-provisioning-abcdefgh"
            root = Path(parent) / root_name
            root.mkdir(mode=0o700)
            downloads = root / "downloads"
            downloads.mkdir(mode=0o700)
            (downloads / "asset").write_bytes(b"persistent")
            guest_root = f"/Users/admin/{root_name}"
            self.assertTrue(probe.GUEST_ROOT.fullmatch(guest_root))
            self.assertFalse(probe.GUEST_ROOT.fullmatch(str(old_root)))
            with mock.patch.object(probe, "GUEST_PARENT", parent):
                root_fd, downloads_fd = probe._open_guest_downloads(guest_root)
            try:
                asset_fd = os.open("asset", os.O_RDONLY, dir_fd=downloads_fd)
                try:
                    self.assertEqual(os.read(asset_fd, 10), b"persistent")
                finally:
                    os.close(asset_fd)
            finally:
                os.close(downloads_fd)
                os.close(root_fd)

    def test_guest_rejects_synthetic_legacy_root_before_open(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest, raw, input_doc = self._fixture(directory)
            input_doc["guestRoot"] = "/tmp/knitli-native-provisioning-abcdefgh"  # nosec B108 -- Invalid input fixture rejected before filesystem access.
            with self.assertRaisesRegex(ValueError, "guest_root_invalid"):
                self._guest_collect(directory, manifest, raw, input_doc)

    def test_persistent_root_parent_must_be_private_nofollow_directory(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd().resolve()) as parent:
            root = Path(parent) / ".knitli-native-provisioning-abcdefgh"
            root.mkdir(mode=0o700)
            (root / "downloads").mkdir(mode=0o700)
            asset = root / "downloads/asset"
            asset.write_bytes(b"read-only")
            guest_root = f"/Users/admin/{root.name}"
            # A group-writable parent must fail before downloads are opened.
            os.chmod(parent, 0o720)  # nosec B103 -- Isolated rejection fixture; restored to 0700 below.
            try:
                with mock.patch.object(probe, "GUEST_PARENT", parent):
                    with self.assertRaisesRegex(ValueError, "guest_parent_unsafe"):
                        probe._open_guest_downloads(guest_root)
            finally:
                os.chmod(parent, 0o700)
            self.assertEqual(asset.read_bytes(), b"read-only")
            parent_link = Path(parent).with_name(Path(parent).name + "-link")
            parent_link.symlink_to(parent, target_is_directory=True)
            try:
                with mock.patch.object(probe, "GUEST_PARENT", str(parent_link)):
                    with self.assertRaises(OSError):
                        probe._open_guest_downloads(guest_root)
            finally:
                parent_link.unlink()

    def test_bundle_accepts_synthetic_persistent_owner_receipt_and_rejects_legacy_root(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd().resolve()) as directory:
            owner_path = Path(directory) / "owner-result.json"
            owner = self._owner_receipt("/Users/admin/.knitli-native-provisioning-abcdefgh")
            owner_path.write_text(json.dumps(owner))
            bundle = probe.build_bundle(owner_path)
            self.assertEqual(bundle["guestRoot"], owner["guestRoot"])
            self.assertEqual(bundle["baseVmName"], owner["vmName"])
            self.assertLessEqual(len(bundle["argument"]), 128 * 1024)
            self.assertIn(f"decoder.decompress(packed, {probe.MAX_PACKED_BUNDLE_BYTES} + 1)", bundle["loader"])
            self.assertIn(f"len(raw) > {probe.MAX_PACKED_BUNDLE_BYTES}", bundle["loader"])
            compressed = base64.b64decode(bundle["argument"])
            packed_size = len(zlib.decompress(compressed))
            encoded_size = len(bundle["argument"].encode("ascii"))
            for limit_name, size in (("MAX_PACKED_BUNDLE_BYTES", packed_size),
                                     ("MAX_ENCODED_BUNDLE_BYTES", encoded_size)):
                with self.subTest(limit=limit_name):
                    with mock.patch.object(probe, limit_name, size):
                        self.assertEqual(probe.build_bundle(owner_path)["argument"], bundle["argument"])
                    with mock.patch.object(probe, limit_name, size - 1):
                        with self.assertRaisesRegex(probe.canary.CanaryError,
                                                    "native_provisioning_inspection_bundle_oversized"):
                            probe.build_bundle(owner_path)

            owner["guestRoot"] = "/tmp/knitli-native-provisioning-abcdefgh"  # nosec B108 -- Invalid receipt fixture rejected before filesystem access.
            owner_path.write_text(json.dumps(owner))
            with self.assertRaisesRegex(probe.canary.CanaryError, "invalid_owner_receipt"):
                probe.build_bundle(owner_path)


if __name__ == "__main__":
    unittest.main()
