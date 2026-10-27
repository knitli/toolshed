import hashlib
from contextlib import ExitStack
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import stage_native_workspace as staging  # noqa: E402
import package_native_client as builder  # noqa: E402


class StageFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(strict=True)
        self.source = self.root / "source"
        self.source.mkdir()
        self.cargo = self.private_dir("cargo")
        self.rustup = self.private_dir("rustup")
        self.sdk = self.root / "sdk"
        self.sdk.mkdir()
        self.lock_before = "".join(f'[[package]]\nname = "local-{i}"\nversion = "0.0.0"\n\n'
                                    for i in range(159)).encode()
        self.lock_after = self.lock_before.replace(b'version = "0.0.0"', b'version = "0.160.0"')
        self.graph = {"packages": [], "resolve": None, "workspace_members": [],
                      "workspace_default_members": []}
        self.recipe_identity = {"family": "fixture", "revision": 1}

    def private_dir(self, name):
        path = self.root / name
        path.mkdir(mode=0o700)
        path.chmod(0o700)
        return path

    def genv_selector(self):
        original = shutil.which
        executable = original("genv") or original("env")
        self.assertIsNotNone(executable)
        return patch.object(staging.shutil, "which", side_effect=lambda name, path=None:
                            executable if name == "genv" else original(name, path=path))

    def fake_bounded(self, argv, *, timeout, env, output_limit, capture_paths, **kwargs):
        self.bounded_calls.append((argv, timeout, env, output_limit, capture_paths))
        command = argv[2:]
        cwd = argv[1].removeprefix("--chdir=")
        if "--source" in command:
            staged = Path(command[command.index("--output") + 1])
            codex = staged / "codex-rs"
            codex.mkdir(parents=True)
            receipt = {"upstreamCommit": builder.UPSTREAM_COMMIT, "recipe": self.recipe_identity,
                       "v8Assets": {"archive": {"sha256": "c" * 64}}}
            (staged / "qualification.json").write_text(json.dumps(receipt) + "\n")
            (codex / "Cargo.lock").write_bytes(self.lock_before)
            if self.malicious_config:
                config = codex / ".cargo/config.toml"
                config.parent.mkdir()
                config.write_text("[net]\noffline = false\n")
        elif "metadata" in command:
            offline = "--offline" in command
            if not offline:
                (Path(cwd) / "Cargo.lock").write_bytes(self.lock_after)
            graph = dict(self.graph)
            if offline and self.graph_drift:
                graph["packages"] = ["different"]
            Path(capture_paths[0]).write_text(json.dumps(graph))
            if offline and self.lock_drift_at == "offline":
                (Path(cwd) / "Cargo.lock").write_bytes(self.lock_after + b"# drift\n")
        elif "fetch" in command and self.lock_drift_at == "fetch":
            (Path(cwd) / "Cargo.lock").write_bytes(self.lock_after + b"# drift\n")
        Path(capture_paths[0]).touch(exist_ok=True)
        Path(capture_paths[1]).write_bytes(b"")
        return b"", b""

    def setup_stage(self, *, lock_drift_at=None, graph_drift=False, malicious_config=False,
                    source_inventory_drift=False):
        self.lock_drift_at = lock_drift_at
        self.graph_drift = graph_drift
        self.malicious_config = malicious_config
        self.bounded_calls = []
        self.patchers = [
            patch.object(staging.canary, "_run_bounded", side_effect=self.fake_bounded),
            patch.object(staging.platform, "system", return_value="Darwin"),
            patch.object(staging.platform, "mac_ver", return_value=("15.6", ("", "", ""), "")),
            patch.object(staging.platform, "machine", return_value="arm64"),
            patch.dict(os.environ, {"CARGO_HOME": str(self.cargo), "RUSTUP_HOME": str(self.rustup),
                                    "HTTP_PROXY": "http://ambient.invalid", "AWS_SECRET_ACCESS_KEY": "ambient"}),
            patch.object(builder, "_toolchain", return_value=(
                ["rustup", "run", "1.95.0"], "rustc 1.95.0", "cargo 1.95.0",
                {"rustup": {"path": "/tools/rustup"}, "rustc": {}, "cargo": {}})),
            patch.object(staging, "_versioned_tool", side_effect=self.versioned_tool),
            patch.object(staging, "_tool", side_effect=self.tool),
            patch.object(staging.shutil, "which", side_effect=lambda name, path=None: f"/tools/{name}"),
            patch.object(builder, "_binary_evidence", return_value={}),
            patch.object(builder.registry, "validate_recipe", return_value=SimpleNamespace(
                recipe=SimpleNamespace(family="fixture", revision=1,
                                       manifest=SimpleNamespace(sha256="a" * 64)))),
            patch.object(builder, "verify_recipe_source", side_effect=(
                [(57, "b" * 64), (58, "c" * 64)] if source_inventory_drift else None),
                **({} if source_inventory_drift else {"return_value": (57, "b" * 64)})),
            patch.object(builder, "recipe_identity", return_value=self.recipe_identity),
        ]
        if not malicious_config:
            self.patchers.append(patch.object(builder, "_cargo_configuration", return_value={"offline": True}))
        for item in self.patchers:
            item.start()
            self.addCleanup(item.stop)

    @staticmethod
    def versioned_tool(name, args, env, cwd):
        versions = {"cargo-nextest": "cargo-nextest 0.9.128", "just": "just 1.40.0",
                    "gtimeout": "gtimeout 9.1", "pkg-config": "pkg-config 0.29"}
        return {"binary": {}, "version": versions.get(name, name + " 1")}

    def tool(self, path, args, env, cwd):
        if args[:1] == ["--show-sdk-path"]:
            return str(self.sdk)
        if args[:1] == ["--modversion"]:
            return "1.28.0" if args[1].startswith("gstreamer") else "2.80.0"
        return "1.0"


class NativeWorkspaceStageTest(StageFixture):
    def test_wrong_host_rejects_before_output_or_subprocess(self):
        invalid_values = (("system", "Linux"), ("mac_ver", ("27.0", (), "")),
                          ("machine", "x86_64"), ("version_info", (3, 12, 0)))
        for field, invalid in invalid_values:
            with self.subTest(field=field):
                output = self.root / f"host-rejected-{field}"
                with ExitStack() as stack:
                    for module, name, valid in ((staging.platform, "system", "Darwin"),
                                                (staging.platform, "mac_ver", ("15.6", (), "")),
                                                (staging.platform, "machine", "arm64"),
                                                (staging.sys, "version_info", (3, 13, 0))):
                        stack.enter_context(patch.object(
                            module, name, new=valid) if name == "version_info"
                            else patch.object(module, name, return_value=valid))
                    module = staging.platform if field != "version_info" else staging.sys
                    stack.enter_context(patch.object(module, field, new=invalid) if field == "version_info"
                                        else patch.object(module, field, return_value=invalid))
                    run = stack.enter_context(patch.object(staging.canary, "_run_bounded"))
                    with self.assertRaisesRegex(ValueError, "requires_python_3_13_macos_15_arm64"):
                        staging.stage(self.source, output)
                self.assertFalse(output.exists())
                run.assert_not_called()

    def test_success_has_exclusive_receipt_and_exact_staging_evidence(self):
        self.setup_stage()
        output = self.root / "prepared"
        receipt = staging.stage(self.source, output)
        self.assertEqual(receipt["status"], "prepared")
        self.assertFalse(receipt["qualified"])
        self.assertEqual(receipt["locks"]["versionChanges"], 159)
        self.assertEqual(receipt["recipeSourceInventory"], {"files": 57, "sha256": "b" * 64})
        self.assertEqual(receipt["metadata"]["onlineSha256"],
                         hashlib.sha256((output / "metadata.online.json").read_bytes()).hexdigest())
        self.assertEqual(receipt["metadata"]["onlineStderrSha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(json.loads((output / "receipt.json").read_text()), receipt)
        with self.assertRaisesRegex(ValueError, "output_must_be_fresh"):
            staging.stage(self.source, output)
        metadata_calls = [item for item in self.bounded_calls if "metadata" in item[0]]
        metadata = [item[0][2:] for item in metadata_calls]
        self.assertEqual(len(metadata), 2)
        self.assertEqual(staging.FEATURES, "codex-v8-poc/sandbox")
        self.assertIn("--features", metadata[0])
        self.assertEqual(metadata[0][metadata[0].index("--features") + 1], staging.FEATURES)
        self.assertEqual(metadata_calls[0][2]["CARGO_NET_OFFLINE"], "false")
        offline = metadata[1].index("metadata")
        self.assertEqual(metadata[1][offline:offline + 5],
                         ["metadata", "--offline", "--locked", "--features", staging.FEATURES])
        fetch_call = next(item for item in self.bounded_calls if "fetch" in item[0])
        self.assertEqual(fetch_call[0][-2:], ["fetch", "--locked"])
        self.assertEqual(fetch_call[2]["CARGO_NET_OFFLINE"], "false")
        self.assertEqual(metadata_calls[-1][2]["CARGO_NET_OFFLINE"], "true")
        for command, timeout, env, output_limit, paths in self.bounded_calls:
            self.assertEqual(command[0], "/tools/genv")
            self.assertTrue(command[1].startswith("--chdir="))
            self.assertEqual(timeout, 1800)
            self.assertEqual(output_limit, staging.MAX_METADATA_BYTES)
            self.assertEqual(len(paths), 2)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", receipt["environmentKeys"])
        self.assertNotIn("HTTP_PROXY", receipt["environmentKeys"])
        for invocation in self.bounded_calls:
            self.assertTrue(Path(invocation[2]["HOME"]).resolve().is_relative_to(output.resolve()))
            self.assertNotIn("HTTP_PROXY", invocation[2])
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", invocation[2])

    def test_metadata_output_cap_kills_and_reaps_real_child(self):
        destination = self.root / "oversized.json"
        popen = subprocess.Popen
        children = []

        def capture_child(*args, **kwargs):
            child = popen(*args, **kwargs)
            children.append(child)
            return child

        cwd_marker = self.root / "child-cwd.txt"
        child_code = (f"import os, time; open({str(cwd_marker)!r}, 'w').write(os.getcwd()); "
                      "os.write(1, b'x' * 1000000); time.sleep(30)")
        command = [sys.executable, "-c", child_code]
        with patch.object(staging, "MAX_METADATA_BYTES", 128), \
                patch.object(subprocess, "Popen", side_effect=capture_child), self.genv_selector():
            with self.assertRaisesRegex(ValueError, "tart_command_output_limit"):
                staging._run_file(command, cwd=self.root, env=os.environ.copy(), destination=destination)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        with self.assertRaises(ProcessLookupError):
            os.killpg(children[0].pid, 0)
        self.assertLessEqual(destination.stat().st_size, 128)
        self.assertLessEqual(destination.with_suffix(".json.stderr.bin").stat().st_size, 128)
        self.assertEqual(cwd_marker.read_text(), str(self.root))

    def test_metadata_output_cap_rejects_large_completed_child(self):
        destination = self.root / "completed-oversized.json"
        command = [sys.executable, "-c", "import os; os.write(1, b'x' * 1000000)"]
        with patch.object(staging, "MAX_METADATA_BYTES", 128), self.genv_selector():
            with self.assertRaisesRegex(ValueError, "tart_command_output_limit"):
                staging._run_file(command, cwd=self.root, env=os.environ.copy(), destination=destination)
        self.assertLessEqual(destination.stat().st_size, 128)

    def test_metadata_capture_collision_preserves_existing_file_and_skips_child(self):
        destination = self.root / "already-owned.json"
        destination.write_text("owned by caller\n")
        with patch.object(subprocess, "Popen") as spawn, self.genv_selector():
            with self.assertRaises((ValueError, FileExistsError)):
                staging._run_file([sys.executable, "-c", "pass"], cwd=self.root,
                                  env=os.environ.copy(), destination=destination)
        spawn.assert_not_called()
        self.assertEqual(destination.read_text(), "owned by caller\n")

    def test_lock_drift_after_fetch_or_offline_metadata_never_publishes_receipt(self):
        for point, error in (("fetch", "cargo_lock_changed_after_fetch"),
                             ("offline", "cargo_lock_changed_after_offline_metadata")):
            with self.subTest(point=point):
                self.setup_stage(lock_drift_at=point)
                output = self.root / f"lock-drift-{point}"
                with self.assertRaisesRegex(ValueError, error):
                    staging.stage(self.source, output)
                self.assertFalse((output / "receipt.json").exists())

    def test_offline_graph_drift_never_publishes_success_receipt(self):
        self.setup_stage(graph_drift=True)
        output = self.root / "graph-drift"
        with self.assertRaisesRegex(ValueError, "cargo_offline_metadata_graph_mismatch"):
            staging.stage(self.source, output)
        self.assertFalse((output / "receipt.json").exists())

    def test_source_inventory_drift_never_publishes_success_receipt(self):
        self.setup_stage(source_inventory_drift=True)
        output = self.root / "source-drift"
        with self.assertRaisesRegex(ValueError, "native_workspace_source_changed_during_resolution"):
            staging.stage(self.source, output)
        self.assertFalse((output / "receipt.json").exists())

    def test_credentials_and_overlapping_paths_are_rejected(self):
        self.setup_stage()
        (self.cargo / "credentials.toml").write_text("token = 'secret'\n")
        output = self.root / "credential-rejected"
        with self.assertRaisesRegex(ValueError, "cargo_credentials_forbidden"):
            staging.stage(self.source, output)
        self.assertFalse((output / "receipt.json").exists())
        self.assertEqual(self.bounded_calls, [])
        (self.cargo / "credentials.toml").unlink()
        with self.assertRaisesRegex(ValueError, "paths_overlap"):
            staging.stage(self.source, self.source / "nested-output")

    def test_protected_cache_and_output_ancestors_reject_symlinks_before_commands(self):
        self.setup_stage()
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with patch.dict(os.environ, {"CARGO_HOME": str(alias / "cargo")}):
            with self.assertRaisesRegex(ValueError, "tart_not_executable|unsafe_tart_path"):
                staging.stage(self.source, self.root / "cache-alias")
        output_alias = self.root / "output-alias"
        output_alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "tart_not_executable|unsafe_tart_path"):
            staging.stage(self.source, output_alias / "prepared")
        self.assertEqual(self.bounded_calls, [])

    def test_unreviewed_cache_configuration_rejects_before_output_and_commands(self):
        self.setup_stage()
        (self.cargo / "config.toml").write_text("[net]\noffline = false\n")
        output = self.root / "cache-config"
        with self.assertRaisesRegex(ValueError, "unreviewed_cargo_home_configuration"):
            staging.stage(self.source, output)
        self.assertFalse(output.exists())
        self.assertEqual(self.bounded_calls, [])

    def test_source_ancestor_config_rejection_stops_before_cargo(self):
        self.setup_stage(malicious_config=True)
        output = self.root / "config-rejected"
        with self.assertRaisesRegex(ValueError, "unreviewed_cargo_configuration"):
            staging.stage(self.source, output)
        self.assertFalse((output / "receipt.json").exists())
        self.assertEqual(len(self.bounded_calls), 1)
        self.assertIn("--source", self.bounded_calls[0][0])
        self.assertFalse(any("metadata" in item[0] or "fetch" in item[0]
                             for item in self.bounded_calls))

    def test_unexpected_receipt_created_at_finalizer_is_preserved(self):
        self.setup_stage()
        output = self.root / "receipt-race"
        target = output / "receipt.json"
        writer = builder._write_new

        def race(path, contents, mode=None):
            target.write_text("owned by another process\n")
            return writer(path, contents, mode)

        with patch.object(builder, "_write_new", side_effect=race):
            with self.assertRaisesRegex(ValueError, "native_output_must_be_new"):
                staging.stage(self.source, output)
        self.assertEqual(target.read_text(), "owned by another process\n")


if __name__ == "__main__":
    unittest.main()
