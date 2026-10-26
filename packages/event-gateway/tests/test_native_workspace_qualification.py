import hashlib
import io
import json
import os
import subprocess  # nosec B404 - only the absolute Git executable in private fixtures.
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import native_workspace_qualification as qualification  # noqa: E402


class PinnedV8InputsTest(unittest.TestCase):
    def test_registry_returns_the_fixed_default_source_recipe(self):
        self.assertTrue(Path(qualification.GIT).is_absolute())
        evidence = qualification.builder.registry.validate_recipe("core-idle-v1", 1)
        self.assertEqual(evidence.recipe.family, "core-idle-v1")
        self.assertEqual(evidence.recipe.revision, 1)
        self.assertEqual(evidence.recipe.file_count, 57)
        self.assertEqual(len(evidence.recipe.ordered_patches), 1)
        self.assertEqual(len(evidence.file_sha256), 57)

    def test_reads_only_the_pinned_archive_binding_pair(self):
        module = '''
http_file(
    name = "rusty_v8_150_4_0_aarch64_apple_darwin_archive",
    downloaded_file_path = "librusty_v8_ptrcomp_sandbox_release_aarch64-apple-darwin.a.gz",
    sha256 = "00adbb48798848c77550441c68673a5e8529b8e1b73eabcdee232cb39b40f4a1",
    urls = ["https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/librusty_v8_ptrcomp_sandbox_release_aarch64-apple-darwin.a.gz"],
)
http_file(
    name = "rusty_v8_150_4_0_aarch64_apple_darwin_binding",
    downloaded_file_path = "src_binding_ptrcomp_sandbox_release_aarch64-apple-darwin.rs",
    sha256 = "ca5adf0cf89c9a70ad460ae73648b2fe89b74aa113b3cb7f757b6a02b758394f",
    urls = ["https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/src_binding_ptrcomp_sandbox_release_aarch64-apple-darwin.rs"],
)
'''
        assets = qualification.pinned_v8_assets(module)
        self.assertEqual(set(assets), set(qualification.V8_ASSETS))
        self.assertEqual(assets["rusty_v8_150_4_0_aarch64_apple_darwin_archive"]["sha256"],
                         "00adbb48798848c77550441c68673a5e8529b8e1b73eabcdee232cb39b40f4a1")
        self.assertEqual(assets["rusty_v8_150_4_0_aarch64_apple_darwin_binding"]["sha256"],
                         "ca5adf0cf89c9a70ad460ae73648b2fe89b74aa113b3cb7f757b6a02b758394f")
        self.assertTrue(all(asset["url"].startswith("https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/")
                            for asset in assets.values()))
        with self.assertRaisesRegex(ValueError, "pinned_rusty_v8_archive_digest_changed"):
            qualification.pinned_v8_assets(module.replace("00adbb", "11adbb"))

    def test_named_v8_pins_survive_reordered_mapping(self):
        module = '''
http_file(
    name = "rusty_v8_150_4_0_aarch64_apple_darwin_archive",
    downloaded_file_path = "librusty_v8_ptrcomp_sandbox_release_aarch64-apple-darwin.a.gz",
    sha256 = "00adbb48798848c77550441c68673a5e8529b8e1b73eabcdee232cb39b40f4a1",
    urls = ["https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/librusty_v8_ptrcomp_sandbox_release_aarch64-apple-darwin.a.gz"],
)
http_file(
    name = "rusty_v8_150_4_0_aarch64_apple_darwin_binding",
    downloaded_file_path = "src_binding_ptrcomp_sandbox_release_aarch64-apple-darwin.rs",
    sha256 = "ca5adf0cf89c9a70ad460ae73648b2fe89b74aa113b3cb7f757b6a02b758394f",
    urls = ["https://github.com/openai/codex/releases/download/rusty-v8-v150.4.0/src_binding_ptrcomp_sandbox_release_aarch64-apple-darwin.rs"],
)
'''
        with patch.dict(qualification.__dict__, {"V8_ASSETS": dict(reversed(list(qualification.V8_ASSETS.items())))}):
            self.assertEqual(set(qualification.pinned_v8_assets(module)), set(qualification.V8_ASSETS))

    def test_download_hash_accepts_pinned_bytes_and_rejects_corruption(self):
        body = b"pinned archive fixture"
        digest = hashlib.sha256(body).hexdigest()
        qualification.verify_downloaded_asset(body, digest)
        with self.assertRaisesRegex(ValueError, "rusty_v8_asset_digest_mismatch"):
            qualification.verify_downloaded_asset(body + b"corrupt", digest)

    def test_response_read_is_bounded_and_rejects_one_byte_over_limit(self):
        self.assertEqual(qualification.MAX_ASSET_BYTES, 32 * 1024 * 1024)

        class Response:
            def __init__(self, body):
                self.body = body

            def read(self, size):
                self.size = size
                return self.body[:size]

        with patch.object(qualification, "MAX_ASSET_BYTES", 8):
            accepted = Response(b"12345678")
            self.assertEqual(qualification.read_downloaded_asset(accepted), b"12345678")
            self.assertEqual(accepted.size, 9)
            oversize = Response(b"123456789")
            with self.assertRaisesRegex(ValueError, "rusty_v8_asset_too_large"):
                qualification.read_downloaded_asset(oversize)
            self.assertEqual(oversize.size, 9)


class PreparePipelineTest(unittest.TestCase):
    def git(self, *args, **kwargs):
        # Fixed argv in an owned private fixture; no shell or external inputs.
        return subprocess.run([qualification.GIT, *args], cwd=self.source, check=True,  # nosec B603
                              **kwargs)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "upstream"
        self.source.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        (self.source / "MODULE.bazel").write_text('module(name = "fixture")\n')
        (self.source / "codex-rs").mkdir()
        (self.source / "codex-rs/Cargo.lock").write_text("fixture lock\n")
        self.git("add", ".")
        self.git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture")
        self.commit = self.git("rev-parse", "HEAD", text=True,
                               capture_output=True).stdout.strip()
        self.archive = b"archive bytes"
        self.binding = b"binding bytes"
        self.assets = {
            "rusty_v8_150_4_0_aarch64_apple_darwin_archive": {
                "url": "https://fixtures.invalid/archive", "sha256": hashlib.sha256(self.archive).hexdigest()},
            "rusty_v8_150_4_0_aarch64_apple_darwin_binding": {
                "url": "https://fixtures.invalid/binding", "sha256": hashlib.sha256(self.binding).hexdigest()},
        }
        self.recipe = SimpleNamespace(family="core-idle-v1", revision=1,
                                      manifest=SimpleNamespace(sha256="a" * 64), ordered_patches=())

    def run_prepare(self, output, responses=None, assets=None):
        sequence = responses or [self.archive, self.binding]
        validate_recipe = patch.object(qualification.builder.registry, "validate_recipe",
                                       return_value=SimpleNamespace(recipe=self.recipe))
        with (patch.object(qualification, "UPSTREAM", self.commit),
              validate_recipe as validate,
              patch.object(qualification.builder, "verify_recipe_source",
                           return_value=(57, "b" * 64)),
              patch.object(qualification, "pinned_v8_assets", return_value=assets or self.assets),
              patch.object(qualification.urllib.request, "urlopen",
                           side_effect=[io.BytesIO(item) for item in sequence])):
            receipt = qualification.prepare(self.source, output)
            self.assertEqual(validate.call_args_list, [call("core-idle-v1", 1)])
            return receipt

    def test_prepare_records_source_and_both_verified_assets_and_rejects_existing_output(self):
        output = self.root / "prepared"
        receipt = self.run_prepare(output)
        self.assertEqual(receipt["patchedFileCount"], 57)
        self.assertEqual(receipt["v8Assets"]["rusty_v8_150_4_0_aarch64_apple_darwin_archive"]["downloadedSha256"],
                         self.assets["rusty_v8_150_4_0_aarch64_apple_darwin_archive"]["sha256"])
        self.assertEqual(json.loads((output / "qualification.json").read_text()), receipt)
        with self.assertRaises(FileExistsError):
            self.run_prepare(output)

    def test_prepare_rejects_corrupt_asset_without_receipt(self):
        output = self.root / "corrupt"
        with self.assertRaisesRegex(ValueError, "rusty_v8_asset_digest_mismatch"):
            self.run_prepare(output, [self.archive + b"corrupt", self.binding])
        self.assertFalse((output / "qualification.json").exists())

    def test_prepare_keeps_named_asset_destinations_when_pins_are_reordered(self):
        assets = dict(reversed(list(self.assets.items())))
        output = self.root / "reordered"
        self.run_prepare(output, [self.binding, self.archive], assets)
        self.assertEqual((output / "rusty-v8.a.gz").read_bytes(), self.archive)
        self.assertEqual((output / "rusty-v8-binding.rs").read_bytes(), self.binding)

    def test_git_calls_use_isolated_environment_despite_hostile_global_config(self):
        hostile_attributes = self.root / "hostile.attributes"
        hostile_attributes.write_text("* export-ignore\n")
        hostile_config = self.root / "hostile.gitconfig"
        hostile_config.write_text(f"[core]\n attributesFile = {hostile_attributes}\n")
        output = self.root / "isolated-git"
        git_envs = []
        original_run = subprocess.run

        def capture_git_environment(argv, **kwargs):
            if argv and argv[0] == qualification.GIT:
                git_envs.append(kwargs.get("env"))
            return original_run(argv, **kwargs)

        with (patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(hostile_config)}),
              patch.object(qualification.subprocess, "run", side_effect=capture_git_environment)):
            self.run_prepare(output)
        self.assertTrue((output / "MODULE.bazel").exists())
        # The source archive contains files despite a hostile global attributes file.
        self.assertTrue((output / "codex-rs/Cargo.lock").exists())
        self.assertGreaterEqual(len(git_envs), 2)
        for env in git_envs:
            self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")

    def test_prepare_rejects_non_pinned_checkout_before_creating_output(self):
        output = self.root / "wrong-upstream"
        self.assertNotEqual(self.commit, qualification.UPSTREAM)
        with self.assertRaisesRegex(ValueError,
                                    "native_source_checkout_must_be_exact_pinned_commit"):
            qualification.prepare(self.source, output)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
