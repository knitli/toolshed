import copy
from contextlib import redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess  # nosec B404 - fixed Git executable and disposable repo fixture, no shell
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from event_gateway import launcher


PACKAGER = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts/package_native_client.py")
)
PACKAGER_GLOBALS = PACKAGER["package"].__globals__


class NativePackagingTests(unittest.TestCase):
    def test_archive_ignores_git_replacement_refs_for_checkout_and_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "checkout"
            checkout.mkdir()
            env = {
                "PATH": os.environ.get("PATH", os.defpath),
                "HOME": str(root),
                "TMPDIR": str(root),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
            }
            git_executable = PACKAGER["_git_executable"](env)

            def git(*args):
                return subprocess.run(  # nosec B603 - fixed Git executable and literal fixture arguments
                    [str(git_executable), *args], cwd=checkout, env=env, check=True,
                    stdout=subprocess.PIPE, text=True,
                ).stdout.strip()

            subprocess.run(  # nosec B603 - fixed Git executable initializes this disposable repository
                [str(git_executable), "init", "--quiet"], cwd=checkout, env=env, check=True,
            )
            (checkout / "codex-rs").mkdir()
            generated = checkout / "sdk/python/src/openai_codex/generated"
            generated.mkdir(parents=True)
            outside = checkout / "outside"
            outside.mkdir()
            tracked = checkout / "codex-rs/unpatched.rs"
            tracked.write_bytes(b"pinned source")
            (generated / "model.py").write_bytes(b"pinned generated source")
            (checkout / "README.md").write_bytes(b"pinned root file")
            (outside / "ordinary.txt").write_bytes(b"pinned outside file")
            (checkout / ".cargo").mkdir()
            (checkout / ".cargo/config.toml").write_bytes(b"pinned root cargo config")
            git("config", "user.name", "Native packaging test")
            git("config", "user.email", "native-packaging@example.invalid")
            git("add", ".")
            git("commit", "--quiet", "-m", "pinned source")
            pinned = git("rev-parse", "HEAD")

            tracked.write_bytes(b"replacement source")
            git("commit", "--quiet", "-am", "replacement source")
            replacement = git("rev-parse", "HEAD")
            git("checkout", "--quiet", pinned)
            git("replace", pinned, replacement)

            default_archive = subprocess.run(  # nosec B603 - fixed executable and fixture-owned commit
                [str(git_executable), "archive", "--format=tar", pinned],
                cwd=checkout, env=env, check=True, stdout=subprocess.PIPE,
            ).stdout
            with tarfile.open(fileobj=io.BytesIO(default_archive), mode="r:") as archive:
                self.assertEqual(
                    archive.extractfile("codex-rs/unpatched.rs").read(), b"replacement source"
                )
                self.assertEqual(archive.extractfile("README.md").read(), b"pinned root file")
                self.assertEqual(
                    archive.extractfile("outside/ordinary.txt").read(), b"pinned outside file"
                )
                self.assertEqual(
                    archive.extractfile(".cargo/config.toml").read(), b"pinned root cargo config"
                )

            hostile_env = {
                **env,
                "GIT_DIR": str(root / "wrong-git-dir"),
                "GIT_WORK_TREE": str(root),
                "GIT_COMMON_DIR": str(root),
                "GIT_INDEX_FILE": str(root / "wrong-index"),
                "GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "core.worktree",
                "GIT_CONFIG_VALUE_0": str(root),
                "GIT_NO_REPLACE_OBJECTS": "0",
                "GIT_ATTR_NOSYSTEM": "0",
            }
            destination = root / "archive"
            destination.mkdir()
            with patch.dict(PACKAGER_GLOBALS, {"UPSTREAM_COMMIT": pinned}):
                self.assertEqual(
                    PACKAGER["_clean_checkout"](checkout, hostile_env), checkout.resolve()
                )
                PACKAGER["_archive_source"](checkout, destination, hostile_env)

            def assert_pinned_archive_source(archive_path):
                self.assertEqual(
                    (archive_path / "codex-rs/unpatched.rs").read_bytes(), b"pinned source"
                )
                self.assertEqual((archive_path / "README.md").read_bytes(), b"pinned root file")
                self.assertEqual(
                    (archive_path / "outside/ordinary.txt").read_bytes(), b"pinned outside file"
                )
                self.assertEqual(
                    (archive_path / ".cargo/config.toml").read_bytes(), b"pinned root cargo config"
                )

            assert_pinned_archive_source(destination)
            self.assertEqual(tracked.read_bytes(), b"pinned source")
            self.assertEqual(
                (destination / "sdk/python/src/openai_codex/generated/model.py").read_bytes(),
                b"pinned generated source",
            )

            original_git_environment = PACKAGER["_git_environment"]

            def git_environment_with_archive_replacements(env):
                selected = original_git_environment(env)
                selected.pop("GIT_NO_REPLACE_OBJECTS", None)
                return selected

            unprotected_destination = root / "archive-with-replacements"
            unprotected_destination.mkdir()
            with patch.dict(PACKAGER_GLOBALS, {
                "UPSTREAM_COMMIT": pinned,
                "_git_environment": git_environment_with_archive_replacements,
            }):
                PACKAGER["_archive_source"](checkout, unprotected_destination, hostile_env)
            with self.assertRaises(AssertionError):
                assert_pinned_archive_source(unprotected_destination)
            self.assertEqual(
                (unprotected_destination / "codex-rs/unpatched.rs").read_bytes(),
                b"replacement source",
            )

            git("config", "--local", "core.attributesFile", str(root / "attributes"))
            with patch.dict(PACKAGER_GLOBALS, {"UPSTREAM_COMMIT": pinned}):
                with self.assertRaisesRegex(ValueError, "unreviewed_git_attributes"):
                    PACKAGER["_clean_checkout"](checkout, hostile_env)
            git("config", "--local", "--unset", "core.attributesFile")

            included_attributes = root / "included-git-config"
            included_attributes.write_text(
                f"[core]\n\tattributesFile = {root / 'attributes'}\n"
            )
            git("config", "--local", "include.path", str(included_attributes))
            with patch.dict(PACKAGER_GLOBALS, {"UPSTREAM_COMMIT": pinned}):
                with self.assertRaisesRegex(ValueError, "unreviewed_git_attributes"):
                    PACKAGER["_clean_checkout"](checkout, hostile_env)
            git("config", "--local", "--unset", "include.path")

            info_attributes = Path(git("rev-parse", "--git-path", "info/attributes"))
            if not info_attributes.is_absolute():
                info_attributes = checkout / info_attributes
            info_attributes.parent.mkdir(parents=True, exist_ok=True)
            info_attributes.write_text("codex-rs/unpatched.rs export-ignore\n")
            with patch.dict(PACKAGER_GLOBALS, {"UPSTREAM_COMMIT": pinned}):
                with self.assertRaisesRegex(ValueError, "unreviewed_git_attributes"):
                    PACKAGER["_clean_checkout"](checkout, hostile_env)

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

    def test_package_rechecks_source_before_publication_and_preserves_raced_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "checkout"
            source.mkdir()
            state = {
                "scenario": "success", "build_completed": False, "copies": [], "evidence": None,
            }

            def archive_source(_checkout, work, _env, _git):
                codex_rs = work / "codex-rs"
                codex_rs.mkdir()
                (codex_rs / "Cargo.lock").write_text("version = 4\n")

            def run(command, *, cwd, **_kwargs):
                if "apply" in command:
                    pass
                elif "metadata" in command:
                    return subprocess.CompletedProcess(
                        command, 0,
                        stdout=json.dumps({"target_directory": str(Path(cwd) / "target")}),
                    )
                elif "build" in command:
                    state["build_completed"] = True
                    binary = Path(cwd) / "target/dev-small/codex"
                    binary.parent.mkdir(parents=True, exist_ok=True)
                    binary.write_bytes(b"mock native CLI")
                    if state["scenario"] == "race":
                        state["evidence"].write_bytes(b"created during build")
                else:
                    self.fail(f"unexpected mocked build command: {command}")
                return subprocess.CompletedProcess(command, 0)

            def verify_source(_work, _manifest):
                digest = "b" * 64 if (
                    state["scenario"] == "drift" and state["build_completed"]
                ) else "a" * 64
                return PACKAGER["PATCHED_FILE_COUNT"], digest

            original_copy = PACKAGER["_copy_new"]

            def copy_candidate(binary, destination):
                state["copies"].append(destination)
                return original_copy(binary, destination)

            replacements = {
                "_binary_evidence": lambda _path: {"path": str(root / "git"), "sha256": "0" * 64},
                "_clean_checkout": lambda path, _env, _git: path.resolve(strict=True),
                "_archive_source": archive_source,
                "_run": run,
                "_toolchain": lambda _env: (
                    ["rustup", "run", "1.95.0"], "mock rustc", "mock cargo",
                    {"rustup": {"path": str(root / "mock-rustup"), "sha256": "1" * 64}},
                ),
                "_cargo_configuration": lambda *_args: {
                    "cargoHome": str(root / "cargo-cache"), "cargoHomeConfig": None,
                    "ancestorConfigs": [
                        {
                            "path": "codex-rs/.cargo/config.toml",
                            "sha256": PACKAGER["PINNED_CARGO_CONFIG_SHA256"],
                        },
                        {
                            "path": ".cargo/config.toml",
                            "sha256": PACKAGER["PINNED_SOURCE_ROOT_CARGO_CONFIG_SHA256"],
                        },
                    ],
                },
                "verify_patched_source": verify_source,
                "lock_version_changes": lambda *_args: 159,
                "_copy_new": copy_candidate,
            }

            output = root / "candidate"
            evidence_path = root / "candidate.json"
            state["evidence"] = evidence_path
            with patch.dict(PACKAGER_GLOBALS, replacements), patch("builtins.print"):
                evidence = PACKAGER["package"](source, output, evidence_path)
                self.assertEqual(evidence["archiveScope"], {
                    "selection": "git archive of the pinned commit without pathspecs",
                    "extractionFilter": "tarfile.data_filter",
                })
                self.assertEqual(
                    evidence["patchedSourceInventoryBeforeBuildSha256"],
                    evidence["patchedSourceInventoryAfterBuildSha256"],
                )
                self.assertEqual(output.read_bytes(), b"mock native CLI")
                self.assertEqual(json.loads(evidence_path.read_text()), evidence)
                self.assertEqual(
                    evidence["binarySha256"], hashlib.sha256(output.read_bytes()).hexdigest()
                )

                drift_output = root / "drifted-candidate"
                drift_evidence = root / "drifted-candidate.json"
                state.update(
                    scenario="drift", build_completed=False, copies=[], evidence=drift_evidence,
                )
                stderr = io.StringIO()
                with redirect_stderr(stderr), self.assertRaises(SystemExit) as failure:
                    PACKAGER["main"]([
                        "--source", str(source), "--output", str(drift_output),
                        "--evidence", str(drift_evidence),
                    ])
                self.assertEqual(failure.exception.code, 2)
                self.assertIn("native_patched_source_changed_during_build", stderr.getvalue())
                self.assertEqual(state["copies"], [])
                self.assertFalse(drift_output.exists())
                self.assertFalse(drift_evidence.exists())

                raced_output = root / "raced-candidate"
                raced_evidence = root / "raced-candidate.json"
                state.update(
                    scenario="race", build_completed=False, copies=[], evidence=raced_evidence,
                )
                with self.assertRaisesRegex(ValueError, "native_output_must_be_new"):
                    PACKAGER["package"](source, raced_output, raced_evidence)
                self.assertFalse(raced_output.exists())
                self.assertEqual(raced_evidence.read_bytes(), b"created during build")

    def test_build_env_strips_ambient_build_overrides_and_keeps_selected_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "build"
            work.mkdir()
            cargo_home = root / "selected-cargo-cache"
            rustup_home = root / "selected-rustup-home"
            with patch.dict(os.environ, {
                "HOME": str(root / "user-home"),
                "PATH": "/usr/bin:/bin",
                "CARGO_HOME": str(cargo_home),
                "RUSTUP_HOME": str(rustup_home),
                "CARGO_PROFILE_DEV_SMALL_OPT_LEVEL": "0",
                "CARGO_PROFILE_RELEASE_LTO": "false",
                "CARGO_BUILD_RUSTC_WRAPPER": str(root / "unused-cargo-wrapper"),
                "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER": str(root / "unused-linker"),
                "CARGO_ENCODED_RUSTFLAGS": "-C link-arg=unreviewed",
                "CARGO_BUILD_TARGET": "unreviewed-target",
                "RUSTC": str(root / "unused-rustc"),
                "RUSTDOC": str(root / "unused-rustdoc"),
                "RUSTC_WRAPPER": str(root / "unused-rustc-wrapper"),
                "RUSTFLAGS": "-C opt-level=0",
                "RUSTDOCFLAGS": "--cfg unreviewed",
                "RUSTUP_TOOLCHAIN": "stable",
            }, clear=True):
                env = PACKAGER["_build_env"](work)

            self.assertEqual(env["CARGO_HOME"], str(cargo_home.resolve()))
            self.assertEqual(env["RUSTUP_HOME"], str(rustup_home.resolve()))
            self.assertEqual(env["RUSTUP_TOOLCHAIN"], PACKAGER["RUSTUP_TOOLCHAIN"])
            self.assertEqual(env["CARGO_NET_OFFLINE"], "true")
            self.assertEqual(env["CARGO_INCREMENTAL"], "0")
            self.assertEqual(env["PATH"], "/usr/bin:/bin")
            self.assertEqual(set(env), {
                "PATH", "HOME", "TMPDIR", "CARGO_HOME", "RUSTUP_HOME",
                "RUSTUP_TOOLCHAIN", "CARGO_NET_OFFLINE", "CARGO_INCREMENTAL", "LC_ALL",
            })

    def test_rustup_discovery_skips_command_manager_shim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shim = root / "shim"
            actual = root / "actual"
            shim.mkdir()
            actual.mkdir()
            manager = actual / "mise"
            manager.write_bytes(b"manager shim target")
            manager.chmod(0o755)
            rustup = actual / "rustup"
            rustup.write_bytes(b"actual rustup")
            rustup.chmod(0o755)
            (shim / "rustup").symlink_to(manager)
            (actual / "rustup").chmod(0o755)

            self.assertEqual(
                PACKAGER["_rustup_executable"]({"PATH": f"{shim}{os.pathsep}{actual}"}),
                rustup.resolve(),
            )

    def test_cargo_configuration_accepts_only_pinned_file_and_rejects_home_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            root = parent / "source"
            codex_rs = root / "codex-rs"
            cargo_config_dir = codex_rs / ".cargo"
            cargo_config_dir.mkdir(parents=True)
            cargo_home = parent / "cargo-home"
            cargo_home.mkdir()
            config = cargo_config_dir / "config.toml"
            config_bytes = b"[target]\n"
            config.write_bytes(config_bytes)
            digest = hashlib.sha256(config_bytes).hexdigest()
            source_config_dir = root / ".cargo"
            source_config_dir.mkdir()
            source_config = source_config_dir / "config.toml"
            source_config_bytes = b"[env]\nMALLOC_CONF = { value = 'thp:always', force = false }\n"
            source_config.write_bytes(source_config_bytes)
            source_digest = hashlib.sha256(source_config_bytes).hexdigest()

            with patch.dict(PACKAGER_GLOBALS, {
                "PINNED_CARGO_CONFIG_SHA256": digest,
                "PINNED_SOURCE_ROOT_CARGO_CONFIG_SHA256": source_digest,
            }):
                configuration = PACKAGER["_cargo_configuration"](codex_rs, cargo_home)
                self.assertEqual(configuration["cargoHome"], str(cargo_home.resolve()))
                self.assertEqual(configuration["cargoHomeConfig"], None)
                self.assertEqual(configuration["ancestorConfigs"], [{
                    "path": "codex-rs/.cargo/config.toml", "sha256": digest,
                }, {
                    "path": ".cargo/config.toml", "sha256": source_digest,
                }])

                source_config.unlink()
                with self.assertRaisesRegex(ValueError, "pinned_cargo_configuration_missing"):
                    PACKAGER["_cargo_configuration"](codex_rs, cargo_home)
                source_config.write_bytes(source_config_bytes)

                source_config.write_bytes(b"modified pinned root config")
                with self.assertRaisesRegex(ValueError, "unreviewed_cargo_configuration"):
                    PACKAGER["_cargo_configuration"](codex_rs, cargo_home)
                source_config.write_bytes(source_config_bytes)

                home_config = cargo_home / "config.toml"
                home_config.write_text("[build]\nrustflags = ['-C', 'opt-level=0']\n")
                with self.assertRaisesRegex(ValueError, "unreviewed_cargo_home_configuration"):
                    PACKAGER["_cargo_configuration"](codex_rs, cargo_home)
                home_config.unlink()

                ancestor_config_dir = parent / ".cargo"
                ancestor_config_dir.mkdir()
                pinned_bytes_at_unapproved_location = ancestor_config_dir / "config.toml"
                pinned_bytes_at_unapproved_location.write_bytes(source_config_bytes)
                with self.assertRaisesRegex(ValueError, "unreviewed_cargo_configuration"):
                    PACKAGER["_cargo_configuration"](codex_rs, cargo_home)
                pinned_bytes_at_unapproved_location.unlink()

                ancestor_config = ancestor_config_dir / "config"
                ancestor_config.write_text("[build]\nrustc-wrapper = 'wrapper'\n")
                with self.assertRaisesRegex(ValueError, "unreviewed_cargo_configuration"):
                    PACKAGER["_cargo_configuration"](codex_rs, cargo_home)
                ancestor_config.unlink()

                config.write_bytes(b"changed pinned config")
                with self.assertRaisesRegex(ValueError, "unreviewed_cargo_configuration"):
                    PACKAGER["_cargo_configuration"](codex_rs, cargo_home)

    def test_output_paths_reject_symlink_and_dotdot_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            (real / "subdir").mkdir(parents=True)
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "native_output_paths_must_differ"):
                PACKAGER["_resolve_output_pair"](
                    real / "candidate",
                    alias / "subdir/../candidate",
                )

    def test_evidence_failure_cleans_owned_candidate_and_preserves_raced_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"candidate")
            output = root / "codex"
            evidence = root / "evidence.json"
            other = root / "other-file"
            other.write_bytes(b"unrelated")
            identity = PACKAGER["_copy_new"](source, output)
            evidence.write_bytes(b"created by another process")

            with self.assertRaisesRegex(ValueError, "native_output_must_be_new"):
                PACKAGER["_write_evidence"](evidence, {"candidate": True}, output, identity)

            self.assertFalse(output.exists())
            self.assertEqual(evidence.read_bytes(), b"created by another process")
            self.assertEqual(other.read_bytes(), b"unrelated")

    def test_evidence_cleanup_permission_error_surfaces_and_preserves_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"candidate")
            output = root / "codex"
            evidence = root / "evidence.json"
            identity = PACKAGER["_copy_new"](source, output)

            def fail_evidence_write(*_args):
                raise ValueError("evidence write failed")

            with patch.dict(PACKAGER_GLOBALS, {"_write_new": fail_evidence_write}):
                with patch.object(Path, "unlink", side_effect=PermissionError("cleanup denied")):
                    with self.assertRaisesRegex(PermissionError, "cleanup denied"):
                        PACKAGER["_write_evidence"](
                            evidence, {"candidate": True}, output, identity
                        )

            self.assertEqual(output.read_bytes(), b"candidate")

    def test_evidence_failure_preserves_candidate_path_replaced_by_another_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"candidate")
            output = root / "codex"
            evidence = root / "evidence.json"
            replacement = root / "replacement"
            replacement.write_bytes(b"created by another process")
            identity = PACKAGER["_copy_new"](source, output)

            def replace_then_fail(_path, _contents):
                output.unlink()
                replacement.replace(output)
                raise ValueError("native_output_must_be_new_in_existing_directory")

            with patch.dict(PACKAGER_GLOBALS, {"_write_new": replace_then_fail}):
                with self.assertRaisesRegex(ValueError, "native_output_must_be_new"):
                    PACKAGER["_write_evidence"](evidence, {"candidate": True}, output, identity)

            self.assertEqual(output.read_bytes(), b"created by another process")

    def test_evidence_interruption_cleans_owned_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.write_bytes(b"candidate")
            output = root / "codex"
            evidence = root / "evidence.json"
            identity = PACKAGER["_copy_new"](source, output)

            def interrupt(*_args):
                raise KeyboardInterrupt

            with patch.dict(PACKAGER_GLOBALS, {"_write_new": interrupt}):
                with self.assertRaises(KeyboardInterrupt):
                    PACKAGER["_write_evidence"](evidence, {"candidate": True}, output, identity)

            self.assertFalse(output.exists())

    def test_write_new_failure_does_not_unlink_replacement_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "evidence.json"
            replacement = root / "replacement"
            replacement.write_bytes(b"created by another process")

            def replace_before_failure(_fd, _mode):
                output.unlink()
                replacement.replace(output)
                raise PermissionError("synthetic chmod failure")

            with patch("os.fchmod", new=replace_before_failure):
                with self.assertRaisesRegex(PermissionError, "synthetic chmod failure"):
                    PACKAGER["_write_new"](output, b"ours", mode=0o600)

            self.assertEqual(output.read_bytes(), b"created by another process")

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
