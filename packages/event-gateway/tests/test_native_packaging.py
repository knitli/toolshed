import copy
from contextlib import redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shlex
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
    def test_host_pins_match_launcher_and_official_release(self):
        self.assertEqual(PACKAGER["CODE_MODE_HOST_SHA256"], launcher.QUALIFIED_CODE_MODE_HOST_SHA256)
        self.assertEqual(PACKAGER["CODE_MODE_HOST_ARCHIVE_SHA256"],
                         "dc70fbc76e9dcae5ae3d5424808c8e7c2df5e0db4ac827ddd4fbe339015aad75")
        self.assertEqual(PACKAGER["CODE_MODE_HOST_RELEASE_TAG"], "rust-v0.160.0")
        self.assertEqual(PACKAGER["UPSTREAM_COMMIT"], "a956835d020762cb2b570053af06f643a11c0ecc")
        self.assertEqual(PACKAGER["HOST_TRIPLE"], "aarch64-apple-darwin")

    def test_host_archive_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "host.tar.gz"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "native_code_mode_host_archive_must_be_regular"):
                PACKAGER["_verified_code_mode_host"](fifo)

    def test_host_archive_verifies_pins_and_rejects_unsafe_members(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "host.tar.gz"
            payload = b"host fixture"
            member_name = PACKAGER["CODE_MODE_HOST_MEMBER"]
            for scenario in ("valid", "wrong_archive", "wrong_host", "traversal", "absolute",
                             "symlink", "hardlink", "directory", "duplicate", "extra", "size"):
                with self.subTest(scenario=scenario):
                    with tarfile.open(archive, "w:gz") as bundle:
                        name = {"traversal": "../" + member_name,
                                "absolute": "/" + member_name}.get(scenario, member_name)
                        member = tarfile.TarInfo(name)
                        member.size = len(payload)
                        member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                                       "directory": tarfile.DIRTYPE}.get(scenario, tarfile.REGTYPE)
                        member.linkname = "../outside"
                        bundle.addfile(member, io.BytesIO(payload) if member.isfile() else None)
                        if scenario in ("duplicate", "extra"):
                            member.name = member_name if scenario == "duplicate" else "../outside"
                            bundle.addfile(member, io.BytesIO(payload))
                    pins = {
                        "CODE_MODE_HOST_ARCHIVE_SHA256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                        "CODE_MODE_HOST_ARCHIVE_BYTES": archive.stat().st_size,
                        "CODE_MODE_HOST_SHA256": hashlib.sha256(payload).hexdigest(),
                        "CODE_MODE_HOST_BYTES": len(payload),
                    }
                    if scenario == "wrong_archive":
                        pins["CODE_MODE_HOST_ARCHIVE_SHA256"] = "0" * 64
                    if scenario == "wrong_host":
                        pins["CODE_MODE_HOST_SHA256"] = "0" * 64
                    if scenario == "size":
                        pins["CODE_MODE_HOST_BYTES"] += 1
                    with patch.dict(PACKAGER_GLOBALS, pins):
                        if scenario == "valid":
                            self.assertEqual(PACKAGER["_verified_code_mode_host"](archive), payload)
                        else:
                            with self.assertRaisesRegex(ValueError, "native_code_mode_host_"):
                                PACKAGER["_verified_code_mode_host"](archive)
                    self.assertEqual(list(Path(directory).iterdir()), [archive])

    def test_package_rejects_all_collisions_and_preexisting_outputs_before_build(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output, evidence, host = root / "codex", root / "evidence.json", root / "codex-code-mode-host"
            for existing in (output, evidence, host):
                with self.subTest(existing=existing):
                    existing.write_bytes(b"preexisting")
                    with self.assertRaisesRegex(ValueError, "native_output_must_be_new"):
                        PACKAGER["package"](root, output, evidence, root / "missing.tar.gz")
                    self.assertEqual(existing.read_bytes(), b"preexisting")
                    existing.unlink()
            for cli, record in ((output, output), (host, evidence), (output, host)):
                with self.assertRaisesRegex(ValueError, "native_output_paths_must_differ"):
                    PACKAGER["package"](root, cli, record, root / "missing.tar.gz")

    def test_host_write_failure_removes_partial_file_and_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "binary"
            binary.write_bytes(b"cli")
            output, host, evidence = root / "codex", root / "codex-code-mode-host", root / "evidence.json"
            original_chmod = os.fchmod

            def chmod(fd, mode):
                if host.exists() and os.fstat(fd).st_ino == host.stat().st_ino:
                    raise OSError("host chmod failure")
                original_chmod(fd, mode)
            with patch("os.fchmod", new=chmod):
                with self.assertRaisesRegex(OSError, "host chmod failure"):
                    PACKAGER["_publish_package"](binary, b"host", output, host, evidence, {})
            self.assertFalse(output.exists())
            self.assertFalse(host.exists())
            self.assertFalse(evidence.exists())

    def test_publication_failure_cleans_owned_outputs_and_preserves_replacements(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "binary"
            binary.write_bytes(b"cli")
            original_write = PACKAGER["_write_new"]
            for scenario in ("host_failure", "evidence_failure", "interrupt", "replacement"):
                with self.subTest(scenario=scenario):
                    run = root / scenario
                    run.mkdir()
                    output, host, evidence = run / "codex", run / "codex-code-mode-host", run / "evidence.json"
                    replacement = run / "replacement"
                    replacement.write_bytes(b"other process")

                    def write(path, contents, mode=None):
                        if path == host and scenario == "host_failure":
                            raise OSError("injected failure")
                        if path == evidence:
                            if scenario == "replacement":
                                replacement.replace(host)
                            if scenario == "interrupt":
                                raise KeyboardInterrupt
                            raise OSError("injected failure")
                        return original_write(path, contents, mode)
                    with patch.dict(PACKAGER_GLOBALS, {"_write_new": write}):
                        with self.assertRaises(KeyboardInterrupt if scenario == "interrupt" else OSError):
                            PACKAGER["_publish_package"](binary, b"host", output, host, evidence, {})
                    self.assertFalse(output.exists())
                    self.assertFalse(evidence.exists())
                    if scenario == "replacement":
                        self.assertEqual(host.read_bytes(), b"other process")
                    else:
                        self.assertFalse(host.exists())

    def test_rollback_attempts_every_output_when_one_unlink_is_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / name for name in ("codex", "codex-code-mode-host", "evidence.json")]
            owned = [(path, PACKAGER["_write_new"](path, b"ours")) for path in paths]
            original_unlink = Path.unlink

            def unlink(path, *args, **kwargs):
                if path == paths[1]:
                    raise PermissionError("cleanup denied")
                return original_unlink(path, *args, **kwargs)
            with patch.object(Path, "unlink", new=unlink):
                with self.assertRaisesRegex(PermissionError, "cleanup denied"):
                    PACKAGER["_cleanup_owned"](owned)
            self.assertFalse(paths[0].exists())
            self.assertEqual(paths[1].read_bytes(), b"ours")
            self.assertFalse(paths[2].exists())

    def test_checkout_and_archive_do_not_execute_local_git_configuration(self):
        for configuration in ("local", "included", "worktree"):
            for trigger in ("fsmonitor", "post-index-change", "clean-filter"):
                with self.subTest(configuration=configuration, trigger=trigger), \
                        tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    checkout = root / "checkout"
                    checkout.mkdir()
                    env = {
                        "PATH": os.environ.get("PATH", os.defpath), "HOME": str(root),
                        "TMPDIR": str(root), "GIT_CONFIG_NOSYSTEM": "1",
                        "GIT_CONFIG_GLOBAL": os.devnull,
                    }
                    executable = str(PACKAGER["_git_executable"](env))

                    def git(*args):
                        return subprocess.run(  # nosec B603 - fixed Git and disposable fixture
                            [executable, *args], cwd=checkout, env=env, check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                        ).stdout.strip()

                    git("init", "--quiet")
                    git("config", "user.name", "Native packaging test")
                    git("config", "user.email", "native-packaging@example.invalid")
                    tracked = checkout / "source.txt"
                    tracked.write_text("pinned source\n")
                    if trigger == "clean-filter":
                        (checkout / ".gitattributes").write_text("source.txt filter=fixture\n")
                    git("add", ".")
                    git("commit", "--quiet", "-m", "pinned source")
                    pinned = git("rev-parse", "HEAD")
                    hooks = root / "hooks"
                    hooks.mkdir()
                    marker = root / "executed"
                    hook = hooks / trigger
                    hook.write_text(f"#!/bin/sh\nprintf ran > {shlex.quote(str(marker))}\n"
                                    + ("cat\n" if trigger == "clean-filter" else ""))
                    hook.chmod(0o755)
                    key = "core.fsmonitor" if trigger == "fsmonitor" else "core.hooksPath"
                    value = str(hook if trigger == "fsmonitor" else hooks)
                    if trigger == "clean-filter":
                        key, value = "filter.fixture.clean", str(hook)
                    if configuration == "included":
                        included = root / "included.config"
                        git("config", "--file", str(included), key, value)
                        git("config", "include.path", str(included))
                    elif configuration == "worktree":
                        git("config", "extensions.worktreeConfig", "true")
                        git("config", "--worktree", key, value)
                    else:
                        git("config", key, value)

                    def refresh_stat():
                        mtime = tracked.stat().st_mtime_ns + 1_000_000_000
                        os.utime(tracked, ns=(mtime, mtime))

                    refresh_stat()
                    self.assertEqual(git("status", "--porcelain=v1"), "")
                    self.assertTrue(marker.exists(), "unprotected Git must execute the fixture")
                    marker.unlink()
                    refresh_stat()
                    archive = root / "archive"
                    archive.mkdir()
                    with patch.dict(PACKAGER_GLOBALS, {"UPSTREAM_COMMIT": pinned}):
                        self.assertEqual(PACKAGER["_clean_checkout"](checkout, env), checkout.resolve())
                        self.assertFalse(marker.exists())
                        PACKAGER["_archive_source"](checkout, archive, env)
                        self.assertEqual((archive / "source.txt").read_bytes(), tracked.read_bytes())
                        (checkout / "untracked.txt").write_text("untracked\n")
                        with self.assertRaisesRegex(ValueError, "native_source_checkout_must_be_clean"):
                            PACKAGER["_clean_checkout"](checkout, env)
                        (checkout / "untracked.txt").unlink()
                        tracked.write_text("modified source\n")
                        with self.assertRaisesRegex(ValueError, "native_source_checkout_must_be_clean"):
                            PACKAGER["_clean_checkout"](checkout, env)
                    self.assertFalse(marker.exists())

    def test_checkout_preserves_normalization_and_rejects_staged_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            checkout = Path(directory)
            env = {"PATH": os.defpath, "HOME": directory, "TMPDIR": directory,
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
            executable = str(PACKAGER["_git_executable"](env))

            def git(*args):
                return subprocess.run(  # nosec B603 - fixed Git and disposable fixture
                    [executable, *args], cwd=checkout, env=env, check=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                ).stdout.strip()

            git("init", "--quiet")
            git("config", "user.name", "Native packaging test")
            git("config", "user.email", "native-packaging@example.invalid")
            tracked = checkout / "source.txt"
            tracked.write_text("pinned source\n")
            git("add", ".")
            git("commit", "--quiet", "-m", "pinned source")
            pinned = git("rev-parse", "HEAD")
            git("update-index", "--skip-worktree", "source.txt")
            tracked.write_text("modified source\n")
            with patch.dict(PACKAGER_GLOBALS, {"UPSTREAM_COMMIT": pinned}):
                with self.assertRaisesRegex(ValueError, "native_source_checkout_must_be_clean"):
                    PACKAGER["_clean_checkout"](checkout, env)
            git("update-index", "--no-skip-worktree", "source.txt")
            tracked.write_text("pinned source\n")
            git("config", "core.autocrlf", "true")
            tracked.unlink()
            git("checkout", "--", "source.txt")
            self.assertEqual(tracked.read_bytes(), b"pinned source\r\n")
            self.assertEqual(git("status", "--porcelain=v1"), "")
            with tempfile.TemporaryDirectory() as archive_directory, \
                    patch.dict(PACKAGER_GLOBALS, {"UPSTREAM_COMMIT": pinned}):
                archive = Path(archive_directory)
                self.assertEqual(PACKAGER["_clean_checkout"](checkout, env), checkout.resolve())
                PACKAGER["_archive_source"](checkout, archive, env)
                self.assertEqual((archive / "source.txt").read_bytes(), b"pinned source\r\n")
            git("config", "core.autocrlf", "false")
            tracked.write_text("staged source\n")
            git("add", ".")
            tracked.write_text("pinned source\n")
            with patch.dict(PACKAGER_GLOBALS, {"UPSTREAM_COMMIT": pinned}):
                with self.assertRaisesRegex(ValueError, "native_source_checkout_must_be_clean"):
                    PACKAGER["_clean_checkout"](checkout, env)

    def test_sparse_checkout_preserves_omissions_and_archives_the_complete_pin(self):
        for mode in ("non-cone", "cone", "sparse-index"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                checkout = root / "checkout"
                checkout.mkdir()
                env = {"PATH": os.defpath, "HOME": directory, "TMPDIR": directory,
                       "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
                executable = str(PACKAGER["_git_executable"](env))

                def git(*args):
                    return subprocess.run(  # nosec B603 - fixed Git and disposable fixture
                        [executable, *args], cwd=checkout, env=env, check=True,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    ).stdout.strip()

                git("init", "--quiet")
                git("config", "user.name", "Native packaging test")
                git("config", "user.email", "native-packaging@example.invalid")
                names = ("selected/source.txt", "omitted/source.txt", "omitted/space and\nnewline.txt")
                for name in names:
                    file = checkout / name
                    file.parent.mkdir(exist_ok=True)
                    file.write_text("pinned source\n")
                git("add", ".")
                git("commit", "--quiet", "-m", "pinned source")
                pinned = git("rev-parse", "HEAD")
                arguments = ["sparse-checkout", "init", "--no-cone" if mode == "non-cone" else "--cone"]
                if mode == "sparse-index":
                    arguments.append("--sparse-index")
                git(*arguments)
                git("sparse-checkout", "set", "selected")
                self.assertFalse((checkout / "omitted/source.txt").exists())
                self.assertEqual(git("status", "--porcelain=v1"), "")
                source_index = (checkout / ".git/index").read_bytes()
                with patch.dict(PACKAGER_GLOBALS, {"UPSTREAM_COMMIT": pinned}):
                    self.assertEqual(PACKAGER["_clean_checkout"](checkout, env), checkout.resolve())
                    self.assertEqual((checkout / ".git/index").read_bytes(), source_index)
                    archive = root / "archive"
                    archive.mkdir()
                    PACKAGER["_archive_source"](checkout, archive, env)
                    for name in names:
                        self.assertEqual((archive / name).read_bytes(), b"pinned source\n")
                    (checkout / "untracked.txt").write_text("untracked\n")
                    with self.assertRaisesRegex(ValueError, "native_source_checkout_must_be_clean"):
                        PACKAGER["_clean_checkout"](checkout, env)
                    (checkout / "untracked.txt").unlink()
                    omitted = checkout / "omitted/source.txt"
                    omitted.parent.mkdir(exist_ok=True)
                    omitted.symlink_to(root / "missing")
                    with self.assertRaisesRegex(ValueError, "native_source_checkout_must_be_clean"):
                        PACKAGER["_clean_checkout"](checkout, env)
                    omitted.unlink()
                    (checkout / "selected/source.txt").write_text("modified source\n")
                    with self.assertRaisesRegex(ValueError, "native_source_checkout_must_be_clean"):
                        PACKAGER["_clean_checkout"](checkout, env)

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

    def test_historical_proof_inputs_retain_their_recorded_hashes(self):
        docs = Path(__file__).resolve().parents[1] / "docs/native-bridge"
        candidate = json.loads((docs / "durable-restart-v3-proof-manifest.json").read_text())["candidate"]
        inputs = (
            (candidate["sourceManifest"], candidate["sourceManifestSha256"]),
            (candidate["implementationPatch"]["path"], candidate["implementationPatch"]["sha256"]),
        )
        for relative, expected in inputs:
            with self.subTest(path=relative):
                self.assertEqual(hashlib.sha256((docs / relative).read_bytes()).hexdigest(), expected)

    def test_manifest_rejects_a_missing_patched_file(self):
        manifest_bytes = PACKAGER["SOURCE_MANIFEST"].read_bytes()
        patch_bytes = PACKAGER["PATCH"].read_bytes()
        manifest = PACKAGER["verify_manifest"](manifest_bytes, patch_bytes)
        self.assertEqual(manifest["fileCount"], 52)
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

    def test_launcher_pin_is_literal_data_and_rejects_ambiguous_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "launcher.py"
            path.write_text('raise RuntimeError("must not execute")\nQUALIFIED_SHA256 = "' + "a" * 64 + '"\n')
            self.assertEqual(PACKAGER["_launcher_pin"](path), "a" * 64)
            for value in ('"a" * 64', '"short"', 'None'):
                path.write_text("QUALIFIED_SHA256 = " + value)
                with self.assertRaises(ValueError):
                    PACKAGER["_launcher_pin"](path)
            path.write_text('QUALIFIED_SHA256 = "' + "a" * 64 + '"\n'
                            + 'QUALIFIED_SHA256 = "' + "b" * 64 + '"\n')
            with self.assertRaises(ValueError):
                PACKAGER["_launcher_pin"](path)

    def test_builder_pin_matches_the_only_launcher_digest(self):
        self.assertEqual(PACKAGER["QUALIFIED_SHA256"], launcher.QUALIFIED_SHA256)

    def test_package_rechecks_source_before_publication_and_preserves_raced_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "checkout"
            source.mkdir()
            state = {
                "scenario": "success", "build_completed": False, "copies": [], "evidence": None,
                "commands": [],
            }

            def archive_source(_checkout, work, _env, _git):
                codex_rs = work / "codex-rs"
                codex_rs.mkdir()
                (codex_rs / "Cargo.lock").write_text("version = 4\n")

            def run(command, *, cwd, **_kwargs):
                state["commands"].append((command, _kwargs.get("env", {})))
                if "fetch" in command:
                    self.assertIn("--locked", command)
                elif "apply" in command:
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
                "_verified_code_mode_host": lambda _path: b"mock host",
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
                with self.assertRaisesRegex(ValueError, "native_release_digest_mismatch"):
                    PACKAGER["package"](source, output, evidence_path, root / "host.tar.gz",
                                        verify_release=True, prime_dependencies=True)
                cargo_steps = [(c, e) for c, e in state["commands"] if "cargo" in c]
                self.assertEqual([c[4] for c, _e in cargo_steps],
                                 ["metadata", "fetch", "metadata", "build"])
                self.assertEqual([e["CARGO_NET_OFFLINE"] for _c, e in cargo_steps],
                                 ["false", "false", "true", "true"])
                self.assertFalse(output.exists())
                self.assertFalse(evidence_path.exists())
                self.assertFalse((root / "codex-code-mode-host").exists())
                self.assertEqual(state["copies"], [])
                with patch.dict(PACKAGER_GLOBALS, {
                    "QUALIFIED_SHA256": hashlib.sha256(b"mock native CLI").hexdigest(),
                }):
                    evidence = PACKAGER["package"](
                        source, output, evidence_path, root / "host.tar.gz", verify_release=True,
                    )
                self.assertTrue(evidence["launcherQualified"])
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

                host_output = root / "codex-code-mode-host"
                self.assertEqual(host_output.read_bytes(), b"mock host")
                self.assertEqual(evidence["codeModeHost"]["path"], str(host_output.resolve()))
                host_output.unlink()
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
                        "--code-mode-host-archive", str(root / "host.tar.gz"),
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
                    PACKAGER["package"](source, raced_output, raced_evidence, root / "host.tar.gz")
                self.assertFalse(raced_output.exists())
                self.assertFalse(host_output.exists())
                self.assertEqual(raced_evidence.read_bytes(), b"created during build")

                original_exit = tempfile.TemporaryDirectory.__exit__
                for replaced in (None, "codex", "codex-code-mode-host", "evidence.json"):
                    with self.subTest(cleanup_replacement=replaced):
                        run_dir = root / f"cleanup-{replaced}"
                        run_dir.mkdir()
                        cli = run_dir / "codex"
                        host = run_dir / "codex-code-mode-host"
                        record = run_dir / "evidence.json"
                        replacement = run_dir / "replacement"
                        replacement.write_bytes(b"other process")
                        state.update(scenario="success", build_completed=False, evidence=record)

                        def cleanup_failure(context, *args):
                            self.assertTrue(all(path.exists() for path in (cli, host, record)))
                            if replaced is not None:
                                replacement.replace(run_dir / replaced)
                            original_exit(context, *args)
                            raise OSError("temporary cleanup failure")
                        with patch.object(tempfile.TemporaryDirectory, "__exit__", new=cleanup_failure):
                            with self.assertRaisesRegex(OSError, "temporary cleanup failure"):
                                PACKAGER["package"](source, cli, record, root / "host.tar.gz")
                        for path in (cli, host, record):
                            if path.name == replaced:
                                self.assertEqual(path.read_bytes(), b"other process")
                            else:
                                self.assertFalse(path.exists())

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
            self.assertEqual(env["CARGO_BUILD_JOBS"], "2")
            self.assertEqual(env["PATH"], "/usr/bin:/bin")
            self.assertEqual(set(env), {
                "PATH", "HOME", "TMPDIR", "CARGO_HOME", "RUSTUP_HOME",
                "RUSTUP_TOOLCHAIN", "CARGO_NET_OFFLINE", "CARGO_INCREMENTAL", "LC_ALL",
                "CARGO_BUILD_JOBS",
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
