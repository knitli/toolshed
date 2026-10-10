#!/usr/bin/env python3
"""Rebuild the pinned native Codex candidate without installing it."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[3]
DOCS = ROOT / "packages/event-gateway/docs/native-bridge"
PATCH = DOCS / "native-metadata-v1-implementation.patch"
SOURCE_MANIFEST = DOCS / "native-metadata-v1-source-manifest.json"
UPSTREAM_COMMIT = "a956835d020762cb2b570053af06f643a11c0ecc"
PATCH_SHA256 = "922c3b2aa733564f67765aec27d4128b96b697441b37b42665b6656a4ad884fb"
SOURCE_MANIFEST_SHA256 = "8f40ca398770501412963786ade67891749f3c9296a1c82c14d62f6257e98469"
PINNED_CARGO_CONFIG_SHA256 = "b8ae1cea341beb2d4a3c8fb81f97a96f4aee1fd53f769c57f140dfe949806a80"
PINNED_SOURCE_ROOT_CARGO_CONFIG_SHA256 = "b34b20f64e30695e8629ddad8b80885764e947f51e4ce49c6378a3b5a238d25e"
PATCHED_FILE_COUNT = 52
# Keep the builder standalone; the pin-parity test enforces this launcher constant.
QUALIFIED_SHA256 = "362074bba4d43bbcc7e1e4162f67f8439106ef388670899309effd75cca65f27"
RUSTC_COMMIT_PREFIX = "59807616e"
LOCK_VERSION_CHANGES = 159
HOST_TRIPLE = "aarch64-apple-darwin"
RUSTUP_TOOLCHAIN = "1.95.0"
BUILD_COMMAND = (
    "rustup run 1.95.0 cargo build --offline --locked -p codex-cli --bin codex "
    "-p codex-tui --bin codex-tui --profile dev-small"
)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_manifest(manifest_bytes, patch_bytes):
    """Check the checked-in patch and source inventory against their pins."""
    manifest = json.loads(manifest_bytes)
    if (sha256(manifest_bytes) != SOURCE_MANIFEST_SHA256
            or manifest.get("baseCommit") != UPSTREAM_COMMIT
            or manifest.get("patchSha256") != PATCH_SHA256
            or sha256(patch_bytes) != PATCH_SHA256
            or manifest.get("fileCount") != PATCHED_FILE_COUNT
            or manifest.get("fileCount") != len(manifest.get("fileSha256", {}))
            or manifest.get("fileCount") != len(manifest.get("files", []))):
        raise ValueError("native_source_manifest_mismatch")
    files = manifest["files"]
    if (len({entry.get("path") for entry in files}) != len(files)
            or {entry.get("path"): entry.get("sha256") for entry in files}
            != manifest["fileSha256"]):
        raise ValueError("native_source_manifest_mismatch")
    return manifest


def verify_patched_source(source, manifest):
    """Verify every pinned patched file and reject path escapes or symlinks."""
    entries = {entry["path"]: entry for entry in manifest["files"]}
    inventory = hashlib.sha256()
    for relative, expected in sorted(manifest["fileSha256"].items()):
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or relative not in entries:
            raise ValueError("native_source_manifest_mismatch")
        candidate = source
        for part in path.parts:
            candidate = candidate / part
            if candidate.is_symlink():
                raise ValueError("native_source_manifest_mismatch")
        if not candidate.is_file():
            raise ValueError("native_source_manifest_mismatch")
        contents = candidate.read_bytes()
        if len(contents) != entries[relative]["bytes"] or sha256(contents) != expected:
            raise ValueError("native_source_hash_mismatch")
        inventory.update(relative.encode())
        inventory.update(b"\0")
        inventory.update(bytes.fromhex(expected))
    return len(manifest["fileSha256"]), inventory.hexdigest()


def lock_version_changes(before, after):
    """Allow only the 159 pinned local 0.0.0 to 0.160.0 lock edits."""
    if (set(before) != set(after)
            or len(before.get("package", [])) != len(after.get("package", []))
            or {key: value for key, value in before.items() if key != "package"}
            != {key: value for key, value in after.items() if key != "package"}):
        raise ValueError("unexpected_cargo_lock_change")
    changed = 0
    for old, new in zip(before["package"], after["package"]):
        if old == new:
            continue
        expected = dict(old)
        if old.get("source") is not None or old.get("version") != "0.0.0":
            raise ValueError("unexpected_cargo_lock_change")
        expected["version"] = "0.160.0"
        if new != expected:
            raise ValueError("unexpected_cargo_lock_change")
        changed += 1
    if changed != LOCK_VERSION_CHANGES:
        raise ValueError("unexpected_cargo_lock_change")
    return changed


def _file_identity(file_stat):
    return file_stat.st_dev, file_stat.st_ino


def _unlink_if_owned(path, identity):
    """Remove only the regular file this process created at ``path``."""
    if identity is None:
        return
    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if stat.S_ISREG(current.st_mode) and _file_identity(current) == identity:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _resolve_new_output(path):
    """Resolve parent aliases while still rejecting an existing leaf."""
    candidate = Path(path).expanduser().absolute()
    if candidate.exists() or candidate.is_symlink() or not candidate.parent.is_dir():
        raise ValueError("native_output_must_be_new_in_existing_directory")
    return candidate.resolve(strict=False)


def _resolve_output_pair(output, evidence_path):
    output = _resolve_new_output(output)
    evidence_path = _resolve_new_output(evidence_path)
    if output == evidence_path:
        raise ValueError("native_output_paths_must_differ")
    return output, evidence_path


def _git_environment(env=None):
    selected_env = os.environ if env is None else env
    return {
        "PATH": selected_env.get("PATH", os.defpath),
        "HOME": selected_env.get("HOME", str(Path.home())),
        "TMPDIR": selected_env.get("TMPDIR", tempfile.gettempdir()),
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }


def _git_executable(env=None):
    selected_env = os.environ if env is None else env
    path = shutil.which("git", path=selected_env.get("PATH"))
    if path is None:
        raise ValueError("native_build_requires_git")
    return Path(path).resolve(strict=True)


def _binary_evidence(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ValueError("native_build_tool_missing")
    return {"path": str(path), "sha256": sha256_file(path)}


def _rustup_executable(env):
    """Find the actual rustup binary, skipping command-manager shims."""
    for directory in env.get("PATH", os.defpath).split(os.pathsep):
        candidate = Path(directory or os.curdir) / "rustup"
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        resolved = candidate.resolve(strict=True)
        if resolved.name == "rustup":
            return resolved
    raise ValueError("native_build_requires_rustup_1_95_0_arm64_macos")


def _run(command, *, cwd, env=None, capture=False, stdout=None):
    return subprocess.run(
        command, cwd=cwd, env=env, check=True, text=True, stdout=stdout or (
            subprocess.PIPE if capture else None
        ), stderr=subprocess.PIPE if capture else None,
    )


def _clean_checkout(source, env=None, git=None):
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("invalid_native_source_checkout")
    git = str(git or _git_executable(env))
    git_env = _git_environment(env)
    pinned_git = [git, "-c", f"core.attributesFile={os.devnull}"]
    top_level = Path(_run(
        [*pinned_git, "rev-parse", "--show-toplevel"], cwd=source, env=git_env, capture=True,
    ).stdout.strip()).resolve(strict=True)
    if top_level != source:
        raise ValueError("native_source_must_be_checkout_root")
    attributes = Path(_run(
        [*pinned_git, "rev-parse", "--git-path", "info/attributes"],
        cwd=source, env=git_env, capture=True,
    ).stdout.strip())
    if not attributes.is_absolute():
        attributes = source / attributes
    if attributes.exists() or attributes.is_symlink():
        raise ValueError("unreviewed_git_attributes")
    attributes_file = subprocess.run(
        [git, "config", "--local", "--includes", "--get", "core.attributesFile"],
        cwd=source, env=git_env, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if attributes_file.returncode == 0:
        raise ValueError("unreviewed_git_attributes")
    if attributes_file.returncode != 1:
        raise subprocess.CalledProcessError(
            attributes_file.returncode,
            [git, "config", "--local", "--includes", "--get", "core.attributesFile"],
            output=attributes_file.stdout,
            stderr=attributes_file.stderr,
        )
    head = _run([*pinned_git, "rev-parse", "HEAD"], cwd=source, env=git_env, capture=True).stdout.strip()
    status = _run(
        [*pinned_git, "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=source, env=git_env, capture=True,
    ).stdout
    if head != UPSTREAM_COMMIT or status:
        raise ValueError("native_source_checkout_must_be_clean_pinned_commit")
    return source


def _toolchain(env):
    rustup = _rustup_executable(env)
    command = [rustup, "run", RUSTUP_TOOLCHAIN]
    rustc = _run([*command, "rustc", "--version", "--verbose"], cwd=Path(env["HOME"]), env=env, capture=True).stdout
    values = dict(line.split(": ", 1) for line in rustc.splitlines() if ": " in line)
    cargo = _run([*command, "cargo", "--version"], cwd=Path(env["HOME"]), env=env, capture=True).stdout.strip()
    if (values.get("release") != RUSTUP_TOOLCHAIN
            or not values.get("commit-hash", "").startswith(RUSTC_COMMIT_PREFIX)
            or values.get("host") != HOST_TRIPLE
            or cargo.split(" ", 2)[1:2] != [RUSTUP_TOOLCHAIN]):
        raise ValueError("native_build_requires_rust_1_95_0_arm64_macos")
    sysroot = Path(_run(
        [*command, "rustc", "--print", "sysroot"],
        cwd=Path(env["HOME"]), env=env, capture=True,
    ).stdout.strip())
    toolchains = {
        "rustup": _binary_evidence(rustup),
        "rustc": _binary_evidence(sysroot / "bin/rustc"),
        "cargo": _binary_evidence(sysroot / "bin/cargo"),
    }
    return command, rustc.strip(), cargo, toolchains


def _archive_source(checkout, destination, env, git=None):
    git = str(git or _git_executable(env))
    with tempfile.TemporaryFile() as archive:
        _run(
            [git, "-c", f"core.attributesFile={os.devnull}",
             "archive", "--format=tar", UPSTREAM_COMMIT],
            cwd=checkout, env=_git_environment(env), stdout=archive,
        )
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode="r:") as bundle:
            bundle.extractall(destination, filter="data")


def _build_env(work):
    """Keep the selected offline caches, but discard ambient build overrides."""
    inherited = os.environ
    original_home = Path(inherited.get("HOME", str(Path.home()))).expanduser()

    def selected_home(name, default):
        path = Path(inherited.get(name, str(default))).expanduser()
        if not path.is_absolute():
            path = Path.cwd() / path
        return path.resolve(strict=False)

    cargo_home = selected_home("CARGO_HOME", original_home / ".cargo")
    rustup_home = selected_home("RUSTUP_HOME", original_home / ".rustup")
    build_home = Path(work).resolve(strict=True)
    home = build_home / "home"
    temp = build_home / "tmp"
    home.mkdir()
    temp.mkdir()
    return {
        "PATH": inherited.get("PATH", os.defpath),
        "HOME": str(home),
        "TMPDIR": str(temp),
        "CARGO_HOME": str(cargo_home),
        "RUSTUP_HOME": str(rustup_home),
        "RUSTUP_TOOLCHAIN": RUSTUP_TOOLCHAIN,
        "CARGO_NET_OFFLINE": "true",
        "CARGO_INCREMENTAL": "0",
        "LC_ALL": "C",
    }


def _cargo_configuration(codex_rs, cargo_home):
    """Reject unreviewed Cargo home and ancestor config files."""
    codex_rs = Path(codex_rs).resolve(strict=True)
    cargo_home = Path(cargo_home).resolve(strict=False)
    for name in ("config.toml", "config"):
        candidate = cargo_home / name
        if candidate.exists() or candidate.is_symlink():
            raise ValueError("unreviewed_cargo_home_configuration")

    allowed = {
        codex_rs / ".cargo/config.toml": (
            "codex-rs/.cargo/config.toml", PINNED_CARGO_CONFIG_SHA256,
        ),
        codex_rs.parent / ".cargo/config.toml": (
            ".cargo/config.toml", PINNED_SOURCE_ROOT_CARGO_CONFIG_SHA256,
        ),
    }
    accepted = []
    for directory in (codex_rs, *codex_rs.parents):
        for name in ("config.toml", "config"):
            candidate = directory / ".cargo" / name
            if not candidate.exists() and not candidate.is_symlink():
                continue
            if (candidate.is_symlink() or candidate.parent.is_symlink()
                    or not candidate.is_file()):
                raise ValueError("unreviewed_cargo_configuration")
            digest = sha256_file(candidate)
            expected = allowed.get(candidate)
            if name != "config.toml" or expected is None or digest != expected[1]:
                raise ValueError("unreviewed_cargo_configuration")
            accepted.append({"path": expected[0], "sha256": digest})
    if {config["path"] for config in accepted} != {
            "codex-rs/.cargo/config.toml", ".cargo/config.toml"}:
        raise ValueError("pinned_cargo_configuration_missing")
    return {
        "cargoHome": str(cargo_home),
        "cargoHomeConfig": None,
        "ancestorConfigs": accepted,
    }


def _write_new(path, contents, mode=None):
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError("native_output_must_be_new_in_existing_directory")
    identity = None
    try:
        with path.open("xb") as output:
            identity = _file_identity(os.fstat(output.fileno()))
            output.write(contents)
            if mode is not None:
                os.fchmod(output.fileno(), mode)
        return identity
    except BaseException:
        _unlink_if_owned(path, identity)
        raise


def _copy_new(source, destination):
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError("native_output_must_be_new_in_existing_directory")
    identity = None
    try:
        with source.open("rb") as input_file, destination.open("xb") as output_file:
            identity = _file_identity(os.fstat(output_file.fileno()))
            shutil.copyfileobj(input_file, output_file)
            os.fchmod(output_file.fileno(), 0o755)
        return identity
    except BaseException:
        _unlink_if_owned(destination, identity)
        raise


def _write_evidence(evidence_path, evidence, output, output_identity):
    try:
        contents = (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode()
        _write_new(evidence_path, contents)
    except BaseException:
        _unlink_if_owned(output, output_identity)
        raise


def package(source, output, evidence_path):
    output, evidence_path = _resolve_output_pair(output, evidence_path)

    manifest_bytes = SOURCE_MANIFEST.read_bytes()
    patch_bytes = PATCH.read_bytes()
    manifest = verify_manifest(manifest_bytes, patch_bytes)

    with tempfile.TemporaryDirectory(prefix="codex-native-v3-build-") as directory:
        work = Path(directory)
        env = _build_env(work)
        git = _git_executable(env)
        git_evidence = _binary_evidence(git)
        source = _clean_checkout(source, env, git)
        _archive_source(source, work, env, git)
        git_env = _git_environment(env)
        git_args = [str(git), "-c", f"core.attributesFile={os.devnull}", "apply"]
        _run([*git_args, "--check", "--whitespace=error", str(PATCH)], cwd=work, env=git_env)
        _run([*git_args, "--whitespace=error", str(PATCH)], cwd=work, env=git_env)
        patched_count, source_before_build = verify_patched_source(work, manifest)

        codex_rs = work / "codex-rs"
        cargo_configuration = _cargo_configuration(codex_rs, env["CARGO_HOME"])
        rustup_command, rustc, cargo, toolchain_binaries = _toolchain(env)
        lock_path = codex_rs / "Cargo.lock"
        lock_before = tomllib.loads(lock_path.read_text())
        metadata = _run(
            [*rustup_command, "cargo", "metadata", "--offline", "--format-version", "1"],
            cwd=codex_rs, env=env, capture=True,
        )
        lock_after_bytes = lock_path.read_bytes()
        lock_changes = lock_version_changes(lock_before, tomllib.loads(lock_after_bytes.decode()))
        target_dir = Path(json.loads(metadata.stdout)["target_directory"]).resolve()
        if not target_dir.is_relative_to(work.resolve()):
            raise ValueError("native_build_target_must_be_disposable")

        print("Building the pinned Codex CLI in a disposable source archive.", flush=True)
        _run(
            [*rustup_command, "cargo", "build", "--offline", "--locked", "-p", "codex-cli", "--bin", "codex",
             "-p", "codex-tui", "--bin", "codex-tui", "--profile", "dev-small"],
            cwd=codex_rs, env=env,
        )
        if lock_path.read_bytes() != lock_after_bytes:
            raise ValueError("cargo_lock_changed_during_build")
        cargo_configuration_after = _cargo_configuration(codex_rs, env["CARGO_HOME"])
        if cargo_configuration_after != cargo_configuration:
            raise ValueError("cargo_configuration_changed_during_build")
        patched_after_count, source_after_build = verify_patched_source(work, manifest)
        if patched_after_count != patched_count or source_after_build != source_before_build:
            raise ValueError("native_patched_source_changed_during_build")

        binary = target_dir / "dev-small/codex"
        if binary.is_symlink() or not binary.is_file():
            raise ValueError("native_cli_build_output_missing")
        binary_hash = sha256_file(binary)
        evidence = {
            "upstreamCommit": UPSTREAM_COMMIT,
            "archiveScope": {
                "selection": "git archive of the pinned commit without pathspecs",
                "extractionFilter": "tarfile.data_filter",
            },
            "patchSha256": PATCH_SHA256,
            "sourceManifestSha256": sha256(manifest_bytes),
            "patchedFileCount": patched_count,
            "patchedFileSha256": manifest["fileSha256"],
            "patchedSourceInventoryBeforeBuildSha256": source_before_build,
            "patchedSourceInventoryAfterBuildSha256": source_after_build,
            "rustc": rustc,
            "cargo": cargo,
            "gitBinary": git_evidence,
            "toolchainBinaries": toolchain_binaries,
            "buildEnvironment": {
                "allowlistedVariables": sorted(env),
                "ambientBuildOverridesRemoved": True,
            },
            "cargoConfiguration": cargo_configuration,
            "host": HOST_TRIPLE,
            "cargoLockLocalVersionChanges": lock_changes,
            "buildCommand": BUILD_COMMAND,
            "binarySha256": binary_hash,
            "binaryBytes": binary.stat().st_size,
            "launcherQualified": binary_hash == QUALIFIED_SHA256,
            "launcherSha256": QUALIFIED_SHA256,
        }
        output_identity = _copy_new(binary, output)

    _write_evidence(evidence_path, evidence, output, output_identity)
    return evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True,
                        help="clean upstream Codex checkout at the pinned commit")
    parser.add_argument("--output", type=Path, required=True, help="new binary path")
    parser.add_argument("--evidence", type=Path, required=True, help="new JSON evidence path")
    args = parser.parse_args(argv)
    try:
        evidence = package(args.source, args.output, args.evidence)
    except subprocess.CalledProcessError as error:
        detail = error.stderr or error.stdout or "native_packaging_command_failed"
        parser.error(detail.strip()[-2000:])
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
