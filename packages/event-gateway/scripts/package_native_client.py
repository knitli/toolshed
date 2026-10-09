#!/usr/bin/env python3
"""Rebuild the pinned native Codex candidate without installing it."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import tempfile
import tomllib


ROOT = Path(__file__).resolve().parents[3]
DOCS = ROOT / "packages/event-gateway/docs/native-bridge"
PATCH = DOCS / "durable-restart-v3-implementation.patch"
SOURCE_MANIFEST = DOCS / "durable-restart-v3-source-manifest.json"
UPSTREAM_COMMIT = "a956835d020762cb2b570053af06f643a11c0ecc"
PATCH_SHA256 = "b9ab28d49a62f5756495f729c6716511d3136f58c3b9ea4061f4f7dba3d2598c"
SOURCE_MANIFEST_SHA256 = "cb3897e086557213634b380d09d258d06af45e8f69b35f7603425e882749460b"
PATCHED_FILE_COUNT = 48
QUALIFIED_SHA256 = "0fb3a5de06ab2ccb8dcc20c11cb71cad1f0c1b85fbfa3a5c6fd16ca1f57d22de"
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


def _run(command, *, cwd, env=None, capture=False, stdout=None):
    return subprocess.run(
        command, cwd=cwd, env=env, check=True, text=True, stdout=stdout or (
            subprocess.PIPE if capture else None
        ), stderr=subprocess.PIPE if capture else None,
    )


def _clean_checkout(source):
    source = source.resolve(strict=True)
    if not source.is_dir():
        raise ValueError("invalid_native_source_checkout")
    head = _run(["git", "rev-parse", "HEAD"], cwd=source, capture=True).stdout.strip()
    status = _run(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=source, capture=True,
    ).stdout
    if head != UPSTREAM_COMMIT or status:
        raise ValueError("native_source_checkout_must_be_clean_pinned_commit")
    return source


def _toolchain(env):
    rustup = shutil.which("rustup")
    if rustup is None:
        raise ValueError("native_build_requires_rustup_1_95_0_arm64_macos")
    command = [rustup, "run", RUSTUP_TOOLCHAIN]
    rustc = _run([*command, "rustc", "--version", "--verbose"], cwd=ROOT, env=env, capture=True).stdout
    values = dict(line.split(": ", 1) for line in rustc.splitlines() if ": " in line)
    cargo = _run([*command, "cargo", "--version"], cwd=ROOT, env=env, capture=True).stdout.strip()
    if (values.get("release") != RUSTUP_TOOLCHAIN
            or not values.get("commit-hash", "").startswith(RUSTC_COMMIT_PREFIX)
            or values.get("host") != HOST_TRIPLE
            or cargo.split(" ", 2)[1:2] != [RUSTUP_TOOLCHAIN]):
        raise ValueError("native_build_requires_rust_1_95_0_arm64_macos")
    return command, rustc.strip(), cargo


def _archive_source(checkout, destination, env):
    archive_paths = ("codex-rs", "sdk/python/src/openai_codex/generated")
    with tempfile.TemporaryFile() as archive:
        _run(
            ["git", "archive", "--format=tar", UPSTREAM_COMMIT, "--", *archive_paths],
            cwd=checkout, env=env, stdout=archive,
        )
        archive.seek(0)
        with tarfile.open(fileobj=archive, mode="r:") as bundle:
            bundle.extractall(destination, filter="data")


def _build_env():
    env = dict(os.environ)
    for key in (
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET",
        "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTDOCFLAGS",
    ):
        env.pop(key, None)
    env["RUSTUP_TOOLCHAIN"] = RUSTUP_TOOLCHAIN
    env["CARGO_NET_OFFLINE"] = "true"
    env["CARGO_INCREMENTAL"] = "0"
    return env


def _write_new(path, contents, mode=None):
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError("native_output_must_be_new_in_existing_directory")
    created = False
    try:
        with path.open("xb") as output:
            created = True
            output.write(contents)
        if mode is not None:
            path.chmod(mode)
    except OSError:
        if created:
            path.unlink(missing_ok=True)
        raise


def _copy_new(source, destination):
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError("native_output_must_be_new_in_existing_directory")
    created = False
    try:
        with source.open("rb") as input_file, destination.open("xb") as output_file:
            created = True
            shutil.copyfileobj(input_file, output_file)
        destination.chmod(0o755)
    except OSError:
        if created:
            destination.unlink(missing_ok=True)
        raise


def package(source, output, evidence_path):
    source = _clean_checkout(source)
    output = output.absolute()
    evidence_path = evidence_path.absolute()
    if output == evidence_path:
        raise ValueError("native_output_paths_must_differ")
    if (output.exists() or output.is_symlink() or not output.parent.is_dir()
            or evidence_path.exists() or evidence_path.is_symlink()
            or not evidence_path.parent.is_dir()):
        raise ValueError("native_output_must_be_new_in_existing_directory")

    manifest_bytes = SOURCE_MANIFEST.read_bytes()
    patch_bytes = PATCH.read_bytes()
    manifest = verify_manifest(manifest_bytes, patch_bytes)
    env = _build_env()
    rustup_command, rustc, cargo = _toolchain(env)

    with tempfile.TemporaryDirectory(prefix="codex-native-v3-build-") as directory:
        work = Path(directory)
        _archive_source(source, work, env)
        _run(["git", "apply", "--check", "--whitespace=error", str(PATCH)], cwd=work, env=env)
        _run(["git", "apply", "--whitespace=error", str(PATCH)], cwd=work, env=env)
        patched_count, source_before_build = verify_patched_source(work, manifest)

        codex_rs = work / "codex-rs"
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
        patched_after_count, source_after_build = verify_patched_source(work, manifest)
        if patched_after_count != patched_count or source_after_build != source_before_build:
            raise ValueError("native_patched_source_changed_during_build")

        binary = target_dir / "dev-small/codex"
        if binary.is_symlink() or not binary.is_file():
            raise ValueError("native_cli_build_output_missing")
        binary_hash = sha256_file(binary)
        evidence = {
            "upstreamCommit": UPSTREAM_COMMIT,
            "patchSha256": PATCH_SHA256,
            "sourceManifestSha256": sha256(manifest_bytes),
            "patchedFileCount": patched_count,
            "patchedFileSha256": manifest["fileSha256"],
            "patchedSourceInventoryBeforeBuildSha256": source_before_build,
            "patchedSourceInventoryAfterBuildSha256": source_after_build,
            "rustc": rustc,
            "cargo": cargo,
            "host": HOST_TRIPLE,
            "cargoLockLocalVersionChanges": lock_changes,
            "buildCommand": BUILD_COMMAND,
            "binarySha256": binary_hash,
            "binaryBytes": binary.stat().st_size,
            "launcherQualified": binary_hash == QUALIFIED_SHA256,
            "launcherSha256": QUALIFIED_SHA256,
        }
        _copy_new(binary, output)

    try:
        _write_new(evidence_path, (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode())
    except OSError:
        output.unlink(missing_ok=True)
        raise
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
