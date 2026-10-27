#!/usr/bin/env python3
"""Stage bounded native workspace inputs in a provisioned macOS 15 ARM64 guest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import sys
import tomllib

import native_workspace_qualification as replay
import package_native_client as builder
import qualify_offline_macos_vm as canary

FEATURES = "codex-v8-poc/sandbox"
MAX_METADATA_BYTES = 64 * 1024 * 1024
TEST_COMMAND = "just test --cargo-profile dev-small --features codex-v8-poc/sandbox"
MODULES = ("glib-2.0", "gobject-2.0", "gstreamer-1.0", "gstreamer-base-1.0",
           "gstreamer-app-1.0", "gstreamer-audio-1.0")


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _runtime():
    if (platform.system() != "Darwin" or not platform.mac_ver()[0].startswith("15.")
            or platform.machine() != "arm64" or sys.version_info < (3, 13)):
        raise ValueError("native_workspace_requires_python_3_13_macos_15_arm64")
    return {"os": "macOS", "osVersion": platform.mac_ver()[0], "architecture": "arm64",
            "python": platform.python_version()}


def _selected_cache(name):
    raw = os.environ.get(name)
    if not raw:
        raise ValueError(f"{name.lower()}_must_be_explicit_private_guest_directory")
    requested = Path(raw)
    if not requested.is_absolute():
        raise ValueError(f"{name.lower()}_must_be_explicit_private_guest_directory")
    path = canary._qualified_tart_path(requested)
    canary._check_tart_acl(path)
    if not path.is_dir():
        raise ValueError(f"{name.lower()}_must_be_explicit_private_guest_directory")
    info = path.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError(f"{name.lower()}_must_be_explicit_private_guest_directory")
    return path


def _overlap(paths):
    resolved = [(name, Path(path).resolve(strict=False)) for name, path in paths.items()]
    for index, (left_name, left) in enumerate(resolved):
        for right_name, right in resolved[index + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise ValueError(f"native_workspace_paths_overlap:{left_name}:{right_name}")


def _tool(path, args, env, cwd):
    genv = shutil.which("genv", path=env["PATH"])
    if genv is None:
        raise ValueError("native_workspace_requires_gnu_env")
    stdout, _ = canary._run_bounded(
        [genv, f"--chdir={cwd}", str(path), *args], timeout=30, env=env,
        output_limit=canary.MAX_SHORT_OUTPUT,
    )
    return stdout.decode().strip()


def _versioned_tool(name, args, env, cwd):
    path = shutil.which(name, path=env["PATH"])
    if path is None:
        raise ValueError(f"native_workspace_requires_{name}")
    return {"binary": builder._binary_evidence(path), "version": _tool(Path(path), args, env, cwd)}


def _cache_bytes(root):
    total = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
        for name in files:
            path = Path(directory) / name
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
    return total


def _run_file(command, *, cwd, env, destination):
    genv = shutil.which("genv", path=env["PATH"])
    if genv is None:
        raise ValueError("native_workspace_requires_gnu_env")
    canary._run_bounded(
        [genv, f"--chdir={cwd}", *command], timeout=1800, env=env,
        output_limit=MAX_METADATA_BYTES,
        capture_paths=(destination, destination.with_suffix(destination.suffix + ".stderr.bin")),
    )


def _provisioned_toolchain(env):
    home = Path(env["HOME"])
    rustup_cmd, rustc_version, cargo_version, rust_evidence = builder._toolchain(env)
    nextest = _versioned_tool("cargo-nextest", ["--version"], env, home)
    if not re.search(r"\b0\.9\.128\b", nextest["version"]):
        raise ValueError("native_workspace_requires_nextest_0_9_128")
    tools = {"rustup": rust_evidence["rustup"], "rustc": rust_evidence["rustc"],
             "cargo": rust_evidence["cargo"], "cargoNextest": nextest,
             "just": _versioned_tool("just", ["--version"], env, home),
             "gtimeout": _versioned_tool("gtimeout", ["--version"], env, home),
             "pkgConfig": _versioned_tool("pkg-config", ["--version"], env, home),
             "git": _versioned_tool("git", ["--version"], env, home),
             "genv": _versioned_tool("genv", ["--version"], env, home),
             "rustupVersion": _tool(Path(rust_evidence["rustup"]["path"]),
                                     ["--version"], env, home)}
    pkg = shutil.which("pkg-config", path=env["PATH"])
    modules = {name: _tool(Path(pkg), ["--modversion", name], env, home) for name in MODULES}
    for name in MODULES[2:]:
        versions = tuple(int(part) for part in re.findall(r"\d+", modules[name])[:2])
        if versions < (1, 28):
            raise ValueError("native_workspace_requires_gstreamer_1_28")
    xcrun = shutil.which("xcrun", path=env["PATH"])
    if xcrun is None:
        raise ValueError("native_workspace_requires_macos_sdk")
    sdk = _tool(Path(xcrun), ["--show-sdk-path"], env, home)
    if not Path(sdk).is_dir():
        raise ValueError("native_workspace_requires_macos_sdk")
    tools["xcrun"] = {"binary": builder._binary_evidence(xcrun),
                       "version": _tool(Path(xcrun), ["--version"], env, home)}
    return rustup_cmd, {"rustc": rustc_version, "cargo": cargo_version,
                        "tools": tools, "pkgConfigModules": modules, "sdkPath": sdk}


def stage(source: Path, output: Path):
    runtime = _runtime()  # Host rejection happens before subprocesses or filesystem mutations.
    cargo_home = _selected_cache("CARGO_HOME")
    rustup_home = _selected_cache("RUSTUP_HOME")
    source = Path(source).resolve(strict=True)
    if not source.is_dir():
        raise ValueError("invalid_native_source_checkout")
    output = Path(output).absolute()
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("native_workspace_output_must_be_fresh")
    canary._qualified_tart_path(output.parent)
    canary._check_tart_acl(output.parent)
    parent_info = output.parent.stat()
    if (parent_info.st_uid != os.getuid() or parent_info.st_mode & 0o022):
        raise ValueError("native_workspace_output_parent_not_private")
    _overlap({"source": source, "output": output, "cargo": cargo_home, "rustup": rustup_home})
    for name in ("credentials", "credentials.toml"):
        if (cargo_home / name).exists() or (cargo_home / name).is_symlink():
            raise ValueError("cargo_credentials_forbidden")
    if ((rustup_home / "credentials.toml").exists()
            or (rustup_home / "credentials.toml").is_symlink()):
        raise ValueError("rustup_credentials_forbidden")
    if any((cargo_home / name).exists() or (cargo_home / name).is_symlink()
           for name in ("config.toml", "config")):
        raise ValueError("unreviewed_cargo_home_configuration")
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    env = builder._build_env(output)
    home = Path(env["HOME"])
    rustup_cmd, toolchain = _provisioned_toolchain(env)

    source_root = output / "source"
    child_env = dict(env)
    child = Path(replay.__file__).resolve(strict=True)
    _run_file([sys.executable, str(child), "--source", str(source),
               "--output", str(source_root)], cwd=home, env=child_env,
              destination=output / "replay.stdout.json")
    codex_rs = source_root / "codex-rs"
    cargo_config = builder._cargo_configuration(codex_rs, cargo_home)
    evidence = builder.registry.validate_recipe("core-idle-v1", 1)
    count, inventory = builder.verify_recipe_source(source_root, evidence)
    source_receipt = json.loads((source_root / "qualification.json").read_text())
    if (source_receipt.get("upstreamCommit") != builder.UPSTREAM_COMMIT
            or source_receipt.get("recipe") != builder.recipe_identity(evidence.recipe)):
        raise ValueError("native_workspace_source_receipt_mismatch")
    lock_path = codex_rs / "Cargo.lock"
    lock_before = lock_path.read_bytes()
    builder._write_new(output / "Cargo.lock.before", lock_before, mode=0o600)
    parsed_before = tomllib.loads(lock_before.decode())
    metadata_online = output / "metadata.online.json"
    online_env = dict(env)
    online_env["CARGO_NET_OFFLINE"] = "false"
    cargo = [*rustup_cmd, "cargo"]
    metadata_args = ["metadata", "--features", FEATURES, "--format-version", "1"]
    _run_file([*cargo, *metadata_args], cwd=codex_rs, env=online_env,
              destination=metadata_online)
    lock_normalized = lock_path.read_bytes()
    changes = builder.lock_version_changes(
        parsed_before, tomllib.loads(lock_normalized.decode()),
    )
    builder._write_new(output / "Cargo.lock.normalized", lock_normalized, mode=0o600)
    _run_file([*cargo, "fetch", "--locked"], cwd=codex_rs, env=online_env,
              destination=output / "fetch.stdout.bin")
    if lock_path.read_bytes() != lock_normalized:
        raise ValueError("cargo_lock_changed_after_fetch")
    metadata_offline = output / "metadata.offline.json"
    _run_file([*cargo, "metadata", "--offline", "--locked", "--features", FEATURES,
               "--format-version", "1"],
              cwd=codex_rs, env=env, destination=metadata_offline)
    online = json.loads(metadata_online.read_text())
    offline = json.loads(metadata_offline.read_text())
    graph_keys = ("packages", "resolve", "workspace_members", "workspace_default_members")
    if any(online[key] != offline[key] for key in graph_keys):
        raise ValueError("cargo_offline_metadata_graph_mismatch")
    if lock_path.read_bytes() != lock_normalized:
        raise ValueError("cargo_lock_changed_after_offline_metadata")
    final_count, final_inventory = builder.verify_recipe_source(source_root, evidence)
    if (final_count, final_inventory) != (count, inventory):
        raise ValueError("native_workspace_source_changed_during_resolution")
    cargo_config["cargoHome"] = str(cargo_home)
    receipt = {
        "kind": "native-workspace-stage-v1", "qualified": False, "status": "prepared",
        "runtime": runtime,
        "sourceReceiptSha256": _sha256(source_root / "qualification.json"),
        "sourceInputs": {"upstreamCommit": source_receipt["upstreamCommit"],
                         "v8Assets": source_receipt["v8Assets"]},
        "recipeIdentity": builder.recipe_identity(evidence.recipe),
        "recipeSourceInventory": {"files": count, "sha256": inventory},
        "sourceManifestSha256": evidence.recipe.manifest.sha256,
        "testCommand": TEST_COMMAND,
        "locks": {"beforeSha256": hashlib.sha256(lock_before).hexdigest(),
                  "normalizedSha256": hashlib.sha256(lock_normalized).hexdigest(),
                  "versionChanges": changes},
        "metadata": {"onlineSha256": _sha256(metadata_online),
                     "offlineSha256": _sha256(metadata_offline),
                     "onlineStderrSha256": _sha256(
                         metadata_online.with_suffix(metadata_online.suffix + ".stderr.bin")),
                     "offlineStderrSha256": _sha256(
                         metadata_offline.with_suffix(metadata_offline.suffix + ".stderr.bin")),
                     "bytes": metadata_online.stat().st_size + metadata_offline.stat().st_size},
        "environmentKeys": sorted(env),
        "toolchain": toolchain,
        "cargoConfiguration": cargo_config,
        "operatorPrecondition": (
            "already-provisioned, credential-free macOS 15 arm64 VM; guest checks do not "
            "prove VM isolation or host secret absence"
        ),
        "cacheBytes": {"source": _cache_bytes(source_root), "cargo": _cache_bytes(cargo_home),
                       "rustup": _cache_bytes(rustup_home)},
        "limitations": ["metadata-ready only; no compile, test, or native client execution",
                         "freeze the entire stopped VM and host receipt next",
                         "build peak is unknown; fixture adaptations and full suite are "
                         "not admitted"],
    }
    builder._write_new(output / "receipt.json",
                       (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode(),
                       mode=0o600)
    return receipt

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(stage(args.source, args.output), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
