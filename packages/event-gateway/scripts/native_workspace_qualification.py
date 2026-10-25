#!/usr/bin/env python3
"""Prepare the fixed native Rust workspace proof inputs from pinned source."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

import package_native_client as builder


UPSTREAM = builder.UPSTREAM_COMMIT
GIT = shutil.which("git")
if GIT is None:
    raise RuntimeError("native_workspace_requires_git")
V8_TAG = "rusty-v8-v150.4.0"
MAX_ASSET_BYTES = 32 * 1024 * 1024
V8_ASSETS = {
    "rusty_v8_150_4_0_aarch64_apple_darwin_archive": (
        "librusty_v8_ptrcomp_sandbox_release_aarch64-apple-darwin.a.gz",
    ),
    "rusty_v8_150_4_0_aarch64_apple_darwin_binding": (
        "src_binding_ptrcomp_sandbox_release_aarch64-apple-darwin.rs",
    ),
}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify_downloaded_asset(data, expected_sha256):
    if sha256(data) != expected_sha256:
        raise ValueError("rusty_v8_asset_digest_mismatch")


def read_downloaded_asset(response):
    data = response.read(MAX_ASSET_BYTES + 1)
    if len(data) > MAX_ASSET_BYTES:
        raise ValueError("rusty_v8_asset_too_large")
    return data


def pinned_v8_assets(module):
    """Read the paired archive/binding digest and URL from pinned MODULE.bazel."""
    result = {}
    for name, (filename,) in V8_ASSETS.items():
        match = re.search(
            rf'http_file\(\s*name = "{re.escape(name)}",\s*'
            rf'downloaded_file_path = "{re.escape(filename)}",\s*'
            r'sha256 = "([0-9a-f]{64})",\s*urls = \[\s*'
            rf'"(https://github\.com/openai/codex/releases/download/{V8_TAG}/[^"/]+)"',
            module,
        )
        if match is None or not match.group(2).endswith("/" + filename):
            raise ValueError("pinned_rusty_v8_pair_missing_or_changed")
        result[name] = {"sha256": match.group(1), "url": match.group(2)}
    if result[next(iter(V8_ASSETS))]["sha256"] != "00adbb48798848c77550441c68673a5e8529b8e1b73eabcdee232cb39b40f4a1":
        raise ValueError("pinned_rusty_v8_archive_digest_changed")
    if result[list(V8_ASSETS)[1]]["sha256"] != "ca5adf0cf89c9a70ad460ae73648b2fe89b74aa113b3cb7f757b6a02b758394f":
        raise ValueError("pinned_rusty_v8_binding_digest_changed")
    return result


def _run(argv, *, cwd=None, capture=False):
    return subprocess.run(argv, cwd=cwd, check=True, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


def prepare(source, output):
    if _run([GIT, "rev-parse", "HEAD"], cwd=source, capture=True).stdout.strip() != UPSTREAM:
        raise ValueError("native_source_checkout_must_be_exact_pinned_commit")
    recipe = builder.registry.validate_recipe("core-idle-v1", 1).recipe
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="native-workspace-replay-") as temporary:
        archive = Path(temporary) / "source.tar"
        with archive.open("wb") as stream:
            subprocess.run([GIT, "-c", f"core.attributesFile={Path('/dev/null')}",
                            "archive", "--format=tar", UPSTREAM], cwd=source,
                           check=True, stdout=stream)
        with tarfile.open(archive) as bundle:
            bundle.extractall(output, filter="data")
    work = output / "codex-rs"
    for patch in recipe.ordered_patches:
        contents = builder.registry._read_asset(patch)
        subprocess.run([GIT, "apply", "--check", "--whitespace=error", "-"], cwd=output,
                       input=contents, check=True)
        subprocess.run([GIT, "apply", "--whitespace=error", "-"], cwd=output,
                       input=contents, check=True)
    evidence = builder.registry.validate_recipe("core-idle-v1", 1)
    file_count, inventory = builder.verify_recipe_source(output, evidence)
    pins = pinned_v8_assets((output / "MODULE.bazel").read_text())
    asset_paths = (output / "rusty-v8.a.gz", output / "rusty-v8-binding.rs")
    for asset, destination in zip(pins.values(), asset_paths):
        with urllib.request.urlopen(asset["url"], timeout=120) as response:
            data = read_downloaded_asset(response)
        verify_downloaded_asset(data, asset["sha256"])
        destination.write_bytes(data)
    receipt = {
        "kind": "native-full-workspace-source-proof-inputs",
        "upstreamCommit": UPSTREAM,
        "recipe": {"family": recipe.family, "revision": recipe.revision,
                   "manifestSha256": recipe.manifest.sha256},
        "patchedFileCount": file_count,
        "patchedSourceInventorySha256": inventory,
        "moduleBazelSha256": sha256((output / "MODULE.bazel").read_bytes()),
        "upstreamCargoLockSha256": sha256((work / "Cargo.lock").read_bytes()),
        "v8Assets": {name: {**asset, "downloadedSha256": sha256(path.read_bytes()),
                            "bytes": path.stat().st_size}
                      for (name, asset), path in zip(pins.items(), asset_paths)},
    }
    (output / "qualification.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
