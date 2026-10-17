#!/usr/bin/env python3
"""Produce a candidate and CI receipt from the trusted main build workflow."""

import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess

import package_native_client as builder

REPOSITORY_ID = 1200860702
WORKFLOW = ".github/workflows/event-native-build.yml"


def identity(env):
    if (env.get("GITHUB_REPOSITORY_ID") != str(REPOSITORY_ID)
            or env.get("GITHUB_REPOSITORY") != "knitli/toolshed"
            or env.get("GITHUB_REF") != "refs/heads/main"
            or env.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or env.get("RUNNER_ARCH") != "ARM64"
            or env.get("GITHUB_WORKFLOW_REF") != f"knitli/toolshed/{WORKFLOW}@refs/heads/main"
            or re.fullmatch(r"[0-9a-f]{40}", env.get("GITHUB_SHA", "")) is None):
        raise ValueError("native_producer_requires_main_arm64_dispatch")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if re.fullmatch(r"[1-9][0-9]*", env.get(key, "")) is None:
            raise ValueError("native_producer_invalid_run_identity")
    return {"repositoryId": REPOSITORY_ID, "runId": int(env["GITHUB_RUN_ID"]),
            "runAttempt": int(env["GITHUB_RUN_ATTEMPT"]), "headSha": env["GITHUB_SHA"]}


def command(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()


def environment(env):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("native_producer_requires_arm64_macos")
    return {"runnerImageOS": env.get("ImageOS", ""),
            "runnerImageVersion": env.get("ImageVersion", ""),
            "runnerArch": env["RUNNER_ARCH"],
            "sdkVersion": command("/usr/bin/xcrun", "--show-sdk-version"),
            "sdkPath": command("/usr/bin/xcrun", "--show-sdk-path"),
            "clangVersion": command("/usr/bin/xcrun", "clang", "--version"),
            "linkerVersion": command("/usr/bin/xcrun", "ld", "-version_details")}


def produce(source, host_archive, output_dir, *, family="core-idle-v1", revision=1):
    run = identity(os.environ)
    if command("/usr/bin/git", "-C", str(builder.ROOT), "rev-parse", "HEAD") != run["headSha"]:
        raise ValueError("native_producer_checkout_mismatch")
    observed_environment = environment(os.environ)
    selected = builder.registry.validate_recipe(family, revision).recipe
    recipe = builder.recipe_identity(selected)
    paths = {"builderSha256": Path(builder.__file__), "producerSha256": Path(__file__),
             "workflowSha256": builder.ROOT / WORKFLOW,
             "registrySha256": builder.REGISTRY,
             "sourceManifestSha256": builder.DOCS / selected.manifest.path}
    assets = (selected.manifest, *selected.parents, *selected.ordered_patches)
    asset_hashes = {asset.path: builder.sha256(builder.registry._read_asset(asset)) for asset in assets}
    inputs = {name: builder.sha256_file(path) for name, path in paths.items()}
    output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    # The builder creates fresh outputs and compiles in its own disposable archive.
    build = builder.package(source, output_dir / "codex", output_dir / "build-evidence.json",
                            host_archive, family=family, revision=revision, prime_dependencies=True)
    if (inputs != {name: builder.sha256_file(path) for name, path in paths.items()}
            or asset_hashes != {asset.path: builder.sha256(builder.registry._read_asset(asset))
                                for asset in assets}):
        raise ValueError("native_producer_recipe_changed_during_build")
    build_recipe = build.get("recipe")
    if (not isinstance(build_recipe, dict) or type(build_recipe.get("revision")) is not int
            or build_recipe != recipe
            or build.get("sourceManifestSha256") != selected.manifest.sha256
            or build.get("appliedPatches") != [builder.registry._asset_record(asset)
                                              for asset in selected.ordered_patches]):
        raise ValueError("native_producer_build_recipe_mismatch")
    for path, expected in ((output_dir / "codex", build["binarySha256"]),
                           (output_dir / "codex-code-mode-host",
                            build["codeModeHost"]["executableSha256"])):
        if path.is_symlink() or builder.sha256_file(path) != expected:
            raise ValueError("native_producer_output_changed")
    receipt = {"schemaVersion": 2, "kind": "native-client-ci-build", **run,
               "artifactName": f"native-client-{run['runId']}-{run['runAttempt']}",
               "recipe": recipe, "inputs": inputs, "environment": observed_environment, "build": build}
    builder._write_new(output_dir / "build-receipt.json",
                       (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode())
    (output_dir / "build-evidence.json").unlink()
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--host-archive", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--family", choices=sorted({key[0] for key in builder.registry.RECIPES}),
                        default=builder.registry.DEFAULT_FAMILY)
    parser.add_argument("--revision", type=int, choices=[1], default=1)
    args = parser.parse_args()
    produce(args.source, args.host_archive, args.output_dir, family=args.family, revision=args.revision)


if __name__ == "__main__":
    main()
