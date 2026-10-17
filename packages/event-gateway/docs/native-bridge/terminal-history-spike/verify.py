"""Check frozen artifacts and optional source bytes without executing native code."""

import argparse
import hashlib
import json
from pathlib import Path
import re


JSON_LIMIT = 2 * 1024 * 1024
PATCH_LIMIT = 4 * 1024 * 1024
SOURCE_LIMIT = 16 * 1024 * 1024
PROVENANCE = {
    "native-core-idle-v1-source-manifest.json",
    "terminal-completion-spike/terminal-completion.patch",
    "terminal-ordering-spike/manifest.json",
    "terminal-ordering-spike/ordering-incremental.patch",
    "terminal-ordering-spike/terminal-ordering-cumulative.patch",
}


def relative_file(root, name):
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("manifest path must stay relative to its root")
    path = Path(name)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != name:
        raise ValueError("manifest path must stay relative to its root")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError(f"missing or escaped manifest file: {name}")
    return resolved


def read_bounded(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"artifact exceeds size limit: {path.name}")
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def hashes(value, count=None):
    if not isinstance(value, dict) or (count is not None and len(value) != count):
        raise ValueError("invalid hash map size")
    for name, checksum in value.items():
        if (
            not isinstance(name, str)
            or not isinstance(checksum, str)
            or not re.fullmatch(r"[0-9a-f]{64}", checksum)
        ):
            raise ValueError("invalid SHA-256 map")
        path = Path(name)
        if (
            not name
            or "\\" in name
            or path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != name
        ):
            raise ValueError("manifest path must stay relative to its root")
    return value


def verify(bundle, source_root=None, frozen_manifest=None):
    bundle = Path(bundle)
    manifest = json.loads(
        read_bounded(relative_file(bundle, "manifest.json"), JSON_LIMIT)
    )
    pins = hashes(manifest["provenanceSha256"], 5)
    if pins.keys() != PROVENANCE:
        raise ValueError("provenance must pin exactly the five prior artifacts")
    provenance = {}
    # Authenticate every provenance artifact before interpreting any of them.
    for name, checksum in pins.items():
        data = read_bounded(
            relative_file(bundle.parent, name),
            JSON_LIMIT if name.endswith(".json") else PATCH_LIMIT,
        )
        if sha(data) != checksum:
            raise ValueError(f"provenance hash mismatch: {name}")
        provenance[name] = data
    historical = hashes(
        json.loads(provenance["native-core-idle-v1-source-manifest.json"])[
            "fileSha256"
        ],
        57,
    )
    prior = json.loads(provenance["terminal-ordering-spike/manifest.json"])
    prior_sources = hashes(prior["fileSha256"], 13)
    prior_closure = hashes(prior["selectedSourceClosureSha256"], 61)
    if historical | prior_sources != prior_closure:
        raise ValueError(
            "prior selected source closure must contain the full 61-file union"
        )
    sources = hashes(manifest["fileSha256"], 19)
    tested = hashes(manifest["testedSha256"], 19)
    if tested.keys() != sources.keys():
        raise ValueError("tested source keys must equal final source keys")
    selected = hashes(manifest["selectedSourceClosureSha256"], 66)
    if prior_closure | sources != selected:
        raise ValueError("selected source closure must contain the full 66-file union")
    payloads = {}
    for name, checksum in hashes(manifest["bundledArtifactSha256"]).items():
        data = read_bounded(
            relative_file(bundle, name),
            PATCH_LIMIT
            if name.endswith(".patch") or name.endswith(".diff")
            else JSON_LIMIT,
        )
        if sha(data) != checksum:
            raise ValueError(f"bundle hash mismatch: {name}")
        payloads[name] = data
    for kind in ("incremental", "cumulative"):
        entry = manifest["patches"][kind]
        name = entry["path"]
        if (
            name not in payloads
            or entry["sha256"] != manifest["bundledArtifactSha256"][name]
        ):
            raise ValueError(f"patch must match bundled pin: {kind}")
    # No proof is parsed until all payload hashes have passed.
    for name, data in payloads.items():
        if name.startswith("proof/") and name.endswith(".json"):
            json.loads(data)
    if frozen_manifest is not None:
        if (
            sha(read_bounded(Path(frozen_manifest), JSON_LIMIT))
            != manifest["frozenManifestSha256"]
        ):
            raise ValueError("provenance hash mismatch: frozenManifestSha256")
    if source_root is not None:
        for name, checksum in selected.items():
            if (
                sha(read_bounded(relative_file(Path(source_root), name), SOURCE_LIMIT))
                != checksum
            ):
                raise ValueError(f"selected source hash mismatch: {name}")
    return {
        "bundle": "PASS",
        "provenanceHashes": {
            "bundled": "PASS",
            "frozenManifest": "PASS"
            if frozen_manifest is not None
            else "not checked (not bundled)",
        },
        "unbundledRawEvidenceHashes": "not checked (not bundled)",
        "selectedSourceFiles": len(selected),
        "sourceHashes": "PASS" if source_root is not None else "not checked",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument(
        "--frozen-manifest",
        type=Path,
        help="Original unbundled manifest to hash-check when available",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            verify(
                Path(__file__).resolve().parent, args.source_root, args.frozen_manifest
            )
        )
    )


if __name__ == "__main__":
    main()
