"""Verify packaged evidence and an optional selected source closure; execute no code."""

import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative_file(root, name):
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("manifest path must stay relative to its root")
    resolved = (root / path).resolve()
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError(f"missing or escaped manifest file: {name}")
    return resolved


def verify(bundle, source_root=None, frozen_manifest=None):
    manifest = json.loads((bundle / "manifest.json").read_text())
    provenance = {}
    for field, name in [
        ("historicalManifestSha256", "native-core-idle-v1-source-manifest.json"),
        (
            "priorTerminalPatchSha256",
            "terminal-completion-spike/terminal-completion.patch",
        ),
    ]:
        data = relative_file(bundle.parent, name).read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest[field]:
            raise ValueError(f"provenance hash mismatch: {field}")
        provenance[field] = data
    if frozen_manifest is not None:
        if digest(frozen_manifest) != manifest["frozenManifestSha256"]:
            raise ValueError("provenance hash mismatch: frozenManifestSha256")
    historical = json.loads(provenance["historicalManifestSha256"])["fileSha256"]
    # Final bytes supersede historical entries for overlapping paths.
    expected = historical | manifest["fileSha256"]
    if len(expected) != 61 or expected != manifest["selectedSourceClosureSha256"]:
        raise ValueError("selected source closure must contain the full 61-file union")
    for name, checksum in manifest["bundledArtifactSha256"].items():
        if digest(relative_file(bundle, name)) != checksum:
            raise ValueError(f"bundle hash mismatch: {name}")
    if source_root is not None:
        for name, checksum in expected.items():
            if digest(relative_file(source_root, name)) != checksum:
                raise ValueError(f"selected source hash mismatch: {name}")
    return {
        "bundle": "PASS",
        "provenanceHashes": {
            "historicalManifest": "PASS",
            "priorTerminalPatch": "PASS",
            "frozenManifest": "PASS"
            if frozen_manifest is not None
            else "not checked (not bundled)",
        },
        "selectedSourceFiles": len(expected),
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
