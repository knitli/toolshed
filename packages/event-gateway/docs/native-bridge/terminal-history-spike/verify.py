"""Check frozen artifacts and optional source bytes without executing native code."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re


JSON_LIMIT = 2 * 1024 * 1024
PATCH_LIMIT = 4 * 1024 * 1024
SOURCE_LIMIT = 16 * 1024 * 1024
INVENTORY_LIMIT = 128
NONPAYLOAD_FILES = {"manifest.json", "README.md", "verify.py"}
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


def _validate_provenance(bundle, manifest):
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
    return provenance


def _validate_source_closure(manifest, provenance):
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
    return selected


def _inventory_directories(files):
    directories = set()
    if len(files) > INVENTORY_LIMIT:
        raise ValueError("bundle inventory exceeds limit")
    for name in files:
        path = Path(name)
        if len(path.parts) > INVENTORY_LIMIT:
            raise ValueError("bundle inventory path exceeds depth limit")
        for parent in path.parents:
            if parent != Path("."):
                directories.add(parent.as_posix())
            if len(files) + len(directories) > INVENTORY_LIMIT:
                raise ValueError("bundle inventory exceeds limit")
    return directories


def _validate_inventory(bundle, pins):
    files = NONPAYLOAD_FILES | pins.keys()
    directories = _inventory_directories(files)
    if bundle.is_symlink():
        raise ValueError("bundle inventory rejects symlink root")
    pending = [bundle]
    found = set()
    count = 0
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                count += 1
                if count > INVENTORY_LIMIT:
                    raise ValueError("bundle inventory exceeds limit")
                name = Path(entry.path).relative_to(bundle).as_posix()
                if entry.is_symlink():
                    raise ValueError("bundle inventory rejects symlink")
                if entry.is_dir(follow_symlinks=False) and name in directories:
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False) and name in files:
                    limit = (
                        PATCH_LIMIT
                        if name.endswith((".patch", ".diff"))
                        else JSON_LIMIT
                    )
                    if entry.stat(follow_symlinks=False).st_size > limit:
                        raise ValueError("bundle inventory file exceeds size limit")
                    found.add(name)
                else:
                    raise ValueError("unexpected bundle inventory entry")
    if found != files:
        raise ValueError("bundle inventory has missing files")


def _formatting_hunk_lines(lines, index, old_count, new_count):
    before, after = [], []
    while len(before) < old_count or len(after) < new_count:
        if index >= len(lines) or lines[index][:1] not in (b" ", b"-", b"+"):
            raise ValueError("formatting evidence has incomplete hunk")
        line = lines[index]
        if not line.endswith(b"\n"):
            raise ValueError("formatting evidence requires complete lines")
        if line[:1] != b"+":
            before.append(line[1:])
        if line[:1] != b"-":
            after.append(line[1:])
        index += 1
    if len(before) != old_count or len(after) != new_count:
        raise ValueError("formatting evidence has incorrect hunk counts")
    return index, before, after


def _validate_formatting(manifest, payloads):
    tested = hashes(manifest["testedSha256"], 19)
    if tested != hashes(json.loads(payloads["proof/source-hashes.json"]), 19):
        raise ValueError("tested source hash mismatch with bundled proof")
    final = hashes(manifest["fileSha256"], 19)
    flags = manifest.get("equalsExactRustfmtOfTestedSource")
    if (
        not isinstance(flags, dict)
        or flags.keys() != final.keys()
        or any(value is not True for value in flags.values())
    ):
        raise ValueError("formatting evidence must cover every final source")
    changed = {name for name in final if final[name] != tested[name]}
    lines = payloads["tested-to-formatted.diff"].splitlines(keepends=True)
    hunks = {}
    index = 0
    while index < len(lines):
        if not lines[index].startswith(b"--- tested/"):
            raise ValueError("formatting evidence has invalid source header")
        name = lines[index][11:].removesuffix(b"\n").decode("utf-8")
        if name not in changed or name in hunks or index + 1 >= len(lines):
            raise ValueError("formatting evidence has unexpected source path")
        if lines[index + 1] != b"+++ formatted/" + name.encode() + b"\n":
            raise ValueError("formatting evidence has mismatched source paths")
        index += 2
        file_hunks = []
        old_end = new_end = 0
        while index < len(lines) and lines[index].startswith(b"@@ "):
            match = re.fullmatch(
                rb"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n", lines[index]
            )
            if match is None:
                raise ValueError("formatting evidence has invalid hunk header")
            old_start, old_count, new_start, new_count = (
                int(value) if value is not None else 1 for value in match.groups()
            )
            old_start -= bool(old_count)
            new_start -= bool(new_count)
            if (
                old_start < old_end
                or new_start < new_end
                or old_start - old_end != new_start - new_end
            ):
                raise ValueError("formatting evidence has inconsistent hunk positions")
            index += 1
            index, before, after = _formatting_hunk_lines(
                lines, index, old_count, new_count
            )
            file_hunks.append((new_start, before, after))
            old_end, new_end = old_start + old_count, new_start + new_count
        if not file_hunks:
            raise ValueError("formatting evidence requires source hunks")
        hunks[name] = file_hunks
    if hunks.keys() != changed:
        raise ValueError("formatting evidence must match changed source hashes")
    return hunks


def _validate_payloads(bundle, manifest):
    payloads = {}
    pins = hashes(manifest["bundledArtifactSha256"])
    _validate_inventory(bundle, pins)
    for name, checksum in pins.items():
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
    return _validate_formatting(manifest, payloads)


def _validate_optional_inputs(manifest, selected, source_root, frozen_manifest, hunks):
    if frozen_manifest is not None:
        if (
            sha(read_bounded(Path(frozen_manifest), JSON_LIMIT))
            != manifest["frozenManifestSha256"]
        ):
            raise ValueError("provenance hash mismatch: frozenManifestSha256")
    if source_root is not None:
        for name, checksum in selected.items():
            data = read_bounded(relative_file(Path(source_root), name), SOURCE_LIMIT)
            if sha(data) != checksum:
                raise ValueError(f"selected source hash mismatch: {name}")
            if name in manifest["testedSha256"]:
                lines = data.splitlines(keepends=True)
                for start, before, after in reversed(hunks.get(name, [])):
                    if start > len(lines) or lines[start : start + len(after)] != after:
                        raise ValueError(
                            "formatting evidence does not match final bytes"
                        )
                    lines[start : start + len(after)] = before
                if sha(b"".join(lines)) != manifest["testedSha256"][name]:
                    raise ValueError(
                        "tested source hash mismatch: formatting evidence does not reconstruct tested bytes"
                    )


def verify(bundle, source_root=None, frozen_manifest=None):
    bundle = Path(bundle)
    manifest = json.loads(
        read_bounded(relative_file(bundle, "manifest.json"), JSON_LIMIT)
    )
    provenance = _validate_provenance(bundle, manifest)
    selected = _validate_source_closure(manifest, provenance)
    hunks = _validate_payloads(bundle, manifest)
    _validate_optional_inputs(manifest, selected, source_root, frozen_manifest, hunks)
    return {
        "bundle": "PASS",
        "formattingBytes": "PASS: reverse diff reconstructs tested hashes"
        if source_root is not None
        else "not checked (structural evidence only; source bytes not supplied)",
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
