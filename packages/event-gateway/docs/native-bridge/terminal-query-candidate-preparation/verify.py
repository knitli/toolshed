"""Read and hash an inactive selected-source recipe; never execute or export it."""

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re


MANIFEST_SHA256 = "19519a2d017b3c62726d13f620cecaa3a37a34cd3fb0f414e3754e210dcb9269"
UPSTREAM = "a956835d020762cb2b570053af06f643a11c0ecc"
JSON_LIMIT = 2 * 1024 * 1024
PATCH_LIMIT = 2 * 1024 * 1024
SOURCE_LIMIT = 16 * 1024 * 1024
SOURCE_TOTAL_LIMIT = 64 * 1024 * 1024
PARENTS = [
    "native-core-idle-v1-source-manifest.json",
    "terminal-history-spike/manifest.json",
    "terminal-public-query-spike/manifest.json",
]
QUERY_PATCHES = [
    "01-public-query.patch", "02-tui-terminal-query.patch",
    "03-generated-protocol.patch", "04-generated-sdk.patch",
    "05-terminal-query-recovery.patch",
]
PATCHES = [
    "native-core-idle-v1-implementation.patch",
    "terminal-history-spike/terminal-history-cumulative.patch",
    *[f"terminal-public-query-spike/{name}" for name in QUERY_PATCHES],
]
SUPPLEMENT = {
    "path": "codex-rs/app-server/tests/suite/v2/mod.rs", "bytes": 3916,
    "sha256": "9c15c68814f2f45df7023abf62a1e250ef3fa5629d674b790b746a29b7570ebd",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(value):
    require(isinstance(value, str) and value and "\\" not in value, "unsafe path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and ".." not in path.parts
            and path.as_posix() == value and value != ".", "unsafe path")
    return path


def read_file(root, name, limit):
    relative = safe_path(name)
    require(not root.is_symlink() and root.is_dir(), "invalid or symlink root")
    candidate = root
    for part in relative.parts:
        candidate = candidate / part
        require(not candidate.is_symlink(), "symlink file or directory")
    require(candidate.is_file(), "missing regular file")
    require(candidate.stat().st_size <= limit, "file exceeds size limit")
    with candidate.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "file exceeds size limit")
    return data


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def read_json(data):
    return json.loads(data, object_pairs_hook=unique_object)


def source_map(value, count):
    require(isinstance(value, dict) and len(value) == count, "source map count mismatch")
    for path, hashed in value.items():
        safe_path(path)
        require(isinstance(hashed, str) and re.fullmatch(r"[a-f0-9]{64}", hashed), "invalid source digest")
    return value


def assets(root, records, names, limit):
    require(isinstance(records, list) and len(records) == len(names), "asset count mismatch")
    result = []
    for record, name in zip(records, names):
        require(isinstance(record, dict) and set(record) == {"path", "bytes", "sha256"}, "invalid asset record")
        require(record["path"] == name, "asset order mismatch")
        require(isinstance(record["bytes"], int) and not isinstance(record["bytes"], bool)
                and 0 < record["bytes"] <= limit, "invalid asset size")
        data = read_file(root, name, limit)
        require(len(data) == record["bytes"] and digest(data) == record["sha256"], "asset hash mismatch")
        result.append(data)
    return result


def verify(bundle, source_root=None):
    """Verify fixed recipe metadata and, optionally, only its 71 selected files."""
    bundle = Path(bundle)
    require(not bundle.is_symlink() and bundle.is_dir(), "invalid or symlink bundle")
    names = set()
    for entry in bundle.iterdir():
        require(not entry.is_symlink() and entry.is_file(), "unexpected bundle entry")
        names.add(entry.name)
        require(len(names) <= 3, "unlisted bundle entry")
    require(names == {"manifest.json", "README.md", "verify.py"}, "unlisted or missing bundle entry")
    data = read_file(bundle, "manifest.json", JSON_LIMIT)
    require(digest(data) == MANIFEST_SHA256, "manifest hash mismatch")
    manifest = read_json(data)
    require(isinstance(manifest, dict) and set(manifest) == {
        "schemaVersion", "kind", "upstreamCommit", "authorization", "coverage", "parents",
        "patches", "upstreamSupplement", "fileCount", "fileSha256",
    }, "invalid manifest fields")
    require(isinstance(manifest["schemaVersion"], int) and not isinstance(manifest["schemaVersion"], bool)
            and manifest["schemaVersion"] == 1
            and manifest["kind"] == "inactive-native-terminal-query-source-closure"
            and manifest["upstreamCommit"] == UPSTREAM and manifest["authorization"] == "none"
            and manifest["coverage"] == "selected_source_only", "invalid inactive recipe identity")
    require(isinstance(manifest["fileCount"], int) and not isinstance(manifest["fileCount"], bool)
            and manifest["fileCount"] == 71, "source count mismatch")
    selected = source_map(manifest["fileSha256"], 71)
    require(manifest["upstreamSupplement"] == SUPPLEMENT, "upstream supplement mismatch")
    # Authenticate every parent and patch before parsing any parent's claims.
    parent_bytes = assets(bundle.parent, manifest["parents"], PARENTS, JSON_LIMIT)
    assets(bundle.parent, manifest["patches"], PATCHES, PATCH_LIMIT)
    core, history, query = map(read_json, parent_bytes)
    require(core["baseCommit"] == history["baseCommit"] == UPSTREAM, "upstream parent mismatch")
    require(core["fileCount"] == 57 and core["patchSha256"] == manifest["patches"][0]["sha256"], "core parent mismatch")
    require(history["provenanceSha256"][PARENTS[0]] == manifest["parents"][0]["sha256"]
            and history["patches"]["cumulative"]["sha256"] == manifest["patches"][1]["sha256"], "history parent mismatch")
    require(query["baseFrozenManifestSha256"] == history["frozenManifestSha256"]
            and query["baseReplaySupplementSha256"] == {SUPPLEMENT["path"]: SUPPLEMENT["sha256"]}, "query parent mismatch")
    require(query["patchOrder"] + query["followupPatchOrder"] + query["repairPatchOrder"] == QUERY_PATCHES,
            "query patch order mismatch")
    for name, record in zip(QUERY_PATCHES, manifest["patches"][2:]):
        require(query["patches"][name]["sha256"] == record["sha256"], "query patch digest mismatch")
    closure = dict(source_map(core["fileSha256"], 57))
    closure.update(source_map(history["fileSha256"], 19))
    require(closure == source_map(history["selectedSourceClosureSha256"], 66), "history closure mismatch")
    closure.update(source_map(query["fileSha256"], 18))
    require(closure == source_map(query["selectedSourceClosureSha256"], 71), "query closure mismatch")
    closure.update(source_map(query["followupFileSha256"], 1))
    require(closure == source_map(query["finalSelectedSourceClosureSha256"], 71), "SDK closure mismatch")
    closure.update(source_map(query["repairFileSha256"], 3))
    require(closure == source_map(query["repairedSelectedSourceClosureSha256"], 71)
            and closure == selected, "repaired closure mismatch")
    checked = 0
    if source_root is not None:
        root = Path(source_root)
        total = 0
        for path, expected in sorted(selected.items()):
            contents = read_file(root, path, SOURCE_LIMIT)
            total += len(contents)
            require(total <= SOURCE_TOTAL_LIMIT, "source total exceeds size limit")
            require(digest(contents) == expected, "source hash mismatch")
            checked += 1
    return {"status": "verified", "authorization": "none", "coverage": "selected_source_only",
            "orderedPatchCount": 7, "selectedFileCount": 71, "sourceFilesChecked": checked}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, help="existing patched source; read and hash only")
    args = parser.parse_args(argv)
    try:
        result = verify(Path(__file__).resolve().parent, args.source_root)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
