"""Inactive source recipes; no build, artifact acceptance, or release authority."""

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from types import MappingProxyType


DOCS = Path(__file__).resolve().parents[1] / "docs/native-bridge"
DEFAULT_FAMILY = "core-idle-v1"
UPSTREAM = "a956835d020762cb2b570053af06f643a11c0ecc"
ASSET_LIMIT = 2 * 1024 * 1024
TOTAL_ASSET_LIMIT = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Asset:
    path: str
    bytes: int
    sha256: str


@dataclass(frozen=True, slots=True)
class Recipe:
    family: str
    revision: int
    upstream_commit: str
    manifest: Asset
    ordered_patches: tuple[Asset, ...]
    file_count: int
    parents: tuple[Asset, ...] = ()
    base_prerequisites: tuple[Asset, ...] = ()


@dataclass(frozen=True, slots=True)
class RecipeEvidence:
    recipe: Recipe
    file_sha256: Mapping[str, str]
    authorization: str = "none"
    coverage: str = "selected_source_only"
    source_files_checked: int = 0


@dataclass(frozen=True, slots=True)
class HistoricalInputs:
    builderSha256: str
    producerSha256: str
    workflowSha256: str
    sourceManifestSha256: str
    patchSha256: str


_CORE_MANIFEST = Asset(
    "native-core-idle-v1-source-manifest.json", 19145,
    "8c6f136f215deb4dca30b4d230eede5eaf8e65c1850635b199b62457a7759924",
)
_CORE_PATCH = Asset(
    "native-core-idle-v1-implementation.patch", 1173331,
    "ef74b28f308d4eb16556771cbfc47f3db00d83165e332f546edd9b65b6b302db",
)
_TERMINAL_PATCHES = (
    _CORE_PATCH,
    Asset("terminal-history-spike/terminal-history-cumulative.patch", 109735,
          "c302089ef685d13a4179b0674ea5fae260a0bb440fb7e87aaadfba95d5b8dd07"),
    Asset("terminal-public-query-spike/01-public-query.patch", 25736,
          "e29c4d9c69210d66003228ea7f0f704cb1fa052611d57a9606577c4bde36e2bc"),
    Asset("terminal-public-query-spike/02-tui-terminal-query.patch", 19721,
          "926d3f09b44519688aeb9d060e95b1e2c1d517ab79c7e7260063881a023c0737"),
    Asset("terminal-public-query-spike/03-generated-protocol.patch", 744990,
          "855530b0cf44e4777a049e4695d5b6110dc4696e9134b408ca9f39cbc1876e55"),
    Asset("terminal-public-query-spike/04-generated-sdk.patch", 443,
          "256a7875231ed273c7fc2c4ac45aa52c878df8351e4636919f8ae040ce03ed41"),
    Asset("terminal-public-query-spike/05-terminal-query-recovery.patch", 10568,
          "2d48000986196e981f1aaaa9301edc88608961a5e3ae36e218b97ae2bb7a471b"),
)
_TERMINAL_PARENTS = (
    _CORE_MANIFEST,
    Asset("terminal-history-spike/manifest.json", 19840,
          "84ab3a5379c06e0df49ef95cc17eb70c667a2473235090c81a552235edf08841"),
    Asset("terminal-public-query-spike/manifest.json", 36572,
          "75b3553b8d92dc00f0a409ad06cfe9717108d51b7a7015605f4076d0810ba309"),
)
RECIPES = MappingProxyType({
    (DEFAULT_FAMILY, 1): Recipe(DEFAULT_FAMILY, 1, UPSTREAM, _CORE_MANIFEST, (_CORE_PATCH,), 57),
    ("terminal-query-v1", 1): Recipe(
        "terminal-query-v1", 1, UPSTREAM,
        Asset("terminal-query-candidate-preparation/manifest.json", 11299,
              "19519a2d017b3c62726d13f620cecaa3a37a34cd3fb0f414e3754e210dcb9269"),
        _TERMINAL_PATCHES, 71, _TERMINAL_PARENTS,
        (Asset("codex-rs/app-server/tests/suite/v2/mod.rs", 3916,
               "9c15c68814f2f45df7023abf62a1e250ef3fa5629d674b790b746a29b7570ebd"),),
    ),
})

# Complete reviewed input tuple from main build 38681762403, attempt 1,
# commit 5f95409cdbd137769b67eb9cb4a37da1b4207d71. This is not artifact acceptance.
HISTORICAL_INPUTS = MappingProxyType({
    (DEFAULT_FAMILY, 1): (HistoricalInputs(
        "ce2d3e5cb826726904c99fa41d2e709888d155005928cc15e47de24e349ca7a4",
        "d1d47b4beea2e23969a447ff805baeea119655aed490ff3764ae1ac0ea330763",
        "6af28bc91ce449c32cd15d3d0a194c92f17092e16af5622dad4c613efd84400e",
        _CORE_MANIFEST.sha256, _CORE_PATCH.sha256,
    ),),
    ("terminal-query-v1", 1): (),
})


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _safe_path(value):
    _require(isinstance(value, str) and value and "\\" not in value, "unsafe asset path")
    path = PurePosixPath(value)
    _require(not path.is_absolute() and ".." not in path.parts
             and path.as_posix() == value and value != ".", "unsafe asset path")
    return path


def recipe(family=DEFAULT_FAMILY, revision=1):
    """Select a fixed record, not an authorization or a caller-provided recipe."""
    _require(type(family) is str and type(revision) is int and revision > 0,
             "invalid recipe identity")
    _require((family, revision) in RECIPES, "unknown recipe")
    return RECIPES[family, revision]


def matches_historical_inputs(family, revision, inputs):
    """Match one complete tuple; never authorize an artifact or bypass current gates."""
    selected = recipe(family, revision)
    fields = tuple(HistoricalInputs.__dataclass_fields__)
    _require(isinstance(inputs, Mapping) and set(inputs) == set(fields), "invalid input fields")
    _require(all(_digest(inputs[name]) for name in fields), "invalid input digest")
    observed = HistoricalInputs(**inputs)
    return observed in HISTORICAL_INPUTS[selected.family, selected.revision]


def _asset_record(asset):
    return {"path": asset.path, "bytes": asset.bytes, "sha256": asset.sha256}


def _read_asset(asset):
    relative = _safe_path(asset.path)
    _require(type(asset.bytes) is int and 0 < asset.bytes <= ASSET_LIMIT and _digest(asset.sha256),
             "invalid asset identity")
    _require(not DOCS.is_symlink() and DOCS.is_dir(), "invalid asset root")
    candidate = DOCS
    for part in relative.parts:
        candidate = candidate / part
        _require(not candidate.is_symlink(), "symlink asset")
    _require(candidate.is_file(), "missing regular asset")
    _require(candidate.stat().st_size == asset.bytes, "asset size mismatch")
    with candidate.open("rb") as stream:
        data = stream.read(asset.bytes + 1)
    _require(len(data) == asset.bytes and hashlib.sha256(data).hexdigest() == asset.sha256,
             "asset hash mismatch")
    return data


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def _json(data):
    value = json.loads(data, object_pairs_hook=_unique_object)
    _require(isinstance(value, dict), "invalid manifest object")
    return value


def _source_map(value, count):
    _require(isinstance(value, dict) and len(value) == count, "source map count mismatch")
    for path, hashed in value.items():
        _safe_path(path)
        _require(_digest(hashed), "invalid source digest")
    return value


def _core_map(manifest):
    _require(manifest.get("baseCommit") == UPSTREAM
             and type(manifest.get("fileCount")) is int and manifest["fileCount"] == 57
             and manifest.get("patchSha256") == _CORE_PATCH.sha256, "core manifest mismatch")
    selected = _source_map(manifest.get("fileSha256"), 57)
    files = manifest.get("files")
    _require(isinstance(files, list) and len(files) == 57, "core file records mismatch")
    records = {}
    for item in files:
        _require(isinstance(item, dict) and set(item) == {"path", "bytes", "sha256"},
                 "core file records mismatch")
        _safe_path(item["path"])
        _require(item["path"] not in records and type(item["bytes"]) is int and item["bytes"] > 0,
                 "core file records mismatch")
        records[item["path"]] = item["sha256"]
    _require(records == selected, "core file records mismatch")
    return selected


def _terminal_map(selected, manifest, assets):
    _require(set(manifest) == {
        "schemaVersion", "kind", "upstreamCommit", "authorization", "coverage", "parents",
        "patches", "upstreamSupplement", "fileCount", "fileSha256",
    }, "invalid terminal manifest fields")
    _require(type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 1
             and manifest["kind"] == "inactive-native-terminal-query-source-closure"
             and manifest["upstreamCommit"] == selected.upstream_commit
             and manifest["authorization"] == "none" and manifest["coverage"] == "selected_source_only"
             and type(manifest["fileCount"]) is int and manifest["fileCount"] == selected.file_count,
             "invalid inactive recipe identity")
    _require(manifest["parents"] == [_asset_record(item) for item in selected.parents],
             "parent identity or order mismatch")
    _require(manifest["patches"] == [_asset_record(item) for item in selected.ordered_patches],
             "patch identity or order mismatch")
    supplement = selected.base_prerequisites[0]
    _require(manifest["upstreamSupplement"] == _asset_record(supplement), "base prerequisite mismatch")
    core, history, query = [_json(assets[item.path]) for item in selected.parents]
    closure = dict(_core_map(core))
    _require(history["baseCommit"] == selected.upstream_commit
             and history["provenanceSha256"][selected.parents[0].path] == selected.parents[0].sha256
             and history["patches"]["cumulative"]["sha256"] == selected.ordered_patches[1].sha256,
             "history parent mismatch")
    _require(query["baseFrozenManifestSha256"] == history["frozenManifestSha256"]
             and query["baseReplaySupplementSha256"] == {supplement.path: supplement.sha256},
             "query parent mismatch")
    query_patches = selected.ordered_patches[2:]
    _require(query["patchOrder"] + query["followupPatchOrder"] + query["repairPatchOrder"]
             == [PurePosixPath(item.path).name for item in query_patches], "query patch order mismatch")
    for item in query_patches:
        _require(query["patches"][PurePosixPath(item.path).name]["sha256"] == item.sha256,
                 "query patch digest mismatch")
    for value, count, expected, expected_count in (
        (history["fileSha256"], 19, history["selectedSourceClosureSha256"], 66),
        (query["fileSha256"], 18, query["selectedSourceClosureSha256"], 71),
        (query["followupFileSha256"], 1, query["finalSelectedSourceClosureSha256"], 71),
        (query["repairFileSha256"], 3, query["repairedSelectedSourceClosureSha256"], 71),
    ):
        closure.update(_source_map(value, count))
        _require(closure == _source_map(expected, expected_count), "source closure mismatch")
    _require(closure == _source_map(manifest["fileSha256"], selected.file_count), "source closure mismatch")
    return closure


def validate_recipe(family=DEFAULT_FAMILY, revision=1):
    """Read fixed assets; return selected hashes without inspecting or executing source."""
    selected = recipe(family, revision)
    records = (selected.manifest, *selected.parents, *selected.ordered_patches)
    _require(sum(item.bytes for item in records) <= TOTAL_ASSET_LIMIT, "asset total exceeds limit")
    assets = {item.path: _read_asset(item) for item in records}
    manifest = _json(assets[selected.manifest.path])
    try:
        source = (_core_map(manifest) if selected.family == DEFAULT_FAMILY
                  else _terminal_map(selected, manifest, assets))
    except (KeyError, TypeError) as error:
        raise ValueError("invalid recipe structure") from error
    return RecipeEvidence(selected, MappingProxyType(dict(source)))
