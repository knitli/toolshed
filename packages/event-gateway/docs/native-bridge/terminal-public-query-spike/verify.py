"""Check bounded public-query artifacts; never invoke native code or apply patches."""

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
PATCH_ORDER = [
    "01-public-query.patch",
    "02-tui-terminal-query.patch",
    "03-generated-protocol.patch",
]
FOLLOWUP = ["04-generated-sdk.patch"]
SDK = "sdk/python/src/openai_codex/generated/v2_all.py"
SUPPLEMENT = "codex-rs/app-server/tests/suite/v2/mod.rs"
QUALIFICATION_SHA256 = (
    "696492d809a8744e4ef7b0e86fcdc902a0ac4949e13c574be78734aebafd6abc"
)
BASE_CLOSURE_SHA256 = "5aa9be3e75a95064c4c6deeab2f897623fa1892d63542a994a4ff2f332273be2"
PAYLOADS = set(PATCH_ORDER + FOLLOWUP) | {
    "tested-to-final.diff",
    "clippy-source-delta.diff",
    "proof/source-qualification.json",
    "proof/base-history-closure.json",
    "proof/tested-source-hashes.json",
    "proof/pre-format-source-hashes.json",
    "proof/replay.json",
    "proof/sdk-generation.json",
}
NONPAYLOAD = {"manifest.json", "README.md", "verify.py"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_bounded(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("artifact exceeds size limit")
    return data


def safe_path(name):
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("manifest path must stay relative")
    path = Path(name)
    if (
        path.is_absolute()
        or ".." in path.parts
        or path.as_posix() != name
        or name == "."
    ):
        raise ValueError("manifest path must stay relative")
    if len(path.parts) > INVENTORY_LIMIT:
        raise ValueError("inventory path exceeds depth limit")
    return path


def relative_file(root, name):
    path = root / safe_path(name)
    current = root
    if root.is_symlink():
        raise ValueError("symlink root")
    for part in Path(name).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("symlink source or artifact")
    if not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f"missing or escaped manifest file: {name}")
    return path


def hashes(value, count=None):
    if not isinstance(value, dict) or (count is not None and len(value) != count):
        raise ValueError("invalid hash map size")
    for name, checksum in value.items():
        safe_path(name)
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("invalid SHA-256 map")
    return value


def parse_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique)


def inventory(bundle, pins):
    if set(pins) != PAYLOADS:
        raise ValueError("bundle payload inventory must be exact")
    files = PAYLOADS | NONPAYLOAD
    directories = {
        p.as_posix() for name in files for p in Path(name).parents if p != Path(".")
    }
    if bundle.is_symlink():
        raise ValueError("bundle inventory rejects symlink root")
    pending, found, count = [bundle], set(), 0
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


def diff_hunks(lines, index):
    hunks, old_end, new_end = [], 0, 0
    while index < len(lines) and lines[index].startswith(b"@@ "):
        match = re.fullmatch(
            rb"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n", lines[index]
        )
        if match is None:
            raise ValueError("invalid diff hunk header")
        old, old_count, new, new_count = (
            int(x) if x is not None else 1 for x in match.groups()
        )
        old -= bool(old_count)
        new -= bool(new_count)
        if old < old_end or new < new_end or old - old_end != new - new_end:
            raise ValueError("inconsistent diff hunk positions")
        index += 1
        before, after = [], []
        while len(before) < old_count or len(after) < new_count:
            if index >= len(lines) or lines[index][:1] not in (b" ", b"-", b"+"):
                raise ValueError("incomplete diff hunk")
            line = lines[index]
            if not line.endswith(b"\n"):
                raise ValueError("diff requires complete lines")
            if line[:1] != b"+":
                before.append(line[1:])
            if line[:1] != b"-":
                after.append(line[1:])
            index += 1
        if len(before) != old_count or len(after) != new_count:
            raise ValueError("incorrect diff hunk counts")
        hunks.append((new, before, after))
        old_end, new_end = old + old_count, new + new_count
    if not hunks:
        raise ValueError("diff requires source hunks")
    return hunks, index


def parse_diff(data):
    lines = data.splitlines(keepends=True)
    result, index = {}, 0
    while index < len(lines):
        if not lines[index].startswith(b"--- a/") or index + 1 >= len(lines):
            raise ValueError("invalid diff source header")
        name = lines[index][6:].removesuffix(b"\n").decode()
        safe_path(name)
        if name in result or lines[index + 1] != b"+++ b/" + name.encode() + b"\n":
            raise ValueError("duplicate or mismatched diff paths")
        result[name], index = diff_hunks(lines, index + 2)
    return result


def binary_patch_blocks(lines, index):
    blocks = 0
    while index < len(lines) and not lines[index].startswith(b"diff --git "):
        if re.fullmatch(rb"(?:literal|delta) [0-9]+\n", lines[index]) is None:
            raise ValueError("invalid binary patch header")
        index += 1
        encoded = 0
        while index < len(lines) and lines[index] != b"\n":
            if re.fullmatch(rb"[A-Za-z][!-~]+\n", lines[index]) is None:
                raise ValueError("invalid binary patch encoding")
            encoded += 1
            index += 1
        if not encoded:
            raise ValueError("empty binary patch")
        if index < len(lines):
            index += 1
        blocks += 1
    if blocks != 2:
        raise ValueError("binary patch requires forward and reverse blocks")
    return index


def patch_paths(data):
    lines = data.splitlines(keepends=True)
    paths, index, changed, binaries = [], 0, 0, 0
    while index < len(lines):
        match = re.fullmatch(rb"diff --git a/(\S+) b/\1\n", lines[index])
        if match is None:
            raise ValueError("invalid patch file header")
        name = match[1].decode()
        safe_path(name)
        if name in paths:
            raise ValueError("duplicate patch path")
        paths.append(name)
        index += 1
        if index < len(lines) and lines[index] == b"new file mode 100644\n":
            index += 1
        if (
            index >= len(lines)
            or re.fullmatch(
                rb"index [0-9a-f]+\.\.[0-9a-f]+(?: 100644)?\n", lines[index]
            )
            is None
        ):
            raise ValueError("invalid patch index or file mode")
        index += 1
        if index < len(lines) and lines[index] == b"GIT binary patch\n":
            if not name.endswith(".json.zst"):
                raise ValueError("unexpected binary patch")
            binaries += 1
            index += 1
            index = binary_patch_blocks(lines, index)
        else:
            if index + 1 >= len(lines) or lines[index] not in (
                b"--- a/" + name.encode() + b"\n",
                b"--- /dev/null\n",
            ):
                raise ValueError("invalid patch old path")
            if lines[index + 1] != b"+++ b/" + name.encode() + b"\n":
                raise ValueError("invalid patch new path")
            start = index + 2
            _, index = diff_hunks(lines, start)
            changed += sum(line[:1] in (b"+", b"-") for line in lines[start:index])
    return paths, changed, binaries


def reverse_diff(data, hunks):
    lines = data.splitlines(keepends=True)
    for start, before, after in reversed(hunks):
        if start > len(lines) or lines[start : start + len(after)] != after:
            raise ValueError("diff does not match final source bytes")
        lines[start : start + len(after)] = before
    return b"".join(lines)


def authenticated_payloads(bundle):
    manifest = parse_json(
        read_bounded(relative_file(bundle, "manifest.json"), JSON_LIMIT)
    )
    pins = hashes(manifest["bundledArtifactSha256"])
    inventory(bundle, pins)
    payloads = {}
    # Authenticate all payloads before interpreting any patch or proof.
    for name, checksum in pins.items():
        data = read_bounded(
            relative_file(bundle, name),
            PATCH_LIMIT if name.endswith((".patch", ".diff")) else JSON_LIMIT,
        )
        if sha(data) != checksum:
            raise ValueError(f"bundle hash mismatch: {name}")
        payloads[name] = data
    if sha(payloads["proof/source-qualification.json"]) != QUALIFICATION_SHA256:
        raise ValueError("immutable source qualification hash mismatch")
    if sha(payloads["proof/base-history-closure.json"]) != BASE_CLOSURE_SHA256:
        raise ValueError("immutable base history closure hash mismatch")
    immutable = {
        "proof/pre-format-source-hashes.json": "9d82bbe60ae36cac72670bed5db419416a9f44cde15fe0aec4b3db7163932be2",
        "proof/sdk-generation.json": "81f4003fefdd0c6590af60e89a91da0244b1f0138d719674ebd88e24c4e7f0e0",
    }
    for name, checksum in immutable.items():
        if pins[name] != checksum:
            raise ValueError(f"immutable proof hash mismatch: {name}")
    proofs = {
        name: parse_json(data)
        for name, data in payloads.items()
        if name.endswith(".json")
    }
    return manifest, pins, payloads, proofs


def source_chain(bundle, manifest, proofs):
    qualified = proofs["proof/source-qualification.json"]
    base = hashes(proofs["proof/base-history-closure.json"], 66)
    sibling = parse_json(
        read_bounded(
            relative_file(bundle.parent, "terminal-history-spike/manifest.json"),
            JSON_LIMIT,
        )
    )
    if (
        hashes(sibling["selectedSourceClosureSha256"], 66) != base
        or sibling["frozenManifestSha256"] != qualified["baseFrozenManifestSha256"]
    ):
        raise ValueError("sibling history source chain mismatch")
    for field, count in (
        ("fileSha256", 18),
        ("testedSha256", 18),
        ("selectedSourceClosureSha256", 71),
    ):
        if hashes(manifest[field], count) != qualified[field]:
            raise ValueError(f"qualified source hash mismatch: {field}")
    final, tested, selected = (
        manifest[field]
        for field in ("fileSha256", "testedSha256", "selectedSourceClosureSha256")
    )
    if (
        base | final != selected
        or hashes(proofs["proof/tested-source-hashes.json"], 18) != tested
    ):
        raise ValueError("selected or tested source hash mismatch")
    pre_format = hashes(proofs["proof/pre-format-source-hashes.json"], 18)
    if pre_format.keys() != tested.keys():
        raise ValueError("pre-format source inventory mismatch")
    return qualified, final, tested, selected, pre_format


def followup_chain(manifest, qualified, selected):
    if (
        manifest["patchOrder"] != PATCH_ORDER
        or manifest["followupPatchOrder"] != FOLLOWUP
    ):
        raise ValueError("patch order must be exact")
    followup = hashes(manifest["followupFileSha256"], 1)
    if set(followup) != {SDK}:
        raise ValueError("SDK followup scope mismatch")
    final_selected = hashes(manifest["finalSelectedSourceClosureSha256"], 71)
    if selected | followup != final_selected:
        raise ValueError("final selected source closure mismatch")
    if manifest["baseFrozenManifestSha256"] != qualified["baseFrozenManifestSha256"]:
        raise ValueError("base frozen manifest chain mismatch")
    if set(manifest["patches"]) != set(PATCH_ORDER + FOLLOWUP):
        raise ValueError("patch metadata inventory mismatch")
    return followup, final_selected


def sdk_generation(proofs, selected, followup, pins):
    sdk = proofs["proof/sdk-generation.json"]
    if (
        sdk["generatedFiles"]
        != {SDK: {"before": selected[SDK], "after": followup[SDK]}}
        or sdk["patchSha256"] != pins[FOLLOWUP[0]]
    ):
        raise ValueError("SDK generation source chain mismatch")
    for field, value in (
        ("stageLockUnchanged", True),
        ("sourceFinal18HashesUnchanged", True),
        ("sdkOrCliInstalled", False),
        ("nativeTestsRerun", False),
        ("originalFrozenProofUnchanged", True),
    ):
        if sdk.get(field) is not value:
            raise ValueError("SDK generation scope mismatch")
    if (
        sdk["generationExitCode"] != 0
        or len(sdk["environment"]["packages"]) != sdk["installedPackageCount"]
    ):
        raise ValueError("SDK generation result mismatch")
    if ["pydantic_core", "2.46.4"] not in sdk["environment"]["packages"]:
        raise ValueError("SDK generation locked dependency mismatch")


def patch_scopes(manifest, qualified, pins, payloads, final):
    supplement = hashes(manifest["baseReplaySupplementSha256"], 1)
    if supplement != {
        SUPPLEMENT: "9c15c68814f2f45df7023abf62a1e250ef3fa5629d674b790b746a29b7570ebd"
    }:
        raise ValueError("base replay supplement scope mismatch")
    scopes = []
    for name, count in zip(PATCH_ORDER + FOLLOWUP, (8, 4, 6, 1)):
        entry = manifest["patches"][name]
        if entry["sha256"] != pins[name] or entry["files"] != count:
            raise ValueError("patch must match bundled pin and inventory")
        if name in PATCH_ORDER and entry != qualified["patches"][name]:
            raise ValueError("original patch qualification mismatch")
        if name in FOLLOWUP:
            paths = list(parse_diff(payloads[name]))
            changed = sum(
                line[:1] in (b"+", b"-") and not line.startswith((b"+++", b"---"))
                for line in payloads[name].splitlines()
            )
            binaries = 0
        else:
            paths, changed, binaries = patch_paths(payloads[name])
        if len(paths) != count or changed != entry["textChangedLines"]:
            raise ValueError("patch count mismatch")
        if binaries != (2 if name == PATCH_ORDER[2] else 0):
            raise ValueError("generated binary patch inventory mismatch")
        scopes.append(set(paths))
    if (
        len(set.union(*scopes[:3])) != 18
        or set.union(*scopes[:3]) != final.keys()
        or scopes[3] != {SDK}
    ):
        raise ValueError("patch source inventory mismatch")
    return supplement, scopes


def source_deltas(payloads, final, tested, pre_format, pins, qualified):
    delta = parse_diff(payloads["tested-to-final.diff"])
    clippy = parse_diff(payloads["clippy-source-delta.diff"])
    if set(delta) != {name for name in final if final[name] != tested[name]}:
        raise ValueError("tested-to-final diff source mismatch")
    if set(clippy) != {name for name in tested if tested[name] != pre_format[name]}:
        raise ValueError("clippy diff source mismatch")
    for name in ("tested-to-final.diff", "clippy-source-delta.diff"):
        if pins[name] != qualified["supportArtifactSha256"][name]:
            raise ValueError("qualified source delta hash mismatch")
    return delta, clippy


def replay_metadata(
    proofs, qualified, final, followup, final_selected, supplement, pins, scopes
):
    replay = proofs["proof/replay.json"]
    expected = {
        "baseFrozenManifestSha256": qualified["baseFrozenManifestSha256"],
        "baseSelectedSourceFiles": 66,
        "patchOrder": PATCH_ORDER + FOLLOWUP,
        "finalChangedFiles": 19,
        "selectedSourceFiles": 71,
        "fileSha256": final | followup,
        "selectedSourceClosureSha256": final_selected,
        "baseReplaySupplementSha256": supplement,
        "nativeExecution": False,
    }
    for field, value in expected.items():
        if replay.get(field) != value or (
            field == "nativeExecution" and replay[field] is not False
        ):
            raise ValueError(f"replay metadata mismatch: {field}")
    stages = replay["stages"]
    if not isinstance(stages, list) or len(stages) != 4:
        raise ValueError("replay requires four stages")
    for stage, name, scope in zip(stages, PATCH_ORDER + FOLLOWUP, scopes):
        wanted = {key: (final | followup)[key] for key in scope}
        if (
            stage.get("patch") != name
            or stage.get("sha256") != pins[name]
            or stage.get("fileSha256") != wanted
            or stage.get("applyCheck") != "PASS"
        ):
            raise ValueError("replay stage mismatch")
    provenance = replay["baseSupplementProvenance"]
    if provenance != {
        "kind": "frozen-history-baseline-git-object",
        "commit": "ad3cab244c5c7cac72d152e587ff7d4697523173",
        "path": SUPPLEMENT,
        "sha256": supplement[SUPPLEMENT],
    }:
        raise ValueError("base supplement provenance mismatch")


def optional_source_proof(
    frozen_base_manifest,
    qualified,
    source_root,
    final_selected,
    tested,
    delta,
    clippy,
    pre_format,
):
    if (
        frozen_base_manifest is not None
        and sha(read_bounded(Path(frozen_base_manifest), JSON_LIMIT))
        != qualified["baseFrozenManifestSha256"]
    ):
        raise ValueError("frozen base manifest hash mismatch")
    if source_root is not None:
        for name, checksum in final_selected.items():
            data = read_bounded(relative_file(Path(source_root), name), SOURCE_LIMIT)
            if sha(data) != checksum:
                raise ValueError(f"selected source hash mismatch: {name}")
            if name in tested:
                tested_bytes = reverse_diff(data, delta.get(name, []))
                if sha(tested_bytes) != tested[name]:
                    raise ValueError("reverse diff tested source hash mismatch")
                preformat_bytes = tested_bytes
                for start, before, after in clippy.get(name, []):
                    # Clippy changes tested -> pre-format, before rustfmt.
                    lines = preformat_bytes.splitlines(keepends=True)
                    old_start = start
                    if lines[old_start : old_start + len(before)] != before:
                        raise ValueError("clippy delta does not match tested bytes")
                    lines[old_start : old_start + len(before)] = after
                    preformat_bytes = b"".join(lines)
                if sha(preformat_bytes) != pre_format[name]:
                    raise ValueError("pre-format source hash mismatch")


def _verify(bundle, source_root, frozen_base_manifest):
    manifest, pins, payloads, proofs = authenticated_payloads(bundle)
    qualified, final, tested, selected, pre_format = source_chain(
        bundle, manifest, proofs
    )
    followup, final_selected = followup_chain(manifest, qualified, selected)
    sdk_generation(proofs, selected, followup, pins)
    supplement, scopes = patch_scopes(manifest, qualified, pins, payloads, final)
    delta, clippy = source_deltas(payloads, final, tested, pre_format, pins, qualified)
    replay_metadata(
        proofs, qualified, final, followup, final_selected, supplement, pins, scopes
    )
    optional_source_proof(
        frozen_base_manifest,
        qualified,
        source_root,
        final_selected,
        tested,
        delta,
        clippy,
        pre_format,
    )
    return {
        "bundle": "PASS",
        "selectedSourceFiles": 71,
        "sourceHashes": "PASS" if source_root is not None else "not checked",
        "frozenBaseManifestHash": "PASS"
        if frozen_base_manifest is not None
        else "not checked",
        "nativeExecution": False,
        "rawEvidence": "not checked (not bundled)",
        "binaryExports": "pinned bytes and structural patch checks only",
    }


def verify(bundle, source_root=None, frozen_base_manifest=None):
    try:
        return _verify(Path(bundle), source_root, frozen_base_manifest)
    except (KeyError, TypeError, UnicodeError, OSError, RecursionError) as error:
        raise ValueError(f"invalid or missing bundle evidence: {error}") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--frozen-base-manifest", type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            verify(
                Path(__file__).resolve().parent,
                args.source_root,
                args.frozen_base_manifest,
            )
        )
    )


if __name__ == "__main__":
    main()
