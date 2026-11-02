#!/usr/bin/env python3
"""Build fixed source inputs for guest receipt only; this code never stages or executes them.

The future host call contract is to pass ``receiver`` as the fixed ``python3 -I -c``
program and the returned ``archive`` on stdin using ``qualify_offline_macos_vm._run_bounded``
with ``input_fd``. The receiver is bound to this bundle's manifest and archive digest.
"""

import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

import package_native_client as builder


ROOT = Path(__file__).resolve().parents[3]
MEMBERS = (
    "packages/event-gateway/scripts/stage_native_workspace.py",
    "packages/event-gateway/scripts/native_workspace_qualification.py",
    "packages/event-gateway/scripts/package_native_client.py",
    "packages/event-gateway/scripts/native_recipe_registry.py",
    "packages/event-gateway/scripts/qualify_offline_macos_vm.py",
    "packages/event-gateway/src/event_gateway/launcher.py",
    "packages/event-gateway/docs/native-bridge/native-core-idle-v1-source-manifest.json",
    "packages/event-gateway/docs/native-bridge/native-core-idle-v1-implementation.patch",
)
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024
RECEIPT_NAME = "receipt.json"
FIXED_ENV = {
    "HOME": "/Users/admin", "USER": "admin", "LOGNAME": "admin",
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": "/private/tmp/",
    "LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1",
}


def _read_regular(root, relative):
    """Read one exact repository member without following links or exceeding its cap."""
    parts = PurePosixPath(relative).parts
    if (not parts or PurePosixPath(relative).is_absolute() or ".." in parts
            or "\\" in relative):
        raise ValueError("source_member_path_unsafe")
    descriptors = []
    try:
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptors.append(os.open(root, directory_flags))
        for part in parts[:-1]:
            before = os.stat(part, dir_fd=descriptors[-1], follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise ValueError("source_member_parent_not_directory")
            child = os.open(part, directory_flags, dir_fd=descriptors[-1])
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                os.close(child)
                raise ValueError("source_member_parent_not_directory")
            descriptors.append(child)
        before = os.stat(parts[-1], dir_fd=descriptors[-1], follow_symlinks=False)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
            raise ValueError("source_member_not_regular")
        if before.st_size > MAX_MEMBER_BYTES:
            raise ValueError("source_member_oversized")
        fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_NONBLOCK", 0), dir_fd=descriptors[-1])
        try:
            after = os.fstat(fd)
            if not stat.S_ISREG(after.st_mode) or after.st_size > MAX_MEMBER_BYTES:
                raise ValueError("source_member_not_regular")
            chunks = []
            remaining = MAX_MEMBER_BYTES + 1
            while remaining:
                block = os.read(fd, min(65536, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            data = b"".join(chunks)
            if len(data) > MAX_MEMBER_BYTES:
                raise ValueError("source_member_oversized")
            return data
        finally:
            os.close(fd)
    except OSError as error:
        raise ValueError("source_member_unavailable") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _recipe_pins():
    evidence = builder.registry.validate_recipe("core-idle-v1", 1)
    recipe = evidence.recipe
    if (recipe.family, recipe.revision) != ("core-idle-v1", 1):
        raise ValueError("unexpected_registered_recipe")
    expected = {
        f"packages/event-gateway/docs/native-bridge/{recipe.manifest.path}": recipe.manifest,
        **{f"packages/event-gateway/docs/native-bridge/{asset.path}": asset
           for asset in recipe.ordered_patches},
    }
    pins = {}
    for relative, asset in expected.items():
        data = builder.registry._read_asset(asset)
        if len(data) != asset.bytes or hashlib.sha256(data).hexdigest() != asset.sha256:
            raise ValueError("registered_recipe_asset_mismatch")
        pins[relative] = data
    return pins


def _tar_bytes(files):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in MEMBERS:
            data = files[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            info.type = tarfile.REGTYPE
            archive.addfile(info, io.BytesIO(data))
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0, compresslevel=9) as packed:
        packed.write(stream.getvalue())
    return output.getvalue()


def _receiver(manifest):
    """Return fixed receiver source with host-pinned metadata; no payload import or execution."""
    if type(manifest) is not dict:
        raise ValueError("invalid_bundle_manifest")
    try:
        encoded_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                                      allow_nan=False)
        encoded_size = len(encoded_manifest.encode("ascii"))
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid_bundle_manifest") from None
    if encoded_size > MAX_MANIFEST_BYTES:
        raise ValueError("invalid_bundle_manifest")
    template = r'''import hashlib, io, json, os, pathlib, shutil, sys, tarfile, tempfile
EXPECTED = json.loads(EXPECTED_JSON)
FIXED_MEMBERS = FIXED_MEMBER_PATHS
MAX_ARCHIVE = 4194304
MAX_TOTAL = 2097152
MAX_MEMBER = 2097152
MAX_TAR = MAX_TOTAL + MEMBER_COUNT * 1024 + 10240
def fail(): raise SystemExit(2)
def digest(data): return hashlib.sha256(data).hexdigest()
def receive():
    unhashed = dict(EXPECTED)
    manifest_hash = unhashed.pop("manifestSha256", None)
    if (EXPECTED.get("kind") != "native-workspace-stage-inputs-v1"
            or EXPECTED.get("qualified") is not False
            or type(EXPECTED.get("memberCount")) is not int
            or EXPECTED["memberCount"] != len(FIXED_MEMBERS)
            or type(EXPECTED.get("totalBytes")) is not int
            or EXPECTED["totalBytes"] < 0 or EXPECTED["totalBytes"] > MAX_TOTAL
            or type(EXPECTED.get("archiveBytes")) is not int
            or EXPECTED["archiveBytes"] < 1 or EXPECTED["archiveBytes"] > MAX_ARCHIVE
            or digest(json.dumps(unhashed, sort_keys=True, separators=(",", ":")).encode())
               != manifest_hash): fail()
    records = EXPECTED.get("members")
    if type(records) is not list or len(records) != len(FIXED_MEMBERS): fail()
    for item in records:
        if (type(item) is not dict or set(item) != {"path", "bytes", "sha256"}
                or item["path"] not in FIXED_MEMBERS
                or type(item["bytes"]) is not int or item["bytes"] < 0
                or item["bytes"] > MAX_MEMBER or not isinstance(item["sha256"], str)
                or len(item["sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in item["sha256"])): fail()
    if ({item["path"] for item in records} != set(FIXED_MEMBERS)
            or sum(item["bytes"] for item in records) != EXPECTED["totalBytes"]): fail()
    packed = sys.stdin.buffer.read(MAX_ARCHIVE + 1)
    if (len(packed) > MAX_ARCHIVE or len(packed) != EXPECTED["archiveBytes"]
            or digest(packed) != EXPECTED["archiveSha256"]): fail()
    try:
        decoder = __import__("zlib").decompressobj(16 + __import__("zlib").MAX_WBITS)
        raw = decoder.decompress(packed, MAX_TAR)
        if (len(raw) > MAX_TAR or decoder.unconsumed_tail or not decoder.eof
                or decoder.unused_data): fail()
        raw += decoder.flush()
        if len(raw) > MAX_TAR: fail()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            if len(members) != len(records): fail()
            expected = {item["path"]: item for item in records}
            contents = {}
            for member in members:
                name = member.name
                if (name not in expected or name in contents or not member.isreg()
                        or member.size != expected[name]["bytes"] or member.size > MAX_MEMBER): fail()
                stream = archive.extractfile(member)
                if stream is None: fail()
                data = stream.read(MAX_MEMBER + 1)
                if len(data) != member.size or digest(data) != expected[name]["sha256"]: fail()
                contents[name] = data
            if set(contents) != set(expected) or sum(map(len, contents.values())) != EXPECTED["totalBytes"]: fail()
    except (OSError, EOFError, ValueError, tarfile.TarError, __import__("zlib").error):
        fail()
    root = tempfile.mkdtemp(prefix="native-workspace-inputs-")
    try:
        os.chmod(root, 0o700)
        for record in EXPECTED["members"]:
            name = record["path"]
            parts = pathlib.PurePosixPath(name).parts
            current = root
            for part in parts[:-1]:
                current = os.path.join(current, part)
                try: os.mkdir(current, 0o700)
                except FileExistsError: pass
            path = os.path.join(root, *parts)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(contents[name]); stream.flush(); os.fsync(stream.fileno())
        receipt = {"status":"inputs-received", "qualified":False,
                   "archiveSha256":EXPECTED["archiveSha256"],
                   "manifestSha256":EXPECTED["manifestSha256"],
                   "memberCount":EXPECTED["memberCount"], "totalBytes":EXPECTED["totalBytes"],
                   "members":[{"path":item["path"],"bytes":item["bytes"],"sha256":item["sha256"]}
                              for item in EXPECTED["members"]]}
        path = os.path.join(root, "receipt.json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(receipt, sort_keys=True, separators=(",", ":"))+"\n").encode())
            stream.flush(); os.fsync(stream.fileno())
        print(json.dumps({"root":root, **receipt}, sort_keys=True, separators=(",", ":")))
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise
receive()
'''
    template = template.replace("FIXED_MEMBER_PATHS", repr(MEMBERS)).replace(
        "MEMBER_COUNT", str(len(MEMBERS)))
    return template.replace("EXPECTED_JSON", repr(encoded_manifest))


def command_template(tart_path, vm_name, manifest):
    """Fixed future stdin receiver invocation; does not authenticate VM or owner state."""
    receiver = _receiver(manifest)
    fixed = [key + "=" + value for key, value in FIXED_ENV.items()]
    return [str(tart_path), "exec", "-i", vm_name, "/usr/bin/sudo", "-n", "-u", "admin",
            "-g", "staff", "--", "/usr/bin/env", "-i", *fixed, "/usr/bin/python3", "-I",
            "-B", "-c", receiver]


def build_bundle(root=ROOT):
    """Build the exact eight-file, deterministic core-idle-v1 staging input archive."""
    root = Path(root)
    files = {}
    total = 0
    pins = _recipe_pins()
    for name in MEMBERS:
        data = _read_regular(root, name)
        pin = pins.get(name)
        if pin is not None and data != pin:
            raise ValueError("registered_recipe_asset_mismatch")
        files[name] = data
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("source_bundle_oversized")
    records = [{"path": name, "bytes": len(files[name]),
                "sha256": hashlib.sha256(files[name]).hexdigest()} for name in MEMBERS]
    archive = _tar_bytes(files)
    if len(archive) > MAX_ARCHIVE_BYTES:
        raise ValueError("source_bundle_oversized")
    manifest = {
        "kind": "native-workspace-stage-inputs-v1",
        "qualified": False,
        "memberCount": len(MEMBERS),
        "totalBytes": total,
        "members": records,
        "archiveBytes": len(archive),
        "archiveSha256": hashlib.sha256(archive).hexdigest(),
    }
    manifest["manifestSha256"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {"archive": archive, "manifest": manifest, "receiver": _receiver(manifest)}
