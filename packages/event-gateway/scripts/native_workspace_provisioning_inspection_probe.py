"""Read-only, bounded inspection of already downloaded native workspace assets."""

import hashlib
import gzip
import json
import lzma
import os
from pathlib import Path
import re
import stat
import tarfile
import base64
import zlib

import qualify_offline_macos_vm as canary

KIND = "native-workspace-provisioning-inspection-v1"
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_EXPANDED_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_MEMBERS = 100_000
MAX_METADATA_BYTES = 64 * 1024
MAX_CHANNEL_TEXT_BYTES = 1024 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_ARCHIVE_DETAILS = 64
RUST_INSTALLER_METADATA = {"components", "rust-installer-version", "manifest.in",
                           "git-commit-hash", "version"}
MAX_OUTPUT_BYTES = 256 * 1024
MAX_FORMULAE = 2048
MAX_FORMULA_LIST_BYTES = 256 * 1024
MAX_DIR_ENTRIES = 4096
TIMEOUT = 180
GUEST_ROOT = re.compile(r"/Users/admin/\.knitli-native-provisioning-[a-z0-9_]{8}\Z")
GUEST_PARENT = "/Users/admin"
SOURCE_FILES = {"probe": "native_workspace_provisioning_inspection_probe.py",
                "canary": "qualify_offline_macos_vm.py", "manifest": "manifest.json",
                "input": "inspection-input.json"}
ENV = {"HOME": "/Users/admin", "USER": "admin", "LOGNAME": "admin",
       "PATH": "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin:/usr/sbin:/sbin",
       "HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_INSTALL_CLEANUP": "1",
       "HOMEBREW_NO_ANALYTICS": "1", "HOMEBREW_NO_INSTALL_FROM_API": "1",
       "PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C", "LANG": "C"}
LOG_NAMES = ("native-workspace-provisioning-inspection.stdout.bin",
             "native-workspace-provisioning-inspection.stderr.bin")
ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = ROOT / "packages/event-gateway/docs/native-bridge/native-workspace-provisioning-assets.json"
BREW = "/opt/homebrew/bin/brew"
CORE = "/opt/homebrew/Library/Taps/homebrew/homebrew-core"


def _fixed_command(argv, output_limit):
    try:
        stdout, stderr = canary._run_bounded(argv, timeout=3, env=dict(ENV), output_limit=output_limit)
        if stderr:
            return {"state": "incomplete", "errorCode": "stderr_unexpected"}
        return {"state": "present", "value": stdout.decode("utf-8").strip()}
    except (OSError, UnicodeError, canary.CanaryError) as exc:
        return {"state": "incomplete", "errorCode": str(exc.args[0])[:64] if exc.args else "command_failed"}


def _directory_rows(directory_fd):
    result = []
    try:
        with os.scandir(directory_fd) as entries:
            for entry in entries:
                if len(result) >= MAX_DIR_ENTRIES:
                    return {"state": "capped", "items": result}
                info = entry.stat(follow_symlinks=False)
                if len(entry.name) > 256:
                    return {"state": "incomplete", "items": result, "errorCode": "entry_name_oversized"}
                row = {"name": entry.name, "kind": "directory" if stat.S_ISDIR(info.st_mode)
                       else "symlink" if stat.S_ISLNK(info.st_mode) else "other"}
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(entry.name, dir_fd=directory_fd)
                    if len(target) > 1024:
                        return {"state": "incomplete", "items": result, "errorCode": "link_target_oversized"}
                    row["target"] = target
                result.append(row)
    except FileNotFoundError:
        return {"state": "missing", "items": []}
    except OSError:
        return {"state": "incomplete", "items": result}
    return {"state": "present", "items": result}


def _open_directory(path):
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open("/", flags)
    try:
        for part in Path(path).parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _directories(path):
    try:
        descriptor = _open_directory(path)
    except FileNotFoundError:
        return {"state": "missing", "items": []}
    except OSError:
        return {"state": "incomplete", "items": []}
    try:
        return _directory_rows(descriptor)
    finally:
        os.close(descriptor)


def _local_homebrew():
    version = _fixed_command([BREW, "--version"], 4096)
    formula = _fixed_command([BREW, "list", "--versions", "--formula"], MAX_FORMULA_LIST_BYTES)
    if formula["state"] == "present":
        rows = formula["value"].splitlines()
        if len(rows) > MAX_FORMULAE or any(not row or len(row) > 512 for row in rows):
            formula["state"] = "capped"
        else:
            formula["items"] = rows
        formula.pop("value", None)
    git = {name: _fixed_command(["/opt/homebrew/bin/git", "-C", CORE, *args], 16 * 1024)
           for name, args in (("head", ("rev-parse", "HEAD")),
                              ("origin", ("remote", "get-url", "origin")),
                              ("dirty", ("status", "--porcelain")))}
    cellar = _cellar_inventory()
    opt_links = _directories("/opt/homebrew/opt")
    if opt_links["state"] == "present" and any(item["kind"] != "symlink" for item in opt_links["items"]):
        opt_links["state"] = "incomplete"
    git_valid = (all(item["state"] == "present" for item in git.values())
                 and bool(re.fullmatch(r"[a-f0-9]{40,64}", git["head"]["value"]))
                 and git["origin"]["value"] == "https://github.com/Homebrew/homebrew-core"
                 and git["dirty"]["value"] == "")
    complete = (version["state"] == "present" and version.get("value", "").startswith("Homebrew ")
                and formula["state"] == "present" and cellar["state"] == "present"
                and opt_links["state"] == "present" and git_valid)
    return {"state": "present" if complete else "incomplete", "version": version,
            "formulae": formula, "cellar": cellar, "optLinks": opt_links,
            "coreGit": git}


def _cellar_inventory():
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        cellar_fd = _open_directory("/opt/homebrew/Cellar")
    except FileNotFoundError:
        return {"state": "missing", "items": []}
    except OSError:
        return {"state": "incomplete", "items": []}
    rows = []
    try:
        formulas = _directory_rows(cellar_fd)
        if formulas["state"] != "present":
            return formulas
        for formula in formulas["items"]:
            if formula["kind"] != "directory":
                return {"state": "incomplete", "items": rows, "errorCode": "cellar_entry_not_directory"}
            try:
                formula_fd = os.open(formula["name"], flags, dir_fd=cellar_fd)
            except OSError:
                return {"state": "incomplete", "items": rows, "errorCode": "cellar_formula_unreadable"}
            try:
                versions = _directory_rows(formula_fd)
                if versions["state"] != "present" or any(item["kind"] != "directory" for item in versions["items"]):
                    return {"state": "incomplete", "items": rows, "errorCode": "cellar_versions_incomplete"}
                rows.append({"formula": formula["name"], "versions": [item["name"] for item in versions["items"]]})
            finally:
                os.close(formula_fd)
        return {"state": "present", "items": rows}
    finally:
        os.close(cellar_fd)


def _stat_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _hash_fd(fd, maximum):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_size > maximum
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid()
            or info.st_nlink != 1):
        raise ValueError("asset_file_unsafe")
    identity = _stat_identity(info)
    os.lseek(fd, 0, os.SEEK_SET)
    digest, size = hashlib.sha256(), 0
    while True:
        block = os.read(fd, 65536)
        if not block:
            break
        size += len(block)
        if size > maximum:
            raise ValueError("asset_oversized")
        digest.update(block)
    if _stat_identity(os.fstat(fd)) != identity or size != info.st_size:
        raise ValueError("asset_changed_during_read")
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest(), size, identity


class _LimitedReader:
    def __init__(self, stream):
        self.stream, self.count = stream, 0

    def read(self, size=-1):
        if size < 0 or size > MAX_HEADER_BYTES:
            raise ValueError("archive_metadata_header_cap")
        data = self.stream.read(size)
        self.count += len(data)
        if self.count > MAX_EXPANDED_BYTES:
            raise ValueError("archive_expansion_cap")
        return data


class _BoundedXZReader:
    def __init__(self, stream):
        self.stream = stream
        self.decoder = lzma.LZMADecompressor(memlimit=128 * 1024 * 1024)
        self.buffer = bytearray()
        self.count = 0

    def read(self, size=-1):
        if size < 0 or size > MAX_HEADER_BYTES:
            raise ValueError("archive_metadata_header_cap")
        while len(self.buffer) < size and not self.decoder.eof:
            block = self.stream.read(64 * 1024) if self.decoder.needs_input else b""
            output = self.decoder.decompress(block, max_length=min(64 * 1024, size - len(self.buffer)))
            self.buffer.extend(output)
            self.count += len(output)
            if self.count > MAX_EXPANDED_BYTES:
                raise ValueError("archive_expansion_cap")
            if self.decoder.eof and self.decoder.unused_data:
                raise ValueError("archive_xz_trailing_data")
            if not block and not output and self.decoder.needs_input and not self.decoder.eof:
                raise ValueError("archive_xz_truncated")
            if not block and not output and self.decoder.needs_input:
                break
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result


def _decompressor(raw, compression):
    if compression == "gz":
        return gzip.GzipFile(fileobj=raw, mode="rb")
    return _BoundedXZReader(raw)


def _tar_number(field):
    if field[0] & 0x80:
        value = int.from_bytes(field, "big", signed=True)
        return value & ((1 << (len(field) * 8 - 1)) - 1)
    raw = field.rstrip(b"\0 ").lstrip(b" ")
    return int(raw or b"0", 8)


def _scan_tar(fd, compression):
    os.lseek(fd, 0, os.SEEK_SET)
    expanded, members = 0, 0
    with os.fdopen(os.dup(fd), "rb") as raw:
        stream = _decompressor(raw, compression)
        while True:
            header = stream.read(512)
            if not header:
                break
            if len(header) != 512:
                raise ValueError("archive_truncated_header")
            expanded += 512
            if expanded > MAX_EXPANDED_BYTES:
                raise ValueError("archive_expansion_cap")
            if header == b"\0" * 512:
                terminator = stream.read(512)
                if terminator not in (b"", b"\0" * 512):
                    raise ValueError("archive_invalid_terminator")
                expanded += len(terminator)
                break
            members += 1
            if members > MAX_MEMBERS:
                raise ValueError("archive_member_cap")
            size = _tar_number(header[124:136])
            if size < 0 or size > MAX_MEMBER_BYTES:
                raise ValueError("archive_member_size_cap")
            kind = header[156:157]
            if kind in (b"x", b"g", b"L", b"K") and size > MAX_HEADER_BYTES:
                raise ValueError("archive_metadata_header_cap")
            if kind == b"S":
                raise ValueError("archive_sparse_metadata_unsupported")
            total = (size + 511) // 512 * 512
            if expanded + total > MAX_EXPANDED_BYTES:
                raise ValueError("archive_expansion_cap")
            remaining = size
            while remaining:
                chunk = stream.read(min(64 * 1024, remaining))
                if not chunk:
                    raise ValueError("archive_truncated_member")
                remaining -= len(chunk)
                expanded += len(chunk)
            padding = total - size
            if padding:
                pad = stream.read(padding)
                if len(pad) != padding:
                    raise ValueError("archive_truncated_member")
                expanded += len(pad)
        while True:
            tail = stream.read(64 * 1024)
            if not tail:
                break
            expanded += len(tail)
            if expanded > MAX_EXPANDED_BYTES:
                raise ValueError("archive_expansion_cap")
    os.lseek(fd, 0, os.SEEK_SET)
    return expanded


def _archive_fd(fd, compression="gz"):
    members, roots, total, symlink_count, observed = [], set(), 0, 0, 0
    inventory = hashlib.sha256()
    try:
        initial = os.fstat(fd)
        if initial.st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("archive_compressed_cap")
        expanded_stream = _scan_tar(fd, compression)
        os.lseek(fd, 0, os.SEEK_SET)
        archive_fd = os.dup(fd)
        os.lseek(archive_fd, 0, os.SEEK_SET)
        with os.fdopen(archive_fd, "rb") as raw:
            limited = _LimitedReader(_decompressor(raw, compression))
            with tarfile.open(fileobj=limited, mode="r|") as archive:
                for index, member in enumerate(archive):
                    observed = index + 1
                    if index >= MAX_MEMBERS:
                        raise ValueError("archive_member_cap")
                    name = member.name
                    if (not isinstance(name, str) or len(name) > 2048 or name.startswith("/")
                            or ".." in name.split("/") or "\x00" in name):
                        raise ValueError("archive_path_unsafe")
                    if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                        raise ValueError("archive_member_size_cap")
                    total += member.size
                    if total > MAX_EXPANDED_BYTES:
                        raise ValueError("archive_expansion_cap")
                    row = {"path": name, "type": member.type.decode("ascii", "replace") if isinstance(member.type, bytes) else str(member.type),
                           "sizeBytes": member.size}
                    if member.issym() or member.islnk():
                        if len(member.linkname) > 2048:
                            raise ValueError("archive_link_target_cap")
                        row["linkTarget"] = member.linkname
                        symlink_count += 1
                    root = name.split("/", 1)[0]
                    if len(root) > 256:
                        raise ValueError("archive_root_name_cap")
                    roots.add(root)
                    if len(roots) > 128:
                        raise ValueError("archive_root_count_cap")
                    inventory.update(json.dumps([name, row["type"], member.size,
                                                 member.mode, member.uid, member.gid,
                                                 member.mtime, member.uname, member.gname,
                                                 sorted(member.pax_headers.items()), row.get("linkTarget")],
                                                separators=(",", ":")).encode("utf-8"))
                    root_name = name.split("/", 1)[0]
                    rust_metadata = (root_name.startswith(("rustc-", "cargo-", "rust-std-"))
                                     and name.rsplit("/", 1)[-1] in RUST_INSTALLER_METADATA)
                    if member.isfile() and (name.endswith("INSTALL_RECEIPT.json")
                                            or "/.brew/" in name and name.endswith(".rb")
                                            or rust_metadata):
                        stream = archive.extractfile(member)
                        if stream is not None:
                            data = stream.read(MAX_METADATA_BYTES + 1)
                            if len(data) > MAX_METADATA_BYTES:
                                row["metadataState"] = "capped"
                            else:
                                row["metadataSha256"] = hashlib.sha256(data).hexdigest()
                                if name.endswith("INSTALL_RECEIPT.json"):
                                    try:
                                        receipt = json.loads(data)
                                    except (ValueError, UnicodeError, AttributeError):
                                        row["metadataState"] = "invalid_json"
                                    else:
                                        if type(receipt) is not dict:
                                            row["metadataState"] = "invalid_json"
                                        else:
                                            row["receipt"] = {key: receipt.get(key) for key in (
                                                "name", "version", "arch", "built_on", "time", "tap",
                                                "compiler", "stdlib", "built_as_bottle",
                                                "poured_from_bottle", "runtime_dependencies")}
                                else:
                                    if rust_metadata:
                                        row["rustInstallerMetadata"] = data.decode("utf-8", "replace")
                                        row["metadataKind"] = name.rsplit("/", 1)[-1]
                                    else:
                                        row["formulaSource"] = data.decode("utf-8", "replace")
                    keep = ("receipt" in row or "formulaSource" in row or "rustInstallerMetadata" in row
                            or "metadataState" in row
                            or ((member.issym() or member.islnk()) and name.startswith("opt/")))
                    if keep:
                        if len(members) >= MAX_ARCHIVE_DETAILS:
                            raise ValueError("archive_metadata_record_cap")
                        members.append(row)
        if _stat_identity(os.fstat(fd)) != _stat_identity(initial):
            raise ValueError("archive_changed_during_inspection")
        metadata_complete = all(member.get("metadataState") not in ("capped", "invalid_json")
                                for member in members)
        return {"status": "present", "members": members, "memberCount": observed,
                "unpackedBytes": total, "inventorySha256": inventory.hexdigest(),
                "expandedStreamBytes": expanded_stream,
                "topLevelRoots": sorted(roots), "symlinkCount": symlink_count,
                "complete": metadata_complete,
                **({} if metadata_complete else {"failureCode": "archive_metadata_incomplete"})}
    except (OSError, tarfile.TarError, EOFError, ValueError, lzma.LZMAError) as exc:
        return {"status": "incomplete", "members": members, "memberCount": observed,
                "unpackedBytes": total, "complete": False,
                "failureCode": str(exc)[:80] or "archive_invalid"}


def _inspect_assets(data, manifest, download_fd):
    assets = manifest.get("assets")
    if type(assets) is not list:
        raise ValueError("receipt_manifest_mismatch")
    downloaded = {item["name"]: item for item in assets}
    if len(downloaded) != len(assets):
        raise ValueError("asset_set_mismatch")
    try:
        with os.scandir(download_fd) as entries:
            names = []
            for entry in entries:
                if len(names) >= 256:
                    raise ValueError("asset_entry_cap")
                if len(entry.name) > 200:
                    raise ValueError("asset_name_oversized")
                names.append(entry.name)
    except OSError as exc:
        raise ValueError("downloads_directory_unreadable") from exc
    if len(names) != len(set(names)) or set(names) != set(downloaded):
        raise ValueError("asset_set_mismatch")
    verified = []
    inspected = []
    try:
        total_bytes = 0
        for asset in assets:
            item = downloaded[asset["name"]]
            fd = os.open(asset["name"], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                         getattr(os, "O_NONBLOCK", 0), dir_fd=download_fd)
            try:
                digest, size, identity = _hash_fd(fd, min(asset["maxBytes"], MAX_ARCHIVE_BYTES))
                if digest != asset["sha256"] or digest != item["sha256"]:
                    raise ValueError("asset_digest_mismatch")
                total_bytes += size
                if total_bytes > MAX_ARCHIVE_BYTES:
                    raise ValueError("asset_total_size_cap")
                verified.append({"asset": asset, "digest": digest, "size": size,
                                 "fd": fd, "identity": identity})
                fd = -1
            finally:
                if fd >= 0:
                    os.close(fd)
        # The full pinned asset set is verified before parsing archives or invoking local tools.
        expanded_total = 0
        for item in verified:
            asset, fd = item["asset"], item["fd"]
            row = {"name": asset["name"], "sha256": item["digest"], "bytes": item["size"]}
            if asset["name"].endswith((".tar.gz", ".tgz", ".tar.xz", ".txz")):
                compression = "xz" if asset["name"].endswith((".tar.xz", ".txz")) else "gz"
                row["archive"] = _archive_fd(fd, compression)
                expanded_total += row["archive"].get("expandedStreamBytes", 0)
                if expanded_total > MAX_TOTAL_EXPANDED_BYTES:
                    raise ValueError("archive_total_expansion_cap")
            elif "rust" in asset["name"].lower():
                text_cap = MAX_CHANNEL_TEXT_BYTES if asset["name"].startswith("channel-rust-") else MAX_METADATA_BYTES
                if item["size"] > text_cap:
                    row["metadataState"] = "capped"
                    inspected.append(row)
                    continue
                os.lseek(fd, 0, os.SEEK_SET)
                raw = os.read(fd, text_cap + 1)
                if len(raw) <= text_cap:
                    row["textMetadata"] = raw.decode("utf-8", "replace")
                else:
                    row["metadataState"] = "capped"
            if _stat_identity(os.fstat(fd)) != item["identity"]:
                raise ValueError("asset_changed_during_inspection")
            inspected.append(row)
        return inspected, total_bytes
    finally:
        for item in verified:
            os.close(item["fd"])


def _open_guest_downloads(guest_root):
    if not isinstance(guest_root, str) or not GUEST_ROOT.fullmatch(guest_root):
        raise ValueError("guest_root_invalid")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = _open_directory(GUEST_PARENT)
    try:
        parent_info = os.fstat(parent_fd)
        if parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) & 0o022:
            raise ValueError("guest_parent_unsafe")
        root_fd = os.open(guest_root.rsplit("/", 1)[-1], flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    try:
        root_info = os.fstat(root_fd)
        if (root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) != 0o700):
            raise ValueError("guest_root_unsafe")
        downloads_fd = os.open("downloads", flags, dir_fd=root_fd)
        info = os.fstat(downloads_fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(downloads_fd)
            raise ValueError("downloads_directory_unsafe")
        return root_fd, downloads_fd
    except BaseException:
        os.close(root_fd)
        raise


def collect_guest():
    input_doc = json.loads(Path(__file__).with_name("inspection-input.json").read_text())
    manifest_raw = Path(__file__).with_name("manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    if hashlib.sha256(manifest_raw).hexdigest() != input_doc["manifestSha256"]:
        raise ValueError("manifest_pin_mismatch")
    if not GUEST_ROOT.fullmatch(input_doc["guestRoot"]):
        raise ValueError("guest_root_invalid")
    root_fd, downloads_fd = _open_guest_downloads(input_doc["guestRoot"])
    try:
        inspected, _ = _inspect_assets(input_doc, manifest, downloads_fd)
    finally:
        os.close(downloads_fd)
        os.close(root_fd)
    local = _local_homebrew()
    archives_complete = all(item.get("archive", {}).get("complete", True)
                            and item.get("metadataState") != "capped" for item in inspected)
    local_complete = local["state"] == "present"
    complete = archives_complete and local_complete
    report = {"kind": KIND, "status": "passed" if complete else "incomplete", "qualified": False, "prepared": False,
            "complete": complete, "assets": inspected, "manifestSha256": input_doc["manifestSha256"],
            "ownerReceiptSha256": input_doc["ownerReceiptSha256"],
            "postDownloadMeasurement": input_doc["postDownloadMeasurement"], "homebrew": local}
    if len(json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")) > MAX_REPORT_BYTES - 1024:
        return {"kind": KIND, "status": "incomplete", "qualified": False, "prepared": False,
                "complete": False, "failureCode": "inspection_report_cap",
                "manifestSha256": input_doc["manifestSha256"],
                "ownerReceiptSha256": input_doc["ownerReceiptSha256"],
                "postDownloadMeasurement": input_doc["postDownloadMeasurement"]}
    return report


def build_bundle(owner_receipt_path, root=ROOT):
    import scpreferences_guest_probe as shared
    import native_workspace_provisioning_downloads as downloads

    owner_path = Path(owner_receipt_path)
    owner_raw = downloads._read_regular(owner_path, 64 * 1024)
    owner = downloads._json_no_duplicates(owner_raw)
    required = {"kind", "status", "qualified", "prepared", "vmName", "guestRoot",
                "baseMeasurementBefore", "baseMeasurementAfter", "preDownloadMeasurement",
                "postDownloadMeasurement", "baseUnchanged", "vmStopped", "vmDeleted",
                "bundleSha256", "downloadReceiptSha256", "inventorySha256", "admissionSha256",
                "runId", "macAddress"}
    if (type(owner) is not dict or set(owner) != required
            or owner["kind"] != "native-provisioning-downloaded-only-owner-receipt-v1"
            or owner["status"] != "downloaded-only" or owner["qualified"] is not False
            or owner["prepared"] is not False or owner["baseUnchanged"] is not True
            or owner["vmStopped"] is not True or owner["vmDeleted"] is not False
            or owner["baseMeasurementBefore"] != owner["baseMeasurementAfter"]
            or not isinstance(owner["vmName"], str)
            or not re.fullmatch(r"softnet-canary-[a-f0-9]{32}", owner["vmName"])
            or not isinstance(owner["guestRoot"], str) or not GUEST_ROOT.fullmatch(owner["guestRoot"])
            or any(not isinstance(owner.get(key), str) or not re.fullmatch(r"[a-f0-9]{64}", owner[key])
                   for key in ("downloadReceiptSha256", "bundleSha256", "inventorySha256", "admissionSha256"))
            or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", owner.get("macAddress", ""))
            or not re.fullmatch(r"[a-f0-9]{32}", owner.get("runId", ""))):
        raise canary.CanaryError("invalid_owner_receipt")
    for key in ("baseMeasurementBefore", "baseMeasurementAfter", "preDownloadMeasurement", "postDownloadMeasurement"):
        measurement = owner[key]
        if (type(measurement) is not dict or set(measurement) != {"configBytes", "configSha256", "diskBytes", "diskSha256", "nvramBytes", "nvramSha256"}
                or any(type(measurement[k]) is not int or measurement[k] <= 0 for k in ("configBytes", "diskBytes", "nvramBytes"))
                or any(not isinstance(measurement[k], str)
                       or not re.fullmatch(r"[a-f0-9]{64}", measurement[k])
                       for k in ("configSha256", "diskSha256", "nvramSha256"))):
            raise canary.CanaryError("invalid_owner_measurement")
    before, pre, post = (owner[key] for key in ("baseMeasurementBefore", "preDownloadMeasurement", "postDownloadMeasurement"))
    if (pre["diskBytes"] != before["diskBytes"] or pre["diskSha256"] != before["diskSha256"]
            or pre["nvramBytes"] != before["nvramBytes"] or pre["nvramSha256"] != before["nvramSha256"]
            or pre["configBytes"] != post["configBytes"] or pre["configSha256"] != post["configSha256"]):
        raise canary.CanaryError("owner_measurement_relationship_invalid")
    manifest_raw = downloads._read_regular(Path(root) / downloads.MANIFEST, downloads.MAX_MANIFEST_BYTES)
    manifest = downloads._json_no_duplicates(manifest_raw)
    downloads._validate_manifest(manifest)
    if hashlib.sha256(manifest_raw).hexdigest() != downloads.MANIFEST_SHA256:
        raise canary.CanaryError("manifest_pin_mismatch")
    input_raw = json.dumps({"guestRoot": owner["guestRoot"], "manifestSha256": downloads.MANIFEST_SHA256,
                            "ownerReceiptSha256": hashlib.sha256(owner_raw).hexdigest(),
                            "postDownloadMeasurement": owner["postDownloadMeasurement"]},
                           sort_keys=True, separators=(",", ":")).encode()
    paths = {"probe": Path(__file__).resolve(), "canary": Path(canary.__file__).resolve(),
             "manifest": Path(root) / downloads.MANIFEST, "input": input_raw}
    # Keep the approved exact source set while using the shared hardened loader.
    source_paths = {key: value for key, value in paths.items() if key != "input"}
    bundle = shared._build_source_bundle(
        {"probe": SOURCE_FILES["probe"], "canary": SOURCE_FILES["canary"], "manifest": SOURCE_FILES["manifest"]},
        source_paths, error_prefix="native_provisioning_inspection",
        max_source_bytes=256 * 1024, max_bundle_arg=128 * 1024)
    files = {"native_workspace_provisioning_inspection_probe.py": Path(__file__).read_bytes(),
             "qualify_offline_macos_vm.py": Path(canary.__file__).read_bytes(),
             "manifest.json": manifest_raw, "inspection-input.json": input_raw}
    # The additional fixed input is folded into the same canonical checked bundle.
    packed = {name: {"sha256": hashlib.sha256(data).hexdigest(), "content": base64.b64encode(data).decode("ascii")}
              for name, data in files.items()}
    raw_bundle = json.dumps(packed, sort_keys=True, separators=(",", ":")).encode()
    encoded = base64.b64encode(zlib.compress(raw_bundle, 9))
    if len(raw_bundle) > 256 * 1024 or len(encoded) > 128 * 1024:
        raise canary.CanaryError("native_provisioning_inspection_bundle_oversized")
    from scpreferences_guest_probe import _source_loader
    bundle["argument"] = encoded.decode("ascii")
    bundle["sourceSha256"] = {key: value["sha256"] for key, value in packed.items()}
    bundle["bundleSha256"] = hashlib.sha256(encoded).hexdigest()
    bundle["loader"] = _source_loader(set(files), "native_workspace_provisioning_inspection_probe",
                                      "collect_guest", "native-provision-inspection-", guest_setup=(
        "os.environ.clear()\nos.environ.update(" + repr(ENV) + ")\nsys.dont_write_bytecode = True"))
    bundle.update(baseVmName=owner["vmName"], guestRoot=owner["guestRoot"],
                  ownerReceiptSha256=hashlib.sha256(owner_raw).hexdigest(),
                  postDownloadMeasurement=owner["postDownloadMeasurement"],
                  manifestSha256=downloads.MANIFEST_SHA256,
                  expectedAssets={asset["name"]: {"sha256": asset["sha256"],
                                                  "maxBytes": asset["maxBytes"]}
                                  for asset in manifest["assets"]})
    return bundle


def command_template(tart, vm, loader, argument="<fixed-source-bundle-b64>"):
    fixed = [key + "=" + value for key, value in ENV.items()]
    return [str(tart), "exec", vm, "/usr/bin/sudo", "-n", "-u", "admin", "-g", "staff", "--",
            "/usr/bin/env", "-i", *fixed, "/usr/bin/python3", "-I", "-B", "-c", loader, argument]


def collect(tart, vm, env, evidence, bundle, *, run_bounded=None, cancel_check=None):
    runner = canary._run_bounded if run_bounded is None else run_bounded
    if (type(bundle) is not dict or not isinstance(vm, str)
            or not re.fullmatch(r"offline-canary-[a-f0-9]{32}", vm)
            or not GUEST_ROOT.fullmatch(bundle.get("guestRoot", ""))):
        raise canary.CanaryError("inspection_bundle_binding_mismatch")
    stdout_path, stderr_path = (Path(evidence) / name for name in LOG_NAMES)
    argv = command_template(tart, vm, bundle["loader"], bundle["argument"])
    stdout, stderr = runner(argv, timeout=TIMEOUT, env=env, output_limit=MAX_REPORT_BYTES,
                            capture_paths=(stdout_path, stderr_path), cancel_check=cancel_check)
    if len(stdout) > MAX_REPORT_BYTES or stderr:
        raise canary.CanaryError("inspection_output_invalid")
    try:
        report = json.loads(stdout)
    except (ValueError, UnicodeError, RecursionError):
        raise canary.CanaryError("inspection_report_invalid") from None
    if (type(report) is not dict or report.get("kind") != KIND or report.get("status") != "passed"
            or report.get("qualified") is not False or report.get("prepared") is not False
            or report.get("manifestSha256") != bundle["manifestSha256"]
            or report.get("ownerReceiptSha256") != bundle["ownerReceiptSha256"]
            or report.get("postDownloadMeasurement") != bundle["postDownloadMeasurement"]
            or report.get("complete") is not True or type(report.get("assets")) is not list):
        raise canary.CanaryError("inspection_report_unqualified")
    expected_assets = bundle.get("expectedAssets")
    rows = report["assets"]
    if (type(expected_assets) is not dict or len(rows) != len(expected_assets)
            or any(type(row) is not dict for row in rows)):
        raise canary.CanaryError("inspection_report_assets_invalid")
    actual_assets = {row.get("name"): row for row in rows}
    if len(actual_assets) != len(rows) or set(actual_assets) != set(expected_assets):
        raise canary.CanaryError("inspection_report_assets_mismatch")
    for name, expected in expected_assets.items():
        row = actual_assets[name]
        if (row.get("sha256") != expected["sha256"] or type(row.get("bytes")) is not int
                or row["bytes"] < 0 or row["bytes"] > expected["maxBytes"]):
            raise canary.CanaryError("inspection_report_asset_binding_mismatch")
        if name.endswith((".tar.gz", ".tgz", ".tar.xz", ".txz")):
            archive = row.get("archive")
            if (type(archive) is not dict or archive.get("complete") is not True
                    or archive.get("status") != "present"
                    or not re.fullmatch(r"[a-f0-9]{64}", archive.get("inventorySha256", ""))):
                raise canary.CanaryError("inspection_report_archive_incomplete")
        if name.startswith("channel-rust-") and not isinstance(row.get("textMetadata"), str):
            raise canary.CanaryError("inspection_report_rust_metadata_missing")
    homebrew = report.get("homebrew")
    if type(homebrew) is not dict or homebrew.get("state") != "present":
        raise canary.CanaryError("inspection_report_local_state_incomplete")
    return {"kind": KIND, "status": "passed", "qualified": False, "prepared": False,
            "complete": report["complete"], "baseVmName": bundle["baseVmName"],
            "guestRoot": bundle["guestRoot"], "ownerReceiptSha256": bundle["ownerReceiptSha256"],
            "postDownloadMeasurement": bundle["postDownloadMeasurement"],
            "manifestSha256": bundle["manifestSha256"], "sourceSha256": bundle["sourceSha256"],
            "bundleSha256": bundle["bundleSha256"], "report": report,
            "reportRawSha": hashlib.sha256(stdout).hexdigest(),
            "reportRawSha256": hashlib.sha256(stdout).hexdigest(),
            "stdoutEvidence": str(stdout_path), "stderrEvidence": str(stderr_path)}

