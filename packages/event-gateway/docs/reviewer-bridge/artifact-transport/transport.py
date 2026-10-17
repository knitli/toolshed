"""Dormant, offline-qualified artifact transport; no live HTTP adapter or CLI."""

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import time
from urllib.parse import urlsplit
import zipfile

_API = "https://api.github.com"
_DOWNLOAD_HOSTS = (
    frozenset()
)  # Root must freeze an observed exact host before activation.
_REUSABLE = "knitli/.github/.github/workflows/claude-pr-reviewer.yml"
_CALLER = ".github/workflows/reviewer-host-qualification.yml"
_PRODUCER = {"completion.json": 65536, "envelope.json": 65536, "snapshot.json": 65536}
_SEALED = {"reviewer-host-handoff.json": 4096, "attestation.sigstore.json": 2097152}
_ARCHIVE_LIMIT = 3 * 1024 * 1024
_JSON_LIMIT = 512 * 1024


class Refused(ValueError):
    """Fixed errors never disclose authentication tokens or signed URLs."""


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def positive(value):
    return type(value) is int and 0 < value < 2**53


@dataclass(frozen=True)
class Response:
    """Trusted bounded seam response. Body must already obey request ceiling."""

    url: str
    status: int
    headers: dict
    body: bytes


@dataclass(frozen=True)
class Bundle:
    directory: Path
    handoff_bytes: bytes
    attestation_bytes: bytes


def policy_of(value):
    keys = {
        "repository",
        "repositoryId",
        "runId",
        "runAttempt",
        "workflowSha",
        "sourceHeadSha",
    }
    need(type(value) is dict and set(value) == keys, "policy")
    p = dict(value)
    need(
        p["repository"] == "knitli/knitli-site"
        and p["repositoryId"] == 1058277548
        and type(p["repositoryId"]) is int,
        "repository_policy",
    )
    for key in ("runId", "runAttempt"):
        need(
            type(p[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", p[key]),
            "run_policy",
        )
    for key in ("workflowSha", "sourceHeadSha"):
        need(
            type(p[key]) is str and re.fullmatch(r"[a-f0-9]{40}", p[key]), "sha_policy"
        )
    need(
        p["workflowSha"] == "711e265cc280cad7c4a44ba6d2d72f40a1378fec",
        "reusable_policy",
    )
    return p


def _json(body):
    def pairs(values):
        result = {}
        for key, value in values:
            need(key not in result, "duplicate_json_key")
            result[key] = value
        return result

    try:
        result = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(Refused("json_number")),
        )
    except (ValueError, UnicodeError, RecursionError):
        raise Refused("json") from None
    need(type(result) is dict, "json_object")
    return result


def _instant(value):
    need(
        type(value) is str
        and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value),
        "timestamp",
    )
    try:
        return (
            datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
            .replace(tzinfo=timezone.utc)
            .timestamp()
        )
    except ValueError:
        raise Refused("timestamp") from None


def _unzip(data, limits, total_limit):
    """Bound structure before ZipFile allocates entries, then bounded decompression."""
    need(type(data) is bytes and 22 <= len(data) <= _ARCHIVE_LIMIT, "zip_size")
    need(data[-22:-18] == b"PK\x05\x06", "zip_eocd")
    disk, start_disk, disk_count, count, central_size, offset, comment = struct.unpack(
        "<4H2LH", data[-18:]
    )
    need(
        disk == start_disk == comment == 0 and disk_count == count == len(limits),
        "zip_directory",
    )
    need(
        offset + central_size == len(data) - 22 and data[:4] == b"PK\x03\x04",
        "zip_layout",
    )
    # ZipFile trusts central size rather than EOCD count: preflight each bounded
    # record before allowing its parser to allocate ZipInfo objects.
    position = offset
    for _ in range(count):
        record = data[position : position + 46]
        need(len(record) == 46 and record[:4] == b"PK\x01\x02", "zip_central")
        name_length, extra_length, comment_length = struct.unpack("<3H", record[28:34])
        need(
            0 < name_length <= 32 and extra_length == comment_length == 0, "zip_central"
        )
        position += 46 + name_length
    need(position == len(data) - 22, "zip_central")
    result = {}
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            need(len(entries) == len(limits), "zip_entries")
            next_offset = 0
            for entry in entries:
                name = entry.filename
                need(
                    name in limits
                    and name not in result
                    and entry.orig_filename == name,
                    "zip_path",
                )
                need(
                    entry.header_offset == next_offset
                    and not entry.extra
                    and not entry.comment,
                    "zip_entry_layout",
                )
                need(
                    entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                    and entry.flag_bits & ~(0x800 | 8) == 0,
                    "zip_encoding",
                )
                mode = entry.external_attr >> 16
                need(
                    stat.S_IFMT(mode) in (0, stat.S_IFREG)
                    and not (entry.external_attr & 0x10),
                    "zip_type",
                )
                need(
                    0 < entry.file_size <= limits[name]
                    and 0 < entry.compress_size <= _ARCHIVE_LIMIT,
                    "zip_entry_size",
                )
                # Reject local extra fields, mismatched names/flags, preambles and hidden data.
                header = data[entry.header_offset : entry.header_offset + 30]
                need(len(header) == 30 and header[:4] == b"PK\x03\x04", "zip_local")
                fields = struct.unpack("<5H3L2H", header[4:])
                _, flags, method, _, _, crc, compressed, size, name_len, extra_len = (
                    fields
                )
                name_bytes = name.encode("ascii")
                need(
                    flags == entry.flag_bits
                    and method == entry.compress_type
                    and extra_len == 0
                    and name_len == len(name_bytes)
                    and data[
                        entry.header_offset + 30 : entry.header_offset + 30 + name_len
                    ]
                    == name_bytes,
                    "zip_local",
                )
                if not flags & 8:
                    need(
                        (crc, compressed, size)
                        == (entry.CRC, entry.compress_size, entry.file_size),
                        "zip_local_size",
                    )
                else:
                    need(
                        (crc, compressed, size)
                        in (
                            (0, 0, 0),
                            (entry.CRC, entry.compress_size, entry.file_size),
                        ),
                        "zip_descriptor",
                    )
                next_offset = entry.header_offset + 30 + name_len + entry.compress_size
                if flags & 8:
                    descriptor = data[next_offset : next_offset + 16]
                    need(
                        len(descriptor) == 16
                        and descriptor[:4] == b"PK\x07\x08"
                        and struct.unpack("<3L", descriptor[4:])
                        == (entry.CRC, entry.compress_size, entry.file_size),
                        "zip_descriptor",
                    )
                    next_offset += 16
                need(next_offset <= offset, "zip_overlap")
                with archive.open(entry) as stream:
                    value = stream.read(limits[name] + 1)
                    need(
                        len(value) == entry.file_size and not stream.read(1),
                        "zip_inflate",
                    )
                result[name] = value
                need(sum(map(len, result.values())) <= total_limit, "zip_total")
            need(next_offset == offset and set(result) == set(limits), "zip_complete")
    except (
        zipfile.BadZipFile,
        RuntimeError,
        NotImplementedError,
        EOFError,
        OSError,
        struct.error,
    ):
        raise Refused("zip_invalid") from None
    return result


class _Transport:
    def __init__(self, policy, token, request):
        self.p = policy_of(policy)
        need(
            type(token) is str
            and 1 <= len(token) <= 4096
            and all(33 <= ord(char) <= 126 for char in token),
            "token",
        )
        need(callable(request), "request")
        self.token, self.request = token, request
        self.deadline = time.monotonic() + 60
        self.wall_start = time.time()
        self.base = f"/repos/{self.p['repository']}/actions"
        self.run = f"{self.base}/runs/{self.p['runId']}"
        self.calls = 0
        self.transferred = 0

    def call(self, url, *, api=True, limit=_JSON_LIMIT, status=200):
        self.calls += 1
        need(self.calls <= 32 and time.monotonic() < self.deadline, "request_budget")
        if api:
            need(url.startswith(_API + self.base + "/"), "api_origin")
        headers = {
            "Accept": "application/vnd.github+json"
            if api
            else "application/octet-stream",
            "Accept-Encoding": "identity",
        }
        if api:
            headers.update(
                {
                    "Authorization": f"Bearer {self.token}",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
            )
        try:
            response = self.request(
                url, headers=headers, maximum=limit, deadline=self.deadline
            )
        except Exception:
            raise Refused("request_failed") from None
        need(
            time.monotonic() < self.deadline and time.time() >= self.wall_start,
            "request_deadline",
        )
        need(
            type(response) is Response
            and response.url == url
            and type(response.status) is int
            and response.status == status
            and type(response.body) is bytes
            and len(response.body) <= limit
            and type(response.headers) is dict,
            "response",
        )
        lowered = {}
        for key, value in response.headers.items():
            need(
                type(key) is str
                and type(value) is str
                and key.lower() not in lowered
                and len(key) <= 256
                and len(value) <= 8192,
                "headers",
            )
            lowered[key.lower()] = value
        need(
            len(lowered) <= 64
            and lowered.get("content-encoding", "identity") == "identity",
            "headers",
        )
        if "content-length" in lowered:
            length = lowered["content-length"]
            need(
                re.fullmatch(r"0|[1-9][0-9]{0,9}", length)
                and int(length) == len(response.body),
                "content_length",
            )
        self.transferred += len(response.body)
        need(self.transferred <= 12 * 1024 * 1024, "transfer_budget")
        return response.body, lowered

    def get(self, path):
        body, _ = self.call(_API + path)
        return _json(body)

    def run_snapshot(self):
        values = []
        for path in (f"{self.run}/attempts/{self.p['runAttempt']}", self.run):
            run = self.get(path)
            repository = run.get("repository", {})
            need(type(repository) is dict, "run_repository")
            references = run.get("referenced_workflows")
            need(type(references) is list and len(references) <= 20, "run_references")
            matches = [
                r
                for r in references
                if type(r) is dict
                and type(r.get("path")) is str
                and r["path"].split("@")[0] == _REUSABLE
            ]
            need(
                str(run.get("id")) == self.p["runId"]
                and str(run.get("run_attempt")) == self.p["runAttempt"]
                and positive(run.get("id"))
                and positive(run.get("run_attempt"))
                and repository.get("id") == self.p["repositoryId"]
                and repository.get("full_name") == self.p["repository"]
                and repository.get("private") is True
                and run.get("status") == "completed"
                and run.get("conclusion") == "success"
                and run.get("event") == "workflow_dispatch"
                and run.get("head_branch") == "main"
                and run.get("head_sha") == self.p["sourceHeadSha"]
                and run.get("path") == _CALLER
                and len(matches) == 1
                and matches[0].get("sha") == self.p["workflowSha"],
                "source_run",
            )
            values.append(run)
        return values

    def artifact(self, value, name):
        need(type(value) is dict, "artifact")
        run = value.get("workflow_run", {})
        need(type(run) is dict, "artifact_run")
        need(
            positive(value.get("id"))
            and value.get("name") == name
            and value.get("expired") is False
            and positive(value.get("size_in_bytes"))
            and value["size_in_bytes"] <= _ARCHIVE_LIMIT
            and type(value.get("digest")) is str
            and re.fullmatch(r"sha256:[a-f0-9]{64}", value["digest"])
            and str(run.get("id")) == self.p["runId"]
            and positive(run.get("id"))
            and run.get("repository_id") == self.p["repositoryId"]
            and run.get("head_repository_id") == self.p["repositoryId"]
            and run.get("head_branch") == "main"
            and run.get("head_sha") == self.p["sourceHeadSha"],
            "artifact_identity",
        )
        need(_instant(value.get("expires_at")) > time.time(), "artifact_expired")
        need(
            _instant(value.get("created_at"))
            <= _instant(value.get("updated_at"))
            < _instant(value.get("expires_at"))
            and _instant(value.get("updated_at")) <= time.time(),
            "artifact_time",
        )
        # Compare the complete metadata, not response-selected download URLs.
        return value

    def select(self):
        names = [
            f"reviewer-host-{kind}-{self.p['runId']}-{self.p['runAttempt']}"
            for kind in ("producer", "sealed")
        ]
        artifacts, total = [], None
        for page in range(1, 5):
            result = self.get(f"{self.run}/artifacts?per_page=100&page={page}")
            count, items = result.get("total_count"), result.get("artifacts")
            need(
                type(count) is int
                and 2 <= count <= 400
                and type(items) is list
                and len(items) <= 100,
                "artifact_listing",
            )
            need(total is None or total == count, "artifact_listing_changed")
            total = count
            need(
                all(type(item) is dict and positive(item.get("id")) for item in items),
                "artifact_listing",
            )
            artifacts.extend(items)
            need(
                len({item["id"] for item in artifacts}) == len(artifacts),
                "artifact_duplicates",
            )
            if len(artifacts) == total:
                break
            need(len(artifacts) < total and len(items) == 100, "artifact_pagination")
        need(len(artifacts) == total, "artifact_pagination")
        selected = []
        for name in names:
            matches = [item for item in artifacts if item.get("name") == name]
            need(len(matches) == 1, "artifact_name")
            selected.append(self.artifact(matches[0], name))
        return selected

    def download(self, metadata):
        path = f"{self.base}/artifacts/{metadata['id']}"
        need(
            self.artifact(self.get(path), metadata["name"]) == metadata,
            "artifact_changed",
        )
        _, headers = self.call(_API + path + "/zip", limit=4096, status=302)
        location = headers.get("location", "")
        need(
            type(location) is str
            and len(location) <= 8192
            and all(33 <= ord(c) <= 126 for c in location),
            "redirect",
        )
        try:
            url = urlsplit(location)
            need(
                url.scheme == "https"
                and url.hostname in _DOWNLOAD_HOSTS
                and url.netloc == url.hostname
                and not url.fragment
                and url.path.startswith("/")
                and url.query,
                "redirect_host",
            )
        except ValueError:
            raise Refused("redirect") from None
        data, _ = self.call(location, api=False, limit=metadata["size_in_bytes"])
        need(
            len(data) == metadata["size_in_bytes"]
            and "sha256:" + hashlib.sha256(data).hexdigest() == metadata["digest"],
            "archive_digest",
        )
        return data


def _private_parent(parent):
    """Require a physical private leaf beneath trusted, non-replaceable ancestors."""
    # Match the launcher owner/write boundary; sticky exceptions are restricted
    # to the two fixed system temporary roots. Same-UID adversaries are outside
    # this host-owned preparation boundary.
    need(isinstance(parent, Path) and parent.is_absolute(), "scratch_parent")
    try:
        need(parent.resolve(strict=True) == parent, "scratch_parent_alias")
        for directory in (parent, *parent.parents):
            info = directory.lstat()
            need(stat.S_ISDIR(info.st_mode), "scratch_parent_type")
            if directory == parent:
                need(
                    info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                    "scratch_parent_private",
                )
            else:
                sticky_root = (
                    directory in (Path("/private/tmp"), Path("/tmp"))
                    and info.st_uid == 0
                    and bool(info.st_mode & stat.S_ISVTX)
                )
                need(
                    info.st_uid in (0, os.getuid())
                    and (not info.st_mode & 0o022 or sticky_root),
                    "scratch_ancestor",
                )
    except OSError:
        raise Refused("scratch_parent") from None


@contextmanager
def transport(policy, token, request, parent):
    """Yield temporary transport bytes only; unchanged signed acquisition must follow."""
    host = _Transport(policy, token, request)
    _private_parent(parent)
    with tempfile.TemporaryDirectory(
        prefix="reviewer-artifact-", dir=parent
    ) as scratch:
        before = host.run_snapshot()
        selected = host.select()
        producer = _unzip(host.download(selected[0]), _PRODUCER, 128 * 1024)
        sealed = _unzip(host.download(selected[1]), _SEALED, sum(_SEALED.values()))
        need(host.select() == selected, "artifacts_changed")
        for artifact in selected:
            path = f"{host.base}/artifacts/{artifact['id']}"
            need(
                host.artifact(host.get(path), artifact["name"]) == artifact,
                "artifact_changed",
            )
        need(host.run_snapshot() == before, "source_changed")
        directory = Path(scratch) / "producer"
        directory.mkdir(mode=0o700)
        for name, value in producer.items():
            with (directory / name).open("xb") as stream:
                stream.write(value)
            (directory / name).chmod(0o600)
        for artifact in selected:
            host.artifact(artifact, artifact["name"])
        need(
            time.monotonic() < host.deadline and time.time() >= host.wall_start,
            "request_deadline",
        )
        yield Bundle(
            directory,
            sealed["reviewer-host-handoff.json"],
            sealed["attestation.sigstore.json"],
        )
