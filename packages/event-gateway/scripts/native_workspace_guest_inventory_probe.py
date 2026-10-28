"""Fixed, read-only native workspace inventory for a prepared macOS guest."""

import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import stat
import sys
import time

import qualify_offline_macos_vm as canary

KIND = "native-workspace-guest-inventory-v1"
SOURCE_FILES = {"inventory": "native_workspace_guest_inventory_probe.py",
                "canary": "qualify_offline_macos_vm.py"}
MAX_SOURCE_BYTES = 256 * 1024
MAX_BUNDLE_ARG = 128 * 1024
MAX_REPORT_BYTES = 16 * 1024
MAX_COMMAND_BYTES = 2048
MAX_COMMAND_SECONDS = 2
GUEST_BUDGET_SECONDS = 24
MAX_CANDIDATES = 8
MAX_SCAN_ENTRIES = 4096
SCAN_SECONDS = 2
FIXED_ENV = {
    "HOME": "/Users/admin", "USER": "admin", "LOGNAME": "admin",
    "PATH": "/Users/admin/.cargo/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
    "CARGO_HOME": "/Users/admin/.cargo", "RUSTUP_HOME": "/Users/admin/.rustup",
    "CARGO_NET_OFFLINE": "true", "RUSTUP_AUTO_INSTALL": "0",
    "RUSTUP_NO_UPDATE_CHECK": "1", "HOMEBREW_NO_AUTO_UPDATE": "1",
    "HOMEBREW_NO_INSTALL_CLEANUP": "1", "PYTHONDONTWRITEBYTECODE": "1",
    "LC_ALL": "C", "LANG": "C",
}
TOOL_PATH = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
TOOL_ARGS = {name: ("--version",) for name in ("just", "genv", "gtimeout", "pkg-config", "git")}
MODULES = ("glib-2.0", "gobject-2.0", "gstreamer-1.0", "gstreamer-base-1.0",
           "gstreamer-app-1.0", "gstreamer-audio-1.0")
RUST_TOOLCHAIN = "/Users/admin/.rustup/toolchains/1.95.0-aarch64-apple-darwin"


def build_bundle():
    import scpreferences_guest_probe as shared
    paths = {"inventory": Path(__file__).resolve(), "canary": Path(canary.__file__).resolve()}
    bundle = shared._build_source_bundle(
        SOURCE_FILES, paths, error_prefix="native_guest_inventory",
        max_source_bytes=MAX_SOURCE_BYTES, max_bundle_arg=MAX_BUNDLE_ARG)
    bundle["loader"] = shared._source_loader(
        set(SOURCE_FILES.values()), "native_workspace_guest_inventory_probe", "collect_guest",
        "native-guest-inventory-")
    return bundle


def command_template(tart_path, vm_name, loader):
    fixed = [key + "=" + value for key, value in FIXED_ENV.items()]
    return [str(tart_path), "exec", vm_name, "/usr/bin/sudo", "-n", "-u", "admin",
            "-g", "staff", "--", "/usr/bin/env", "-i", *fixed,
            "/usr/bin/python3", "-I", "-c", loader, "<fixed-source-bundle-b64>"]


def _source_hashes():
    return {key: canary._hash_file(Path(__file__).resolve() if key == "inventory"
                                    else Path(canary.__file__).resolve(),
                                    maximum=MAX_SOURCE_BYTES)[0]
            for key in SOURCE_FILES}


def _run(argv, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {"state": "budget_exhausted", "version": None}
    try:
        out, _ = canary._run_bounded(
            list(argv), timeout=min(MAX_COMMAND_SECONDS, remaining), env=dict(FIXED_ENV),
            output_limit=MAX_COMMAND_BYTES)
        value = out.decode("utf-8").strip()
        return {"state": "present", "version": value if len(value) <= MAX_COMMAND_BYTES else None}
    except UnicodeError:
        return {"state": "unsupported", "version": None, "errorCode": "invalid_utf8"}
    except PermissionError:
        return {"state": "inaccessible", "version": None, "errorCode": "permission_denied"}
    except FileNotFoundError:
        return {"state": "missing", "version": None, "errorCode": "command_missing"}
    except OSError:
        return {"state": "inaccessible", "version": None, "errorCode": "command_io_error"}
    except canary.CanaryError as exc:
        code = str(exc.args[0]) if exc.args else "probe_failed"
        return {"state": "unsupported", "version": None, "errorCode": code}


def _metadata(path):
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {"state": "missing"}
    except OSError:
        return {"state": "inaccessible"}
    if stat.S_ISLNK(info.st_mode):
        return {"state": "unsupported", "mode": stat.S_IMODE(info.st_mode)}
    return {"state": "present", "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode),
            "sizeBytes": info.st_size}


def _shallow_inventory(path, deadline):
    result = _metadata(path)
    result.update(bytesObserved=0, entriesObserved=0, scanComplete=False)
    if result["state"] != "present":
        return result
    stop = min(deadline, time.monotonic() + SCAN_SECONDS)
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                if result["entriesObserved"] >= MAX_SCAN_ENTRIES or time.monotonic() >= stop:
                    result["state"] = "scan_capped"
                    return result
                result["entriesObserved"] += 1
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISREG(info.st_mode):
                    result["bytesObserved"] += info.st_size
    except OSError:
        result["state"] = "inaccessible"
        return result
    # A shallow scan deliberately does not measure files inside child directories.
    return result


def _python_roots(deadline):
    roots = ["/opt/homebrew/bin", "/opt/homebrew/opt/python/bin"]
    scanned, capped = 0, False
    try:
        with os.scandir("/opt/homebrew/opt") as entries:
            for entry in entries:
                if scanned >= MAX_SCAN_ENTRIES or time.monotonic() >= deadline:
                    capped = True
                    break
                scanned += 1
                if re.fullmatch(r"python@3\.\d+", entry.name):
                    roots.append(entry.path + "/bin")
    except FileNotFoundError:
        pass
    except OSError:
        capped = True
    return roots, scanned, capped


def _scan_python_root(root, candidates, seen, scanned, deadline):
    capped = False
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if scanned >= MAX_SCAN_ENTRIES or time.monotonic() >= deadline:
                    return scanned, True
                scanned += 1
                if not re.fullmatch(r"python3(?:\.\d+)?", entry.name):
                    continue
                resolved = os.path.realpath(entry.path)
                if resolved in seen:
                    continue
                seen.add(resolved)
                candidates.append((entry.path, resolved))
                if len(candidates) >= MAX_CANDIDATES:
                    return scanned, True
    except FileNotFoundError:
        pass
    except OSError:
        capped = True
    return scanned, capped


def _scan_python_roots(roots, deadline, scanned, capped):
    candidates, seen = [], set()
    for root in roots:
        if len(candidates) >= MAX_CANDIDATES or time.monotonic() >= deadline:
            capped = True
            break
        scanned, root_capped = _scan_python_root(root, candidates, seen, scanned, deadline)
        capped |= root_capped
        if root_capped and len(candidates) >= MAX_CANDIDATES:
            break
    return candidates, capped


def _python_candidates(deadline):
    roots, scanned, capped = _python_roots(deadline)
    candidates, capped = _scan_python_roots(roots, deadline, scanned, capped)
    rows = [{"path": sys.executable, **_run(["/usr/bin/python3", "--version"], deadline)}]
    for path, resolved in candidates:
        rows.append({"path": path, "canonicalPath": resolved,
                     **_run([path, "--version"], deadline)})
    return {"state": "scan_capped" if capped else "present", "items": rows}


def _tool_path(name):
    return shutil.which(name, path=TOOL_PATH)


def _fixed_tool(name, deadline):
    path = _tool_path(name)
    if path is None:
        return {"state": "missing", "path": None, "version": None}
    # Avoid Apple's CLT placeholder; it can launch an installer prompt.
    if name == "git" and path == "/usr/bin/git":
        return {"state": "unsupported", "path": path, "version": None,
                "errorCode": "apple_git_not_invoked"}
    return {"path": path, **_run([path, *TOOL_ARGS[name]], deadline)}


def _direct_tool(path, args, deadline):
    try:
        info = os.lstat(path)
        resolved = os.path.realpath(path)
        if (not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK)
                or os.path.basename(resolved) == "rustup"):
            return {"state": "unsupported", "path": path, "version": None,
                    "errorCode": "not_direct_tool"}
    except FileNotFoundError:
        return {"state": "missing", "path": path, "version": None}
    except PermissionError:
        return {"state": "inaccessible", "path": path, "version": None}
    except OSError:
        return {"state": "inaccessible", "path": path, "version": None}
    try:
        rustup = os.stat("/Users/admin/.cargo/bin/rustup")
        if (info.st_dev, info.st_ino) == (rustup.st_dev, rustup.st_ino):
            return {"state": "unsupported", "path": path, "version": None,
                    "errorCode": "not_direct_tool"}
    except OSError:
        pass
    return {"path": path, **_run([path, *args], deadline)}


def _rust_tools(deadline):
    return {"rustc": _direct_tool(RUST_TOOLCHAIN + "/bin/rustc", ("--version", "--verbose"), deadline),
            "cargo": _direct_tool(RUST_TOOLCHAIN + "/bin/cargo", ("--version",), deadline),
            "cargoNextest": _direct_tool("/Users/admin/.cargo/bin/cargo-nextest", ("--version",), deadline)}


def _xcode_sdk_roots(deadline):
    roots = [("clt", "/Library/Developer/CommandLineTools/SDKs")]
    scanned, capped = 0, False
    try:
        with os.scandir("/Applications") as entries:
            for entry in entries:
                if scanned >= 64 or time.monotonic() >= deadline:
                    capped = True
                    break
                scanned += 1
                if entry.name.startswith("Xcode") and entry.name.endswith(".app"):
                    roots.append(("xcode", entry.path + "/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs"))
    except FileNotFoundError:
        pass
    except OSError:
        capped = True
    if len(roots) > 5:
        capped = True
    return roots[:5], capped


def _sdk_location(label, root, deadline):
    sdks, count, capped = [], 0, False
    state = "present"
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if count >= 32 or time.monotonic() >= deadline:
                    state, capped = "scan_capped", True
                    break
                count += 1
                if not re.fullmatch(r"MacOSX[^/]*\.sdk", entry.name):
                    continue
                plist = Path(entry.path) / "SDKSettings.plist"
                try:
                    _, _, raw = canary._hash_file(plist, maximum=16 * 1024, collect=True)
                    data = plistlib.loads(raw)
                    if type(data) is not dict:
                        raise ValueError("invalid_sdk_settings")
                    version, canonical = data.get("Version"), data.get("CanonicalName")
                    if (type(version) is not str or len(version) > 64
                            or type(canonical) is not str or len(canonical) > 64):
                        raise ValueError("invalid_sdk_settings")
                    sdks.append({"state": "present", "version": version,
                                 "canonicalName": canonical})
                except (OSError, ValueError, canary.CanaryError):
                    sdks.append({"state": "unsupported"})
    except FileNotFoundError:
        state = "missing"
    except OSError:
        state = "inaccessible"
    return {"label": label, "state": state, "sdks": sdks}, capped


def _sdk_inventory(deadline):
    roots, capped = _xcode_sdk_roots(deadline)
    result = []
    for label, root in roots:
        location, root_capped = _sdk_location(label, root, deadline)
        result.append(location)
        capped |= root_capped
    receipt = _run(["/usr/sbin/pkgutil", "--pkg-info", "com.apple.pkg.CLTools_Executables"], deadline)
    version = re.search(r"(?m)^version:\s*(\S+)$", receipt.get("version") or "")
    receipt["version"] = version.group(1) if version else None
    if receipt["state"] == "present" and not version:
        receipt["state"] = "unsupported"
        receipt["errorCode"] = "clt_receipt_version_missing"
    return {"locations": result, "scanCapped": capped, "cltReceipt": receipt}


def collect_guest():
    """Collect only fixed observations after checking the nonroot guest boundary."""
    version = platform.mac_ver()[0]
    if (platform.system() != "Darwin" or not version.startswith("15.")
            or platform.machine() != "arm64"):
        raise ValueError("guest_runtime_invalid")
    if os.geteuid() != 501 or os.getegid() != 20:
        raise ValueError("guest_identity_invalid")
    if set(os.environ) != set(FIXED_ENV) or any(os.environ.get(k) != v for k, v in FIXED_ENV.items()):
        raise ValueError("guest_environment_invalid")
    os.chdir("/private/tmp")
    deadline = time.monotonic() + GUEST_BUDGET_SECONDS
    python = _python_candidates(deadline)
    rust = _rust_tools(deadline)
    tools = {name.replace("-", ""): _fixed_tool(name, deadline) for name in TOOL_ARGS}
    pkg = tools["pkgconfig"].get("path")
    modules = {name: ({"state": "missing", "version": None} if pkg is None else
                      _run([pkg, "--modversion", name], deadline)) for name in MODULES}
    sdk = _sdk_inventory(deadline)
    try:
        usage = shutil.disk_usage("/")
        disk = {"state": "present", "totalBytes": usage.total, "freeBytes": usage.free}
    except OSError:
        disk = {"state": "inaccessible", "totalBytes": None, "freeBytes": None}
    memory = _run(["/usr/sbin/sysctl", "-n", "hw.memsize"], deadline)
    memory_text = memory.get("version")
    memory_bytes = int(memory_text) if memory_text and memory_text.isdigit() else None
    if memory["state"] == "present" and memory_bytes is None:
        memory = dict(memory, state="unsupported", errorCode="invalid_memory_size")
    link = _metadata("/var/db/xcode_select_link")
    report = {
        "kind": KIND, "status": "passed", "collectionOnly": True,
        "prepared": False, "nativeQualified": False,
        "runtime": {"os": platform.system(), "osVersion": version,
                    "osBuild": _run(["/usr/bin/sw_vers", "-buildVersion"], deadline),
                    "architecture": platform.machine(), "pythonPath": sys.executable,
                    "pythonVersion": platform.python_version()},
        "sourceSha256": _source_hashes(), "pythonCandidates": python,
        "rust": {"rustc": rust["rustc"], "cargo": rust["cargo"],
                 "cargoNextest": rust["cargoNextest"],
                 "rustupShim": _metadata("/Users/admin/.cargo/bin/rustup"),
                 "rustlib": _shallow_inventory(RUST_TOOLCHAIN + "/lib/rustlib", deadline)},
        "tools": tools, "pkgConfigModules": modules,
        "sdk": dict(sdk, developerLink=link),
        "resources": {"disk": disk, "memoryBytes": {"state": memory["state"],
                                                        "bytes": memory_bytes,
                                                        "errorCode": memory.get("errorCode")},
                      "cargoHome": _shallow_inventory("/Users/admin/.cargo", deadline),
                      "rustupHome": _shallow_inventory("/Users/admin/.rustup", deadline)},
    }
    if len(json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("inventory_report_oversized")
    return report


_STATES = {"present", "missing", "inaccessible", "unsupported", "budget_exhausted", "scan_capped"}


def _observation(value, *, required, optional=()):
    if (type(value) is not dict or not required.issubset(value)
            or set(value) - required - set(optional)):
        return False
    state = value.get("state")
    if type(state) is not str or state not in _STATES:
        return False
    if "version" in value and (state == "present" and type(value["version"]) is not str
            or state != "present" and value["version"] is not None):
        return False
    for key, limit in (("version", MAX_COMMAND_BYTES), ("path", 512), ("label", 64),
                       ("canonicalPath", 512), ("errorCode", 128)):
        item = value.get(key)
        if key in value and item is not None and (type(item) is not str or len(item) > limit):
            return False
    return True


def _metadata_record(value, *, inventory=False):
    fields = {"state", "uid", "mode", "sizeBytes", "bytesObserved", "entriesObserved", "scanComplete"}
    required = {"state", "bytesObserved", "entriesObserved", "scanComplete"} if inventory else {"state"}
    if (type(value) is not dict or set(value) - fields or not required.issubset(value)
            or type(value.get("state")) is not str or value["state"] not in _STATES):
        return False
    if value["state"] == "present" and not {"uid", "mode", "sizeBytes"}.issubset(value):
        return False
    for key in ("uid", "mode", "sizeBytes", "bytesObserved", "entriesObserved"):
        if key in value and (type(value[key]) is not int or value[key] < 0):
            return False
    if (value.get("uid", 0) > 2**32 - 1 or value.get("mode", 0) > 0o7777
            or value.get("sizeBytes", 0) > 2**63 - 1
            or value.get("bytesObserved", 0) > 2**63 - 1
            or value.get("entriesObserved", 0) > MAX_SCAN_ENTRIES):
        return False
    return "scanComplete" not in value or value["scanComplete"] is False


def _valid_runtime(runtime):
    keys = {"os", "osVersion", "osBuild", "architecture", "pythonPath", "pythonVersion"}
    if type(runtime) is not dict or set(runtime) != keys:
        return False
    if (runtime.get("os") != "Darwin" or type(runtime.get("osVersion")) is not str
            or not runtime["osVersion"].startswith("15.")
            or runtime.get("architecture") != "arm64"):
        return False
    if any(type(runtime.get(key)) is not str or len(runtime[key]) > 512
           for key in ("pythonPath", "pythonVersion")):
        return False
    return _observation(runtime["osBuild"], required={"state", "version"}, optional={"errorCode"})


def _valid_python(python, runtime_path):
    if type(python) is not dict or set(python) != {"state", "items"}:
        return False
    if (type(python["state"]) is not str or python["state"] not in {"present", "scan_capped"}
            or type(python["items"]) is not list
            or not 1 <= len(python["items"]) <= MAX_CANDIDATES + 1):
        return False
    for row in python["items"]:
        if not _observation(row, required={"path", "state", "version"},
                            optional={"canonicalPath", "errorCode"}):
            return False
        if not row["path"] or not row["path"].startswith("/"):
            return False
        if "canonicalPath" in row and (not row["canonicalPath"] or not row["canonicalPath"].startswith("/")):
            return False
    return python["items"][0]["path"] == runtime_path


def _valid_rust(rust):
    keys = {"rustc", "cargo", "cargoNextest", "rustupShim", "rustlib"}
    if type(rust) is not dict or set(rust) != keys:
        return False
    paths = {"rustc": RUST_TOOLCHAIN + "/bin/rustc",
             "cargo": RUST_TOOLCHAIN + "/bin/cargo",
             "cargoNextest": "/Users/admin/.cargo/bin/cargo-nextest"}
    for key, path in paths.items():
        row = rust[key]
        if (not _observation(row, required={"state", "path", "version"}, optional={"errorCode"})
                or row["path"] != path):
            return False
    return (_metadata_record(rust["rustupShim"])
            and _metadata_record(rust["rustlib"], inventory=True))


def _valid_observation_maps(tools, modules):
    if type(tools) is not dict or set(tools) != {name.replace("-", "") for name in TOOL_ARGS}:
        return False
    if type(modules) is not dict or set(modules) != set(MODULES):
        return False
    return all(_observation(row, required={"state", "version"}, optional={"path", "errorCode"})
               for row in list(tools.values()) + list(modules.values()))


def _valid_sdk_item(item):
    if type(item) is not dict or type(item.get("state")) is not str or item["state"] not in _STATES:
        return False
    if item["state"] != "present":
        return set(item) == {"state"}
    return (set(item) == {"state", "version", "canonicalName"}
            and type(item["version"]) is str and len(item["version"]) <= 64
            and type(item["canonicalName"]) is str and len(item["canonicalName"]) <= 64)


def _valid_sdk_location(row):
    if type(row) is not dict or set(row) != {"label", "state", "sdks"}:
        return False
    if (type(row["label"]) is not str or row["label"] not in {"clt", "xcode"}
            or type(row["state"]) is not str or row["state"] not in _STATES
            or type(row["sdks"]) is not list or len(row["sdks"]) > 32):
        return False
    return all(_valid_sdk_item(item) for item in row["sdks"])


def _valid_sdk(sdk):
    keys = {"locations", "scanCapped", "cltReceipt", "developerLink"}
    if type(sdk) is not dict or set(sdk) != keys:
        return False
    locations = sdk["locations"]
    if (type(locations) is not list or len(locations) > 5
            or type(sdk["scanCapped"]) is not bool):
        return False
    if not all(_valid_sdk_location(row) for row in locations):
        return False
    if not locations or locations[0]["label"] != "clt":
        return False
    return (_observation(sdk["cltReceipt"], required={"state", "version"}, optional={"errorCode"})
            and _metadata_record(sdk["developerLink"]))


def _valid_disk(disk):
    keys = {"state", "totalBytes", "freeBytes"}
    if type(disk) is not dict or set(disk) != keys:
        return False
    if type(disk["state"]) is not str or disk["state"] not in _STATES:
        return False
    values = (disk["totalBytes"], disk["freeBytes"])
    if any(value is not None and (type(value) is not int or value < 0 or value > 2**63 - 1)
           for value in values):
        return False
    return disk["state"] != "present" or all(type(value) is int for value in values)


def _valid_resources(resources):
    keys = {"disk", "memoryBytes", "cargoHome", "rustupHome"}
    if type(resources) is not dict or set(resources) != keys:
        return False
    memory = resources["memoryBytes"]
    if not _valid_disk(resources["disk"]):
        return False
    if not _observation(memory, required={"state", "bytes", "errorCode"}):
        return False
    if memory["bytes"] is not None and (type(memory["bytes"]) is not int
            or memory["bytes"] < 0 or memory["bytes"] > 2**63 - 1):
        return False
    return (_metadata_record(resources["cargoHome"], inventory=True)
            and _metadata_record(resources["rustupHome"], inventory=True))


def _valid_report(report, expected_hashes):
    keys = {"kind", "status", "collectionOnly", "prepared", "nativeQualified", "runtime",
            "sourceSha256", "pythonCandidates", "rust", "tools", "pkgConfigModules", "sdk", "resources"}
    if type(report) is not dict or set(report) != keys:
        return False
    if (report.get("kind") != KIND or report.get("status") != "passed"
            or report.get("collectionOnly") is not True or report.get("prepared") is not False
            or report.get("nativeQualified") is not False):
        return False
    if not _valid_runtime(report["runtime"]):
        return False
    if type(report["sourceSha256"]) is not dict or report["sourceSha256"] != expected_hashes:
        return False
    return (_valid_python(report["pythonCandidates"], report["runtime"]["pythonPath"])
            and _valid_rust(report["rust"])
            and _valid_observation_maps(report["tools"], report["pkgConfigModules"])
            and _valid_sdk(report["sdk"])
            and _valid_resources(report["resources"]))


def _validated_report(stdout, stderr, expected_hashes):
    if len(stdout) > MAX_REPORT_BYTES or len(stderr) > 2048 or stderr:
        raise canary.CanaryError("native_guest_inventory_output_invalid")
    try:
        report = json.loads(stdout)
    except (ValueError, UnicodeError, RecursionError):
        raise canary.CanaryError("native_guest_inventory_report_invalid") from None
    if not _valid_report(report, expected_hashes):
        raise canary.CanaryError("native_guest_inventory_report_invalid")
    return report


def collect(tart_path, vm_name, env, evidence, bundle, *, run_bounded=None):
    runner = canary._run_bounded if run_bounded is None else run_bounded
    evidence = Path(evidence)
    try:
        command = command_template(tart_path, vm_name, bundle["loader"])
        command[-1] = bundle["argument"]
        stdout_path = evidence / "native-workspace-guest-inventory-stdout.json"
        stderr_path = evidence / "native-workspace-guest-inventory-stderr.bin"
        stdout, stderr = runner(command, timeout=30, env=env, output_limit=MAX_REPORT_BYTES,
                                capture_paths=(stdout_path, stderr_path))
        report = _validated_report(stdout, stderr, bundle["sourceSha256"])
        return {"status": "passed", "report": report, "bundleSha256": bundle["bundleSha256"],
                "failureCode": None, "rawEvidence": _raw_records(evidence)}
    except canary.CanaryError as exc:
        return {"status": "failed", "report": None,
                "failureCode": str(exc.args[0]) if exc.args else "inventory_collection_failed",
                "rawEvidence": _raw_records(evidence)}


def _raw_records(evidence):
    names = ("native-workspace-guest-inventory-stdout.json",
             "native-workspace-guest-inventory-stderr.bin")
    return {name: canary._raw_evidence(Path(evidence) / name, MAX_REPORT_BYTES, []) for name in names}
