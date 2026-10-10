"""Private-auth metadata stability qualifier; never prints terminal or log contents."""
import argparse
import hashlib
import importlib
import importlib.util
import json
import math
import os
import re
from pathlib import Path
import select
import sqlite3
import stat
import sys
import tempfile
import time
import types

FROZEN_SHA = "073ddf6a43248db44345e0a20d09f11ced91740186d741b9038b7f7bea5dd33e"
PREFLIGHT_SHA = "22002b7e599c266b512546c67ff383a643846624adb2b188520250d19fcd061c"
PASSIVE_SECONDS = 125


def require(value, message):
    if not value:
        raise AssertionError(message)


def helpers():
    origin = Path(__file__).parent
    pinned = {
        "native-release-launcher-smoke.py": FROZEN_SHA,
        "qualification-installed.py": PREFLIGHT_SHA,
    }
    sources = {}
    for name, digest in pinned.items():
        source = (origin / name).read_bytes()
        require(hashlib.sha256(source).hexdigest() == digest, "frozen helper digest mismatch")
        sources[name] = source
    # Import only fresh private copies of the exact verified bytes. This avoids
    # rereading mutable original paths or accepting their cached bytecode.
    temporary = tempfile.TemporaryDirectory(prefix="nm-helper-")
    try:
        directory = Path(temporary.name)
        for name, source in sources.items():
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(source)
        path = directory / "native-release-launcher-smoke.py"
        spec = importlib.util.spec_from_file_location("frozen_launcher_smoke", path)
        require(spec is not None and spec.loader is not None, "private helper loader unavailable")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # installed_preflight resolves its verified sibling relative to __file__.
        module._private_helpers = temporary
        return module
    except BaseException:
        temporary.cleanup()
        raise


def terminal_replies(previous, data):
    replies = []
    queries = [(b"\x1b[6n", b"\x1b[1;1R"), (b"\x1b[?u", b"\x1b[?0u"),
               (b"\x1b[c", b"\x1b[?1;2c")]
    for number, color in ((10, b"dddd/dddd/dddd"), (11, b"1111/1111/1111")):
        for ending in (b"\x07", b"\x1b\\"):
            queries.append((f"\x1b]{number};?".encode() + ending,
                            f"\x1b]{number};rgb:".encode() + color + ending))
    for query, reply in queries:
        replies.extend([reply] * (previous[-len(query) + 1:] + data).count(query))
    return replies


def make_drain(log):
    def drain(master, tail, timeout=0.1):
        if not select.select([master], [], [], timeout)[0]:
            return 0
        try:
            data = os.read(master, 65536)
        except OSError:
            return 0
        log.write(data)
        log.flush()
        for reply in terminal_replies(bytes(tail), data):
            os.write(master, reply)
        tail.extend(data)
        del tail[:-16384]
        return len(data)
    return drain


def private_home(root, source):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077,
                "auth source must be a private regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            auth = stream.read()
        parsed = json.loads(auth)
        require(parsed.get("auth_mode") == "chatgpt" and isinstance(parsed.get("tokens"), dict),
                "ChatGPT auth required")
    finally:
        os.close(fd)
    home = root / "home"
    home.mkdir(mode=0o700)
    config = ('check_for_update_on_startup=false\nmodel="gpt-6.1-sol"\n'
              '[analytics]\nenabled=false\n[feedback]\nenabled=false\n'
              '[otel]\nexporter="none"\ntrace_exporter="none"\nmetrics_exporter="none"\n'
              f'[projects.{json.dumps(str(root))}]\ntrust_level="trusted"\n')
    for name, content in (("auth.json", auth), ("config.toml", config.encode())):
        with os.fdopen(os.open(home / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
            stream.write(content)
    return home


RATE_REQUEST = re.compile(
    r'(?:^|\s)request_id=String\("(account-rate-limits-'
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"\)(?=\s|$)'
)


def rate_request_times(rows):
    # This exact request-ID prefix is assigned by fetch_account_rate_limits.
    # A compatibility retry can reuse an ID; count its first typed request only.
    requests = {}
    for stamp, body in rows:
        if "app-server typed request" not in (body or ""):
            continue
        match = RATE_REQUEST.search(body)
        if match:
            requests.setdefault(match.group(1), stamp)
    return sorted(requests.values())


def rpc_evidence(home, start, end):
    paths = list(home.glob("logs_*.sqlite"))
    require(len(paths) == 1, "expected one private log database")
    with sqlite3.connect(paths[0].as_uri() + "?mode=ro", uri=True) as db:
        require(db.execute("SELECT count(*) FROM logs").fetchone()[0] > 0,
                "private RPC log database has no flushed rows")
        rows = db.execute(
            "SELECT ts + ts_nanos / 1000000000.0, feedback_log_body FROM logs "
            "WHERE target = ? AND feedback_log_body LIKE ? "
            "ORDER BY ts, ts_nanos",
            ("codex_app_server::message_processor", "%app-server typed request%"),
        ).fetchall()
    times = rate_request_times(rows)
    passive = [stamp for stamp in times if start <= stamp <= end]
    unavailable = {"totalObserved": None, "passiveObserved": None,
                   "reason": "Typed-request records do not include method; no dedicated request-ID prefix"}
    return {
        "account/read": dict(unavailable),
        "turn/start": dict(unavailable),
        "account/rateLimits/read": {
            "measurement": "Distinct source-defined account-rate-limits-UUID typed-request IDs",
            "source": "codex-rs/tui/src/app/background_requests.rs:fetch_account_rate_limits",
            "totalObserved": len(times), "passiveObserved": len(passive),
            "passiveOffsetsSeconds": [stamp - start for stamp in passive],
            "passiveIntervalsSeconds": [b - a for a, b in zip(passive, passive[1:])],
        },
    }


def settle(h, launcher, state, process, master, tail, proof):
    started = time.monotonic()
    deadline = started + 120
    stable_since = None
    previous = None
    proof.update(requiredStableSeconds=10, minimumWarmupSeconds=60, startupDeadlineSeconds=120,
                 warmupEvidence="Measured warmup only; asynchronous startup completion is not proven",
                 resets=0, samples=0)
    while True:
        require(process.poll() is None, "foreground exited before readiness")
        require(time.monotonic() < deadline, "startup settling deadline exceeded")
        h.drain(master, tail)
        selection = h.current_selection(launcher, state)
        proof["samples"] += 1
        if selection is None:
            if stable_since is not None:
                proof["resets"] += 1
            stable_since, previous = None, None
            continue
        _, status, binding, challenge = selection
        h.check_selection(status, binding, challenge)
        if previous != binding:
            if stable_since is not None:
                proof["resets"] += 1
            previous = dict(binding)
            stable_since = time.monotonic()
        elapsed = time.monotonic() - stable_since
        if elapsed >= 10 and time.monotonic() - started >= 60:
            proof.update(elapsedSeconds=time.monotonic() - started, continuouslyStableSeconds=elapsed)
            return selection


def observe(h, launcher, state, process, master, tail, binding, proof):
    started = time.monotonic()
    proof.update(startedUnix=time.time(), samples=0, elapsedSeconds=0)
    while time.monotonic() - started < PASSIVE_SECONDS:
        until = min(started + PASSIVE_SECONDS, time.monotonic() + 0.5)
        while time.monotonic() < until:
            require(process.poll() is None, "foreground exited during passive observation")
            h.drain(master, tail)
        proof["elapsedSeconds"] = time.monotonic() - started
        selection = h.current_selection(launcher, state)
        require(selection is not None, "selection unavailable during passive observation")
        _, status, current, challenge = selection
        h.check_selection(status, current, challenge)
        proof["samples"] += 1
        if current != binding:
            proof["changedBindingFields"] = [key for key in set(current) | set(binding)
                                              if current.get(key) != binding.get(key)]
            raise AssertionError("binding changed during passive metadata observation")
    proof.update(endedUnix=time.time(), bindingUnchanged=True, inputEvents=0, resizeEvents=0)


REVOCATION_CATEGORIES = frozenset({
    "periodic-response-queued-event", "periodic-response-semantic", "rate-limits-recovery",
    "rate-limits-other-origin", "app-event-other", "server-mcp-status",
    "server-account-rate-limits", "server-account-updated", "server-notification-other",
    "server-request", "server-lagged", "server-disconnected", "server-stream-closed",
    "pending-app-event", "pending-active-thread-event", "selection-state-not-ready",
    "selection-not-ready", "selection-loop-gap", "selection-binding-expired-or-mismatched",
    "connecting", "native-revoke", "native-update", "native-connect", "pending-transition",
    "pending-event", "app-event", "thread-event", "tui-event", "server-event", "reconnect",
    "commit-event", "startup-drain", "shutdown", "exit",
    "loop-gap", "native-transport-unavailable",
})


SERVER_REVOCATION_CATEGORIES = frozenset({
    "connection-closed", "lease-expired", "client-selection-ready", "client-revoke",
})


def parse_revocation(stamp, body, target="codex_selection_witness"):
    if not isinstance(stamp, (int, float)) or isinstance(stamp, bool) or not math.isfinite(stamp):
        return None
    if target == "codex_selection_witness":
        side, marker, allowed = "tui", "native selection revocation trigger", REVOCATION_CATEGORIES
        fields = ("generation", "server_generation")
    elif target == "codex_native_selection":
        side, marker, allowed = "server", "native selection authority changed", SERVER_REVOCATION_CATEGORIES
        fields = ("generation", "expected_generation")
    else:
        return None
    if not isinstance(body, str) or marker not in body:
        return None
    categories = re.findall(r'(?:^|\s)category="([a-z-]+)"(?=\s|$)', body)
    if len(categories) != 1 or categories[0] not in allowed:
        return None
    record = {"timestampUnix": stamp, "side": side, "target": target, "category": categories[0]}
    for name in fields:
        # A present but malformed value must not silently become an absent field.
        present = re.findall(r'(?:^|\s)' + name + r'=', body)
        values = re.findall(r'(?:^|\s)' + name + r'=([0-9]{1,20})(?=\s|$)', body)
        if len(present) != len(values) or len(values) > 1 or (name == "generation" and not values):
            return None
        if values:
            value = int(values[0])
            if value > 2**64 - 1:
                return None
            record[name] = value
    return record


def collect_revocations(home, proof):
    capture = proof["postFailureCapture"]
    paths = list(home.glob("logs_*.sqlite"))
    require(len(paths) == 1, "expected one cause log database")
    with sqlite3.connect(paths[0].as_uri() + "?mode=ro", uri=True, timeout=0.1) as db:
        rows = db.execute(
            "SELECT ts + ts_nanos / 1000000000.0, feedback_log_body, target FROM logs "
            "WHERE target IN (?, ?) AND ts BETWEEN ? AND ? ORDER BY ts, ts_nanos LIMIT 256",
            ("codex_selection_witness", "codex_native_selection", int(proof["failureObservedUnix"]) - 2,
             int(capture["endedUnix"]) + 1),
        ).fetchall()
    capture["authorityTransitions"] = [record for stamp, body, target in rows
                              if proof["failureObservedUnix"] - 2 <= stamp <= capture["endedUnix"]
                              and (record := parse_revocation(stamp, body, target)) is not None]
    capture["actualRevocationRecordsObserved"] = any(
        record["category"] != "client-selection-ready" for record in capture["authorityTransitions"]
    )


def capture_failure(h, home, process, master, tail, proof):
    started = time.monotonic()
    deadline = started + 11
    capture = {"maxWaitSeconds": 11, "startedUnix": time.time(),
               "authorityTransitions": [], "actualRevocationRecordsObserved": False}
    proof["postFailureCapture"] = capture
    try:
        while process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            h.drain(master, tail, timeout=min(0.1, remaining))
    except Exception as error:
        capture["drainFailureType"] = type(error).__name__
    capture.update(elapsedSeconds=time.monotonic() - started, endedUnix=time.time())
    try:
        collect_revocations(home, proof)
    except Exception as error:
        capture["collectionFailureType"] = type(error).__name__


def record_failure(proof, error, phase):
    # Imported helper exceptions may contain raw PTY text; publish only our own assertions.
    if "failureStage" in proof:
        return
    proof.update(result="FAIL", failureType=type(error).__name__, failureStage=phase,
                 failureObservedUnix=time.time())
    if isinstance(error, AssertionError) and error.__traceback__ is not None:
        tb = error.__traceback__
        while tb.tb_next:
            tb = tb.tb_next
        if tb.tb_frame.f_code.co_filename == __file__:
            proof["failureReason"] = str(error)


def cleanup_auth(root, proof):
    try:
        (root / "home" / "auth.json").unlink(missing_ok=True)
        proof["copiedAuthRemoved"] = True
    except OSError as error:
        proof["copiedAuthRemoved"] = False
        proof["authCleanupFailureType"] = type(error).__name__
        if "failureStage" not in proof:
            record_failure(proof, error, "authCleanup")
        else:
            proof["result"] = "FAIL"


def qualify(args):
    h = helpers()
    provenance = h.installed_preflight(args.package_source)
    launcher = importlib.import_module("event_gateway.launcher")
    require(args.binary_sha256 == launcher.QUALIFIED_SHA256, "candidate and installed pin differ")
    launcher.qualified_binary(args.binary, args.binary_sha256)
    root = Path(tempfile.mkdtemp(prefix="nm-", dir=Path(tempfile.gettempdir()).resolve()))
    proof = {"result": "FAIL", "privateEvidenceDirectory": str(root),
             "frozenHelperSha256": FROZEN_SHA, "runnerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             "binarySha256": args.binary_sha256, "installedPackagePreflight": provenance,
             "model": "gpt-6.1-sol", "provider": "openai", "harnessUserPrompts": 0,
             "harnessTurnStartRequests": 0, "realModelNetworkCalls": None,
             "realModelNetworkCallsEvidence": "Not instrumented; RPC observations are not HTTP-call counts",
             "passiveObservation": {}}
    home = None
    phase = "startup"
    try:
        home = private_home(root, args.auth_source)
        state = root / "state"
        argv = [sys.executable, "-I", "-B", "-m", "event_gateway.cli", "--state-dir", str(state),
                "launch", "--codex-binary", str(args.binary), "--binary-sha256", args.binary_sha256,
                "--cwd", str(root)]
        with os.fdopen(os.open(root / "terminal.private.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as log:
            h.drain = make_drain(log)
            tail = bytearray()
            with h.foreground_process(root, home, argv) as (process, master):
                try:
                    proof["startupSettling"] = {}
                    selection = settle(h, launcher, state, process, master, tail, proof["startupSettling"])
                    socket_path, status, binding, challenge = selection
                    h.check_selection(status, binding, challenge)
                    proof["initialBinding"] = binding
                    phase = "passive"
                    observe(h, launcher, state, process, master, tail, binding, proof["passiveObservation"])
                    phase = "nonDraw"
                    proof["nonDrawFences"] = h.check_non_draw_fences(launcher, state, process, master, tail, socket_path, binding)
                    phase = "termination"
                    proof["terminationExitCode"] = h.quit_foreground(process, master, tail, socket_path, binding["backendPid"])
                    proof.update(controlSocketRemoved=True, backendStopped=True)
                except Exception as error:
                    record_failure(proof, error, phase)
                    capture_failure(h, home, process, master, tail, proof)
                    raise
        phase = "finalBinary"
        launcher.qualified_binary(args.binary, args.binary_sha256)
        phase = "rpcProof"
        passive = proof["passiveObservation"]
        proof["rpcMetadata"] = rpc_evidence(home, passive["startedUnix"], passive["endedUnix"])
        require(proof["rpcMetadata"]["account/rateLimits/read"]["passiveObserved"] >= 2,
                "fewer than two periodic rate-limit RPCs observed")
        proof["result"] = "PASS"
    except Exception as error:
        record_failure(proof, error, phase)
        if home is not None and "postFailureCapture" in proof:
            try:
                collect_revocations(home, proof)
            except Exception as capture_error:
                proof["postFailureCapture"]["postExitCollectionFailureType"] = type(capture_error).__name__
        if home is not None and proof["passiveObservation"].get("startedUnix"):
            try:
                proof["rpcMetadata"] = rpc_evidence(home, proof["passiveObservation"]["startedUnix"],
                                                       proof["failureObservedUnix"])
            except Exception:
                proof["rpcMetadataUnavailable"] = True
    finally:
        # The foreground context has stopped its owned process before this runs.
        # Address the known copy even if private_home failed after creating it.
        cleanup_auth(root, proof)
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps(proof))
    return 0 if proof["result"] == "PASS" else 1


def self_test_cause_parser():
    valid_cause = 'native selection revocation trigger category="app-event-other" generation=4 server_generation=9'
    require(parse_revocation(1000, valid_cause) == {
        "timestampUnix": 1000, "side": "tui", "target": "codex_selection_witness",
        "category": "app-event-other", "generation": 4, "server_generation": 9,
    }, "valid sanitized cause rejected")
    for invalid in (valid_cause.replace("app-event-other", "secret-unknown"),
                    valid_cause.replace("generation=4", 'generation="credential"'),
                    valid_cause.replace("server_generation=9", "server_generation=Some(9)"),
                    valid_cause.replace("generation=4", "generation=-1"),
                    valid_cause + " generation=5", valid_cause.replace("generation=4", "generation=18446744073709551616")):
        require(parse_revocation(1000, invalid) is None, "unsafe cause accepted")
    require(parse_revocation(float("nan"), valid_cause) is None, "invalid cause timestamp accepted")
    server_cause = 'native selection authority changed category="lease-expired" generation=6 expected_generation=5'
    parsed_server = parse_revocation(1000, server_cause, "codex_native_selection")
    require(parsed_server == {"timestampUnix": 1000, "side": "server", "target": "codex_native_selection",
                              "category": "lease-expired", "generation": 6, "expected_generation": 5},
            "server cause rejected")
    for body, target in ((server_cause, "codex_selection_witness"), (valid_cause, "codex_native_selection"),
                         (server_cause, "unknown"),
                         (server_cause.replace("lease-expired", "app-event-other"), "codex_native_selection"),
                         (server_cause.replace("expected_generation=5", 'expected_generation="secret"'),
                          "codex_native_selection")):
        require(parse_revocation(1000, body, target) is None, "invalid target/category pair accepted")
    for category in ("loop-gap", "native-transport-unavailable"):
        require(parse_revocation(1000, valid_cause.replace("app-event-other", category)) is not None,
                "direct emission cause rejected")
    return valid_cause, server_cause


def self_test_failure_capture(valid_cause, server_cause):
    real_monotonic, real_time = time.monotonic, time.time
    with tempfile.TemporaryDirectory(prefix="nm-capture-selftest-") as directory:
        home = Path(directory)
        with sqlite3.connect(home / "logs_2.sqlite") as db:
            db.execute("CREATE TABLE logs (ts INTEGER, ts_nanos INTEGER, target TEXT, feedback_log_body TEXT)")
        try:
            clock = [0.0]
            time.monotonic = lambda: clock[0]
            time.time = lambda: 1000 + clock[0]

            def advance_capture(*_, timeout):
                clock[0] += timeout

            fake = types.SimpleNamespace(drain=advance_capture)
            proof = {}
            original = AssertionError("original capture failure")
            record_failure(proof, original, "passive")
            captured_failure = dict(proof)
            capture_failure(fake, home, types.SimpleNamespace(poll=lambda: None), None, bytearray(), proof)
            require(proof["postFailureCapture"]["elapsedSeconds"] == 11,
                    "capture wait did not respect eleven-second deadline")
            record_failure(proof, RuntimeError("later cleanup failure"), "termination")
            require(all(proof[key] == value for key, value in captured_failure.items()),
                    "capture changed original failure stage, type, result or time")
            require(not proof["postFailureCapture"]["actualRevocationRecordsObserved"], "elapsed time invented cause proof")
            clock[0] = 0
            short = {}
            record_failure(short, original, "startup")
            capture_failure(fake, home, types.SimpleNamespace(poll=lambda: None if clock[0] < 0.5 else 1),
                            None, bytearray(), short)
            require(short["postFailureCapture"]["elapsedSeconds"] == 0.5
                    and not short["postFailureCapture"]["actualRevocationRecordsObserved"], "500ms implied cause proof")
            with sqlite3.connect(home / "logs_2.sqlite") as db:
                db.executemany("INSERT INTO logs VALUES (1000,0,?,?)", [
                    ("codex_selection_witness", valid_cause),
                    ("codex_native_selection", server_cause),
                    ("wrong_target", valid_cause),
                    ("codex_selection_witness", valid_cause.replace("app-event-other", "secret-unknown")),
                ])
            collect_revocations(home, proof)
            require(len(proof["postFailureCapture"]["authorityTransitions"]) == 2,
                    "cause collector accepted untrusted target or label")
            with sqlite3.connect(home / "logs_2.sqlite") as db:
                db.execute("DELETE FROM logs")
                db.execute("INSERT INTO logs VALUES (1000,0,?,?)", (
                    "codex_native_selection", server_cause.replace("lease-expired", "client-selection-ready"),
                ))
            collect_revocations(home, proof)
            require(len(proof["postFailureCapture"]["authorityTransitions"]) == 1
                    and not proof["postFailureCapture"]["actualRevocationRecordsObserved"],
                    "positive authority transition was reported as revocation")
        finally:
            time.monotonic, time.time = real_monotonic, real_time


def self_test_auth_cleanup():
    with tempfile.TemporaryDirectory(prefix="nm-auth-selftest-") as directory:
        root = Path(directory)
        source = root / "dummy-source.json"
        source.write_text(json.dumps({"auth_mode": "chatgpt", "tokens": {"dummy": "test-only"}}))
        source.chmod(0o600)
        source_bytes = source.read_bytes()
        for phase in (None, "startup", "passive", "nonDraw", "termination", "finalBinary", "rpcProof"):
            attempt = root / (phase or "success")
            attempt.mkdir(mode=0o700)
            proof = {"result": "PASS", "passiveObservation": {"startedUnix": 1}}
            try:
                private_home(attempt, source)
                if phase is not None:
                    raise AssertionError("self-test phase failure")
            except AssertionError as error:
                record_failure(proof, error, phase)
            finally:
                cleanup_auth(attempt, proof)
            require(not (attempt / "home" / "auth.json").exists() and proof["copiedAuthRemoved"],
                    "copied auth retained after qualification")
            require(source.read_bytes() == source_bytes, "source auth changed")
            require(proof.get("failureStage") == phase, "failure phase misreported")
        failed = root / "cleanup-failure"
        (failed / "home" / "auth.json").mkdir(parents=True)
        for primary in (None, "passive"):
            proof = {"result": "PASS"}
            if primary:
                proof.update(result="FAIL", failureStage=primary, failureType="AssertionError")
            cleanup_auth(failed, proof)
            require(proof["result"] == "FAIL" and not proof["copiedAuthRemoved"]
                    and proof["failureStage"] == (primary or "authCleanup")
                    and "authCleanupFailureType" in proof, "auth cleanup masked primary failure")


def self_test_private_helpers():
    helper = helpers()
    private = Path(helper.__file__).parent
    require(stat.S_IMODE(private.stat().st_mode) == 0o700, "helper directory is not private")
    for name, digest in (("native-release-launcher-smoke.py", FROZEN_SHA),
                         ("qualification-installed.py", PREFLIGHT_SHA)):
        copied = private / name
        original = Path(__file__).with_name(name)
        require(stat.S_IMODE(copied.stat().st_mode) == 0o600, "helper copy is not private")
        require(hashlib.sha256(copied.read_bytes()).hexdigest() == digest,
                "private helper pin mismatch")
        require(hashlib.sha256(original.read_bytes()).hexdigest() == digest,
                "historical helper changed")
    require(not (private / "__pycache__").exists(), "unexpected helper bytecode cache")
    marker = object()
    helper.drain = marker
    require(helper.check_non_draw_fences.__globals__["drain"] is marker,
            "private helper drain override lost module globals")
    helper._private_helpers.cleanup()
    require(not private.exists(), "private helpers not cleaned up")


def self_test_request_parser():
    request = 'request_id=String("account-rate-limits-12345678-1234-1234-1234-123456789abc")'
    valid = "app-server typed request connection_id=1 " + request
    require(rate_request_times([(1, valid), (2, valid)]) == [1], "duplicate request counted")
    for invalid in (valid.replace("account-rate-limits-", "account-rate-limits-lookalike-"),
                    valid.replace("request_id=", "other_request_id="),
                    valid.replace("request_id=", "request_id_prefix="),
                    valid.replace("app-server typed request", "unrelated request"),
                    valid.replace("123456789abc", "123456789abz"), "", None):
        require(rate_request_times([(1, invalid)]) == [], "ineligible request matched")
    require(rate_request_times([]) == [], "empty request metadata matched")


def self_test_terminal_replies():
    for query in (b"\x1b[6n", b"\x1b[?u", b"\x1b[c", b"\x1b]10;?\x07", b"\x1b]11;?\x1b\\"):
        for split in range(len(query)):
            require(len(terminal_replies(query[:split], query[split:])) == 1, "split query reply failed")
        require(not terminal_replies(query, b"ordinary"), "terminal query replayed")


def self_test_observation():
    require(PASSIVE_SECONDS >= 125, "passive duration too short")
    real_monotonic, real_time = time.monotonic, time.time
    clock = [0.0]
    binding = {"generation": 1}
    fake = types.SimpleNamespace(
        drain=lambda *_: clock.__setitem__(0, clock[0] + 0.1),
        current_selection=lambda *_: (None, {}, dict(binding), {}),
        check_selection=lambda *_: None,
    )
    try:
        time.monotonic = lambda: clock[0]
        time.time = lambda: 1000 + clock[0]
        process = types.SimpleNamespace(poll=lambda: None)
        fake.current_selection = lambda *_: (None if clock[0] < 2 else
            (None, {}, {"generation": 2 if clock[0] < 4 else 1}, {}))
        settled = {}
        settle(fake, None, None, process, None, bytearray(), settled)
        require(settled["continuouslyStableSeconds"] >= 10 and settled["resets"] == 1
                and settled["elapsedSeconds"] >= 60, "startup settling did not honor churn and minimum warmup")
        clock[0] = 0
        fake.current_selection = lambda *_: None
        try:
            settle(fake, None, None, process, None, bytearray(), {})
        except AssertionError:
            require(clock[0] >= 120, "startup deadline fired early")
        else:
            raise AssertionError("startup settling accepted unavailable selection")
        clock[0] = 0
        fake.current_selection = lambda *_: (None, {}, dict(binding), {})
        proof = {}
        observe(fake, None, None, process, None, bytearray(), binding, proof)
        require(proof["elapsedSeconds"] >= 125 and proof["samples"] >= 200,
                "bounded passive observer did not cover interval")
        for selection in (None, (None, {}, {"generation": 2}, {})):
            clock[0] = 0
            fake.current_selection = lambda *_, value=selection: value
            try:
                observe(fake, None, None, process, None, bytearray(), binding, {})
            except AssertionError:
                pass
            else:
                raise AssertionError("observer accepted unavailable or changed binding")
    finally:
        time.monotonic, time.time = real_monotonic, real_time


def self_test():
    valid_cause, server_cause = self_test_cause_parser()
    self_test_failure_capture(valid_cause, server_cause)
    self_test_auth_cleanup()
    self_test_private_helpers()
    self_test_request_parser()
    self_test_terminal_replies()
    self_test_observation()
    print(json.dumps({"result": "PASS", "checks": [
        "bounded-post-failure-capture", "original-failure-preserved",
        "strict-cause-target-label-and-integers", "server-and-tui-closed-pairs",
        "direct-emission-causes", "positive-transition-is-not-revocation",
        "short-wait-is-not-cause-proof",
        "auth-copy-success-and-failure-cleanup", "auth-source-preserved",
        "explicit-failure-phases", "auth-cleanup-failure-preserves-primary",
        "both-frozen-helper-pins", "private-copy-permissions-and-cleanup",
        "historical-helpers-unchanged", "helper-module-drain-override",
        "exact-request-id-parser-and-deduplication",
        "split-terminal-queries", "no-query-replay", "minimum-passive-duration",
        "startup-minimum-warmup-reset-and-deadline", "bounded-stable-observer",
        "unavailable-and-changed-binding-rejected",
    ]}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--binary-sha256")
    parser.add_argument("--package-source", type=Path)
    parser.add_argument("--auth-source", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    for name in ("binary", "binary_sha256", "package_source", "auth_source", "output"):
        if getattr(args, name) is None:
            parser.error("missing --" + name.replace("_", "-"))
    return qualify(args)


if __name__ == "__main__":
    sys.exit(main())
