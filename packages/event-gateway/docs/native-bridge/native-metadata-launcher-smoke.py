"""Private-auth metadata stability qualifier; never prints terminal or log contents."""
import argparse
import hashlib
import importlib
import json
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
PASSIVE_SECONDS = 125


def require(value, message):
    if not value:
        raise AssertionError(message)


def helpers():
    path = Path(__file__).with_name("native-release-launcher-smoke.py")
    source = path.read_bytes()
    require(hashlib.sha256(source).hexdigest() == FROZEN_SHA, "frozen helper digest mismatch")
    module = types.ModuleType("frozen_launcher_smoke")
    module.__file__ = str(path)
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


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
    def drain(master, tail):
        if not select.select([master], [], [], 0.1)[0]:
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


def qualify(args):
    h = helpers()
    provenance = h.installed_preflight(args.package_source)
    launcher = importlib.import_module("event_gateway.launcher")
    require(args.binary_sha256 == launcher.QUALIFIED_SHA256, "candidate and installed pin differ")
    launcher.qualified_binary(args.binary, args.binary_sha256)
    root = Path(tempfile.mkdtemp(prefix="nm-", dir=Path("/tmp").resolve()))
    proof = {"result": "FAIL", "privateEvidenceDirectory": str(root),
             "frozenHelperSha256": FROZEN_SHA, "runnerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             "binarySha256": args.binary_sha256, "installedPackagePreflight": provenance,
             "model": "gpt-6.1-sol", "provider": "openai", "harnessUserPrompts": 0,
             "harnessTurnStartRequests": 0, "realModelNetworkCalls": None,
             "realModelNetworkCallsEvidence": "Not instrumented; RPC observations are not HTTP-call counts",
             "passiveObservation": {}}
    home = None
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
                proof["startupSettling"] = {}
                selection = settle(h, launcher, state, process, master, tail, proof["startupSettling"])
                socket_path, status, binding, challenge = selection
                h.check_selection(status, binding, challenge)
                proof["initialBinding"] = binding
                observe(h, launcher, state, process, master, tail, binding, proof["passiveObservation"])
                proof["nonDrawFences"] = h.check_non_draw_fences(launcher, state, process, master, tail, socket_path, binding)
                proof["terminationExitCode"] = h.quit_foreground(process, master, tail, socket_path, binding["backendPid"])
                proof.update(controlSocketRemoved=True, backendStopped=True)
        launcher.qualified_binary(args.binary, args.binary_sha256)
        passive = proof["passiveObservation"]
        proof["rpcMetadata"] = rpc_evidence(home, passive["startedUnix"], passive["endedUnix"])
        require(proof["rpcMetadata"]["account/rateLimits/read"]["passiveObserved"] >= 2,
                "fewer than two periodic rate-limit RPCs observed")
        proof["result"] = "PASS"
    except Exception as error:
        # Exception strings from imported helpers can contain raw PTY text; never publish them.
        proof["failureType"] = type(error).__name__
        proof["failureStage"] = ("passive" if proof["passiveObservation"].get("startedUnix") else "startup")
        if type(error) is AssertionError and error.__traceback__ is not None:
            tb = error.__traceback__
            while tb.tb_next:
                tb = tb.tb_next
            if tb.tb_frame.f_code.co_filename == __file__:
                proof["failureReason"] = str(error)
        if home is not None and proof["passiveObservation"].get("startedUnix"):
            try:
                proof["rpcMetadata"] = rpc_evidence(home, proof["passiveObservation"]["startedUnix"], time.time())
            except Exception:
                proof["rpcMetadataUnavailable"] = True
    args.output.write_text(json.dumps(proof, indent=2) + "\n")
    print(json.dumps(proof))
    return 0 if proof["result"] == "PASS" else 1


def self_test():
    helpers()
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
    for query in (b"\x1b[6n", b"\x1b[?u", b"\x1b[c", b"\x1b]10;?\x07", b"\x1b]11;?\x1b\\"):
        for split in range(len(query)):
            require(len(terminal_replies(query[:split], query[split:])) == 1, "split query reply failed")
        require(not terminal_replies(query, b"ordinary"), "terminal query replayed")
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
    print(json.dumps({"result": "PASS", "checks": ["frozen-helper-digest", "exact-request-id-parser-and-deduplication", "split-terminal-queries", "no-query-replay", "minimum-passive-duration", "startup-minimum-warmup-reset-and-deadline", "bounded-stable-observer", "unavailable-and-changed-binding-rejected"]}))


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
