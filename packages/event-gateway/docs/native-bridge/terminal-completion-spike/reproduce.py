import hashlib
import json
import os
import pathlib
import resource
import sqlite3
import subprocess

resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
# Use a disposable patched checkout and an empty output directory.
ROOT = pathlib.Path(os.environ["CODEX_SPIKE_ROOT"]).resolve()
OUT = pathlib.Path(os.environ["SPIKE_PROOF_DIR"]).resolve()
OUT.mkdir(parents=True, exist_ok=False)
JUST = os.environ.get("JUST_BIN", "just")
env = dict(os.environ, CARGO_NET_OFFLINE="true")
source_paths = [
    "core/src/tasks/mod_tests.rs",
    "core/src/session/tests.rs",
    "app-server/src/thread_state.rs",
    "app-server/src/request_processors/thread_lifecycle.rs",
    "app-server/src/request_processors/native_selection_processor.rs",
    "app-server/src/request_processors/native_selection_processor_tests.rs",
    "state/src/lib.rs",
    "state/src/runtime.rs",
    "state/src/runtime/native_receipts.rs",
    "state/src/runtime/native_receipts_tests.rs",
    "state/migrations/0061_native_turn_terminal_receipts.sql",
]
source_hashes = {
    p: hashlib.sha256((ROOT / "codex-rs" / p).read_bytes()).hexdigest()
    for p in source_paths
}
manifest = json.loads(pathlib.Path(__file__).with_name("manifest.json").read_text())
expected_hashes = {
    str(pathlib.PurePosixPath(p).relative_to("codex-rs")): digest
    for p, digest in manifest["fileSha256"].items()
}
if source_hashes != expected_hashes:
    raise RuntimeError("source manifest mismatch: refusing to run native tests")
(OUT / "source-hashes.json").write_text(json.dumps(source_hashes, indent=2) + "\n")
rows = []


def run(name, crate, test, extra, crash=False):
    log = OUT / (name + ".log")
    cmd = [
        JUST,
        "test",
        "-p",
        crate,
        "--lib",
        test,
        "--run-ignored",
        "only",
        "--retries",
        "0",
    ]
    with log.open("w") as f:
        r = subprocess.run(
            cmd, cwd=ROOT, env=dict(env, **extra), stdout=f, stderr=subprocess.STDOUT
        )
    row = dict(
        name=name,
        command=cmd,
        env=extra,
        exitCode=r.returncode,
        log=str(log),
        logSha256=hashlib.sha256(log.read_bytes()).hexdigest(),
    )
    rows.append(row)
    (OUT / "results.json").write_text(json.dumps(rows, indent=2) + "\n")
    text = log.read_text()
    if crash:
        code = "71" if name.endswith("-before") else "72"
        if r.returncode == 0 or not (
            ("exit code " + code) in text or ("exit status: " + code) in text
        ):
            raise RuntimeError(f"{name}: expected child exit " + code)
    elif r.returncode != 0 or "1 passed" not in text:
        raise RuntimeError(f"{name}: failed")
    if any(
        hashlib.sha256((ROOT / "codex-rs" / p).read_bytes()).hexdigest() != h
        for p, h in source_hashes.items()
    ):
        raise RuntimeError("source changed during proof")
    print(name, "expected immediate child exit" if crash else "PASS", flush=True)


normal = str(OUT / "core-normal.json")
fault = str(OUT / "core-rollout-failure.json")
run(
    "core-normal",
    "codex-core",
    "export_native_terminal_core_fixture",
    dict(EVENT_TERMINAL_CORE_FIXTURE=normal),
)
run(
    "core-rollout-failure",
    "codex-core",
    "export_native_terminal_core_fixture",
    dict(EVENT_TERMINAL_CORE_FIXTURE=fault, EVENT_TERMINAL_ROLLOUT_FAILURE="1"),
)
for label, fixture in [("normal", normal), ("rollout-failure", fault)]:
    data = pathlib.Path(fixture).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    base = dict(
        EVENT_TERMINAL_CORE_FIXTURE=fixture, EVENT_TERMINAL_CORE_FIXTURE_SHA256=digest
    )
    for phase in [
        "normal",
        "write_failure",
        "before",
        "recover_before",
        "after",
        "recover_after",
    ]:
        dbphase = {"recover_before": "before", "recover_after": "after"}.get(
            phase, phase
        )
        home = OUT / (label + "-" + dbphase)
        home.mkdir(exist_ok=True)

        def terminal_rows():
            paths = list(home.glob("state_*.sqlite"))
            if len(paths) != 1:
                raise RuntimeError("expected one state database")
            db = sqlite3.connect("file:" + str(paths[0]) + "?mode=rw", uri=True)
            try:
                return db.execute(
                    "SELECT attempt_id,turn_id,terminal_status,terminal_receipt_id FROM native_turn_start_receipts ORDER BY attempt_id"
                ).fetchall()
            finally:
                db.close()

        previous = terminal_rows() if phase.startswith("recover") else None
        run(
            label + "-" + phase,
            "codex-app-server",
            "native_terminal_core_fixture_to_durable_observer",
            dict(base, EVENT_TERMINAL_DB_HOME=str(home), EVENT_TERMINAL_PHASE=phase),
            phase in ["before", "after"],
        )
        if previous is not None:
            if previous != terminal_rows():
                raise RuntimeError("recovery mutated immutable receipt")
            (OUT / (label + "-" + phase + "-rows.json")).write_text(
                json.dumps(previous, indent=2) + "\n"
            )
        if hashlib.sha256(pathlib.Path(fixture).read_bytes()).hexdigest() != digest:
            raise RuntimeError("fixture changed")
