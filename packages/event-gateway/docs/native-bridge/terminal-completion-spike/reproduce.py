import hashlib
import json
import os
import pathlib
import resource
import sqlite3
import subprocess


def terminal_rows(home):
    paths = list(home.glob("state_*.sqlite"))
    if len(paths) != 1:
        raise RuntimeError("expected one state database")
    db = sqlite3.connect(paths[0].resolve().as_uri() + "?mode=rw", uri=True)
    try:
        return db.execute(
            "SELECT attempt_id,turn_id,terminal_status,terminal_receipt_id FROM native_turn_start_receipts ORDER BY attempt_id"
        ).fetchall()
    finally:
        db.close()


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Use a disposable patched checkout and an empty output directory.
    ROOT = pathlib.Path(os.environ["CODEX_SPIKE_ROOT"]).resolve()
    OUT = pathlib.Path(os.environ["SPIKE_PROOF_DIR"]).resolve()
    OUT.mkdir(parents=True, exist_ok=False)
    JUST = pathlib.Path(os.environ["JUST_BIN"])
    if not JUST.is_absolute() or not JUST.is_file() or not os.access(JUST, os.X_OK):
        raise RuntimeError(
            "JUST_BIN must be an absolute existing executable selected by the owner"
        )
    JUST = str(JUST)
    env = dict(os.environ, CARGO_NET_OFFLINE="true")
    artifact = pathlib.Path(__file__).resolve()
    historical = json.loads(
        (
            artifact.parent.parent / "native-core-idle-v1-source-manifest.json"
        ).read_text()
    )["fileSha256"]
    final = json.loads(artifact.with_name("manifest.json").read_text())["fileSha256"]
    # Final spike bytes supersede historical hashes for overlapping files.
    expected = historical | final
    source_hashes = {
        p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in expected
    }
    if source_hashes != expected:
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
            # Owner-selected absolute executable; argv is fixed and no shell is used.
            r = subprocess.run(  # noqa: B603
                cmd,
                cwd=ROOT,
                env=dict(env, **extra),
                stdout=f,
                stderr=subprocess.STDOUT,
            )
        row = dict(
            name=name,
            command=["just", *cmd[1:]],
            env={k: v.replace(str(OUT), "$PROOF_DIR") for k, v in extra.items()},
            exitCode=r.returncode,
            log=log.name,
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
            hashlib.sha256((ROOT / p).read_bytes()).hexdigest() != h
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
            EVENT_TERMINAL_CORE_FIXTURE=fixture,
            EVENT_TERMINAL_CORE_FIXTURE_SHA256=digest,
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

            previous = terminal_rows(home) if phase.startswith("recover") else None
            run(
                label + "-" + phase,
                "codex-app-server",
                "native_terminal_core_fixture_to_durable_observer",
                dict(
                    base, EVENT_TERMINAL_DB_HOME=str(home), EVENT_TERMINAL_PHASE=phase
                ),
                phase in ["before", "after"],
            )
            if previous is not None:
                if previous != terminal_rows(home):
                    raise RuntimeError("recovery mutated immutable receipt")
                (OUT / (label + "-" + phase + "-rows.json")).write_text(
                    json.dumps(previous, indent=2) + "\n"
                )
            if hashlib.sha256(pathlib.Path(fixture).read_bytes()).hexdigest() != digest:
                raise RuntimeError("fixture changed")


if __name__ == "__main__":
    main()
