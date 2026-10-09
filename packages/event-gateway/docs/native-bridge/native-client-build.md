# Build and qualify the pinned native client

The launcher accepts only the reviewed v3 CLI digest `0fb3a5de06ab2ccb8dcc20c11cb71cad1f0c1b85fbfa3a5c6fd16ca1f57d22de`. This runbook rebuilds a disposable candidate from upstream Codex `a956835d020762cb2b570053af06f643a11c0ecc`, applies the cumulative v3 patch, checks all 48 patched source hashes, and records the toolchain and binary digest. It never installs the client or changes the launcher's digest.

Use a clean checkout of the exact upstream commit, Rust 1.95.0 (`59807616e`), Cargo's existing offline cache, and Apple Silicon macOS. The builder archives the entire pinned Git tree into a temporary directory, with no pathspecs, then applies the reviewed patch and validates the 48 patched source files. Its only outputs are the two new paths you name:

```sh
python3 scripts/package_native_client.py \
  --source "$CODEX_SOURCE" \
  --output /private/tmp/codex-native-v3 \
  --evidence /private/tmp/codex-native-v3.json
```

The builder keeps only `PATH` for Git/Rustup discovery, an isolated `HOME` and `TMPDIR`, the selected `CARGO_HOME` offline cache, `RUSTUP_HOME`, and fixed offline/toolchain settings. It strips other inherited `CARGO_*` and `RUST*` overrides. It rejects Cargo config in the selected cache and all unreviewed working-directory ancestors. The two exact pinned configs are recorded in evidence: the repository-root `.cargo/config.toml` (`b34b20f64e30695e8629ddad8b80885764e947f51e4ce49c6378a3b5a238d25e`) sets `MALLOC_CONF=thp:always` with `force=false`, and `codex-rs/.cargo/config.toml` has SHA-256 `b8ae1cea341beb2d4a3c8fb81f97a96f4aee1fd53f769c57f140dfe949806a80`. Cargo propagates the root setting to its child processes. Any missing or modified pinned config, Cargo-home config, or other ancestor config is rejected.

The evidence contains the upstream commit, full-tree archive selection and extraction filter, patch and file hashes, both accepted Cargo config paths and hashes, Git/Rustup/Cargo/rustc binary paths and hashes, exact Rust/Cargo versions, the 159 build-only lockfile version changes, and the CLI SHA-256. The selected offline Cargo cache remains same-user mutable local state; recording its path and configuration does not remotely attest the cached package bytes. `launcherQualified` is true only when the rebuilt file matches the existing launcher digest. A different digest remains a candidate and is refused by the shipped launcher.

### Artifact handoff

Keep the builder's executable and evidence JSON together as one external artifact
pair; neither is included in the Python wheel. Before launch, require
`launcherQualified: true`, recompute the executable SHA-256, and confirm it
matches both `binarySha256` and `launcherSha256` in the evidence. Pass that
absolute executable path and `launcherSha256` to `knitli-event-gateway launch`.
The launcher checks the path and digest again immediately before execution. A
candidate with `launcherQualified: false` is not launchable by the shipped CLI.

The latest full-tree clean build and v3 runtime result are recorded in
[`native-client-build-proof.json`](native-client-build-proof.json). The rebuilt
candidate SHA-256 is
`3e88bd929a8c1d6e29dd562c47c9264df5b8f5904847695b8b490ddcf492387c`; it differs
from the frozen launcher hash, so the evidence records
`launcherQualified: false`. Three earlier builds using the selective
`codex-rs` plus generated SDK archive and only `codex-rs/.cargo/config.toml`
produced different hashes; temporary source paths appear in those binary
strings, but the cause has not been isolated. The full-tree build uses a
different archive and includes the pinned repository-root Cargo config, so it
is a separate observation rather than another sample in that comparison. No
bit-for-bit reproducibility is claimed. The two-TUI runtime proof uses only a
loopback synthetic model (`realModelCalls: 0`); it
does not prove cloud settlement or public admission.

Run the native runtime qualifier against the candidate and the exact installed wheel/reader recorded in its proof. For the two-TUI restart proof, the captured v3 runner is `docs/native-bridge/durable-restart-v3-qualify.py`; use the reader and wheel hashes pinned in `durable-restart-v3-checkpoint.md`, and pass the candidate's freshly computed SHA:

```sh
EVENT_NATIVE_QUALIFIER="$EVENT_PINNED_READER" "$EVENT_PROOF_PYTHON" -I -O \
  docs/native-bridge/durable-restart-v3-qualify.py \
  --binary /private/tmp/codex-native-v3 \
  --sha256 "$(shasum -a 256 /private/tmp/codex-native-v3 | cut -d ' ' -f 1)" \
  --output /private/tmp/codex-native-v3-runtime.json
```

Review the source/build and runtime evidence together before any separately
authorized qualification change. This runbook does not install the client or
rotate the launcher's digest. Public owner enrollment and cloud attachment
remain blocked on the separately reviewed attach tuple/challenge/CAS contract
and executable combined admission proof. Native self-report, a build manifest,
or a checkbox does not grant public runtime authority.
