# Build and qualify the pinned native client

The current launcher pins main CI artifact digest `763e5e2b574f60b766d0d1b73b74ecc32d09d46479afe24e164299ca3633717b`; see [CI artifact qualification](native-ci-qualification.md). The earlier restored build remains historical in [restored-build qualification](native-restored-qualification.md). The earlier `362074…5f27` proof remains in [metadata qualification](native-metadata-qualification.md). This runbook rebuilds a disposable candidate from upstream Codex `a956835d020762cb2b570053af06f643a11c0ecc`, applies the cumulative `native-core-idle-v1-implementation.patch`, checks every output hash in `native-core-idle-v1-source-manifest.json`, and records the toolchain and binary digest. It never installs the client or changes the launcher's digest.

The build recipe includes the [Core active-turn snapshot](core-turn-idle-spike.md). The current release pin remains unchanged: the new recipe produces a candidate for separate runtime qualification and a reviewed pin update. The historical metadata and CI qualification proofs describe their original recipes.

Use a clean checkout of the exact upstream commit, Rust 1.95.0 (`59807616e`), Cargo's existing offline cache, and Apple Silicon macOS. Supply the matching official [code-mode host archive](https://github.com/openai/codex/releases/download/rust-v0.160.0/codex-code-mode-host-aarch64-apple-darwin.tar.gz) as a local file; the builder never downloads it. Its SHA-256 must be `dc70fbc76e9dcae5ae3d5424808c8e7c2df5e0db4ac827ddd4fbe339015aad75`. The builder archives the entire pinned Git tree into a temporary directory, with no pathspecs, then applies the reviewed patch and validates every patched source file against the complete output manifest. It creates the two new paths you name and a new `codex-code-mode-host` beside the CLI:

```sh
python3 scripts/package_native_client.py \
  --source "$CODEX_SOURCE" \
  --code-mode-host-archive "$EVENT_CODE_MODE_HOST_ARCHIVE" \
  --output /private/tmp/codex-native-v3 \
  --evidence /private/tmp/codex-native-v3.json
```

The builder keeps only `PATH` for Git/Rustup discovery, an isolated `HOME` and `TMPDIR`, the selected `CARGO_HOME` offline cache, `RUSTUP_HOME`, and fixed offline/toolchain settings. It strips other inherited `CARGO_*` and `RUST*` overrides. It rejects Cargo config in the selected cache and all unreviewed working-directory ancestors. The two exact pinned configs are recorded in evidence: the repository-root `.cargo/config.toml` (`b34b20f64e30695e8629ddad8b80885764e947f51e4ce49c6378a3b5a238d25e`) sets `MALLOC_CONF=thp:always` with `force=false`, and `codex-rs/.cargo/config.toml` has SHA-256 `b8ae1cea341beb2d4a3c8fb81f97a96f4aee1fd53f769c57f140dfe949806a80`. Cargo propagates the root setting to its child processes. Any missing or modified pinned config, Cargo-home config, or other ancestor config is rejected.

The evidence contains the upstream commit, full-tree archive selection and extraction filter, patch and file hashes, both accepted Cargo config paths and hashes, Git/Rustup/Cargo/rustc binary paths and hashes, exact Rust/Cargo versions, the 159 build-only lockfile version changes, and the CLI SHA-256. It also records the official host's release tag, target, archive digest, extracted executable digest and byte sizes. Only its expected regular archive member is accepted; links, unexpected members and altered bytes are rejected. The selected offline Cargo cache remains same-user mutable local state; recording its path and configuration does not remotely attest the cached package bytes. `launcherQualified` is true only when the rebuilt file matches the existing launcher digest. A different digest remains a candidate and is refused by the shipped launcher.

### Artifact handoff

Keep the builder's CLI, sibling `codex-code-mode-host` and evidence JSON together;
neither executable is included in the Python wheel. All three outputs must be new
and distinct. Failed publication removes only files created by that invocation.
Treat `launcherQualified: true`
as an operator handoff check: recompute the executable SHA-256 and confirm it
matches both `binarySha256` and `launcherSha256` in the evidence. When the
original build predates a reviewed pin promotion, retain that historical
evidence and use the separately reviewed release proof to identify the
promoted digest; it must match the current hard-coded launcher pin. The launcher
does not read the evidence JSON. It independently verifies the sibling host
against digest `679eedaea70529aa1cffc9bc0a0788c186412663544fa76c09d63b57f383a65a`
and rejects host path overrides. Pass the absolute executable path and its
SHA-256 to `knitli-event-gateway launch`; the CLI checks that digest against the
hard-coded `QUALIFIED_SHA256` pin again immediately before execution. A
different build requires a separate reviewed pin update, and changing the
evidence file alone does not authorize it.

The earlier full-tree clean build and v3 runtime result are recorded in
[`native-client-build-proof.json`](native-client-build-proof.json). The rebuilt
candidate SHA-256 is
`3e88bd929a8c1d6e29dd562c47c9264df5b8f5904847695b8b490ddcf492387c`. The historical
build evidence records `launcherQualified: false` against the former `0fb3…22de`
pin. The [native release checkpoint](native-release-runtime.md) subsequently
qualified this exact preserved candidate with the current reader and actual
foreground launcher; the launcher and builder pinned `3e88…387c` at that checkpoint. Historical
evidence remains unchanged. Three earlier builds using the selective
`codex-rs` plus generated SDK archive and only `codex-rs/.cargo/config.toml`
produced different hashes; temporary source paths appear in those binary
strings, but the cause has not been isolated. The full-tree build uses a
different archive and includes the pinned repository-root Cargo config, so it
is a separate observation rather than another sample in that comparison. No
bit-for-bit reproducibility is claimed. The two-TUI runtime proof uses only a
loopback synthetic model (`realModelCalls: 0`); it
does not prove cloud settlement or public admission.

Run the native runtime qualifier against the candidate and the exact installed wheel/reader recorded in its proof. For the two-TUI restart proof, the current v3 runner is `docs/native-bridge/durable-restart-v3-qualify.py`; use the current reader, adapter, and wheel hashes in [`native-release-runtime.md`](native-release-runtime.md), and pass the candidate's freshly computed SHA. Earlier durable-restart checkpoints retain historical wheel pins.

```sh
EVENT_RECOVERY_CACHE="$(mktemp -d)"
EVENT_NATIVE_QUALIFIER="$EVENT_PINNED_READER" "$EVENT_PROOF_PYTHON" -I -B -O \
  -X "pycache_prefix=$EVENT_RECOVERY_CACHE" \
  docs/native-bridge/durable-restart-v3-qualify.py \
  --binary /private/tmp/codex-native-v3 \
  --sha256 "$(shasum -a 256 /private/tmp/codex-native-v3 | cut -d ' ' -f 1)" \
  --output /private/tmp/codex-native-v3-runtime.json
rm -d "$EVENT_RECOVERY_CACHE"
```

Review the source/build and runtime evidence together before any separately
authorized qualification change. This runbook does not install the client or
rotate the launcher's digest. The attach tuple/challenge/CAS implementation is
merged; the [controlled admission proof](admission-workerd.md) exercises its
actual paths with real native witnesses. Public owner enrollment and deployed
cloud admission still require their live qualification. Native self-report, a build manifest,
or a checkbox does not grant public runtime authority.
