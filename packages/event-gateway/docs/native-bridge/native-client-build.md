# Build and qualify the pinned native client

The launcher accepts only the reviewed v3 CLI digest `0fb3a5de06ab2ccb8dcc20c11cb71cad1f0c1b85fbfa3a5c6fd16ca1f57d22de`. This runbook rebuilds a disposable candidate from upstream Codex `a956835d020762cb2b570053af06f643a11c0ecc`, applies the cumulative v3 patch, checks all 48 patched source hashes, and records the toolchain and binary digest. It never installs the client or changes the launcher's digest.

Use a clean checkout of the exact upstream commit, Rust 1.95.0 (`59807616e`), Cargo's existing offline cache, and Apple Silicon macOS. The builder copies only the pinned Codex and generated SDK source paths into a temporary directory. Its only outputs are the two new paths you name:

```sh
python3 scripts/package_native_client.py \
  --source "$CODEX_SOURCE" \
  --output /private/tmp/codex-native-v3 \
  --evidence /private/tmp/codex-native-v3.json
```

The builder keeps only `PATH` for Git/Rustup discovery, an isolated `HOME` and `TMPDIR`, the selected `CARGO_HOME` offline cache, `RUSTUP_HOME`, and fixed offline/toolchain settings. It strips other inherited `CARGO_*` and `RUST*` overrides. It rejects Cargo config in the selected cache or any working-directory ancestor, except the exact pinned upstream `codex-rs/.cargo/config.toml` whose SHA-256 is `b8ae1cea341beb2d4a3c8fb81f97a96f4aee1fd53f769c57f140dfe949806a80`.

The evidence contains the upstream commit, patch and file hashes, accepted Cargo config hash, Git/Rustup/Cargo/rustc binary paths and hashes, exact Rust/Cargo versions, the 159 build-only lockfile version changes, and the CLI SHA-256. The selected offline Cargo cache remains same-user mutable local state; recording its path and configuration does not remotely attest the cached package bytes. `launcherQualified` is true only when the rebuilt file matches the existing launcher digest. A different digest remains a candidate and is refused by the shipped launcher.

The latest clean build and v3 runtime result are recorded in
[`native-client-build-proof.json`](native-client-build-proof.json). The rebuilt
candidate SHA-256 is
`055c99b49ef203d72965de72355d5b91b38306ec7fb8ec2e7fdac3b5575d8588`; it differs
from the frozen launcher hash, so the evidence records
`launcherQualified: false`. Three clean builds from the same pinned source and
patch, using the same Rust 1.95.0/Cargo 1.95.0 toolchain, produced different
hashes; temporary source paths appear in their binary strings, but the cause
has not been isolated. The two-TUI
runtime proof uses only a loopback synthetic model (`realModelCalls: 0`); it
does not prove cloud settlement or public admission.

Run the native runtime qualifier against the candidate and the exact installed wheel/reader recorded in its proof. For the two-TUI restart proof, the captured v3 runner is `docs/native-bridge/durable-restart-v3-qualify.py`; use the reader and wheel hashes pinned in `durable-restart-v3-checkpoint.md`, and pass the candidate's freshly computed SHA:

```sh
EVENT_NATIVE_QUALIFIER="$EVENT_PINNED_READER" "$EVENT_PROOF_PYTHON" -I -O \
  docs/native-bridge/durable-restart-v3-qualify.py \
  --binary /private/tmp/codex-native-v3 \
  --sha256 "$(shasum -a 256 /private/tmp/codex-native-v3 | cut -d ' ' -f 1)" \
  --output /private/tmp/codex-native-v3-runtime.json
```

Review the source/build and runtime evidence together before changing `QUALIFIED_SHA256` in `event_gateway/launcher.py`. Public owner enrollment and cloud attachment remain blocked on the separately reviewed attach tuple/challenge/CAS contract and executable combined admission proof. Native self-report, a build manifest, or a checkbox does not grant public runtime authority.
