# Build and qualify the pinned native client

The launcher accepts only the reviewed v3 CLI digest `0fb3a5de06ab2ccb8dcc20c11cb71cad1f0c1b85fbfa3a5c6fd16ca1f57d22de`. This runbook rebuilds a disposable candidate from upstream Codex `a956835d020762cb2b570053af06f643a11c0ecc`, applies the cumulative v3 patch, checks all 48 patched source hashes, and records the toolchain and binary digest. It never installs the client or changes the launcher's digest.

Use a clean checkout of the exact upstream commit, Rust 1.95.0 (`59807616e`), Cargo's existing offline cache, and Apple Silicon macOS. The builder copies only the pinned Codex and generated SDK source paths into a temporary directory. Its only outputs are the two new paths you name:

```sh
python3 scripts/package_native_client.py \
  --source "$CODEX_SOURCE" \
  --output /private/tmp/codex-native-v3 \
  --evidence /private/tmp/codex-native-v3.json
```

The evidence contains the upstream commit, patch and file hashes, exact Rust/Cargo versions, the 159 build-only lockfile version changes, and the CLI SHA-256. `launcherQualified` is true only when the rebuilt file matches the existing launcher digest. A different digest remains a candidate and is refused by the shipped launcher.

The latest clean build and v3 runtime result are recorded in
[`native-client-build-proof.json`](native-client-build-proof.json). The rebuilt
candidate SHA-256 is
`ab1b74b5338d05b9285e6c28f3d81c4d94b38c6eeaa51b6a6955dcbd5ba0392b`; it differs
from the frozen launcher hash, so the evidence records
`launcherQualified: false`. Two clean builds from the same pinned source,
patch, and toolchain produced different hashes; temporary source paths appear
in their binary strings, but the cause has not been isolated. The two-TUI
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
