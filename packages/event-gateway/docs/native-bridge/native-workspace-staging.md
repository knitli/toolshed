# Native workspace input staging

The offline VM boundary canary passed in [PR #210](https://github.com/knitli/toolshed/pull/210).
The full Rust workspace remains unqualified. This step prepares source and a
Cargo dependency cache inside an already provisioned, credential-free macOS 15
arm64 VM. It does not compile or test the workspace, launch the native client,
install or promote a release, or enable automatic turns.

## Boundary

Use a disposable preparation VM with no owner credentials, shared host folders,
clipboard, SSH agent, or user data. Public dependency acquisition belongs in that
guest. The macOS 27 host must not supply its Cargo, Rustup, Homebrew, or SDK trees.
A version check inside the guest does not attest that it is a VM or credential-free;
those remain operator and host-controller responsibilities.

The existing NIC-drop canary cannot download dependencies. Connected preparation
requires separately reviewed networking enforced outside the guest that permits
public downloads while denying host, private, link-local, and metadata access.
This staging command does not configure networking or authorize a VM launch.
No workspace compilation or test execution is permitted during connected preparation.

Freeze the entire stopped preparation VM after successful staging. This preserves
the guest's SDK, Homebrew libraries, Rust toolchain, and absolute paths together.
A source/Cargo receipt alone is not a portable toolchain bundle or proof that a
later build needs no other inputs. The host must measure the powered-off VM's
config, disk, and NVRAM and bind that receipt to the staging receipt before an
offline clone can be admitted. The original prepared base remains unchanged.

## Provisioned inputs

Before staging, the guest must already have the reviewed tools used by the
existing [workspace workflow](../../../../.github/workflows/event-native-workspace.yml):

- macOS 15, arm64, Python 3.13 or newer, and Git.
- Rust 1.95.0 for `aarch64-apple-darwin`, with its existing pinned compiler check.
- cargo-nextest 0.9.128, `just`, GNU `timeout` and `env` (`gtimeout` and
  `genv` from coreutils), and an available Apple SDK.
- GLib/GObject and GStreamer, base, app, and audio pkg-config modules; the four
  GStreamer modules must be at least 1.28.
- Explicit private Cargo and Rustup homes created for this preparation VM.
- The exact upstream checkout and the reviewed Toolshed scripts and recipe assets.

The command does not bootstrap these tools. Record how their public inputs were
acquired; successful version checks are not a supply-chain attestation.

## Fixed preparation

Run `packages/event-gateway/scripts/stage_native_workspace.py --source <upstream>
--output <new-stage-directory>` inside that guest with the selected Cargo and
Rustup homes. The output must be new, and the selected roots must be private and
non-overlapping. Credential files and unreviewed Cargo configuration are refused.
The subprocess environment uses a new empty HOME and temporary directory, keeping
only the explicit tool/cache selection and fixed build settings. Replay, metadata, and fetch stdout
and stderr are retained exclusively, capped at 64 MiB per stream with a 30-minute
timeout per command and owned process-group cleanup. GNU `env --chdir` supplies the working
directory to the existing bounded runner without modifying the canary controller.

The command:

1. Verifies the runtime and provisioned tools before source acquisition.
2. Calls the existing pinned source replay in a clean child environment. The
   immutable `core-idle-v1` revision 1 recipe and paired V8 asset checks stay intact.
3. Resolves metadata with `codex-v8-poc/sandbox`, then validates only the existing
   159 local lock-version normalizations. It preserves both lock versions.
4. Fetches the exact normalized lock with `cargo fetch --locked` and rejects drift.
5. Resolves metadata again with `--offline --locked` and the same feature selection,
   checks the graph, lock, and recipe-covered source inventory, and writes the
   staging receipt last.

The `recipeSourceInventory` hashes only files covered by the registered recipe,
not every file in the upstream tree. The later stopped-VM measurement covers the
complete prepared disk.

A partial failure must not publish a successful receipt. Preserve its output for
diagnosis rather than reusing it or deleting caller inputs. The receipt reports
`qualified: false`; successful offline metadata proves dependency resolution,
not compilation, the full workspace suite, or arbitrary build-script behavior.

## Freeze and later qualification

After staging, the host must stop and reap the owned preparation VM, confirm its
stopped state, and measure its complete files into a new protected base receipt.
A later runner must clone that measured base and attach only the reviewed
`--net-fd` drain/drop boundary. Do not add a caller-supplied command to the fixed
canary. The runner needs its own reviewed fixed suite command, timeout, complete
logs, disk evidence, and exact-clone cleanup.

The existing 50 GB virtual disk is not a demonstrated build fit. Measure staged
source, caches, toolchain and installed dependencies, then budget target growth
and reporting space before compilation. Host free space does not establish guest
free space. No host `target/` directory is created by this step.

The known source-fixture failures in
[native-workspace-qualification.md](native-workspace-qualification.md) remain
separate blockers. Any fixture overlay must be reviewed independently without
rewriting the immutable production recipe, excluding tests, weakening assertions,
or automatically accepting snapshots. Keep native promotion and automatic turns
off until the separate qualification and admission gates pass.
