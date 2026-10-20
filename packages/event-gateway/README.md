# Knitli event gateway foundation

This package owns local event transport, durable receipts, and harness adapters
for the Event Runtime. **Automatic wake is disabled by default.** An explicit
private dispatch configuration enables local delivery through an admitted,
launcher-owned session. Production release still requires live qualification.

Owner decision, 2026-10-05: build the foundation and investigate Codex bridges
with a separate agent. Do not infer a live client's selected thread from a PID,
working directory, loaded thread, or session-tree ID.

```text
signed metadata → bounded listener → private SQLite spool
  queued → durable claim → admitted → durable native request → submitted (ACK pending)
                           └→ never written       └→ retained terminal no-start
                                  └──── exact cloud settlement ────┘ → new attempt
  uncertain native outcome → ambiguous (exact receipt recovery; no blind replay)
```

The dispatcher uses the injected cloud claim DTO and private native bridge.
It persists claim intent before network access and the complete native request
before submission. Definite no-start proof retires only the original permit;
unknown outcomes remain fenced. The integrations have no production defaults.
Without `run --dispatch-config`, the shipped CLI runs only the private control
daemon. An explicit configuration connects the signed listener, cloud authority,
and durable dispatch/recovery worker; see [configured dispatch](docs/native-dispatch.md). `attach`, `renew`, and `transfer` require an explicit
private cloud configuration and remain subject to the server's native-admission
gate. `enroll` creates a local key and prepares an owner request without
claiming cloud enrollment. The private control daemon supports status, detach,
and single-writer attachment mapping updates. Installation does not start it.
The separate foreground `launch` command owns one explicitly qualified native
client and exposes local selection status plus bounded conditional Start and
receipt operations. Launching alone does not attach a cloud runtime or enable delivery.

## Install and run

Requires Apple Silicon macOS or Linux and Python 3.13+. Development and CI pin Python 3.13.14
and uv 0.12.15. Use the committed lock:

```sh
cd packages/event-gateway
uv sync --frozen
uv run --frozen knitli-event-gateway --help
uv run --frozen knitli-event-gateway status
uv run --frozen knitli-event-gateway run
```

Build with `uv build --wheel`. For a supported owner installation on Apple Silicon
macOS, use the repository's paired installer from current protected main with
CPython 3.13+ and an authenticated `GITHUB_TOKEN`:

```sh
python3 -I scripts/install_paired_client.py \
  --wheel /absolute/path/to/knitli_event_gateway-0.1.0-py3-none-any.whl \
  --native-artifact /absolute/path/to/native-client-artifact.zip \
  --destination /absolute/path/to/new-client-environment
```

The destination must not exist. Before creating it, the command checks the wheel
against authenticated main source and verifies the promoted native/companion pair,
CI receipt and current build recipe. A pending consumer/native transition fails
closed, even when launcher pins have not changed. Keep the previous working client
until the paired release is promoted; a successful consumer PR alone does not
permit installation. Raw `uv tool install` bypasses this paired release gate.

The installer uses PyPI only for runtime dependencies pinned by main's `uv.lock`,
requires approved wheel hashes and refuses source builds. It verifies the fresh
installed package and copied executables before printing handoff paths. It does
not switch the active client, register a default tool, create gateway state, start
a service, or execute the native binary. Failures clean up its owned destination;
existing installations remain untouched. Same-user code is trusted, as for launch.
The wheel embeds the verified contract; no contract fetch happens at runtime.

The wheel includes `event_gateway.native_reader.NativeBridge`, the same private
socket reader used by the qualification harness. A qualified host supplies an
already connected private Unix stream and owns client selection and launch.
The reader closes that stream on `close()` or an invalid exchange. Version 2
remains the default; `receipt_version=3` explicitly enables durable receipt
identity. `restore_attempt(request)` consumes the start-once identity for exact
read-only recovery; it grants neither selection nor permission to start.
`NativeBridgeAdapter` connects this reader to the existing gateway admission
and recovery flow. Installing the reader does not attach or launch a client. See the
[combined native restart qualification](docs/native-bridge/packaged-recovery.md).

### Explicit foreground client

Run from an interactive terminal, naming the exact [qualified CI artifact](docs/native-bridge/native-ci-qualification.md):

```sh
knitli-event-gateway launch \
  --codex-binary /absolute/path/to/qualified/codex \
  --binary-sha256 763e5e2b574f60b766d0d1b73b74ecc32d09d46479afe24e164299ca3633717b \
  --cwd /absolute/path/to/project
```

Add `--resume NATIVE-THREAD-UUID` to resume one explicit native thread. A resumed
session reports selected only while its live witness names that exact thread.
The launcher preserves the user's Codex home, authentication and configuration;
it refuses inherited bridge/test-adoption markers and dynamic-loader overrides.
It never searches PATH for Codex. The executable and its ancestors must be
owned by the current user or root, without other-user write access (root-owned
sticky temporary directories are allowed). The executable must match the one
reviewed digest above; a stock Codex binary or a different rebuild is refused.
Its sibling `codex-code-mode-host` must match the pinned official
`rust-v0.160.0` Apple Silicon executable digest
`679eedaea70529aa1cffc9bc0a0788c186412663544fa76c09d63b57f383a65a`,
with the same ownership and permission checks. Host path overrides are refused.
Neither executable is distributed in this wheel. Same-user code and configuration
are trusted: hash validation precedes execution but is not an atomic hash/exec
guarantee against another process running as that user.

Build and qualify a candidate from the pinned upstream source using the
[native client build workflow](docs/native-bridge/native-client-build.md). It
records source and binary hashes. Keep the CLI, its sibling code-mode host and
evidence JSON together. Treat `launcherQualified: true` as an operator handoff
check: the evidence is not read by the launcher. `launch` accepts the executable
path and supplied SHA-256, then checks them against the hard-coded
`QUALIFIED_SHA256` pin. Admitting a different build requires a separate reviewed
pin update; changing the evidence file alone does not authorize it.
The binary is not in the Python wheel, and the workflow does not install or
enroll a client.

The standalone build runs with `--no-daemon`, keeping its app-server in the
owned foreground process group. The TUI retains terminal input, output and resize behavior. A private inherited
socket carries v3 bridge traffic. Startup synchronization grants no selection;
selected status requires a fresh witness. A timed-out status read preserves one
pending reply without interrupting the TUI. A later query drains and discards
that old reply; the following query requests a fresh witness. This read-only path
revokes any prior Start eligibility and never grants permission to start a turn;
conditional Start obtains and checks fresh eligibility under the launcher lock. The printed session UUID identifies
only this launcher. From another terminal, use the same `--state-dir` if supplied:

```sh
knitli-event-gateway client-status --session-id PRINTED-SESSION-UUID
```

The response reports `selection: selected` with the exact native thread, or
`selection: unavailable`; `attached` and `automaticWakeEnabled` remain false.
Status is an observation at query time, never admission or a reusable lease.
When a fresh validated reply contains a complete binding for the expected thread,
`nativeObservation` reports only `eligible`, the opaque native `cause` label, and
`binding` (`clientId`, `connectionId`, `backendPid`, `threadId`, `generation`,
`serverInstanceId`, `serverGeneration`). Ineligible observations keep
`selection: unavailable` and grant no Start eligibility, including with a zero
lease. Missing, malformed, late, incomplete, or wrong-thread replies omit this
field. The binding supports correlation with independently observed work on the
owned client; neither ineligibility nor the cause label proves that a tool is busy.
The observed `eligible` flag can remain true while `selection` becomes unavailable
if its local lease expires before the final selection check. This diagnostic flag
grants no Start authority; Core independently checks that the thread is idle.
The owner-only session socket accepts presence, binding and admission witness
requests, plus conditional Start and exact read-only receipt recovery for an
explicit mapped session. It exposes no arbitrary native commands. The foreground launcher removes it and closes its bridge when
the TUI exits. Cleanup signals only the owned, unreaped process group, never a
PID reported by a witness. There is no background restart or service install.

### Explicit cloud attachment lifecycle

The foreground `attach`, `renew`, and `transfer` commands use the cloud
challenge API and a fresh read-only witness from the running launcher. They do
not enable automatic renewal, wake, or dispatch. The server controls whether
native admission is enabled; while its production gate is disabled, requests
are refused with `native_binding_unqualified`.

### Explicit assigned-stock conversation

This is a default-off development path for the existing v1 manual canary.
GitHub publication does not yet materialize local deliveries, and Messaging v2
delivery remains disabled. Before activation, the shared authority settlement
must be completed: the current generic reservation leaves a permanent native
unsettled marker that blocks a later Messaging v2 route for the same agent.

The stock Codex path is opt-in and names an existing canonical conversation UUID;
it never discovers or selects a latest thread. Reuse the private cloud config and
node key below. First assignment creates generation 1:

```sh
knitli-event-gateway stock-control attach \
  --runtime-id RUNTIME-UUID --conversation-id CODEX-CONVERSATION-UUID \
  --cloud-config /private/path/cloud-config.json
```

Renew with the exact returned generation pair:

```sh
knitli-event-gateway stock-control renew \
  --runtime-id RUNTIME-UUID --conversation-id CODEX-CONVERSATION-UUID \
  --expected-runtime-generation 1 --expected-attachment-generation 1 \
  --cloud-config /private/path/cloud-config.json
```

A replacement attach also requires the current generation pair and advances
both generations. If the request outcome is unknown, renew the exact profile
using the generation pair printed by the command; do not send new client input
to resolve uncertainty. Reassignment fences future submissions; it does not
cancel input already accepted by the old conversation.

To enable the local adapter, the private dispatch config must also name
`"stockCodexBinary": "/absolute/path/to/codex"`. Omitting it disables stock
dispatch. The cloud profile has its own explicit principal/agent canary gate;
the native binding gate remains separate. The existing runtime lease lasts
90 seconds. A running daemon with `stockCodexBinary` configured renews an
existing assigned-stock mapping every 30 seconds using its exact conversation
and generation pair; it does not start, inspect, or reassign client sessions.
Renewal stops for that exact mapping after a definitive refusal or mismatched
response. An ambiguous transport result retries the same renewal with bounded
backoff while the local lease remains live. This does not change global client
configuration.

A stock ACK with status `command_accepted` records a successful CLI exit in the
Gateway journal. It is not an independently verified durable client receipt or
proof that a turn started or completed. Lost cloud ACKs replay that stored ACK;
uncertain client submissions remain ambiguous and are never automatically sent
again. A running stock daemon may continue the same assigned conversation after
the TUI closes. Fully stopped-runtime behavior remains unqualified; the
[0.163.0 upstream command](https://github.com/openai/codex/blob/rust-v0.163.0/codex-rs/tui/src/session_archive_commands.rs)
can choose an embedded server when no shared daemon is available.

Create `cloud-config.json` and its sibling `cloud-credentials.json` in a private
directory. The configuration stores immutable identity and only the credential
filename; credentials are reread for each request:

```json
{
  "version": 1,
  "origin": "https://events.example.com",
  "principal": "owner@example.com",
  "agent": "pilot-agent",
  "nodeId": "00000000-0000-4000-8000-000000000001",
  "nodeGeneration": 1,
  "credentialsFile": "cloud-credentials.json"
}
```

The credential file has exactly `accessToken` and `agentToken`. Set both files
to mode `600`; replace the sample identity with the enrolled node and
owner-approved agent for this Event origin. A new attach can be requested with:

```sh
chmod 600 /private/path/cloud-config.json /private/path/cloud-credentials.json
knitli-event-gateway --state-dir "$HOME/.local/state/knitli-event-gateway" attach \
  --runtime-id 00000000-0000-4000-8000-000000000002 \
  --session-id 00000000-0000-4000-8000-000000000003 \
  --cloud-config /private/path/cloud-config.json
```

`--session-id` is the exact UUID printed by the foreground launcher. Renewal
also requires `--expected-runtime-generation` and
`--expected-attachment-generation`; transfer requires source and replacement
generation pairs. `runtime-status` reads stored cloud generations; `reconcile`
creates a fenced successor for retained ambiguous attach/renew evidence. See the
[retained native recovery procedure](docs/native-bridge/runtime-reconciliation.md)
and [cloud client lifecycle details](docs/cloud-adapter.md).

Default state is `~/.local/state/knitli-event-gateway`, with mode 0700 directories
and 0600 files/socket. `--state-dir PATH` accepts a private directory without
symlink components; use canonical `/private/tmp` paths for macOS scratch tests.
Never place it in a shared or synced directory. Stop the daemon before upgrading;
unsupported database versions refuse to open. Restart quarantines unfinished
native attempts as ambiguous, preserving receipts and explicit recovery needs.

No service is installed or native client resumed on reboot. User-service
installation and full owner enrollment remain qualification work after the
presence/authority seams are implemented.

## Contract and validation

`contracts/event-v1/manifest.json` pins the canonical OS schema, semantic
reference, and fixture bytes at `7b63bee97395a70e05ffb08ee214e8351f6dda06`.
The fixture embeds the canonical 45 semantic verdicts: 30 raw-parser, six
delivery-digest and nine ACK-binding cases. Both runtimes execute these cases;
normal Python tests require the embedded corpus, including optimized-mode
wrong-verdict rejection.

```sh
uv run --frozen python scripts/sync_contract.py --check --fetch
uv run --frozen ruff check src tests scripts
uv run --frozen python -m unittest discover -s tests -v
```

An update requires an explicit reviewed 40-character commit; never a branch or
tag. Ordinary Linux/macOS PR CI checks the local manifest hashes offline, runs
the shared corpus and local fault tests, and installs the wheel outside the
repository. It receives no App key. A trusted-main workflow matches all seven
event/control snapshot files, including both manifests, against one complete
reviewed family. Candidate paths must be regular Git blobs; candidate code is
never checked out or executed. Rotations add policy data rather than verifier
branches or fixture-specific tests. Keep reviewed immutable source pins through
unrelated upstream changes; new snapshot bytes require a reviewed policy change
on main before the consumer can pass.

Policy merges automatically revalidate all open PR heads. Retargeting and
gateway CI completion revalidate the affected head, including stacked PRs.
Queued runs remain serialized; publication rechecks the current head and main
policy so obsolete runs cannot overwrite newer results. Transient reads retry
within a bounded budget, and unavailable evidence reports an error rather than
claiming contract drift. Policy-only PRs retain the existing snapshots and can
pass before the policy lands; dependent consumers remain gated until it lands.
The control corpus includes GitHub source readback request/result vectors
exported from the pinned cloud schema using Zod 4.6.5: numeric and Unicode
limits, projected record types, cursor completion/epoch checks, and response
byte limits. Consumer tests exercise these through Python validation and the
HTTP response boundary. Request identity, pagination binding, and duplicate
record checks remain separately tested local invariants. These vectors do not
qualify live authorization, source initialization, delivery, or native wake.
The `cloud-guard-baseline-messaging-v2-dispatch` family selects the immutable
Cloud guard baseline `7b63bee97395a70e05ffb08ee214e8351f6dda06`. Its complete
seven-file hash map was authorized on trusted main in #162. All eleven historical
families retain their hashes and archived snapshots; their authorization does not
establish runtime compatibility with this or later Cloud revisions.

The control manifest pins 39 source paths, including `github/host-storage-version.ts`
and `messaging/protocol-v2.ts`. The exporter explicitly resolves the messaging DTO's
Zod, policy and protocol imports after checking every source hash and Zod version
4.6.5. It does not evaluate the host storage guard, internal reader or Worker
runtime modules. The selected Cloud dispatch schema preserves manual v1, rejects
GitHub v1 and accepts messaging v2 only when the envelope and claim node IDs agree.
The control fixture's unchanged manual-admission vectors do not cover this entire
acceptance change.

The source chain also covers watch-store, internal watch-control, watch-kernel,
owner-proof, delegated read authority and deadlines, GitHub client and principal
allowlist, source-control and watches, manual/native canary boundaries, admin
API/types, and memory authentication/admin security. The generated control DTO
fixture, event schema, policy and corpus remain byte-identical, preserving the
same 45 semantic cases. Event protocol.ts now exports its existing JSON decoder,
and both manifests rotate. This baseline does not attest future Cloud #902. There is no public watch route or client activation. New
create requires an exact-true flag that is unset in deployment configuration;
source activation, delivery and native attachment remain disabled by default.
These are selected offline provenance pins, not an executable dependency bundle or
proof of external authority, provider APIs, Cloudflare topology or native wake.
The shared 45 cases establish their listed semantic verdicts, not every possible
cross-language edge or live delivery readiness.

`security.py` documents a **proposed local** Ed25519 transport seam (exact bytes,
recipient audience, configured public-key ID). The dispatcher retains the exact
cloud admission DTO. Recovery of an expired
original permit can authorize its retirement, never a native start. Cloud
settlement must confirm the complete attempt, permit and evidence before one
fresh attempt returns to waiting; the original budget charge remains. No offline
or cached authority is accepted. Direct native starts retain the full original
request/receipt and one immutable
`native_turn_started` submitted ACK. Recovery retries that ACK and may poll the
original request read-only; it never claims or starts again. Registration does
not prove input observation or release the pending slot. A full InputRecorded
receipt permits a separate immutable observed ACK after confirmed registration.
Older cloud parsers leave the exact ACK pending.
See [no-start settlement](docs/no-start-settlement.md) and
[native input observation](docs/native-input-observation.md) for the qualification
gates. The historical [registration ACK proof](docs/native-start-ack-proof.json)
records its 23 individual causal cases, 173 passing source tests, independent
Node vector and installed-wheel qualification; it does not prove the later
observed phase.

The spool retains accepted metadata, private attachment mappings, deduplication,
and ambiguity. It fences generations, stops at capacity, and never evicts live
work to admit new deliveries. Busy queued work outlives transport freshness and
needs fresh admission later. It preserves all distinct events; source-aware
coalescing remains a later full-gateway gate.

See [client presence evidence](docs/client-presence.md) and
[bridge investigation](docs/codex-bridge-options.md) for the remaining client gate.
Three-session routing, authenticated live Mesh delivery, owner enrollment,
installed user-service lifecycle, and cross-repository semantic conformance
must pass before release. The prior bounded spike is historical evidence only.

### Retained GitHub source readback

`github-source-read` requests exactly one authorized page using the private cloud
configuration and enrolled node key already used by `runtime-status`:

```sh
knitli-event-gateway --state-dir /private/state github-source-read \
  --cloud-config /private/cloud.json \
  --installation-id 123 --repository-id 456 --pr-number 7 \
  --from-version 2 --to-version 5
```

For another page, repeat the same subject/range flags and pass the returned
`nextCursor` object as `--cursor '<JSON>'`. The caller validates the subject,
range, fixed anchor, cursor progression and closed safe record projections.
The cursor binds both the current lifecycle epoch and the retained observation
epoch, which can be older after a failed reconciliation. Duplicate record
identities within a page are rejected.
Each request is capped at 4096 bytes and each response at 8192 bytes. The command
prints one JSON result and exits 0 for `ok`, or 2 for `coverage_unavailable`,
`conflict`, or a sanitized transport/authorization failure. It does not retry or
paginate automatically. A conflict requires restarting without the old cursor.

`complete` means this is the final page of that cursor chain. A standalone final
page does not prove the caller retained all earlier pages. Anchor state and
backward transitions can include versions above `toVersion`; those bridge records
are needed to reconstruct the requested inclusive range. This command reads
retained source state, not GitHub directly, and does not attach a runtime or
establish native wake qualification.
