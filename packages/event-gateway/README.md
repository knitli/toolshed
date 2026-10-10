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

Build with `uv build --wheel`, then install that wheel in an isolated environment
or with `uv tool install path/to/knitli_event_gateway-0.1.0-py3-none-any.whl`.
The installed wheel embeds the verified contract; no contract fetch happens at
runtime. There is no PyPI publication workflow in this PR.

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

Run from an interactive terminal, naming the exact reviewed v3 prototype:

```sh
knitli-event-gateway launch \
  --codex-binary /absolute/path/to/qualified/codex \
  --binary-sha256 d82007ca79c2d73cfdf811bcb5efe949831c2652b3114b836f5eefea9f269c02 \
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
The binary is not distributed in this wheel. Same-user code and configuration
are trusted: hash validation precedes execution but is not an atomic hash/exec
guarantee against another process running as that user.

Build and qualify a candidate from the pinned upstream source using the
[native client build workflow](docs/native-bridge/native-client-build.md). It
records source and binary hashes. Keep its executable and evidence JSON as one
external artifact pair. Treat `launcherQualified: true` as an operator handoff
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
generation pairs. See the [cloud client lifecycle and recovery details](docs/cloud-adapter.md).

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
reference, and fixture bytes at `ed23882eac491e26e070e3ef26cf8c0e9e702b38`.

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
Snapshot verification does not prove that every Python semantic
edge matches TypeScript: the canonical corpus still lacks portable semantic
boundary vectors. Expanding that corpus and running both validators is an open
cross-repository qualification gate.

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
