# Offline Messaging v2 admission interoperability

`tests/test_messaging_workerd.py` crosses the actual Python `Gateway`, `CloudClient`
and SQLite journal through loopback HTTP into workerd's production `eventFetch`,
`OwnerRegistry`, `EventAuthority`, `Mailbox` and `AgentCoordinator`. It does not
substitute a mocked HTTP response or a fake reservation authority.

The fixture creates a message through real `issue`/`deliver`, prepares its cloud
publication, and signs the actual v2 transport envelope. Python verifies those
bytes and journals them as held. Its cloud client signs the exact delivery/attempt
claim, which the real HTTP API and owner registry authenticate. The real Mailbox
owns the consumer check and shared budget reservation.

The four integration tests cover:

- One shared-budget charge and exact permit/envelope history after SQLite reopen,
  without a second HTTP claim.
- A server-side committed admission followed by a closed HTTP connection: local
  intent remains uncertain after SQLite reopen, with no automatic resend.
- Routing, key and source revocation before claim: no permit or generic-budget fallback.
- A corrupted node proof: `node_denied` before reservation.

Every case asserts zero native adapter calls, held local state, no native receipts,
and empty dispatch/reconciliation polling. External Worker egress is blocked by
Miniflare and its attempted-call count must remain zero. Each case uses a fresh
worker process and synthetic keys; the broker binds only to loopback and requires
an ephemeral secret on its closed fixture/API route set.

Three host-only tests also verify a partial-handshake deadline, process-group shutdown,
and preservation of the original failure when cleanup fails. Two opt-in mutation tests
verify rejection of dirty source, missing/added inputs and changed compiled bytes before
worker execution, plus detection of a swallowed native-construction assertion on the
original lost-reply gateway before its ledger is reopened.

## Run

Use a fresh cloud checkout with its committed `apps/os/cloudflare-os` revision and
installed OS dependencies. The fixture uses the installed `capnweb-validate`
esbuild plugin, including generated RPC argument validation, and aliases OS
workspace packages to the supplied checkout's source. Supply explicit local
paths; no dependency install or provider access is performed by the test.

`tests/fixtures/messaging-workerd-inputs.json` pins the exact approved input set and
SHA-256 hashes from merged Cloud source commit
`9503b8e2a99fbe099a4b90cb576a17dcf4b786aa` with the
`apps/os/cloudflare-os` gitlink at `22daf8d01f701da90d3d68f686883288802ad420`.
Paths are relative to the cloud source, fixture directory or dependency `.pnpm`
directory, allowing checkout relocation.
A pinned whitespace-minified bundle digest additionally binds the bytes actually
executed, including RPC validation plugin output, closing the source-reread race.
Both checks run before Miniflare construction. Updating source, dependencies or
compiler output requires explicit review and a new manifest; a claimed Git revision
alone never admits a build.

From the Toolshed root, using its existing gateway Python environment:

```sh
export FIXTURE_NODE=/absolute/path/to/node
export FIXTURE_CLOUD_SOURCE=/absolute/path/to/knitli-site/apps/os
export FIXTURE_MINIFLARE=/absolute/path/to/miniflare/package-directory
PYTHONPATH=packages/event-gateway/src \
  packages/event-gateway/.venv/bin/python -m unittest discover \
  -s packages/event-gateway/tests -p test_messaging_workerd.py -v
```

The tests skip unless all three paths are explicitly configured. A skipped default
suite is not evidence for this interoperability gate. No CI activation is added.

## Source-admission 9503 qualification

The final source-bound qualification ran on Gateway base
`37abd1616a98b811757025f09a1d87902b2fabab` against Cloud source
`9503b8e2a99fbe099a4b90cb576a17dcf4b786aa` and `cloudflare-os` gitlink
`22daf8d01f701da90d3d68f686883288802ad420`. The workerd profile passed all 11
tests in 17.601 seconds with no skips. The exact 353-input manifest (134 Cloud,
218 dependencies, one fixture worker) and compiled bundle SHA-256
`ae2780852f959675a19a53d04f8b6a05cbf9915a8fa97b2e359c7f39524b81d4` are
recorded in the [final qualification receipt](messaging-v2-source-admission-9503-final-qualification.json).
That receipt records all six profile results, commands, runtime and executable
source hashes, prior failed attempts and cleanup evidence.

The initial and corrected compile-preparation receipts remain unchanged and
describe preparation only; the corrected record is
[messaging-v2-source-admission-9503-reduced-env-preparation.json](messaging-v2-source-admission-9503-reduced-env-preparation.json).
The Oct 17 crash and alarm receipts remain historical evidence for their earlier
Cloud freeze. This local qualification does not claim later Gateway heads or
production runtime behavior.

## Qualification boundary

This is local admission/history proof. Owner approval, active keys, route ownership,
node enrollment and native binding are seeded prior state. The Access JWT is
cryptographically verified against a synthetic local JWKS; Cloudflare Access
itself is not exercised. A closed transport port translates the configured
synthetic HTTPS origin to loopback HTTP while preserving signed body bytes and
node proof. It does not qualify TLS, deployed Mesh, an active gateway listener,
installed clients, native execution/receipts, positive ACKs or settlement.

The fixture invokes the real preparation alarm explicitly; its automatic alarm
callback is suppressed and queue handoff is a controlled port. This does not prove
Queue delivery, alarm recovery or unattended wake. SQLite reopening is within the
same Python process, not a process-crash or machine-reboot test. All production
activation gates and production source files remain unchanged.
