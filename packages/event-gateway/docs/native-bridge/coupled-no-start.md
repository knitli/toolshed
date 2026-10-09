# Controlled combined terminal no-start qualification

PASS, 2026-10-08. The pinned native binary, production local Gateway/Store/CloudClient,
and production coordinator/registry in disposable workerd complete the terminal
no-start lifecycle. [Retained-evidence proof](coupled-no-start-proof.json),
[unknown-after-restart proof](coupled-no-start-unknown-proof.json), and
[source/causal manifest](coupled-no-start-manifest.json) retain the exact evidence.
Production admission remains unproved. No deployment or owner-client installation occurred.

## Retained terminal evidence

The actual cloud admission is persisted with the complete native request before
submission. An explicit harness adapter delays submission until that same permit
expires, refreshes the unchanged selected-native witness, then calls the normal
NativeBridgeAdapter submission path. The SDK checks selection freshness and request
identity but does not reject expired permits locally. No guard is bypassed, request
field changed, or native result manufactured. The real v3 backend returns an exact
`terminalNotStarted` / `permitExpired` receipt without model traffic.

The harness drops this native reply before Gateway persistence. Reopening SQLite
and reconciling performs one exact read-only native receipt lookup. Gateway durably
records the recovered terminal UUID and submits settlement to the real coordinator.
The harness drops that HTTP 200 reply only after workerd commits. A second local
restart sends identical settlement bytes with a fresh node-proof nonce; coordinator
readback is unchanged. The original attempt and permit remain `not_started`, with
one immutable settlement and the original synthetic budget charge still consumed.
The pending delivery retains its actual registry slot; this is not input observation.

One fresh attempt and permit then produce an authentic native start and submitted
ACK. Repeated dispatch does not claim or start again. There are exactly two successful
claims and one primary mock-model call. Budget usage is two: the refused original
attempt and its one fresh replacement. No observed ACK or watermark is inferred.

## Unknown evidence remains fenced

The second run loses the real terminal reply, then stops the actual TUI/backend and
starts different processes against the disposable StateDB. This native implementation
retains terminal no-start evidence only in memory. Three reconcile/dispatch rounds
therefore each receive an actual v3 `unknown` native reply, with the complete original
request tuple and matching nonce captured. Each exchange must finish successfully
and leave the validated bridge open; a transport exception cannot satisfy this proof.
The gateway remains ambiguous with the original attempt, no settlement, no fresh claim,
no native start, and zero model traffic. The coordinator readback remains unchanged.
A durable positive receipt does not make terminal evidence durable across restart.

## Reproduce and check

Use the existing prerequisites and invocation from [packaged recovery](packaged-recovery.md),
with current source `--package` / `--qualifier`, omit `--installed --restart-native`,
and add `--terminal-no-start`. Add `--forget-terminal` for the unknown branch.
These runs used source imports, not an installed-wheel claim. The frozen binary SHA is
`0fb3a5de06ab2ccb8dcc20c11cb71cad1f0c1b85fbfa3a5c6fd16ca1f57d22de`;
cloud source is `dc8cb0117ca4d5f497563a13dc438fa3b5238ba2`. All executed first-party
cloud source hashes match that commit; each proof also records all 133 bundled inputs.
The broker adds only the fixed settlement route; readback adds the actual immutable
settlement table. Other authority fixtures retain the existing coupled harness scope.

Four scratch harness mutations failed at their intended assertions, then restored
runs passed: delivering the initial terminal reply violated the required ambiguous
checkpoint; omitting native restart preserved real terminal evidence and violated
the required unknown checkpoint; closing the private socket before recovery violated
the successful-native-communication assertion even though Gateway remained ambiguous.
Altering the settlement only in the readback after the fresh attempt violated the
immutable-settlement assertion. The final readback also checks the original retired
attempt/permit, the submitted replacement/current claim, retained slot, and absent
observed watermark.
These are causal harness checks, not product-source
mutation coverage. Setup/readback assertion mistakes during development are excluded.
Ruff and `git diff --check` pass. No broad product suite was rerun for this harness-only change.

The post-retry assertion refresh ran with checkout HEAD `5f9012f8b470cdb8e6a942215b4eb58b1c41cc1c`;
all executed first-party cloud inputs still match the pinned `dc8cb011` commit exactly.
