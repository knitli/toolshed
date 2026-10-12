# Main CI artifact qualification

**Controlled offline PASS, 2026-10-12.** The proposed launcher pin is the
exact executable from successful protected-main
[build 38273438173, attempt 1](https://github.com/knitli/toolshed/actions/runs/38273438173),
commit `7ff224a1fc8a9923e33aeafbd66cfa65efdc8bea`.
The [selection](native-release-provenance.json) identifies immutable artifact
`11758567975`, its raw ZIP digest, and both executable digests. The CLI is
`763e5e2b574f60b766d0d1b73b74ecc32d09d46479afe24e164299ca3633717b`;
the companion code-mode host remains `679eedae…83a65a`.

The protected-main verifier checked fresh GitHub run/artifact identity,
successful main-only execution, ancestry, five approved recipe hashes, the
build receipt and all 52 patched-source hashes. It hashed the raw ZIP and
bounded executable members before extraction or execution. Candidate recipe
files match protected main; the launcher changes only its permitted digest
literal. This establishes provenance of these exact CI-built bytes, without
claiming bitwise reproducibility across machines. Artifact expiry or deletion
invalidates promotion verification.

The [proof projection](native-ci-qualification-proof.json) records the exact
wheel, installed module/contract inventory, unchanged private proof hashes and
their field mapping. Qualification used one fresh non-editable wheel matching
the complete candidate source, private executable copies and fresh synthetic
Codex homes. Independent audits rehashed the artifact, installed package and
qualification inputs and checked the correlated results.

| Check | Controlled result |
| --- | --- |
| Production launcher and host | One Start; fresh file contents returned by the actual host; correlated `inputRecorded` |
| Installed GitHub source command | One signed synthetic transport; exact validated source output; correlated receipt |
| Foreground lifecycle | Six active redraw samples preserve binding; resize and composer revoke readiness; graceful exit 0 |
| Two-TUI restart | Exact expired receipt recovered twice; 15 changed identity probes return Unknown; old Start refused |
| Three-session gateway/workerd | A/B isolated; busy C2 retained through daemon restart; C1 observed history preserved through explicit attach; stale C2 fenced; one fresh C3 Start; identical observed ACK replay |
| Cleanup and integrity | All 53 inventoried inputs unchanged; no owned processes/control sockets remain; recovery cache empty |
| Regression checks | 568 gateway tests passed during qualification; after rebasing the test-only socket-readiness fix, all 569 pass. Four Node source-boundary checks, Ruff and vendored contract verification pass |

The historical [restored build](native-restored-qualification.md) remains
unchanged evidence for its former `62eac2…343a3` digest. It is not relabeled as
CI-built. The launcher rejects that digest and earlier releases after this
promotion. The current builder obtains its admission pin from the launcher;
it does not independently authorize another executable.

Repeat the installed-launcher checks using the
[host runbook](native-host-qualification.md), and the recovery checks using
the retained two-TUI qualifier. Choose new evidence paths. These fixtures use
synthetic providers/source transport, zero real model/cloud calls, and no owner
credentials. Host runs enforce their existing outer sandbox; lifecycle/restart
runs deny external networking and permit loopback/Unix sockets.

The three-session rerun used the same wheel and exact CI executable pair, the
unchanged runner, and cloud source `df7cf5b1e4ac3fb40de664c594c934abdda730de`.
All 142 workerd input hashes matched the selected source/dependencies; all 510
inventoried run inputs remained unchanged. Its raw proof SHA-256 is
`51f8acaae227fa943ee51d76e545d96be50e084bdfdf4b5b09582e7db3dc711e`.
The first invocation failed during proof assembly because broker-relative build
paths were resolved from another working directory; it emitted no PASS proof.
The successful retry used the same explicit private directory for runner cwd
and `TMPDIR`, with absolute input/output arguments. Failed logs remain private.
All scenario and cleanup assertions passed, including native Start counts
A/B/C of 1/1/2 and unchanged C1 history through attach. Access, Messaging,
publication and model responses are fixtures; loopback replaces Mesh. There
is no independent network capture or runner-wide outer sandbox claim. C2
remains stale; C3 requires explicit fixture reattachment.

No owner client was installed or changed. Production admission, authenticated
Mesh delivery, live owner wake, automatic rebinding and GitHub delivery remain
unqualified and disabled. Earlier ambiguous attempts remain unresolved.
