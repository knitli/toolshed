# Native pair candidate, 2026-10-25

**Held: provenance and four local fixture proofs complete; workspace tests, hosted qualification and promotion pending.**

The candidate comes from protected-main [build 40245269530, attempt 1](https://github.com/knitli/toolshed/actions/runs/40245269530),
Toolshed `378a017bcc2c53bb198ff555727c52e046037f94`. The exact v2
[selection](native-release-provenance.json) binds artifact `12619145586`, the
core-idle-v1 revision 1 recipe (57 files), raw archive and both executables.
The CLI is `d1758a403e2066209e01f2c250cb58a50ab9636383f5cdee87a41a6d4463d993`;
the paired host remains `679eedaea70529aa1cffc9bc0a0788c186412663544fa76c09d63b57f383a65a`.

Independent verification checked GitHub run/artifact identity, protected-main
ancestry, trusted recipe inputs, the complete patched-source inventory, receipt,
raw ZIP digest and exact three arm64 artifact members before private extraction.
Nothing in that verification executes or qualifies the candidate.

The candidate retains current-main launcher logic and the dormant fail-closed
terminal-evidence path; only the CLI digest changes. The two-TUI runner's three
integrity pins are rebased to the current qualifier, adapter and reader. These
files changed behavior since the historical proof (held-response timing and
Messaging V2 validation); pin updates are preparation, not equivalence evidence.
Historical proofs and their source hashes remain unchanged.

Local proofs used one noneditable wheel, SHA-256
`66e27d734d049ac5df2b820c121b4f73f9dfb6706ad0e80835eb45f6ea6baef3`,
and the exact authenticated pair. Each run exited 0 with no real model calls:

| Proof | SHA-256 of private raw JSON |
| --- | --- |
| Installed host source read and InputRecorded correlation | `f95118aa6d97d6b3731a80c73ac14493b041fdf0afbcb6e6d9970e3d03f4afd0` |
| Foreground redraw, resize and readiness | `5142dac9f72bf2a656cdfb94ebef7753cf3f04e4af4123a29cf3847edb467f55` |
| Two-TUI durable recovery and identity refusals | `44a173c4efcb3232f3d0740fd7d0a39ee4437b47d04345df61bab555137dc806` |
| Workerd admission/renewal using fixture authority | `2cf4d202d79a6712297fea3d3b6c16c4e8f3911c6e93db1f49dfc2a999a6311c` |

All four proofs have independent raw-evidence audits. Admission covers lost-reply
attach retry, renew, stale/gate refusals and transfer fencing; no explicit detach
route is exercised. Bundle inputs are hash-correlated; emitted bundle bytes were
not retained for independent digest recomputation. Local containment allows
localhost and Unix sockets. It does not prove
production admission, cloud settlement, hostile same-user containment, or VM
disposal. Recovery explicitly leaves cloud settlement unproven.

Admission initially stopped before native launch on two fixture defects:
`node:crypto` was not externalized, then cold direct SQL reads preceded lazy
coordinator initialization. The broker now matches the coupled broker's exact
external rule; fixture readers call the existing read-only `status()` method.
Broker-only negative/positive checks reproduced missing-table 500s, then returned
200 for admission, coupled admission and coupled diagnostic reads. Production
runtime source is unchanged.

[Workspace run 40249802476](https://github.com/knitli/toolshed/actions/runs/40249802476)
passed source/V8 replay and dependency priming, but stopped before tests because
Cargo was absent from the restricted PATH. This is no native test result;
[PR #205](https://github.com/knitli/toolshed/pull/205) corrects the runner path.

Before promotion, retain and independently audit fresh exact-wheel evidence for:

- Full patched Rust workspace tests with the pinned V8 pair and GLib present.
- Installed launcher/host source read and correlated InputRecorded receipt.
- Foreground redraw, resize and readiness lifecycle.
- Two-TUI durable recovery with all identity-mutation and stale-Start refusals.
- Workerd admission/renewal and the contained three-session/recovery scenarios.

Use synthetic authorities/providers, disposable configuration, private evidence,
and reviewed bounded containment. No owner credentials, real model calls, policy
widening, automatic turns, or executable-mapping probe is part of these fixtures.
The executable-mapping finding and live production qualification remain separate.
Official installation requires promotion merged under CI/review gates; the
disposable qualification wheel is never an active user profile.
