# Local reviewer Docker boundary proof

Current hardened source passed staged **attempt 4: 13/13 checks, exit 0**, with init PID **1** and descendant PID **7**. Root separately reported empty exact-ID and exact-name absence readbacks, both exit 0. See [hardened-attempt-4-receipt.json](hardened-attempt-4-receipt.json) and [exact log](hardened-attempt-4.log).

The current candidate adds lint-only `nosec B404/B603` annotations, an `__init__` docstring, and test blank lines. These edits change source bytes without intended behavior changes. Attempt 4 executed the fresh byte-exact staged source successfully; attempt 3 remains evidence for the prior source only.

Historical run 1 at commit `dc8c028e0cc09f45e85879ade6c59a0ff6551fa6` passed: **13/13 child checks**, PID-namespace init **1**, harmless sleeping descendant **7**. Seven mock-only tests passed before execution. See [result-receipt.json](result-receipt.json) and the exact bounded [actual-run-1.log](actual-run-1.log).

Environment: local **macOS Docker Desktop**, Linux ARM64 engine **29.7.2** (root-reported). The supervisor checked the image's Linux/ARM64 identity. This is not hosted-runner equivalence. The already-present official `python:3.12-slim` image was selected by full immutable local ID; no pull or installation occurred.

The same hardened source failed at the repository bind path in attempt 2, then passed from byte-identical temporary staging in attempt 3. All attempts remain recorded below. The historical tables and seven-test counts describe original run 1, not the hardened source.

## Historical frozen source and result

| File | SHA256 |
| --- | --- |
| `supervisor.py` | `9b97e86cfb497b33c422fa5151e4d6f9acf76ffbccb710164811c957269ce838` |
| `fixture/child.py` | `0d53fe1df5c4253bd8770e931fb9c29176a3773513def15dd4f7ef776d4c8647` |
| `test_supervisor.py` | `627e9f781d6be515df8f32170ec791a7087c655686c6fddc7caa35c0ad0fb020` |
| `actual-run-1.log` | `481cd1e2073dc31aa58311a263a7ccbe2bbffde9863ed01c111957bfe8640b75` |

## Historical execution configuration

The approved entrypoint was:

```sh
python3 /private/tmp/reviewer-docker-isolation-20261017/supervisor.py --run
```

The original `supervisor.py:create_args` constructed this command. `<OWNED_HOST_DIR>` is a fresh private directory under this proof folder; it is **not mounted**. Only the UUID/container name and that directory vary:

```sh
/usr/local/bin/docker create \
  --pull=never \
  --name reviewer-isolation-<UUID> \
  --cidfile <OWNED_HOST_DIR>/container.cid \
  --label reviewer.fixture=reviewer-isolation-<UUID> \
  --network=none --user=65532:65532 --cap-drop=ALL \
  --security-opt=no-new-privileges:true --read-only --ipc=private \
  --pids-limit=32 --memory=128m --memory-swap=128m --cpus=1 \
  --tmpfs /work:rw,noexec,nosuid,nodev,size=16777216,uid=65532,gid=65532,mode=0700 \
  --log-driver=none --restart=no \
  --mount type=bind,src=/private/tmp/reviewer-docker-isolation-20261017/fixture,dst=/fixture,readonly \
  --entrypoint=python3 \
  sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d \
  -I -B /fixture/child.py <OWNED_HOST_DIR>/host-canary
```

The private default PID namespace is required by inspect validation (`PidMode` empty/private); host/shared PID mode is rejected. No socket, repository, home, host `/proc`, token or command-file mount exists. The original client environment retained Docker client configuration/path variables. Worker configuration is checked for GitHub/Actions/Anthropic/canary environment variables. Canary bytes are synthetic and remain host-only.

The supervisor validates actual image/container configuration **before start**, then attaches to the exact created container ID. Each captured subprocess read is bounded to 64 KiB and 15 seconds; this is not a 15-second total-run deadline, and cleanup uses additional bounded commands. Docker logging is disabled.

Actual owned container: `c0d7012ef4d2378fd589fc1517556472ffdc6f3f8f5ac4211a71f4f32a3fa6ac`; name: `reviewer-isolation-59f55c5eec7a48689bc61766cdac3a7d`.

## Observations and cleanup

All checks passed: scratch writes succeed; rootfs/fixture writes fail; host canary cannot be read; Docker socket absent; UID/GID 65532; no extra groups; all capability sets zero; no-new-privileges active; credential environment absent; init PID 1; descendant shares that namespace with parent PID 1. The host also verifies its canary digest remains unchanged.

The supervisor's PASS requires kill if running, exact-ID stopped readback with `State.Pid == 0`, removal, then empty exact-ID list readback. Root reported those transitions for this run. Root independently confirmed both the exact container ID and exact name absent at 2026-10-17T15:38:53.580435+00:00; the combined receipt includes the original observation fields and source receipt hash, without raw inspect transcripts. The log contains the summarized PASS, not raw Docker inspect transcripts. Create-response-loss recovery uses the exact random name plus matching ownership label; ambiguity or cleanup error prevents PASS. No broad kill/prune operation exists.

## Mock-only checks

```sh
cd /private/tmp/reviewer-docker-isolation-20261017
python3 -m unittest -v test_supervisor.py
```

Observed: **7 tests passed, 0 failed**; root independently repeated them successfully. These test incorrect inspect/config rejection, failed child checks, stop/removal requirements, continued cleanup after simulated errors, lost-create-response ownership recovery, command-plan restrictions and credential environment exclusion. Negative controls use fake observations; no live weakened container configuration was run. Actual limit exhaustion, daemon failure and creation-timeout recovery were not induced in the live run.

## Meaning and next dependency

This proof establishes the tested local Docker filesystem/process boundary and supervisor-owned cleanup for this harmless Python probe. Docker daemon, Docker VM/kernel and host supervisor are trusted. It is not a hostile-kernel escape test.

The next required work is a **Docker-aware spawn/lifecycle seam**: track exact container identity and authoritative state across startup, stdio, timeout and cleanup. The existing reviewer's native `ChildProcess` owner cannot be replaced with a Docker CLI process unchanged: **Docker CLI exit or kill does not prove the container or descendants stopped**. This proof does not implement that SDK integration.

No SDK, native Claude runtime, model/provider invocation, hosted runner, platform attempt/digest handoff, authenticated artifact acquisition, durable admission or clean-round notification was qualified. No additional Docker execution occurred during the original packaging; the later hardened attempts are recorded below. The `--run` flag explicitly opts into the experiment; it is not a production activation switch.

## Repository packaging and checks

The original packaging at commit `dc8c028e0cc09f45e85879ade6c59a0ff6551fa6` copied the three executed Python files byte for byte. The hashes above identify that historical source and log; current modified files are not covered by run 1. The private run path and command are historical evidence.

For mock-only checks of the current candidate from this repository folder:

```sh
python3 -m unittest -v test_supervisor.py
ruff check --config ../../../pyproject.toml supervisor.py fixture/child.py test_supervisor.py
```

No Docker run is part of these checks. A live run binds the executed supervisor's sibling `fixture` directory; attempts 3 and 4 used their respective frozen temporary staging paths below. Run 1 used the configured local Docker Desktop context; its name was not captured and no context was explicitly pinned.

## Hardened attempts and successful staged runs

One later root-executed attempt of supervisor SHA256 `27e9b24bda45bb4378201448563f42b5018d36d68666e6baa9754ea23661d7cc` exited **1**: `docker create failed`, with no CID or child evidence. The cause remains unknown. The supervisor reported incomplete cleanup. Root later independently confirmed its exact random name absent (exit 0, empty output); no CID or prior stopped-PID transition is known, and this does not establish that creation never happened. Daemon IDs before and after matched. See the exact [hardened-attempt-1.log](hardened-attempt-1.log) and [attempt receipt](hardened-attempt-1-receipt.json).

Attempt 2 executed diagnostic supervisor SHA256 `8e3bdae9189a8798cdab8d9b0748f882525bceed47b10da4f91577761c4ab1ed` and exited **1**. Its bounded Docker error output reports that the repository fixture bind source does not exist from the daemon’s perspective. The host source exists; this does not prove the Docker VM can see `/opt`. No CID or child evidence was obtained; the supervisor reported incomplete cleanup. Root later confirmed its exact random name absent (exit 0, empty output); no CID or stopped-PID transition is known. See [hardened-attempt-2.log](hardened-attempt-2.log) and [attempt receipt](hardened-attempt-2-receipt.json).

The three prior reviewed source files were staged byte for byte at `/private/tmp/reviewer-docker-hardened-m6v1uarm`, documented in [hardened-staging-manifest.json](hardened-staging-manifest.json). The manifest records staging-time state, before execution. Attempt 3 executed these unchanged sources successfully from this frozen owned staging directory. No global Docker file-sharing change was made. This demonstrates access to the staged fixture for this run, not access to the repository under `/opt`.

Attempt 3 returned **PASS**, exit **0**, with all 13 child checks true, init PID **1**, and descendant PID **7**. Container ID: `e1bff78be1fda4b1d0965272a4582c8dc06d8dbe05e2426a218f3f474ef01541`; name: `reviewer-isolation-f939dc4541ee4fdabee6278fdc6d895f`. Daemon ID before and after was `804dc7e7-2939-459e-b28d-4e1a35038c92`. Root separately reported explicitly local exact-ID and exact-name list readbacks, both exit 0 with empty output. These independent checks are operator-supplied evidence; raw readback transcripts are not included. The [attempt 3 receipt](hardened-attempt-3-receipt.json) records all three executed source hashes and the exact log hash. The earlier failed attempts retain their separate exact-name absence observations; they do not become passing qualification results.

Attempt 4 ran the unchanged final lint-only source from `/private/tmp/reviewer-docker-final-y9lu18gi` and returned **PASS**, exit **0**, with all 13 checks true, init PID **1**, and descendant PID **7**. Container ID: `15dac90cd4360a5f9d86621197bf26ee7443ac16fbe9ce99f9a4d1c59a402158`; name: `reviewer-isolation-a50bc397c5394178b9e940eacae0514d`. Daemon ID before and after was `804dc7e7-2939-459e-b28d-4e1a35038c92`. Root separately reported explicitly local exact-ID and exact-name absence readbacks, both exit 0 with empty output; these are operator-supplied observations, not archived raw readback transcripts. See [attempt 4 receipt](hardened-attempt-4-receipt.json) and [exact log](hardened-attempt-4.log). Attempts 1–3 remain historical evidence for their respective source bytes.

The candidate targets the fixed user-owned Unix socket `~/.docker/run/docker.sock`. It verifies socket type and ownership with `lstat` and rechecks socket identity before each command. Every Docker command uses explicit `--host=unix://<socket>` and a fresh owned client configuration directory, with no ambient `DOCKER_*` environment. Supported operations and their arguments are validated. A CID becomes eligible for mutation only after read-only inspect confirms its exact ID, owned random name, and ownership label; an owned container with invalid configuration is still cleaned up. The candidate records Docker daemon `info` ID before and after the run in its receipt.

Attempt 4 qualifies the tested local staged boundary for the current source; the earlier attempts remain distinct historical evidence. Historical run 1 hashes and test counts remain unchanged. The fixture still requires `/usr/local/bin/docker`, the exact already-present Linux ARM64 image ID, and the documented isolation flags; it does not pull a replacement. Unsupported configuration fails closed. The `--run` flag is an explicit experiment opt-in.

Next protocol work remains unimplemented: a Docker-aware producer spawn/lifecycle seam, independently protected platform-attempt/envelope-digest handoff, then authenticated **post-run** acquisition. The existing composer requires the source run completed; a finalizer inside that same run cannot satisfy that fence. No workflow, SDK/provider call, admission policy or production activation is introduced by this documentation fixture.

Historical repository packaging validation: 7 mock-only tests PASS; the event-gateway Ruff configuration and standalone C901 check PASS; all six files pass whitespace diff checks. No Docker re-execution or source changes occurred during that original packaging. These results do not validate the modified candidate.

Prior hardened-source validation before attempt 3 staging: **20 mock-only tests passed**; event-gateway Ruff and standalone C901 (maximum complexity 15) passed. The three source hashes remained unchanged through attempt 3.
