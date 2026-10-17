# Local reviewer Docker boundary proof

One authorized local run passed: **13/13 child checks**, PID-namespace init **1**, harmless sleeping descendant **7**. Seven mock-only tests passed before execution. See [result-receipt.json](result-receipt.json) and the exact bounded [actual-run-1.log](actual-run-1.log).

Environment: local **macOS Docker Desktop**, Linux ARM64 engine **29.7.2** (root-reported). The supervisor checked the image's Linux/ARM64 identity. This is not hosted-runner equivalence. The already-present official `python:3.12-slim` image was selected by full immutable local ID; no pull or installation occurred.

## Frozen source and result

| File | SHA256 |
| --- | --- |
| `supervisor.py` | `9b97e86cfb497b33c422fa5151e4d6f9acf76ffbccb710164811c957269ce838` |
| `fixture/child.py` | `0d53fe1df5c4253bd8770e931fb9c29176a3773513def15dd4f7ef776d4c8647` |
| `test_supervisor.py` | `627e9f781d6be515df8f32170ec791a7087c655686c6fddc7caa35c0ad0fb020` |
| `actual-run-1.log` | `481cd1e2073dc31aa58311a263a7ccbe2bbffde9863ed01c111957bfe8640b75` |

## Exact execution configuration

The approved entrypoint was:

```sh
python3 /private/tmp/reviewer-docker-isolation-20261017/supervisor.py --run
```

`supervisor.py:create_args` constructs this command. `<OWNED_HOST_DIR>` is a fresh private directory under this proof folder; it is **not mounted**. Only the UUID/container name and that directory vary:

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

The private default PID namespace is required by inspect validation (`PidMode` empty/private); host/shared PID mode is rejected. No socket, repository, home, host `/proc`, token or command-file mount exists. The client environment keeps only Docker client configuration/path variables. Worker configuration is checked for GitHub/Actions/Anthropic/canary environment variables. Canary bytes are synthetic and remain host-only.

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

No SDK, native Claude runtime, model/provider invocation, hosted runner, platform attempt/digest handoff, authenticated artifact acquisition, durable admission or clean-round notification was qualified. No additional Docker execution occurred while packaging this proof. The `--run` flag explicitly opts into the experiment; it is not a production activation switch.

## Repository packaging and checks

The three executed Python files are byte-for-byte copies of the frozen private proof. Their hashes above identify the executed source, not a refactored implementation. The private run path and command are historical evidence; the files do not hardcode that folder as their source location. For mock-only checks from this repository folder:

```sh
python3 -m unittest -v test_supervisor.py
ruff check --config ../../../pyproject.toml supervisor.py fixture/child.py test_supervisor.py
```

The Ruff config path above is relative to this folder. No Docker run is part of these checks. Any later approved live run binds this folder's `fixture` directory, so its actual mount path differs from the historical command. The historical run used the configured local Docker Desktop context; its name was not captured and no context was explicitly pinned. The fixture requires `/usr/local/bin/docker`, the exact already-present Linux ARM64 image ID, and the documented isolation flags; it does not pull a replacement, and the inherited Docker client context must be understood before an opt-in run. It does not enforce a named context. Unsupported configuration fails closed. The `--run` flag is an explicit experiment opt-in.

Next protocol work remains unimplemented: a Docker-aware producer spawn/lifecycle seam, independently protected platform-attempt/envelope-digest handoff, then authenticated **post-run** acquisition. The existing composer requires the source run completed; a finalizer inside that same run cannot satisfy that fence. No workflow, SDK/provider call, admission policy or production activation is introduced by this documentation fixture.

Repository packaging validation: 7 mock-only tests PASS; the event-gateway Ruff configuration and standalone C901 check PASS; all six files pass whitespace diff checks. No Docker re-execution or source changes occurred.
