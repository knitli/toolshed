#!/usr/bin/env python3
"""Run a reviewed, pre-staged native fixture only on a disposable hosted macOS VM."""

import argparse
from contextlib import ExitStack
from datetime import datetime
import socket
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import subprocess
import stat
import traceback
import tempfile
from uuid import UUID

PORTS = (43121, 43122, 43123, 43124, 43125, 43126, 43127)


def require(value, message):
    if not value:
        raise ValueError(message)


def admit(environment, repository_id):
    expected = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_REF": "refs/heads/main", "GITHUB_REF_PROTECTED": "true", "GITHUB_RUN_ATTEMPT": "1",
                "RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_OS": "macOS",
                "RUNNER_ARCH": "ARM64", "GITHUB_REPOSITORY_ID": repository_id}
    require(all(environment.get(key) == value for key, value in expected.items()),
            "requires explicitly dispatched protected-main hosted macOS attempt 1")
    require(platform.system() == "Darwin" and platform.machine() == "arm64", "wrong host platform")
    require(re.fullmatch(r"[0-9a-f]{40}", environment.get("GITHUB_SHA", "")), "invalid workflow SHA")
    require(environment.get("GITHUB_RUN_ID", "").isdigit(), "missing run identity")
    require(environment.get("ImageOS") and environment.get("ImageVersion"), "missing hosted image identity")


def network_profile():
    # Reviewed code is trusted within the VM; this policy prevents accidental off-host calls.
    rules = ['(version 1)', '(allow default)', '(deny network*)',
             '(allow network* (local unix-socket) (remote unix-socket))']
    for port in PORTS:
        rules.extend((f'(allow network-bind (local tcp "localhost:{port}"))',
                      f'(allow network-outbound (remote tcp "localhost:{port}"))',
                      f'(allow network-inbound (local tcp "localhost:{port}"))'))
    return '\n'.join(rules) + '\n'


def write_private(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
        stream.write(value)


def command(args, profile, output):
    package = Path(args.package_root).resolve(strict=True)
    return ['/usr/bin/sandbox-exec', '-f', str(profile),
            str(Path(args.python).absolute()), '-I', '-B',
            str(package / 'docs/native-bridge/three-session-workerd.py'),
            '--package-source', str(package / 'src/event_gateway'),
            '--binary', str(Path(args.binary).resolve(strict=True)),
            '--binary-sha256', args.binary_sha256,
            '--node', str(Path(args.node).resolve(strict=True)),
            '--cloud-source', str(Path(args.cloud_source).resolve(strict=True)),
            '--cloud-commit', args.cloud_commit,
            '--esbuild', str(Path(args.esbuild).resolve(strict=True)),
            '--miniflare', str(Path(args.miniflare).resolve(strict=True)),
            '--output', str(output / 'proof.json'),
            '--trusted-hosted-vm',
            '--entry-port', str(PORTS[0]), '--loopback-port', str(PORTS[1]),
            '--broker-port', str(PORTS[2]), '--listener-port', str(PORTS[3]),
            '--model-ports', *(str(port) for port in PORTS[4:])]


def recovery_command(args, profile, output):
    package = Path(args.package_root).resolve(strict=True)
    return ['/usr/bin/sandbox-exec', '-f', str(profile), str(Path(args.python).absolute()), '-I', '-B',
            str(package / 'docs/native-bridge/coupled-workerd.py'),
            '--installed', '--restart-native', '--restart-inflight', '--trusted-hosted-vm',
            '--package', str(package), '--qualifier', str(package / 'scripts/qualify_native_bridge.py'),
            '--binary', str(Path(args.binary).resolve(strict=True)), '--binary-sha', args.binary_sha256,
            '--node', str(Path(args.node).resolve(strict=True)),
            '--cloud-source', str(Path(args.cloud_source).resolve(strict=True)), '--cloud-commit', args.cloud_commit,
            '--esbuild', str(Path(args.esbuild).resolve(strict=True)),
            '--miniflare', str(Path(args.miniflare).resolve(strict=True)), '--output', str(output / 'proof.json'),
            '--entry-port', str(PORTS[0]), '--loopback-port', str(PORTS[1]),
            '--broker-port', str(PORTS[2]), '--model-port', str(PORTS[4])]


def ports_released():
    # Intentionally stronger/different than the fixture's single IPv4 boolean
    # cleanup probe: hold every IPv4/IPv6 endpoint concurrently before scenario
    # reuse. Darwin permits TIME_WAIT; live listeners fail with no fallback.
    with ExitStack() as stack:
        for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
            for port in PORTS:
                listener = stack.enter_context(socket.socket(family, socket.SOCK_STREAM))
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if family == socket.AF_INET6:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind((host, port))


def cloud_identity(args, environment):
    source = Path(args.cloud_source).resolve(strict=True)
    require(source.parts[-5:] == ('apps', 'os', 'packages', 'event-runtime', 'src'), 'unexpected cloud source')
    root = source.parents[4]

    def git(*arguments):
        return subprocess.run(['/usr/bin/git', '-C', str(root), *arguments],
                              env={**environment, 'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                                   'GIT_OPTIONAL_LOCKS': '0'}, capture_output=True, text=True, check=True, timeout=10)
    checked = git('rev-parse', '--show-toplevel', '--verify', 'HEAD')
    require(checked.stdout.splitlines() == [str(root), args.cloud_commit], 'cloud source identity mismatch')
    git('diff', '--quiet', '--ignore-submodules=none', 'HEAD', '--')
    # Cached dependencies are pre-staged separately. Neither ignored nor ordinary
    # untracked application files may silently participate in module resolution.
    for ignored in (False, True):
        extra = ('--ignored',) if ignored else ()
        require(not git('ls-files', '--others', '--exclude-standard', *extra, '--', 'apps/os',
                        ':(glob,exclude)**/node_modules/**').stdout, 'uncommitted cloud application input')


def read_bounded(path, limit):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'invalid bounded evidence')
        value = stream.read(limit + 1)
    require(len(value) <= limit, 'evidence exceeds bound')
    return value


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_proof(args, scenario, output):
    raw = read_bounded(output / 'proof.json', 2_000_000)
    proof = json.loads(raw)
    require(proof['result'] == 'PASS' and proof['productionAdmissionProven'] is False
            and proof['realModelCalls'] == 0 and proof['cloudSourceCommit'] == args.cloud_commit,
            'wrong scenario outcome or cloud identity')
    containment = proof['executionContainment']
    require(containment['mode'] == 'trusted-hosted-vm-network-sandbox'
            and containment['kernelSandboxActive'] is True and containment['defaultNetworkDenied'] is True
            and containment['filesystemIsolationProven'] is False and containment['vmDisposalObserved'] is False,
            'wrong containment evidence')
    package = Path(args.package_root).resolve(strict=True)
    fixture = package / 'docs/native-bridge'
    if scenario == 'three-session':
        verify_three_session_proof(args, proof, output, fixture)
    else:
        require(scenario == 'native-recovery', 'unknown qualification scenario')
        verify_native_recovery_proof(args, proof, fixture, package)
    cloud_root = Path(args.cloud_source).resolve(strict=True).parents[2]
    inputs = (proof['workerdInputsSha256'] if scenario == 'three-session' else proof['cloudBundle']['inputs'])
    require(isinstance(inputs, dict) and bool(inputs), 'missing cloud source hashes')
    for name, expected in inputs.items():
        if scenario == 'native-recovery':
            require(Path(name).is_absolute(), 'recovery bundle input is not producer-normalized')
        source = (cloud_root / name).resolve(strict=True)
        require(source.is_relative_to(cloud_root) or source.is_relative_to(fixture), 'unexpected cloud bundle input')
        require(sha(source) == expected, 'cloud bundle source mismatch')
    return {'proofSha256': hashlib.sha256(raw).hexdigest(), 'scenario': scenario,
            'semanticChecksPassed': True}


def verify_busy_attach(proof, evidence):
    """Bind the public result to the recorded CLI challenge, CAS and C1 history."""
    message = 'three-session Busy attach evidence mismatch'

    def exact_int(value, minimum=0, maximum=2**53 - 1):
        return type(value) is int and minimum <= value <= maximum

    def uuid_string(value):
        return isinstance(value, str) and str(UUID(value)) == value

    def finite(value):
        return type(value) in (int, float) and math.isfinite(value)

    def binding_valid(binding):
        return (isinstance(binding, dict) and set(binding) == {
            'clientId', 'connectionId', 'backendPid', 'threadId', 'serverInstanceId',
            'generation', 'serverGeneration'}
            and all(uuid_string(binding[key]) for key in
                    ('clientId', 'connectionId', 'threadId', 'serverInstanceId'))
            and exact_int(binding['backendPid'], 1, 2**32 - 1)
            and exact_int(binding['generation']) and exact_int(binding['serverGeneration']))

    try:
        result = proof['busyFixtureAttach']
        require(all(result[key] is True for key in (
            'productionCliPath', 'coreBusyBeforeAndAfter', 'coreBusyDuringAttach',
            'c1HistoryAndChargesUnchanged'))
            and result['remoteStatus'] == 'attached' and result['localStatus'] == 'current', message)
        for name in ('runtimeGeneration', 'attachmentGeneration'):
            require(exact_int(result[name + 'Before'], 1) and exact_int(result[name + 'After'], 1)
                    and result[name + 'After'] == result[name + 'Before'] + 1, message)
        records = [json.loads(line) for line in evidence.splitlines() if line.strip()]
        rows = [row['value'] for row in records if row.get('kind') == 'busyFixtureAttach']
        require(len(rows) == 1, message)
        row = rows[0]
        hold_rows = [(index, record['value']) for index, record in enumerate(records)
                     if record.get('kind') == 'providerHoldStarted' and record.get('value', {}).get('session') == 'C']
        require(len(hold_rows) == 1, message)
        hold_index, hold = hold_rows[0]
        attach_index = next(index for index, record in enumerate(records) if record.get('kind') == 'busyFixtureAttach')
        require(hold_index < attach_index and hold['phase'] == 'initial'
                and all(finite(hold[key]) for key in ('startedAt', 'holdDeadline'))
                and 0 < hold['holdDeadline'] - hold['startedAt'] <= 60
                and finite(row['holdDeadline']) and row['holdDeadline'] == hold['holdDeadline'], message)
        require(row['result'] == result, message)
        history = row['before']
        require(history == row['after'] and all(key in history for key in (
            'localDelivery', 'localAttempts', 'workerdAttempts', 'workerdClaims',
            'receiptStatuses', 'nativeStarts', 'cloudHistory', 'slots', 'budget')), message)
        require(history['localDelivery']['state'] == 'observed'
                and history['localDelivery']['ack_state'] == 'observed'
                and len(history['localAttempts']) == len(history['workerdAttempts'])
                == len(history['workerdClaims']) == len(history['nativeStarts']) == 1
                and history['localAttempts'][0]['state'] == 'observed'
                and history['workerdAttempts'][0]['state'] == 'observed'
                and history['localAttempts'][0]['native_observed_ack'] is not None
                and type(history['localAttempts'][0]['reserved_bytes']) is int
                and history['localAttempts'][0]['reserved_bytes'] == 0
                and history['receiptStatuses'] == ['inputRecorded']
                and isinstance(history['cloudHistory'], dict)
                and isinstance(history['slots'], list)
                and all(isinstance(history['cloudHistory'].get(key), list) for key in (
                    'attempts', 'deliveries', 'native_claims', 'native_correlations',
                    'manual_sources', 'slot_intents', 'no_start_settlements'))
                and isinstance(history['budget'], dict)
                and all(key in history['budget'] for key in ('used', 'remaining', 'limit', 'windowMs')), message)
        mapping, previous = row['mapping'], row['bindingBefore']
        binding = mapping['nativeBinding']
        require(binding_valid(previous) and binding_valid(binding)
                and all(binding[key] == previous[key] for key in (
                    'clientId', 'connectionId', 'backendPid', 'threadId', 'serverInstanceId'))
                and all(binding[key] >= previous[key] for key in ('generation', 'serverGeneration'))
                and any(binding[key] > previous[key] for key in ('generation', 'serverGeneration')),
                message)
        require(all(type(mapping[key]) is int and mapping[key] == result[key + 'After']
                    for key in ('runtimeGeneration', 'attachmentGeneration')), message)
        for field, raw in (('runtimeSha256', mapping['runtimeId']), ('sessionSha256', mapping['sessionId']),
                           ('threadSha256', binding['threadId'])):
            require(isinstance(raw, str) and hashlib.sha256(raw.encode()).hexdigest()
                    == proof['nativeCliSessions']['C'][field], message)
        spent = row['preAttachNonces']
        require(isinstance(spent, list) and len(spent) >= 3
                and all(exact_int(nonce) for nonce in spent)
                and spent == sorted(set(spent)), message)
        observations = row['busyEvidence']
        require(isinstance(observations, list) and len(observations) == 3, message)
        challenges, nonces, checked = [], [], []

        def validate_observation(observation):
            request, response = observation['request'], observation['response']
            witness = response['witness']
            received, checked_at = observation['receivedAt'], observation['checkedAt']
            deadline = response['validUntilMonotonic']
            require(request['command'] == 'challenge' and binding_valid(request['expectedBinding'])
                    and request['expectedBinding'] == binding
                    and uuid_string(request['challengeId'])
                    and response['challengeId'] == request['challengeId']
                    and set(response) == {'challengeId', 'observedAt', 'validUntilMonotonic', 'witness'}
                    and set(witness) == set(binding) | {
                        'version', 'nonce', 'sequence', 'cause', 'leaseMs', 'eligible', 'nativeCoreTurnState'}
                    and binding_valid({key: witness[key] for key in binding})
                    and {key: witness[key] for key in binding} == binding
                    and type(witness['version']) is int and witness['version'] == 2
                    and exact_int(witness['nonce']) and exact_int(witness['sequence'], 1)
                    and isinstance(witness['cause'], str) and len(witness['cause']) <= 128
                    and exact_int(witness['leaseMs'], 1) and witness['eligible'] is True
                    and witness['nativeCoreTurnState'] == 'busy'
                    and all(finite(value) for value in (received, checked_at, deadline))
                    and hold['startedAt'] <= received <= checked_at < hold['holdDeadline']
                    and received <= checked_at < deadline <= received + min(witness['leaseMs'], 750) / 1000,
                    message)
            observed = response['observedAt']
            require(isinstance(observed, str) and len(observed) == 24 and observed.endswith('Z')
                    and datetime.fromisoformat(observed[:-1] + '+00:00').isoformat(
                        timespec='milliseconds').replace('+00:00', 'Z') == observed, message)
            return request['challengeId'], witness['nonce'], checked_at

        for observation in observations:
            challenge_id, nonce, checked_at = validate_observation(observation)
            challenges.append(challenge_id)
            nonces.append(nonce)
            checked.append(checked_at)
        require(finite(row['holdDeadline']) and all(value < row['holdDeadline'] for value in checked), message)
        require(len(set(challenges)) == len(set(nonces)) == 3 and checked == sorted(checked)
                and nonces[0] in spent and nonces[1] not in spent and nonces[2] not in spent, message)
        cli = observations[1]
        attach = row['attachRequest']
        require(cli['session'] == 'C' and cli['sessionId'] == mapping['sessionId']
                and attach['operation'] == 'attach' and attach['runtimeId'] == mapping['runtimeId']
                and attach['sessionId'] == mapping['sessionId']
                and binding_valid(attach['expectedNativeBinding']) and attach['expectedNativeBinding'] == binding
                and attach['challengeId'] == cli['request']['challengeId']
                and all(type(attach['expected' + key[0].upper() + key[1:]]) is int
                        and attach['expected' + key[0].upper() + key[1:]] == result[key + 'Before']
                        for key in ('runtimeGeneration', 'attachmentGeneration')), message)
        argv = row['attachArgv']
        require(isinstance(argv, list) and len(argv) == 13 and all(isinstance(value, str) for value in argv)
                and bool(argv[1]) and Path(argv[1]).is_absolute()
                and argv == ['--state-dir', argv[1], 'attach', '--runtime-id', attach['runtimeId'],
                             '--session-id', attach['sessionId'], '--cloud-config', str(Path(argv[1]) / 'cloud.json'),
                             '--expected-runtime-generation', str(attach['expectedRuntimeGeneration']),
                             '--expected-attachment-generation', str(attach['expectedAttachmentGeneration'])], message)

        # C2 must remain authoritatively Busy on both sides of the daemon restart.
        dispatches = [(index, record['value']) for index, record in enumerate(records)
                      if record.get('kind') == 'c2CoreBusy']
        restarts = [(index, record['value']) for index, record in enumerate(records)
                    if record.get('kind') == 'c2BusyRestart']
        require(len(restarts) == 1 and len(dispatches) >= 2
                and not any(record.get('kind') == 'c2CoreBusyError' for record in records), message)
        restart_index, restart = restarts[0]
        require(restart['binding'] == binding and binding_valid(restart['binding'])
                and uuid_string(restart['deliveryId']) and restart['evidenceError'] is None
                and hashlib.sha256(restart['deliveryId'].encode()).hexdigest() == proof['busyC']['deliverySha256']
                and finite(restart['checkedAt'])
                and checked[-1] < restart['checkedAt'] < hold['holdDeadline'], message)
        seen = set(spent) | set(nonces)
        seen_challenges = set(challenges)
        counts = {'initial': 0, 'post-restart': 0}
        last_checked = checked[-1]
        for index, dispatch in dispatches:
            phase = 'initial' if index < restart_index else 'post-restart'
            require(index > attach_index and dispatch['phase'] == phase
                    and dispatch['binding'] == binding and binding_valid(dispatch['binding'])
                    and dispatch['deliveryId'] == restart['deliveryId']
                    and dispatch['evidenceError'] is None
                    and dispatch['status'] == 'queued'
                    and dispatch['reason'] == 'client_unavailable_or_busy'
                    and finite(dispatch['checkedAt'])
                    and last_checked <= dispatch['checkedAt'] < hold['holdDeadline']
                    and isinstance(dispatch['observations'], list) and bool(dispatch['observations']), message)
            for observation in dispatch['observations']:
                challenge_id, nonce, checked_at = validate_observation(observation)
                require(observation['session'] == 'C' and observation['sessionId'] == mapping['sessionId']
                        and challenge_id not in seen_challenges and nonce not in seen
                        and last_checked <= observation['receivedAt'] <= checked_at <= dispatch['checkedAt']
                        and ((dispatch['checkedAt'] < restart['checkedAt']) if phase == 'initial'
                             else (restart['checkedAt'] <= observation['receivedAt'])), message)
                seen.add(nonce)
                seen_challenges.add(challenge_id)
            last_checked = dispatch['checkedAt']
            counts[phase] += 1
        require(all(counts.values())
                and exact_int(proof['busyC']['busyDispatchCount'], 2)
                and proof['busyC']['busyDispatchCount'] == len(dispatches)
                and exact_int(proof['busyDeliveryRestart']['busyDispatchCountAfterRestart'], 1)
                and proof['busyDeliveryRestart']['busyDispatchCountAfterRestart'] == counts['post-restart']
                and exact_int(proof['privateEvidence']['coreBusyNonces'], 1)
                and proof['privateEvidence']['coreBusyNonces'] == len(seen), message)

    except (KeyError, TypeError, IndexError, AttributeError, ValueError, OverflowError) as error:
        raise ValueError(message) from error


def verify_three_session_proof(args, proof, output, fixture):
    require(proof['qualification'] == 'controlled-three-real-cli-production-daemon-workerd'
            and proof['nativeBinarySha256'] == args.binary_sha256
            and proof['codeModeHostSha256'] == sha(Path(args.binary).resolve(strict=True).parent / 'codex-code-mode-host'),
            'three-session candidate mismatch')
    sessions = proof['nativeCliSessions']
    require(set(sessions) == {'A', 'B', 'C'}, 'three-session identity set missing')
    for field in ('runtimeSha256', 'sessionSha256', 'threadSha256'):
        values = [sessions[label][field] for label in ('A', 'B', 'C')]
        require(len(set(values)) == 3 and all(re.fullmatch(r'[0-9a-f]{64}', value) for value in values),
                'three-session identities not independent')
    require([sessions[label]['nativeStartCount'] for label in ('A', 'B', 'C')] == [1, 1, 2]
            and all(sessions[label]['initiallySelectedIdle'] is True for label in sessions),
            'three-session starts or initial selection mismatch')
    require(all(proof['nativeProcessCleanup'][label][key] is True for label in sessions
                for key in ('launcherExited', 'processGroupClosed', 'backendStopped', 'controlSocketRemoved'))
            and proof['brokerCleanup']['ownedProcessGroupClosed'] is True
            and proof['brokerCleanup']['loopbackPortsClosed'] is True, 'three-session cleanup incomplete')
    required = ('threeIndependentAttachments', 'aOnlyAndBOnlySessionIsolation',
                'busyDeliveryRemainsDurableWithoutStart', 'changedBindingRequiresExplicitAttach',
                'oldGenerationDeliveryFencedWithoutStart', 'newGenerationDeliverySettledExactlyOnce',
                'observedAckReplayLeavesWorkerdStateUnchanged', 'exactObservedAckRetryAfterDaemonRestart')
    require(all(proof['controlledAssertions'][key] is True for key in required), 'three-session assertions incomplete')
    ack = proof['observedAckRestart']
    require(all(ack[key] is True for key in ('daemonRestarted', 'firstReplyLostAfterWorkerdCommit',
                                            'ackBodyBytesIdentical', 'proofNonceChanged'))
            and ack['nativeProcessRestarted'] is False and ack['nativeStartCount'] == 1,
            'three-session ACK recovery mismatch')
    require(proof['busyC']['nativeClaimCreated'] is False and proof['busyC']['nativeStartWhileBusy'] is False
            and proof['busyDeliveryRestart']['queuedAfterBusyRestart'] is True
            and proof['postAttachC3']['nativeStartCount'] == 1
            and proof['postAttachC3']['workerdClaimCount'] == 1
            and proof['postAttachC3']['localState'] == 'observed', 'three-session recovery mismatch')
    sources = {'runner': fixture / 'three-session-workerd.py', 'workerFixture': fixture / 'coupled-workerd-worker.ts',
               'broker': fixture / 'coupled-workerd-broker.mjs',
               'nativeHostQualifier': fixture / 'native-host-launcher-qualification.py',
               'launcherSmoke': fixture / 'native-release-launcher-smoke.py',
               'installedPreflight': fixture / 'qualification-installed.py'}
    require(all(proof['sourceSha256'][key] == sha(path) for key, path in sources.items()), 'three-session source mismatch')
    evidence = read_bounded(output / 'proof.private-evidence.jsonl', 64_000_000)
    require(proof['privateEvidence']['bytes'] == len(evidence)
            and proof['privateEvidence']['sha256'] == hashlib.sha256(evidence).hexdigest(), 'private evidence mismatch')
    verify_busy_attach(proof, evidence)
    causal_raw = read_bounded(output / 'proof.private-causal.json', 2_000_000)
    require(proof['privateCausal']['bytes'] == len(causal_raw)
            and proof['privateCausal']['sha256'] == hashlib.sha256(causal_raw).hexdigest(),
            'private causal evidence mismatch')
    causal = json.loads(causal_raw)
    nonces = causal['sourceNonceSha256']
    require(causal['nonReuse'] is True and set(nonces) == {'C1', 'C3'}
            and all(isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) for value in nonces.values())
            and nonces['C1'] != nonces['C3'],
            'causal nonce evidence mismatch')


def verify_native_recovery_proof(args, proof, fixture, package):
    require(proof['qualification'] == 'fixture-qualified-native-local-workerd'
            and proof['binarySha256'] == args.binary_sha256, 'native recovery candidate mismatch')
    require(all(proof[key] is True for key in ('nativeProcessRestarted', 'nativeInFlightRestartProven',
                                             'localStoreRestarted', 'installedPackage')),
            'native recovery scope incomplete')
    require(proof['interruptedTurnCompletionProven'] is False and proof['oldStartNoStartSettlementProven'] is False,
            'native recovery overclaims completion')
    restart = proof['restart']
    require(all(restart[key] is True for key in ('expiredBeforeRecovery', 'oldAttachmentUnavailable',
                'stoppedBeforeHeldModelResponseReleased', 'gatewayReceiptAbsentBeforeRecovery')),
            'native recovery causal ordering missing')
    require(all(restart['processChecks'][key] is True for key in ('oldTuiStopped', 'oldBackendStopped',
                'tuiPidRotated', 'clientIdRotated', 'serverInstanceIdRotated', 'backendPidRotated', 'threadIdRotated')),
            'native process death checks missing')
    require(restart['oldPid'] != restart['newPid'] and all(restart['oldWitness'][key] != restart['newWitness'][key]
            for key in ('clientId', 'serverInstanceId', 'backendPid', 'threadId')), 'native identities did not rotate')
    request, receipt = proof['nativeRequest'], proof['fullInputRecordedReceipt']
    require(all(receipt[key] == value for key, value in request.items() if key not in ('receiptVersion', 'event')),
            'receipt is not bound to original request')
    observed = receipt['outcome']
    require(observed == restart['independentlyRecorded'] and observed['status'] == 'inputRecorded',
            'original receipt not recovered')
    wire = proof['wire']
    require(len(wire) == 4 and wire[-1]['body'] == wire[-2]['body']
            and wire[-1]['proof']['nonce'] != wire[-2]['proof']['nonce'], 'lost ACK replay mismatch')
    require([item['path'] for item in wire] == ['/v1/dispatch/claim', '/v1/ack', '/v1/ack', '/v1/ack']
            and [json.loads(item['body'])['status'] for item in wire[1:]] == ['submitted', 'observed', 'observed'],
            'unexpected cloud claim or ACK sequence')
    require(proof['modelRequests']['primary'] == 1 and proof['modelRequests']['unknown'] == 0,
            'recovery repeated native model work')
    settled = proof['settled']
    require(not settled['slots'] and not settled['cloud']['slot_intents']
            and all(len(settled['cloud'][key]) == 1 and settled['cloud'][key][0]['state'] == 'observed'
                    for key in ('attempts', 'deliveries', 'native_claims')), 'recovery did not settle exactly once')
    require(settled['cloud']['manual_sources'][0]['observed_source_state_version']
            == request['event']['sourceStateVersion'] and settled['budget']['used'] == 1, 'recovery watermark or budget mismatch')
    verify_recovery_identity(proof)
    required = [fixture / name for name in ('coupled-workerd.py', 'coupled-workerd-broker.mjs',
                'coupled-workerd-worker.ts', 'coupled-workerd-source-hashes.mjs',
                'qualification-installed.py', 'three-session-workerd.py')]
    required.append(package / 'scripts/qualify_native_bridge.py')
    require(all(proof['sourceSha256'][str(path)] == sha(path) for path in required), 'recovery source mismatch')
    require(proof['fixturePorts'] == {'model': 43125, 'entry': 43121, 'loopback': 43122, 'broker': 43123},
            'recovery ports mismatch')


def verify_recovery_identity(proof):
    """Conjoin the native receipt, exact wire exchange and durable cloud rows."""
    request, receipt = proof['nativeRequest'], proof['fullInputRecordedReceipt']
    require(request['receiptVersion'] == 3, 'recovery requires durable receipt v3')
    pair = {key: request[key] for key in ('deliveryId', 'attemptId')}
    event, outcome = request['event'], receipt['outcome']
    bodies = [json.loads(item['body']) for item in proof['wire']]
    require(bodies[0] == pair, 'claim does not identify recovered attempt')
    correlation = {'permitId': request['permitId'], 'turnId': outcome['turnId']}
    require(outcome['turnId'] == request['clientUserMessageId'], 'recovered turn identity mismatch')
    cloud = proof['settled']['cloud']
    attempt, delivery, claim = (cloud[key][0] for key in ('attempts', 'deliveries', 'native_claims'))
    envelope = json.loads(attempt['envelope_json'])
    require(json.loads(claim['envelope_json']) == envelope
            and all(envelope[key] == value for key, value in {**pair, **event}.items()),
            'settled envelope differs from native request')
    for row in (attempt, claim):
        require(row['delivery_id'] == pair['deliveryId'] and row['attempt_id'] == pair['attemptId']
                and row['permit_id'] == request['permitId'] and row['permit_until'] == request['permitExpiresAt'],
                'settled attempt or permit identity mismatch')
    require(claim['permit_issued_at'] == request['permitIssuedAt'] and attempt['turn_id'] == outcome['turnId'],
            'settled native correlation mismatch')
    attached = proof['fixtureAdmission']['attached']
    for field in ('clientId', 'threadId', 'generation', 'serverInstanceId', 'serverGeneration'):
        require(request[field] == attached['nativeBinding'][field]
                and request[field] == proof['restart']['oldWitness'][field], 'original native binding mismatch')
    identity = ('principal', 'agent', 'runtimeId', 'nodeGeneration', 'runtimeGeneration', 'attachmentGeneration')
    for index, ack in enumerate(bodies[1:]):
        expected = {**correlation, 'kind': 'native_turn_started'} if index == 0 else {
            **correlation, 'kind': 'native_input_recorded', 'itemId': outcome['itemId']}
        require(all(ack[key] == value for key, value in pair.items())
                and ack['eventId'] == event['eventId']
                and ack['deliveredSourceStateVersion'] == event['sourceStateVersion']
                and all(ack[key] == envelope[key] for key in identity)
                and ack['nativeCorrelation'] == expected, 'ACK differs from recovered attempt')
    require(json.loads(attempt['ack_json']) == bodies[1]
            and json.loads(attempt['native_observed_ack_json']) == bodies[2], 'durable ACK differs from wire')
    for field, column in (('deliveryId', 'delivery_id'), ('eventId', 'event_id'),
                          ('sourceStateVersion', 'source_state_version'), ('runtimeId', 'runtime_id'),
                          ('runtimeGeneration', 'runtime_generation'), ('attachmentGeneration', 'attachment_generation'),
                          ('nodeGeneration', 'node_generation')):
        require(delivery[column] == envelope[field], 'settled delivery identity mismatch')
    require(delivery['node_id'] == attached['nodeId'] and all(
        item['proof']['nodeId'] == attached['nodeId'] and item['proof']['nodeGeneration'] == attached['nodeGeneration']
        for item in proof['wire']), 'wire node differs from attachment')
    require(all(envelope[key] == attached[key] for key in ('runtimeId', 'runtimeGeneration', 'nodeGeneration', 'attachmentGeneration')),
            'settled runtime differs from attachment')
    require(len(cloud['manual_sources']) == 1 and all(cloud['manual_sources'][0][column] == event[field]
        for field, column in (('eventId', 'event_id'), ('sourceStateVersion', 'source_state_version'), ('eventReference', 'event_reference')))
        and cloud['manual_sources'][0]['subject_id'] == event['canonicalSubject']['subjectId']
        and delivery['subject_id'] == event['canonicalSubject']['subjectId'], 'settled source identity mismatch')


def run(args):
    admit(os.environ, args.repository_id)
    require(re.fullmatch(r'[0-9a-f]{64}', args.binary_sha256), 'invalid candidate digest')
    require(re.fullmatch(r'[0-9a-f]{40}', args.cloud_commit), 'invalid cloud revision')
    output = Path(args.output_dir).absolute()
    output.mkdir(mode=0o700)  # Exclusive reservation: a failed launch consumes this attempt.
    profile = output / 'network.sb'
    write_private(profile, network_profile())
    result = {'schemaVersion': 1, 'outcome': 'INCOMPLETE',
              'scope': 'reviewed-native-controlled-fixture', 'nativePromoted': False,
              'productionAcceptance': False, 'vmDisposalBasis': 'providerLifecycleContract',
              'vmDisposalObserved': False, 'completeDescendantTerminationProven': False,
              'runId': os.environ['GITHUB_RUN_ID'], 'runAttempt': 1,
              'workflowSha': os.environ['GITHUB_SHA'],
              'imageOS': os.environ['ImageOS'], 'imageVersion': os.environ['ImageVersion'],
              'candidateSha256': args.binary_sha256, 'cloudCommit': args.cloud_commit,
              'profileSha256': hashlib.sha256(profile.read_bytes()).hexdigest(),
              'networkScope': 'host-local-fixed-TCP-and-Unix', 'timeoutSecondsPerScenario': 240}
    # Retain scratch until VM disposal, including on timeout; never race live writers with deletion.
    scratch = Path(tempfile.mkdtemp(prefix='nq-', dir='/private/tmp')).resolve()
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(scratch), 'TMPDIR': str(scratch),
                   'TERM': 'xterm-256color', 'LANG': 'en_US.UTF-8'}
    scenario = None
    phase = 'preflight'
    try:
        cloud_identity(args, environment)
        require(sha(Path(args.binary)) == args.binary_sha256, 'candidate digest mismatch')
        frozen_sources = {path: sha(path) for folder in ('src', 'scripts', 'docs/native-bridge')
                          for path in (Path(args.package_root) / folder).rglob('*')
                          if path.is_file() and path.suffix in ('.py', '.ts', '.mjs')}
        result['scenarios'] = []
        for scenario, build in (('three-session', command), ('native-recovery', recovery_command)):
            phase = 'scenario_preflight'
            ports_released()
            destination = output / scenario
            destination.mkdir(mode=0o700)
            argv = build(args, profile, destination)
            phase = 'fixture_execution'
            with os.fdopen(os.open(destination / 'fixture.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as log:
                completed = subprocess.run(argv, cwd=scratch, env=environment, stdin=subprocess.DEVNULL,
                                           stdout=log, stderr=subprocess.STDOUT, close_fds=True, timeout=240, umask=0o077)
            result.setdefault('scenarioExecutions', []).append({'scenario': scenario, 'returncode': completed.returncode})
            require(completed.returncode == 0, 'scenario exited unsuccessfully')
            phase = 'evidence_validation'
            require(all(sha(path) == digest for path, digest in frozen_sources.items()), 'fixture source changed')
            require(sha(Path(args.binary)) == args.binary_sha256, 'candidate changed')
            result['scenarios'].append(verify_proof(args, scenario, destination))
            phase = 'scenario_cleanup'
            ports_released()
            cloud_identity(args, environment)
        result['outcome'] = 'FIXTURE_COMPLETED_PENDING_INDEPENDENT_VERIFICATION'
    except subprocess.TimeoutExpired:
        result['failure'] = {'scenario': scenario, 'phase': phase, 'exceptionType': 'TimeoutExpired'}
        result['reason'] = 'attempt_timeout_vm_lifetime_contains_remaining_descendants'
    except (OSError, ValueError, KeyError, TypeError, IndexError, subprocess.CalledProcessError) as error:
        # Preserve locations without exception messages, source text or locals,
        # which may contain arbitrary private evidence from a malformed proof.
        result['failure'] = {'scenario': scenario, 'phase': phase, 'exceptionType': type(error).__name__,
                             'frames': [{'file': Path(frame.filename).name, 'line': frame.lineno, 'function': frame.name}
                                        for frame in traceback.extract_tb(error.__traceback__)[-16:]]}
        result['reason'] = 'verifier_error' if isinstance(error, (KeyError, TypeError, IndexError)) else 'fixture_launch_or_evidence_validation_error'
    finally:
        write_private(output / 'hosted-result.json', json.dumps(result, indent=2) + '\n')
    return 0 if result['outcome'] == 'FIXTURE_COMPLETED_PENDING_INDEPENDENT_VERIFICATION' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repository-id', 'python', 'package-root', 'binary', 'binary-sha256',
                 'node', 'cloud-source', 'cloud-commit', 'esbuild', 'miniflare', 'output-dir'):
        parser.add_argument('--' + name, required=True)
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
