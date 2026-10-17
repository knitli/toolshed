#!/usr/bin/env python3
"""Run a reviewed, pre-staged native fixture only on a disposable hosted macOS VM."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile

PORTS = (43121, 43122, 43123, 43124, 43125, 43126, 43127)


def require(value, message):
    if not value:
        raise ValueError(message)


def admit(environment, repository_id):
    expected = {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ATTEMPT": "1",
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
            '--entry-port', str(PORTS[0]), '--loopback-port', str(PORTS[1]),
            '--broker-port', str(PORTS[2]), '--listener-port', str(PORTS[3]),
            '--model-ports', *(str(port) for port in PORTS[4:])]


def run(args):
    admit(os.environ, args.repository_id)
    require(re.fullmatch(r'[0-9a-f]{64}', args.binary_sha256), 'invalid candidate digest')
    require(re.fullmatch(r'[0-9a-f]{40}', args.cloud_commit), 'invalid cloud revision')
    output = Path(args.output_dir).absolute()
    output.mkdir(mode=0o700)  # Exclusive reservation: a failed launch consumes this attempt.
    profile = output / 'network.sb'
    write_private(profile, network_profile())
    argv = command(args, profile, output)
    result = {'schemaVersion': 1, 'outcome': 'INCOMPLETE',
              'scope': 'reviewed-native-controlled-fixture', 'nativePromoted': False,
              'productionAcceptance': False, 'vmDisposalBasis': 'providerLifecycleContract',
              'vmDisposalObserved': False, 'completeDescendantTerminationProven': False,
              'runId': os.environ['GITHUB_RUN_ID'], 'runAttempt': 1,
              'workflowSha': os.environ['GITHUB_SHA'],
              'imageOS': os.environ['ImageOS'], 'imageVersion': os.environ['ImageVersion'],
              'candidateSha256': args.binary_sha256, 'cloudCommit': args.cloud_commit,
              'profileSha256': hashlib.sha256(profile.read_bytes()).hexdigest(),
              'networkScope': 'host-local-fixed-TCP-and-Unix', 'timeoutSeconds': 240}
    # Retain scratch until VM disposal, including on timeout; never race live writers with deletion.
    scratch = Path(tempfile.mkdtemp(prefix='nq-', dir='/private/tmp')).resolve()
    environment = {'PATH': '/usr/bin:/bin', 'HOME': str(scratch), 'TMPDIR': str(scratch),
                   'TERM': 'xterm-256color', 'LANG': 'en_US.UTF-8'}
    try:
        with os.fdopen(os.open(output / 'fixture.log', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as log:
            completed = subprocess.run(argv, cwd=scratch, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=subprocess.STDOUT, close_fds=True, timeout=240)
        result['returncode'] = completed.returncode
        proof = output / 'proof.json'
        if completed.returncode == 0 and proof.is_file():
            result['outcome'] = 'FIXTURE_COMPLETED_PENDING_INDEPENDENT_VERIFICATION'
            result['proofSha256'] = hashlib.sha256(proof.read_bytes()).hexdigest()
    except subprocess.TimeoutExpired:
        result['reason'] = 'attempt_timeout_vm_lifetime_contains_remaining_descendants'
    except OSError:
        result['reason'] = 'fixture_launch_or_evidence_io_error'
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
