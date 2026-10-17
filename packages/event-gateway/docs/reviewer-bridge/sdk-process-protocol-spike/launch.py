"""Opt-in launcher for the private, credential-free SDK protocol fixture."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import subprocess  # nosec B404 - Only fixed sandbox-exec and hash-verified Node are launched.
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent
NODE = Path('/Users/adampoulemanos/.local/share/mise/installs/node/24.21.0/bin/node')
LIMIT = 65536
TIMEOUT = 20


def classify_stderr(raw):
    diagnostics, warnings = [], []
    for line in raw.decode(errors='replace').splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            warnings.append(line)
            continue
        if isinstance(item, dict) and item.get('fixtureDiagnostic') is True:
            diagnostics.append(item)
        else:
            warnings.append(line)
    return diagnostics, warnings


def verify_inputs():
    manifest = json.loads((ROOT / 'manifest.json').read_text())
    if str(NODE.resolve()) != manifest['node']['realpath'] or str(NODE.resolve()) != str(NODE):
        raise RuntimeError('Node path drift')
    if hashlib.sha256(NODE.read_bytes()).hexdigest() != manifest['node']['sha256']:
        raise RuntimeError('Node bytes drift')
    for name, expected in manifest['files'].items():
        path = ROOT / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError('Fixture bytes drift: ' + name)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if not args.run:
        parser.error('explicit --run required; review manifest/profile before opting in')
    manifest = verify_inputs()
    canary = ROOT / ('outside-scratch-' + uuid.uuid4().hex)
    with canary.open('xb') as output:
        output.write(os.urandom(32))
    canary.chmod(0o600)
    expected_canary = hashlib.sha256(canary.read_bytes()).hexdigest()
    try:
        with tempfile.TemporaryDirectory(prefix='scratch-', dir=ROOT) as directory:
            scratch = Path(directory)
            for name in ('tmp', 'claude', 'xdg'):
                (scratch / name).mkdir(mode=0o700)
            env = {'PATH': '/usr/bin:/bin', 'HOME': str(scratch), 'TMPDIR': str(scratch / 'tmp'),
                   'CLAUDE_CONFIG_DIR': str(scratch / 'claude'), 'XDG_CONFIG_HOME': str(scratch / 'xdg'),
                   'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'CLAUDE_CODE_DISABLE_AUTO_MEMORY': '1',
                   'DISABLE_TELEMETRY': '1', 'DO_NOT_TRACK': '1', 'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}
            argv = ['/usr/bin/sandbox-exec', '-f', str(ROOT / 'profile.sb'), '-D', f'SCRATCH={scratch}',
                    str(NODE), '--no-addons', str(ROOT / 'fixture.mjs'), str(canary)]
            evidence = Path(tempfile.mkdtemp(prefix='capture-', dir=ROOT))
            # Fixed executables, manifest-verified source/profile paths, closed argv/environment; no shell.
            process = subprocess.Popen(argv, cwd=scratch, env=env, close_fds=True,  # nosec B603
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            streams = {'stdout': bytearray(), 'stderr': bytearray()}
            print('Fixture capture directory: ' + str(evidence), file=sys.stderr, flush=True)
            deadline = time.monotonic() + TIMEOUT
            total = 0
            code = None
            failure = None
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
                    selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        ready = selector.select(max(0, remaining))
                        if remaining <= 0 or not ready:
                            raise RuntimeError('fixture timeout')
                        # One bounded read per ready descriptor per round; neither
                        # stream can starve the other. Both share the same cap.
                        for key, _ in ready:
                            part = os.read(key.fileobj.fileno(), min(4096, LIMIT - total + 1))
                            if not part:
                                selector.unregister(key.fileobj)
                                continue
                            available = LIMIT - total
                            streams[key.data].extend(part[:available])
                            total += min(len(part), available)
                            if len(part) > available:
                                raise RuntimeError('fixture aggregate output limit; capture truncated at 65536 bytes')
                code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
                if code != 0:
                    raise RuntimeError(f'fixture failed ({code})')
                # A single JSON document is required; extra JSON or warning text
                # on stdout remains a failure. Stderr never supplies acceptance.
                result = json.loads(streams['stdout'])
                if not isinstance(result, dict) or result.get('status') != 'PASS':
                    raise RuntimeError('fixture did not pass')
                if hashlib.sha256(canary.read_bytes()).hexdigest() != expected_canary:
                    raise RuntimeError('outside canary changed')
                diagnostics, warnings = classify_stderr(streams['stderr'])
                print(json.dumps({'result': result, 'diagnostics': diagnostics, 'warnings': warnings,
                                  'rawStdout': streams['stdout'].decode(errors='replace'),
                                  'rawStderr': streams['stderr'].decode(errors='replace'),
                                  'captureDirectory': str(evidence), 'sourceManifest': manifest,
                                  'profileSha256': manifest['files']['profile.sb'],
                                  'outsideCanaryPreserved': True}, sort_keys=True))
            except BaseException as error:
                failure = {'name': type(error).__name__, 'message': str(error)[:1000]}
                raise
            finally:
                # Persist exact bounded bytes even when JSON parsing or validation
                # fails. Capture files live outside the child's readable sandbox.
                try:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=3)
                    code = process.returncode
                finally:
                    process.stdout.close()
                    process.stderr.close()
                    (evidence / 'stdout.bin').write_bytes(streams['stdout'])
                    (evidence / 'stderr.bin').write_bytes(streams['stderr'])
                    diagnostics, warnings = classify_stderr(streams['stderr'])
                    (evidence / 'capture.json').write_text(json.dumps({
                        'exitCode': code, 'failure': failure, 'aggregateBytes': total,
                        'diagnostics': diagnostics, 'warnings': warnings,
                        'aggregateLimit': LIMIT, 'manifestSha256': hashlib.sha256((ROOT / 'manifest.json').read_bytes()).hexdigest(),
                    }, indent=2) + '\n')
    finally:
        canary.unlink()


if __name__ == '__main__':
    main()
