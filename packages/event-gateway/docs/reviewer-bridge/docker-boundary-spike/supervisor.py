"""Private Docker boundary fixture. No execution unless explicitly passed --run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import tempfile
import time
import uuid

IMAGE = 'sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d'
DOCKER = '/usr/local/bin/docker'
ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / 'fixture'
LIMIT = 65536
TIMEOUT = 15
TMPFS = 'rw,noexec,nosuid,nodev,size=16777216,uid=65532,gid=65532,mode=0700'
CHECKS = {'work_write', 'root_write_denied', 'fixture_write_denied', 'host_canary_unreadable', 'docker_socket_absent', 'uid_gid', 'groups', 'caps_zero', 'no_new_privileges', 'credential_env_absent', 'private_init', 'descendant_same_namespace', 'descendant_parent'}


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def docker_env():
    # Docker's client configuration is host-only; none is passed into the container.
    return {key: value for key, value in os.environ.items()
            if key in {'PATH', 'HOME', 'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY'}}


def read_bounded(process, *, first_line=False, timeout=TIMEOUT):
    data = bytearray()
    deadline = time.monotonic() + timeout
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'command timeout')
            events = selector.select(remaining)
            require(bool(events), 'command timeout')
            chunk = os.read(process.stdout.fileno(), min(4096, LIMIT + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            require(len(data) <= LIMIT, 'output limit')
            if first_line and b'\n' in data:
                require(data.count(b'\n') == 1 and data.endswith(b'\n'), 'unexpected extra output')
                return bytes(data)


def start(args):
    return subprocess.Popen([DOCKER, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=docker_env(), close_fds=True)


def finish_client(process):
    # This terminates only our CLI subprocess, never claims container cleanup.
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    if process.stdout:
        process.stdout.close()


def command(args, *, timeout=TIMEOUT):
    process = start(args)
    try:
        output = read_bounded(process, timeout=timeout)
        require(process.wait(timeout=2) == 0, f'docker {args[0]} failed')
        return output
    finally:
        finish_client(process)


def create_args(name, cidfile, canary):
    return ['create', '--pull=never', '--name', name, '--cidfile', str(cidfile),
            '--label', 'reviewer.fixture=' + name, '--network=none', '--user=65532:65532', '--cap-drop=ALL',
            '--security-opt=no-new-privileges:true', '--read-only', '--ipc=private',
            '--pids-limit=32', '--memory=128m', '--memory-swap=128m', '--cpus=1',
            '--tmpfs', '/work:' + TMPFS, '--log-driver=none', '--restart=no',
            '--mount', f'type=bind,src={FIXTURE},dst=/fixture,readonly',
            '--entrypoint=python3', IMAGE, '-I', '-B', '/fixture/child.py', str(canary)]


def validate_inspect(value, cid, canary, name):
    require(value.get('Id') == cid and value.get('Image') == IMAGE, 'container/image identity')
    h, c = value['HostConfig'], value['Config']
    require(value.get('Name') == '/' + name and c.get('Labels', {}).get('reviewer.fixture') == name, 'owned container identity')
    expected = {'NetworkMode': 'none', 'Privileged': False, 'ReadonlyRootfs': True,
                'PidsLimit': 32, 'Memory': 134217728, 'MemorySwap': 134217728, 'NanoCpus': 1000000000,
                'IpcMode': 'private', 'PublishAllPorts': False}
    require(all(h.get(k) == v for k, v in expected.items()), 'container limits/isolation')
    require(h.get('PidMode', '') in ('', 'private'), 'host/shared PID namespace')
    require(h.get('CapDrop') == ['ALL'] and not h.get('CapAdd'), 'capability policy')
    require(h.get('SecurityOpt') == ['no-new-privileges:true'], 'security policy')
    require(h.get('Tmpfs') == {'/work': TMPFS}, 'scratch policy')
    require(h.get('LogConfig', {}).get('Type') == 'none', 'log retention')
    require(h.get('RestartPolicy', {}).get('Name') == 'no', 'restart policy')
    require(not any(h.get(k) for k in ('Devices', 'DeviceRequests', 'VolumesFrom', 'PortBindings', 'Links')), 'additional access')
    mounts = value.get('Mounts', [])
    binds = [m for m in mounts if m.get('Type') == 'bind']
    require(len(binds) == 1 and all(m.get('Type') == 'bind' or (m.get('Type') == 'tmpfs' and m.get('Destination') == '/work') for m in mounts), 'unexpected mounts')
    mount = binds[0]
    require(mount.get('Type') == 'bind' and mount.get('Source') == str(FIXTURE)
            and mount.get('Destination') == '/fixture' and mount.get('RW') is False, 'fixture mount')
    require(c.get('User') == '65532:65532' and c.get('Entrypoint') == ['python3'], 'process identity')
    require(c.get('Cmd') == ['-I', '-B', '/fixture/child.py', str(canary)], 'child command')
    require(not any(v.split('=', 1)[0].startswith(('GH_', 'GITHUB_', 'ACTIONS_', 'ANTHROPIC_', 'HOST_CANARY')) for v in c.get('Env', [])), 'credential environment')
    require(value.get('State', {}).get('Status') == 'created' and value['State'].get('Running') is False, 'container already started')


def validate_report(raw):
    report = json.loads(raw)
    require(set(report) == {'checks', 'init_pid', 'descendant_pid'}, 'report shape')
    require(set(report['checks']) == CHECKS and all(v is True for v in report['checks'].values()), 'child boundary checks')
    require(report['init_pid'] == 1 and type(report['descendant_pid']) is int and report['descendant_pid'] > 1, 'PID namespace report')
    return report


def cleanup(cid, invoke=command):
    require(bool(re.fullmatch(r'[0-9a-f]{64}', cid)), 'invalid cleanup identity')
    failures = []
    # cid is already validated as this invocation's owned container. Attempt all
    # cleanup phases even if an earlier response is lost; ambiguity never passes.
    try:
        state = json.loads(invoke(['inspect', cid]))[0]
        require(state.get('Id') == cid, 'cleanup identity mismatch')
        running = state.get('State', {}).get('Running')
    except Exception as error:
        failures.append(str(error))
        running = True
    if running:
        try:
            invoke(['kill', cid])
        except Exception as error:
            failures.append(str(error))
    try:
        state = json.loads(invoke(['inspect', cid]))[0]
        require(state.get('Id') == cid and state.get('State', {}).get('Running') is False
                and state['State'].get('Pid') == 0, 'container process namespace not stopped')
    except Exception as error:
        failures.append(str(error))
    try:
        invoke(['rm', '--force', cid])
    except Exception as error:
        failures.append(str(error))
    try:
        remaining = invoke(['container', 'ls', '--all', '--no-trunc', '--filter', f'id={cid}', '--format', '{{.ID}}'])
        require(not remaining.strip(), 'container removal unconfirmed')
    except Exception as error:
        failures.append(str(error))
    require(not failures, 'cleanup incomplete: ' + '; '.join(failures))


def recover_owned(name, invoke=command):
    # Exact random name plus matching label; never a global prune or PID signal.
    ids = invoke(['container', 'ls', '--all', '--no-trunc', '--filter', f'name=^/{name}$', '--format', '{{.ID}}']).decode().splitlines()
    if not ids:
        return None
    require(len(ids) == 1 and re.fullmatch(r'[0-9a-f]{64}', ids[0]), 'ambiguous recovery')
    value = json.loads(invoke(['inspect', ids[0]]))[0]
    require(value.get('Id') == ids[0] and value.get('Name') == '/' + name
            and value.get('Config', {}).get('Labels', {}).get('reviewer.fixture') == name, 'recovery ownership mismatch')
    return ids[0]


def run():
    name = 'reviewer-isolation-' + uuid.uuid4().hex
    # This directory is never mounted; canaries have no relationship to real credentials.
    with tempfile.TemporaryDirectory(prefix='reviewer-host-', dir=ROOT) as directory:
        host = Path(directory)
        canary = host / 'host-canary'
        canary.write_bytes(os.urandom(32))
        canary.chmod(0o600)
        expected = hashlib.sha256(canary.read_bytes()).hexdigest()
        cidfile = host / 'container.cid'
        cid = None
        attached = None
        failures = []
        report = None
        creation_attempted = False
        try:
            image = json.loads(command(['image', 'inspect', IMAGE]))[0]
            require(image.get('Id') == IMAGE and image.get('Os') == 'linux' and image.get('Architecture') == 'arm64', 'local image mismatch')
            require(recover_owned(name) is None, 'owned name already exists')
            creation_attempted = True
            output = command(create_args(name, cidfile, canary)).decode().strip()
            created = cidfile.read_text().strip()
            require(re.fullmatch(r'[0-9a-f]{64}', created) and output == created, 'create identity mismatch')
            cid = created
            state = json.loads(command(['inspect', cid]))[0]
            validate_inspect(state, cid, canary, name)
            attached = start(['start', '--attach', cid])
            report = validate_report(read_bounded(attached, first_line=True))
            require(hashlib.sha256(canary.read_bytes()).hexdigest() == expected, 'host canary changed')
        except Exception as error:
            failures.append(str(error))
        finally:
            # A create timeout may precede CID delivery; recover only our random name/label.
            if cid is None and creation_attempted:
                try:
                    cid = recover_owned(name)
                except Exception as error:
                    failures.append('recovery: ' + str(error))
            if cid:
                try:
                    cleanup(cid)
                except Exception as error:
                    failures.append('cleanup: ' + str(error))
            elif creation_attempted:
                failures.append('container identity unavailable; creation/cleanup incomplete')
            if attached:
                finish_client(attached)
            if hashlib.sha256(canary.read_bytes()).hexdigest() != expected:
                failures.append('host canary changed')
        result = {'status': 'FAIL' if failures else 'PASS', 'image': IMAGE, 'container_id': cid, 'container_name': name,
                  'checks': report, 'failures': failures,
                  'scope': 'Docker boundary only; no SDK/provider/hosted-handoff qualification'}
        print(json.dumps(result, sort_keys=True))
        return 1 if failures else 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', action='store_true', help='requires separate root approval')
    args = parser.parse_args()
    if not args.run:
        parser.error('Docker execution disabled; --run requires approval')
    raise SystemExit(run())
