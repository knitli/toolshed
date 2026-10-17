"""Private Docker boundary fixture. No execution unless explicitly passed --run."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess  # nosec B404 - Fixed Docker executable, validated argv, no shell.
import tempfile
import time
import uuid

IMAGE = 'sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d'
DOCKER = '/usr/local/bin/docker'
ROOT = Path(__file__).resolve().parent
FIXTURE = ROOT / 'fixture'
LIMIT = 65536
DIAGNOSTIC_LIMIT = 2048
TIMEOUT = 15
TMPFS = 'rw,noexec,nosuid,nodev,size=16777216,uid=65532,gid=65532,mode=0700'
CHECKS = {
    'work_write', 'root_write_denied', 'fixture_write_denied', 'host_canary_unreadable',
    'docker_socket_absent', 'uid_gid', 'groups', 'caps_zero', 'no_new_privileges',
    'credential_env_absent', 'private_init', 'descendant_same_namespace', 'descendant_parent',
}


def require(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def docker_env():
    # No ambient contexts, endpoints, credentials, proxy or Docker client settings.
    return {'PATH': '/usr/bin:/bin', 'HOME': str(Path.home())}


def command_failure(operation, code, output):
    # Fixed operations carry no credentials. Do not include argv or environment;
    # JSON escaping prevents daemon text from becoming terminal control output.
    detail = {
        'exitCode': code,
        'outputBytes': len(output),
        'outputSha256': hashlib.sha256(output).hexdigest(),
        'outputPrefix': output[:DIAGNOSTIC_LIMIT].decode('utf-8', errors='replace'),
        'truncated': len(output) > DIAGNOSTIC_LIMIT,
    }
    return f'docker {operation} failed: ' + json.dumps(detail, sort_keys=True)


def socket_identity(path):
    info = path.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(), 'untrusted local Docker socket')
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid)


class LocalDocker:
    """Only this invocation's fixed operations on the owned local daemon socket."""

    def __init__(self, host, name):
        """Bind validated owned paths and name to the fixed local Docker socket."""
        require(isinstance(name, str) and re.fullmatch(r'reviewer-isolation-[0-9a-f]{32}', name),
                'invalid owned container name')
        info = host.lstat()
        require(host.is_absolute() and host.resolve() == host and stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                'invalid owned host directory')
        require(FIXTURE.resolve() == FIXTURE and FIXTURE.is_dir() and ',' not in str(FIXTURE),
                'invalid fixed fixture directory')
        self.host, self.name, self.cid = host, name, None
        self.socket = Path.home() / '.docker/run/docker.sock'
        self.socket_identity = socket_identity(self.socket)
        self.config = host / 'docker-config'
        self.config.mkdir(mode=0o700)

    def adopt(self, cid):
        require(isinstance(cid, str) and re.fullmatch(r'[0-9a-f]{64}', cid)
                and self.cid in (None, cid), 'invalid owned container identity')
        self.cid = cid

    def validate_args(self, args):
        require(isinstance(args, (list, tuple)) and all(isinstance(arg, str) for arg in args),
                'invalid Docker arguments')
        args = list(args)
        fixed = [
            ['info', '--format', '{{.ID}}'],
            ['image', 'inspect', IMAGE],
            create_args(self.name, self.host / 'container.cid', self.host / 'host-canary'),
            ['container', 'ls', '--all', '--no-trunc', '--filter',
             f'name=^/{self.name}$', '--format', '{{.ID}}'],
        ]
        if args in fixed:
            return
        if len(args) == 2 and args[0] == 'inspect' and re.fullmatch(r'[0-9a-f]{64}', args[1]):
            return  # Read-only ownership recovery before adopting a CID.
        owned = [
            ['start', '--attach', self.cid], ['kill', self.cid], ['rm', '--force', self.cid],
            ['container', 'ls', '--all', '--no-trunc', '--filter', f'id={self.cid}', '--format', '{{.ID}}'],
        ]
        require(self.cid is not None and args in owned, 'unsupported Docker operation or identity')

    def start(self, args):
        self.validate_args(args)
        require(socket_identity(self.socket) == self.socket_identity, 'local Docker socket changed')
        argv = [DOCKER, '--host=unix://' + str(self.socket), '--config', str(self.config), *args]
        return subprocess.Popen(  # nosec B603 - Fixed Docker executable, validated argv, no shell.
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, env=docker_env(), close_fds=True)

    def command(self, args, *, timeout=TIMEOUT):
        process = self.start(args)
        try:
            output = read_bounded(process, timeout=timeout)
            code = process.wait(timeout=2)
            if code != 0:
                raise RuntimeError(command_failure(args[0], code, output))
            return output
        finally:
            finish_client(process)

    def daemon_identity(self):
        identity = self.command(['info', '--format', '{{.ID}}']).decode().strip()
        require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9:._-]{0,127}', identity), 'invalid Docker daemon identity')
        return identity


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


def create_args(name, cidfile, canary):
    return ['create', '--pull=never', '--name', name, '--cidfile', str(cidfile),
            '--label', 'reviewer.fixture=' + name, '--network=none', '--user=65532:65532', '--cap-drop=ALL',
            '--security-opt=no-new-privileges:true', '--read-only', '--ipc=private',
            '--pids-limit=32', '--memory=128m', '--memory-swap=128m', '--cpus=1',
            '--tmpfs', '/work:' + TMPFS, '--log-driver=none', '--restart=no',
            '--mount', f'type=bind,src={FIXTURE},dst=/fixture,readonly',
            '--entrypoint=python3', IMAGE, '-I', '-B', '/fixture/child.py', str(canary)]


def validate_ownership(value, cid, name):
    require(value.get('Id') == cid and value.get('Name') == '/' + name
            and value.get('Config', {}).get('Labels', {}).get('reviewer.fixture') == name,
            'owned container identity')


def validate_inspect(value, cid, canary, name):
    validate_ownership(value, cid, name)
    require(value.get('Image') == IMAGE, 'container/image identity')
    h, c = value['HostConfig'], value['Config']
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
    extra_access = ('Devices', 'DeviceRequests', 'VolumesFrom', 'PortBindings', 'Links')
    require(not any(h.get(key) for key in extra_access), 'additional access')
    mounts = value.get('Mounts', [])
    binds = [m for m in mounts if m.get('Type') == 'bind']
    allowed_mounts = all(
        mount.get('Type') == 'bind'
        or (mount.get('Type') == 'tmpfs' and mount.get('Destination') == '/work')
        for mount in mounts
    )
    require(len(binds) == 1 and allowed_mounts, 'unexpected mounts')
    mount = binds[0]
    require(mount.get('Type') == 'bind' and mount.get('Source') == str(FIXTURE)
            and mount.get('Destination') == '/fixture' and mount.get('RW') is False, 'fixture mount')
    require(c.get('User') == '65532:65532' and c.get('Entrypoint') == ['python3'], 'process identity')
    require(c.get('Cmd') == ['-I', '-B', '/fixture/child.py', str(canary)], 'child command')
    credential_prefixes = ('GH_', 'GITHUB_', 'ACTIONS_', 'ANTHROPIC_', 'HOST_CANARY')
    require(not any(value.split('=', 1)[0].startswith(credential_prefixes)
                    for value in c.get('Env', [])), 'credential environment')
    require(value.get('State', {}).get('Status') == 'created'
            and value['State'].get('Running') is False, 'container already started')


def validate_report(raw):
    report = json.loads(raw)
    require(set(report) == {'checks', 'init_pid', 'descendant_pid'}, 'report shape')
    require(set(report['checks']) == CHECKS
            and all(value is True for value in report['checks'].values()), 'child boundary checks')
    init, descendant = report['init_pid'], report['descendant_pid']
    require(isinstance(init, int) and not isinstance(init, bool) and init == 1
            and isinstance(descendant, int) and not isinstance(descendant, bool) and descendant > 1,
            'PID namespace report')
    return report


def cleanup(cid, invoke):
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


def recover_owned(name, invoke):
    # Exact random name plus matching label; never a global prune or PID signal.
    listing = invoke(['container', 'ls', '--all', '--no-trunc', '--filter',
                      f'name=^/{name}$', '--format', '{{.ID}}'])
    ids = listing.decode().splitlines()
    if not ids:
        return None
    require(len(ids) == 1 and re.fullmatch(r'[0-9a-f]{64}', ids[0]), 'ambiguous recovery')
    value = json.loads(invoke(['inspect', ids[0]]))[0]
    validate_ownership(value, ids[0], name)
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
        docker = None
        daemon_before = daemon_after = None
        try:
            docker = LocalDocker(host, name)
            daemon_before = docker.daemon_identity()
            image = json.loads(docker.command(['image', 'inspect', IMAGE]))[0]
            require(image.get('Id') == IMAGE and image.get('Os') == 'linux'
                    and image.get('Architecture') == 'arm64', 'local image mismatch')
            require(recover_owned(name, docker.command) is None, 'owned name already exists')
            creation_attempted = True
            output = docker.command(create_args(name, cidfile, canary)).decode().strip()
            created = cidfile.read_text().strip()
            require(re.fullmatch(r'[0-9a-f]{64}', created) and output == created, 'create identity mismatch')
            state = json.loads(docker.command(['inspect', created]))[0]
            validate_ownership(state, created, name)
            docker.adopt(created)
            cid = created
            validate_inspect(state, cid, canary, name)
            attached = docker.start(['start', '--attach', cid])
            report = validate_report(read_bounded(attached, first_line=True))
            require(hashlib.sha256(canary.read_bytes()).hexdigest() == expected, 'host canary changed')
        except Exception as error:
            failures.append(str(error))
        finally:
            # A create timeout may precede CID delivery; recover only our random name/label.
            if cid is None and creation_attempted:
                try:
                    cid = recover_owned(name, docker.command)
                    if cid:
                        docker.adopt(cid)
                except Exception as error:
                    failures.append('recovery: ' + str(error))
            if cid:
                try:
                    cleanup(cid, docker.command)
                except Exception as error:
                    failures.append('cleanup: ' + str(error))
            elif creation_attempted:
                failures.append('container identity unavailable; creation/cleanup incomplete')
            if attached:
                try:
                    finish_client(attached)
                except Exception as error:
                    failures.append('client cleanup: ' + str(error))
            if docker is not None:
                try:
                    daemon_after = docker.daemon_identity()
                    require(daemon_after == daemon_before, 'Docker daemon identity changed')
                except Exception as error:
                    failures.append('daemon readback: ' + str(error))
            if hashlib.sha256(canary.read_bytes()).hexdigest() != expected:
                failures.append('host canary changed')
        result = {'status': 'FAIL' if failures else 'PASS', 'image': IMAGE, 'container_id': cid, 'container_name': name,
                  'checks': report, 'failures': failures,
                  'daemon': {'endpoint': str(docker.socket) if docker else None,
                             'idBefore': daemon_before, 'idAfter': daemon_after},
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
