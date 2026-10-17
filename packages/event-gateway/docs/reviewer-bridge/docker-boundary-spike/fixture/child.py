"""Harmless containment probe; intentionally contains no host secret."""
import json
import os
from pathlib import Path
import sys
import time


def refused(operation):
    try:
        operation()
    except OSError:
        return True
    return False


status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines())
work = Path('/work/probe')
work.write_text('private scratch')
checks = {
    'work_write': work.read_text() == 'private scratch',
    'root_write_denied': refused(lambda: Path('/rootfs-probe').write_text('x')),
    'fixture_write_denied': refused(lambda: Path('/fixture/child.py').open('a')),
    'host_canary_unreadable': refused(lambda: Path(sys.argv[1]).read_bytes()),
    'docker_socket_absent': not Path('/var/run/docker.sock').exists(),
    'uid_gid': os.getuid() == 65532 and os.getgid() == 65532,
    'groups': set(os.getgroups()).issubset({65532}),
    'caps_zero': all(int(status[key].strip(), 16) == 0 for key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')),
    'no_new_privileges': status['NoNewPrivs'].strip() == '1',
    'credential_env_absent': not any(key.startswith(('GH_', 'GITHUB_', 'ACTIONS_', 'ANTHROPIC_', 'HOST_CANARY')) for key in os.environ),
    'private_init': os.getpid() == 1,
}
child = os.fork()
if child == 0:
    time.sleep(60)
    os._exit(0)
child_status = dict(line.split(':', 1) for line in Path(f'/proc/{child}/status').read_text().splitlines())
checks['descendant_same_namespace'] = os.readlink('/proc/self/ns/pid') == os.readlink(f'/proc/{child}/ns/pid')
checks['descendant_parent'] = child > 1 and child_status['PPid'].strip() == str(os.getpid())
print(json.dumps({'checks': checks, 'init_pid': os.getpid(), 'descendant_pid': child}, sort_keys=True), flush=True)
time.sleep(60)  # Supervisor must stop the namespace, not merely its Docker client.
