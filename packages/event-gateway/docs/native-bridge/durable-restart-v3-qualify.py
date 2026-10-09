"""Disposable two-TUI v3 restart proof; synthetic model only, no installed-client access."""
import argparse
import asyncio
import fcntl
import hashlib
import importlib.util
import importlib.metadata
import json
import os
import pty
import select
import signal
import socket
import struct
import subprocess  # nosec B404 - Explicit hash-checked disposable native fixture.
import sys
import termios
import threading
import time
from copy import deepcopy
from pathlib import Path
from uuid import uuid4


def require(condition, message=None):
    if not condition:
        if message is None:
            raise AssertionError
        raise AssertionError(message)


SOURCE = Path(os.environ['EVENT_NATIVE_QUALIFIER']).resolve(strict=True)
SOURCE_SHA = 'c74ba56b3ee324aa5b490dfe7cc767e3b72d168054fcce7ba8469caddfafa552'
require(hashlib.sha256(SOURCE.read_bytes()).hexdigest() == SOURCE_SHA)
INSTALLED_SHA = '4ab38f6f5231acda4fee0af5d017ab33c583f3fecfc4e68531000a8dd25c0f85'
DISTRIBUTION = importlib.metadata.distribution('knitli-event-gateway')
require(any(str(file) == 'event_gateway/native.py' for file in DISTRIBUTION.files or ()))
INSTALLED = Path(DISTRIBUTION.locate_file('event_gateway/native.py')).resolve(strict=True)
require(hashlib.sha256(INSTALLED.read_bytes()).hexdigest() == INSTALLED_SHA)
PACKAGE_INIT = INSTALLED.with_name('__init__.py')
PACKAGE_INIT_SHA = 'c8d3b1e2a5706c34278758e5f3ea820e055f1ec9f1634632cc43e65928458c8e'
require(any(str(file) == 'event_gateway/__init__.py' for file in DISTRIBUTION.files or ()))
require(PACKAGE_INIT == Path(DISTRIBUTION.locate_file('event_gateway/__init__.py')).resolve(strict=True))
require(hashlib.sha256(PACKAGE_INIT.read_bytes()).hexdigest() == PACKAGE_INIT_SHA)
READER = INSTALLED.with_name('native_reader.py')
READER_SHA = '7ee1925d3334382199159525dc9e066edef2d9a7910621143f61b0b808166c7a'
require(any(str(file) == 'event_gateway/native_reader.py' for file in DISTRIBUTION.files or ()))
require(READER == Path(DISTRIBUTION.locate_file('event_gateway/native_reader.py')).resolve(strict=True))
require(hashlib.sha256(READER.read_bytes()).hexdigest() == READER_SHA)
require(not any(name == 'event_gateway' or name.startswith('event_gateway.') for name in sys.modules),
        'SDK already loaded before integrity preflight')
# Prefer only the verified installed package over cwd/PYTHONPATH shadows.
sys.path.insert(0, str(INSTALLED.parent.parent))
installed_native = importlib.import_module('event_gateway.native')
require(Path(installed_native.__file__).resolve() == INSTALLED)
NativeBridgeAdapter = installed_native.NativeBridgeAdapter
validate_receipt = installed_native.validate_receipt
installed_reader = importlib.import_module('event_gateway.native_reader')
require(Path(installed_reader.__file__).resolve() == READER)
spec = importlib.util.spec_from_file_location('native_qualifier', SOURCE)
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def wait_for(predicate, process, seconds=10):
    deadline = time.monotonic() + seconds
    while not predicate():
        require(process.poll() is None and time.monotonic() < deadline, 'bounded live-process wait expired')
        time.sleep(0.05)


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def stop_process(process, backend_pid):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    # The leader may exit while a descendant survives SIGTERM.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)
    if backend_pid is None:
        return
    deadline = time.monotonic() + 5
    while alive(backend_pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    require(not alive(backend_pid), 'old app-server still alive')


def assert_counts(server):
    require(server.request_counts['primary'] == 1, 'primary model request repeated')
    require(server.request_counts['title'] <= 1 and server.request_counts['unknown'] == 0)
    require(server.model_requests == sum(server.request_counts.values()))


def old_request_probes(bridge, request, recorded, server):
    bridge.restore_attempt(request)
    require(bridge.receipt(request) == recorded and bridge.receipt(request) == recorded)
    changed = []
    fields = [key for key in (*native.IDENTITY, 'generation') if key != 'permitExpiresAt']
    for key in (*fields, *('event.' + k for k in request['event'])):
        candidate = deepcopy(request)
        target, field = (candidate['event'], key[6:]) if key.startswith('event.') else (candidate, key)
        value = target[field]
        if key == 'event.source':
            target[field] = 'github'
            target['canonicalSubject'] = {'kind': 'github_pr', 'repositoryId': '1', 'pullRequestNumber': 1}
            key = 'event.source+event.canonicalSubject'
        elif key == 'permitIssuedAt':
            candidate['permitIssuedAt'] += 1
            candidate['permitExpiresAt'] += 1
            key = 'permitIssuedAt+permitExpiresAt'
        elif isinstance(value, dict):
            target[field] = {**value, 'subjectId': 'changed-subject'}
        elif isinstance(value, int):
            target[field] = value + 1
        elif field == 'deliveryId':
            target[field] = 'dly_' + uuid4().hex + uuid4().hex
        elif field == 'eventReference':
            target[field] = 'ref_' + str(uuid4())
        elif field == 'sourceStateVersion':
            target[field] = 'changed-version'
        else:
            target[field] = str(uuid4())
        installed_reader.validate_start(candidate)  # Every negative remains a structurally valid request.
        # Deliberate wire probes bypass the SDK's local exact-attempt guard.
        require(bridge._receipt_exchange('receipt', candidate) == {'status': 'unknown'}, key)
        require(not bridge.closed, 'Unknown caused by a broken transport rather than native lookup')
        require(bridge.receipt(request) == recorded, key)
        changed.append(key)
    require((bridge._receipt_exchange('start', request) == {
        'status': 'notStarted', 'reason': 'selectionChanged'}), 'old Start bypassed local selection')
    # This local refusal is not a certified old-attempt no-start settlement.
    require(not bridge.closed and bridge.receipt(request) == recorded)
    assert_counts(server)
    return changed


def restart_callback(first, server, process, witness):
    request = native.synthetic_request(witness)
    mapping = {'nativeThreadId': request['threadId']}
    submitted = asyncio.run(NativeBridgeAdapter(mapping, first).submit({**request, 'receiptVersion': 3}))
    require(submitted['generation'] == request['generation'])
    require(validate_receipt({**request, 'receiptVersion': 3}, submitted)['status'] == 'started')
    observed = {}

    def input_seen():
        observed.update(first.receipt(request))
        require(observed['status'] in ('started', 'inputRecorded'))
        return observed['status'] == 'inputRecorded'

    wait_for(input_seen, process)
    recorded = dict(observed)
    wait_for(lambda: server.request_counts['primary'] == 1, process)
    wait_for(lambda: time.time_ns() // 1_000_000 > request['permitExpiresAt'], process)
    require(first.receipt(request) == recorded)
    server.release_primary.set()
    wait_for(lambda: first.challenge()['eligible'], process)
    assert_counts(server)
    args = list(process.args)
    root = Path(args[args.index('-C') + 1])
    (root / 'old-bridge-event.json').write_text(json.dumps(request, sort_keys=True))
    stop_process(process, witness['backendPid'])
    first.close()
    parent = child = master = slave = bridge = None
    stop, second, thread, new_witness = threading.Event(), None, None, None
    startup_tail = bytearray()

    def drain():
        while not stop.is_set():
            if select.select([master], [], [], 0.1)[0]:
                try:
                    data = os.read(master, 65536)
                    if not data:
                        break
                    startup_tail.extend(data)
                    del startup_tail[:-8192]
                    if b'\x1b[6n' in data:
                        os.write(master, b'\x1b[1;1R')
                except OSError:
                    break

    try:
        parent, child = socket.socketpair()
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 120, 0, 0))
        bridge = native.NativeBridge(parent, receipt_version=3)
        second = subprocess.Popen(args, cwd=root, stdin=slave, stdout=slave, stderr=slave,  # nosec B603
                                  pass_fds=(child.fileno(),), start_new_session=True,
                                  env={'PATH': os.defpath, 'HOME': str(root), 'CODEX_HOME': str(root / 'codex-home'),
                                       'TERM': 'xterm-256color', 'CODEX_NATIVE_BRIDGE_FD': str(child.fileno()),
                                       'CODEX_NATIVE_BRIDGE_RECEIPT_VERSION': '3'})
        child.close()
        os.close(slave)
        slave = None
        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        bridge.exchange({}, 30)  # Synchronize only; never grants a witness.
        new_witness = {}

        def connected():
            new_witness.update(bridge.challenge())
            return new_witness['serverInstanceId'] is not None and new_witness['threadId'] is not None

        wait_for(connected, second)
        require(new_witness['clientId'] != witness['clientId'])
        require(new_witness['serverInstanceId'] not in (None, witness['serverInstanceId']))
        require(new_witness['backendPid'] != witness['backendPid'])
        require(new_witness['threadId'] != request['threadId'])
        restored = json.loads((root / 'old-bridge-event.json').read_text())
        require(restored == request)
        adapter = NativeBridgeAdapter(mapping, bridge)
        require(asyncio.run(adapter.check()) == 'unavailable')
        recovered = asyncio.run(adapter.reconcile({**restored, 'receiptVersion': 3}))
        require(recovered['generation'] == request['generation'])
        require(validate_receipt({**request, 'receiptVersion': 3}, recovered, allow_input_recorded=True) == recorded)
        changed = old_request_probes(bridge, restored, recorded, server)
        require(asyncio.run(adapter.check()) == 'unavailable')
        after_probes = bridge.challenge()
        require(all(after_probes[key] == new_witness[key]
                   for key in ('clientId', 'serverInstanceId', 'backendPid', 'threadId')))
        time.sleep(0.25)
        require(second.poll() is None)
        assert_counts(server)
        return {'qualification': 'synthetic-native-v3-two-tui-restart', 'nativeOnly': True,
                'cloudSettlementProven': False, 'realModelCalls': 0, 'oldRequest': request,
                'installedAdapterProven': True, 'installedAdapterModule': str(INSTALLED),
                'installedAdapterSha256': INSTALLED_SHA,
                'recorded': recorded, 'newWitness': new_witness, 'mutatedFieldsRejected': changed,
                'oldProcessesStopped': True, 'permitExpired': True, 'exactReceiptRecoveredTwice': True,
                'oldStartLocallyRefused': True, 'oldStartNoStartSettlementProven': False,
                'originalAttachmentUnavailable': True, 'newSelectedThreadId': new_witness['threadId'],
                'modelRequestCounts': dict(server.request_counts)}
    except Exception:
        print(json.dumps({'phase': 'second-tui-startup-or-proof', 'argv': args,
                          'processPoll': second.poll() if second else None,
                          'syntheticPtyTail': bytes(startup_tail).decode('utf-8', errors='replace')}), file=sys.stderr)
        raise
    finally:
        stop.set()
        if bridge is not None:
            bridge.close()
        elif parent is not None:
            parent.close()
        if child is not None:
            child.close()
        try:
            if second is not None:
                stop_process(second, new_witness['backendPid'] if new_witness else None)
        finally:
            if thread:
                thread.join(timeout=1)
            if slave is not None:
                os.close(slave)
            if master is not None:
                os.close(master)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(hashlib.sha256(args.binary.read_bytes()).hexdigest() == args.sha256, 'binary SHA mismatch')
    native.qualify_input_recorded = restart_callback
    result = native.qualify(args.binary, input_recorded=True, receipt_version=3)
    result.update(binarySha256=args.sha256, readerSha256=SOURCE_SHA, installedReaderSha256=READER_SHA)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps(result, sort_keys=True))
