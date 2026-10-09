#!/usr/bin/env python3
"""Real native witness + production CLI/daemon + disposable cloud admission proof."""

import argparse
import asyncio
import base64
from contextlib import contextmanager, redirect_stdout
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import socket
import sqlite3
import subprocess  # nosec B404 - Qualification launches verified local executables with fixed argument arrays.
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4


HERE = Path(__file__).absolute().parent
DAEMON_MAIN = '''import importlib.util, sys
spec = importlib.util.spec_from_file_location("qualification_installed", sys.argv[1])
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)
checks.verified_python()
checks.verify_installed(sys.argv[2])
from event_gateway.cli import main
raise SystemExit(main(sys.argv[3:]))
'''


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inputs():
    parser = argparse.ArgumentParser(description=__doc__)
    names = ('package-source', 'qualifier', 'binary', 'binary-sha', 'node', 'cloud-source', 'esbuild', 'miniflare', 'output')
    for name in names:
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    require(sys.flags.isolated, 'qualification requires Python -I')
    args.helper = HERE / 'qualification-installed.py'
    checks = load_module('qualification_installed', args.helper)
    args.python = checks.verified_python()
    args.provenance = checks.verify_installed(args.package_source)
    args.node = checks.verified_executable(args.node)
    args.qualifier = Path(args.qualifier).resolve(strict=True)
    args.output = Path(args.output).resolve()
    args.broker = HERE / 'admission-workerd-broker.mjs'
    artifacts = [Path(__file__).absolute(), args.helper, args.qualifier, args.broker,
                 HERE / 'admission-workerd-worker.ts', HERE / 'coupled-workerd-source-hashes.mjs']
    args.source_hashes = {**args.provenance['verifiedSha256'], **{str(path): sha(path) for path in artifacts}}
    # All installed module and contract bytes have been verified before these imports.
    from event_gateway import cli, client_runtime, launcher, security, store

    args.binary = launcher.qualified_binary(Path(args.binary), args.binary_sha)
    args.source_hashes[str(args.binary)] = args.binary_sha
    gateway = SimpleNamespace(cli=cli, client_runtime=client_runtime, launcher=launcher, security=security, store=store)
    native = load_module('admission_native_qualifier', args.qualifier)
    return args, gateway, native


def qualify_native(args, gateway, native):
    """Recheck one descriptor's metadata and bytes immediately before each owned boot."""
    binary = gateway.launcher.qualified_binary(args.binary, args.binary_sha)
    return native.qualify(binary, input_recorded=True, receipt_version=3)


@contextmanager
def child(command, **options):
    # The caller supplies verified Node/Python paths, fixed code, and isolated environments.
    process = subprocess.Popen(command, **options)  # nosec B603 - Verified executables; no shell or inherited loader variables.
    try:
        yield process
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


@contextmanager
def broker(args, directory, log):
    environment = {'PATH': '/usr/bin:/bin', 'HOME': directory,
                   'FIXTURE_CLOUD_SOURCE': str(Path(args.cloud_source).resolve(strict=True)),
                   'FIXTURE_ESBUILD': str(Path(args.esbuild).resolve(strict=True)),
                   'FIXTURE_MINIFLARE': str(Path(args.miniflare).resolve(strict=True))}
    with child([args.node, str(args.broker)], stdout=subprocess.PIPE, stderr=log, text=True, env=environment, cwd=directory) as process:
        require(select.select([process.stdout], [], [], 30)[0], 'broker startup deadline')
        line = process.stdout.readline()
        require(line, 'broker exited before startup handshake; inspect broker log')
        yield json.loads(line)


class FixtureTransport:
    """The explicit loopback and lost-reply boundary, preserving request body bytes."""

    def __init__(self, address):
        """Bind the fixture endpoint and arrange two lost successful attach replies."""
        self.address = address
        self.wires = []
        self.drop = 2
        self.gate_disabled = False

    def post(self, path, body, headers=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.address['port'], timeout=5)
        fixture_headers = {'cf-access-token': 'fixture-access', 'authorization': 'Bearer fixture-agent'}
        headers = {**(fixture_headers if headers is None else headers), 'x-fixture-secret': self.address['secret'],
                   'content-type': 'application/json'}
        try:
            connection.request('POST', path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read(1048577)
            require(len(raw) <= 1048576, 'bounded response')
            return response.status, {'content-type': response.getheader('content-type')}, raw
        finally:
            connection.close()

    def fixture(self, path, value=None):
        status, _, body = self.post(path, json.dumps(value or {}).encode())
        require(status == 200, 'fixture route ' + path + ': ' + str(status) + ' ' + body.decode())
        return json.loads(body)

    async def send(self, **wire):
        require(wire['method'] == 'POST' and wire['url'].startswith('https://events.example.com/'), 'closed origin')
        require((wire['timeout'], wire['max_response_bytes'], wire['follow_redirects']) == (5, 8192, False), 'transport limits')
        path = wire['url'].removeprefix('https://events.example.com')
        headers = dict(wire['headers'])
        if self.gate_disabled:
            key = 'x-fixture-canary-mismatch' if self.gate_disabled == 'mismatch' else 'x-fixture-gate-disabled'
            headers[key] = 'true'
        response = await asyncio.to_thread(self.post, path, wire['body'], headers)
        self.wires.append({'path': path, 'body': wire['body'].decode(), 'proof': json.loads(headers['x-event-node-proof']),
                           'status': response[0], 'response': json.loads(response[2])})
        if path == '/v1/runtimes/attach' and self.drop:
            require(response[0] == 200, 'reply lost only after actual commit')
            self.drop -= 1
            raise TimeoutError('deliberately lost committed reply')
        return response


class AdmissionRun:
    """One enrollment and daemon ledger, shared across two real native clients."""

    def __init__(self, args, gateway, root, transport):
        """Create private local state and enroll one node for both native clients."""
        self.args, self.gateway, self.transport = args, gateway, transport
        self.state = root / 'state'
        self.state.mkdir(mode=0o700)
        self.config = root / 'cloud.json'
        self.node_id, self.source_id, self.target_id = (str(uuid4()) for _ in range(3))
        self.outcomes, self.sessions = [], []
        self.configure(root)

    def configure(self, root):
        key = self.gateway.security.load_or_create_signing_key(self.state / 'node-key.pem')
        self.config.write_text(json.dumps({'version': 1, 'origin': 'https://events.example.com', 'principal': 'qualification@example.com',
                                          'agent': 'pilot', 'nodeId': self.node_id, 'nodeGeneration': 1, 'credentialsFile': 'credentials.json'}))
        self.config.chmod(0o600)
        credentials = root / 'credentials.json'
        credentials.write_text(json.dumps({'accessToken': 'fixture-access', 'agentToken': 'fixture-agent'}))
        credentials.chmod(0o600)
        public = base64.urlsafe_b64encode(key.public_key().public_bytes_raw()).rstrip(b'=').decode()
        challenge = self.transport.fixture('/fixture/challenge', {'nodeId': self.node_id, 'publicKey': {'kty': 'OKP', 'crv': 'Ed25519', 'x': public},
                                                                  'meshIp': '100.96.0.1', 'meshPort': 8789, 'agents': ['pilot']})
        signature = base64.urlsafe_b64encode(key.sign(challenge['signingPayload'].encode())).rstrip(b'=').decode()
        self.transport.fixture('/v1/nodes/complete', {'challengeId': challenge['challengeId'], 'signature': signature})
        require(self.transport.fixture('/fixture/read')['runtimes'] == [], 'no preinserted runtimes')

    def await_daemon(self, process):
        deadline = time.monotonic() + 10
        while not (self.state / 'control.sock').exists():
            require(process.poll() is None and time.monotonic() < deadline, 'daemon startup')
            time.sleep(.02)
        try:
            with self.gateway.store.Store(self.state):
                raise AssertionError('daemon did not own writer')
        except self.gateway.store.StoreError as error:
            require(error.code == 'writer_locked', 'actual writer lock')

    def local(self):
        with sqlite3.connect(f'file:{self.state}/ledger.sqlite?mode=ro', uri=True) as db:
            return {runtime: json.loads(data) for runtime, data in db.execute('SELECT runtime,data FROM attachments')}

    def command(self, session, operation, *flags):
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = self.gateway.cli.main(['--state-dir', str(self.state), operation, '--session-id', session,
                                          '--cloud-config', str(self.config), *flags])
        result = json.loads(stream.getvalue())
        self.outcomes.append({'operation': operation, 'exitCode': code, 'result': result})
        return result

    @contextmanager
    def session(self, bridge, process, initial_witness):
        launcher = self.gateway.launcher
        # Qualifier has performed the real startup exchange before this callback.
        client = launcher.NativeClient(bridge)
        client.ready = True
        challenge_calls = []
        original_challenge = client.challenge

        def record_challenge(*values):
            challenge_calls.append(values[0])
            return original_challenge(*values)

        client.challenge = record_challenge
        session_id = str(uuid4())
        path = launcher.session_path(self.state, session_id)
        stop = threading.Event()
        thread = None
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            try:
                listener.bind(str(path))
                path.chmod(0o600)
                listener.listen(4)
                listener.settimeout(.1)
                thread = threading.Thread(target=launcher._control, args=(listener, client, stop), daemon=True)
                thread.start()
                binding = launcher.session_binding(self.state, session_id)
                self.sessions.append({'sessionId': session_id, 'pid': process.pid, 'binding': binding, 'initialWitness': initial_witness})
                yield session_id, binding, challenge_calls
            finally:
                stop.set()
                if thread is not None:
                    thread.join(timeout=2)
                    require(not thread.is_alive(), 'launcher control thread stopped')
                path.unlink(missing_ok=True)

    def source_recovery(self, session_id, challenge_calls):
        runtime = self.gateway.client_runtime
        first = self.command(session_id, 'attach', '--runtime-id', self.source_id)
        require(first.get('attached') is None and first['reason'] == 'commit_outcome_unknown', 'both replies lost')
        pending = runtime.load_pending_commit(self.state, 'attach', session_id)
        require(pending is not None and self.source_id not in self.local(), 'durable pending before mapping')
        before = self.transport.fixture('/fixture/read')
        require(len(before['runtimes']) == 1 and before['runtimes'][0]['runtime_generation'] == 1, 'one cloud commit')
        before_challenges = list(challenge_calls)
        # Expire the native witness; exact receipt replay must remain valid.
        time.sleep(.8)
        recovered = self.command(session_id, 'attach', '--runtime-id', self.source_id)
        require(recovered.get('localStatus') == 'current', 'exact pending recovery')
        require(challenge_calls == before_challenges, 'recovery must not resample challenged witness')
        require(self.transport.fixture('/fixture/read') == before, 'exact replay leaves cloud admission unchanged')
        wires = [row for row in self.transport.wires if row['path'] == '/v1/runtimes/attach']
        require(len(wires) == 3 and len({row['body'] for row in wires}) == 1, 'same admission bytes')
        require(len({row['proof']['nonce'] for row in wires}) == 3, 'fresh signed proof each retry')
        require(base64.b64decode(pending['bodyB64']).decode() == wires[0]['body'], 'durable exact body')
        require(runtime.load_pending_commit(self.state, 'attach', session_id) is None, 'pending cleared after daemon write')
        require(self.local()[self.source_id]['runtimeGeneration'] == 1, 'daemon persisted source')

    def renew(self, session_id, generation='1'):
        return self.command(session_id, 'renew', '--runtime-id', self.source_id,
                            '--expected-runtime-generation', generation, '--expected-attachment-generation', '1')

    def source_denials(self, session_id):
        require(self.renew(session_id).get('remoteStatus') == 'renewed', 'actual renew')
        snapshot = self.transport.fixture('/fixture/read')['runtimes']
        stale = self.renew(session_id, '2')
        require(stale.get('renewed') is False and stale['reason'] == 'conflict', 'stale CAS denied')
        for gate in (True, 'mismatch'):
            self.transport.gate_disabled = gate
            try:
                denied = self.renew(session_id)
            finally:
                self.transport.gate_disabled = False
            require(denied.get('renewed') is False and denied['reason'] == 'native_binding_unqualified', 'disabled or mismatched gate denied')
        require(self.transport.fixture('/fixture/read')['runtimes'] == snapshot, 'denials preserve runtime')

    def target_phase(self, session_id, binding):
        require(binding['clientId'] != self.sessions[0]['binding']['clientId'], 'distinct actual native client')
        snapshot = self.transport.fixture('/fixture/read')['runtimes']
        wrong = self.renew(session_id)
        require(wrong.get('renewed') is False and wrong['reason'] == 'native_binding_unqualified', 'different actual native binding denied')
        require(self.transport.fixture('/fixture/read')['runtimes'] == snapshot, 'invalid binding preserves source')
        attached = self.command(session_id, 'attach', '--runtime-id', self.target_id)
        require(attached.get('localStatus') == 'current', 'actual target attach')
        transferred = self.command(session_id, 'transfer', '--source-runtime-id', self.source_id, '--expected-source-runtime-generation', '1',
                                   '--expected-source-attachment-generation', '1', '--replacement-runtime-id', self.target_id,
                                   '--expected-replacement-runtime-generation', '1', '--expected-replacement-attachment-generation', '1')
        require(transferred.get('remoteStatus') == 'transferred' and transferred.get('localStatus') == 'current', 'actual transfer')
        rows = {row['runtime_id']: row for row in self.transport.fixture('/fixture/read')['runtimes']}
        source = rows[self.source_id]
        require(source['qualified'] == 0 and source['lease_until'] == 0 and source['runtime_generation'] == 2, 'cloud source fence')
        require(rows[self.target_id]['attachment_generation'] == 2 and rows[self.target_id]['qualified'] == 1, 'cloud target generation')
        mappings = self.local()
        require(mappings[self.source_id]['leaseExpiresAt'] == 0 and mappings[self.source_id]['runtimeGeneration'] == 2, 'daemon source fence')
        require(mappings[self.target_id]['attachmentGeneration'] == 2, 'daemon target mapping')

    def callback(self, phase):
        def run(bridge, model, process, initial_witness):
            try:
                with self.session(bridge, process, initial_witness) as (session_id, binding, calls):
                    with patch.object(self.gateway.client_runtime, '_send_https', self.transport.send):
                        if phase == 'source':
                            self.source_recovery(session_id, calls)
                            self.source_denials(session_id)
                        else:
                            self.target_phase(session_id, binding)
                    require(model.model_requests == 0 and process.poll() is None, 'live native, no model calls')
                    return {'result': 'PASS'}
            finally:
                model.release_primary.set()

        return run

    def proof(self):
        self.gateway.launcher.qualified_binary(self.args.binary, self.args.binary_sha)
        require(all(sha(path) == digest for path, digest in self.args.source_hashes.items()), 'verified source changed during qualification')
        return {'result': 'PASS', 'qualification': 'fixture-authority-real-native-cloud-admission', 'productionAdmissionProven': False,
                'nativeRuntimeSqlInsertion': False, 'daemonWriterVerified': True, 'realModelCalls': 0, 'binarySha256': self.args.binary_sha,
                'installedDistribution': self.args.provenance, 'sessions': self.sessions, 'wire': self.transport.wires,
                'outcomes': self.outcomes, 'cloud': self.transport.fixture('/fixture/read'), 'local': self.local(),
                'cloudBundle': self.transport.address['bundle'], 'sourceSha256': self.args.source_hashes,
                'mocks': ['Access edge and Messaging identity', 'owner enrollment challenge', 'loopback HTTP transport',
                          'private launcher control socket setup']}


def main():
    args, gateway, native = inputs()
    with tempfile.TemporaryDirectory(prefix='admission-', dir='/private/tmp') as directory, open(str(args.output) + '.broker.log', 'w') as log:
        with broker(args, directory, log) as address:
            run = AdmissionRun(args, gateway, Path(directory), FixtureTransport(address))
            command = [args.python, '-I', '-c', DAEMON_MAIN, str(args.helper), args.package_source, '--state-dir', str(run.state), 'run']
            with child(command, env={'PATH': os.defpath, 'HOME': directory}, stdout=log, stderr=log, cwd=directory) as daemon:
                run.await_daemon(daemon)
                for phase in ('source', 'target'):
                    native.qualify_input_recorded = run.callback(phase)
                    qualify_native(args, gateway, native)
                args.output.write_text(json.dumps(run.proof(), indent=2) + '\n')
                print(json.dumps({'result': 'PASS', 'proof': str(args.output), 'productionAdmissionProven': False}))


if __name__ == '__main__':
    main()
