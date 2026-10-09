#!/usr/bin/env python3
"""Real native witness + production CLI/daemon + disposable cloud admission proof."""
import argparse
import asyncio
import base64
from contextlib import redirect_stdout
import hashlib
import http.client
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch
from uuid import uuid4


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('qualifier', 'binary', 'binary-sha', 'node', 'cloud-source', 'esbuild', 'miniflare', 'output'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    import event_gateway
    from event_gateway import cli, client_runtime, launcher
    from event_gateway.security import load_or_create_signing_key
    from event_gateway.store import Store, StoreError
    distribution = importlib.metadata.distribution('knitli-event-gateway')
    require(Path(event_gateway.__file__).resolve() == Path(distribution.locate_file('event_gateway/__init__.py')).resolve(), 'installed package identity')
    direct_url = distribution.read_text('direct_url.json')
    provenance = json.loads(direct_url) if direct_url else None
    require('event_gateway/native_reader.py' in {str(file) for file in distribution.files or ()}, 'noneditable wheel')
    binary = Path(args.binary).resolve(strict=True)
    require(sha(binary) == args.binary_sha, 'qualified native binary hash')
    qualifier = Path(args.qualifier).resolve(strict=True)
    spec = importlib.util.spec_from_file_location('admission_native_qualifier', qualifier)
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    output = Path(args.output).resolve()
    broker_path = Path(__file__).with_name('admission-workerd-broker.mjs')
    wires, outcomes, sessions = [], [], []
    with tempfile.TemporaryDirectory(prefix='admission-', dir='/private/tmp') as directory, open(str(output)+'.broker.log', 'w') as log:
        root = Path(directory)
        state = root / 'state'
        state.mkdir(mode=0o700)
        key = load_or_create_signing_key(state / 'node-key.pem')
        node_id, source_id, target_id = (str(uuid4()) for _ in range(3))
        config = root / 'cloud.json'
        config.write_text(json.dumps({'version':1,'origin':'https://events.example.com','principal':'qualification@example.com','agent':'pilot','nodeId':node_id,'nodeGeneration':1,'credentialsFile':'credentials.json'}))
        config.chmod(0o600)
        credentials = root / 'credentials.json'
        credentials.write_text(json.dumps({'accessToken':'fixture-access','agentToken':'fixture-agent'}))
        credentials.chmod(0o600)
        broker = subprocess.Popen([str(Path(args.node).resolve(strict=True)), str(broker_path)], stdout=subprocess.PIPE, stderr=log, text=True,
            env={'PATH':'/usr/bin:/bin','HOME':directory,'FIXTURE_CLOUD_SOURCE':str(Path(args.cloud_source).resolve(strict=True)),
                 'FIXTURE_ESBUILD':str(Path(args.esbuild).resolve(strict=True)),'FIXTURE_MINIFLARE':str(Path(args.miniflare).resolve(strict=True))}, cwd=directory)
        daemon = None
        try:
            require(select.select([broker.stdout], [], [], 30)[0], 'broker startup deadline')
            address = json.loads(broker.stdout.readline())
            def post(path, body, headers=None):
                connection = http.client.HTTPConnection('127.0.0.1', address['port'], timeout=5)
                try:
                    connection.request('POST',path,body=body,headers={**({'cf-access-token':'fixture-access','authorization':'Bearer fixture-agent'} if headers is None else headers),
                        'x-fixture-secret':address['secret'],'content-type':'application/json'})
                    response = connection.getresponse()
                    raw = response.read(1048577)
                    require(len(raw)<=1048576, 'bounded response')
                    return response.status, {'content-type':response.getheader('content-type')}, raw
                finally:
                    connection.close()
            def fixture(path, value=None):
                status, _, body = post(path,json.dumps(value or {}).encode())
                require(status == 200, 'fixture route '+path+': '+str(status)+' '+body.decode())
                return json.loads(body)
            def b64(value):
                return base64.urlsafe_b64encode(value).rstrip(b'=').decode()
            challenge = fixture('/fixture/challenge', {'nodeId':node_id,'publicKey':{'kty':'OKP','crv':'Ed25519','x':b64(key.public_key().public_bytes_raw())},'meshIp':'100.96.0.1','meshPort':8789,'agents':['pilot']})
            fixture('/v1/nodes/complete', {'challengeId':challenge['challengeId'],'signature':b64(key.sign(challenge['signingPayload'].encode()))})
            require(fixture('/fixture/read')['runtimes'] == [], 'no preinserted runtimes')
            daemon = subprocess.Popen([str(Path(sys.executable).parent/'knitli-event-gateway'),'--state-dir',str(state),'run'], env={'PATH':os.defpath,'HOME':directory}, stdout=log, stderr=log)
            deadline = time.monotonic()+10
            while not (state/'control.sock').exists():
                require(daemon.poll() is None and time.monotonic()<deadline,'daemon startup')
                time.sleep(.02)
            try:
                with Store(state):
                    raise AssertionError('daemon did not own writer')
            except StoreError as error:
                require(error.code == 'writer_locked','actual writer lock')
            def local():
                with sqlite3.connect(f'file:{state}/ledger.sqlite?mode=ro',uri=True) as db:
                    return {runtime:json.loads(data) for runtime,data in db.execute('SELECT runtime,data FROM attachments')}
            drop = 2
            gate_disabled = False
            async def send(**wire):
                nonlocal drop
                require(wire['method']=='POST' and wire['url'].startswith('https://events.example.com/'),'closed origin')
                require((wire['timeout'],wire['max_response_bytes'],wire['follow_redirects'])==(5,8192,False),'transport limits')
                path = wire['url'].removeprefix('https://events.example.com')
                headers = dict(wire['headers'])
                if gate_disabled:
                    headers['x-fixture-canary-mismatch' if gate_disabled == 'mismatch' else 'x-fixture-gate-disabled']='true'
                response = await asyncio.to_thread(post,path,wire['body'],headers)
                wires.append({'path':path,'body':wire['body'].decode(),'proof':json.loads(headers['x-event-node-proof']),'status':response[0],'response':json.loads(response[2])})
                if path == '/v1/runtimes/attach' and drop:
                    require(response[0] == 200,'reply lost only after actual commit')
                    drop -= 1
                    raise TimeoutError('deliberately lost committed reply')
                return response
            def command(session, operation, *flags):
                stream = io.StringIO()
                with redirect_stdout(stream):
                    code = cli.main(['--state-dir',str(state),operation,'--session-id',session,'--cloud-config',str(config),*flags])
                result = json.loads(stream.getvalue())
                outcomes.append({'operation':operation,'exitCode':code,'result':result})
                return result
            def callback(phase):
                def run(bridge, model, process, initial_witness):
                    nonlocal gate_disabled
                    # Qualifier has performed the real startup exchange before this callback.
                    client = launcher.NativeClient(bridge)
                    client.ready = True
                    challenge_calls = []
                    original_challenge = client.challenge
                    def record_challenge(*values):
                        challenge_calls.append(values[0])
                        return original_challenge(*values)
                    client.challenge = record_challenge
                    session = str(uuid4())
                    listener = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                    path = launcher.session_path(state,session)
                    listener.bind(str(path))
                    path.chmod(0o600)
                    listener.listen(4)
                    listener.settimeout(.1)
                    stop = threading.Event()
                    thread = threading.Thread(target=launcher._control,args=(listener,client,stop),daemon=True)
                    thread.start()
                    try:
                        binding = launcher.session_binding(state,session)
                        sessions.append({'sessionId':session,'pid':process.pid,'binding':binding,'initialWitness':initial_witness})
                        with patch.object(client_runtime,'_send_https',send):
                            if phase == 'source':
                                first = command(session,'attach','--runtime-id',source_id)
                                require(first.get('attached') is None and first['reason']=='commit_outcome_unknown','both replies lost')
                                pending = client_runtime.load_pending_commit(state,'attach',session)
                                require(pending is not None and source_id not in local(),'durable pending before mapping')
                                before = fixture('/fixture/read')
                                require(len(before['runtimes'])==1 and before['runtimes'][0]['runtime_generation']==1,'one cloud commit')
                                before_challenges = list(challenge_calls)
                                # Expire the native witness; exact receipt replay must remain valid.
                                time.sleep(.8)
                                recovered = command(session,'attach','--runtime-id',source_id)
                                require(recovered.get('localStatus')=='current','exact pending recovery')
                                require(challenge_calls==before_challenges,'recovery must not resample challenged witness')
                                require(fixture('/fixture/read')==before,'exact replay leaves cloud admission unchanged')
                                attach_wires=[row for row in wires if row['path']=='/v1/runtimes/attach']
                                require(len(attach_wires)==3 and len({row['body'] for row in attach_wires})==1,'same admission bytes')
                                require(len({row['proof']['nonce'] for row in attach_wires})==3,'fresh signed proof each retry')
                                require(base64.b64decode(pending['bodyB64']).decode()==attach_wires[0]['body'],'durable exact body')
                                require(client_runtime.load_pending_commit(state,'attach',session) is None,'pending cleared after daemon write')
                                require(local()[source_id]['runtimeGeneration']==1,'daemon persisted source')
                                renewed=command(session,'renew','--runtime-id',source_id,'--expected-runtime-generation','1','--expected-attachment-generation','1')
                                require(renewed.get('remoteStatus')=='renewed','actual renew')
                                snapshot=fixture('/fixture/read')['runtimes']
                                stale=command(session,'renew','--runtime-id',source_id,'--expected-runtime-generation','2','--expected-attachment-generation','1')
                                require(stale.get('renewed') is False and stale['reason']=='conflict','stale CAS denied')
                                gate_disabled=True
                                denied=command(session,'renew','--runtime-id',source_id,'--expected-runtime-generation','1','--expected-attachment-generation','1')
                                gate_disabled=False
                                require(denied.get('renewed') is False and denied['reason']=='native_binding_unqualified','disabled gate denied')
                                gate_disabled='mismatch'
                                mismatch=command(session,'renew','--runtime-id',source_id,'--expected-runtime-generation','1','--expected-attachment-generation','1')
                                gate_disabled=False
                                require(mismatch.get('renewed') is False and mismatch['reason']=='native_binding_unqualified','mismatched canary denied')
                                require(fixture('/fixture/read')['runtimes']==snapshot,'denials preserve runtime')
                            else:
                                require(binding['clientId'] != sessions[0]['binding']['clientId'],'distinct actual native client')
                                snapshot=fixture('/fixture/read')['runtimes']
                                wrong=command(session,'renew','--runtime-id',source_id,'--expected-runtime-generation','1','--expected-attachment-generation','1')
                                require(wrong.get('renewed') is False and wrong['reason']=='native_binding_unqualified','different actual native binding denied: '+json.dumps({'result':wrong,'lastWire':wires[-1]}))
                                require(fixture('/fixture/read')['runtimes']==snapshot,'invalid binding preserves source')
                                attached=command(session,'attach','--runtime-id',target_id)
                                require(attached.get('localStatus')=='current','actual target attach')
                                transferred=command(session,'transfer','--source-runtime-id',source_id,'--expected-source-runtime-generation','1','--expected-source-attachment-generation','1',
                                    '--replacement-runtime-id',target_id,'--expected-replacement-runtime-generation','1','--expected-replacement-attachment-generation','1')
                                require(transferred.get('remoteStatus')=='transferred' and transferred.get('localStatus')=='current','actual transfer')
                                rows={row['runtime_id']:row for row in fixture('/fixture/read')['runtimes']}
                                require(rows[source_id]['qualified']==0 and rows[source_id]['lease_until']==0 and rows[source_id]['runtime_generation']==2,'cloud source fence')
                                require(rows[target_id]['attachment_generation']==2 and rows[target_id]['qualified']==1,'cloud target generation')
                                mappings=local()
                                require(mappings[source_id]['leaseExpiresAt']==0 and mappings[source_id]['runtimeGeneration']==2,'daemon source fence')
                                require(mappings[target_id]['attachmentGeneration']==2,'daemon target mapping')
                        require(model.model_requests==0 and process.poll() is None,'live native, no model calls')
                        return {'result':'PASS'}
                    finally:
                        model.release_primary.set()
                        stop.set()
                        listener.close()
                        thread.join(timeout=2)
                        path.unlink(missing_ok=True)
                return run
            for phase in ('source','target'):
                native.qualify_input_recorded=callback(phase)
                native.qualify(binary,input_recorded=True,receipt_version=3)
            proof={'result':'PASS','qualification':'fixture-authority-real-native-cloud-admission','productionAdmissionProven':False,
                'nativeRuntimeSqlInsertion':False,'daemonWriterVerified':True,'realModelCalls':0,'binarySha256':args.binary_sha,'installedDistribution':{'version':distribution.version,'directUrl':provenance},
                'sessions':sessions,'wire':wires,'outcomes':outcomes,'cloud':fixture('/fixture/read'),'local':local(),'cloudBundle':address['bundle'],
                'mocks':['Access edge and Messaging identity','owner enrollment challenge','loopback HTTP transport','private launcher control socket setup'],
                'sourceSha256':{str(path):sha(path) for path in [Path(__file__),broker_path,broker_path.with_name('admission-workerd-worker.ts'),broker_path.with_name('coupled-workerd-source-hashes.mjs'),qualifier,*sorted(Path(event_gateway.__file__).parent.glob('*.py'))]}}
            output.write_text(json.dumps(proof,indent=2)+'\n')
            print(json.dumps({'result':'PASS','proof':str(output),'productionAdmissionProven':False}))
        finally:
            for process in (daemon,broker):
                if process is not None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


if __name__ == '__main__':
    main()
